"use strict";

// Surface-lead promotion + recording flow. Owns the surface-leads.json
// persistence loop and emits the frontier events (frontier.enqueued and
// surface.observed) that the materializer folds into surface-index.json and
// task-queue.json. Selection and priority signals live in lead-scoring.
//
// Cycle D.3 deleted surface-mutator.js: attack_surface.json is no longer
// written; surface-index.json (materialized from frontier events) is the
// authoritative surface source. The promotion path emits one
// surface.observed event per promoted lead so the materializer sees the
// new surface without re-reading the legacy projection.

const {
  assertBoolean,
  assertInteger,
  assertNonEmptyString,
} = require("./validation.js");
const { surfaceLeadsPath } = require("./paths.js");
const { withSessionLock } = require("./storage.js");
const { appendFrontierEvent } = require("./frontier-events.js");
const { scheduleMaterialization } = require("./frontier-materialize-debounce.js");
const {
  mergeSurfaceLead,
  nextLeadId,
  normalizeSurfaceLead,
  readSurfaceLeadsDocument,
  writeSurfaceLeadsDocument,
} = require("./lead-intake.js");
const {
  buildPromotionEnvelope,
  buildPromotionPreview,
  isAssignableSurfaceLead,
  normalizePromotionOptions,
  selectPromotableSurfaceLeads,
  sortLeadsByScore,
} = require("./lead-scoring.js");
const { ERROR_CODES, ToolError } = require("./envelope.js");
const { loadQueuePolicy } = require("./queue-policy.js");

const PROMOTED_SURFACE_LEAD_LABEL = "promoted_surface_lead";

function slugify(value) {
  const slug = String(value || "lead")
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 54);
  return slug || "lead";
}

function uniqueSurfaceId(lead, existingIds) {
  const base = `lead-${slugify(lead.title || (lead.hosts && lead.hosts[0]) || (lead.endpoints && lead.endpoints[0]) || lead.id)}`;
  let candidate = base;
  let suffix = 2;
  while (existingIds.has(candidate)) {
    candidate = `${base}-${suffix}`;
    suffix += 1;
  }
  existingIds.add(candidate);
  return candidate;
}

function emitPromotedSurfaceObserved(domain, lead, surfaceId) {
  try {
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      surface_id: surfaceId,
      payload: {
        surface_type: lead.surface_type || "unknown",
        title: lead.title,
        hosts: lead.hosts,
        endpoints: lead.endpoints,
        priority: lead.priority,
        score: lead.score,
        confidence: lead.confidence,
        labels: [PROMOTED_SURFACE_LEAD_LABEL, lead.confidence ? `confidence:${lead.confidence}` : null].filter(Boolean),
        lead_id: lead.id,
      },
      source: { artifact: "surface-leads.json", tool: "bob_promote_surface_leads" },
    });
    scheduleMaterialization(domain);
  } catch {
    // Frontier ledger append is best-effort here; materialization runs on
    // the next producer event.
  }
}

function applyPromotionToFrontier(domain, candidates) {
  if (!Array.isArray(candidates) || candidates.length === 0) {
    return { promoted_surface_ids: [] };
  }
  // Allocate unique surface_ids based on the existing materialized surfaces
  // so re-promotion across waves does not collide. The materialized view is
  // accessed via frontier-projections.currentSurfaces to avoid a direct
  // dependency on the materializer module from the producer path.
  const { currentSurfaces } = require("./frontier-projections.js");
  let knownSurfaceIds;
  try {
    const projection = currentSurfaces(domain);
    knownSurfaceIds = new Set((projection.surfaces || [])
      .map((surface) => String(surface.id || ""))
      .filter(Boolean));
  } catch {
    knownSurfaceIds = new Set();
  }
  const promotedSurfaceIds = [];
  for (const lead of candidates) {
    const surfaceId = uniqueSurfaceId(lead, knownSurfaceIds);
    emitPromotedSurfaceObserved(domain, lead, surfaceId);
    promotedSurfaceIds.push(surfaceId);
  }
  return { promoted_surface_ids: promotedSurfaceIds };
}

function emitFrontierEnqueued(domain, lead) {
  try {
    appendFrontierEvent({
      target_domain: domain,
      kind: "frontier.enqueued",
      payload: {
        lead_id: lead.id,
        surface_ref: lead.source_surface_id || lead.promoted_surface_id || null,
        score: lead.score,
        priority: lead.priority,
        confidence: lead.confidence,
        provenance: {
          source: lead.source,
          source_wave: lead.source_wave,
          source_agent: lead.source_agent,
          source_surface_id: lead.source_surface_id,
        },
      },
      source: { artifact: "surface-leads.json", tool: "bob_record_surface_leads" },
    });
    scheduleMaterialization(domain);
  } catch {
    // Frontier ledger is dual-write best-effort during the deprecation window.
  }
}

// Y.12 (rev 4.1 defect 1) — producer-side rationale enforcement on
// bob_record_surface_leads. When queue-policy.lead_rationale_required_when_below_threshold
// is TRUE and a recorded lead's score is below queue-policy min_score
// (default 60 from lead-scoring.normalizePromotionOptions), the lead MUST
// carry a non-empty rationale (≤512 chars). Validator runs BEFORE write so
// no partial state is persisted. Structural complement to the Y.7
// silent_lead_threshold_drop runtime tripwire (mcp/lib/friction-scanners.js).
function enforceLeadRationalePolicy(domain, normalizedLeads) {
  let policy;
  try {
    policy = loadQueuePolicy(domain);
  } catch {
    return;
  }
  if (!policy || policy.lead_rationale_required_when_below_threshold !== true) {
    return;
  }
  const { minScore } = normalizePromotionOptions({});
  for (let i = 0; i < normalizedLeads.length; i += 1) {
    const lead = normalizedLeads[i];
    const score = typeof lead.score === "number" ? lead.score : 0;
    if (score >= minScore) continue;
    const rationale = typeof lead.rationale === "string" ? lead.rationale.trim() : "";
    if (rationale) continue;
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `leads[${i}] has score ${score} below queue-policy min_score ${minScore} but lacks rationale`,
      { index: i, score, min_score: minScore },
      {
        remediation: `lead at index ${i} has score ${score} below min_score ${minScore} but lacks rationale; provide a non-empty rationale (≤512 chars) explaining why this lead is being recorded despite being below threshold, OR raise the lead's score, OR set queue-policy.lead_rationale_required_when_below_threshold: false to disable the gate`,
      },
    );
  }
}

function recordSurfaceLeadsInternal(domain, leads, context = {}) {
  if (!Array.isArray(leads) || leads.length === 0) {
    return { recorded: 0, lead_ids: [], path: surfaceLeadsPath(domain) };
  }
  const document = readSurfaceLeadsDocument(domain);
  const byKey = new Map(document.leads.map((lead) => [lead.key, lead]));
  const leadIds = [];
  const ledgerEntries = [];
  let recorded = 0;
  // Pre-normalize all leads so the rationale-policy validator can read the
  // computed `score` (evidenceScore fallback when input.score is absent)
  // before any partial state is persisted.
  const normalizedLeads = leads.map((leadInput) => normalizeSurfaceLead(leadInput, context));
  enforceLeadRationalePolicy(domain, normalizedLeads);
  for (const incoming of normalizedLeads) {
    const existing = byKey.get(incoming.key);
    const lead = existing
      ? mergeSurfaceLead(existing, incoming)
      : { ...incoming, id: incoming.id || nextLeadId(document.leads), created_at: new Date().toISOString() };
    if (existing) {
      document.leads[document.leads.findIndex((entry) => entry.id === existing.id)] = lead;
    } else {
      document.leads.push(lead);
      recorded += 1;
    }
    byKey.set(lead.key, lead);
    leadIds.push(lead.id);
    ledgerEntries.push(lead);
  }
  // LEGACY: removed in Plane D — surface-leads.json is the legacy projection;
  // frontier-events.jsonl is the append-only authority after F.2 materializes.
  const filePath = writeSurfaceLeadsDocument(domain, document);
  // Dual-write per Pact P2: each recorded/merged lead also appends a
  // frontier.enqueued event so the frontier projection sees the same intake.
  for (const lead of ledgerEntries) emitFrontierEnqueued(domain, lead);
  return { recorded, total: document.leads.length, lead_ids: leadIds, path: filePath };
}

function previewSurfaceLeadPromotion(domain, options = {}) {
  const document = readSurfaceLeadsDocument(domain);
  return buildPromotionPreview(domain, selectPromotableSurfaceLeads(document, options));
}

function promoteSurfaceLeadsInternal(domain, options = {}) {
  // update_state is retained for argument-shape compatibility but no longer
  // mutates state.json — D.3 deleted state.lead_surface_ids; lead-surface
  // membership is derived from frontier surface.observed events.
  if (options.update_state != null) {
    assertBoolean(options.update_state, "update_state");
  }
  const document = readSurfaceLeadsDocument(domain);
  const candidates = selectPromotableSurfaceLeads(document, options);
  if (candidates.length === 0) return buildPromotionEnvelope(domain, []);
  const { promoted_surface_ids: promotedSurfaceIds } = applyPromotionToFrontier(domain, candidates);
  const now = new Date().toISOString();
  for (let i = 0; i < candidates.length; i += 1) {
    const index = document.leads.findIndex((item) => item.id === candidates[i].id);
    if (index === -1) continue;
    document.leads[index] = {
      ...document.leads[index],
      status: "promoted",
      promoted_surface_id: promotedSurfaceIds[i],
      promoted_at: now,
    };
  }
  writeSurfaceLeadsDocument(domain, document);
  return buildPromotionEnvelope(domain, promotedSurfaceIds);
}

function recordSurfaceLeads(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const leads = Array.isArray(args.leads) ? args.leads : [];
  const context = {
    source: args.source,
    source_wave: args.source_wave,
    source_agent: args.source_agent,
    source_surface_id: args.source_surface_id,
  };
  return withSessionLock(domain, () => JSON.stringify({
    version: 1,
    ...recordSurfaceLeadsInternal(domain, leads, context),
  }));
}

function recordSurfaceLeadsForWaveHandoff(domain, leads, context = {}) {
  return withSessionLock(domain, () => recordSurfaceLeadsInternal(domain, leads, context));
}

function readSurfaceLeads(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const limit = args.limit == null ? 50 : assertInteger(args.limit, "limit", { min: 1, max: 200 });
  const document = readSurfaceLeadsDocument(domain);
  const leads = sortLeadsByScore(document.leads).slice(0, limit);
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    path: surfaceLeadsPath(domain),
    total: document.leads.length,
    returned: leads.length,
    high_confidence_unpromoted: document.leads.filter(
      (lead) => lead.status !== "promoted" && lead.confidence === "high" && isAssignableSurfaceLead(lead),
    ).length,
    leads,
  });
}

function promoteSurfaceLeads(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  return withSessionLock(domain, () => JSON.stringify({
    version: 1,
    ...promoteSurfaceLeadsInternal(domain, args),
  }));
}

function promoteSurfaceLeadsForWave(domain, options = {}) {
  return withSessionLock(domain, () => promoteSurfaceLeadsInternal(domain, {
    ...options,
    update_state: false,
  }));
}

module.exports = {
  previewSurfaceLeadPromotion,
  promoteSurfaceLeads,
  promoteSurfaceLeadsForWave,
  readSurfaceLeads,
  recordSurfaceLeads,
  recordSurfaceLeadsForWaveHandoff,
};
