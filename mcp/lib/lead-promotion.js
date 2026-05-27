"use strict";

// Surface-lead promotion + recording flow. Owns the surface-leads.json
// persistence loop and the frontier.enqueued / promotion dual-write event
// stream. Selection and priority signals live in lead-scoring; the legacy
// attack_surface.json mutation is delegated to surface-mutator.

const {
  assertBoolean,
  assertInteger,
  assertNonEmptyString,
  pushUnique,
} = require("./validation.js");
const { surfaceLeadsPath } = require("./paths.js");
const {
  readSessionStateStrict,
  writeSessionStateDocument,
} = require("./session-state-store.js");
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
  selectPromotableSurfaceLeads,
  sortLeadsByScore,
} = require("./lead-scoring.js");
const { applyPromotionToLegacySurface } = require("./surface-mutator.js");

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

function recordSurfaceLeadsInternal(domain, leads, context = {}) {
  if (!Array.isArray(leads) || leads.length === 0) {
    return { recorded: 0, lead_ids: [], path: surfaceLeadsPath(domain) };
  }
  const document = readSurfaceLeadsDocument(domain);
  const byKey = new Map(document.leads.map((lead) => [lead.key, lead]));
  const leadIds = [];
  const ledgerEntries = [];
  let recorded = 0;
  for (const leadInput of leads) {
    const incoming = normalizeSurfaceLead(leadInput, context);
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
  const updateState = options.update_state == null ? true : assertBoolean(options.update_state, "update_state");
  const document = readSurfaceLeadsDocument(domain);
  const candidates = selectPromotableSurfaceLeads(document, options);
  if (candidates.length === 0) return buildPromotionEnvelope(domain, []);
  const { promoted_surface_ids: promotedSurfaceIds } = applyPromotionToLegacySurface(domain, candidates);
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
  if (updateState) {
    try {
      const { raw, state } = readSessionStateStrict(domain);
      const leadSurfaceIds = [...state.lead_surface_ids];
      pushUnique(leadSurfaceIds, new Set(leadSurfaceIds), promotedSurfaceIds);
      writeSessionStateDocument(domain, raw, { ...state, lead_surface_ids: leadSurfaceIds });
    } catch {
      // Promotion can run immediately after surface-discovery before later state reads; a
      // missing or legacy state should not corrupt the promoted attack surface.
    }
  }
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
