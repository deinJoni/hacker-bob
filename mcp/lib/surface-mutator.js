"use strict";

// LEGACY: removed in Plane D.
//
// Surface-mutator exists ONLY to keep the legacy attack_surface.json projection
// populated during the deprecation window. Per F.6, lead-promotion delegates
// the actual attack_surface.json write here and pairs it with the dual-write
// surface.observed frontier event. Once Plane D retires attack_surface.json as
// a writer (D.3), this whole module is deleted along with the legacy file.

const fs = require("fs");
const {
  attackSurfacePath,
} = require("./paths.js");
const {
  readJsonFile,
  writeFileAtomic,
} = require("./storage.js");
const {
  appendFrontierEvent,
} = require("./frontier-events.js");
const {
  scheduleMaterialization,
} = require("./frontier-materialize-debounce.js");

function slugify(value) {
  const slug = String(value || "lead")
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 54);
  return slug || "lead";
}

function readAttackSurfaceDocument(domain) {
  const filePath = attackSurfacePath(domain);
  if (!fs.existsSync(filePath)) {
    return { domain, surfaces: [] };
  }
  let parsed;
  try {
    parsed = readJsonFile(filePath, { label: "attack_surface.json" });
  } catch (error) {
    throw new Error(`Malformed attack surface JSON: ${filePath} (${error.message || String(error)})`);
  }
  if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed) || !Array.isArray(parsed.surfaces)) {
    throw new Error(`Malformed attack surface JSON: ${filePath} (expected object with surfaces array)`);
  }
  return parsed;
}

function uniqueSurfaceId(lead, surfaceIds) {
  const base = `lead-${slugify(lead.title || lead.hosts[0] || lead.endpoints[0] || lead.id)}`;
  let candidate = base;
  let suffix = 2;
  while (surfaceIds.has(candidate)) {
    candidate = `${base}-${suffix}`;
    suffix += 1;
  }
  surfaceIds.add(candidate);
  return candidate;
}

function leadToSurface(lead, surfaceId) {
  return {
    id: surfaceId,
    hosts: lead.hosts,
    tech_stack: lead.tech_stack,
    endpoints: lead.endpoints,
    interesting_params: lead.interesting_params,
    nuclei_hits: lead.nuclei_hits,
    priority: lead.priority,
    surface_type: lead.surface_type || "unknown",
    bug_class_hints: lead.bug_class_hints,
    high_value_flows: lead.high_value_flows,
    evidence: lead.evidence,
    ranking: {
      version: 1,
      score: lead.score || 0,
      priority: lead.priority,
      reasons: ["promoted_surface_lead", lead.confidence ? `confidence:${lead.confidence}` : null]
        .filter(Boolean),
    },
  };
}

// LEGACY: removed in Plane D — applyPromotionToLegacySurface mutates the legacy
// attack_surface.json projection AND emits surface.observed events so the
// frontier projection sees newly-promoted surfaces. lead-promotion calls this
// during promoteSurfaceLeadsInternal; the call site is the lone dual-write seam
// for promotion. Once attack_surface.json is purely read-only (D.3), the
// legacy write here is deleted and surface-mutator collapses to a no-op stub.
function applyPromotionToLegacySurface(domain, candidates) {
  if (!Array.isArray(candidates) || candidates.length === 0) {
    return { promoted_surface_ids: [] };
  }
  const attackSurface = readAttackSurfaceDocument(domain);
  const surfaceIds = new Set(attackSurface.surfaces
    .filter((surface) => surface && typeof surface === "object")
    .map((surface) => String(surface.id || ""))
    .filter(Boolean));
  const promotedSurfaceIds = [];

  for (const lead of candidates) {
    const surfaceId = uniqueSurfaceId(lead, surfaceIds);
    attackSurface.surfaces.push(leadToSurface(lead, surfaceId));
    promotedSurfaceIds.push(surfaceId);
  }

  // LEGACY: removed in Plane D — attack_surface.json is the legacy projection.
  // surface-index.json (F.2) becomes authoritative; surface.observed events here
  // populate the frontier projection that the materializer folds.
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify(attackSurface, null, 2)}\n`);

  // Dual-write per Pact P2: each promoted lead becomes a surface in the legacy
  // projection AND a surface.observed event in the frontier ledger.
  for (let i = 0; i < candidates.length; i += 1) {
    const lead = candidates[i];
    const surfaceId = promotedSurfaceIds[i];
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
          labels: ["promoted_surface_lead", lead.confidence ? `confidence:${lead.confidence}` : null].filter(Boolean),
          lead_id: lead.id,
        },
        source: { artifact: "attack_surface.json", tool: "bob_promote_surface_leads" },
      });
      scheduleMaterialization(domain);
    } catch {
      // Frontier ledger is dual-write best-effort during the deprecation window.
    }
  }

  return { promoted_surface_ids: promotedSurfaceIds };
}

module.exports = {
  applyPromotionToLegacySurface,
};
