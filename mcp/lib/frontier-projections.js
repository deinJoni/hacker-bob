"use strict";

const fs = require("fs");

const {
  assertSafeDomain,
  frontierEventsJsonlPath,
  statePath,
} = require("./paths.js");
const {
  readFrontierEvents,
} = require("./frontier-events.js");
const {
  readJsonFile,
} = require("./storage.js");

// frontier-projections fold frontier-events.jsonl into per-surface views that
// phase-gates.js (and downstream coverage gating) consume in place of
// state.json arrays.
//
// Cycle F.3 establishes the ledger as the read source while keeping legacy
// writes (state.terminally_blocked / state.explored) in place per Pact P2
// (dual-write before deletion). Cycle D.3 deletes those state arrays once the
// ledger has been authoritative for one operational release.
//
// Transitional fallback: F.1 wired coverage.js and waves.js to emit closure /
// blocker events, but the existing F.1 producers are coarser-grained than the
// legacy state.json arrays. The state.explored array is populated only by
// applyWaveMerge when a `surface_status: complete` handoff lands; F.1's
// closure.recorded events from `bounty_log_coverage` capture endpoint-batch
// closures (not surface-fully-explored closures). state.terminally_blocked is
// populated by the merge-promotion path; F.1's blocker.asserted events from
// `bounty_log_dead_ends` capture per-batch dead-end signals (not the
// merge-promotion's terminally-blocked promotion).
//
// To preserve functional equivalence with the legacy reads during the
// deprecation window, this module:
//
// 1. Treats only events that carry an explicit surface-level marker
//    (`payload.surface_fully_explored: true` for closures,
//    `payload.terminally_blocked: true` for blockers) — or that originate
//    from the wave-merge tool — as authoritative surface-state events.
// 2. Falls back to the legacy state.json arrays per projection when no
//    qualifying event exists. This keeps both legacy sessions (no events at
//    all) and current F.1 sessions (events that are coverage / dead-end
//    batches, not surface-level state) reading the same surfaces as before.
//
// The fallback is removed in D.3 once waves.js merge-promotion path also
// emits authoritative frontier events and the legacy state arrays are
// themselves deleted.

const SURFACE_STATE_MERGE_SOURCE = "bounty_apply_wave_merge";

function readStateRaw(domain) {
  const filePath = statePath(domain);
  if (!fs.existsSync(filePath)) return null;
  try {
    return readJsonFile(filePath, { label: "state.json" });
  } catch {
    return null;
  }
}

function fallbackClosuresFromState(state) {
  if (state == null || typeof state !== "object") return [];
  const explored = Array.isArray(state.explored) ? state.explored : [];
  const seen = new Set();
  const closures = [];
  for (const surfaceId of explored) {
    if (typeof surfaceId !== "string" || !surfaceId.trim()) continue;
    if (seen.has(surfaceId)) continue;
    seen.add(surfaceId);
    closures.push({
      surface_id: surfaceId,
      closed_at: null,
      reason: null,
      source_event_id: null,
    });
  }
  return closures.sort((a, b) => a.surface_id.localeCompare(b.surface_id));
}

function fallbackBlockersFromState(state) {
  if (state == null || typeof state !== "object") return [];
  const list = Array.isArray(state.terminally_blocked) ? state.terminally_blocked : [];
  const seen = new Set();
  const blockers = [];
  for (const entry of list) {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) continue;
    const surfaceId = typeof entry.surface_id === "string" ? entry.surface_id.trim() : "";
    if (!surfaceId || seen.has(surfaceId)) continue;
    seen.add(surfaceId);
    const reason = Array.isArray(entry.blockers) && entry.blockers.length > 0
      ? entry.blockers
        .map((blocker) => (
          blocker && typeof blocker === "object" && typeof blocker.kind === "string"
            ? blocker.kind
            : null
        ))
        .filter((kind) => typeof kind === "string" && kind.length > 0)
        .join(",") || null
      : null;
    blockers.push({
      surface_id: surfaceId,
      closed_at: null,
      reason,
      source_event_id: null,
    });
  }
  return blockers.sort((a, b) => a.surface_id.localeCompare(b.surface_id));
}

function frontierEventsExist(domain) {
  return fs.existsSync(frontierEventsJsonlPath(domain));
}

function loadFrontierEventsSafely(domain) {
  if (!frontierEventsExist(domain)) return [];
  try {
    return readFrontierEvents(domain);
  } catch {
    return [];
  }
}

function pickReasonFromPayload(payload) {
  if (payload == null || typeof payload !== "object" || Array.isArray(payload)) return null;
  if (typeof payload.reason === "string" && payload.reason.trim()) return payload.reason.trim();
  if (typeof payload.code === "string" && payload.code.trim()) return payload.code.trim();
  if (typeof payload.outcome === "string" && payload.outcome.trim()) return payload.outcome.trim();
  return null;
}

function isMergeSourcedEvent(event) {
  const source = event.source;
  if (source == null || typeof source !== "object" || Array.isArray(source)) return false;
  return source.tool === SURFACE_STATE_MERGE_SOURCE;
}

function isSurfaceClosureEvent(event) {
  if (event.kind !== "closure.recorded") return false;
  if (typeof event.surface_id !== "string" || !event.surface_id) return false;
  const payload = event.payload;
  if (payload && typeof payload === "object" && !Array.isArray(payload)
    && payload.surface_fully_explored === true) {
    return true;
  }
  return isMergeSourcedEvent(event);
}

function isSurfaceBlockerEvent(event) {
  if (event.kind !== "blocker.asserted") return false;
  if (typeof event.surface_id !== "string" || !event.surface_id) return false;
  const payload = event.payload;
  if (payload && typeof payload === "object" && !Array.isArray(payload)
    && payload.terminally_blocked === true) {
    return true;
  }
  return isMergeSourcedEvent(event);
}

function foldLatestBySurface(events, predicate) {
  const latest = new Map();
  for (const event of events) {
    if (!predicate(event)) continue;
    const existing = latest.get(event.surface_id);
    if (existing == null) {
      latest.set(event.surface_id, event);
      continue;
    }
    const existingTs = Date.parse(existing.ts || "");
    const candidateTs = Date.parse(event.ts || "");
    if (Number.isFinite(candidateTs) && Number.isFinite(existingTs)) {
      if (candidateTs >= existingTs) latest.set(event.surface_id, event);
    } else {
      // ledger order wins when timestamps are not parseable
      latest.set(event.surface_id, event);
    }
  }
  return Array.from(latest.values())
    .map((event) => ({
      surface_id: event.surface_id,
      closed_at: typeof event.ts === "string" ? event.ts : null,
      reason: pickReasonFromPayload(event.payload),
      source_event_id: typeof event.event_id === "string" ? event.event_id : null,
    }))
    .sort((a, b) => a.surface_id.localeCompare(b.surface_id));
}

function currentClosures(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  const events = loadFrontierEventsSafely(domain);
  const projected = foldLatestBySurface(events, isSurfaceClosureEvent);
  if (projected.length > 0) return projected;
  // Transitional fallback (D.3 removes): no authoritative surface-closure events
  // in the ledger — fall back to the legacy state.explored array so phase-gates
  // gating preserves the legacy semantics during the dual-write window.
  return fallbackClosuresFromState(readStateRaw(domain));
}

function currentBlockers(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  const events = loadFrontierEventsSafely(domain);
  const projected = foldLatestBySurface(events, isSurfaceBlockerEvent);
  if (projected.length > 0) return projected;
  // Transitional fallback (D.3 removes): no authoritative surface-blocker events
  // in the ledger — fall back to the legacy state.terminally_blocked array so
  // phase-gates gating preserves the legacy semantics during the dual-write
  // window.
  return fallbackBlockersFromState(readStateRaw(domain));
}

function normalizeObservationEvent(event) {
  const payload = event.payload && typeof event.payload === "object" && !Array.isArray(event.payload)
    ? event.payload
    : {};
  // F.4 normalized shape: `kind` carries the observation-class label (e.g.
  // "http_route", "schema_field", "auth_redirect"). Producers stamp this on
  // `payload.observation_kind`; callers can also stash it under `payload.kind`
  // for backward compatibility. Falls back to the event source artifact name.
  let observationKind = null;
  if (typeof payload.observation_kind === "string" && payload.observation_kind.trim()) {
    observationKind = payload.observation_kind.trim();
  } else if (typeof payload.kind === "string" && payload.kind.trim()) {
    observationKind = payload.kind.trim();
  } else if (event.source && typeof event.source === "object" && !Array.isArray(event.source)
    && typeof event.source.artifact === "string" && event.source.artifact.trim()) {
    observationKind = event.source.artifact.trim();
  }
  const source = event.source && typeof event.source === "object" && !Array.isArray(event.source)
    ? {
      artifact: typeof event.source.artifact === "string" ? event.source.artifact : null,
      ref: typeof event.source.ref === "string"
        ? event.source.ref
        : (typeof event.source.tool === "string" ? event.source.tool : null),
    }
    : { artifact: null, ref: null };
  return {
    event_id: typeof event.event_id === "string" ? event.event_id : null,
    surface_id: typeof event.surface_id === "string" ? event.surface_id : null,
    ts: typeof event.ts === "string" ? event.ts : null,
    kind: observationKind,
    payload,
    source,
  };
}

function compareObservationEvents(a, b) {
  const tsA = Date.parse(a.ts || "");
  const tsB = Date.parse(b.ts || "");
  if (Number.isFinite(tsA) && Number.isFinite(tsB) && tsA !== tsB) {
    return tsA - tsB;
  }
  return String(a.event_id || "").localeCompare(String(b.event_id || ""));
}

function observationsForSurface(targetDomain, surfaceId) {
  const domain = assertSafeDomain(targetDomain);
  if (typeof surfaceId !== "string" || !surfaceId.trim()) {
    throw new Error("surface_id must be a non-empty string");
  }
  const trimmed = surfaceId.trim();
  const events = loadFrontierEventsSafely(domain);
  return events
    .filter((event) => event.kind === "observation.recorded" && event.surface_id === trimmed)
    .sort(compareObservationEvents)
    .map(normalizeObservationEvent);
}

module.exports = {
  compareObservationEvents,
  currentBlockers,
  currentClosures,
  normalizeObservationEvent,
  observationsForSurface,
};
