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
// phase-gates.js and coverage.js consume in place of state.json arrays.
//
// Cycle F.3 establishes the ledger as the read source while keeping legacy
// writes (state.terminally_blocked / state.explored) in place per Pact P2
// (dual-write before deletion). Cycle D.3 deletes those state arrays once the
// ledger has been authoritative for one operational release.
//
// Transitional fallback: legacy sessions that pre-date the F.1 producers may
// have populated state.terminally_blocked / state.explored arrays without ever
// emitting frontier events. If frontier-events.jsonl is empty or missing for a
// given domain, we read those state arrays directly so phase-gates and coverage
// continue to see the same surfaces during the deprecation window. The fallback
// is removed in D.3 when the legacy arrays are themselves deleted.

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
  return closures;
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
  return blockers;
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

function foldLatestBySurface(events, kind) {
  const latest = new Map();
  for (const event of events) {
    if (event.kind !== kind) continue;
    if (typeof event.surface_id !== "string" || !event.surface_id) continue;
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
  if (events.length === 0) {
    return fallbackClosuresFromState(readStateRaw(domain));
  }
  return foldLatestBySurface(events, "closure.recorded");
}

function currentBlockers(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  const events = loadFrontierEventsSafely(domain);
  if (events.length === 0) {
    return fallbackBlockersFromState(readStateRaw(domain));
  }
  return foldLatestBySurface(events, "blocker.asserted");
}

function observationsForSurface(targetDomain, surfaceId) {
  const domain = assertSafeDomain(targetDomain);
  if (typeof surfaceId !== "string" || !surfaceId.trim()) {
    throw new Error("surface_id must be a non-empty string");
  }
  const trimmed = surfaceId.trim();
  const events = loadFrontierEventsSafely(domain);
  // F.4 will refine this with a top-level observations[] view on
  // surface-index.json. For now, return the ordered event stream so callers
  // that need to walk observations per surface have a single entry point.
  return events
    .filter((event) => event.kind === "observation.recorded" && event.surface_id === trimmed)
    .sort((a, b) => {
      const tsA = Date.parse(a.ts || "");
      const tsB = Date.parse(b.ts || "");
      if (Number.isFinite(tsA) && Number.isFinite(tsB) && tsA !== tsB) {
        return tsA - tsB;
      }
      return String(a.event_id || "").localeCompare(String(b.event_id || ""));
    });
}

module.exports = {
  currentBlockers,
  currentClosures,
  observationsForSurface,
};
