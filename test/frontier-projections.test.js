"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendFrontierEvent,
} = require("../mcp/lib/frontier-events.js");
const {
  currentBlockers,
  currentClosures,
  observationsForSurface,
} = require("../mcp/lib/frontier-projections.js");
const {
  sessionDir,
  statePath,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-frontier-projections-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function ensureSessionDir(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
}

test("currentBlockers reflects a blocker.asserted event without touching state.terminally_blocked", () => {
  withTempHome(() => {
    const domain = "blocker-projection.example.com";
    ensureSessionDir(domain);
    // No state.json — state.terminally_blocked is implicit empty.
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      ts: "2026-05-27T10:00:00.000Z",
      surface_id: "surface:billing",
      payload: {
        terminally_blocked: true,
        kind: "auth_missing",
      },
      source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
    });
    const projected = currentBlockers(domain);
    assert.equal(projected.length, 1);
    assert.equal(projected[0].surface_id, "surface:billing");
    assert.ok(projected[0].source_event_id.startsWith("FE-"));
  });
});

test("currentBlockers folds latest event per surface_id", () => {
  withTempHome(() => {
    const domain = "blocker-fold.example.com";
    ensureSessionDir(domain);
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      ts: "2026-05-27T10:00:00.000Z",
      surface_id: "surface:alpha",
      payload: { terminally_blocked: true, kind: "auth_missing", reason: "first" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      ts: "2026-05-27T10:01:00.000Z",
      surface_id: "surface:alpha",
      payload: { terminally_blocked: true, kind: "egress_unreachable", reason: "second" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      ts: "2026-05-27T10:02:00.000Z",
      surface_id: "surface:beta",
      payload: { terminally_blocked: true, kind: "auth_missing", reason: "beta-first" },
    });
    const projected = currentBlockers(domain);
    assert.equal(projected.length, 2);
    const byId = new Map(projected.map((entry) => [entry.surface_id, entry]));
    assert.equal(byId.get("surface:alpha").reason, "second");
    assert.equal(byId.get("surface:beta").reason, "beta-first");
  });
});

test("currentClosures projects merge-sourced closures and ignores logCoverage batch closures", () => {
  withTempHome(() => {
    const domain = "closure-projection.example.com";
    ensureSessionDir(domain);
    // A logCoverage-style closure event must not be treated as a surface
    // closure — these capture endpoint-batch coverage, not surface state.
    appendFrontierEvent({
      target_domain: domain,
      kind: "closure.recorded",
      ts: "2026-05-27T10:00:00.000Z",
      surface_id: "surface:coverage-batch",
      payload: { records: 1, statuses: { requeue: 1 } },
      source: { artifact: "coverage.jsonl", tool: "bob_log_coverage" },
    });
    // A merge-sourced closure event is a surface-state event and projects.
    appendFrontierEvent({
      target_domain: domain,
      kind: "closure.recorded",
      ts: "2026-05-27T10:01:00.000Z",
      surface_id: "surface:explored",
      payload: { surface_fully_explored: true, reason: "complete handoff" },
      source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
    });
    const projected = currentClosures(domain);
    assert.equal(projected.length, 1);
    assert.equal(projected[0].surface_id, "surface:explored");
    assert.equal(projected[0].reason, "complete handoff");
  });
});

test("currentClosures falls back to state.explored when no qualifying surface-closure events exist", () => {
  withTempHome(() => {
    const domain = "fallback-closures.example.com";
    ensureSessionDir(domain);
    fs.writeFileSync(statePath(domain), JSON.stringify({
      explored: ["surface:legacy-a", "surface:legacy-b"],
      terminally_blocked: [],
    }, null, 2));
    // Append one non-qualifying closure (logCoverage-style) and confirm we
    // still fall back to state.explored.
    appendFrontierEvent({
      target_domain: domain,
      kind: "closure.recorded",
      ts: "2026-05-27T10:00:00.000Z",
      surface_id: "surface:coverage-batch",
      payload: { records: 1, statuses: { requeue: 1 } },
      source: { artifact: "coverage.jsonl", tool: "bob_log_coverage" },
    });
    const projected = currentClosures(domain);
    assert.equal(projected.length, 2);
    assert.deepEqual(projected.map((c) => c.surface_id), [
      "surface:legacy-a",
      "surface:legacy-b",
    ]);
    assert.equal(projected[0].source_event_id, null);
  });
});

test("currentBlockers falls back to state.terminally_blocked when no qualifying surface-blocker events exist", () => {
  withTempHome(() => {
    const domain = "fallback-blockers.example.com";
    ensureSessionDir(domain);
    fs.writeFileSync(statePath(domain), JSON.stringify({
      explored: [],
      terminally_blocked: [
        {
          surface_id: "surface:legacy-blocked",
          blocked_at_wave: 1,
          blockers: [{ kind: "auth_missing" }],
        },
      ],
    }, null, 2));
    // Append one non-qualifying blocker (logDeadEnds-style) and confirm we
    // still fall back to state.terminally_blocked.
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      ts: "2026-05-27T10:00:00.000Z",
      surface_id: "surface:dead-end-batch",
      payload: {
        dead_ends: ["GET /foo"],
        waf_blocked_endpoints: [],
        dead_end_count: 1,
        waf_blocked_count: 0,
      },
      source: { artifact: "live-dead-ends.jsonl", tool: "bob_log_dead_ends" },
    });
    const projected = currentBlockers(domain);
    assert.equal(projected.length, 1);
    assert.equal(projected[0].surface_id, "surface:legacy-blocked");
    assert.equal(projected[0].reason, "auth_missing");
    assert.equal(projected[0].source_event_id, null);
  });
});

test("currentClosures and currentBlockers return empty arrays when neither state nor ledger has surface state", () => {
  withTempHome(() => {
    const domain = "pristine.example.com";
    ensureSessionDir(domain);
    assert.deepEqual(currentClosures(domain), []);
    assert.deepEqual(currentBlockers(domain), []);
  });
});

test("observationsForSurface returns observation events for the requested surface in timestamp order", () => {
  withTempHome(() => {
    const domain = "observations.example.com";
    ensureSessionDir(domain);
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-27T10:02:00.000Z",
      surface_id: "surface:gamma",
      payload: { note: "second" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-27T10:01:00.000Z",
      surface_id: "surface:gamma",
      payload: { note: "first" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-27T10:03:00.000Z",
      surface_id: "surface:other",
      payload: { note: "different surface" },
    });
    const ordered = observationsForSurface(domain, "surface:gamma");
    assert.equal(ordered.length, 2);
    assert.equal(ordered[0].payload.note, "first");
    assert.equal(ordered[1].payload.note, "second");
  });
});

test("observationsForSurface returns empty array when no events exist for the surface", () => {
  withTempHome(() => {
    const domain = "empty-observations.example.com";
    ensureSessionDir(domain);
    assert.deepEqual(observationsForSurface(domain, "surface:absent"), []);
  });
});

test("observationsForSurface rejects empty surface_id", () => {
  withTempHome(() => {
    const domain = "observation-validation.example.com";
    ensureSessionDir(domain);
    assert.throws(
      () => observationsForSurface(domain, ""),
      /surface_id/,
    );
  });
});
