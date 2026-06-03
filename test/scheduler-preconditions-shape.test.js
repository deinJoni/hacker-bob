"use strict";

// Y.10 — scheduler-preconditions registry shape + paired safety test.
//
// Asserts:
//   1. SCHEDULER_PRECONDITION_VALUES is Object.freeze'd and non-empty.
//   2. Every value in SCHEDULER_PRECONDITION_VALUES has a backing check
//      function in PRECONDITION_CHECKS (paired safety per Y.10 Do step 9).
//   3. partial_surfaces_drained returns {satisfied, blocked_surface_ids}
//      shape with semantics tied to mergeWaveHandoffs snapshot state.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  SCHEDULER_PRECONDITION_VALUES,
  PRECONDITION_CHECKS,
  evaluateSchedulerPrecondition,
} = require("../mcp/lib/scheduler-preconditions.js");
const {
  waveMergeSnapshotPath,
  waveHandoffsSnapshotDir,
} = require("../mcp/lib/wave-handoff-store.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sched-pre-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

test("SCHEDULER_PRECONDITION_VALUES is frozen and includes partial_surfaces_drained", () => {
  assert.equal(Object.isFrozen(SCHEDULER_PRECONDITION_VALUES), true);
  assert.ok(SCHEDULER_PRECONDITION_VALUES.length >= 1);
  assert.ok(SCHEDULER_PRECONDITION_VALUES.includes("partial_surfaces_drained"));
});

test("PRECONDITION_CHECKS is frozen and covers every value in SCHEDULER_PRECONDITION_VALUES (paired safety)", () => {
  assert.equal(Object.isFrozen(PRECONDITION_CHECKS), true);
  for (const name of SCHEDULER_PRECONDITION_VALUES) {
    assert.equal(typeof PRECONDITION_CHECKS[name], "function", `${name} has no check function`);
  }
});

test("evaluateSchedulerPrecondition rejects unknown precondition names", () => {
  assert.throws(
    () => evaluateSchedulerPrecondition("not_a_real_precondition", { target_domain: "x.com" }),
    /unknown scheduler precondition/,
  );
});

test("partial_surfaces_drained returns satisfied=true when no merge snapshot exists", () => {
  withTempHome(() => {
    const domain = "no-merges-yet.com";
    const result = evaluateSchedulerPrecondition("partial_surfaces_drained", { target_domain: domain });
    assert.equal(result.satisfied, true);
    assert.deepEqual(result.blocked_surface_ids, []);
  });
});

test("partial_surfaces_drained returns satisfied=false with blocked_surface_ids from snapshot", () => {
  withTempHome(() => {
    const domain = "has-partials.com";
    fs.mkdirSync(waveHandoffsSnapshotDir(domain), { recursive: true });
    fs.writeFileSync(waveMergeSnapshotPath(domain, 1), JSON.stringify({
      wave_number: 1,
      partial_surface_ids: ["surface-partial-a", "surface-partial-b"],
    }));
    const result = evaluateSchedulerPrecondition("partial_surfaces_drained", { target_domain: domain });
    assert.equal(result.satisfied, false);
    assert.deepEqual(result.blocked_surface_ids, ["surface-partial-a", "surface-partial-b"]);
  });
});

test("partial_surfaces_drained returns satisfied=true when all partials drained in highest snapshot", () => {
  withTempHome(() => {
    const domain = "drained-in-latest.com";
    fs.mkdirSync(waveHandoffsSnapshotDir(domain), { recursive: true });
    fs.writeFileSync(waveMergeSnapshotPath(domain, 1), JSON.stringify({
      wave_number: 1,
      partial_surface_ids: ["surface-partial-a"],
    }));
    fs.writeFileSync(waveMergeSnapshotPath(domain, 2), JSON.stringify({
      wave_number: 2,
      partial_surface_ids: [],
    }));
    const result = evaluateSchedulerPrecondition("partial_surfaces_drained", { target_domain: domain });
    assert.equal(result.satisfied, true);
    assert.deepEqual(result.blocked_surface_ids, []);
  });
});

test("partial_surfaces_drained requires target_domain", () => {
  assert.throws(
    () => evaluateSchedulerPrecondition("partial_surfaces_drained", {}),
    /target_domain/,
  );
});
