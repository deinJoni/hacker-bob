"use strict";

// Y.10 (Y-D12 / Y-P12) — scheduler-precondition registry.
//
// Each scheduler precondition is a closed-enum name that maps to a check
// function returning `{satisfied: boolean, blocked_surface_ids?: string[]}`.
// The runtime gate at bob_advance_session consults these checks before
// allowing OPEN_FRONTIER -> CLAIM_FREEZE; the CI marker scan at
// scripts/check-skill-scheduler-coherence.js consumes the closed enum to
// assert that committed skill / role markdown carries the `@precondition:`
// directive on the relevant state-block.
//
// The set is intentionally narrow: only conditions the runtime gate
// mechanically enforces appear here. New preconditions extend the enum
// AND register a check function in PRECONDITION_CHECKS at the same time
// (paired safety enforcement — see test/scheduler-preconditions-shape.test.js).

const {
  getLatestMergedWavePartialSurfaceIds,
} = require("./wave-handoff-store.js");

const SCHEDULER_PRECONDITION_VALUES = Object.freeze([
  "partial_surfaces_drained",
]);

// Each check receives `{target_domain}` and returns an object with at minimum
// `{satisfied: boolean}`. When unsatisfied, the check MAY return additional
// structured context (e.g., `blocked_surface_ids`) that the gate surfaces in
// the STATE_CONFLICT payload.
const PRECONDITION_CHECKS = Object.freeze({
  partial_surfaces_drained(context) {
    const targetDomain = context && context.target_domain;
    if (typeof targetDomain !== "string" || targetDomain.length === 0) {
      throw new Error("partial_surfaces_drained: target_domain is required");
    }
    const blockedSurfaceIds = getLatestMergedWavePartialSurfaceIds(targetDomain);
    return {
      satisfied: blockedSurfaceIds.length === 0,
      blocked_surface_ids: blockedSurfaceIds,
    };
  },
});

function evaluateSchedulerPrecondition(name, context) {
  if (!SCHEDULER_PRECONDITION_VALUES.includes(name)) {
    throw new Error(`unknown scheduler precondition: ${name}`);
  }
  const check = PRECONDITION_CHECKS[name];
  if (typeof check !== "function") {
    throw new Error(`scheduler precondition ${name} has no check function`);
  }
  return check(context || {});
}

module.exports = {
  SCHEDULER_PRECONDITION_VALUES,
  PRECONDITION_CHECKS,
  evaluateSchedulerPrecondition,
};
