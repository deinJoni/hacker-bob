"use strict";

// Lifecycle gate engine. Cycle G.2 of the frontier-topology realization
// hypergraph establishes the bob_advance_session lifecycle machine and
// reserves this module as the place where future cycles (F.3, C.3, C.7)
// hang real prerequisite checks on per-transition gate hooks.
//
// Today the gates are intentionally minimal: every transition listed in
// ALLOWED_TRANSITIONS returns an empty blocker list. The hook architecture
// must exist so later cycles can extend it without rewriting the surface.
//
// Decision D3 from the hypergraph is honored verbatim: OPEN_FRONTIER ⇄
// CLAIM_FREEZE is bidirectional, and REPORT → OPEN_FRONTIER is allowed so
// the operator can re-enter the open frontier from any later state.

const {
  LIFECYCLE_STATE_VALUES,
} = require("./governance-contracts.js");

const ALLOWED_TRANSITIONS = Object.freeze({
  SETUP: Object.freeze(["OPEN_FRONTIER"]),
  OPEN_FRONTIER: Object.freeze(["CLAIM_FREEZE"]),
  CLAIM_FREEZE: Object.freeze(["VERIFY", "OPEN_FRONTIER"]),
  VERIFY: Object.freeze(["GRADE", "OPEN_FRONTIER"]),
  GRADE: Object.freeze(["REPORT", "OPEN_FRONTIER"]),
  REPORT: Object.freeze(["OPEN_FRONTIER"]),
});

// Per-transition gate functions. Each is keyed by `${from}->${to}` and
// receives a context object with the target_domain, the current and target
// lifecycle states, and the persisted session nucleus. The gate returns an
// array of structured blocker entries; an empty array means "transition is
// permitted by this gate".
//
// Cycle G.2 ships the gate architecture; Cycle D.1 retires the legacy
// phase-gates module and migrates the VERIFY -> GRADE freshness check here.
// The gate consults requireVerificationCompleteForGrade and surfaces blocked
// entries that mirror the legacy "VERIFY -> GRADE blocked" message.
const TRANSITION_GATES = Object.freeze({
  "VERIFY->GRADE": gateVerifyToGrade,
  "GRADE->REPORT": gateGradeToReport,
});

function compactError(error) {
  return error && error.message ? error.message : String(error);
}

function gateVerifyToGrade(context) {
  const blockers = [];
  try {
    require("./verification.js").requireVerificationCompleteForGrade(context.target_domain);
  } catch (error) {
    const message = compactError(error);
    const evidenceLike = /Evidence packs|evidence packs|Missing evidence packs|final reportable/i.test(message);
    const prefix = evidenceLike
      ? "evidence packs are missing or invalid for final reportable findings"
      : "verification v2 chain is incomplete or stale";
    blockers.push({
      code: evidenceLike ? "evidence_packs_invalid" : "verification_chain_incomplete",
      blocked_by: "verification_stale",
      message: `VERIFY -> GRADE blocked: ${prefix}: ${message}`,
      error: message,
    });
  }
  return blockers;
}

function gateGradeToReport(context) {
  // GRADE -> REPORT keeps the legacy invariant that final reportable
  // findings have valid evidence packs at advance time. The new finalize-
  // report tool re-verifies the four-hash binding (C.7); this gate keeps
  // the legacy refusal so callers receive a structured blocker before they
  // start writing report.md.
  const blockers = [];
  try {
    require("./verification.js").requireVerificationCompleteForGrade(context.target_domain);
  } catch (error) {
    const message = compactError(error);
    blockers.push({
      code: "evidence_packs_invalid",
      blocked_by: "evidence_incomplete",
      message: `GRADE -> REPORT blocked: ${message}`,
      error: message,
    });
  }
  return blockers;
}

function transitionKey(fromState, toState) {
  return `${fromState}->${toState}`;
}

function isTransitionAllowed(fromState, toState) {
  const targets = ALLOWED_TRANSITIONS[fromState];
  return Array.isArray(targets) && targets.includes(toState);
}

function allowedTargetsFor(fromState) {
  const targets = ALLOWED_TRANSITIONS[fromState];
  return Array.isArray(targets) ? targets.slice() : [];
}

function buildNoTransitionBlocker(fromState, toState) {
  return {
    blocked_by: "no_transition",
    code: "no_transition",
    from: fromState,
    to: toState,
    allowed: allowedTargetsFor(fromState),
    message: `Transition ${fromState} -> ${toState} is not in allowedTransitions`,
  };
}

function runTransitionGate(context) {
  const fromState = context.from_state;
  const toState = context.to_state;
  const gate = TRANSITION_GATES[transitionKey(fromState, toState)];
  if (typeof gate !== "function") return [];
  const result = gate(context);
  if (!Array.isArray(result)) return [];
  return result.filter((entry) => entry && typeof entry === "object");
}

function evaluateLifecycleTransition(context = {}) {
  const fromState = context.from_state;
  const toState = context.to_state;
  if (!LIFECYCLE_STATE_VALUES.includes(fromState)) {
    throw new Error(`unknown from_state: ${fromState}`);
  }
  if (!LIFECYCLE_STATE_VALUES.includes(toState)) {
    throw new Error(`unknown to_state: ${toState}`);
  }
  const blockers = [];
  if (!isTransitionAllowed(fromState, toState)) {
    blockers.push(buildNoTransitionBlocker(fromState, toState));
    // No-transition is a structural rejection; per-transition gates are not
    // consulted for a transition the engine does not recognize.
    return { from_state: fromState, to_state: toState, blockers };
  }
  const gateBlockers = runTransitionGate(context);
  for (const entry of gateBlockers) {
    blockers.push(entry);
  }
  return { from_state: fromState, to_state: toState, blockers };
}

module.exports = {
  ALLOWED_TRANSITIONS,
  TRANSITION_GATES,
  allowedTargetsFor,
  buildNoTransitionBlocker,
  evaluateLifecycleTransition,
  isTransitionAllowed,
  transitionKey,
};
