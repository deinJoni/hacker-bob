"use strict";

// Plane X Cycle X.1 — bob_propose_transition.
//
// Records a TaskGraph Transition-node proposal. Reuses observation.recorded
// with payload.kind: "transition_proposed" per X-P8. The trust_assumption
// prose is bounded at append time (X-P9 / X.1 step 2). The transition_kind
// is restricted to the X-D3 closed enum (identity_propagation,
// value_movement, trust_handoff, state_dependency, oracle_dependency,
// message_passing). X.3 wires the same enum into surface-index's
// "transition" surface kind so the materializer can fold this proposal
// onto a first-class transition node.

const {
  appendTransitionProposal,
  TRANSITION_KIND_VALUES,
  TRANSITION_TRUST_ASSUMPTION_MAX_CHARS,
} = require("../task-graph-events.js");
const {
  scheduleMaterialization,
} = require("../frontier-materialize-debounce.js");

function handler(args) {
  const event = appendTransitionProposal(args || {});
  try {
    scheduleMaterialization(event.target_domain);
  } catch {
    // Materialization debounce is best-effort; do not regress the append.
  }
  return JSON.stringify({
    version: 1,
    appended: true,
    event_id: event.event_id,
    event_hash: event.event_hash,
    kind: event.kind,
    payload_kind: event.payload && event.payload.kind,
    target_domain: event.target_domain,
  });
}

module.exports = Object.freeze({
  name: "bob_propose_transition",
  description:
    "Propose a TaskGraph Transition node bridging two surfaces. Appends an "
    + "observation.recorded frontier event with payload.kind: \"transition_proposed\". "
    + "trust_assumption is capped at "
    + `${TRANSITION_TRUST_ASSUMPTION_MAX_CHARS} characters at append time per X-P9 `
    + "(over → structured prose_too_long error). The transition_kind must be in "
    + "the X-D3 closed enum so the cross-stack brief composer (X.11) can "
    + "select the right hunting vocabulary.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
      },
      from_surface: {
        type: "string",
        description: "Origin surface_id of the proposed transition (e.g. a web auth endpoint).",
      },
      to_surface: {
        type: "string",
        description: "Destination surface_id of the proposed transition (e.g. an EVM contract entrypoint).",
      },
      kind: {
        type: "string",
        enum: [...TRANSITION_KIND_VALUES],
        description: "Transition kind from the X-D3 closed enum.",
      },
      trust_assumption: {
        type: "string",
        description:
          `Statement of the trust hop the transition implies, capped at ${TRANSITION_TRUST_ASSUMPTION_MAX_CHARS} characters. `
          + "Phrase as a falsifiable claim (\"X is recovered server-side and trusted on-chain\").",
      },
      evidence_refs: {
        type: "array",
        items: { type: "string" },
        description: "Optional artifact_ref strings backing the proposal (e.g. http_record:R7).",
      },
      proposal_id: {
        type: "string",
        description: "Optional caller-supplied proposal identifier (e.g. TP-<slug>).",
      },
      ts: { type: "string" },
      source: { type: "object" },
      actor: { type: "string" },
    },
    required: [
      "target_domain",
      "from_surface",
      "to_surface",
      "kind",
      "trust_assumption",
    ],
  },
  handler,
  // X-D10: Hypothesis proposal is allowed for operator OR evaluator;
  // transition proposal mirrors that surface in v1.
  role_bundles: ["orchestrator", "evaluator-shared"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["frontier-events.jsonl"],
});
