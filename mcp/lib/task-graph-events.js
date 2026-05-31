"use strict";

// Plane X Cycle X.1 — TaskGraph event-ledger wrappers.
//
// Per X-P1 the TaskGraph is the dispatch authority for Transition and
// Hypothesis nodes (Surface and Claim continue to dispatch through the
// wave-scheduler unchanged per X-D7). Per X-P8 the ledger gains ONE new
// top-level frontier event kind (`node.transitioned`); proposal events
// reuse the existing `observation.recorded` framework with typed
// `payload.kind` values.
//
// This module is the only sanctioned writer for the three kinds of
// TaskGraph events:
//
//   1. appendNodeTransition           → kind: "node.transitioned"
//   2. appendTransitionProposal       → kind: "observation.recorded" with
//                                       payload.kind: "transition_proposed"
//   3. appendHypothesisProposal       → kind: "observation.recorded" with
//                                       payload.kind: "hypothesis_proposed"
//
// All three honor X-P9 (storage-distilled emission): payloads are
// natively summary-grade (IDs, hashes, structured failure_reason, prose
// bounded at ≤512 chars). Bodies do not live in these events.

const {
  appendFrontierEvent,
  readFrontierEvents,
} = require("./frontier-events.js");
const {
  assertEnumValue,
  assertNonEmptyString,
  normalizeOptionalText,
  normalizeStringArray,
} = require("./validation.js");
const {
  normalizeId,
  normalizeOptionalId,
  normalizeOptionalObject,
} = require("./fabric-common.js");

// Plane X Target Vocabulary: state ∈ {proposed, contracted, ready,
// dispatched, executed, verified, finalized, failed, abandoned}.
const NODE_STATE_VALUES = Object.freeze([
  "proposed",
  "contracted",
  "ready",
  "dispatched",
  "executed",
  "verified",
  "finalized",
  "failed",
  "abandoned",
]);

// X.1 Do step 4: the frozen state-transition table.
// Append-time enforcement: any (from_state, to_state) pair outside this
// table is refused with a structured `invalid_node_transition` error.
const NODE_STATE_TRANSITIONS = Object.freeze({
  proposed: Object.freeze(["contracted", "abandoned"]),
  contracted: Object.freeze(["ready", "abandoned"]),
  ready: Object.freeze(["dispatched", "abandoned"]),
  dispatched: Object.freeze(["executed", "failed"]),
  executed: Object.freeze(["verified", "failed"]),
  verified: Object.freeze(["finalized", "failed"]),
  // Terminal states have no successors. They appear as legal from_states
  // (so isAllowedNodeTransition can return false) but never as to_states
  // for any other state in the table above.
  finalized: Object.freeze([]),
  failed: Object.freeze([]),
  abandoned: Object.freeze([]),
});

// X-D3 closed enum of transition surface kinds. Imported here so the
// proposal-tool input schema and the wrapper both share one source of
// truth. The X.3 cycle wires this enum into the surface-index "transition"
// surface kind; X.1 references it from the proposal wrapper so a caller
// cannot record an undefined transition kind even before X.3 ships.
const TRANSITION_KIND_VALUES = Object.freeze([
  "identity_propagation",
  "value_movement",
  "trust_handoff",
  "state_dependency",
  "oracle_dependency",
  "message_passing",
]);

// Per X-P9 the spec caps two text fields at append-time so brief renderers
// can inline them without a render-time budget. Hard cap is 512 chars; over
// the cap surfaces a structured `prose_too_long` error.
const TRANSITION_TRUST_ASSUMPTION_MAX_CHARS = 512;
const HYPOTHESIS_STATEMENT_MAX_CHARS = 512;

// Node identifiers in the TaskGraph plane carry a `TG-` prefix. The
// pre-flight sweep noted that mcp/lib/surface-graph.js uses generic
// `node_id` strings for an unrelated surface-adjacency graph; the prefix
// disambiguates which graph a given id belongs to in tool descriptions,
// in agent reasoning, and in any cross-tool join.
const TASK_GRAPH_NODE_ID_PREFIX = "TG-";
const TASK_GRAPH_NODE_ID_PATTERN = /^TG-[A-Za-z0-9][A-Za-z0-9._:-]{0,128}$/;

function assertTaskGraphNodeId(value, fieldName = "node_id") {
  const text = assertNonEmptyString(value, fieldName);
  if (!TASK_GRAPH_NODE_ID_PATTERN.test(text)) {
    throw new Error(
      `${fieldName} must match ${TASK_GRAPH_NODE_ID_PREFIX}<id> (received: ${text})`,
    );
  }
  return text;
}

function assertSurfaceRef(value, fieldName) {
  // Surface refs are arbitrary strings minted by surface discovery (e.g.
  // "surface:billing-profile"). They are not TaskGraph node ids and they
  // intentionally do NOT carry the TG- prefix.
  return normalizeId(value, fieldName);
}

function isAllowedNodeTransition(fromState, toState) {
  const successors = NODE_STATE_TRANSITIONS[fromState];
  return Array.isArray(successors) && successors.includes(toState);
}

function assertNodeTransitionAllowed(fromState, toState) {
  if (!isAllowedNodeTransition(fromState, toState)) {
    const err = new Error(
      `invalid_node_transition: ${fromState} -> ${toState} is not in the frozen state-transition table`,
    );
    err.code = "invalid_node_transition";
    err.details = {
      from_state: fromState,
      to_state: toState,
      allowed_from_state: NODE_STATE_TRANSITIONS[fromState]
        ? NODE_STATE_TRANSITIONS[fromState].slice()
        : [],
    };
    throw err;
  }
}

function assertProseUnderCap(value, fieldName, maxChars) {
  if (typeof value !== "string") {
    throw new Error(`${fieldName} must be a string`);
  }
  // Cap is applied to the trimmed value because trailing whitespace
  // (especially the trailing newline that lots of editors append) is not
  // semantically meaningful and would otherwise lead to confusing
  // off-by-one prose-cap violations for human authors.
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  if (trimmed.length > maxChars) {
    const err = new Error(
      `prose_too_long: ${fieldName} length ${trimmed.length} exceeds cap ${maxChars}`,
    );
    err.code = "prose_too_long";
    err.details = {
      field: fieldName,
      length: trimmed.length,
      max_chars: maxChars,
    };
    throw err;
  }
  return trimmed;
}

// Append a node-state-machine transition. Caller passes the full
// from_state → to_state pair so the frozen table can refuse out-of-order
// transitions without first reading the ledger. Payload structure is the
// X-D1 schema: {node_id, from_state, to_state, contract_hash?, prep_token?,
// output_hash?, failure_reason?, edge_added_to[]}.
function appendNodeTransition(input, options = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("appendNodeTransition input must be an object");
  }
  const nodeId = assertTaskGraphNodeId(input.node_id, "node_id");
  const fromState = assertEnumValue(input.from_state, NODE_STATE_VALUES, "from_state");
  const toState = assertEnumValue(input.to_state, NODE_STATE_VALUES, "to_state");
  assertNodeTransitionAllowed(fromState, toState);

  const contractHash = normalizeOptionalText(input.contract_hash, "contract_hash");
  const prepToken = normalizeOptionalText(input.prep_token, "prep_token");
  const outputHash = normalizeOptionalText(input.output_hash, "output_hash");
  const failureReason = normalizeOptionalObject(input.failure_reason, "failure_reason");
  const edgeAddedTo = normalizeStringArray(input.edge_added_to, "edge_added_to")
    .map((edge) => assertTaskGraphNodeId(edge, "edge_added_to[]"));

  const payload = {
    node_id: nodeId,
    from_state: fromState,
    to_state: toState,
  };
  if (contractHash) payload.contract_hash = contractHash;
  if (prepToken) payload.prep_token = prepToken;
  if (outputHash) payload.output_hash = outputHash;
  if (failureReason) payload.failure_reason = failureReason;
  if (edgeAddedTo.length > 0) payload.edge_added_to = edgeAddedTo;

  const source = normalizeOptionalObject(input.source, "source");
  const actor = normalizeOptionalText(input.actor, "actor");

  return appendFrontierEvent({
    target_domain: input.target_domain,
    kind: "node.transitioned",
    ts: input.ts,
    payload,
    source: source || undefined,
    actor: actor || undefined,
    // node.transitioned events do not have a surface_id, frontier_item_id,
    // task_id, or claim_id. The materializer (X.2) joins via payload.node_id
    // → node.surface_refs[] folded from the proposal event.
  }, options);
}

// Append a transition-proposed observation. Reuses observation.recorded
// per X-D1 / X-P8. trust_assumption is the only free-form prose field;
// capped at TRANSITION_TRUST_ASSUMPTION_MAX_CHARS (X.1 step 2) so the
// rev-4 storage-distilled emission discipline (X-P9) holds at append time.
function appendTransitionProposal(input, options = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("appendTransitionProposal input must be an object");
  }
  const fromSurface = assertSurfaceRef(input.from_surface, "from_surface");
  const toSurface = assertSurfaceRef(input.to_surface, "to_surface");
  if (fromSurface === toSurface) {
    throw new Error("from_surface and to_surface must differ");
  }
  const transitionKind = assertEnumValue(input.kind, TRANSITION_KIND_VALUES, "kind");
  const trustAssumption = assertProseUnderCap(
    input.trust_assumption,
    "trust_assumption",
    TRANSITION_TRUST_ASSUMPTION_MAX_CHARS,
  );
  const evidenceRefs = normalizeStringArray(input.evidence_refs, "evidence_refs");
  const proposalId = normalizeOptionalId(input.proposal_id, "proposal_id");

  const payload = {
    kind: "transition_proposed",
    from_surface: fromSurface,
    to_surface: toSurface,
    transition_kind: transitionKind,
    trust_assumption: trustAssumption,
  };
  if (evidenceRefs.length > 0) payload.evidence_refs = evidenceRefs;
  if (proposalId) payload.proposal_id = proposalId;

  const source = normalizeOptionalObject(input.source, "source");
  const actor = normalizeOptionalText(input.actor, "actor");

  return appendFrontierEvent({
    target_domain: input.target_domain,
    kind: "observation.recorded",
    ts: input.ts,
    payload,
    source: source || undefined,
    actor: actor || undefined,
  }, options);
}

// Append a hypothesis-proposed observation. hypothesis_statement is the
// only free-form prose field; capped at HYPOTHESIS_STATEMENT_MAX_CHARS so
// briefs that inline it (X.8 adjacent_hypotheses slice; X.11 cross-stack
// composition) stay summary-grade by construction per X-P9.
function appendHypothesisProposal(input, options = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("appendHypothesisProposal input must be an object");
  }
  const hypothesisStatement = assertProseUnderCap(
    input.hypothesis_statement,
    "hypothesis_statement",
    HYPOTHESIS_STATEMENT_MAX_CHARS,
  );
  const surfaceRefs = normalizeStringArray(input.surface_refs, "surface_refs")
    .map((ref) => assertSurfaceRef(ref, "surface_refs[]"));
  if (surfaceRefs.length === 0) {
    throw new Error("surface_refs must contain at least one surface_id");
  }
  const suggestedContract = normalizeOptionalObject(input.suggested_contract, "suggested_contract");
  const proposalId = normalizeOptionalId(input.proposal_id, "proposal_id");

  const payload = {
    kind: "hypothesis_proposed",
    hypothesis_statement: hypothesisStatement,
    surface_refs: surfaceRefs,
  };
  if (suggestedContract) payload.suggested_contract = suggestedContract;
  if (proposalId) payload.proposal_id = proposalId;

  const source = normalizeOptionalObject(input.source, "source");
  const actor = normalizeOptionalText(input.actor, "actor");

  return appendFrontierEvent({
    target_domain: input.target_domain,
    kind: "observation.recorded",
    ts: input.ts,
    payload,
    source: source || undefined,
    actor: actor || undefined,
  }, options);
}

// Reader helpers. The materializer (X.2) will subsume most of these but
// during X.1 the proposal-tool tests need a lightweight projection that
// returns only the TaskGraph-flavored events without re-decoding every
// observation.recorded payload by hand.
function readNodeTransitions(targetDomain) {
  return readFrontierEvents(targetDomain)
    .filter((event) => event.kind === "node.transitioned");
}

function readTransitionProposals(targetDomain) {
  return readFrontierEvents(targetDomain)
    .filter((event) => (
      event.kind === "observation.recorded"
      && event.payload
      && event.payload.kind === "transition_proposed"
    ));
}

function readHypothesisProposals(targetDomain) {
  return readFrontierEvents(targetDomain)
    .filter((event) => (
      event.kind === "observation.recorded"
      && event.payload
      && event.payload.kind === "hypothesis_proposed"
    ));
}

module.exports = {
  HYPOTHESIS_STATEMENT_MAX_CHARS,
  NODE_STATE_TRANSITIONS,
  NODE_STATE_VALUES,
  TASK_GRAPH_NODE_ID_PATTERN,
  TASK_GRAPH_NODE_ID_PREFIX,
  TRANSITION_KIND_VALUES,
  TRANSITION_TRUST_ASSUMPTION_MAX_CHARS,
  appendHypothesisProposal,
  appendNodeTransition,
  appendTransitionProposal,
  assertNodeTransitionAllowed,
  assertTaskGraphNodeId,
  isAllowedNodeTransition,
  readHypothesisProposals,
  readNodeTransitions,
  readTransitionProposals,
};
