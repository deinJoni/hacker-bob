"use strict";

// Plane X Cycle X.8 — bob_prepare_node.
//
// The first call of the clou-style three-call protocol (X-D8). Reads the
// dispatched node from the materialized TaskGraph, derives its capability
// pack via X.5 (≤1-hop graph context per X-P5), renders the per-node brief
// via the X.8 `node` profile slice registry (X.8 Do step 1), mints a
// `prep_token` that binds the graph_context_hash so post-dispatch drift is
// detectable (rev 4 X-R15 mitigation), and emits the
// `node.transitioned (contracted | ready) → dispatched` event with the token
// inlined in the payload.
//
// Per X-P9 the brief renderer inlines DISTILLED SUMMARIES of every artifact
// the Contract names — never raw bodies. The agent calls bob_resolve_body
// (X.7) to pull bodies on demand. The `recommended_reads` slice is the X.5
// `recommended_reads_for_node[]` output projected through the resolver
// registry's per-prefix summary (for http_record the matching
// http_record_observed event from the ledger; for repo_check the
// repo_check_observed; for other prefixes a {artifact_ref, ref_kind, hint}
// pointer the agent resolves via bob_resolve_body).
//
// Per X.8 Do step 5 the tests cover:
//   - refuse on state ∉ {contracted, ready}
//   - empty agent_output refused at finalize (tested via finalize)
//   - stale prep_token refused at finalize (tested via finalize)
//   - successful flow with relational_value_match Contract
//   - mechanical-fail flow surfaces structured failure_reason
//   - re-prepare after failed finalize → brief contains prior_attempt slice
//   - graph drift detection via differing graph_context_hash
//   - hypothesis visibility for Surface nodes
//   - recommended_reads inlines DISTILLED SUMMARIES not bodies
//
// Allowed bundles per X.8 Do step 3: orchestrator + graph-scheduler-only.
// The graph-scheduler bundle ships in X.9; v1 here is realized as
// `orchestrator` (the only bundle wired to the operator-facing slash
// command at this point in the plane). X.9 will extend role_bundles[]
// when the dedicated graph-scheduler bundle lands.

const crypto = require("crypto");
const {
  assertNonEmptyString,
} = require("../validation.js");
const {
  assertSafeDomain,
} = require("../paths.js");
const {
  assertTaskGraphNodeId,
  appendNodeTransition,
  findAttachedContract,
  readHypothesisProposals,
  readNodeTransitions,
} = require("../task-graph-events.js");
const {
  materializeTaskGraph,
} = require("../task-graph-materializer.js");
const {
  buildOneHopGraphContext,
  derivePackForNode,
} = require("../capability-pack-derivation.js");
const {
  scheduleMaterialization,
} = require("../frontier-materialize-debounce.js");
const {
  readSurfaceRoutesStrict,
} = require("../surface-router.js");
const {
  isPlainObject,
} = require("../verification-contracts.js");
const {
  readFrontierEvents,
} = require("../frontier-events.js");
const {
  renderNodeBriefExtras,
} = require("../assignment-brief.js");

// X.8 Do step 1: only nodes in state contracted or ready may be prepared.
// `ready` is reserved for X.9's graph-scheduler — the X.4 attach path lands
// the node in `contracted`. Both states are dispatch-legal because the
// frozen state-transition table permits ready → dispatched as well; X.8
// keeps both legal so the X.9 scheduler can dispatch without re-emitting
// an interim transition.
const PREPARE_NODE_LEGAL_STATES = Object.freeze(["contracted", "ready"]);

// Cap the adjacent-observations slice to the most recent N events whose
// surface_id overlaps the dispatched node's surfaces. Per X-P9 the SHAPE of
// each observation is summary-grade at emit-time; we do not re-cap per-event
// text, only the count. The cap defends against pathological session ledgers
// with thousands of identical observations; 32 is enough to land the
// 5 most-touched surface threads without blowing the brief budget.
const ADJACENT_OBSERVATIONS_CAP = 32;

// Cap the prior-attempt failures slice to the most recent K failure events
// for the dispatched node. The failure payload is structured (X.6 verifier
// output) so each entry is bounded; K=3 lets the brief expose the last
// three attempts' verdicts without overwhelming the agent.
const PRIOR_ATTEMPT_CAP = 3;

// Adjacent hypotheses cap. Inline up to N open Hypothesis nodes whose
// surface_refs[] overlaps the dispatched node's surfaces. 8 is generous
// enough to surface every adjacent hypothesis in a typical run and small
// enough to never dominate the brief.
const ADJACENT_HYPOTHESES_CAP = 8;

function structuredError(code, message, details) {
  const err = new Error(`${code}: ${message}`);
  err.code = code;
  if (details) err.details = details;
  return err;
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function safeSurfaceRouteMap(targetDomain) {
  let result;
  try {
    result = readSurfaceRoutesStrict(targetDomain);
  } catch {
    return {};
  }
  const map = {};
  const doc = result && result.document;
  if (!doc || !Array.isArray(doc.routes)) return map;
  for (const route of doc.routes) {
    if (!route || typeof route !== "object") continue;
    const surfaceId = typeof route.surface_id === "string" ? route.surface_id : null;
    if (!surfaceId) continue;
    map[surfaceId] = {
      id: surfaceId,
      surface_type: route.surface_type || null,
      chain_family: route.chain_family || null,
      capability_pack: route.capability_pack || null,
      brief_profile: route.brief_profile || null,
    };
  }
  return map;
}

// Build the ≤1-hop snapshot the X.5 pack derivation expects. Reads the
// materialized graph, walks edges incident to the dispatched node, and
// trims surface metadata to only the surfaces the dispatched + adjacent
// nodes touch (X-P5 bound).
function snapshotOneHopGraphContext({ document, nodeId, surfaceMetadataById }) {
  return buildOneHopGraphContext(document, nodeId, surfaceMetadataById);
}

// graph_context_hash binds the snapshot the agent's reasoning is grounded
// in. The hash is computed over a stable projection (node_ids, kinds,
// states, edges by (from, to, kind), surface_ids in the metadata) so a
// re-prepare after the same materialization produces the same hash.
function computeGraphContextHash(graphContext) {
  if (!isPlainObject(graphContext)) return null;
  const dispatched = graphContext.dispatched_node;
  const projection = {
    dispatched_node: dispatched
      ? {
        node_id: dispatched.node_id,
        kind: dispatched.kind,
        state: dispatched.state,
        contract_hash: dispatched.contract_hash || null,
        surface_refs: Array.isArray(dispatched.surface_refs)
          ? dispatched.surface_refs.slice().sort()
          : [],
      }
      : null,
    adjacent_nodes: (graphContext.adjacent_nodes || []).map((node) => ({
      node_id: node.node_id,
      kind: node.kind,
      state: node.state,
      surface_refs: Array.isArray(node.surface_refs)
        ? node.surface_refs.slice().sort()
        : [],
    })),
    incident_edges: (graphContext.incident_edges || []).map((edge) => ({
      from_node_id: edge.from_node_id,
      to_node_id: edge.to_node_id,
      edge_kind: edge.edge_kind,
    })),
    surface_metadata_keys: Object.keys(graphContext.surface_metadata_by_id || {}).sort(),
  };
  return sha256Hex(JSON.stringify(projection));
}

function findNodeInDocument(document, nodeId) {
  if (!document || !Array.isArray(document.nodes)) return null;
  for (const node of document.nodes) {
    if (node && node.node_id === nodeId) return node;
  }
  return null;
}

// Collect prior failed transitions for a node (Do step 1 prior_attempt
// slice). Returns the most recent PRIOR_ATTEMPT_CAP entries in
// reverse-chronological order (most-recent-first) so the brief renderer
// can lead with the latest failure.
function collectPriorAttempts(targetDomain, nodeId) {
  const events = readNodeTransitions(targetDomain);
  const failed = [];
  for (const event of events) {
    if (!event || !event.payload) continue;
    if (event.payload.node_id !== nodeId) continue;
    if (event.payload.to_state !== "failed") continue;
    failed.push({
      event_id: event.event_id,
      ts: event.ts,
      from_state: event.payload.from_state,
      failure_reason: event.payload.failure_reason || null,
      verification: event.payload.verification || null,
      prep_token: event.payload.prep_token_hash || null,
    });
  }
  failed.sort((a, b) => (b.ts || "").localeCompare(a.ts || ""));
  return failed.slice(0, PRIOR_ATTEMPT_CAP);
}

// Collect adjacent observations: observation.recorded events whose
// surface_id matches one of the dispatched node's surface_refs. Capped at
// ADJACENT_OBSERVATIONS_CAP (per X-P9 the SHAPE of each event is summary-
// grade; the cap defends against pathological session ledgers).
function collectAdjacentObservations(targetDomain, dispatchedNode) {
  if (!dispatchedNode) return [];
  const surfaces = Array.isArray(dispatchedNode.surface_refs)
    ? new Set(dispatchedNode.surface_refs.filter((s) => typeof s === "string"))
    : new Set();
  if (surfaces.size === 0) return [];
  const events = readFrontierEvents(targetDomain);
  const matched = [];
  for (const event of events) {
    if (!event || event.kind !== "observation.recorded") continue;
    const surfaceId = event.surface_id
      || (event.payload && typeof event.payload.surface_id === "string" ? event.payload.surface_id : null);
    if (surfaceId && surfaces.has(surfaceId)) {
      matched.push({
        event_id: event.event_id,
        ts: event.ts,
        surface_id: surfaceId,
        payload: event.payload || {},
      });
    }
  }
  // Most-recent-first so the brief leads with the latest observation.
  matched.sort((a, b) => (b.ts || "").localeCompare(a.ts || ""));
  return matched.slice(0, ADJACENT_OBSERVATIONS_CAP);
}

// Collect open Hypothesis nodes (state: proposed) whose surface_refs[]
// overlap the dispatched node's surface_refs[] OR adjacent-surface ids.
// Per the spec this slice is conditional: emitted for Surface AND
// Transition nodes (X.8 Do step 1) so the cross-stack composition (X.11)
// can pick it up. Hypothesis nodes themselves don't surface adjacent
// hypotheses (they ARE hypotheses; the brief renders the node's own
// statement separately via the contract slice).
function collectAdjacentHypotheses(document, dispatchedNode) {
  if (!dispatchedNode) return [];
  if (dispatchedNode.kind !== "surface" && dispatchedNode.kind !== "transition") return [];
  const wantSurfaces = new Set();
  if (Array.isArray(dispatchedNode.surface_refs)) {
    for (const ref of dispatchedNode.surface_refs) {
      if (typeof ref === "string") wantSurfaces.add(ref);
    }
  }
  // Also include adjacent surfaces via the document's edges.
  if (document && Array.isArray(document.edges)) {
    for (const edge of document.edges) {
      if (!edge) continue;
      if (edge.from_node_id === dispatchedNode.node_id) {
        const adj = findNodeInDocument(document, edge.to_node_id);
        if (adj && Array.isArray(adj.surface_refs)) {
          for (const ref of adj.surface_refs) {
            if (typeof ref === "string") wantSurfaces.add(ref);
          }
        }
      }
      if (edge.to_node_id === dispatchedNode.node_id) {
        const adj = findNodeInDocument(document, edge.from_node_id);
        if (adj && Array.isArray(adj.surface_refs)) {
          for (const ref of adj.surface_refs) {
            if (typeof ref === "string") wantSurfaces.add(ref);
          }
        }
      }
    }
  }
  if (wantSurfaces.size === 0) return [];
  const hypotheses = [];
  if (document && Array.isArray(document.nodes)) {
    for (const node of document.nodes) {
      if (!node || node.kind !== "hypothesis") continue;
      if (node.state !== "proposed") continue;
      const surfaceRefs = Array.isArray(node.surface_refs) ? node.surface_refs : [];
      const overlaps = surfaceRefs.some((ref) => wantSurfaces.has(ref));
      if (overlaps) hypotheses.push(node);
    }
  }
  // Look up the hypothesis_statement from the proposal events so the brief
  // can show the conjecture text — the materializer doesn't carry it.
  const proposalByNodeId = new Map();
  for (const proposal of readHypothesisProposals(getDomainFromDocument(document))) {
    const proposalId = proposal.payload && typeof proposal.payload.proposal_id === "string"
      ? proposal.payload.proposal_id
      : null;
    if (!proposalId) continue;
    proposalByNodeId.set(`TG-H-${proposalId}`, proposal);
  }
  const out = [];
  for (const node of hypotheses) {
    const proposal = proposalByNodeId.get(node.node_id);
    const statement = proposal && proposal.payload && typeof proposal.payload.hypothesis_statement === "string"
      ? proposal.payload.hypothesis_statement
      : null;
    out.push({
      node_id: node.node_id,
      surface_refs: node.surface_refs.slice().sort(),
      hypothesis_statement: statement,
    });
    if (out.length >= ADJACENT_HYPOTHESES_CAP) break;
  }
  return out;
}

// Pull the target_domain off a materialized document. Documents always
// carry it; defensive default so a malformed test fixture doesn't crash.
function getDomainFromDocument(document) {
  return document && typeof document.target_domain === "string" ? document.target_domain : null;
}

// Resolve the distilled summary for a given artifact_ref. The summary is
// the SHAPE-bounded brief-inlinable form. For prefixes that emit an
// observation.recorded summary event at write-time (http_record_observed,
// repo_check_observed, etc.) we look up the matching event by ref_id and
// return its payload. For prefixes without a paired summary event
// (finding, evidence_pack, frontier_event, evm_call) we return a typed
// pointer the agent resolves via bob_resolve_body. Per X-P9 the brief
// renderer NEVER inlines a body — bodies are pull-only.
function resolveRecommendedReadSummary(targetDomain, artifactRef, ledgerEvents) {
  if (typeof artifactRef !== "string" || !artifactRef.includes(":")) {
    return { artifact_ref: artifactRef, kind: null, summary: null };
  }
  const idx = artifactRef.indexOf(":");
  const prefix = artifactRef.slice(0, idx);
  const refId = artifactRef.slice(idx + 1);
  // For http_record_observed-style summaries, scan the cached ledger
  // events for the matching payload. The caller passes ledgerEvents to
  // avoid re-reading the JSONL once per ref.
  if (prefix === "http_record") {
    for (const event of ledgerEvents) {
      if (event.kind !== "observation.recorded") continue;
      if (!event.payload) continue;
      if (event.payload.observation_kind !== "http_record_observed") continue;
      if (event.payload.request_id !== refId) continue;
      return {
        artifact_ref: artifactRef,
        kind: "http_record_observed",
        summary: event.payload,
      };
    }
    return {
      artifact_ref: artifactRef,
      kind: "http_record",
      summary: { request_id: refId, hint: "call bob_resolve_body(http_record:<request_id>) for the body" },
    };
  }
  // Other prefixes: typed pointer with a hint. The agent calls
  // bob_resolve_body to pull the body. We do not inline anything else.
  return {
    artifact_ref: artifactRef,
    kind: prefix,
    summary: { ref_id: refId, hint: `call bob_resolve_body(${artifactRef}) for the body` },
  };
}

// Build the brief context bag the NODE_BRIEF_SLICE_REGISTRY consumes.
function buildBriefContext({
  targetDomain,
  document,
  dispatchedNode,
  contract,
  pack,
  graphContext,
  graphContextHash,
}) {
  const surfaces = Array.isArray(dispatchedNode.surface_refs)
    ? dispatchedNode.surface_refs.slice().sort()
    : [];

  const governance = {
    target_domain: targetDomain,
    plane: "X",
    cycle: "X.8",
    discipline: [
      "X-P1: TaskGraph is the dispatch authority for Transition + Hypothesis nodes.",
      "X-P2: Every node carries a Contract before dispatch.",
      "X-P3: Mechanical verifier runs FIRST; LLM adjudication runs ONLY if mechanical passes.",
      "X-P9: Brief renderers inline DISTILLED SUMMARIES. Bodies are pull-only via bob_resolve_body.",
    ],
  };

  const nodeContext = {
    node_id: dispatchedNode.node_id,
    kind: dispatchedNode.kind,
    state: dispatchedNode.state,
    surface_refs: surfaces,
    contract_hash: dispatchedNode.contract_hash || null,
    severity_floor: contract ? contract.severity_floor : (dispatchedNode.severity_floor || null),
    priority: dispatchedNode.priority || null,
    graph_context_hash: graphContextHash,
    materialized_at: document.materialized_at,
    ts_first: dispatchedNode.ts_first,
    ts_last: dispatchedNode.ts_last,
  };

  // Inline the full Contract — already distilled per X-D4 + X-P9.
  const contractSlice = contract ? {
    contract_id: contract.contract_id,
    contract_hash: contract.contract_hash,
    severity_floor: contract.severity_floor,
    invariants: contract.invariants,
    witnesses: contract.witnesses,
    production_paths: contract.production_paths,
  } : null;

  const allowedToolsForNode = {
    constraint: "The mechanical verifier (X.6) records a tool_constraint_violation when a tool outside this set is invoked. The finalize call WILL reject if any out-of-band tool appears in agent_output.tool_invocations.",
    allowed_tools: pack.allowed_tools_for_node.slice().sort(),
    positive_example: pack.allowed_tools_for_node.length > 0
      ? `INVOKE: ${pack.allowed_tools_for_node[0]}`
      : "INVOKE: <see allowed_tools>",
    negative_example: "REFUSED: any tool not in allowed_tools (e.g., bob_init_session — orchestrator-only)",
  };

  // recommended_reads slice: pull the distilled summary for each artifact_ref
  // in the pack's recommended_reads_for_node[]. Per X-P9 we inline SUMMARIES
  // not BODIES. The agent calls bob_resolve_body if they need the body.
  const ledgerEvents = readFrontierEvents(targetDomain);
  const recommendedReadsEntries = (pack.recommended_reads_for_node || []).map(
    (ref) => resolveRecommendedReadSummary(targetDomain, ref, ledgerEvents),
  );
  const recommendedReads = {
    refs: recommendedReadsEntries,
    discipline: "Each entry is a DISTILLED SUMMARY per X-P9. Call bob_resolve_body(<artifact_ref>) for the full body.",
    count: recommendedReadsEntries.length,
  };

  const adjacentObservationsList = collectAdjacentObservations(targetDomain, dispatchedNode);
  const adjacentObservations = {
    events: adjacentObservationsList,
    discipline: "Each event is already summary-grade per X-P9 (Plane T/O emit discipline). No top-N cap on per-event text.",
    count: adjacentObservationsList.length,
    cap: ADJACENT_OBSERVATIONS_CAP,
  };

  const priorAttemptsList = collectPriorAttempts(targetDomain, dispatchedNode.node_id);
  const priorAttempt = priorAttemptsList.length > 0
    ? {
      attempts: priorAttemptsList,
      discipline: "Most recent failures listed first. The structured failure_reason carries witness ids, extracted values (for relational_value_match), and the failing predicate refs. Use this to refine the Contract or the production path.",
      count: priorAttemptsList.length,
      cap: PRIOR_ATTEMPT_CAP,
    }
    : "";

  const adjacentHypothesesList = collectAdjacentHypotheses(document, dispatchedNode);
  const adjacentHypotheses = adjacentHypothesesList.length > 0
    ? {
      hypotheses: adjacentHypothesesList,
      discipline: "If you find evidence touching one of these hypotheses, refine its Contract via bob_attach_contract and propose the next dispatch.",
      count: adjacentHypothesesList.length,
      cap: ADJACENT_HYPOTHESES_CAP,
    }
    : "";

  const recapAndHandoff = {
    next_steps: [
      "Execute the production_paths in the Contract against the dispatched node.",
      "Capture evidence via the appropriate evidence-emitting tools.",
      "Return your agent_output as a structured object; the finalize-node call runs the mechanical verifier first, then queues adjudication only if it passes.",
    ],
    contract_hash: contract ? contract.contract_hash : null,
    graph_context_hash: graphContextHash,
    drift_check: "Call bob_read_task_graph mid-run; if the live graph_context_hash differs from this brief's, re-prepare before continuing.",
  };

  return {
    governance,
    nodeContext,
    contract: contractSlice,
    allowedToolsForNode,
    recommendedReads,
    adjacentObservations,
    priorAttempt,
    adjacentHypotheses,
    recapAndHandoff,
  };
}

function handler(args) {
  const input = args || {};
  const domain = assertSafeDomain(
    assertNonEmptyString(input.target_domain, "target_domain"),
  );
  const nodeId = assertTaskGraphNodeId(input.node_id, "node_id");

  const result = materializeTaskGraph(domain, { write: false });
  const document = result.document;
  const dispatchedNode = findNodeInDocument(document, nodeId);
  if (!dispatchedNode) {
    throw structuredError(
      "unknown_node",
      `node ${nodeId} is not present in the materialized task-graph`,
      { node_id: nodeId },
    );
  }
  if (!PREPARE_NODE_LEGAL_STATES.includes(dispatchedNode.state)) {
    throw structuredError(
      "node_not_dispatch_ready",
      `node ${nodeId} is in state "${dispatchedNode.state}"; prepare-node requires one of ${PREPARE_NODE_LEGAL_STATES.join(", ")}`,
      {
        node_id: nodeId,
        current_state: dispatchedNode.state,
        legal_states: PREPARE_NODE_LEGAL_STATES.slice(),
      },
    );
  }

  // Recover the Contract. The materializer carries the contract_hash on
  // the node; the full content lives on the proposed → contracted
  // node.transitioned event payload (X.4 + X.8 appendContract extension).
  const attached = findAttachedContract(domain, nodeId);
  if (!attached || !attached.contract) {
    throw structuredError(
      "contract_not_attached",
      `node ${nodeId} has no attached Contract; call bob_attach_contract first`,
      { node_id: nodeId, contract_hash: dispatchedNode.contract_hash || null },
    );
  }

  // Build the ≤1-hop graph context and derive the per-node pack.
  const surfaceMetadataById = safeSurfaceRouteMap(domain);
  const graphContext = snapshotOneHopGraphContext({
    document,
    nodeId,
    surfaceMetadataById,
  });
  const graphContextHash = computeGraphContextHash(graphContext);
  const pack = derivePackForNode(
    dispatchedNode,
    graphContext,
    [], // observation_history — adjacent observations folded in the brief context separately
    attached.contract,
  );

  // Assemble the brief.
  const briefContext = buildBriefContext({
    targetDomain: domain,
    document,
    dispatchedNode,
    contract: attached.contract,
    pack,
    graphContext,
    graphContextHash,
  });
  const briefExtras = renderNodeBriefExtras(briefContext);
  const brief = {
    version: 1,
    profile: "node",
    target_domain: domain,
    node_id: nodeId,
    materialized_at: document.materialized_at,
    graph_context_hash: graphContextHash,
    ...briefExtras,
  };
  const briefJson = JSON.stringify(brief);
  const briefHash = sha256Hex(briefJson);

  // Mint the prep_token. The token binds node_id + contract_hash + brief_hash
  // + materialized_at + graph_context_hash so any drift in the underlying
  // snapshot invalidates the token at finalize.
  const prepToken = sha256Hex([
    nodeId,
    attached.contract.contract_hash,
    briefHash,
    document.materialized_at,
    graphContextHash,
  ].join("|"));

  // Emit the node.transitioned events. The X.1 frozen table requires
  // contracted → ready → dispatched (the table forbids a direct
  // contracted → dispatched). When the node arrives in `contracted`,
  // prepare_node first promotes it to `ready` (the auxiliary transition
  // the X.9 graph scheduler would otherwise emit) and then immediately
  // emits the canonical ready → dispatched with the prep_token. When the
  // node is already in `ready` (the X.9 path) we skip the promotion.
  if (dispatchedNode.state === "contracted") {
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "contracted",
      to_state: "ready",
      contract_hash: attached.contract.contract_hash,
      ts: input.ts,
      source: { tool: "bob_prepare_node", reason: "auto_promote_for_dispatch" },
      actor: input.actor,
    });
  }
  const event = appendNodeTransition({
    target_domain: domain,
    node_id: nodeId,
    from_state: "ready",
    to_state: "dispatched",
    contract_hash: attached.contract.contract_hash,
    prep_token_hash: prepToken,
    ts: input.ts,
    source: { tool: "bob_prepare_node" },
    actor: input.actor,
  });

  try {
    scheduleMaterialization(domain);
  } catch {
    // Best-effort materialization debounce; do not regress the append.
  }

  return JSON.stringify({
    version: 1,
    target_domain: domain,
    node_id: nodeId,
    prep_token: prepToken,
    brief_hash: briefHash,
    graph_context_hash: graphContextHash,
    materialized_at: document.materialized_at,
    contract_hash: attached.contract.contract_hash,
    allowed_tools_for_node: pack.allowed_tools_for_node.slice().sort(),
    recommended_reads_for_node: pack.recommended_reads_for_node.slice(),
    technique_pack_ids: pack.technique_packs.map((p) => p.id),
    brief,
    event_id: event.event_id,
    event_hash: event.event_hash,
    to_state: event.payload.to_state,
  });
}

module.exports = Object.freeze({
  name: "bob_prepare_node",
  description:
    "Prepare a TaskGraph node for dispatch (clou-style three-call protocol, "
    + "first call). Reads the node from the materialized task-graph, derives "
    + "its capability pack via X.5 (≤1-hop graph context per X-P5), renders "
    + "the per-node brief via the X.8 `node` profile slice registry, and mints "
    + "a prep_token binding node_id + contract_hash + brief_hash + "
    + "materialized_at + graph_context_hash so post-dispatch drift is "
    + "detectable. Emits node.transitioned (contracted | ready) → dispatched "
    + "with prep_token in payload. Per X-P9 the brief inlines DISTILLED "
    + "SUMMARIES of recommended_reads — never bodies; the agent calls "
    + "bob_resolve_body for bodies. Refuses on state ∉ {contracted, ready} or "
    + "when no Contract is attached. Orchestrator + graph-scheduler only (X.9 "
    + "ships the graph-scheduler bundle).",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      node_id: {
        type: "string",
        description:
          "TaskGraph node id (TG-<prefix>-<slug>). Must be in state \"contracted\" or \"ready\".",
      },
      ts: { type: "string" },
      actor: { type: "string" },
    },
    required: ["target_domain", "node_id"],
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["frontier-events.jsonl"],
});
