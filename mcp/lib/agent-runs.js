"use strict";

const {
  assertEnumValue,
  normalizeOptionalText,
} = require("./validation.js");
const {
  assertSafeDomain,
  agentRunsJsonlPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("./storage.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  validateHandoffProvenance,
} = require("./wave-handoff-contracts.js");
const {
  normalizeId,
  normalizeIsoTimestamp,
  normalizeOptionalId,
  normalizeOptionalObject,
  normalizeReferenceArray,
  readJsonlStrict,
  withDocumentHash,
} = require("./fabric-common.js");

const AGENT_RUN_VERSION = 1;
const AGENT_RUN_STATUSES = Object.freeze(["assigned", "running", "completed", "failed", "abandoned", "settled"]);
const AGENT_RUNS_MAX_RECORDS = 20000;

function generatedAgentRunId(fields) {
  return `AR-${hashCanonicalJson(fields).slice(0, 24)}`;
}

function normalizeAgentRun(input, { targetDomain = null, now = new Date() } = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("agent run must be an object");
  }
  const domain = assertSafeDomain(input.target_domain || targetDomain);
  const status = assertEnumValue(input.status || "assigned", AGENT_RUN_STATUSES, "status");
  const taskId = normalizeId(input.task_id, "task_id");
  const agentId = normalizeId(input.agent_id || input.agent, "agent_id");
  const startedAt = normalizeIsoTimestamp(input.started_at || input.ts, "started_at", now);
  const base = {
    version: AGENT_RUN_VERSION,
    target_domain: domain,
    task_id: taskId,
    agent_id: agentId,
    status,
    started_at: startedAt,
  };

  const endedAt = input.ended_at == null ? null : normalizeIsoTimestamp(input.ended_at, "ended_at", null);
  const assignmentId = normalizeOptionalId(input.assignment_id, "assignment_id");
  const contextSliceHash = normalizeOptionalText(input.context_slice_hash, "context_slice_hash");
  const summary = normalizeOptionalText(input.summary, "summary");
  const failureReason = normalizeOptionalText(input.failure_reason, "failure_reason");
  const inputRefs = normalizeReferenceArray(input.input_refs, "input_refs");
  const outputRefs = normalizeReferenceArray(input.output_refs, "output_refs");
  const handoffRefs = normalizeReferenceArray(input.handoff_refs, "handoff_refs");
  const metrics = normalizeOptionalObject(input.metrics, "metrics");

  if (endedAt) base.ended_at = endedAt;
  if (assignmentId) base.assignment_id = assignmentId;
  if (contextSliceHash) base.context_slice_hash = contextSliceHash;
  if (summary) base.summary = summary;
  if (failureReason) base.failure_reason = failureReason;
  if (inputRefs.length > 0) base.input_refs = inputRefs;
  if (outputRefs.length > 0) base.output_refs = outputRefs;
  if (handoffRefs.length > 0) base.handoff_refs = handoffRefs;
  if (metrics) base.metrics = metrics;

  const runId = normalizeOptionalId(input.agent_run_id, "agent_run_id") || generatedAgentRunId(base);
  return withDocumentHash({
    agent_run_id: runId,
    ...base,
  }, "agent_run_hash");
}

function appendAgentRun(input, options = {}) {
  const run = normalizeAgentRun(input, options);
  return withSessionLock(run.target_domain, () => {
    appendJsonlLine(agentRunsJsonlPath(run.target_domain), run, {
      maxRecords: options.maxRecords == null ? AGENT_RUNS_MAX_RECORDS : options.maxRecords,
    });
    return run;
  });
}

function readAgentRuns(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  return readJsonlStrict(
    agentRunsJsonlPath(domain),
    "agent-runs.jsonl",
    (record) => normalizeAgentRun(record, { targetDomain: domain, now: null }),
  );
}

function signedHandoffReference(handoff, provenance) {
  const signature = handoff && handoff.provenance_signature;
  return {
    kind: "signed_handoff",
    provenance,
    provenance_model: handoff.provenance_model,
    provenance_assignment_hash: handoff.provenance_assignment_hash,
    signature_digest: signature && typeof signature.digest === "string" ? signature.digest : null,
  };
}

function settleAgentRunFromHandoff(input, options = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("settled agent run input must be an object");
  }
  const assignment = input.assignment;
  const handoff = input.handoff;
  const provenance = validateHandoffProvenance(handoff, assignment, {
    signingKey: input.signing_key || input.signingKey || null,
    requireProvenance: true,
  });
  const run = normalizeAgentRun({
    target_domain: input.target_domain || (handoff && handoff.target_domain),
    task_id: input.task_id || (assignment && assignment.task_id),
    agent_id: input.agent_id || input.agent || (assignment && assignment.agent),
    assignment_id: input.assignment_id || (assignment && assignment.assignment_id),
    status: "settled",
    started_at: input.started_at || input.ts,
    ended_at: input.ended_at || new Date().toISOString(),
    summary: input.summary || (handoff && handoff.summary),
    handoff_refs: [signedHandoffReference(handoff, provenance)],
    metrics: input.metrics,
  }, options);
  if (options.write) {
    return appendAgentRun(run, options);
  }
  return run;
}

module.exports = {
  AGENT_RUNS_MAX_RECORDS,
  AGENT_RUN_STATUSES,
  AGENT_RUN_VERSION,
  appendAgentRun,
  generatedAgentRunId,
  normalizeAgentRun,
  readAgentRuns,
  settleAgentRunFromHandoff,
};
