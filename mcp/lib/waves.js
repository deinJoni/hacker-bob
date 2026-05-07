"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const {
  assertBoolean,
  assertNonEmptyString,
  compareAgentLabels,
  normalizeStringArray,
  parseAgentId,
  parseSurfaceStatus,
  parseWaveId,
  parseWaveNumber,
  pushUnique,
} = require("./validation.js");
const {
  sessionDir,
  waveAssignmentsPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  readJsonFile,
  withSessionLock,
  writeFileAtomic,
} = require("./storage.js");
const {
  compactSessionState,
  readSessionStateStrict,
  terminallyBlockedSurfaceIds,
  writeSessionStateDocument,
} = require("./session-state.js");
const {
  loadWaveAssignments,
  normalizeWaveAssignmentsInput,
  validateAssignedWaveAgentSurface,
} = require("./assignments.js");
const {
  computeCoverageRequeueSurfaceIds,
  readCoverageRecordsFromJsonl,
} = require("./coverage.js");
const { readAttackSurfaceStrict } = require("./attack-surface.js");
const {
  routeSurfacesInternal,
} = require("./surface-router.js");
const {
  isAssignableSurfaceLead,
  promoteSurfaceLeadsInternal,
  readSurfaceLeadsDocument,
  recordSurfaceLeadsInternal,
} = require("./surface-leads.js");
const {
  readFindingsFromJsonl,
  summarizeFindings,
} = require("./findings.js");
const { readScopeExclusions } = require("./scope.js");
const {
  buildCircuitBreakerSummary,
  readHttpAuditRecordsFromJsonl,
  readTrafficRecordsFromJsonl,
  summarizeHttpAuditRecords,
  summarizeTrafficRecords,
} = require("./http-records.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  safeAppendPipelineEventDirect,
} = require("./pipeline-analytics.js");
const {
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");
const { listAuthProfiles } = require("./auth.js");
const { listEgressProfiles } = require("./egress-profiles.js");
const {
  computeHuntToChainGate,
} = require("./phase-gates.js");

function listWaveHandoffFiles(dir, wave) {
  const handoffPrefix = `handoff-${wave}-`;
  // Readiness intentionally indexes only structured handoff JSON. Markdown handoffs are for humans/debugging.
  return fs.existsSync(dir)
    ? fs.readdirSync(dir)
        .filter((name) => name.startsWith(handoffPrefix) && name.endsWith(".json"))
        .sort()
    : [];
}

function buildWaveHandoffFileIndex(dir, wave, assignmentByAgent) {
  const handoffFiles = listWaveHandoffFiles(dir, wave);
  const handoffPathByAgent = new Map();
  const unexpectedAgentSet = new Set();

  for (const fileName of handoffFiles) {
    const rawAgent = fileName.slice(`handoff-${wave}-`.length, -".json".length);
    if (!assignmentByAgent.has(rawAgent)) {
      unexpectedAgentSet.add(rawAgent);
      continue;
    }
    handoffPathByAgent.set(rawAgent, path.join(dir, fileName));
  }

  return {
    handoffFiles,
    handoffPathByAgent,
    unexpectedAgents: Array.from(unexpectedAgentSet).sort(compareAgentLabels),
  };
}

function loadWaveArtifacts(domain, waveNumber) {
  const assignmentsInfo = loadWaveAssignments(domain, waveNumber);
  const handoffInfo = buildWaveHandoffFileIndex(
    assignmentsInfo.dir,
    assignmentsInfo.wave,
    assignmentsInfo.assignmentByAgent,
  );

  return {
    ...assignmentsInfo,
    ...handoffInfo,
  };
}

function buildWaveReadiness(artifacts) {
  const receivedAgents = [];
  const missingAgents = [];

  for (const assignment of artifacts.assignments) {
    if (artifacts.handoffPathByAgent.has(assignment.agent)) {
      receivedAgents.push(assignment.agent);
    } else {
      missingAgents.push(assignment.agent);
    }
  }

  return {
    assignments_total: artifacts.assignments.length,
    handoffs_total: artifacts.handoffFiles.length,
    received_agents: receivedAgents,
    missing_agents: missingAgents,
    unexpected_agents: artifacts.unexpectedAgents,
    is_complete: missingAgents.length === 0,
  };
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
}

function generateHandoffToken() {
  return crypto.randomBytes(24).toString("base64url");
}

function assignmentRequiresToken(assignment) {
  return !!(assignment && assignment.handoff_token_sha256);
}

function validateHandoffToken(assignment, token) {
  if (!assignmentRequiresToken(assignment)) {
    return "legacy_unverified";
  }
  if (typeof token !== "string" || !token.trim()) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff_token is required for this wave assignment");
  }
  if (sha256Hex(token.trim()) !== assignment.handoff_token_sha256) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff_token does not match this wave assignment");
  }
  return "verified";
}

function validateHandoffProvenance(payload, assignment) {
  if (!assignmentRequiresToken(assignment)) {
    return "legacy_unverified";
  }
  if (payload.provenance !== "verified") {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff provenance is not verified for this tokenized assignment");
  }
  normalizeHandoffSummary(payload, { requireStructuredSummary: true });
  return "verified";
}

function normalizeHandoffSummary(payload, { requireStructuredSummary = false } = {}) {
  if (payload.summary == null && !requireStructuredSummary) {
    return null;
  }
  const summary = assertNonEmptyString(payload.summary, "summary");
  if (summary.length > 2000) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "summary must be at most 2000 characters");
  }
  return summary;
}

function normalizeChainNotes(value) {
  const notes = normalizeStringArray(value, "chain_notes");
  if (notes.length > 20) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "chain_notes must contain at most 20 entries");
  }
  for (const note of notes) {
    if (note.length > 300) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "chain_notes entries must be at most 300 characters");
    }
  }
  return notes;
}

// Phase E/F: enum mirrors the bounty_write_wave_handoff JSON schema and the
// renderer's BLOCKED_HARNESS_RUN_KINDS constant. Mismatch here would cause
// SVM/Move/Substrate/CosmWasm hunters to fail finalization even though the
// schema accepted their handoff. capability-packs-rendering.js exports a
// schema-vs-renderer parity test; this mirror is the runtime side of that
// invariant.
const BLOCKED_HARNESS_KIND_VALUES = Object.freeze([
  "foundry_fork",
  "anchor_fork",
  "aptos_fork",
  "sui_fork",
  "substrate_fork",
  "cosmwasm_fork",
  "rpc_endpoint",
  "fuzzer",
  "symbolic_solver",
  "mock_dependency",
  "external_api",
  "other",
]);

// Mirror of capability-packs-rendering.js BLOCKED_PREREQ_KINDS and the
// bounty_write_wave_handoff schema enum for blocked_prereqs[].kind. Like
// BLOCKED_HARNESS_KIND_VALUES this is a runtime guard that throws on unknown
// kinds before the JSON schema would even check; mismatch with the renderer
// constant or schema enum is caught by the parity test in
// test/prompt-contracts.test.js.
const BLOCKED_PREREQ_KIND_VALUES = Object.freeze([
  "auth_missing",
  "egress_unreachable",
  "funded_wallet_missing",
  "key_material_missing",
  "external_credential_missing",
]);

const BLOCKED_PREREQ_IDENTIFIER_HINT_PATTERN = /^[a-z0-9][a-z0-9_.-]{0,63}$/;

// Long-hex rejector for identifier_hint. Catches private-key / hash shapes
// (32+ lowercase hex chars) that pass the handle-format regex but should
// never appear in a registry handle. Layered defense above
// validateNoSensitiveMaterial which targets JWT / bearer / cookie shapes.
const BLOCKED_PREREQ_IDENTIFIER_HINT_LONG_HEX_PATTERN = /^[0-9a-f]{32,}$/;

const BYPASS_ATTEMPT_OUTCOME_VALUES = Object.freeze([
  "no_finding",
  "partial_evidence",
  "finding_recorded",
  "blocked",
]);

function normalizeBlockedHarnessRuns(value) {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "blocked_harness_runs must be an array");
  }
  if (value.length > 20) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "blocked_harness_runs must contain at most 20 entries");
  }
  return value.map((entry, index) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_harness_runs[${index}] must be an object`);
    }
    const kind = assertNonEmptyString(entry.kind, `blocked_harness_runs[${index}].kind`);
    if (!BLOCKED_HARNESS_KIND_VALUES.includes(kind)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_harness_runs[${index}].kind must be one of ${BLOCKED_HARNESS_KIND_VALUES.join(", ")}`);
    }
    const harness = assertNonEmptyString(entry.harness, `blocked_harness_runs[${index}].harness`);
    const reason = assertNonEmptyString(entry.reason, `blocked_harness_runs[${index}].reason`);
    if (harness.length > 120) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_harness_runs[${index}].harness must be at most 120 characters`);
    }
    if (reason.length > 240) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_harness_runs[${index}].reason must be at most 240 characters`);
    }
    const normalized = { kind, harness, reason };
    if (entry.needed_for != null) {
      const neededFor = assertNonEmptyString(entry.needed_for, `blocked_harness_runs[${index}].needed_for`);
      if (neededFor.length > 200) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_harness_runs[${index}].needed_for must be at most 200 characters`);
      }
      normalized.needed_for = neededFor;
    }
    return normalized;
  });
}

function normalizeBlockedPrereqs(value) {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "blocked_prereqs must be an array");
  }
  if (value.length > 20) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "blocked_prereqs must contain at most 20 entries");
  }
  return value.map((entry, index) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_prereqs[${index}] must be an object`);
    }
    const kind = assertNonEmptyString(entry.kind, `blocked_prereqs[${index}].kind`);
    if (!BLOCKED_PREREQ_KIND_VALUES.includes(kind)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_prereqs[${index}].kind must be one of ${BLOCKED_PREREQ_KIND_VALUES.join(", ")}`);
    }
    const reason = assertNonEmptyString(entry.reason, `blocked_prereqs[${index}].reason`);
    if (reason.length > 240) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_prereqs[${index}].reason must be at most 240 characters`);
    }
    try {
      validateNoSensitiveMaterial(reason, `blocked_prereqs[${index}].reason`);
    } catch (error) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message);
    }
    const normalized = { kind, reason };
    if (entry.identifier_hint != null) {
      const identifierHint = assertNonEmptyString(entry.identifier_hint, `blocked_prereqs[${index}].identifier_hint`);
      if (identifierHint.length > 64) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_prereqs[${index}].identifier_hint must be at most 64 characters`);
      }
      if (!BLOCKED_PREREQ_IDENTIFIER_HINT_PATTERN.test(identifierHint)) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_prereqs[${index}].identifier_hint must match /^[a-z0-9][a-z0-9_.-]{0,63}$/ — use a lowercase registry handle, not a credential or token value`);
      }
      if (BLOCKED_PREREQ_IDENTIFIER_HINT_LONG_HEX_PATTERN.test(identifierHint)) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_prereqs[${index}].identifier_hint looks like a hex private key, address, or hash; use a human-readable registry handle instead`);
      }
      try {
        validateNoSensitiveMaterial(identifierHint, `blocked_prereqs[${index}].identifier_hint`);
      } catch (error) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message);
      }
      normalized.identifier_hint = identifierHint;
    }
    if (entry.evidence_summary != null) {
      const evidenceSummary = assertNonEmptyString(entry.evidence_summary, `blocked_prereqs[${index}].evidence_summary`);
      if (evidenceSummary.length > 300) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_prereqs[${index}].evidence_summary must be at most 300 characters`);
      }
      try {
        validateNoSensitiveMaterial(evidenceSummary, `blocked_prereqs[${index}].evidence_summary`);
      } catch (error) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message);
      }
      normalized.evidence_summary = evidenceSummary;
    }
    if (entry.needed_for != null) {
      const neededFor = assertNonEmptyString(entry.needed_for, `blocked_prereqs[${index}].needed_for`);
      if (neededFor.length > 200) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_prereqs[${index}].needed_for must be at most 200 characters`);
      }
      try {
        validateNoSensitiveMaterial(neededFor, `blocked_prereqs[${index}].needed_for`);
      } catch (error) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message);
      }
      normalized.needed_for = neededFor;
    }
    return normalized;
  });
}

const BYPASS_ATTEMPT_CONDITION_MIN_CHARS = 4;
const BYPASS_ATTEMPT_SUMMARY_MIN_CHARS = 30;

function normalizeBypassAttempts(value, { findingIds = null } = {}) {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "bypass_attempts must be an array");
  }
  if (value.length > 30) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "bypass_attempts must contain at most 30 entries");
  }
  return value.map((entry, index) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}] must be an object`);
    }
    const condition = assertNonEmptyString(entry.condition, `bypass_attempts[${index}].condition`);
    if (condition.length < BYPASS_ATTEMPT_CONDITION_MIN_CHARS) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}].condition must be at least ${BYPASS_ATTEMPT_CONDITION_MIN_CHARS} characters`);
    }
    if (condition.length > 120) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}].condition must be at most 120 characters`);
    }
    const attemptSummary = assertNonEmptyString(entry.attempt_summary, `bypass_attempts[${index}].attempt_summary`);
    if (attemptSummary.length < BYPASS_ATTEMPT_SUMMARY_MIN_CHARS) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}].attempt_summary must be at least ${BYPASS_ATTEMPT_SUMMARY_MIN_CHARS} characters; describe the concrete state machine or payload you exercised`);
    }
    if (attemptSummary.length > 500) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}].attempt_summary must be at most 500 characters`);
    }
    const outcome = assertNonEmptyString(entry.outcome, `bypass_attempts[${index}].outcome`);
    if (!BYPASS_ATTEMPT_OUTCOME_VALUES.includes(outcome)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}].outcome must be one of ${BYPASS_ATTEMPT_OUTCOME_VALUES.join(", ")}`);
    }
    const normalized = { condition, attempt_summary: attemptSummary, outcome };
    if (entry.finding_id != null) {
      const findingId = assertNonEmptyString(entry.finding_id, `bypass_attempts[${index}].finding_id`);
      if (!/^F-([1-9]\d*)$/.test(findingId)) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}].finding_id must match F-N pattern`);
      }
      if (findingIds && !findingIds.has(findingId)) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}].finding_id ${findingId} does not match any recorded finding for this run`);
      }
      normalized.finding_id = findingId;
    }
    if (outcome === "finding_recorded" && !normalized.finding_id) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}].finding_id is required when outcome is "finding_recorded"`);
    }
    return normalized;
  });
}

function assertBlockedHarnessConsistency(surfaceStatus, blockedHarnessRuns) {
  if (surfaceStatus === "complete" && blockedHarnessRuns.length > 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "surface_status cannot be 'complete' when blocked_harness_runs is non-empty; set surface_status to 'partial' or resolve the blocked harnesses first",
    );
  }
}

function assertBlockedPrereqConsistency(surfaceStatus, blockedPrereqs) {
  if (surfaceStatus === "complete" && blockedPrereqs.length > 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "surface_status cannot be 'complete' when blocked_prereqs is non-empty; set surface_status to 'partial' or resolve the missing prerequisites first",
    );
  }
}

function assertSmartContractCompletionEvidence({
  surfaceType,
  surfaceStatus,
  bypassAttempts,
  findingCount,
}) {
  if (surfaceType !== "smart_contract") return;
  if (surfaceStatus !== "complete") return;
  if (findingCount > 0) return;
  if (bypassAttempts.length > 0) return;
  throw new ToolError(
    ERROR_CODES.INVALID_ARGUMENTS,
    "smart_contract surfaces cannot be marked 'complete' without evidence of attempted invariant breaks: record at least one finding for this surface, or supply at least one bypass_attempts entry citing a trust_assumptions[*].bypass_conditions condition that was tested. Set surface_status to 'partial' if no attempt was made.",
  );
}

function validateWaveHandoffPayload(payload, {
  targetDomain,
  wave,
  agent,
  surfaceId,
  effectiveSurfaceType,
  findingsForRun,
}) {
  if (payload == null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff payload must be an object");
  }

  if (payload.target_domain != null && assertNonEmptyString(payload.target_domain, "target_domain") !== targetDomain) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff target_domain does not match merge target");
  }

  const payloadWave = parseWaveId(payload.wave);
  const payloadAgent = parseAgentId(payload.agent);
  const payloadSurfaceId = assertNonEmptyString(payload.surface_id, "surface_id");
  const surfaceStatus = parseSurfaceStatus(payload.surface_status);

  if (payloadWave !== wave) throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff wave does not match assignment wave");
  if (payloadAgent !== agent) throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff agent does not match assignment");
  if (payloadSurfaceId !== surfaceId) throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff surface_id does not match assignment");

  const findingsForCheck = Array.isArray(findingsForRun)
    ? findingsForRun
    : readFindingsFromJsonl(targetDomain).filter((finding) => (
      finding.wave === wave &&
      finding.agent === agent &&
      finding.surface_id === surfaceId
    ));
  const findingIdSet = new Set(findingsForCheck.map((finding) => finding.id));

  const blockedHarnessRuns = normalizeBlockedHarnessRuns(payload.blocked_harness_runs);
  const blockedPrereqs = normalizeBlockedPrereqs(payload.blocked_prereqs);
  const bypassAttempts = normalizeBypassAttempts(payload.bypass_attempts, { findingIds: findingIdSet });
  assertBlockedHarnessConsistency(surfaceStatus, blockedHarnessRuns);
  assertBlockedPrereqConsistency(surfaceStatus, blockedPrereqs);

  // Authoritative source for surface_type is the MCP-owned assignment file
  // (captured at start_wave time). Callers from active wave paths
  // (mergeWaveHandoffsInternal, buildWaveHandoffsDocument, writeWaveHandoff)
  // pass effectiveSurfaceType from the assignment. The payload.surface_type
  // fallback is defensive for legacy callers and is consistent with the
  // stored value (which itself was sourced from the assignment).
  const surfaceTypeFallback = typeof payload.surface_type === "string" && payload.surface_type.trim() !== ""
    ? payload.surface_type.trim()
    : null;
  const surfaceType = effectiveSurfaceType !== undefined
    ? effectiveSurfaceType
    : surfaceTypeFallback;
  assertSmartContractCompletionEvidence({
    surfaceType,
    surfaceStatus,
    bypassAttempts,
    findingCount: findingsForCheck.length,
  });

  return {
    surface_type: surfaceType,
    summary: normalizeHandoffSummary(payload),
    chain_notes: normalizeChainNotes(payload.chain_notes),
    blocked_harness_runs: blockedHarnessRuns,
    blocked_prereqs: blockedPrereqs,
    bypass_attempts: bypassAttempts,
    dead_ends: normalizeStringArray(payload.dead_ends, "dead_ends"),
    waf_blocked_endpoints: normalizeStringArray(payload.waf_blocked_endpoints, "waf_blocked_endpoints"),
    lead_surface_ids: normalizeStringArray(payload.lead_surface_ids, "lead_surface_ids"),
    surface_lead_ids: normalizeStringArray(payload.surface_lead_ids, "surface_lead_ids"),
    surface_status: surfaceStatus,
  };
}

function groupBlockedHarnessRuns(entries) {
  const groups = new Map();
  for (const entry of entries) {
    const key = `${entry.kind} ${entry.harness}`;
    if (!groups.has(key)) {
      groups.set(key, { kind: entry.kind, harness: entry.harness, count: 0, agents: new Set(), surface_ids: new Set() });
    }
    const group = groups.get(key);
    group.count += 1;
    if (entry.agent) group.agents.add(entry.agent);
    if (entry.surface_id) group.surface_ids.add(entry.surface_id);
  }
  return Array.from(groups.values()).map((group) => ({
    kind: group.kind,
    harness: group.harness,
    count: group.count,
    agents: Array.from(group.agents).sort(compareAgentLabels),
    surface_ids: Array.from(group.surface_ids).sort(),
  }));
}

// Group blocked_prereqs by (kind, identifier_hint||""). identifier_hint is
// optional, so "" stands in for "unspecified" — group "auth_missing without
// any specific profile name" together. Matches the loop-detector identity
// the merge promotion uses.
function groupBlockedPrereqs(entries) {
  const groups = new Map();
  for (const entry of entries) {
    const hint = entry.identifier_hint || "";
    const key = `${entry.kind}\t${hint}`;
    if (!groups.has(key)) {
      groups.set(key, {
        kind: entry.kind,
        identifier_hint: entry.identifier_hint || null,
        count: 0,
        agents: new Set(),
        surface_ids: new Set(),
      });
    }
    const group = groups.get(key);
    group.count += 1;
    if (entry.agent) group.agents.add(entry.agent);
    if (entry.surface_id) group.surface_ids.add(entry.surface_id);
  }
  return Array.from(groups.values()).map((group) => ({
    kind: group.kind,
    identifier_hint: group.identifier_hint,
    count: group.count,
    agents: Array.from(group.agents).sort(compareAgentLabels),
    surface_ids: Array.from(group.surface_ids).sort(),
  }));
}

function groupBypassAttempts(entries) {
  const groups = new Map();
  for (const entry of entries) {
    const key = `${entry.condition} ${entry.outcome}`;
    if (!groups.has(key)) {
      groups.set(key, { condition: entry.condition, outcome: entry.outcome, count: 0, agents: new Set(), surface_ids: new Set() });
    }
    const group = groups.get(key);
    group.count += 1;
    if (entry.agent) group.agents.add(entry.agent);
    if (entry.surface_id) group.surface_ids.add(entry.surface_id);
  }
  return Array.from(groups.values()).map((group) => ({
    condition: group.condition,
    outcome: group.outcome,
    count: group.count,
    agents: Array.from(group.agents).sort(compareAgentLabels),
    surface_ids: Array.from(group.surface_ids).sort(),
  }));
}

function buildSuspicionFlags({ smartContractCompletedSurfaceIds, bypassAttemptsForCompletedSurfaces, recordedFindingsBySurface }) {
  const flags = [];
  for (const surfaceId of smartContractCompletedSurfaceIds) {
    const findings = recordedFindingsBySurface.get(surfaceId) || [];
    const attempts = bypassAttemptsForCompletedSurfaces.get(surfaceId) || [];
    if (findings.length > 0) continue;
    if (attempts.length === 0) continue;
    // Flag SC complete with no finding when no attempt yielded substantive
    // evidence. "no_finding" alone or "blocked" alone indicates structural
    // attestation without recorded evidence; only partial_evidence or
    // finding_recorded outcomes signal that a real attempt produced something.
    const hasSubstantiveOutcome = attempts.some((attempt) => (
      attempt.outcome === "partial_evidence" || attempt.outcome === "finding_recorded"
    ));
    if (hasSubstantiveOutcome) continue;
    flags.push({
      flag: "sc_complete_with_zero_evidence",
      surface_id: surfaceId,
      reason: "smart_contract surface marked complete with no recorded finding and no bypass_attempts entry produced partial_evidence or finding_recorded; review for low-effort attestation",
    });
  }
  return flags;
}

function mergeWaveHandoffsInternal(domain, waveNumber) {
  const artifacts = loadWaveArtifacts(domain, waveNumber);
  const readiness = buildWaveReadiness(artifacts);

  const receivedAgents = [];
  const invalidAgents = [];
  const completedSurfaceIds = [];
  const partialSurfaceIds = [];
  const missingSurfaceIds = [];
  const deadEnds = [];
  const wafBlockedEndpoints = [];
  const leadSurfaceIds = [];
  const blockedHarnessRuns = [];
  const blockedPrereqs = [];
  const bypassAttempts = [];
  const provenance = {
    verified_agents: [],
    legacy_unverified_agents: [],
  };

  const deadEndSet = new Set();
  const wafSet = new Set();
  const leadSet = new Set();

  // Pre-read findings once and index by (wave, agent, surface_id) so per-handoff
  // validation does not re-parse findings.jsonl O(handoffs × findings) times.
  const allFindings = readFindingsFromJsonl(domain);
  const findingsByRun = new Map();
  const recordedFindingsBySurface = new Map();
  for (const finding of allFindings) {
    if (finding.wave === artifacts.wave) {
      const runKey = `${finding.wave} ${finding.agent} ${finding.surface_id}`;
      if (!findingsByRun.has(runKey)) findingsByRun.set(runKey, []);
      findingsByRun.get(runKey).push(finding);
      if (!recordedFindingsBySurface.has(finding.surface_id)) recordedFindingsBySurface.set(finding.surface_id, []);
      recordedFindingsBySurface.get(finding.surface_id).push(finding);
    }
  }

  const smartContractCompletedSurfaceIds = [];
  const bypassAttemptsForCompletedSurfaces = new Map();

  for (const assignment of artifacts.assignments) {
    const filePath = artifacts.handoffPathByAgent.get(assignment.agent);
    if (!filePath) {
      missingSurfaceIds.push(assignment.surface_id);
      continue;
    }

    try {
      const handoffJson = readJsonFile(filePath);
      const runKey = `${artifacts.wave} ${assignment.agent} ${assignment.surface_id}`;
      const findingsForRun = findingsByRun.get(runKey) || [];
      const effectiveSurfaceType = assignment.surface_type || null;
      const payload = validateWaveHandoffPayload(handoffJson, {
        targetDomain: domain,
        wave: artifacts.wave,
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
        effectiveSurfaceType,
        findingsForRun,
      });
      const provenanceStatus = validateHandoffProvenance(handoffJson, assignment);

      receivedAgents.push(assignment.agent);
      if (provenanceStatus === "verified") {
        provenance.verified_agents.push(assignment.agent);
      } else {
        provenance.legacy_unverified_agents.push(assignment.agent);
      }
      if (payload.surface_status === "complete") {
        completedSurfaceIds.push(assignment.surface_id);
        if (effectiveSurfaceType === "smart_contract") {
          smartContractCompletedSurfaceIds.push(assignment.surface_id);
          bypassAttemptsForCompletedSurfaces.set(assignment.surface_id, payload.bypass_attempts || []);
        }
      } else {
        partialSurfaceIds.push(assignment.surface_id);
      }
      pushUnique(deadEnds, deadEndSet, payload.dead_ends);
      pushUnique(wafBlockedEndpoints, wafSet, payload.waf_blocked_endpoints);
      pushUnique(leadSurfaceIds, leadSet, payload.lead_surface_ids);
      for (const entry of payload.blocked_harness_runs || []) {
        blockedHarnessRuns.push({ ...entry, agent: assignment.agent, surface_id: assignment.surface_id });
      }
      for (const entry of payload.blocked_prereqs || []) {
        blockedPrereqs.push({ ...entry, agent: assignment.agent, surface_id: assignment.surface_id });
      }
      for (const entry of payload.bypass_attempts || []) {
        bypassAttempts.push({ ...entry, agent: assignment.agent, surface_id: assignment.surface_id });
      }
    } catch {
      invalidAgents.push(assignment.agent);
    }
  }

  const suspicionFlags = buildSuspicionFlags({
    smartContractCompletedSurfaceIds,
    bypassAttemptsForCompletedSurfaces,
    recordedFindingsBySurface,
  });

  for (const assignment of artifacts.assignments) {
    const logPath = path.join(artifacts.dir, `live-dead-ends-${artifacts.wave}-${assignment.agent}.jsonl`);
    if (!fs.existsSync(logPath)) continue;
    let raw;
    try {
      raw = fs.readFileSync(logPath, "utf8");
    } catch {
      continue;
    }
    const lines = raw.trim().split("\n");
    for (const line of lines) {
      if (!line) continue;
      try {
        const record = JSON.parse(line);
        if (record.surface_id !== assignment.surface_id) continue;
        pushUnique(deadEnds, deadEndSet, normalizeStringArray(record.dead_ends, "live_dead_ends"));
        pushUnique(wafBlockedEndpoints, wafSet, normalizeStringArray(record.waf_blocked_endpoints, "live_waf_blocked"));
      } catch {
        // Skip malformed line, keep processing remaining records
      }
    }
  }

  return {
    artifacts,
    readiness,
    merge: {
      received_agents: receivedAgents,
      invalid_agents: invalidAgents,
      unexpected_agents: readiness.unexpected_agents,
      completed_surface_ids: completedSurfaceIds,
      partial_surface_ids: partialSurfaceIds,
      missing_surface_ids: missingSurfaceIds,
      dead_ends: deadEnds,
      waf_blocked_endpoints: wafBlockedEndpoints,
      lead_surface_ids: leadSurfaceIds,
      blocked_harness_runs: blockedHarnessRuns,
      blocked_harness_runs_grouped: groupBlockedHarnessRuns(blockedHarnessRuns),
      blocked_prereqs: blockedPrereqs,
      blocked_prereqs_grouped: groupBlockedPrereqs(blockedPrereqs),
      bypass_attempts: bypassAttempts,
      bypass_attempts_grouped: groupBypassAttempts(bypassAttempts),
      suspicion_flags: suspicionFlags,
      provenance,
    },
  };
}

function computeRequeueSurfaceIds(artifacts, merge, coverageRecords = []) {
  const requeueSurfaceIds = [];
  const seen = new Set();
  pushUnique(requeueSurfaceIds, seen, merge.partial_surface_ids);
  pushUnique(requeueSurfaceIds, seen, merge.missing_surface_ids);

  for (const agent of merge.invalid_agents) {
    const assignment = artifacts.assignmentByAgent.get(agent);
    if (!assignment) continue;
    pushUnique(requeueSurfaceIds, seen, [assignment.surface_id]);
  }

  pushUnique(requeueSurfaceIds, seen, computeCoverageRequeueSurfaceIds(artifacts, coverageRecords));

  return requeueSurfaceIds;
}

function waveStatus(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const findings = readFindingsFromJsonl(domain);
  const summary = summarizeFindings(findings);

  // Compute transition-gate inputs for deterministic wave decisions.
  let coverage = null;
  let transitionBlockers = [];
  try {
    const { state } = readSessionStateStrict(domain);
    const gate = computeHuntToChainGate(domain, state);
    coverage = gate.coverage;
    transitionBlockers = gate.transition_blockers;
  } catch (error) {
    transitionBlockers = [{
      code: "state_unavailable",
      message: "session state could not be read for HUNT -> CHAIN gating",
      error: error && error.message ? error.message : String(error),
    }];
  }

  let auditSummary = null;
  let trafficSummary = null;
  let circuitBreakerSummary = null;
  let surfaceLeadsSummary = null;
  try {
    const auditRecords = readHttpAuditRecordsFromJsonl(domain);
    auditSummary = summarizeHttpAuditRecords(auditRecords, { limit: 0 });
    circuitBreakerSummary = buildCircuitBreakerSummary(auditRecords);
  } catch {}
  try {
    trafficSummary = summarizeTrafficRecords(readTrafficRecordsFromJsonl(domain), { limit: 0 });
  } catch {}
  try {
    const surfaceLeads = readSurfaceLeadsDocument(domain);
    surfaceLeadsSummary = {
      total: surfaceLeads.leads.length,
      high_confidence_unpromoted: surfaceLeads.leads.filter(
        (lead) => lead.status !== "promoted" && lead.confidence === "high" && isAssignableSurfaceLead(lead),
      ).length,
      promoted: surfaceLeads.leads.filter((lead) => lead.status === "promoted").length,
    };
  } catch {}

  return JSON.stringify({
    ...summary,
    coverage,
    transition_blockers: transitionBlockers,
    http_audit: auditSummary,
    traffic: trafficSummary,
    circuit_breaker: circuitBreakerSummary,
    surface_leads: surfaceLeadsSummary,
    findings_summary: findings.map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      title: finding.title,
      endpoint: finding.endpoint,
      wave_agent: finding.wave || finding.agent ? `${finding.wave || "?"}/${finding.agent || "?"}` : null,
    })),
  });
}

function startWave(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  const assignments = normalizeWaveAssignmentsInput(args.assignments);

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    if (state.phase !== "HUNT" && state.phase !== "EXPLORE") {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Wave start requires phase HUNT or EXPLORE, found ${state.phase}`);
    }
    if (state.pending_wave != null) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Wave start requires pending_wave null, found ${state.pending_wave}`);
    }
    if (waveNumber !== state.hunt_wave + 1) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `wave_number must equal hunt_wave + 1 (${state.hunt_wave + 1})`);
    }

    const assignmentsPath = waveAssignmentsPath(domain, waveNumber);
    if (fs.existsSync(assignmentsPath)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Assignment file already exists: ${assignmentsPath}`);
    }

    const attackSurface = readAttackSurfaceStrict(domain);
    const surfaceTypeById = new Map();
    for (const surface of attackSurface.document.surfaces || []) {
      if (!surface || typeof surface !== "object" || Array.isArray(surface)) continue;
      const surfaceTypeRaw = typeof surface.surface_type === "string" ? surface.surface_type.trim() : "";
      surfaceTypeById.set(surface.id, surfaceTypeRaw !== "" ? surfaceTypeRaw : null);
    }
    for (const assignment of assignments) {
      if (!attackSurface.surface_id_set.has(assignment.surface_id)) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `Unknown surface_id in assignments: ${assignment.surface_id}`);
      }
    }

    // Hard write-side filter: terminally-blocked surfaces cannot be
    // assigned to a wave until an operator clears the block via
    // bounty_clear_terminal_block. Defends against an orchestrator
    // regression that drops the soft-prompt exclusion and silently burns
    // hunter cycles on classified-blocked work.
    const terminallyBlockedSet = new Set(terminallyBlockedSurfaceIds(state));
    const blockedAssignments = assignments
      .filter((assignment) => terminallyBlockedSet.has(assignment.surface_id))
      .map((assignment) => assignment.surface_id);
    if (blockedAssignments.length > 0) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `Cannot assign terminally-blocked surfaces to a wave; clear the block via bounty_clear_terminal_block first: ${blockedAssignments.join(", ")}`,
      );
    }

    // Capture surface_type from attack_surface.json AT WAVE START into the
    // immutable, MCP-owned assignment file. This makes the smart_contract
    // completion gate tamper-resistant — hunters cannot disable enforcement
    // by mutating attack_surface.json mid-wave.
    const routedSurfaces = routeSurfacesInternal(domain, { attackSurfaceInfo: attackSurface });
    const routeBySurfaceId = new Map(
      routedSurfaces.document.routes.map((route) => [route.surface_id, route]),
    );
    for (const assignment of assignments) {
      if (!routeBySurfaceId.has(assignment.surface_id)) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `Missing route for surface_id in assignments: ${assignment.surface_id}`);
      }
    }


    const persistedAssignments = assignments.map((assignment) => {
      const token = generateHandoffToken();
      const route = routeBySurfaceId.get(assignment.surface_id);
      return {
        ...assignment,
        surface_type: surfaceTypeById.get(assignment.surface_id) || null,
        capability_pack: route.capability_pack,
        capability_pack_version: route.capability_pack_version,
        hunter_agent: route.hunter_agent,
        brief_profile: route.brief_profile,
        context_budget: route.context_budget,
        handoff_token_sha256: sha256Hex(token),
        handoff_token: token,
      };
    });
    const assignmentsForDisk = persistedAssignments.map(({ handoff_token, ...assignment }) => assignment);

    // Snapshot registries BEFORE the assignment file is written. If the
    // snapshot throws (auth.json malformed, egress config missing, etc.)
    // we want the wave start to fail cleanly with no orphaned assignment
    // file — not a half-written session that fails on retry with
    // "Assignment file already exists".
    const startSnapshot = snapshotPrereqRegistries(domain);
    const priorSnapshots = Array.isArray(state.prereq_registry_snapshots) ? state.prereq_registry_snapshots : [];
    const nextSnapshots = [
      ...priorSnapshots.filter((s) => s.wave !== waveNumber),
      { wave: waveNumber, ...startSnapshot },
    ].sort((a, b) => a.wave - b.wave);

    writeFileAtomic(assignmentsPath, `${JSON.stringify({
      wave_number: waveNumber,
      assignments: assignmentsForDisk,
    }, null, 2)}\n`);

    const nextState = {
      ...state,
      pending_wave: waveNumber,
      prereq_registry_snapshots: nextSnapshots,
    };

    try {
      writeSessionStateDocument(domain, raw, nextState);
    } catch (error) {
      let rollbackSucceeded = false;
      try {
        fs.rmSync(assignmentsPath, { force: true });
        rollbackSucceeded = true;
      } catch {}

      const rollbackStatus = rollbackSucceeded ? "rollback succeeded" : "rollback failed";
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `State write failed after writing assignments; ${rollbackStatus}: ${assignmentsPath} (${error.message || String(error)})`,
      );
    }
    safeAppendPipelineEventDirect(domain, "wave_started", {
      phase: state.phase,
      wave_number: waveNumber,
      status: "started",
      source: "bounty_start_wave",
      counts: {
        assignments: assignments.length,
      },
    });

    return JSON.stringify({
      version: 1,
      started: true,
      wave_number: waveNumber,
      assignments: persistedAssignments.map((assignment) => ({
        agent: assignment.agent,
        surface_id: assignment.surface_id,
        capability_pack: assignment.capability_pack,
        capability_pack_version: assignment.capability_pack_version,
        hunter_agent: assignment.hunter_agent,
        brief_profile: assignment.brief_profile,
        context_budget: assignment.context_budget,
        handoff_token: assignment.handoff_token,
      })),
      assignments_path: assignmentsPath,
      state: compactSessionState(nextState),
    });
  });
}

// Snapshot registry HANDLE SETS at wave start so the loop detector can
// reason about whether the SPECIFIC material a stuck blocker named was
// added since. Counts collapse unrelated additions into "growth" and
// give the original blocker permanent amnesty (e.g., adding `victim`
// would silently satisfy `auth_missing: attacker`). Failures throw
// rather than fail-open because the caller (start_wave) cannot make a
// trustworthy snapshot without registry visibility — better to refuse
// the wave than to record a lying snapshot.
function snapshotPrereqRegistries(domain) {
  let authHandles;
  try {
    const result = JSON.parse(listAuthProfiles({ target_domain: domain }));
    authHandles = Array.isArray(result.profiles)
      ? result.profiles.map((p) => p && typeof p.profile_name === "string" ? p.profile_name : null).filter(Boolean)
      : [];
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Could not snapshot auth-profile registry for ${domain}: ${error.message || String(error)}`,
    );
  }
  let egressHandles;
  try {
    const profiles = listEgressProfiles();
    egressHandles = profiles
      .filter((p) => p && p.enabled)
      .map((p) => p && typeof p.name === "string" ? p.name : null)
      .filter(Boolean);
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Could not snapshot egress-profile registry: ${error.message || String(error)}`,
    );
  }
  return {
    auth_handles: Array.from(new Set(authHandles)).sort(),
    egress_handles: Array.from(new Set(egressHandles)).sort(),
  };
}

const BLOCKED_PREREQ_KINDS_WITH_REGISTRY_DELTA = Object.freeze({
  auth_missing: "auth_handles",
  egress_unreachable: "egress_handles",
});

// Loop detector. For each surface with current-wave blockers, look at
// validated history (state.blocked_prereq_history) for prior occurrences
// of the same (kind, identifier_hint) tuple. For kinds with a
// registry-delta channel (auth_missing, egress_unreachable), skip
// promotion when the SPECIFIC handle the blocker named was added since
// the LATEST prior occurrence — handle-set membership rather than count
// growth. For null identifier_hint (no specific handle requested), skip
// when the handle set itself grew (any new handle appeared). Other
// kinds (funded_wallet_missing, key_material_missing,
// external_credential_missing) have no registry-delta path; they
// promote on any 2-wave recurrence and require operator clear via
// bounty_clear_terminal_block.
function detectTerminalPromotions({
  currentWaveBlockersBySurface,
  historyBySurface,
  prereqRegistrySnapshots,
  clearHistoryBySurface,
  currentWave,
}) {
  const snapshotByWave = new Map(prereqRegistrySnapshots.map((s) => [s.wave, s]));
  const currentSnapshot = snapshotByWave.get(currentWave);
  const promotions = [];
  for (const [surfaceId, currentEntries] of currentWaveBlockersBySurface) {
    const surfaceHistory = historyBySurface.get(surfaceId) || [];
    // The latest clear for this surface defines the recurrence horizon:
    // history entries from waves <= cleared_at_wave are pre-clear and
    // do not count toward the loop detector's "recurred across waves"
    // signal. Without this, every clear-then-reblock would immediately
    // re-promote.
    const clearsForSurface = clearHistoryBySurface.get(surfaceId) || [];
    const latestClearAtWave = clearsForSurface.length > 0
      ? Math.max(...clearsForSurface.map((c) => c.cleared_at_wave))
      : 0;
    const promotedBlockers = [];
    const seenTuples = new Set();
    for (const entry of currentEntries) {
      const hint = entry.identifier_hint || null;
      const tupleKey = `${entry.kind}\t${hint || ""}`;
      if (seenTuples.has(tupleKey)) continue;
      // Prior occurrences are entries from waves strictly before the
      // current one and strictly after the latest clear for this surface.
      const priorMatches = surfaceHistory.filter((h) =>
        h.wave < currentWave &&
        h.wave > latestClearAtWave &&
        h.kind === entry.kind &&
        (h.identifier_hint || null) === hint,
      );
      if (priorMatches.length === 0) continue;
      const registryField = BLOCKED_PREREQ_KINDS_WITH_REGISTRY_DELTA[entry.kind];
      if (registryField && currentSnapshot) {
        // LATEST prior wave: if the handle was added since the most
        // recent unresolved occurrence, the loop was potentially broken.
        const latestPriorWave = Math.max(...priorMatches.map((p) => p.wave));
        const priorSnapshot = snapshotByWave.get(latestPriorWave);
        const priorHandles = priorSnapshot && Array.isArray(priorSnapshot[registryField])
          ? new Set(priorSnapshot[registryField])
          : new Set();
        const currentHandles = new Set(currentSnapshot[registryField] || []);
        if (hint != null) {
          // Specific handle named: skip promotion only if that exact
          // handle is newly registered.
          if (currentHandles.has(hint) && !priorHandles.has(hint)) continue;
        } else {
          // No specific handle: skip if the handle set grew at all.
          let grew = false;
          for (const h of currentHandles) {
            if (!priorHandles.has(h)) { grew = true; break; }
          }
          if (grew) continue;
        }
      }
      seenTuples.add(tupleKey);
      const blocker = { kind: entry.kind };
      if (entry.identifier_hint) blocker.identifier_hint = entry.identifier_hint;
      if (entry.reason) blocker.reason = entry.reason;
      promotedBlockers.push(blocker);
    }
    if (promotedBlockers.length > 0) {
      promotions.push({
        surface_id: surfaceId,
        blocked_at_wave: currentWave,
        blockers: promotedBlockers,
      });
    }
  }
  return promotions;
}

function applyWaveMerge(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  const forceMerge = assertBoolean(args.force_merge, "force_merge");
  const forceMergeReason = args.force_merge_reason == null
    ? null
    : assertNonEmptyString(args.force_merge_reason, "force_merge_reason");
  if (forceMerge && (!forceMergeReason || forceMergeReason.length < 20)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "force_merge_reason is required when force_merge is true and must be at least 20 characters");
  }
  if (!forceMerge && forceMergeReason != null) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "force_merge_reason is only allowed when force_merge is true");
  }

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    if (state.phase !== "HUNT" && state.phase !== "EXPLORE") {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Wave merge requires phase HUNT or EXPLORE, found ${state.phase}`);
    }
    if (state.pending_wave == null) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, "Wave merge requires pending_wave to be set");
    }
    if (state.pending_wave !== waveNumber) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Wave merge requires pending_wave ${waveNumber}, found ${state.pending_wave}`);
    }

    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, waveNumber));
    if (!readiness.is_complete && !forceMerge) {
      safeAppendPipelineEventDirect(domain, "wave_merge_pending", {
        phase: state.phase,
        wave_number: waveNumber,
        status: "pending",
        source: "bounty_apply_wave_merge",
        counts: {
          assignments: readiness.assignments_total,
          handoffs: readiness.handoffs_total,
          missing_handoffs: readiness.missing_agents.length,
          unexpected_handoffs: readiness.unexpected_agents.length,
        },
      });
      return JSON.stringify({
        version: 1,
        status: "pending",
        wave_number: waveNumber,
        force_merge: false,
        readiness,
        state: compactSessionState(state),
      });
    }

    const { artifacts, merge } = mergeWaveHandoffsInternal(domain, waveNumber);
    const coverageRecords = readCoverageRecordsFromJsonl(domain);
    const requeueSurfaceIds = computeRequeueSurfaceIds(artifacts, merge, coverageRecords);
    const requeueSurfaceIdSet = new Set(requeueSurfaceIds);
    const findings = summarizeFindings(readFindingsFromJsonl(domain));
    const scopeExclusions = [...state.scope_exclusions];
    pushUnique(scopeExclusions, new Set(scopeExclusions), readScopeExclusions(domain));

    // Append current wave's validated blocker tuples to state-side
    // history. State history is the single source of truth for the loop
    // detector — no raw handoff re-reads. Cycle 4's clear command will
    // prune this history per surface so re-blocked surfaces start fresh.
    const priorHistory = Array.isArray(state.blocked_prereq_history) ? state.blocked_prereq_history : [];
    const newHistoryEntries = (merge.blocked_prereqs || []).map((entry) => {
      const record = {
        wave: waveNumber,
        surface_id: entry.surface_id,
        kind: entry.kind,
      };
      if (entry.identifier_hint) record.identifier_hint = entry.identifier_hint;
      if (entry.reason) record.reason = entry.reason;
      return record;
    });
    const nextHistory = [...priorHistory, ...newHistoryEntries];

    // Build per-surface history map for the detector.
    const historyBySurface = new Map();
    for (const entry of nextHistory) {
      if (!historyBySurface.has(entry.surface_id)) historyBySurface.set(entry.surface_id, []);
      historyBySurface.get(entry.surface_id).push(entry);
    }

    // Build current wave's blocker map per surface from merge.blocked_prereqs.
    const currentWaveBlockersBySurface = new Map();
    for (const entry of merge.blocked_prereqs || []) {
      if (!currentWaveBlockersBySurface.has(entry.surface_id)) currentWaveBlockersBySurface.set(entry.surface_id, []);
      currentWaveBlockersBySurface.get(entry.surface_id).push({
        kind: entry.kind,
        identifier_hint: entry.identifier_hint || null,
        reason: entry.reason,
      });
    }

    const priorSnapshots = Array.isArray(state.prereq_registry_snapshots) ? state.prereq_registry_snapshots : [];
    const clearHistory = Array.isArray(state.terminal_block_clear_history) ? state.terminal_block_clear_history : [];
    const clearHistoryBySurface = new Map();
    for (const entry of clearHistory) {
      if (!clearHistoryBySurface.has(entry.surface_id)) clearHistoryBySurface.set(entry.surface_id, []);
      clearHistoryBySurface.get(entry.surface_id).push(entry);
    }
    const promotions = detectTerminalPromotions({
      currentWaveBlockersBySurface,
      historyBySurface,
      prereqRegistrySnapshots: priorSnapshots,
      clearHistoryBySurface,
      currentWave: waveNumber,
    });
    // Merge promotions into existing state.terminally_blocked. If the
    // same surface is promoted twice, the new wave's promotion wins.
    // Disjointness with state.explored is enforced at normalize time;
    // a complete handoff in a later wave strips terminally_blocked.
    const promotedSurfaceIds = new Set(promotions.map((p) => p.surface_id));
    const carriedTerminallyBlocked = (Array.isArray(state.terminally_blocked) ? state.terminally_blocked : [])
      .filter((entry) => !promotedSurfaceIds.has(entry.surface_id));
    const nextTerminallyBlocked = [...carriedTerminallyBlocked, ...promotions];

    const explored = [...state.explored];
    const deadEnds = [...state.dead_ends];
    const wafBlockedEndpoints = [...state.waf_blocked_endpoints];
    const leadSurfaceIds = [...state.lead_surface_ids];
    const deepPromotion = state.deep_mode === true
      ? promoteSurfaceLeadsInternal(domain, {
          limit: 8,
          min_score: 60,
          update_state: false,
        })
      : { promoted_surface_ids: [] };
    const attackSurface = readAttackSurfaceStrict(domain);

    // The structured handoff's `surface_status: complete` is the contract;
    // coverage rows are endpoint-level advisory history. A hunter that wrote
    // `complete` and ALSO wrote some unfinished coverage rows during the same
    // wave is internally inconsistent, but the right place to catch that is
    // either the hunter prompt or a server-side handoff validator — not a
    // silent downgrade that strands the surface in HUNT forever. Trust the
    // handoff and add to explored unconditionally.
    pushUnique(
      explored,
      new Set(explored),
      merge.completed_surface_ids,
    );
    pushUnique(deadEnds, new Set(deadEnds), merge.dead_ends);
    pushUnique(wafBlockedEndpoints, new Set(wafBlockedEndpoints), merge.waf_blocked_endpoints);
    pushUnique(leadSurfaceIds, new Set(leadSurfaceIds), merge.lead_surface_ids);
    pushUnique(leadSurfaceIds, new Set(leadSurfaceIds), deepPromotion.promoted_surface_ids || []);

    // Disjointness invariant: a surface marked complete in this wave wins
    // over any prior terminal promotion. Strip from terminally_blocked.
    const exploredSet = new Set(explored);
    const reconciledTerminallyBlocked = nextTerminallyBlocked.filter(
      (entry) => !exploredSet.has(entry.surface_id),
    );
    const reconciledTerminallySet = new Set(reconciledTerminallyBlocked.map((e) => e.surface_id));

    const filteredLeadSurfaceIds = leadSurfaceIds.filter(
      (surfaceId) =>
        attackSurface.surface_id_set.has(surfaceId) &&
        !explored.includes(surfaceId) &&
        !reconciledTerminallySet.has(surfaceId),
    );

    // Filter requeue: terminally-blocked surfaces are not "requeue
    // candidates" — the orchestrator must clear them via
    // bounty_clear_terminal_block before they can be assigned again.
    const filteredRequeueSurfaceIds = requeueSurfaceIds.filter(
      (surfaceId) => !reconciledTerminallySet.has(surfaceId),
    );

    // Snapshots are populated by start_wave; merge does not write them.
    const nextState = {
      ...state,
      explored,
      terminally_blocked: reconciledTerminallyBlocked,
      blocked_prereq_history: nextHistory,
      dead_ends: deadEnds,
      waf_blocked_endpoints: wafBlockedEndpoints,
      lead_surface_ids: filteredLeadSurfaceIds,
      scope_exclusions: scopeExclusions,
      pending_wave: null,
      hunt_wave: waveNumber,
      total_findings: findings.total,
    };

    writeSessionStateDocument(domain, raw, nextState);
    // Emit one surface_terminally_blocked event per (surface, blocker)
    // pair so analytics can attribute promotions back to specific
    // missing-prereq tuples without joining against state.
    for (const promotion of promotions) {
      for (const blocker of promotion.blockers) {
        safeAppendPipelineEventDirect(domain, "surface_terminally_blocked", {
          phase: state.phase,
          wave_number: waveNumber,
          status: "promoted",
          source: "bounty_apply_wave_merge",
          surface_id: promotion.surface_id,
          kind: blocker.kind,
          identifier_hint: blocker.identifier_hint || null,
        });
      }
    }
    safeAppendPipelineEventDirect(domain, "wave_merged", {
      phase: state.phase,
      wave_number: waveNumber,
      force_merge: forceMerge,
      force_merge_reason: forceMergeReason,
      status: "merged",
      source: "bounty_apply_wave_merge",
      counts: {
        assignments: readiness.assignments_total,
        handoffs: readiness.handoffs_total,
        received_handoffs: merge.received_agents.length,
        invalid_handoffs: merge.invalid_agents.length,
        unexpected_handoffs: merge.unexpected_agents.length,
        missing_surfaces: merge.missing_surface_ids.length,
        requeue_surfaces: filteredRequeueSurfaceIds.length,
        terminally_blocked_promoted: promotions.length,
        terminally_blocked_total: reconciledTerminallyBlocked.length,
        findings: findings.total,
      },
    });
    return JSON.stringify({
      version: 1,
      status: "merged",
      wave_number: waveNumber,
      force_merge: forceMerge,
      force_merge_reason: forceMergeReason,
      readiness,
      merge: {
        received_agents: merge.received_agents,
        invalid_agents: merge.invalid_agents,
        unexpected_agents: merge.unexpected_agents,
        completed_surface_ids: merge.completed_surface_ids,
        partial_surface_ids: merge.partial_surface_ids,
        missing_surface_ids: merge.missing_surface_ids,
        requeue_surface_ids: filteredRequeueSurfaceIds,
        new_dead_ends_count: merge.dead_ends.length,
        new_waf_blocked_count: merge.waf_blocked_endpoints.length,
        lead_surface_ids: merge.lead_surface_ids,
        blocked_harness_runs: merge.blocked_harness_runs,
        blocked_harness_runs_grouped: merge.blocked_harness_runs_grouped,
        blocked_prereqs: merge.blocked_prereqs,
        blocked_prereqs_grouped: merge.blocked_prereqs_grouped,
        terminally_blocked_promoted: promotions,
        bypass_attempts: merge.bypass_attempts,
        bypass_attempts_grouped: merge.bypass_attempts_grouped,
        suspicion_flags: merge.suspicion_flags,
        ...(state.deep_mode === true ? { deep_promoted_surface_ids: deepPromotion.promoted_surface_ids || [] } : {}),
        provenance: merge.provenance,
      },
      findings,
      state: compactSessionState(nextState),
    });
  });
}

function writeHandoff(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });

  const lines = [];
  lines.push(`# Handoff — Session ${args.session_number}`);
  lines.push(`## Target: ${args.target_url}`);
  if (args.program_url) lines.push(`## Program: ${args.program_url}`);
  const findings = args.findings_summary || [];
  lines.push(`\n## Findings (${findings.length})`);
  for (const f of findings) lines.push(`- ${f.id} [${(f.severity || "").toUpperCase()}]: ${f.title}`);
  lines.push("\n## Explored");
  for (const e of args.explored_with_results || []) lines.push(`- ${e}`);
  lines.push("\n## Dead Ends");
  for (const d of args.dead_ends || []) lines.push(`- ${d}`);
  lines.push("\n## Unexplored");
  for (const u of args.unexplored || []) lines.push(`- ${u}`);
  lines.push("\n## Must Do Next");
  for (const m of args.must_do_next || []) lines.push(`- [${m.priority}] ${m.description}`);
  lines.push("\n## Promising Leads");
  for (const p of args.promising_leads || []) lines.push(`- ${p}`);

  const handoffPath = path.join(dir, `SESSION_HANDOFF.md`);
  writeFileAtomic(handoffPath, lines.join("\n") + "\n");
  return JSON.stringify({ written: handoffPath });
}

function logDeadEnds(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const wave = parseWaveId(args.wave);
  const agent = parseAgentId(args.agent);
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");

  validateAssignedWaveAgentSurface(domain, wave, agent, surfaceId);

  const deadEnds = normalizeStringArray(args.dead_ends, "dead_ends");
  const wafBlocked = normalizeStringArray(args.waf_blocked_endpoints, "waf_blocked_endpoints");

  if (deadEnds.length === 0 && wafBlocked.length === 0) {
    return JSON.stringify({ appended: 0, message: "Nothing to log" });
  }

  const dir = sessionDir(domain);
  const logPath = path.join(dir, `live-dead-ends-${wave}-${agent}.jsonl`);
  const record = {
    ts: new Date().toISOString(),
    surface_id: surfaceId,
    dead_ends: deadEnds,
    waf_blocked_endpoints: wafBlocked,
  };
  appendJsonlLine(logPath, record);

  return JSON.stringify({
    appended: deadEnds.length + wafBlocked.length,
    dead_ends: deadEnds.length,
    waf_blocked_endpoints: wafBlocked.length,
    log_path: logPath,
  });
}

// Reserved for future paths that need to consult attack_surface.json directly.
// The smart_contract completion gate does NOT use this — it reads from the
// MCP-owned, tamper-resistant assignment file (captured at start_wave time
// in mcp/lib/waves.js startWave). Reading from attack_surface.json would
// allow a hunter with Bash access to mutate the file and disable enforcement.
function lookupSurfaceType(domain, surfaceId) {
  const attackSurface = readAttackSurfaceStrict(domain);
  const surface = (attackSurface.document.surfaces || []).find((entry) => entry && entry.id === surfaceId);
  if (!surface) return null;
  if (typeof surface.surface_type === "string" && surface.surface_type.trim() !== "") {
    return surface.surface_type.trim();
  }
  return null;
}

function writeWaveHandoff(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const wave = parseWaveId(args.wave);
  const agent = parseAgentId(args.agent);
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  const surfaceStatus = parseSurfaceStatus(args.surface_status);
  const summary = normalizeHandoffSummary(args, { requireStructuredSummary: true });
  const chainNotes = normalizeChainNotes(args.chain_notes);
  const blockedHarnessRuns = normalizeBlockedHarnessRuns(args.blocked_harness_runs);
  const blockedPrereqs = normalizeBlockedPrereqs(args.blocked_prereqs);

  if (typeof args.content !== "string") {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "content must be a string");
  }

  return withSessionLock(domain, () => {
    const assignment = validateAssignedWaveAgentSurface(domain, wave, agent, surfaceId);
    const provenance = validateHandoffToken(assignment, args.handoff_token);
    const surfaceLeadResult = recordSurfaceLeadsInternal(domain, Array.isArray(args.surface_leads) ? args.surface_leads : [], {
      source: "hunter_handoff",
      source_wave: wave,
      source_agent: agent,
      source_surface_id: surfaceId,
    });

    // Read surface_type from the immutable, MCP-owned assignment file (captured
    // at start_wave time). Reading from agent-writable attack_surface.json would
    // let a hunter disable the smart_contract gate via Bash mutation.
    const surfaceType = assignment.surface_type || null;
    const findingsForRun = readFindingsFromJsonl(domain).filter((finding) => (
      finding.wave === wave &&
      finding.agent === agent &&
      finding.surface_id === surfaceId
    ));
    const findingIdSet = new Set(findingsForRun.map((finding) => finding.id));
    const bypassAttempts = normalizeBypassAttempts(args.bypass_attempts, { findingIds: findingIdSet });
    assertBlockedHarnessConsistency(surfaceStatus, blockedHarnessRuns);
    assertBlockedPrereqConsistency(surfaceStatus, blockedPrereqs);
    assertSmartContractCompletionEvidence({
      surfaceType,
      surfaceStatus,
      bypassAttempts,
      findingCount: findingsForRun.length,
    });

    const handoff = {
      target_domain: domain,
      wave,
      agent,
      surface_id: surfaceId,
      surface_type: surfaceType,
      surface_status: surfaceStatus,
      provenance,
      summary,
      chain_notes: chainNotes,
      blocked_harness_runs: blockedHarnessRuns,
      blocked_prereqs: blockedPrereqs,
      bypass_attempts: bypassAttempts,
      dead_ends: normalizeStringArray(args.dead_ends, "dead_ends"),
      waf_blocked_endpoints: normalizeStringArray(args.waf_blocked_endpoints, "waf_blocked_endpoints"),
      lead_surface_ids: normalizeStringArray(args.lead_surface_ids, "lead_surface_ids"),
    };
    if (surfaceLeadResult.lead_ids.length > 0) {
      handoff.surface_lead_ids = surfaceLeadResult.lead_ids;
    }

    const dir = sessionDir(domain);
    const markdownPath = path.join(dir, `handoff-${wave}-${agent}.md`);
    const jsonPath = path.join(dir, `handoff-${wave}-${agent}.json`);

    writeFileAtomic(markdownPath, args.content);
    writeFileAtomic(jsonPath, JSON.stringify(handoff, null, 2) + "\n");

    return JSON.stringify({
      written_md: markdownPath,
      written_json: jsonPath,
      provenance,
      surface_lead_ids: surfaceLeadResult.lead_ids,
    });
  });
}

function waveHandoffStatus(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  return JSON.stringify(buildWaveReadiness(loadWaveArtifacts(domain, waveNumber)));
}

function mergeWaveHandoffs(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  const { readiness, merge } = mergeWaveHandoffsInternal(domain, waveNumber);

  return JSON.stringify({
    assignments_total: readiness.assignments_total,
    handoffs_total: readiness.handoffs_total,
    received_agents: merge.received_agents,
    invalid_agents: merge.invalid_agents,
    unexpected_agents: merge.unexpected_agents,
    completed_surface_ids: merge.completed_surface_ids,
    partial_surface_ids: merge.partial_surface_ids,
    missing_surface_ids: merge.missing_surface_ids,
    dead_ends: merge.dead_ends,
    waf_blocked_endpoints: merge.waf_blocked_endpoints,
    lead_surface_ids: merge.lead_surface_ids,
    blocked_harness_runs: merge.blocked_harness_runs,
    blocked_harness_runs_grouped: merge.blocked_harness_runs_grouped,
    blocked_prereqs: merge.blocked_prereqs,
    blocked_prereqs_grouped: merge.blocked_prereqs_grouped,
    bypass_attempts: merge.bypass_attempts,
    bypass_attempts_grouped: merge.bypass_attempts_grouped,
    suspicion_flags: merge.suspicion_flags,
    provenance: merge.provenance,
  });
}

function listWaveAssignmentNumbers(domain) {
  const dir = sessionDir(domain);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .map((fileName) => {
      const match = fileName.match(/^wave-([1-9][0-9]*)-assignments\.json$/);
      return match ? Number(match[1]) : null;
    })
    .filter((waveNumber) => Number.isInteger(waveNumber))
    .sort((a, b) => a - b);
}

function buildWaveHandoffsDocument(domain, waveNumbers) {
  const handoffs = [];
  const missingHandoffs = [];
  const invalidHandoffs = [];
  const unexpectedHandoffs = [];

  // Pre-read findings once per call, not per handoff.
  const allFindings = readFindingsFromJsonl(domain);
  const findingsByRun = new Map();
  for (const finding of allFindings) {
    const runKey = `${finding.wave} ${finding.agent} ${finding.surface_id}`;
    if (!findingsByRun.has(runKey)) findingsByRun.set(runKey, []);
    findingsByRun.get(runKey).push(finding);
  }

  for (const waveNumber of waveNumbers) {
    const artifacts = loadWaveArtifacts(domain, waveNumber);
    for (const agent of artifacts.unexpectedAgents) {
      unexpectedHandoffs.push({ wave: artifacts.wave, agent });
    }

    for (const assignment of artifacts.assignments) {
      const filePath = artifacts.handoffPathByAgent.get(assignment.agent);
      if (!filePath) {
        missingHandoffs.push({
          wave: artifacts.wave,
          agent: assignment.agent,
          surface_id: assignment.surface_id,
        });
        continue;
      }

      try {
        const handoffJson = readJsonFile(filePath);
        const runKey = `${artifacts.wave} ${assignment.agent} ${assignment.surface_id}`;
        const findingsForRun = findingsByRun.get(runKey) || [];
        const effectiveSurfaceType = assignment.surface_type || null;
        const payload = validateWaveHandoffPayload(handoffJson, {
          targetDomain: domain,
          wave: artifacts.wave,
          agent: assignment.agent,
          surfaceId: assignment.surface_id,
          effectiveSurfaceType,
          findingsForRun,
        });
        const provenance = validateHandoffProvenance(handoffJson, assignment);
        const handoff = {
          wave: artifacts.wave,
          agent: assignment.agent,
          surface_id: assignment.surface_id,
          surface_type: payload.surface_type,
          surface_status: payload.surface_status,
          provenance,
          summary: payload.summary,
          chain_notes: payload.chain_notes,
          blocked_harness_runs: payload.blocked_harness_runs,
          blocked_prereqs: payload.blocked_prereqs,
          bypass_attempts: payload.bypass_attempts,
          dead_ends: payload.dead_ends,
          waf_blocked_endpoints: payload.waf_blocked_endpoints,
          lead_surface_ids: payload.lead_surface_ids,
        };
        if (payload.surface_lead_ids.length > 0) {
          handoff.surface_lead_ids = payload.surface_lead_ids;
        }
        handoffs.push(handoff);
      } catch (error) {
        invalidHandoffs.push({
          wave: artifacts.wave,
          agent: assignment.agent,
          surface_id: assignment.surface_id,
          error: error.message || String(error),
        });
      }
    }
  }

  return {
    version: 1,
    target_domain: domain,
    wave_numbers: waveNumbers,
    handoffs,
    missing_handoffs: missingHandoffs,
    invalid_handoffs: invalidHandoffs,
    unexpected_handoffs: unexpectedHandoffs,
  };
}

function readWaveHandoffs(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumbers = args.wave_number == null
    ? listWaveAssignmentNumbers(domain)
    : [parseWaveNumber(args.wave_number)];

  return JSON.stringify(buildWaveHandoffsDocument(domain, waveNumbers));
}

module.exports = {
  applyWaveMerge,
  buildWaveHandoffsDocument,
  logDeadEnds,
  mergeWaveHandoffs,
  readWaveHandoffs,
  startWave,
  waveHandoffStatus,
  waveStatus,
  writeHandoff,
  writeWaveHandoff,
};
