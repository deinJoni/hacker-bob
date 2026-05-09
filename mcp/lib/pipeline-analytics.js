"use strict";

const fs = require("fs");
const path = require("path");
const {
  CHAIN_ATTEMPT_OUTCOME_VALUES,
  CHAIN_ATTEMPT_TERMINAL_OUTCOME_VALUES,
  COVERAGE_STATUS_VALUES,
  GRADE_VERDICT_VALUES,
  PHASE_VALUES,
  SEVERITY_VALUES,
  TECHNIQUE_ATTEMPT_STATUS_VALUES,
  VERIFICATION_ROUND_VALUES,
} = require("./constants.js");
const {
  assertNonEmptyString,
  normalizeStringArray,
  parseAgentId,
  parseWaveId,
} = require("./validation.js");
const {
  attackSurfacePath,
  chainAttemptsJsonlPath,
  coverageJsonlPath,
  evidencePackPaths,
  findingsJsonlPath,
  gradeArtifactPaths,
  httpAuditJsonlPath,
  pipelineEventsJsonlPath,
  reportMarkdownPath,
  sessionDir,
  sessionsRoot,
  statePath,
  techniqueAttemptsJsonlPath,
  techniquePackReadsJsonlPath,
  verificationAdjudicationPath,
  verificationAttemptsDir,
  verificationRoundPaths,
  verificationSnapshotPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  readJsonFile,
  withSessionLock,
} = require("./storage.js");
const {
  loadWaveAssignments,
} = require("./assignments.js");
const {
  readAgentRunTelemetryEvents,
  readToolTelemetryEvents,
  summarizeToolTelemetryEvents,
} = require("./tool-telemetry.js");
const {
  bobVersion,
} = require("./runtime-resources.js");
const {
  requireValidEvidencePacksForFinalReportableFindings,
} = require("./evidence.js");
const {
  buildCircuitBreakerSummary,
  readHttpAuditRecordsFromJsonl,
  summarizeHttpAuditRecords,
} = require("./http-records.js");

const PIPELINE_ANALYTICS_VERSION = 1;
const PIPELINE_EVENT_VERSION = 1;
const DEFAULT_WINDOW_DAYS = 30;
const MAX_WINDOW_DAYS = 365;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const STALE_PENDING_WAVE_MS = 2 * 60 * 60 * 1000;
const HIGH_TOOL_FAILURE_RATE = 0.2;
const HIGH_TOOL_FAILURE_MIN_FAILURES = 3;

const PIPELINE_EVENT_TYPES = Object.freeze([
  "session_started",
  "phase_transitioned",
  "wave_started",
  "hunter_stopped",
  "wave_merge_pending",
  "wave_merged",
  "coverage_logged",
  "technique_attempt_logged",
  "finding_recorded",
  "verification_snapshot_created",
  "verification_adjudication_built",
  "verification_replay_policy_applied",
  "verification_attempt_archived",
  "verification_archive_pruned",
  "verification_written",
  "evidence_written",
  "grade_written",
  "surface_terminally_blocked",
  "terminal_block_cleared",
  "report_written",
]);

function pipelineAnalyticsEnabled(env = process.env) {
  return env.BOUNTY_PIPELINE_ANALYTICS !== "0";
}

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function capString(value, maxChars = 200) {
  if (value == null) return null;
  const text = String(value).replace(/[\r\n\t]+/g, " ").trim();
  if (!text) return null;
  return text.length > maxChars ? text.slice(0, maxChars) : text;
}

function compactErrorMessage(error) {
  return error && error.message ? error.message : String(error);
}

function normalizeIsoTimestamp(value, fallback = new Date()) {
  if (value instanceof Date && Number.isFinite(value.getTime())) {
    return value.toISOString();
  }
  const text = capString(value, 80);
  if (text) {
    const parsedMs = Date.parse(text);
    if (Number.isFinite(parsedMs)) return new Date(parsedMs).toISOString();
  }
  return fallback.toISOString();
}

function timestampMs(value) {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function fileMtimeIso(filePath) {
  try {
    return new Date(fs.statSync(filePath).mtimeMs).toISOString();
  } catch {
    return null;
  }
}

function updateLatestIso(current, candidate) {
  if (!candidate) return current;
  if (!current) return candidate;
  return timestampMs(candidate) > timestampMs(current) ? candidate : current;
}

function normalizePositiveInteger(value, defaultValue, maxValue) {
  if (!Number.isFinite(value)) return defaultValue;
  return Math.max(1, Math.min(maxValue, Math.trunc(value)));
}

function normalizeCounts(counts) {
  if (!isPlainObject(counts)) return null;
  const normalized = {};
  for (const [key, value] of Object.entries(counts)) {
    const safeKey = capString(key, 80);
    if (!safeKey) continue;
    if (Number.isFinite(value)) {
      normalized[safeKey] = Math.max(0, Math.trunc(value));
    } else if (value === true || value === false) {
      normalized[safeKey] = value ? 1 : 0;
    }
  }
  return Object.keys(normalized).length ? normalized : null;
}

function normalizeWaveNumber(value) {
  if (Number.isInteger(value) && value > 0) return value;
  if (typeof value === "string") {
    const match = value.match(/^w([1-9][0-9]*)$/);
    if (match) return Number(match[1]);
  }
  return null;
}

function normalizePipelineEvent(targetDomain, type, fields = {}) {
  const domain = assertNonEmptyString(targetDomain || fields.target_domain, "target_domain");
  const eventType = capString(type || fields.type, 80);
  if (!PIPELINE_EVENT_TYPES.includes(eventType)) {
    throw new Error(`unknown pipeline event type: ${eventType || "<empty>"}`);
  }

  const event = {
    version: PIPELINE_EVENT_VERSION,
    bob_version: capString(fields.bob_version || bobVersion(), 80),
    ts: normalizeIsoTimestamp(fields.ts || fields.now),
    target_domain: domain,
    type: eventType,
  };

  const phase = capString(fields.phase, 40);
  const fromPhase = capString(fields.from_phase, 40);
  const toPhase = capString(fields.to_phase, 40);
  if (phase) event.phase = phase;
  if (fromPhase) event.from_phase = fromPhase;
  if (toPhase) event.to_phase = toPhase;

  const waveNumber = normalizeWaveNumber(fields.wave_number == null ? fields.wave : fields.wave_number);
  if (waveNumber != null) event.wave_number = waveNumber;

  const agent = capString(fields.agent, 40);
  const surfaceId = capString(fields.surface_id, 200);
  const status = capString(fields.status, 120);
  const blockCode = capString(fields.block_code, 120);
  const source = capString(fields.source, 120);
  const counts = normalizeCounts(fields.counts);
  // surface_terminally_blocked / terminal_block_cleared carry structured
  // prereq metadata. Kept short and bounded; identifier_hint is the
  // schema-validated handle (lowercase + ._-, <= 64 chars), kind is an
  // enum value. No free-text reasons — those go in state-side artifacts
  // (state.terminal_block_clear_history) so the event stream stays
  // free of secret-shaped strings.
  const kind = capString(fields.kind, 64);
  const identifierHint = capString(fields.identifier_hint, 64);
  if (agent) event.agent = agent;
  if (surfaceId) event.surface_id = surfaceId;
  if (status) event.status = status;
  if (blockCode) event.block_code = blockCode;
  if (counts) event.counts = counts;
  if (source) event.source = source;
  if (kind) event.kind = kind;
  if (identifierHint) event.identifier_hint = identifierHint;
  if (typeof fields.force_merge === "boolean") event.force_merge = fields.force_merge;
  const forceMergeReason = capString(fields.force_merge_reason, 1000);
  if (forceMergeReason) event.force_merge_reason = forceMergeReason;
  if (typeof fields.override === "boolean") event.override = fields.override;
  const overrideReason = capString(fields.override_reason, 1000);
  if (overrideReason) event.override_reason = overrideReason;

  for (const [sourceField, maxChars] of [
    ["verification_attempt_id", 120],
    ["verification_snapshot_hash", 128],
    ["adjudication_plan_hash", 128],
    ["final_verification_hash", 128],
    ["capability_pack", 128],
    ["lease_scope", 80],
    ["replay_purpose", 80],
  ]) {
    const safe = capString(fields[sourceField], maxChars);
    if (safe) event[sourceField] = safe;
  }

  return event;
}

function appendPipelineEventDirect(targetDomain, type, fields = {}, { env = process.env } = {}) {
  if (!pipelineAnalyticsEnabled(env)) return null;
  const event = normalizePipelineEvent(targetDomain, type, fields);
  appendJsonlLine(pipelineEventsJsonlPath(event.target_domain), event);
  return event;
}

function safeAppendPipelineEventDirect(targetDomain, type, fields = {}, options = {}) {
  try {
    return appendPipelineEventDirect(targetDomain, type, fields, options);
  } catch {
    return null;
  }
}

function safeAppendPipelineEventWithSessionLock(targetDomain, type, fields = {}, options = {}) {
  if (!pipelineAnalyticsEnabled(options.env || process.env)) return null;
  try {
    return withSessionLock(targetDomain, () => appendPipelineEventDirect(targetDomain, type, fields, options));
  } catch {
    return null;
  }
}

function safeRecordHunterStoppedPipelineEvent(input, options = {}) {
  if (!input || !input.target_domain) return null;
  return safeAppendPipelineEventWithSessionLock(input.target_domain, "hunter_stopped", {
    wave: input.wave,
    agent: input.agent,
    surface_id: input.surface_id,
    status: input.status,
    block_code: input.block_code == null ? input.blockCode : input.block_code,
    source: input.source || input.telemetry_source || "hunter-subagent-stop",
    now: input.now,
    counts: {
      coverage: input.coverage && Number.isFinite(input.coverage.total) ? input.coverage.total : 0,
      findings: input.findings && Number.isFinite(input.findings.count) ? input.findings.count : 0,
      handoff_present: input.handoff && input.handoff.present === true ? 1 : 0,
      handoff_valid: input.handoff && input.handoff.valid === true ? 1 : 0,
    },
  }, options);
}

function readJsonSafe(filePath, label) {
  const result = {
    exists: fs.existsSync(filePath),
    path: filePath,
    document: null,
    error: null,
    mtime: fileMtimeIso(filePath),
  };
  if (!result.exists) return result;
  try {
    result.document = readJsonFile(filePath);
  } catch (error) {
    result.error = `Malformed ${label}: ${error.message || String(error)}`;
  }
  return result;
}

function readJsonlSafe(filePath, label) {
  const result = {
    exists: fs.existsSync(filePath),
    path: filePath,
    records: [],
    malformed_lines: 0,
    error: null,
    mtime: fileMtimeIso(filePath),
  };
  if (!result.exists) return result;
  let content;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    result.error = `Unreadable ${label}: ${error.message || String(error)}`;
    return result;
  }
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line);
      if (!isPlainObject(parsed)) {
        result.malformed_lines += 1;
        continue;
      }
      result.records.push(parsed);
    } catch {
      result.malformed_lines += 1;
    }
  }
  return result;
}

function normalizePipelineEventForRead(record, expectedDomain) {
  if (!isPlainObject(record) || record.version !== PIPELINE_EVENT_VERSION) return null;
  const type = capString(record.type, 80);
  const targetDomain = capString(record.target_domain);
  if (!PIPELINE_EVENT_TYPES.includes(type) || !targetDomain) return null;
  if (expectedDomain && targetDomain !== expectedDomain) return null;
  const event = {
    version: PIPELINE_EVENT_VERSION,
    bob_version: capString(record.bob_version, 80),
    ts: normalizeIsoTimestamp(record.ts),
    target_domain: targetDomain,
    type,
  };
  const fieldCaps = {
    surface_id: 200,
    kind: 64,
    identifier_hint: 64,
    verification_snapshot_hash: 128,
    adjudication_plan_hash: 128,
    final_verification_hash: 128,
  };
  for (const field of ["phase", "from_phase", "to_phase", "agent", "surface_id", "status", "block_code", "source", "kind", "identifier_hint", "verification_attempt_id", "verification_snapshot_hash", "adjudication_plan_hash", "final_verification_hash", "capability_pack", "lease_scope", "replay_purpose"]) {
    const safe = capString(record[field], fieldCaps[field] || 120);
    if (safe) event[field] = safe;
  }
  const waveNumber = normalizeWaveNumber(record.wave_number);
  if (waveNumber != null) event.wave_number = waveNumber;
  const counts = normalizeCounts(record.counts);
  if (counts) event.counts = counts;
  if (typeof record.force_merge === "boolean") event.force_merge = record.force_merge;
  const forceMergeReason = capString(record.force_merge_reason, 1000);
  if (forceMergeReason) event.force_merge_reason = forceMergeReason;
  if (typeof record.override === "boolean") event.override = record.override;
  const overrideReason = capString(record.override_reason, 1000);
  if (overrideReason) event.override_reason = overrideReason;
  return event;
}

function listWaveAssignmentNumbers(targetDomain) {
  const dir = sessionDir(targetDomain);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .map((fileName) => {
      const match = fileName.match(/^wave-([1-9][0-9]*)-assignments\.json$/);
      return match ? Number(match[1]) : null;
    })
    .filter((waveNumber) => Number.isInteger(waveNumber))
    .sort((a, b) => a - b);
}

function listHandoffFiles(dir, waveId) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter((fileName) => fileName.startsWith(`handoff-${waveId}-`) && fileName.endsWith(".json"))
    .sort();
}

function validateHandoffMetadata(document, { targetDomain, wave, agent, surfaceId, requiresToken }) {
  if (!isPlainObject(document)) throw new Error("handoff payload must be an object");
  if (document.target_domain != null && document.target_domain !== targetDomain) throw new Error("target_domain mismatch");
  if (parseWaveId(document.wave) !== wave) throw new Error("wave mismatch");
  if (parseAgentId(document.agent) !== agent) throw new Error("agent mismatch");
  if (assertNonEmptyString(document.surface_id, "surface_id") !== surfaceId) throw new Error("surface_id mismatch");
  if (!["complete", "partial"].includes(capString(document.surface_status, 40))) {
    throw new Error("invalid surface_status");
  }
  if (requiresToken && document.provenance !== "verified") {
    throw new Error("handoff provenance is not verified");
  }
}

function readWaveReadiness(targetDomain, waveNumber) {
  const wave = `w${waveNumber}`;
  const result = {
    wave_number: waveNumber,
    assignments_total: 0,
    handoffs_total: 0,
    received_agents: [],
    missing_agents: [],
    invalid_agents: [],
    unexpected_agents: [],
    is_complete: false,
    error: null,
  };

  let artifacts;
  try {
    artifacts = loadWaveAssignments(targetDomain, waveNumber);
  } catch (error) {
    result.error = error.message || String(error);
    return result;
  }

  result.assignments_total = artifacts.assignments.length;
  const handoffFiles = listHandoffFiles(artifacts.dir, wave);
  result.handoffs_total = handoffFiles.length;
  const handoffPathByAgent = new Map();
  for (const fileName of handoffFiles) {
    const agent = fileName.slice(`handoff-${wave}-`.length, -".json".length);
    if (!artifacts.assignmentByAgent.has(agent)) {
      result.unexpected_agents.push(agent);
    } else {
      handoffPathByAgent.set(agent, path.join(artifacts.dir, fileName));
    }
  }

  for (const assignment of artifacts.assignments) {
    const handoffPath = handoffPathByAgent.get(assignment.agent);
    if (!handoffPath) {
      result.missing_agents.push(assignment.agent);
      continue;
    }
    try {
      validateHandoffMetadata(readJsonFile(handoffPath), {
        targetDomain,
        wave,
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
        requiresToken: !!assignment.handoff_token_sha256,
      });
      result.received_agents.push(assignment.agent);
    } catch {
      result.invalid_agents.push(assignment.agent);
    }
  }

  result.is_complete = result.missing_agents.length === 0 && result.invalid_agents.length === 0;
  return result;
}

function summarizeFindingsJsonl(targetDomain) {
  const read = readJsonlSafe(findingsJsonlPath(targetDomain), "findings.jsonl");
  const bySeverity = SEVERITY_VALUES.reduce((result, severity) => {
    result[severity] = 0;
    return result;
  }, {});
  for (const record of read.records) {
    const severity = capString(record.severity, 40);
    if (Object.prototype.hasOwnProperty.call(bySeverity, severity)) {
      bySeverity[severity] += 1;
    }
  }
  return {
    exists: read.exists,
    total: read.records.length,
    by_severity: bySeverity,
    malformed_lines: read.malformed_lines,
    error: read.error,
    mtime: read.mtime,
  };
}

function summarizeCoverageJsonl(targetDomain) {
  const read = readJsonlSafe(coverageJsonlPath(targetDomain), "coverage.jsonl");
  const byStatus = COVERAGE_STATUS_VALUES.reduce((result, status) => {
    result[status] = 0;
    return result;
  }, {});
  const surfaces = new Set();
  for (const record of read.records) {
    const status = capString(record.status, 40);
    if (Object.prototype.hasOwnProperty.call(byStatus, status)) {
      byStatus[status] += 1;
    }
    if (typeof record.surface_id === "string" && record.surface_id.trim()) {
      surfaces.add(record.surface_id.trim());
    }
  }
  return {
    exists: read.exists,
    total_records: read.records.length,
    surface_count: surfaces.size,
    by_status: byStatus,
    malformed_lines: read.malformed_lines,
    error: read.error,
    mtime: read.mtime,
  };
}

function summarizeTechniqueAttemptsJsonl(targetDomain) {
  const read = readJsonlSafe(techniqueAttemptsJsonlPath(targetDomain), "technique-attempts.jsonl");
  const byStatus = TECHNIQUE_ATTEMPT_STATUS_VALUES.reduce((result, status) => {
    result[status] = 0;
    return result;
  }, {});
  const surfaces = new Set();
  const packs = new Set();
  let total = 0;
  let invalidRecords = 0;

  for (const record of read.records) {
    const status = capString(record.status, 40);
    const surfaceId = capString(record.surface_id, 200);
    const packId = capString(record.pack_id, 128);
    if (
      record.target_domain !== targetDomain ||
      !TECHNIQUE_ATTEMPT_STATUS_VALUES.includes(status) ||
      !surfaceId ||
      !packId
    ) {
      invalidRecords += 1;
      continue;
    }
    total += 1;
    byStatus[status] += 1;
    surfaces.add(surfaceId);
    packs.add(packId);
  }

  return {
    exists: read.exists,
    total_records: total,
    surface_count: surfaces.size,
    pack_count: packs.size,
    by_status: byStatus,
    malformed_lines: read.malformed_lines + invalidRecords,
    error: read.error,
    mtime: read.mtime,
  };
}

function summarizeTechniquePackReadsJsonl(targetDomain) {
  const read = readJsonlSafe(techniquePackReadsJsonlPath(targetDomain), "technique-pack-reads.jsonl");
  const surfaces = new Set();
  const packs = new Set();
  let fullReads = 0;
  let invalidRecords = 0;

  for (const record of read.records) {
    const mode = capString(record.mode, 40);
    const surfaceId = capString(record.surface_id, 200);
    const packId = capString(record.pack_id, 128);
    if (record.target_domain !== targetDomain || mode !== "full" || !surfaceId || !packId) {
      invalidRecords += 1;
      continue;
    }
    fullReads += 1;
    surfaces.add(surfaceId);
    packs.add(packId);
  }

  return {
    exists: read.exists,
    total_records: fullReads,
    full_reads: fullReads,
    surface_count: surfaces.size,
    pack_count: packs.size,
    malformed_lines: read.malformed_lines + invalidRecords,
    error: read.error,
    mtime: read.mtime,
  };
}

function summarizeChainAttemptsJsonl(targetDomain) {
  const read = readJsonlSafe(chainAttemptsJsonlPath(targetDomain), "chain-attempts.jsonl");
  const byOutcome = CHAIN_ATTEMPT_OUTCOME_VALUES.reduce((result, outcome) => {
    result[outcome] = 0;
    return result;
  }, {});
  let total = 0;
  let terminalTotal = 0;
  let invalidRecords = 0;

  for (const record of read.records) {
    const outcome = capString(record.outcome, 40);
    if (record.target_domain !== targetDomain || !CHAIN_ATTEMPT_OUTCOME_VALUES.includes(outcome)) {
      invalidRecords += 1;
      continue;
    }
    total += 1;
    byOutcome[outcome] += 1;
    if (CHAIN_ATTEMPT_TERMINAL_OUTCOME_VALUES.includes(outcome)) {
      terminalTotal += 1;
    }
  }

  return {
    exists: read.exists,
    total,
    terminal_total: terminalTotal,
    by_outcome: byOutcome,
    malformed_lines: read.malformed_lines + invalidRecords,
    error: read.error,
    mtime: read.mtime,
  };
}

function summarizeHttpAuditJsonl(targetDomain) {
  const filePath = httpAuditJsonlPath(targetDomain);
  const summary = {
    exists: fs.existsSync(filePath),
    total: 0,
    errors: 0,
    scope_blocked: 0,
    network_unreachable_target: 0,
    egress: { by_profile: {}, by_region: {} },
    geofence_warning: {
      threshold: 3,
      warning: false,
      code: null,
      note: null,
      hosts: [],
    },
    circuit_breaker_summary: buildCircuitBreakerSummary([]),
    error: null,
    mtime: fileMtimeIso(filePath),
  };
  if (!summary.exists) return summary;
  try {
    const records = readHttpAuditRecordsFromJsonl(targetDomain);
    const auditSummary = summarizeHttpAuditRecords(records, { targetDomain });
    summary.total = auditSummary.total;
    summary.errors = auditSummary.errors;
    summary.scope_blocked = auditSummary.scope_blocked;
    summary.network_unreachable_target = auditSummary.network_unreachable_target;
    summary.egress = auditSummary.egress;
    summary.geofence_warning = auditSummary.geofence_warning;
    summary.circuit_breaker_summary = buildCircuitBreakerSummary(records);
  } catch (error) {
    summary.error = `Malformed http-audit.jsonl: ${error.message || String(error)}`;
  }
  return summary;
}

function summarizeStructuredHandoffChainNotes(targetDomain) {
  const dir = sessionDir(targetDomain);
  const summary = {
    chain_notes_count: 0,
    handoff_count: 0,
    handoff_refs: [],
    malformed_files: 0,
  };
  if (!fs.existsSync(dir)) return summary;

  for (const fileName of fs.readdirSync(dir).sort()) {
    const match = fileName.match(/^handoff-(w[1-9][0-9]*)-(a[1-9][0-9]*)\.json$/);
    if (!match) continue;
    let document;
    try {
      document = readJsonFile(path.join(dir, fileName));
    } catch {
      summary.malformed_files += 1;
      continue;
    }
    if (!isPlainObject(document)) {
      summary.malformed_files += 1;
      continue;
    }
    if (document.target_domain != null && document.target_domain !== targetDomain) continue;
    let chainNotes;
    try {
      chainNotes = normalizeStringArray(document.chain_notes, "chain_notes");
    } catch {
      summary.malformed_files += 1;
      continue;
    }
    if (chainNotes.length === 0) continue;
    summary.handoff_count += 1;
    summary.chain_notes_count += chainNotes.length;
    summary.handoff_refs.push({
      wave: match[1],
      agent: match[2],
      surface_id: capString(document.surface_id, 200),
      chain_notes_count: chainNotes.length,
    });
  }

  return summary;
}

function summarizeVerificationArtifacts(targetDomain) {
  const rounds = {};
  let latestMtime = null;
  const errors = [];
  let finalReportableIds = [];
  const snapshotRead = readJsonSafe(verificationSnapshotPath(targetDomain), "verification input snapshot JSON");
  const adjudicationRead = readJsonSafe(verificationAdjudicationPath(targetDomain), "verification adjudication JSON");
  latestMtime = updateLatestIso(latestMtime, snapshotRead.mtime);
  latestMtime = updateLatestIso(latestMtime, adjudicationRead.mtime);
  const snapshot = {
    exists: snapshotRead.exists,
    schema_version: isPlainObject(snapshotRead.document) && Number.isInteger(snapshotRead.document.schema_version)
      ? snapshotRead.document.schema_version
      : null,
    attempt_id: isPlainObject(snapshotRead.document) ? capString(snapshotRead.document.verification_attempt_id, 120) : null,
    snapshot_hash: isPlainObject(snapshotRead.document) ? capString(snapshotRead.document.snapshot_hash, 128) : null,
    finding_count: isPlainObject(snapshotRead.document) && Array.isArray(snapshotRead.document.finding_ids)
      ? snapshotRead.document.finding_ids.length
      : 0,
    input_hashes: isPlainObject(snapshotRead.document) && isPlainObject(snapshotRead.document.input_hashes)
      ? snapshotRead.document.input_hashes
      : null,
    mtime: snapshotRead.mtime,
    error: snapshotRead.error,
  };
  if (snapshotRead.error) errors.push(snapshotRead.error);
  const adjudication = {
    exists: adjudicationRead.exists,
    current_attempt_id: isPlainObject(adjudicationRead.document) ? capString(adjudicationRead.document.verification_attempt_id, 120) : null,
    snapshot_hash: isPlainObject(adjudicationRead.document) ? capString(adjudicationRead.document.verification_snapshot_hash, 128) : null,
    adjudication_plan_hash: isPlainObject(adjudicationRead.document) ? capString(adjudicationRead.document.adjudication_plan_hash, 128) : null,
    agreed_count: isPlainObject(adjudicationRead.document) && Array.isArray(adjudicationRead.document.agreed)
      ? adjudicationRead.document.agreed.length
      : 0,
    disagreement_count: isPlainObject(adjudicationRead.document) && Array.isArray(adjudicationRead.document.disagreements)
      ? adjudicationRead.document.disagreements.length
      : 0,
    replay_required_count: isPlainObject(adjudicationRead.document) && Array.isArray(adjudicationRead.document.replay_required_ids)
      ? adjudicationRead.document.replay_required_ids.length
      : 0,
    qa_sample_count: isPlainObject(adjudicationRead.document) && Array.isArray(adjudicationRead.document.qa_sampled_ids)
      ? adjudicationRead.document.qa_sampled_ids.length
      : 0,
    mtime: adjudicationRead.mtime,
    error: adjudicationRead.error,
  };
  if (adjudicationRead.error) errors.push(adjudicationRead.error);
  for (const round of VERIFICATION_ROUND_VALUES) {
    const paths = verificationRoundPaths(targetDomain, round);
    const read = readJsonSafe(paths.json, `${round} verification round JSON`);
    latestMtime = updateLatestIso(latestMtime, read.mtime);
    const summary = {
      exists: read.exists,
      valid: false,
      results_count: 0,
      reportable_count: 0,
      confirmed_count: 0,
      mtime: read.mtime,
      error: read.error,
    };
    if (read.error) errors.push(read.error);
    if (isPlainObject(read.document) && Array.isArray(read.document.results)) {
      summary.valid = read.document.target_domain === targetDomain && read.document.round === round;
      summary.schema_version = read.document.version || null;
      summary.verification_attempt_id = capString(read.document.verification_attempt_id, 120);
      summary.verification_snapshot_hash = capString(read.document.verification_snapshot_hash, 128);
      summary.adjudication_plan_hash = capString(read.document.adjudication_plan_hash, 128);
      summary.final_verification_hash = capString(read.document.final_verification_hash, 128);
      summary.results_count = read.document.results.length;
      summary.reportable_count = read.document.results.filter((result) => result && result.reportable === true).length;
      summary.confirmed_count = read.document.results.filter((result) => result && result.disposition === "confirmed").length;
      if (round === "final") {
        finalReportableIds = read.document.results
          .filter((result) => result && result.reportable === true && typeof result.finding_id === "string")
          .map((result) => result.finding_id);
      }
      if (!summary.valid) {
        summary.error = `${round} verification artifact metadata mismatch`;
        errors.push(summary.error);
      }
    }
    rounds[round] = summary;
  }
  const schemaVersion = (
    snapshot.exists ||
    adjudication.exists ||
    Object.values(rounds).some((round) => round.schema_version === 2)
  )
    ? 2
    : (Object.values(rounds).some((round) => round.schema_version === 1) ? 1 : null);
  return {
    schema_version: schemaVersion,
    current_attempt_id: snapshot.attempt_id,
    snapshot_hash: snapshot.snapshot_hash,
    snapshot,
    adjudication,
    archived_attempts: summarizeArchivedVerificationAttempts(targetDomain),
    rounds,
    final_results_count: rounds.final.results_count,
    final_reportable_count: rounds.final.reportable_count,
    final_reportable_ids: finalReportableIds,
    errors,
    latest_mtime: latestMtime,
  };
}

function summarizeArchivedVerificationAttempts(targetDomain) {
  const dir = verificationAttemptsDir(targetDomain);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && /^attempt-/.test(entry.name))
    .map((entry) => {
      const archiveDir = path.join(dir, entry.name);
      const manifestRead = readJsonSafe(path.join(archiveDir, "manifest.json"), "verification attempt manifest JSON");
      return {
        attempt_id: isPlainObject(manifestRead.document) && manifestRead.document.attempt_id
          ? capString(manifestRead.document.attempt_id, 120)
          : entry.name.replace(/^attempt-/, ""),
        archive_dir: archiveDir,
        archived_at: isPlainObject(manifestRead.document) ? capString(manifestRead.document.archived_at, 80) : null,
        snapshot_hash: isPlainObject(manifestRead.document) ? capString(manifestRead.document.snapshot_hash, 128) : null,
        adjudication_plan_hash: isPlainObject(manifestRead.document) ? capString(manifestRead.document.adjudication_plan_hash, 128) : null,
        final_verification_hash: isPlainObject(manifestRead.document) ? capString(manifestRead.document.final_verification_hash, 128) : null,
        files_count: isPlainObject(manifestRead.document) && isPlainObject(manifestRead.document.files)
          ? Object.keys(manifestRead.document.files).length
          : 0,
        missing_files_count: isPlainObject(manifestRead.document) && Array.isArray(manifestRead.document.missing_files)
          ? manifestRead.document.missing_files.length
          : 0,
      };
    })
    .sort((a, b) => String(b.archived_at || "").localeCompare(String(a.archived_at || "")) || a.attempt_id.localeCompare(b.attempt_id));
}

function summarizeEvidenceArtifacts(targetDomain, finalReportableIds) {
  const paths = evidencePackPaths(targetDomain);
  const read = readJsonSafe(paths.json, "evidence packs JSON");
  const finalReportableSet = new Set(finalReportableIds);
  const summary = {
    exists: read.exists,
    valid: false,
    skipped: finalReportableIds.length === 0 && !read.exists,
    packs_count: 0,
    representative_samples_count: 0,
    reportable_findings_covered: 0,
    final_reportable_count: finalReportableIds.length,
    missing_finding_ids: finalReportableIds.slice(),
    duplicate_finding_ids: [],
    extra_finding_ids: [],
    verification_attempt_id: isPlainObject(read.document) ? capString(read.document.verification_attempt_id, 120) : null,
    verification_snapshot_hash: isPlainObject(read.document) ? capString(read.document.verification_snapshot_hash, 128) : null,
    final_verification_hash: isPlainObject(read.document) ? capString(read.document.final_verification_hash, 128) : null,
    error: read.error,
    mtime: read.mtime,
  };

  if (finalReportableIds.length === 0 && !read.exists) {
    summary.valid = true;
    return summary;
  }

  if (isPlainObject(read.document) && Array.isArray(read.document.packs)) {
    if (read.document.version !== 1 || read.document.target_domain !== targetDomain) {
      summary.error = "evidence packs artifact metadata mismatch";
    }

    const seen = new Set();
    const duplicateIds = new Set();
    for (const pack of read.document.packs) {
      if (!isPlainObject(pack) || typeof pack.finding_id !== "string") {
        summary.error = summary.error || "evidence packs artifact has malformed pack entries";
        continue;
      }
      summary.packs_count += 1;
      if (seen.has(pack.finding_id)) {
        duplicateIds.add(pack.finding_id);
      }
      seen.add(pack.finding_id);
      if (Array.isArray(pack.representative_samples)) {
        summary.representative_samples_count += pack.representative_samples.length;
      }
    }

    summary.duplicate_finding_ids = Array.from(duplicateIds).sort();
    summary.missing_finding_ids = finalReportableIds.filter((id) => !seen.has(id));
    summary.extra_finding_ids = Array.from(seen).filter((id) => !finalReportableSet.has(id)).sort();
    summary.reportable_findings_covered = finalReportableIds.filter((id) => seen.has(id)).length;
  } else if (read.exists && !read.error) {
    summary.error = "evidence packs artifact metadata mismatch";
  }

  try {
    const validation = requireValidEvidencePacksForFinalReportableFindings(targetDomain);
    summary.exists = validation.exists;
    summary.valid = true;
    summary.skipped = validation.skipped;
    summary.packs_count = validation.packs_count;
    summary.representative_samples_count = validation.representative_samples_count;
    summary.reportable_findings_covered = validation.reportable_findings_covered;
    summary.final_reportable_count = validation.final_reportable_count;
    summary.missing_finding_ids = [];
    summary.duplicate_finding_ids = [];
    summary.extra_finding_ids = [];
    summary.verification_attempt_id = validation.document.verification_attempt_id || null;
    summary.verification_snapshot_hash = validation.document.verification_snapshot_hash || null;
    summary.final_verification_hash = validation.document.final_verification_hash || null;
    summary.error = null;
  } catch (error) {
    summary.valid = false;
    summary.error = compactErrorMessage(error);
    if (summary.missing_finding_ids.length === 0 && finalReportableIds.length > 0 && summary.reportable_findings_covered < finalReportableIds.length) {
      summary.missing_finding_ids = finalReportableIds.slice();
    }
  }
  return summary;
}

function summarizeGradeArtifact(targetDomain) {
  const paths = gradeArtifactPaths(targetDomain);
  const read = readJsonSafe(paths.json, "grade verdict JSON");
  const summary = {
    exists: read.exists,
    valid: false,
    verdict: null,
    total_score: null,
    findings_count: 0,
    error: read.error,
    mtime: read.mtime,
  };
  if (isPlainObject(read.document)) {
    const verdict = capString(read.document.verdict, 40);
    summary.valid = read.document.target_domain === targetDomain && GRADE_VERDICT_VALUES.includes(verdict);
    summary.verdict = verdict;
    summary.total_score = Number.isFinite(read.document.total_score) ? Math.trunc(read.document.total_score) : null;
    summary.findings_count = Array.isArray(read.document.findings) ? read.document.findings.length : 0;
    if (!summary.valid) {
      summary.error = "grade artifact metadata mismatch";
    }
  }
  return summary;
}

function summarizeAttackSurfaceCoverage(targetDomain, state) {
  const read = readJsonSafe(attackSurfacePath(targetDomain), "attack_surface.json");
  if (!isPlainObject(read.document) || !Array.isArray(read.document.surfaces)) {
    return {
      exists: read.exists,
      error: read.error,
      total_surfaces: 0,
      non_low_total: 0,
      non_low_explored: 0,
      non_low_terminally_blocked: 0,
      coverage_pct: null,
      closed_pct: null,
      unexplored_high: 0,
      blocked_high: 0,
      mtime: read.mtime,
    };
  }
  const exploredSet = new Set(Array.isArray(state?.explored) ? state.explored : []);
  const terminallyBlockedSet = new Set(
    Array.isArray(state?.terminally_blocked)
      ? state.terminally_blocked.map((entry) => entry && typeof entry.surface_id === "string" ? entry.surface_id : null).filter(Boolean)
      : [],
  );
  const surfaces = read.document.surfaces.filter((surface) => isPlainObject(surface) && typeof surface.id === "string");
  const nonLowSurfaces = surfaces.filter((surface) => (surface.priority || "HIGH").toUpperCase() !== "LOW");
  const highSurfaces = surfaces.filter((surface) => ["CRITICAL", "HIGH"].includes((surface.priority || "HIGH").toUpperCase()));
  const exploredNonLow = nonLowSurfaces.filter((surface) => exploredSet.has(surface.id)).length;
  const blockedNonLow = nonLowSurfaces.filter((surface) => terminallyBlockedSet.has(surface.id)).length;
  const closedNonLow = exploredNonLow + blockedNonLow;
  return {
    exists: true,
    error: null,
    total_surfaces: surfaces.length,
    non_low_total: nonLowSurfaces.length,
    non_low_explored: exploredNonLow,
    non_low_terminally_blocked: blockedNonLow,
    // coverage_pct keeps the explored-only meaning for back-compat with
    // existing dashboards. closed_pct is the post-Cycle-2 measure that
    // also counts terminally_blocked surfaces (classified blocked, not
    // neglected). low_coverage analytics fires on closed_pct so blocked
    // surfaces correctly count as "off the queue".
    coverage_pct: nonLowSurfaces.length ? Math.round((exploredNonLow / nonLowSurfaces.length) * 100) : 100,
    closed_pct: nonLowSurfaces.length ? Math.round((closedNonLow / nonLowSurfaces.length) * 100) : 100,
    unexplored_high: highSurfaces.filter((surface) => !exploredSet.has(surface.id) && !terminallyBlockedSet.has(surface.id)).length,
    blocked_high: highSurfaces.filter((surface) => terminallyBlockedSet.has(surface.id)).length,
    mtime: read.mtime,
  };
}

function readSessionArtifactSummary(targetDomain) {
  const dir = sessionDir(targetDomain);
  const stateRead = readJsonSafe(statePath(targetDomain), "session state");
  const state = isPlainObject(stateRead.document) ? stateRead.document : null;
  const waveNumbers = listWaveAssignmentNumbers(targetDomain);
  if (state && Number.isInteger(state.pending_wave) && state.pending_wave > 0 && !waveNumbers.includes(state.pending_wave)) {
    waveNumbers.push(state.pending_wave);
    waveNumbers.sort((a, b) => a - b);
  }

  const waves = waveNumbers.map((waveNumber) => readWaveReadiness(targetDomain, waveNumber));
  const findings = summarizeFindingsJsonl(targetDomain);
  const coverage = summarizeCoverageJsonl(targetDomain);
  const techniqueAttempts = summarizeTechniqueAttemptsJsonl(targetDomain);
  const techniquePackReads = summarizeTechniquePackReadsJsonl(targetDomain);
  const httpAudit = summarizeHttpAuditJsonl(targetDomain);
  const chainAttempts = summarizeChainAttemptsJsonl(targetDomain);
  const chainHandoffs = summarizeStructuredHandoffChainNotes(targetDomain);
  const attackSurfaceCoverage = summarizeAttackSurfaceCoverage(targetDomain, state);
  const verification = summarizeVerificationArtifacts(targetDomain);
  const evidence = summarizeEvidenceArtifacts(targetDomain, verification.final_reportable_ids);
  const grade = summarizeGradeArtifact(targetDomain);
  const reportPath = reportMarkdownPath(targetDomain);
  const reportMtime = fileMtimeIso(reportPath);

  let latestMtime = null;
  for (const value of [
    stateRead.mtime,
    findings.mtime,
    coverage.mtime,
    techniqueAttempts.mtime,
    techniquePackReads.mtime,
    httpAudit.mtime,
    chainAttempts.mtime,
    attackSurfaceCoverage.mtime,
    verification.latest_mtime,
    evidence.mtime,
    grade.mtime,
    reportMtime,
  ]) {
    latestMtime = updateLatestIso(latestMtime, value);
  }

  const artifactErrors = [];
  if (!stateRead.exists) artifactErrors.push("Missing session state");
  if (stateRead.error) artifactErrors.push(stateRead.error);
  if (findings.error) artifactErrors.push(findings.error);
  if (coverage.error) artifactErrors.push(coverage.error);
  if (techniqueAttempts.error) artifactErrors.push(techniqueAttempts.error);
  if (techniquePackReads.error) artifactErrors.push(techniquePackReads.error);
  if (httpAudit.error) artifactErrors.push(httpAudit.error);
  if (chainAttempts.error) artifactErrors.push(chainAttempts.error);
  if (findings.malformed_lines > 0) artifactErrors.push(`Malformed findings.jsonl lines: ${findings.malformed_lines}`);
  if (coverage.malformed_lines > 0) artifactErrors.push(`Malformed coverage.jsonl lines: ${coverage.malformed_lines}`);
  if (techniqueAttempts.malformed_lines > 0) artifactErrors.push(`Malformed technique-attempts.jsonl lines: ${techniqueAttempts.malformed_lines}`);
  if (techniquePackReads.malformed_lines > 0) artifactErrors.push(`Malformed technique-pack-reads.jsonl lines: ${techniquePackReads.malformed_lines}`);
  if (chainAttempts.malformed_lines > 0) artifactErrors.push(`Malformed chain-attempts.jsonl lines: ${chainAttempts.malformed_lines}`);
  if (chainHandoffs.malformed_files > 0) artifactErrors.push(`Malformed chain handoff files: ${chainHandoffs.malformed_files}`);
  for (const wave of waves) {
    if (wave.error) artifactErrors.push(`Wave ${wave.wave_number}: ${wave.error}`);
  }
  artifactErrors.push(...verification.errors);
  if (evidence.error) artifactErrors.push(evidence.error);
  if (grade.error) artifactErrors.push(grade.error);

  return {
    target_domain: targetDomain,
    session_dir: dir,
    state: {
      exists: stateRead.exists,
      phase: capString(state?.phase, 40),
      auth_status: capString(state?.auth_status, 40),
      hunt_wave: Number.isInteger(state?.hunt_wave) ? state.hunt_wave : 0,
      pending_wave: Number.isInteger(state?.pending_wave) ? state.pending_wave : null,
      total_findings: Number.isInteger(state?.total_findings) ? state.total_findings : findings.total,
      hold_count: Number.isInteger(state?.hold_count) ? state.hold_count : 0,
      verification_schema_version: Number.isInteger(state?.verification_schema_version) ? state.verification_schema_version : null,
      verification_attempt_id: capString(state?.verification_attempt_id, 120),
      verification_snapshot_hash: capString(state?.verification_snapshot_hash, 128),
      verification_entered_at: capString(state?.verification_entered_at, 80),
      mtime: stateRead.mtime,
      error: stateRead.error,
    },
    waves,
    findings,
    coverage,
    technique_attempts: techniqueAttempts,
    technique_pack_reads: techniquePackReads,
    http_audit: httpAudit,
    chain_attempts: chainAttempts,
    chain_handoffs: chainHandoffs,
    attack_surface_coverage: attackSurfaceCoverage,
    verification,
    evidence,
    grade,
    report: {
      present: fs.existsSync(reportPath),
      path: reportPath,
      mtime: reportMtime,
    },
    artifact_errors: artifactErrors,
    latest_artifact_ts: latestMtime,
  };
}

function buildBackfillEvents(targetDomain, artifacts) {
  const source = "artifact_backfill";
  const ts = artifacts.latest_artifact_ts || new Date().toISOString();
  const events = [];
  events.push(normalizePipelineEvent(targetDomain, "session_started", {
    ts: artifacts.state.mtime || ts,
    phase: "RECON",
    source,
  }));
  if (artifacts.state.phase && artifacts.state.phase !== "RECON") {
    events.push(normalizePipelineEvent(targetDomain, "phase_transitioned", {
      ts: artifacts.state.mtime || ts,
      to_phase: artifacts.state.phase,
      status: "current",
      source,
    }));
  }
  for (const wave of artifacts.waves) {
    events.push(normalizePipelineEvent(targetDomain, "wave_started", {
      ts,
      wave_number: wave.wave_number,
      status: wave.error ? "invalid" : "started",
      counts: { assignments: wave.assignments_total },
      source,
    }));
    if (artifacts.state.pending_wave === wave.wave_number) {
      events.push(normalizePipelineEvent(targetDomain, "wave_merge_pending", {
        ts,
        wave_number: wave.wave_number,
        status: "pending",
        counts: {
          assignments: wave.assignments_total,
          handoffs: wave.handoffs_total,
          missing_handoffs: wave.missing_agents.length,
          invalid_handoffs: wave.invalid_agents.length,
        },
        source,
      }));
    } else if (artifacts.state.hunt_wave >= wave.wave_number) {
      events.push(normalizePipelineEvent(targetDomain, "wave_merged", {
        ts,
        wave_number: wave.wave_number,
        status: "merged",
        counts: {
          assignments: wave.assignments_total,
          handoffs: wave.handoffs_total,
          invalid_handoffs: wave.invalid_agents.length,
        },
        source,
      }));
    }
  }
  if (artifacts.coverage.total_records > 0) {
    events.push(normalizePipelineEvent(targetDomain, "coverage_logged", {
      ts: artifacts.coverage.mtime || ts,
      status: "backfilled",
      counts: { records: artifacts.coverage.total_records, surfaces: artifacts.coverage.surface_count },
      source,
    }));
  }
  if (artifacts.technique_attempts.total_records > 0) {
    events.push(normalizePipelineEvent(targetDomain, "technique_attempt_logged", {
      ts: artifacts.technique_attempts.mtime || ts,
      status: "backfilled",
      counts: {
        records: artifacts.technique_attempts.total_records,
        surfaces: artifacts.technique_attempts.surface_count,
        packs: artifacts.technique_attempts.pack_count,
      },
      source,
    }));
  }
  if (artifacts.findings.total > 0) {
    events.push(normalizePipelineEvent(targetDomain, "finding_recorded", {
      ts: artifacts.findings.mtime || ts,
      status: "backfilled",
      counts: { findings: artifacts.findings.total },
      source,
    }));
  }
  for (const round of VERIFICATION_ROUND_VALUES) {
    const summary = artifacts.verification.rounds[round];
    if (!summary.exists) continue;
    events.push(normalizePipelineEvent(targetDomain, "verification_written", {
      ts: summary.mtime || ts,
      status: round,
      counts: { results: summary.results_count, reportable: summary.reportable_count },
      source,
    }));
  }
  if (artifacts.evidence.exists) {
    events.push(normalizePipelineEvent(targetDomain, "evidence_written", {
      ts: artifacts.evidence.mtime || ts,
      status: artifacts.evidence.valid ? "valid" : "invalid",
      counts: {
        packs: artifacts.evidence.packs_count,
        representative_samples: artifacts.evidence.representative_samples_count,
        reportable_findings_covered: artifacts.evidence.reportable_findings_covered,
      },
      source,
    }));
  }
  if (artifacts.grade.exists) {
    events.push(normalizePipelineEvent(targetDomain, "grade_written", {
      ts: artifacts.grade.mtime || ts,
      status: artifacts.grade.verdict || "unknown",
      counts: { findings: artifacts.grade.findings_count, total_score: artifacts.grade.total_score || 0 },
      source,
    }));
  }
  return events.sort((a, b) => timestampMs(a.ts) - timestampMs(b.ts));
}

function readPipelineEvents(targetDomain, { allowBackfill = true } = {}) {
  const filePath = pipelineEventsJsonlPath(targetDomain);
  const result = {
    enabled: pipelineAnalyticsEnabled(),
    events_path: filePath,
    exists: fs.existsSync(filePath),
    events: [],
    malformed_lines: 0,
    backfilled: false,
  };

  if (result.exists) {
    const read = readJsonlSafe(filePath, "pipeline-events.jsonl");
    result.malformed_lines = read.malformed_lines;
    for (const record of read.records) {
      const event = normalizePipelineEventForRead(record, targetDomain);
      if (event) {
        result.events.push(event);
      } else {
        result.malformed_lines += 1;
      }
    }
  }

  if (allowBackfill && result.events.length === 0) {
    result.events = buildBackfillEvents(targetDomain, readSessionArtifactSummary(targetDomain));
    result.backfilled = true;
  }

  result.events.sort((a, b) => timestampMs(a.ts) - timestampMs(b.ts));
  return result;
}

function latestEvent(events) {
  return events.length ? events[events.length - 1] : null;
}

function latestActivityTimestamp(events, artifacts) {
  const latest = latestEvent(events);
  const latestMs = Math.max(timestampMs(latest?.ts), timestampMs(artifacts.latest_artifact_ts));
  return latestMs > 0 ? new Date(latestMs).toISOString() : null;
}

function compactEvent(event) {
  if (!event) return null;
  const compact = {
    ts: event.ts,
    bob_version: event.bob_version,
    target_domain: event.target_domain,
    type: event.type,
  };
  for (const field of ["phase", "from_phase", "to_phase", "wave_number", "agent", "surface_id", "status", "block_code", "counts", "source", "force_merge", "force_merge_reason", "override", "override_reason", "kind", "identifier_hint", "verification_attempt_id", "verification_snapshot_hash", "adjudication_plan_hash", "final_verification_hash", "capability_pack", "lease_scope", "replay_purpose"]) {
    if (event[field] != null) compact[field] = event[field];
  }
  return compact;
}

function filterByWindow(events, cutoffMs) {
  if (!cutoffMs) return events;
  return events.filter((event) => timestampMs(event.ts) >= cutoffMs);
}

function slimToolHealth(readResult, events, limit) {
  const summary = summarizeToolTelemetryEvents(events, { limit });
  const topFailureTools = summary.tools
    .filter((tool) => tool.failures > 0)
    .sort((a, b) => b.failures - a.failures || b.calls - a.calls || a.tool.localeCompare(b.tool))
    .slice(0, limit)
    .map((tool) => ({
      tool: tool.tool,
      calls: tool.calls,
      failures: tool.failures,
      success_rate: tool.success_rate,
      error_codes: tool.error_codes,
    }));
  return {
    enabled: readResult.enabled,
    telemetry_path: readResult.telemetry_path,
    total_events: events.length,
    malformed_lines: readResult.malformed_lines,
    totals: {
      calls: summary.totals.calls,
      successes: summary.totals.successes,
      failures: summary.totals.failures,
      success_rate: summary.totals.success_rate,
      error_codes: summary.totals.error_codes,
    },
    top_failure_tools: topFailureTools,
    recent_failures: events
      .filter((event) => !event.ok)
      .slice(-limit)
      .reverse()
      .map((event) => ({
        ts: event.ts,
        tool: event.tool,
        error_code: event.error_code,
        target_domain: event.target_domain,
        wave: event.wave,
        agent: event.agent,
        surface_id: event.surface_id,
      })),
  };
}

function buildToolHealth({ targetDomain = null, cutoffMs = null, limit = DEFAULT_LIMIT, env = process.env } = {}) {
  const readResult = readToolTelemetryEvents({ target_domain: targetDomain, env });
  return slimToolHealth(readResult, filterByWindow(readResult.events, cutoffMs), limit);
}

function buildHunterHealth({ targetDomain = null, cutoffMs = null, limit = DEFAULT_LIMIT, env = process.env } = {}) {
  const readResult = readAgentRunTelemetryEvents({
    target_domain: targetDomain,
    agent_run_type: "hunter",
    env,
  });
  const events = filterByWindow(readResult.events, cutoffMs);
  const byStatus = { allowed: 0, blocked: 0 };
  const byBlockCode = {};
  for (const event of events) {
    byStatus[event.status] = (byStatus[event.status] || 0) + 1;
    if (event.status === "blocked" && event.block_code) {
      byBlockCode[event.block_code] = (byBlockCode[event.block_code] || 0) + 1;
    }
  }
  return {
    enabled: readResult.enabled,
    telemetry_path: readResult.telemetry_path,
    total_runs: events.length,
    malformed_lines: readResult.malformed_lines,
    totals: {
      by_status: byStatus,
      by_block_code: byBlockCode,
    },
    recent_blocked_runs: events
      .filter((event) => event.status === "blocked")
      .slice(-limit)
      .reverse()
      .map((event) => ({
        ts: event.ts,
        block_code: event.block_code,
        target_domain: event.target_domain,
        wave: event.wave,
        agent: event.agent,
        surface_id: event.surface_id,
        handoff: {
          present: event.handoff.present,
          valid: event.handoff.valid,
        },
        coverage: event.coverage,
        findings: event.findings,
      })),
  };
}

function phaseIndex(phase) {
  return PHASE_VALUES.indexOf(phase);
}

function phaseAtLeast(phase, requiredPhase) {
  const current = phaseIndex(phase);
  const required = phaseIndex(requiredPhase);
  return current >= 0 && required >= 0 && current >= required;
}

function computeChainPhaseDurationMs(events) {
  let chainStartMs = null;
  for (const event of events) {
    if (event.type !== "phase_transitioned") continue;
    if (event.to_phase === "CHAIN") {
      chainStartMs = timestampMs(event.ts);
      continue;
    }
    if (event.to_phase === "VERIFY" && chainStartMs != null) {
      const verifyMs = timestampMs(event.ts);
      return verifyMs >= chainStartMs ? verifyMs - chainStartMs : null;
    }
  }
  return null;
}

function issue(code, severity, message, evidence = {}) {
  return { code, severity, message, evidence };
}

function analyzeSession(targetDomain, { cutoffMs = null, limit = DEFAULT_LIMIT, env = process.env } = {}) {
  const artifacts = readSessionArtifactSummary(targetDomain);
  const eventRead = readPipelineEvents(targetDomain);
  const events = filterByWindow(eventRead.events, cutoffMs);
  const allEvents = eventRead.events;
  const toolHealth = buildToolHealth({ targetDomain, cutoffMs, limit, env });
  const hunterHealth = buildHunterHealth({ targetDomain, cutoffMs, limit, env });
  const issues = [];

  if (artifacts.artifact_errors.length > 0) {
    issues.push(issue("unreadable_artifacts", "blocked", "Session has missing or unreadable required artifacts.", {
      errors: artifacts.artifact_errors.slice(0, limit),
    }));
  }

  const pendingWave = artifacts.state.pending_wave;
  const pendingReadiness = pendingWave == null
    ? null
    : artifacts.waves.find((wave) => wave.wave_number === pendingWave) || null;
  if (pendingReadiness && (pendingReadiness.missing_agents.length > 0 || pendingReadiness.invalid_agents.length > 0)) {
    issues.push(issue("hunter_handoff_failures", "blocked", "Pending wave has missing or invalid hunter handoffs.", {
      wave_number: pendingWave,
      missing_handoffs: pendingReadiness.missing_agents.length,
      invalid_handoffs: pendingReadiness.invalid_agents.length,
    }));
  }

  const blockedHunterRuns = hunterHealth.totals.by_status.blocked || 0;
  if (blockedHunterRuns >= 2) {
    issues.push(issue("repeated_hunter_stops", "blocked", "Hunter SubagentStop blocks repeated for this session.", {
      blocked_runs: blockedHunterRuns,
      by_block_code: hunterHealth.totals.by_block_code,
    }));
  }

  if (phaseAtLeast(artifacts.state.phase, "GRADE") && !artifacts.verification.rounds.final.valid) {
    issues.push(issue("missing_verification", "blocked", "Session reached GRADE without a valid final verification artifact.", {
      phase: artifacts.state.phase,
    }));
  }

  if (
    phaseAtLeast(artifacts.state.phase, "GRADE") &&
    artifacts.verification.final_reportable_count > 0 &&
    !artifacts.evidence.valid
  ) {
    issues.push(issue("missing_evidence", "blocked", "Session reached GRADE or later without valid evidence packs for final reportable findings.", {
      phase: artifacts.state.phase,
      final_reportable: artifacts.verification.final_reportable_count,
      covered: artifacts.evidence.reportable_findings_covered,
      missing_finding_ids: artifacts.evidence.missing_finding_ids,
    }));
  }

  if (phaseAtLeast(artifacts.state.phase, "REPORT") && !artifacts.grade.valid) {
    issues.push(issue("missing_grade", "blocked", "Session reached REPORT without a valid grade artifact.", {
      phase: artifacts.state.phase,
    }));
  }

  if (phaseAtLeast(artifacts.state.phase, "REPORT") && !artifacts.report.present) {
    issues.push(issue("missing_report", "needs_attention", "Session reached REPORT but report.md is not present.", {
      phase: artifacts.state.phase,
    }));
  }

  const toolCalls = toolHealth.totals.calls;
  const toolFailures = toolHealth.totals.failures;
  if (toolFailures >= HIGH_TOOL_FAILURE_MIN_FAILURES && toolCalls > 0 && toolFailures / toolCalls > HIGH_TOOL_FAILURE_RATE) {
    issues.push(issue("mcp_tool_failures", "needs_attention", "MCP tool failure rate is high.", {
      calls: toolCalls,
      failures: toolFailures,
      failure_rate: Number((toolFailures / toolCalls).toFixed(4)),
      top_failure_tools: toolHealth.top_failure_tools.slice(0, 5),
    }));
  }

  const authFailures = Object.entries(toolHealth.totals.error_codes || {})
    .filter(([code]) => /AUTH/i.test(code))
    .reduce((total, [, count]) => total + count, 0);
  if (authFailures > 0) {
    issues.push(issue("auth_failures", "needs_attention", "Auth-related MCP failures are present.", {
      failures: authFailures,
    }));
  }

  if (artifacts.http_audit.geofence_warning && artifacts.http_audit.geofence_warning.warning) {
    issues.push(issue("network_unreachable_target", "needs_attention", "Repeated first-party network failures may indicate geofencing or target reachability problems.", {
      egress: artifacts.http_audit.egress,
      geofence_warning: artifacts.http_audit.geofence_warning,
      circuit_breaker: artifacts.http_audit.circuit_breaker_summary,
    }));
  }

  const coverage = artifacts.attack_surface_coverage;
  if (
    phaseAtLeast(artifacts.state.phase, "CHAIN") &&
    coverage.non_low_total > 0 &&
    Number.isFinite(coverage.closed_pct) &&
    coverage.closed_pct < 100
  ) {
    issues.push(issue("low_coverage", "needs_attention", "Non-low attack surface coverage is below the wave policy target — this counts BOTH explored AND terminally_blocked as closed; the gap is genuinely unexplored.", {
      coverage_pct: coverage.coverage_pct,
      closed_pct: coverage.closed_pct,
      non_low_explored: coverage.non_low_explored,
      non_low_terminally_blocked: coverage.non_low_terminally_blocked,
      non_low_total: coverage.non_low_total,
      unexplored_high: coverage.unexplored_high,
      blocked_high: coverage.blocked_high,
    }));
  }

  const chainWorkRequired = artifacts.findings.total >= 2 || artifacts.chain_handoffs.chain_notes_count > 0;
  if (
    phaseAtLeast(artifacts.state.phase, "CHAIN") &&
    chainWorkRequired &&
    artifacts.chain_attempts.terminal_total === 0
  ) {
    issues.push(issue("chain_phase_no_attempts", "blocked", "CHAIN phase has required chain work but no terminal structured chain attempts.", {
      findings: artifacts.findings.total,
      handoff_chain_notes: artifacts.chain_handoffs.chain_notes_count,
      attempts: artifacts.chain_attempts.total,
      by_outcome: artifacts.chain_attempts.by_outcome,
    }));
  }

  if (
    artifacts.findings.total > 0 &&
    artifacts.verification.rounds.final.exists &&
    (artifacts.verification.final_results_count === 0 || artifacts.verification.final_reportable_count === 0)
  ) {
    issues.push(issue("verification_dropoff", "needs_attention", "Final verification dropped all recorded findings or reportable findings.", {
      findings: artifacts.findings.total,
      final_results: artifacts.verification.final_results_count,
      final_reportable: artifacts.verification.final_reportable_count,
    }));
  }

  // HOLD is the only verdict that is operator-actionable on its own — the
  // grader is asking for another HUNT round. SKIP is internally consistent
  // by construction: writeGradeVerdict rejects any SKIP that does not
  // satisfy `!hasReportableMedium || total_score < GRADE_HOLD_MIN_SCORE`,
  // so a SKIP at read time is either "no reportables" or "low-score
  // reportables below the HOLD threshold." Both are the grader doing its
  // job, not anomalies.
  if (artifacts.grade.verdict === "HOLD") {
    issues.push(issue("grade_hold", "needs_attention", "Grade verdict is HOLD; grader requested another round.", {
      verdict: artifacts.grade.verdict,
      total_score: artifacts.grade.total_score,
    }));
  }

  const latest = latestEvent(allEvents);
  const latestActivityTs = latestActivityTimestamp(allEvents, artifacts);
  const latestActivityMs = timestampMs(latestActivityTs);
  if (pendingWave != null && latestActivityMs > 0 && Date.now() - latestActivityMs > STALE_PENDING_WAVE_MS) {
    issues.push(issue("stale_pending_wave", "needs_attention", "Pending wave has not advanced recently.", {
      wave_number: pendingWave,
      latest_event: compactEvent(latest),
      latest_artifact_ts: artifacts.latest_artifact_ts,
      latest_activity_ts: latestActivityTs,
    }));
  }

  const healthStatus = issues.some((item) => item.severity === "blocked")
    ? "blocked"
    : issues.some((item) => item.severity === "needs_attention")
      ? "needs_attention"
      : "healthy";

  const row = {
    target_domain: targetDomain,
    phase: artifacts.state.phase,
    auth_status: artifacts.state.auth_status,
    waves: {
      hunt_wave: artifacts.state.hunt_wave,
      pending_wave: artifacts.state.pending_wave,
      assignment_files: artifacts.waves.length,
      pending_handoffs_missing: pendingReadiness ? pendingReadiness.missing_agents.length : 0,
      pending_handoffs_invalid: pendingReadiness ? pendingReadiness.invalid_agents.length : 0,
    },
    findings: {
      total: artifacts.findings.total,
      by_severity: artifacts.findings.by_severity,
    },
    chain_attempts_count: artifacts.chain_attempts.total,
    chain_attempts_by_outcome: artifacts.chain_attempts.by_outcome,
    technique_attempts: {
      total: artifacts.technique_attempts.total_records,
      by_status: artifacts.technique_attempts.by_status,
      surface_count: artifacts.technique_attempts.surface_count,
      pack_count: artifacts.technique_attempts.pack_count,
    },
    technique_pack_reads: {
      total: artifacts.technique_pack_reads.total_records,
      full_reads: artifacts.technique_pack_reads.full_reads,
      surface_count: artifacts.technique_pack_reads.surface_count,
      pack_count: artifacts.technique_pack_reads.pack_count,
    },
    chain_phase_duration_ms: computeChainPhaseDurationMs(allEvents),
    final_verification_count: artifacts.verification.final_results_count,
    final_reportable_count: artifacts.verification.final_reportable_count,
    evidence: {
      exists: artifacts.evidence.exists,
      valid: artifacts.evidence.valid,
      packs_count: artifacts.evidence.packs_count,
      representative_samples_count: artifacts.evidence.representative_samples_count,
      reportable_findings_covered: artifacts.evidence.reportable_findings_covered,
      missing_finding_ids: artifacts.evidence.missing_finding_ids,
    },
    egress: artifacts.http_audit.egress,
    geofence_warnings: artifacts.http_audit.geofence_warning,
    http_audit: {
      total: artifacts.http_audit.total,
      errors: artifacts.http_audit.errors,
      scope_blocked: artifacts.http_audit.scope_blocked,
      network_unreachable_target: artifacts.http_audit.network_unreachable_target,
    },
    grade_verdict: artifacts.grade.verdict,
    report_present: artifacts.report.present,
    latest_event: compactEvent(latest),
    latest_activity_ts: latestActivityTs,
    health: {
      status: healthStatus,
      reasons: issues.map((item) => item.code),
    },
  };

  return {
    target_domain: targetDomain,
    row,
    artifacts,
    event_read: eventRead,
    events,
    issues,
    tool_health: toolHealth,
    hunter_health: hunterHealth,
  };
}

function sessionReachedPhase(analysis, phase) {
  if (phase === "REPORT" && analysis.artifacts.report.present) return true;
  if (phaseAtLeast(analysis.artifacts.state.phase, phase)) return true;
  return analysis.event_read.events.some((event) => event.to_phase === phase || event.phase === phase);
}

function buildFunnel(analyses) {
  const funnel = {
    sessions_total: analyses.length,
    reached: {
      AUTH: 0,
      HUNT: 0,
      CHAIN: 0,
      VERIFY: 0,
      GRADE: 0,
      REPORT: 0,
    },
    findings_total: 0,
    final_verification_total: 0,
    final_reportable_total: 0,
    grade_total: 0,
    report_total: 0,
  };

  for (const analysis of analyses) {
    for (const phase of Object.keys(funnel.reached)) {
      if (sessionReachedPhase(analysis, phase)) funnel.reached[phase] += 1;
    }
    funnel.findings_total += analysis.artifacts.findings.total;
    funnel.final_verification_total += analysis.artifacts.verification.final_results_count;
    funnel.final_reportable_total += analysis.artifacts.verification.final_reportable_count;
    if (analysis.artifacts.grade.exists) funnel.grade_total += 1;
    if (analysis.artifacts.report.present) funnel.report_total += 1;
  }

  return funnel;
}

function severityRank(severity) {
  if (severity === "blocked") return 2;
  if (severity === "needs_attention") return 1;
  return 0;
}

function buildBottlenecks(analyses, limit) {
  const grouped = new Map();
  for (const analysis of analyses) {
    for (const item of analysis.issues) {
      if (!grouped.has(item.code)) {
        grouped.set(item.code, {
          code: item.code,
          severity: item.severity,
          affected_targets: [],
          evidence: [],
        });
      }
      const group = grouped.get(item.code);
      if (severityRank(item.severity) > severityRank(group.severity)) {
        group.severity = item.severity;
      }
      group.affected_targets.push(analysis.target_domain);
      group.evidence.push({ target_domain: analysis.target_domain, ...item.evidence });
    }
  }

  return Array.from(grouped.values())
    .map((group) => ({
      code: group.code,
      severity: group.severity,
      affected_count: group.affected_targets.length,
      affected_targets: group.affected_targets.slice(0, limit),
      evidence: group.evidence.slice(0, limit),
    }))
    .sort((a, b) => (
      b.affected_count - a.affected_count ||
      severityRank(b.severity) - severityRank(a.severity) ||
      a.code.localeCompare(b.code)
    ))
    .slice(0, limit);
}

function actionForBottleneck(bottleneck) {
  const actionByCode = {
    unreadable_artifacts: "Repair or remove malformed session artifacts before resuming orchestration.",
    hunter_handoff_failures: "Resume the pending wave after missing hunters write valid structured handoffs, or force-merge intentionally.",
    repeated_hunter_stops: "Fix the hunter final-marker or handoff path that is repeatedly blocking SubagentStop.",
    mcp_tool_failures: "Inspect failing MCP tools and address the dominant error code before launching more agents.",
    network_unreachable_target: "Log blocked coverage/dead-end context, then choose an explicit egress profile if the operator approves a regional retry.",
    auth_failures: "Refresh or recapture auth profiles before additional authenticated testing.",
    low_coverage: "Launch another wave for unexplored non-low surfaces before verification.",
    chain_phase_no_attempts: "Run the chain-builder again so it records terminal chain attempts, or transition with an explicit override reason.",
    verification_dropoff: "Review final verification inputs because recorded findings are not surviving as reportable.",
    grade_hold: "Use grader feedback to launch a targeted HUNT wave, then re-run CHAIN -> VERIFY before grading again.",
    missing_verification: "Write a valid final verification round before grading or reporting.",
    missing_evidence: "Run the evidence agent and validate evidence packs before grading or reporting.",
    missing_grade: "Write a valid grade verdict before report completion.",
    missing_report: "Write report.md or move the session out of REPORT if report writing is still pending.",
    stale_pending_wave: "Re-enter resume flow for the stale pending wave and reconcile handoffs.",
  };
  return {
    action: actionByCode[bottleneck.code] || "Inspect this bottleneck before continuing.",
    reason: `${bottleneck.affected_count} session(s) affected by ${bottleneck.code}.`,
    affected_targets: bottleneck.affected_targets,
    source_evidence: bottleneck.evidence,
  };
}

function buildNextActions(bottlenecks, limit) {
  return bottlenecks.slice(0, limit).map(actionForBottleneck);
}

function listSessionDomains() {
  const root = sessionsRoot();
  if (!fs.existsSync(root)) return [];
  return fs.readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .filter((name) => {
      try {
        assertNonEmptyString(name, "target_domain");
        sessionDir(name);
        return true;
      } catch {
        return false;
      }
    })
    .sort();
}

function normalizeReadArgs(args = {}) {
  const targetDomain = args.target_domain == null ? null : assertNonEmptyString(args.target_domain, "target_domain");
  return {
    target_domain: targetDomain,
    window_days: normalizePositiveInteger(args.window_days, DEFAULT_WINDOW_DAYS, MAX_WINDOW_DAYS),
    limit: normalizePositiveInteger(args.limit, DEFAULT_LIMIT, MAX_LIMIT),
    include_events: args.include_events === true,
  };
}

function readPipelineAnalytics(args = {}, { env = process.env } = {}) {
  const options = normalizeReadArgs(args);
  const cutoffMs = Date.now() - options.window_days * 24 * 60 * 60 * 1000;

  if (options.target_domain) {
    const analysis = analyzeSession(options.target_domain, {
      cutoffMs: null,
      limit: options.limit,
      env,
    });
    const bottlenecks = buildBottlenecks([analysis], options.limit);
    const response = {
      version: PIPELINE_ANALYTICS_VERSION,
      mode: "session",
      target_domain: options.target_domain,
      filters: options,
      sessions: [analysis.row],
      funnel: buildFunnel([analysis]),
      bottlenecks,
      next_actions: buildNextActions(bottlenecks, options.limit),
      tool_health: analysis.tool_health,
      hunter_health: analysis.hunter_health,
      event_log: {
        enabled: analysis.event_read.enabled,
        path: analysis.event_read.events_path,
        exists: analysis.event_read.exists,
        malformed_lines: analysis.event_read.malformed_lines,
        backfilled: analysis.event_read.backfilled,
      },
    };
    if (options.include_events) {
      response.events = analysis.event_read.events.slice(-options.limit).map(compactEvent);
    }
    return JSON.stringify(response);
  }

  const analyses = listSessionDomains()
    .map((targetDomain) => analyzeSession(targetDomain, { cutoffMs, limit: options.limit, env }))
    .filter((analysis) => {
      const latest = latestEvent(analysis.event_read.events);
      const latestMs = Math.max(timestampMs(latest?.ts), timestampMs(analysis.artifacts.latest_artifact_ts));
      return latestMs >= cutoffMs;
    })
    .sort((a, b) => {
      const aLatest = Math.max(timestampMs(latestEvent(a.event_read.events)?.ts), timestampMs(a.artifacts.latest_artifact_ts));
      const bLatest = Math.max(timestampMs(latestEvent(b.event_read.events)?.ts), timestampMs(b.artifacts.latest_artifact_ts));
      return bLatest - aLatest || a.target_domain.localeCompare(b.target_domain);
    });

  const bottlenecks = buildBottlenecks(analyses, options.limit);
  const response = {
    version: PIPELINE_ANALYTICS_VERSION,
    mode: "cross_session",
    filters: options,
    sessions: analyses.map((analysis) => analysis.row),
    funnel: buildFunnel(analyses),
    bottlenecks,
    next_actions: buildNextActions(bottlenecks, options.limit),
    tool_health: buildToolHealth({ cutoffMs, limit: options.limit, env }),
    hunter_health: buildHunterHealth({ cutoffMs, limit: options.limit, env }),
  };
  if (options.include_events) {
    response.events = analyses
      .flatMap((analysis) => analysis.event_read.events)
      .sort((a, b) => timestampMs(b.ts) - timestampMs(a.ts))
      .slice(0, options.limit)
      .map(compactEvent);
  }
  return JSON.stringify(response);
}

module.exports = {
  PIPELINE_ANALYTICS_VERSION,
  PIPELINE_EVENT_TYPES,
  PIPELINE_EVENT_VERSION,
  appendPipelineEventDirect,
  buildBackfillEvents,
  listSessionDomains,
  normalizePipelineEvent,
  pipelineAnalyticsEnabled,
  readPipelineAnalytics,
  readPipelineEvents,
  readSessionArtifactSummary,
  safeAppendPipelineEventDirect,
  safeAppendPipelineEventWithSessionLock,
  safeRecordHunterStoppedPipelineEvent,
};
