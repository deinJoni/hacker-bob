"use strict";

const fs = require("fs");
const {
  assertNonEmptyString,
} = require("./validation.js");
const {
  pipelineEventsJsonlPath,
  statePath,
} = require("./paths.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("./storage.js");
const {
  bobVersion,
} = require("./runtime-resources.js");
const {
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");
const {
  normalizeSessionStateDocument,
} = require("./session-state-contracts.js");

const PIPELINE_EVENT_VERSION = 1;
const PIPELINE_EVENTS_MAX_RECORDS = 5000;

const PIPELINE_EVENT_TYPES = Object.freeze([
  "session_started",
  "egress_identity_bound",
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
  "finding_index_failed",
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

function normalizePositiveInteger(value, defaultValue, maxValue) {
  if (!Number.isFinite(value)) return defaultValue;
  return Math.max(1, Math.min(maxValue, Math.trunc(value)));
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
  if (forceMergeReason) {
    validateNoSensitiveMaterial(forceMergeReason, "force_merge_reason", { maxTextChars: 1000 });
    event.force_merge_reason = forceMergeReason;
  }
  if (typeof fields.override === "boolean") event.override = fields.override;
  if (typeof fields.legacy_migration === "boolean") event.legacy_migration = fields.legacy_migration;
  const overrideReason = capString(fields.override_reason, 1000);
  if (overrideReason) {
    validateNoSensitiveMaterial(overrideReason, "override_reason", { maxTextChars: 1000 });
    event.override_reason = overrideReason;
  }

  for (const [sourceField, maxChars] of [
    ["verification_attempt_id", 120],
    ["verification_snapshot_hash", 128],
    ["adjudication_plan_hash", 128],
    ["final_verification_hash", 128],
    ["capability_pack", 128],
    ["lease_scope", 80],
    ["replay_purpose", 80],
    ["started_by", 120],
    ["checkpoint_mode", 40],
    ["block_internal_hosts_source", 80],
    ["egress_profile", 80],
    ["egress_region", 80],
    ["egress_profile_identity_hash", 128],
  ]) {
    const safe = capString(fields[sourceField], maxChars);
    if (safe) event[sourceField] = safe;
  }
  if (typeof fields.proxy_configured === "boolean") {
    event.proxy_configured = fields.proxy_configured;
  }
  if (typeof fields.block_internal_hosts === "boolean") {
    event.block_internal_hosts = fields.block_internal_hosts;
  }
  if (Number.isInteger(fields.egress_profile_identity_version) && fields.egress_profile_identity_version > 0) {
    event.egress_profile_identity_version = fields.egress_profile_identity_version;
  }

  return event;
}

function readSessionEgressFields(targetDomain) {
  try {
    const filePath = statePath(targetDomain);
    if (!fs.existsSync(filePath)) return {};
    const rawState = JSON.parse(fs.readFileSync(filePath, "utf8"));
    const state = normalizeSessionStateDocument(rawState, targetDomain);
    const fields = {};
    for (const [field, maxChars] of [
      ["egress_profile", 80],
      ["egress_region", 80],
      ["egress_profile_identity_hash", 128],
      ["checkpoint_mode", 40],
      ["block_internal_hosts_source", 80],
    ]) {
      if (typeof state[field] === "string" && state[field].length > 0) {
        fields[field] = state[field].slice(0, maxChars);
      }
    }
    if (typeof state.proxy_configured === "boolean") {
      fields.proxy_configured = state.proxy_configured;
    }
    if (typeof state.block_internal_hosts === "boolean") {
      fields.block_internal_hosts = state.block_internal_hosts;
    }
    if (
      Number.isInteger(state.egress_profile_identity_version) &&
      state.egress_profile_identity_version > 0
    ) {
      fields.egress_profile_identity_version = state.egress_profile_identity_version;
    }
    return fields;
  } catch {
    return {};
  }
}

function appendPipelineEventDirect(targetDomain, type, fields = {}, { env = process.env } = {}) {
  if (!pipelineAnalyticsEnabled(env)) return null;
  const domain = assertNonEmptyString(targetDomain || fields.target_domain, "target_domain");
  const event = normalizePipelineEvent(domain, type, {
    ...readSessionEgressFields(domain),
    ...fields,
  });
  withSessionLock(event.target_domain, () => {
    appendJsonlLine(pipelineEventsJsonlPath(event.target_domain), event, {
      maxRecords: PIPELINE_EVENTS_MAX_RECORDS,
    });
  });
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
  for (const field of ["phase", "from_phase", "to_phase", "agent", "surface_id", "status", "block_code", "source", "kind", "identifier_hint", "verification_attempt_id", "verification_snapshot_hash", "adjudication_plan_hash", "final_verification_hash", "capability_pack", "lease_scope", "replay_purpose", "started_by", "checkpoint_mode", "block_internal_hosts_source", "egress_profile", "egress_region", "egress_profile_identity_hash"]) {
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
  if (typeof record.proxy_configured === "boolean") event.proxy_configured = record.proxy_configured;
  if (typeof record.block_internal_hosts === "boolean") event.block_internal_hosts = record.block_internal_hosts;
  if (typeof record.legacy_migration === "boolean") event.legacy_migration = record.legacy_migration;
  if (Number.isInteger(record.egress_profile_identity_version) && record.egress_profile_identity_version > 0) {
    event.egress_profile_identity_version = record.egress_profile_identity_version;
  }
  const overrideReason = capString(record.override_reason, 1000);
  if (overrideReason) event.override_reason = overrideReason;
  return event;
}

module.exports = {
  PIPELINE_EVENT_TYPES,
  PIPELINE_EVENT_VERSION,
  PIPELINE_EVENTS_MAX_RECORDS,
  appendPipelineEventDirect,
  capString,
  isPlainObject,
  normalizeIsoTimestamp,
  normalizePipelineEvent,
  normalizePipelineEventForRead,
  normalizePositiveInteger,
  pipelineAnalyticsEnabled,
  safeAppendPipelineEventDirect,
  safeAppendPipelineEventWithSessionLock,
  safeRecordHunterStoppedPipelineEvent,
  timestampMs,
};
