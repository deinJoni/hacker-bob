"use strict";

const {
  AUTH_STATUS_VALUES,
  CHECKPOINT_MODE_VALUES,
  PHASE_VALUES,
  SESSION_PUBLIC_STATE_FIELDS,
} = require("./constants.js");
const {
  assertEnumValue,
  assertBoolean,
  assertInteger,
  assertNonEmptyString,
  normalizeOptionalText,
  normalizeStringArray,
} = require("./validation.js");
const {
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");

const OPERATOR_NOTE_MAX_CHARS = 1000;
const BLOCK_INTERNAL_HOSTS_SOURCE_VALUES = Object.freeze([
  "explicit_block",
  "explicit_allow",
  "paranoid_default",
  "mode_default",
  "legacy_default",
  "request_override",
]);

function validateOperatorNoteText(note, fieldName) {
  if (note.length > OPERATOR_NOTE_MAX_CHARS) {
    throw new Error(`${fieldName} must be at most ${OPERATOR_NOTE_MAX_CHARS} characters`);
  }
  validateNoSensitiveMaterial(note, fieldName, { maxTextChars: OPERATOR_NOTE_MAX_CHARS + 1 });
  return note;
}

function normalizeOperatorNote(value, fieldName = "operator_note") {
  const note = normalizeOptionalText(value, fieldName);
  return note == null ? null : validateOperatorNoteText(note, fieldName);
}

function assertOperatorNote(value, fieldName = "operator_note") {
  return validateOperatorNoteText(assertNonEmptyString(value, fieldName), fieldName);
}

function normalizeEgressIdentitySource(value, fieldName = "egress_profile_identity_source") {
  if (value == null) {
    return {
      proxy_url_source: "none",
      proxy_env_var: null,
      proxy_url_redacted: null,
      resolved_proxy: null,
    };
  }
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const proxyUrlSource = assertEnumValue(
    value.proxy_url_source == null ? "none" : value.proxy_url_source,
    ["none", "env", "inline"],
    `${fieldName}.proxy_url_source`,
  );
  const source = {
    proxy_url_source: proxyUrlSource,
    proxy_env_var: normalizeOptionalText(value.proxy_env_var, `${fieldName}.proxy_env_var`),
    proxy_url_redacted: normalizeOptionalText(value.proxy_url_redacted, `${fieldName}.proxy_url_redacted`),
    resolved_proxy: null,
  };
  if (value.resolved_proxy != null) {
    if (typeof value.resolved_proxy !== "object" || Array.isArray(value.resolved_proxy)) {
      throw new Error(`${fieldName}.resolved_proxy must be an object`);
    }
    source.resolved_proxy = {
      protocol: assertNonEmptyString(value.resolved_proxy.protocol, `${fieldName}.resolved_proxy.protocol`),
      hostname: assertNonEmptyString(value.resolved_proxy.hostname, `${fieldName}.resolved_proxy.hostname`).toLowerCase(),
      port: normalizeOptionalText(value.resolved_proxy.port, `${fieldName}.resolved_proxy.port`),
    };
  }
  return source;
}

function normalizeEgressLegacyMigration(value, fieldName = "egress_profile_legacy_migration") {
  if (value == null) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const result = {
    migrated_at: normalizeOptionalText(value.migrated_at, `${fieldName}.migrated_at`),
    source: normalizeOptionalText(value.source, `${fieldName}.source`),
    previous_unbound: value.previous_unbound == null
      ? true
      : assertBoolean(value.previous_unbound, `${fieldName}.previous_unbound`),
    previous: null,
  };
  if (value.previous != null) {
    if (typeof value.previous !== "object" || Array.isArray(value.previous)) {
      throw new Error(`${fieldName}.previous must be an object`);
    }
    result.previous = {
      egress_profile: normalizeOptionalText(value.previous.egress_profile, `${fieldName}.previous.egress_profile`),
      egress_region: normalizeOptionalText(value.previous.egress_region, `${fieldName}.previous.egress_region`),
      proxy_configured: value.previous.proxy_configured == null
        ? false
        : assertBoolean(value.previous.proxy_configured, `${fieldName}.previous.proxy_configured`),
      egress_profile_identity_hash: normalizeOptionalText(
        value.previous.egress_profile_identity_hash,
        `${fieldName}.previous.egress_profile_identity_hash`,
      ),
      egress_profile_identity_version: value.previous.egress_profile_identity_version == null
        ? null
        : assertInteger(
          value.previous.egress_profile_identity_version,
          `${fieldName}.previous.egress_profile_identity_version`,
          { min: 1 },
        ),
    };
  }
  return result;
}

function egressProfileStateFields(profile) {
  return {
    egress_profile: profile.name,
    egress_region: profile.region,
    proxy_configured: profile.proxy_configured === true,
    egress_profile_identity_hash: profile.egress_profile_identity_hash,
    egress_profile_identity_version: profile.egress_profile_identity_version,
    egress_profile_identity_source: profile.egress_profile_identity_source,
  };
}

function normalizeCheckpointMode(value, fieldName = "checkpoint_mode") {
  return value == null
    ? "normal"
    : assertEnumValue(value, CHECKPOINT_MODE_VALUES, fieldName);
}

function normalizeBlockInternalHostsSource(value, fieldName = "block_internal_hosts_source") {
  return value == null
    ? null
    : assertEnumValue(value, BLOCK_INTERNAL_HOSTS_SOURCE_VALUES, fieldName);
}

function deriveBlockInternalHostsPolicy({
  checkpointMode = "normal",
  blockInternalHosts = null,
  allowInternalHosts = null,
  legacyDefault = false,
} = {}) {
  const mode = normalizeCheckpointMode(checkpointMode);
  const explicitBlock = blockInternalHosts == null
    ? null
    : assertBoolean(blockInternalHosts, "block_internal_hosts");
  const explicitAllow = allowInternalHosts == null
    ? null
    : assertBoolean(allowInternalHosts, "allow_internal_hosts");

  if (explicitBlock === true && explicitAllow === true) {
    throw new Error("block_internal_hosts and allow_internal_hosts cannot both be true");
  }
  if (explicitBlock === true) {
    return {
      checkpoint_mode: mode,
      block_internal_hosts: true,
      block_internal_hosts_source: "explicit_block",
    };
  }
  if (explicitAllow === true) {
    return {
      checkpoint_mode: mode,
      block_internal_hosts: false,
      block_internal_hosts_source: "explicit_allow",
    };
  }
  if (legacyDefault) {
    return {
      checkpoint_mode: mode,
      block_internal_hosts: false,
      block_internal_hosts_source: "legacy_default",
    };
  }
  if (mode === "paranoid") {
    return {
      checkpoint_mode: mode,
      block_internal_hosts: true,
      block_internal_hosts_source: "paranoid_default",
    };
  }
  return {
    checkpoint_mode: mode,
    block_internal_hosts: false,
    block_internal_hosts_source: "mode_default",
  };
}

function assertBlockInternalHostsPolicyConsistency(policy) {
  const blockInternalHosts = assertBoolean(policy.block_internal_hosts, "block_internal_hosts");
  const source = normalizeBlockInternalHostsSource(policy.block_internal_hosts_source)
    || (blockInternalHosts ? "explicit_block" : "legacy_default");
  const requiresTrue = new Set(["explicit_block", "paranoid_default", "request_override"]);
  const requiresFalse = new Set(["explicit_allow", "mode_default", "legacy_default"]);
  if (requiresTrue.has(source) && blockInternalHosts !== true) {
    throw new Error(`${source} requires block_internal_hosts to be true`);
  }
  if (requiresFalse.has(source) && blockInternalHosts !== false) {
    throw new Error(`${source} requires block_internal_hosts to be false`);
  }
  return {
    checkpoint_mode: normalizeCheckpointMode(policy.checkpoint_mode),
    block_internal_hosts: blockInternalHosts,
    block_internal_hosts_source: source,
  };
}

function normalizeBlockInternalHostsStateFields(document) {
  const checkpointModePresent = document.checkpoint_mode != null;
  const checkpointMode = normalizeCheckpointMode(document.checkpoint_mode);
  const derived = deriveBlockInternalHostsPolicy({
    checkpointMode,
    legacyDefault: !checkpointModePresent,
  });
  const blockInternalHosts = document.block_internal_hosts == null
    ? derived.block_internal_hosts
    : assertBoolean(document.block_internal_hosts, "block_internal_hosts");
  let blockInternalHostsSource = normalizeBlockInternalHostsSource(document.block_internal_hosts_source);
  if (!blockInternalHostsSource) {
    if (document.block_internal_hosts != null && blockInternalHosts === true) {
      blockInternalHostsSource = "explicit_block";
    } else if (document.block_internal_hosts != null && checkpointMode === "paranoid" && blockInternalHosts === false) {
      blockInternalHostsSource = "explicit_allow";
    } else {
      blockInternalHostsSource = derived.block_internal_hosts_source;
    }
  }
  return assertBlockInternalHostsPolicyConsistency({
    checkpoint_mode: checkpointMode,
    block_internal_hosts: blockInternalHosts,
    block_internal_hosts_source: blockInternalHostsSource,
  });
}

function blockInternalHostsPolicyFields(policy) {
  const normalized = assertBlockInternalHostsPolicyConsistency(policy);
  return {
    checkpoint_mode: normalized.checkpoint_mode,
    block_internal_hosts: normalized.block_internal_hosts,
    block_internal_hosts_source: normalized.block_internal_hosts_source,
  };
}

// state.terminally_blocked carries one entry per terminally-blocked surface,
// each with the blocker tuples (kind + identifier_hint + reason) that drove
// promotion. Kind validation here is intentionally soft — the tuple was
// already through normalizeBlockedPrereqs at handoff write time and through
// the merge promotion logic before landing in state. State validation only
// guards structural invariants so analytics / report writers can trust the
// shape without re-walking handoff JSONs.
function normalizeTerminallyBlocked(value, fieldName = "terminally_blocked") {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array`);
  }
  const seenSurfaceIds = new Set();
  return value.map((entry, index) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`${fieldName}[${index}] must be an object`);
    }
    const surfaceId = assertNonEmptyString(entry.surface_id, `${fieldName}[${index}].surface_id`);
    if (seenSurfaceIds.has(surfaceId)) {
      throw new Error(`${fieldName} contains duplicate surface_id ${surfaceId}; one closure entry per surface`);
    }
    seenSurfaceIds.add(surfaceId);
    const blockedAtWave = assertInteger(entry.blocked_at_wave, `${fieldName}[${index}].blocked_at_wave`, { min: 1 });
    if (!Array.isArray(entry.blockers) || entry.blockers.length === 0) {
      throw new Error(`${fieldName}[${index}].blockers must be a non-empty array`);
    }
    const blockers = entry.blockers.map((blocker, blockerIndex) => {
      if (blocker == null || typeof blocker !== "object" || Array.isArray(blocker)) {
        throw new Error(`${fieldName}[${index}].blockers[${blockerIndex}] must be an object`);
      }
      const result = {
        kind: assertNonEmptyString(blocker.kind, `${fieldName}[${index}].blockers[${blockerIndex}].kind`),
      };
      if (blocker.identifier_hint != null) {
        result.identifier_hint = assertNonEmptyString(
          blocker.identifier_hint,
          `${fieldName}[${index}].blockers[${blockerIndex}].identifier_hint`,
        );
      }
      if (blocker.reason != null) {
        result.reason = assertNonEmptyString(
          blocker.reason,
          `${fieldName}[${index}].blockers[${blockerIndex}].reason`,
        );
      }
      return result;
    });
    return {
      surface_id: surfaceId,
      blocked_at_wave: blockedAtWave,
      blockers,
    };
  });
}

function terminallyBlockedSurfaceIds(state) {
  const list = Array.isArray(state.terminally_blocked) ? state.terminally_blocked : [];
  return list.map((entry) => entry.surface_id);
}

function buildInitialSessionState(domain, targetUrl, {
  deepMode = false,
  egressProfile = null,
  checkpointMode = "normal",
  blockInternalHosts = null,
  allowInternalHosts = null,
  blockInternalHostsPolicy = null,
} = {}) {
  const egressFields = egressProfileStateFields(egressProfile);
  const internalHostPolicy = blockInternalHostsPolicy
    ? blockInternalHostsPolicyFields(blockInternalHostsPolicy)
    : deriveBlockInternalHostsPolicy({
      checkpointMode,
      blockInternalHosts,
      allowInternalHosts,
      legacyDefault: false,
    });
  return {
    target: domain,
    target_url: targetUrl,
    deep_mode: deepMode,
    ...internalHostPolicy,
    phase: "RECON",
    hunt_wave: 0,
    pending_wave: null,
    total_findings: 0,
    explored: [],
    terminally_blocked: [],
    prereq_registry_snapshots: [],
    blocked_prereq_history: [],
    terminal_block_clear_history: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    scope_exclusions: [],
    hold_count: 0,
    auth_status: "pending",
    ...egressFields,
    egress_profile_identity_bound_at: null,
    egress_profile_identity_bind_source: null,
    egress_profile_legacy_migration: null,
    operator_note: null,
    verification_schema_version: null,
    verification_attempt_id: null,
    verification_snapshot_hash: null,
    verification_entered_at: null,
    // New v1.3.5 sessions opt into mandatory handoff provenance. When true,
    // validateHandoffProvenance refuses legacy_unverified handoffs, closing
    // the assignment-file-downgrade attack documented in R1-HIGH-#1. Pre-v1.3.5
    // sessions whose state.json lacks this field default to false (legacy
    // compat) per the normalizer. Full removal of the legacy path is scheduled
    // for v1.3.6 with deliberate test-fixture migration.
    handoff_provenance_required: true,
  };
}

// state.prereq_registry_snapshots stores per-wave registry HANDLE SETS so
// the loop detector can reason about whether the specific material that
// would unblock a surface (e.g., the "attacker" auth profile) was added
// since the surface got stuck — not just whether ANY profile was added.
// Counts collapsed unrelated additions into "growth" and gave irrelevant
// blockers permanent amnesty. Snapshot captured at wave start (before
// hunters dispatch), not merge time, so the comparison reflects "what
// the hunter could have used".
function normalizePrereqRegistrySnapshots(value, fieldName = "prereq_registry_snapshots") {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array`);
  }
  return value.map((entry, index) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`${fieldName}[${index}] must be an object`);
    }
    return {
      wave: assertInteger(entry.wave, `${fieldName}[${index}].wave`, { min: 1 }),
      auth_handles: normalizeStringArray(entry.auth_handles, `${fieldName}[${index}].auth_handles`),
      egress_handles: normalizeStringArray(entry.egress_handles, `${fieldName}[${index}].egress_handles`),
    };
  });
}

// state.terminal_block_clear_history records every operator-driven clear:
// when, why, and what was cleared. Stored in state.json (atomic write)
// rather than relying on the best-effort pipeline event for audit
// durability. The loop detector uses these clear epochs to filter
// blocked_prereq_history so a re-block starts a fresh recurrence count
// without erasing prior debugging data.
function normalizeTerminalBlockClearHistory(value, fieldName = "terminal_block_clear_history") {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array`);
  }
  return value.map((entry, index) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`${fieldName}[${index}] must be an object`);
    }
    const result = {
      surface_id: assertNonEmptyString(entry.surface_id, `${fieldName}[${index}].surface_id`),
      cleared_at_wave: assertInteger(entry.cleared_at_wave, `${fieldName}[${index}].cleared_at_wave`, { min: 0 }),
      cleared_at_ts: assertNonEmptyString(entry.cleared_at_ts, `${fieldName}[${index}].cleared_at_ts`),
      reason: assertNonEmptyString(entry.reason, `${fieldName}[${index}].reason`),
    };
    if (entry.previously_blocked_at_wave != null) {
      result.previously_blocked_at_wave = assertInteger(
        entry.previously_blocked_at_wave,
        `${fieldName}[${index}].previously_blocked_at_wave`,
        { min: 1 },
      );
    }
    if (Array.isArray(entry.previous_blockers)) {
      result.previous_blockers = entry.previous_blockers.map((blocker, blockerIndex) => {
        if (blocker == null || typeof blocker !== "object" || Array.isArray(blocker)) {
          throw new Error(`${fieldName}[${index}].previous_blockers[${blockerIndex}] must be an object`);
        }
        const blockerResult = {
          kind: assertNonEmptyString(blocker.kind, `${fieldName}[${index}].previous_blockers[${blockerIndex}].kind`),
        };
        if (blocker.identifier_hint != null) {
          blockerResult.identifier_hint = assertNonEmptyString(
            blocker.identifier_hint,
            `${fieldName}[${index}].previous_blockers[${blockerIndex}].identifier_hint`,
          );
        }
        if (blocker.reason != null) {
          blockerResult.reason = assertNonEmptyString(
            blocker.reason,
            `${fieldName}[${index}].previous_blockers[${blockerIndex}].reason`,
          );
        }
        return blockerResult;
      });
    }
    return result;
  });
}

// state.blocked_prereq_history is the merge-validated record of blocker
// tuples per wave per surface. Replaces raw handoff JSON reads in the
// promotion path: handoffs go through schema/runtime validation at write
// time, but reading them again at merge time bypasses that validation.
// Cleared entries are kept; the loop detector uses
// state.terminal_block_clear_history to skip them.
function normalizeBlockedPrereqHistory(value, fieldName = "blocked_prereq_history") {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array`);
  }
  return value.map((entry, index) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`${fieldName}[${index}] must be an object`);
    }
    const result = {
      wave: assertInteger(entry.wave, `${fieldName}[${index}].wave`, { min: 1 }),
      surface_id: assertNonEmptyString(entry.surface_id, `${fieldName}[${index}].surface_id`),
      kind: assertNonEmptyString(entry.kind, `${fieldName}[${index}].kind`),
    };
    if (entry.identifier_hint != null) {
      result.identifier_hint = assertNonEmptyString(entry.identifier_hint, `${fieldName}[${index}].identifier_hint`);
    }
    if (entry.reason != null) {
      result.reason = assertNonEmptyString(entry.reason, `${fieldName}[${index}].reason`);
    }
    return result;
  });
}

function publicSessionState(state) {
  return SESSION_PUBLIC_STATE_FIELDS.reduce((result, field) => {
    result[field] = state[field];
    return result;
  }, {});
}

function compactSessionState(state) {
  return {
    target: state.target,
    deep_mode: state.deep_mode === true,
    checkpoint_mode: state.checkpoint_mode,
    block_internal_hosts: state.block_internal_hosts === true,
    block_internal_hosts_source: state.block_internal_hosts_source,
    phase: state.phase,
    hunt_wave: state.hunt_wave,
    pending_wave: state.pending_wave,
    total_findings: state.total_findings,
    explored_count: (state.explored || []).length,
    terminally_blocked_count: (state.terminally_blocked || []).length,
    dead_ends_count: (state.dead_ends || []).length,
    waf_blocked_count: (state.waf_blocked_endpoints || []).length,
    lead_surface_ids: state.lead_surface_ids || [],
    hold_count: state.hold_count,
    auth_status: state.auth_status,
    egress_profile: state.egress_profile,
    egress_region: state.egress_region,
    proxy_configured: state.proxy_configured,
    egress_profile_identity_hash: state.egress_profile_identity_hash,
    egress_profile_identity_version: state.egress_profile_identity_version,
    egress_profile_identity_source: state.egress_profile_identity_source,
    egress_profile_identity_bound_at: state.egress_profile_identity_bound_at,
    egress_profile_identity_bind_source: state.egress_profile_identity_bind_source,
    egress_profile_legacy_migration: state.egress_profile_legacy_migration,
    operator_note: state.operator_note,
    verification_schema_version: state.verification_schema_version,
    verification_attempt_id: state.verification_attempt_id,
    verification_snapshot_hash: state.verification_snapshot_hash,
    verification_entered_at: state.verification_entered_at,
    handoff_provenance_required: state.handoff_provenance_required === true,
  };
}

function normalizeSessionStateDocument(document, requestedDomain) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("expected object");
  }

  if (document.target != null) {
    assertNonEmptyString(document.target, "target");
  }

  const normalized = {
    target: requestedDomain,
    target_url: assertNonEmptyString(document.target_url, "target_url"),
    deep_mode: document.deep_mode == null
      ? false
      : assertBoolean(document.deep_mode, "deep_mode"),
    ...normalizeBlockInternalHostsStateFields(document),
    phase: assertEnumValue(document.phase, PHASE_VALUES, "phase"),
    hunt_wave: document.hunt_wave == null
      ? 0
      : assertInteger(document.hunt_wave, "hunt_wave", { min: 0 }),
    pending_wave: document.pending_wave == null
      ? null
      : assertInteger(document.pending_wave, "pending_wave", { min: 1 }),
    total_findings: document.total_findings == null
      ? 0
      : assertInteger(document.total_findings, "total_findings", { min: 0 }),
    explored: normalizeStringArray(document.explored, "explored"),
    terminally_blocked: normalizeTerminallyBlocked(document.terminally_blocked, "terminally_blocked"),
    prereq_registry_snapshots: normalizePrereqRegistrySnapshots(document.prereq_registry_snapshots, "prereq_registry_snapshots"),
    blocked_prereq_history: normalizeBlockedPrereqHistory(document.blocked_prereq_history, "blocked_prereq_history"),
    terminal_block_clear_history: normalizeTerminalBlockClearHistory(document.terminal_block_clear_history, "terminal_block_clear_history"),
    dead_ends: normalizeStringArray(document.dead_ends, "dead_ends"),
    waf_blocked_endpoints: normalizeStringArray(document.waf_blocked_endpoints, "waf_blocked_endpoints"),
    lead_surface_ids: normalizeStringArray(document.lead_surface_ids, "lead_surface_ids"),
    scope_exclusions: normalizeStringArray(document.scope_exclusions, "scope_exclusions"),
    hold_count: document.hold_count == null
      ? 0
      : assertInteger(document.hold_count, "hold_count", { min: 0 }),
    auth_status: document.auth_status == null
      ? "pending"
      : assertEnumValue(document.auth_status, AUTH_STATUS_VALUES, "auth_status"),
    egress_profile: document.egress_profile == null
      ? "default"
      : assertNonEmptyString(document.egress_profile, "egress_profile"),
    egress_region: normalizeOptionalText(document.egress_region, "egress_region"),
    proxy_configured: document.proxy_configured == null
      ? false
      : assertBoolean(document.proxy_configured, "proxy_configured"),
    egress_profile_identity_hash: normalizeOptionalText(
      document.egress_profile_identity_hash,
      "egress_profile_identity_hash",
    ),
    egress_profile_identity_version: document.egress_profile_identity_version == null
      ? null
      : assertInteger(document.egress_profile_identity_version, "egress_profile_identity_version", { min: 1 }),
    egress_profile_identity_source: normalizeEgressIdentitySource(
      document.egress_profile_identity_source,
      "egress_profile_identity_source",
    ),
    egress_profile_identity_bound_at: normalizeOptionalText(
      document.egress_profile_identity_bound_at,
      "egress_profile_identity_bound_at",
    ),
    egress_profile_identity_bind_source: normalizeOptionalText(
      document.egress_profile_identity_bind_source,
      "egress_profile_identity_bind_source",
    ),
    egress_profile_legacy_migration: normalizeEgressLegacyMigration(
      document.egress_profile_legacy_migration,
      "egress_profile_legacy_migration",
    ),
    operator_note: normalizeOperatorNote(document.operator_note, "operator_note"),
    verification_schema_version: document.verification_schema_version == null
      ? null
      : assertInteger(document.verification_schema_version, "verification_schema_version", { min: 1, max: 2 }),
    verification_attempt_id: normalizeOptionalText(document.verification_attempt_id, "verification_attempt_id"),
    verification_snapshot_hash: normalizeOptionalText(document.verification_snapshot_hash, "verification_snapshot_hash"),
    verification_entered_at: normalizeOptionalText(document.verification_entered_at, "verification_entered_at"),
    // Provenance enforcement opt-in (v1.3.5+). Missing field = legacy session,
    // defaulted to false to preserve compat with pre-v1.3.5 fixtures and any
    // in-flight sessions. New sessions set this to true in buildInitialSessionState.
    handoff_provenance_required: document.handoff_provenance_required == null
      ? false
      : assertBoolean(document.handoff_provenance_required, "handoff_provenance_required"),
  };

  // Disjointness invariant: a surface is either explored (hunter declared
  // complete) OR terminally_blocked (system promoted on stuck loop with no
  // registry delta). Both at once would let consumers double-count or pick
  // the wrong closure reason. Fail loud rather than silently dedupe.
  const exploredSet = new Set(normalized.explored);
  const collisions = normalized.terminally_blocked
    .map((entry) => entry.surface_id)
    .filter((id) => exploredSet.has(id));
  if (collisions.length > 0) {
    throw new Error(`state.explored and state.terminally_blocked must be disjoint; overlapping surface_id(s): ${collisions.join(", ")}`);
  }

  return normalized;
}

function composeSessionStateDocument(rawDocument, state) {
  return {
    ...rawDocument,
    ...publicSessionState(state),
  };
}

module.exports = {
  assertOperatorNote,
  blockInternalHostsPolicyFields,
  buildInitialSessionState,
  compactSessionState,
  composeSessionStateDocument,
  deriveBlockInternalHostsPolicy,
  egressProfileStateFields,
  normalizeSessionStateDocument,
  publicSessionState,
  terminallyBlockedSurfaceIds,
};
