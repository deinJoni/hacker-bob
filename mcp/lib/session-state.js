"use strict";

const fs = require("fs");
const {
  AUTH_STATUS_VALUES,
  PHASE_VALUES,
} = require("./constants.js");
const {
  assertEnumValue,
  assertBoolean,
  assertNonEmptyString,
} = require("./validation.js");
const {
  sessionDir,
  statePath,
} = require("./paths.js");
const {
  isSessionDirEffectivelyEmpty,
  withSessionLock,
  writeFileAtomic,
} = require("./storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  resolveEgressProfile,
} = require("./egress-profiles.js");
const {
  safeAppendPipelineEventDirect,
} = require("./pipeline-events.js");
const {
  assertHttpScopeDomain,
  validateHttpScanScope,
} = require("./scope.js");
const {
  computeChainToVerifyGate,
  computeHuntToChainGate,
  computeVerifyToGradeGate,
  formatTransitionBlockers,
} = require("./phase-gates.js");

const {
  assertOperatorNote,
  blockInternalHostsPolicyFields,
  buildInitialSessionState,
  compactSessionState,
  deriveBlockInternalHostsPolicy,
  egressProfileStateFields,
  publicSessionState,
} = require("./session-state-contracts.js");
const {
  readSessionStateStrict,
  sessionStateMissing,
  writeSessionStateDocument,
} = require("./session-state-store.js");

function verificationLib() {
  return require("./verification.js");
}

function assertBlockInternalHostsCompatibleWithEgress(policy, profile) {
  if (!policy || policy.block_internal_hosts !== true || !profile || profile.proxy_configured !== true) {
    return;
  }
  const identityFields = egressProfileStateFields(profile);
  throw new ToolError(
    ERROR_CODES.SCOPE_BLOCKED,
    `block_internal_hosts cannot be enforced with proxy-backed egress_profile "${profile.name}" because target DNS and routing may be resolved outside Bob. Use egress_profile "default" or allow_internal_hosts for authorized internal/lab programs.`,
    {
      ...identityFields,
      ...blockInternalHostsPolicyFields(policy),
    },
  );
}

function assertSessionEgressIdentity(domain, profile, { source = "egress_request" } = {}) {
  const identityFields = egressProfileStateFields(profile);
  let bound = false;

  try {
    withSessionLock(domain, () => {
      const { raw, state } = readSessionStateStrict(domain);
      if (!state.egress_profile_identity_hash) {
        const migratedAt = new Date().toISOString();
        const nextState = {
          ...state,
          ...identityFields,
          egress_profile_identity_bound_at: migratedAt,
          egress_profile_identity_bind_source: "legacy_migration",
          egress_profile_legacy_migration: {
            migrated_at: migratedAt,
            source,
            previous_unbound: true,
            previous: {
              egress_profile: state.egress_profile,
              egress_region: state.egress_region,
              proxy_configured: state.proxy_configured,
              egress_profile_identity_hash: state.egress_profile_identity_hash,
              egress_profile_identity_version: state.egress_profile_identity_version,
            },
          },
        };
        writeSessionStateDocument(domain, raw, nextState);
        safeAppendPipelineEventDirect(domain, "egress_identity_bound", {
          phase: state.phase,
          status: "bound",
          source,
          legacy_migration: true,
          ...identityFields,
        });
        bound = true;
        return;
      }

      if (
        state.egress_profile_identity_hash !== identityFields.egress_profile_identity_hash ||
        state.egress_profile_identity_version !== identityFields.egress_profile_identity_version
      ) {
        throw new ToolError(
          ERROR_CODES.STATE_CONFLICT,
          `egress profile drift for ${domain}: session is bound to ${state.egress_profile} (${state.egress_profile_identity_hash}); requested ${identityFields.egress_profile} (${identityFields.egress_profile_identity_hash})`,
          {
            target_domain: domain,
            expected: {
              egress_profile: state.egress_profile,
              egress_region: state.egress_region,
              proxy_configured: state.proxy_configured,
              egress_profile_identity_hash: state.egress_profile_identity_hash,
              egress_profile_identity_version: state.egress_profile_identity_version,
            },
            requested: identityFields,
          },
        );
      }
    });
  } catch (error) {
    if (!sessionStateMissing(error)) throw error;
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `egress profile identity requires an initialized session for ${domain}; call bounty_init_session before egress-bound requests`,
      {
        target_domain: domain,
        requested: {
          egress_profile: identityFields.egress_profile,
          egress_region: identityFields.egress_region,
          proxy_configured: identityFields.proxy_configured,
          egress_profile_identity_hash: identityFields.egress_profile_identity_hash,
          egress_profile_identity_version: identityFields.egress_profile_identity_version,
        },
      },
    );
  }

  return {
    ...identityFields,
    session_state_present: true,
    session_identity_bound: bound,
  };
}

function resolveAndAssertSessionEgressIdentity(domain, requestedProfile = "default", options = {}) {
  const profile = resolveEgressProfile(requestedProfile, options);
  const identity = assertSessionEgressIdentity(domain, profile, {
    source: options.source || "egress_request",
  });
  return { profile, identity };
}

function initSession(args) {
  let domain;
  try {
    domain = assertHttpScopeDomain(args.target_domain);
  } catch (error) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || String(error));
  }
  const targetUrl = assertNonEmptyString(args.target_url, "target_url");
  try {
    validateHttpScanScope(targetUrl, domain);
  } catch (error) {
    throw new ToolError(ERROR_CODES.SCOPE_BLOCKED, error.message || String(error), error.details);
  }
  const deepMode = args.deep_mode == null ? false : assertBoolean(args.deep_mode, "deep_mode");
  let internalHostPolicy;
  try {
    internalHostPolicy = deriveBlockInternalHostsPolicy({
      checkpointMode: args.checkpoint_mode,
      blockInternalHosts: args.block_internal_hosts,
      allowInternalHosts: args.allow_internal_hosts,
      legacyDefault: false,
    });
  } catch (error) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || String(error));
  }
  const requestedEgressProfile = args.egress_profile == null
    ? "default"
    : assertNonEmptyString(args.egress_profile, "egress_profile");

  return withSessionLock(domain, () => {
    const dir = sessionDir(domain);
    const filePath = statePath(domain);

    if (fs.existsSync(filePath)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session already initialized: ${filePath}`);
    }
    if (!isSessionDirEffectivelyEmpty(dir)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session directory is not empty: ${dir}`);
    }

    const egressProfile = resolveEgressProfile(requestedEgressProfile);
    assertBlockInternalHostsCompatibleWithEgress(internalHostPolicy, egressProfile);
    const egressFields = egressProfileStateFields(egressProfile);
    const state = buildInitialSessionState(domain, targetUrl, {
      deepMode,
      egressProfile,
      blockInternalHostsPolicy: internalHostPolicy,
    });
    writeFileAtomic(filePath, `${JSON.stringify(state, null, 2)}\n`);
    safeAppendPipelineEventDirect(domain, "session_started", {
      phase: state.phase,
      source: "bounty_init_session",
      deep_mode: state.deep_mode,
      checkpoint_mode: state.checkpoint_mode,
      block_internal_hosts: state.block_internal_hosts,
      block_internal_hosts_source: state.block_internal_hosts_source,
      ...egressFields,
    });

    return JSON.stringify({
      version: 1,
      created: true,
      session_dir: dir,
      state: publicSessionState(state),
    });
  });
}

function readSessionState(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const { state } = readSessionStateStrict(domain);
  return JSON.stringify({
    version: 1,
    state: publicSessionState(state),
  });
}

function readStateSummary(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const { state } = readSessionStateStrict(domain);
  return JSON.stringify({
    version: 1,
    state: compactSessionState(state),
  });
}

function setOperatorNote(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const operatorNote = assertOperatorNote(args.operator_note, "operator_note");

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    const nextState = {
      ...state,
      operator_note: operatorNote,
    };
    writeSessionStateDocument(domain, raw, nextState);
    return JSON.stringify({
      version: 1,
      updated: true,
      operator_note: operatorNote,
      state: compactSessionState(nextState),
    });
  });
}

function clearOperatorNote(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    const nextState = {
      ...state,
      operator_note: null,
    };
    writeSessionStateDocument(domain, raw, nextState);
    return JSON.stringify({
      version: 1,
      cleared: true,
      operator_note: null,
      state: compactSessionState(nextState),
    });
  });
}

function transitionPhase(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const toPhase = assertEnumValue(args.to_phase, PHASE_VALUES, "to_phase");

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    const fromPhase = state.phase;
    const allowedTransitions = {
      RECON: ["AUTH"],
      AUTH: ["HUNT"],
      HUNT: ["CHAIN"],
      CHAIN: ["VERIFY"],
      VERIFY: ["GRADE"],
      GRADE: ["REPORT", "HUNT"],
      REPORT: ["EXPLORE"],
      EXPLORE: ["CHAIN"],
    };

    if (!(allowedTransitions[fromPhase] || []).includes(toPhase)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Invalid phase transition: ${fromPhase} -> ${toPhase}`);
    }

    let overrideReason = null;
    const overrideAllowed = (
      (fromPhase === "HUNT" && toPhase === "CHAIN") ||
      (fromPhase === "CHAIN" && toPhase === "VERIFY")
    );
    if (args.override_reason != null) {
      if (!overrideAllowed) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "override_reason is only allowed for HUNT -> CHAIN or CHAIN -> VERIFY");
      }
      if (typeof args.override_reason !== "string" || !args.override_reason.trim()) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "override_reason must be a non-empty string");
      }
      overrideReason = args.override_reason.trim();
      if (overrideReason.length < 20) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "override_reason must be at least 20 characters");
      }
    }

    let nextAuthStatus = state.auth_status;
    if (fromPhase === "AUTH" && toPhase === "HUNT") {
      if (args.auth_status == null) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "auth_status is required for AUTH -> HUNT");
      }
      nextAuthStatus = assertEnumValue(
        args.auth_status,
        AUTH_STATUS_VALUES.filter((value) => value !== "pending"),
        "auth_status",
      );
    } else if (args.auth_status != null) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "auth_status is only allowed for AUTH -> HUNT");
    }

    let transitionGate = null;
    let transitionGateLabel = null;
    if (fromPhase === "HUNT" && toPhase === "CHAIN") {
      transitionGate = computeHuntToChainGate(domain, state);
      transitionGateLabel = "HUNT -> CHAIN";
    } else if (fromPhase === "CHAIN" && toPhase === "VERIFY") {
      transitionGate = computeChainToVerifyGate(domain, state);
      transitionGateLabel = "CHAIN -> VERIFY";
    } else if (fromPhase === "VERIFY" && toPhase === "GRADE") {
      transitionGate = computeVerifyToGradeGate(domain, state);
      transitionGateLabel = "VERIFY -> GRADE";
    } else if (fromPhase === "GRADE" && toPhase === "REPORT") {
      transitionGate = computeVerifyToGradeGate(domain, state);
      transitionGateLabel = "GRADE -> REPORT";
    }
    if (transitionGate && transitionGate.transition_blockers.length > 0 && overrideReason == null) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `${transitionGateLabel} blocked: ${formatTransitionBlockers(transitionGate.transition_blockers)}`,
      );
    }

    const verificationEntry = fromPhase === "CHAIN" && toPhase === "VERIFY"
      ? verificationLib().prepareVerificationEntry(domain, state)
      : null;

    const nextState = {
      ...state,
      ...(verificationEntry ? verificationEntry.state_fields : {}),
      phase: toPhase,
      auth_status: nextAuthStatus,
      hold_count: fromPhase === "GRADE" && toPhase === "HUNT"
        ? state.hold_count + 1
        : state.hold_count,
    };

    writeSessionStateDocument(domain, raw, nextState);
    if (verificationEntry && verificationEntry.schema_version === 2) {
      try {
        verificationLib().refreshVerificationManifest(domain, { throw_on_error: true });
      } catch (manifestError) {
        // Roll back the state advance so the transition is fully aborted on
        // manifest write failure. The verification snapshot stays on disk and
        // will be archived under its real attempt_id by the next CHAIN -> VERIFY.
        try {
          writeSessionStateDocument(domain, raw, state);
        } catch {}
        throw manifestError;
      }
    }
    const eventFields = {
      from_phase: fromPhase,
      to_phase: toPhase,
      phase: toPhase,
      status: "transitioned",
      source: "bounty_transition_phase",
      egress_profile: nextState.egress_profile,
      egress_region: nextState.egress_region,
      proxy_configured: nextState.proxy_configured,
      egress_profile_identity_hash: nextState.egress_profile_identity_hash,
      egress_profile_identity_version: nextState.egress_profile_identity_version,
      counts: {
        hold_count: nextState.hold_count,
      },
    };
    if (overrideReason != null) {
      eventFields.override = true;
      eventFields.override_reason = overrideReason;
      eventFields.counts.transition_blockers = transitionGate
        ? transitionGate.transition_blockers.length
        : 0;
    }
    if (verificationEntry && verificationEntry.schema_version === 2) {
      eventFields.verification_attempt_id = verificationEntry.state_fields.verification_attempt_id;
      eventFields.verification_snapshot_hash = verificationEntry.state_fields.verification_snapshot_hash;
      eventFields.counts.verification_findings = verificationEntry.snapshot
        ? verificationEntry.snapshot.finding_ids.length
        : 0;
      eventFields.counts.verification_archived = verificationEntry.archived != null ? 1 : 0;
    }
    if (fromPhase === "VERIFY" && toPhase === "GRADE" && state.verification_entered_at) {
      const enteredMs = Date.parse(state.verification_entered_at);
      if (Number.isFinite(enteredMs)) {
        eventFields.verification_attempt_id = state.verification_attempt_id;
        eventFields.verification_snapshot_hash = state.verification_snapshot_hash;
        eventFields.counts.verify_phase_wall_clock_ms = Math.max(0, Date.now() - enteredMs);
      }
    }
    safeAppendPipelineEventDirect(domain, "phase_transitioned", eventFields);
    return JSON.stringify({
      version: 1,
      transitioned: true,
      from_phase: fromPhase,
      to_phase: toPhase,
      verification: verificationEntry
        ? {
          schema_version: verificationEntry.schema_version,
          attempt_id: verificationEntry.state_fields.verification_attempt_id,
          snapshot_hash: verificationEntry.state_fields.verification_snapshot_hash,
          archived: verificationEntry.archived != null,
        }
        : undefined,
      state: compactSessionState(nextState),
    });
  });
}

function clearTerminalBlock(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  if (typeof args.reason !== "string" || args.reason.trim().length < 20) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "reason is required and must be at least 20 characters; the operator note is the audit trail",
    );
  }
  const reason = args.reason.trim();
  if (reason.length > 280) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "reason must be at most 280 characters",
    );
  }
  // The clear reason lands in state.terminal_block_clear_history (durable
  // public state). Screen for credentials so an operator pasting "added
  // attacker auth profile with cookie SESS=eyJabc..." cannot leak the
  // cookie into bounty_read_session_state output.
  try {
    require("./sensitive-material.js").validateNoSensitiveMaterial(reason, "reason");
  } catch (error) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message);
  }

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    if (state.pending_wave != null) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `Cannot clear a terminal block while wave ${state.pending_wave} is pending; merge the current wave first`,
      );
    }
    const terminallyBlocked = Array.isArray(state.terminally_blocked) ? state.terminally_blocked : [];
    const previousEntry = terminallyBlocked.find((entry) => entry.surface_id === surfaceId);
    if (!previousEntry) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `Surface ${surfaceId} is not in state.terminally_blocked; nothing to clear`,
      );
    }
    const remainingTerminallyBlocked = terminallyBlocked.filter((entry) => entry.surface_id !== surfaceId);
    // Keep blocked_prereq_history for debugging; the loop detector uses
    // terminal_block_clear_history to filter prior entries that came
    // before the latest clear for this surface.
    const clearedAtTs = new Date().toISOString();
    const priorClearHistory = Array.isArray(state.terminal_block_clear_history) ? state.terminal_block_clear_history : [];
    const clearEntry = {
      surface_id: surfaceId,
      cleared_at_wave: state.hunt_wave,
      cleared_at_ts: clearedAtTs,
      reason,
      previously_blocked_at_wave: previousEntry.blocked_at_wave,
      previous_blockers: Array.isArray(previousEntry.blockers) ? previousEntry.blockers : [],
    };
    const nextClearHistory = [...priorClearHistory, clearEntry];

    const nextState = {
      ...state,
      terminally_blocked: remainingTerminallyBlocked,
      terminal_block_clear_history: nextClearHistory,
    };
    writeSessionStateDocument(domain, raw, nextState);

    safeAppendPipelineEventDirect(domain, "terminal_block_cleared", {
      phase: state.phase,
      status: "cleared",
      source: "bounty_clear_terminal_block",
      surface_id: surfaceId,
      counts: {
        terminally_blocked_total: remainingTerminallyBlocked.length,
        clear_history_size: nextClearHistory.length,
      },
    });

    return JSON.stringify({
      version: 1,
      cleared: true,
      surface_id: surfaceId,
      cleared_at_wave: state.hunt_wave,
      cleared_at_ts: clearedAtTs,
      previous_blockers: clearEntry.previous_blockers,
      previously_blocked_at_wave: clearEntry.previously_blocked_at_wave,
      state: compactSessionState(nextState),
    });
  });
}

function reportWritten(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const reportPath = require("./paths.js").reportMarkdownPath(domain);
  if (!fs.existsSync(reportPath)) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `report.md is not present at ${reportPath}; call bounty_report_written only after writing the report`,
    );
  }
  const stats = fs.statSync(reportPath);
  safeAppendPipelineEventDirect(domain, "report_written", {
    status: "written",
    source: "bounty_report_written",
    counts: {
      report_size_bytes: stats.size,
    },
  });
  return JSON.stringify({
    version: 1,
    report_written: true,
    path: reportPath,
    size_bytes: stats.size,
    mtime: stats.mtime.toISOString(),
  });
}

module.exports = {
  assertBlockInternalHostsCompatibleWithEgress,
  clearOperatorNote,
  clearTerminalBlock,
  initSession,
  reportWritten,
  resolveAndAssertSessionEgressIdentity,
  setOperatorNote,
  readSessionState,
  readStateSummary,
  transitionPhase,
};
