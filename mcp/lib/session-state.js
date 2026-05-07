"use strict";

const fs = require("fs");
const {
  AUTH_STATUS_VALUES,
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
  safeAppendPipelineEventDirect,
} = require("./pipeline-analytics.js");
const {
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");
const {
  computeChainToVerifyGate,
  computeHuntToChainGate,
  computeVerifyToGradeGate,
  formatTransitionBlockers,
} = require("./phase-gates.js");

const OPERATOR_NOTE_MAX_CHARS = 1000;

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

function buildInitialSessionState(domain, targetUrl, { deepMode = false } = {}) {
  return {
    target: domain,
    target_url: targetUrl,
    deep_mode: deepMode,
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
    operator_note: null,
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
    operator_note: state.operator_note,
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
    operator_note: normalizeOperatorNote(document.operator_note, "operator_note"),
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

function readSessionStateStrict(domain) {
  const normalizedDomain = assertNonEmptyString(domain, "target_domain");
  const filePath = statePath(normalizedDomain);

  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing session state: ${filePath}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    throw new Error(`Malformed session state: ${filePath} (${error.message || String(error)})`);
  }

  try {
    return {
      dir: sessionDir(normalizedDomain),
      path: filePath,
      raw: parsed,
      state: normalizeSessionStateDocument(parsed, normalizedDomain),
    };
  } catch (error) {
    throw new Error(`Malformed session state: ${filePath} (${error.message || String(error)})`);
  }
}

function composeSessionStateDocument(rawDocument, state) {
  return {
    ...rawDocument,
    ...publicSessionState(state),
  };
}

function writeSessionStateDocument(domain, rawDocument, state) {
  const filePath = statePath(domain);
  const nextDocument = composeSessionStateDocument(rawDocument, state);
  writeFileAtomic(filePath, `${JSON.stringify(nextDocument, null, 2)}\n`);
  return nextDocument;
}

function initSession(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const targetUrl = assertNonEmptyString(args.target_url, "target_url");
  const deepMode = args.deep_mode == null ? false : assertBoolean(args.deep_mode, "deep_mode");

  return withSessionLock(domain, () => {
    const dir = sessionDir(domain);
    const filePath = statePath(domain);

    if (fs.existsSync(filePath)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session already initialized: ${filePath}`);
    }
    if (!isSessionDirEffectivelyEmpty(dir)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session directory is not empty: ${dir}`);
    }

    const state = buildInitialSessionState(domain, targetUrl, { deepMode });
    writeFileAtomic(filePath, `${JSON.stringify(state, null, 2)}\n`);
    safeAppendPipelineEventDirect(domain, "session_started", {
      phase: state.phase,
      source: "bounty_init_session",
      deep_mode: state.deep_mode,
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

    const nextState = {
      ...state,
      phase: toPhase,
      auth_status: nextAuthStatus,
      hold_count: fromPhase === "GRADE" && toPhase === "HUNT"
        ? state.hold_count + 1
        : state.hold_count,
    };

    writeSessionStateDocument(domain, raw, nextState);
    const eventFields = {
      from_phase: fromPhase,
      to_phase: toPhase,
      phase: toPhase,
      status: "transitioned",
      source: "bounty_transition_phase",
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
    safeAppendPipelineEventDirect(domain, "phase_transitioned", eventFields);
    return JSON.stringify({
      version: 1,
      transitioned: true,
      from_phase: fromPhase,
      to_phase: toPhase,
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
  buildInitialSessionState,
  clearOperatorNote,
  clearTerminalBlock,
  compactSessionState,
  composeSessionStateDocument,
  initSession,
  normalizeSessionStateDocument,
  reportWritten,
  setOperatorNote,
  publicSessionState,
  readSessionState,
  readSessionStateStrict,
  readStateSummary,
  terminallyBlockedSurfaceIds,
  transitionPhase,
  writeSessionStateDocument,
};
