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
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    scope_exclusions: [],
    hold_count: 0,
    auth_status: "pending",
    operator_note: null,
  };
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

module.exports = {
  buildInitialSessionState,
  clearOperatorNote,
  compactSessionState,
  composeSessionStateDocument,
  initSession,
  normalizeSessionStateDocument,
  setOperatorNote,
  publicSessionState,
  readSessionState,
  readSessionStateStrict,
  readStateSummary,
  terminallyBlockedSurfaceIds,
  transitionPhase,
  writeSessionStateDocument,
};
