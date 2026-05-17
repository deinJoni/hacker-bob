"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const {
  assertNonEmptyString,
  parseAgentId,
  parseWaveId,
} = require("./validation.js");
const {
  buildWaveHandoffsDocument,
} = require("./wave-handoff-store.js");
const {
  loadWaveAssignments,
} = require("./assignments.js");
const {
  sessionDir,
} = require("./paths.js");
const {
  readJsonFile,
} = require("./storage.js");

const EVIDENCE_MODE = "evidence";

function cleanString(value) {
  if (typeof value !== "string") return "";
  return value.trim();
}

function markerMode(marker) {
  return cleanString(marker && marker.mode);
}

function isEvidenceMarker(marker) {
  return markerMode(marker) === EVIDENCE_MODE;
}

// Validate the post-report evidence marker shape — distinct from wave-mode
// markers because evidence runs have no wave/agent context. The orchestrator
// permits these only after REPORT (or during EXPLORE) when an operator asks
// the hunter to amplify a single finding's evidence.
function evidenceMarkerValidationError(marker) {
  if (!cleanString(marker && marker.target_domain)) {
    return {
      block_code: "malformed_marker",
      reason: "Post-report evidence marker is missing required field: target_domain",
    };
  }
  if (cleanString(marker.wave) || cleanString(marker.agent)) {
    return {
      block_code: "malformed_marker",
      reason: "Post-report evidence marker must not include wave or agent; use the normal wave marker for EXPLORE hunters.",
    };
  }
  return null;
}

// Read state.phase from disk (not via MCP) because the hook process may not
// have the MCP server in scope at SubagentStop time. Phase must be REPORT or
// EXPLORE for evidence runs to be allowed; outside that window we block to
// prevent accidental evidence collection during HUNT/CHAIN/VERIFY/GRADE.
function evaluateEvidenceCompletion(marker) {
  const targetDomain = cleanString(marker && marker.target_domain);
  if (!targetDomain) {
    return {
      ok: false,
      block_code: "evidence_state_unreadable",
      reason: "Post-report evidence marker missing target_domain.",
    };
  }
  const home = os.homedir();
  if (!home) {
    return {
      ok: false,
      block_code: "evidence_state_unreadable",
      reason: "Post-report evidence marker could not resolve $HOME for session state read.",
    };
  }
  const statePath = path.join(sessionDir(targetDomain), "state.json");
  let state;
  try {
    state = readJsonFile(statePath, { label: "state.json" });
  } catch (error) {
    return {
      ok: false,
      block_code: "evidence_state_unreadable",
      reason: `Post-report evidence marker could not read session state: ${error.message || String(error)}`,
    };
  }
  if (!state || (state.phase !== "REPORT" && state.phase !== "EXPLORE")) {
    return {
      ok: false,
      block_code: "evidence_phase_mismatch",
      reason: `Post-report evidence marker is allowed only in REPORT or EXPLORE phase; current phase is ${state && state.phase ? state.phase : "unknown"}.`,
    };
  }
  return {
    ok: true,
    handoff: {
      present: false,
      valid: true,
      provenance: "post_report_evidence",
      surface_status: "evidence",
      summary_present: cleanString(marker.summary) !== "",
      chain_notes_count: 0,
    },
  };
}

function evidenceTelemetryInput({
  marker,
  status,
  block_code = null,
  handoff = null,
  transcript_path = null,
  now = new Date(),
}) {
  return {
    ok: status === "allowed",
    runType: EVIDENCE_MODE,
    status,
    block_code,
    target_domain: cleanString(marker && marker.target_domain) || null,
    wave: null,
    agent: null,
    surface_id: cleanString(marker && marker.surface_id) || null,
    transcript_path,
    handoff,
    telemetry_source: "hunter-evidence-stop",
    now,
  };
}
const {
  readCoverageRecordsFromJsonl,
} = require("./coverage.js");
const {
  readFindingsFromJsonl,
} = require("./findings.js");
const {
  readTechniqueAttemptRecordsFromJsonl,
} = require("./technique-packs.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  safeRecordAgentRunTelemetry,
} = require("./tool-telemetry.js");
const {
  safeRecordHunterStoppedPipelineEvent,
} = require("./pipeline-events.js");

const TECHNIQUE_ATTEMPT_COMPLETION_STATUSES = new Set([
  "attempted",
  "not_applicable",
  "promising",
  "validated",
  "failed",
  "skipped",
]);

function handoffTelemetry(handoff, { present = true, valid = true } = {}) {
  return {
    present,
    valid,
    provenance: handoff && handoff.provenance ? handoff.provenance : null,
    surface_status: handoff && handoff.surface_status ? handoff.surface_status : null,
    summary_present: typeof (handoff && handoff.summary) === "string" && handoff.summary.trim() !== "",
    chain_notes_count: Array.isArray(handoff && handoff.chain_notes) ? handoff.chain_notes.length : 0,
  };
}

function summarizeCoverageForRun(marker) {
  const summary = { total: 0, by_status: {} };
  if (!marker) return summary;

  try {
    const records = readCoverageRecordsFromJsonl(marker.target_domain);
    for (const record of records) {
      if (
        record.wave !== marker.wave ||
        record.agent !== marker.agent ||
        record.surface_id !== marker.surface_id
      ) {
        continue;
      }
      summary.total += 1;
      summary.by_status[record.status] = (summary.by_status[record.status] || 0) + 1;
    }
  } catch {}
  return summary;
}

function summarizeFindingsForRun(marker) {
  const summary = { count: 0 };
  if (!marker) return summary;

  try {
    const findings = readFindingsFromJsonl(marker.target_domain);
    summary.count = findings.filter((finding) => (
      finding.wave === marker.wave &&
      finding.agent === marker.agent &&
      finding.surface_id === marker.surface_id
    )).length;
  } catch {}
  return summary;
}

function evaluateTechniqueAttemptRequirement(marker, assignment) {
  if (
    !assignment ||
    !assignment.context_budget ||
    assignment.context_budget.attempt_log_required !== true
  ) {
    return null;
  }

  let attempts;
  try {
    attempts = readTechniqueAttemptRecordsFromJsonl(marker.target_domain);
  } catch (error) {
    return {
      ok: false,
      status: "blocked",
      block_code: "invalid_technique_attempt_log",
      reason: `Hunter ${marker.wave}/${marker.agent} has unreadable technique attempt history: ${error.message || String(error)}`,
      marker,
      handoff: null,
    };
  }

  const matchingAttempt = attempts.find((attempt) =>
    attempt.target_domain === marker.target_domain &&
    attempt.wave === marker.wave &&
    attempt.agent === marker.agent &&
    attempt.surface_id === marker.surface_id &&
    TECHNIQUE_ATTEMPT_COMPLETION_STATUSES.has(attempt.status)
  );
  if (matchingAttempt) return null;

  return {
    ok: false,
    status: "blocked",
    block_code: "missing_technique_attempt_log",
    reason: `Hunter ${marker.wave}/${marker.agent} must call bounty_log_technique_attempt with a real attempt outcome before finalizing this surface.`,
    marker,
    handoff: null,
  };
}

function normalizeFinalizeArgs(args) {
  const targetDomain = assertNonEmptyString(args.target_domain, "target_domain");
  const wave = parseWaveId(args.wave);
  const agent = parseAgentId(args.agent);
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  return {
    target_domain: targetDomain,
    wave,
    agent,
    surface_id: surfaceId,
  };
}

function evaluateHunterCompletion(args) {
  const marker = normalizeFinalizeArgs(args);
  const waveNumber = Number(marker.wave.slice(1));
  let waveAssignments;
  try {
    waveAssignments = loadWaveAssignments(marker.target_domain, waveNumber);
  } catch (error) {
    return {
      ok: false,
      status: "blocked",
      block_code: "unreadable_wave_assignments",
      reason: `Hunter ${marker.wave}/${marker.agent} could not read wave assignments: ${error.message || String(error)}`,
      marker,
      handoff: handoffTelemetry(null, { present: false, valid: false }),
    };
  }

  let handoffs;
  try {
    handoffs = buildWaveHandoffsDocument(marker.target_domain, [waveNumber]);
  } catch (error) {
    return {
      ok: false,
      status: "blocked",
      block_code: "unreadable_wave_assignments",
      reason: `Hunter ${marker.wave}/${marker.agent} could not evaluate wave assignments: ${error.message || String(error)}`,
      marker,
      handoff: handoffTelemetry(null, { present: false, valid: false }),
    };
  }

  const missing = (handoffs.missing_handoffs || []).find((item) => item.agent === marker.agent);
  if (missing) {
    return {
      ok: false,
      status: "blocked",
      block_code: "missing_handoff",
      reason: `Hunter ${marker.wave}/${marker.agent} must call bounty_write_wave_handoff before finalizing.`,
      marker,
      handoff: handoffTelemetry(null, { present: false, valid: false }),
    };
  }

  const invalid = (handoffs.invalid_handoffs || []).find((item) => item.agent === marker.agent);
  if (invalid) {
    return {
      ok: false,
      status: "blocked",
      block_code: "invalid_handoff",
      reason: `Hunter ${marker.wave}/${marker.agent} wrote an invalid handoff: ${invalid.error || "validation failed"}`,
      marker,
      handoff: handoffTelemetry(null, { present: true, valid: false }),
    };
  }

  const handoff = (handoffs.handoffs || []).find((item) => item.agent === marker.agent);
  if (!handoff) {
    return {
      ok: false,
      status: "blocked",
      block_code: "missing_handoff",
      reason: `Hunter ${marker.wave}/${marker.agent} handoff was not found in structured wave handoffs.`,
      marker,
      handoff: handoffTelemetry(null, { present: false, valid: false }),
    };
  }

  if (handoff.wave !== marker.wave || handoff.surface_id !== marker.surface_id) {
    return {
      ok: false,
      status: "blocked",
      block_code: "handoff_mismatch",
      reason: `Hunter finalization does not match structured handoff for ${marker.wave}/${marker.agent}.`,
      marker,
      handoff: handoffTelemetry(handoff),
    };
  }

  const assignment = waveAssignments.assignmentByAgent.get(marker.agent);
  const techniqueAttemptBlock = evaluateTechniqueAttemptRequirement(marker, assignment);
  if (techniqueAttemptBlock) {
    return {
      ...techniqueAttemptBlock,
      handoff: handoffTelemetry(handoff),
    };
  }

  return {
    ok: true,
    status: "allowed",
    block_code: null,
    reason: "handoff valid",
    marker,
    handoff: handoffTelemetry(handoff),
  };
}

function telemetryInput(evaluation, {
  transcript_path: transcriptPath = null,
  telemetry_source: telemetrySource = "bounty_finalize_hunter_run",
  now = new Date(),
} = {}) {
  const marker = evaluation && evaluation.marker ? evaluation.marker : null;
  return {
    runType: "hunter",
    status: evaluation.status,
    blockCode: evaluation.block_code,
    target_domain: marker && marker.target_domain,
    wave: marker && marker.wave,
    agent: marker && marker.agent,
    surface_id: marker && marker.surface_id,
    transcript_path: transcriptPath,
    handoff: evaluation.handoff,
    coverage: summarizeCoverageForRun(marker),
    findings: summarizeFindingsForRun(marker),
    telemetry_source: telemetrySource,
    now,
  };
}

function recordHunterCompletionTelemetry(evaluation, options = {}) {
  // Evidence-mode input is already a fully-formed telemetry record (the hook
  // builds it directly because evidence runs have no wave/agent and skip the
  // structured-handoff evaluation path). Detect that shape by the runType
  // field and pass it through to the recorders unchanged.
  if (evaluation && evaluation.runType === "evidence") {
    safeRecordAgentRunTelemetry(evaluation);
    safeRecordHunterStoppedPipelineEvent(evaluation);
    return evaluation;
  }
  const input = telemetryInput(evaluation, options);
  safeRecordAgentRunTelemetry(input);
  safeRecordHunterStoppedPipelineEvent(input);
  return input;
}

function finalizeHunterCompletion(args, options = {}) {
  const evaluation = evaluateHunterCompletion(args);
  recordHunterCompletionTelemetry(evaluation, options);
  return evaluation;
}

function finalizeHunterRun(args) {
  const evaluation = finalizeHunterCompletion(args, {
    telemetry_source: "bounty_finalize_hunter_run",
  });
  if (!evaluation.ok) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, evaluation.reason, {
      block_code: evaluation.block_code,
      target_domain: evaluation.marker.target_domain,
      wave: evaluation.marker.wave,
      agent: evaluation.marker.agent,
      surface_id: evaluation.marker.surface_id,
      handoff: evaluation.handoff,
    });
  }

  return JSON.stringify({
    version: 1,
    status: evaluation.status,
    target_domain: evaluation.marker.target_domain,
    wave: evaluation.marker.wave,
    agent: evaluation.marker.agent,
    surface_id: evaluation.marker.surface_id,
    message: evaluation.reason,
    handoff: evaluation.handoff,
  });
}

module.exports = {
  EVIDENCE_MODE,
  evaluateEvidenceCompletion,
  evaluateHunterCompletion,
  evaluateTechniqueAttemptRequirement,
  evidenceMarkerValidationError,
  evidenceTelemetryInput,
  finalizeHunterCompletion,
  finalizeHunterRun,
  handoffTelemetry,
  isEvidenceMarker,
  markerMode,
  recordHunterCompletionTelemetry,
  summarizeCoverageForRun,
  summarizeFindingsForRun,
  telemetryInput,
};
