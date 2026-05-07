"use strict";

const fs = require("fs");
const {
  PHASE_VALUES,
} = require("./constants.js");
const {
  assertNonEmptyString,
} = require("./validation.js");
const {
  reportMarkdownPath,
} = require("./paths.js");
const {
  readSessionStateStrict,
} = require("./session-state.js");
const {
  readSessionArtifactSummary,
} = require("./pipeline-analytics.js");

function phaseAtLeast(phase, requiredPhase) {
  const current = PHASE_VALUES.indexOf(phase);
  const required = PHASE_VALUES.indexOf(requiredPhase);
  return current >= 0 && required >= 0 && current >= required;
}

function evidenceStatus(artifacts) {
  if (artifacts.evidence.valid && artifacts.evidence.skipped) return "skipped";
  if (artifacts.evidence.valid) return "valid";
  if (artifacts.verification.final_reportable_count > 0) return "missing_or_invalid";
  return artifacts.evidence.exists ? "invalid" : "not_required";
}

function deriveBlockers(state, artifacts) {
  const blockers = [];
  for (const error of artifacts.artifact_errors.slice(0, 6)) {
    blockers.push(`artifact_error: ${error}`);
  }

  if (state.pending_wave != null) {
    const pending = artifacts.waves.find((wave) => wave.wave_number === state.pending_wave);
    if (pending) {
      blockers.push(`wave_${state.pending_wave}_pending: ${pending.received_agents.length}/${pending.assignments_total} handoffs received`);
    } else {
      blockers.push(`wave_${state.pending_wave}_pending: readiness unavailable`);
    }
  }

  if (phaseAtLeast(state.phase, "GRADE") && !artifacts.verification.rounds.final.valid) {
    blockers.push("final_verification_missing_or_invalid");
  }

  if (
    phaseAtLeast(state.phase, "GRADE") &&
    artifacts.verification.final_reportable_count > 0 &&
    !artifacts.evidence.valid
  ) {
    const missing = artifacts.evidence.missing_finding_ids.length
      ? ` (${artifacts.evidence.missing_finding_ids.join(", ")})`
      : "";
    blockers.push(`evidence_missing_or_invalid${missing}`);
  }

  if (phaseAtLeast(state.phase, "REPORT") && !artifacts.grade.valid) {
    blockers.push("grade_missing_or_invalid");
  }

  if (state.phase === "REPORT" && !artifacts.report.present) {
    blockers.push("report_missing");
  }

  return blockers.slice(0, 10);
}

function nextAction(state, artifacts, blockers) {
  if (state.pending_wave != null) {
    return `Resume and reconcile pending wave ${state.pending_wave} with bounty_apply_wave_merge.`;
  }
  if (blockers.includes("report_missing")) {
    return "Run the report writer, then call bounty_read_session_summary again.";
  }
  if (artifacts.grade.verdict === "HOLD") {
    return "Return to HUNT with grader feedback, then re-run CHAIN through REPORT.";
  }
  if (state.phase === "RECON") return "Run recon, write attack_surface.json, then transition to AUTH.";
  if (state.phase === "AUTH") return "Complete auth or use --no-auth, then transition to HUNT.";
  if (state.phase === "HUNT" || state.phase === "EXPLORE") return "Start or resume the next hunter wave.";
  if (state.phase === "CHAIN") return "Run chain-builder and write terminal chain attempts.";
  if (state.phase === "VERIFY") return "Run verification rounds and evidence collection for final reportables.";
  if (state.phase === "GRADE") return "Run grader and read back the grade verdict.";
  if (state.phase === "REPORT") {
    return artifacts.report.present
      ? "Present the compact summary and report path to the operator."
      : "Run report-writer and write report.md.";
  }
  return "Inspect session state through MCP readers.";
}

// Operator-actionability ordering: kinds the operator can resolve
// fastest first. auth/egress have registry-based unblock paths;
// funded_wallet/key_material/external_credential require operator
// procurement. Lower number = higher actionability.
const BLOCKED_PREREQ_KIND_ACTIONABILITY = Object.freeze({
  auth_missing: 0,
  egress_unreachable: 1,
  funded_wallet_missing: 2,
  key_material_missing: 3,
  external_credential_missing: 4,
});

function summarizeBlockedPrereqs(state) {
  const groups = new Map();
  const terminallyBlocked = Array.isArray(state.terminally_blocked) ? state.terminally_blocked : [];
  // Iterate in blocked_at_wave ASC order so the LATEST blocker
  // overrides the example_reason field — operators care about the
  // freshest signal, not the oldest sample.
  const sortedEntries = [...terminallyBlocked].sort((a, b) =>
    (a.blocked_at_wave || 0) - (b.blocked_at_wave || 0),
  );
  for (const entry of sortedEntries) {
    if (!entry || !Array.isArray(entry.blockers)) continue;
    for (const blocker of entry.blockers) {
      const hint = blocker.identifier_hint || null;
      const key = `${blocker.kind}\t${hint || ""}`;
      if (!groups.has(key)) {
        groups.set(key, {
          kind: blocker.kind,
          identifier_hint: hint,
          surface_count: 0,
          surface_ids: [],
          latest_reason: null,
          latest_blocked_at_wave: 0,
        });
      }
      const group = groups.get(key);
      group.surface_count += 1;
      if (!group.surface_ids.includes(entry.surface_id)) {
        group.surface_ids.push(entry.surface_id);
      }
      // Latest wave wins (entries are sorted ASC, so later iterations overwrite).
      if (blocker.reason) {
        group.latest_reason = blocker.reason;
      }
      if ((entry.blocked_at_wave || 0) > group.latest_blocked_at_wave) {
        group.latest_blocked_at_wave = entry.blocked_at_wave || 0;
      }
    }
  }
  return {
    total_blocked_surfaces: terminallyBlocked.length,
    by_kind: Array.from(groups.values()).sort((a, b) => {
      const aRank = BLOCKED_PREREQ_KIND_ACTIONABILITY[a.kind] ?? 99;
      const bRank = BLOCKED_PREREQ_KIND_ACTIONABILITY[b.kind] ?? 99;
      if (aRank !== bRank) return aRank - bRank;
      return (a.identifier_hint || "").localeCompare(b.identifier_hint || "");
    }),
  };
}

function readSessionSummary(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const { state } = readSessionStateStrict(domain);
  const artifacts = readSessionArtifactSummary(domain);
  const blockers = deriveBlockers(state, artifacts);
  const reportPath = reportMarkdownPath(domain);

  return JSON.stringify({
    version: 1,
    summary: {
      target: domain,
      phase: state.phase,
      auth_status: state.auth_status,
      operator_note: state.operator_note,
      waves_run: state.hunt_wave,
      pending_wave: state.pending_wave,
      finding_total: artifacts.findings.total,
      final_reportable_count: artifacts.verification.final_reportable_count,
      blocked_prereqs: summarizeBlockedPrereqs(state),
      evidence_status: {
        status: evidenceStatus(artifacts),
        exists: artifacts.evidence.exists,
        valid: artifacts.evidence.valid,
        skipped: artifacts.evidence.skipped,
        packs_count: artifacts.evidence.packs_count,
        reportable_findings_covered: artifacts.evidence.reportable_findings_covered,
        missing_finding_ids: artifacts.evidence.missing_finding_ids,
      },
      grade_verdict: artifacts.grade.verdict,
      grade: {
        exists: artifacts.grade.exists,
        valid: artifacts.grade.valid,
        verdict: artifacts.grade.verdict,
        total_score: artifacts.grade.total_score,
      },
      report: {
        present: fs.existsSync(reportPath),
        path: reportPath,
      },
      blockers,
      next_action: nextAction(state, artifacts, blockers),
    },
  });
}

module.exports = {
  readSessionSummary,
};
