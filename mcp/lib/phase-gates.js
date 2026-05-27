"use strict";

const {
  COVERAGE_UNFINISHED_STATUS_VALUES,
  CHAIN_ATTEMPT_TERMINAL_OUTCOME_VALUES,
} = require("./constants.js");
const fs = require("fs");
const path = require("path");
const {
  rankAttackSurfaces,
} = require("./ranking.js");
const {
  latestCoverageRecordsByKey,
  readCoverageRecordsFromJsonl,
} = require("./coverage.js");
const {
  readFindingsFromJsonl,
} = require("./findings.js");
const {
  requireVerificationCompleteForGrade,
} = require("./verification.js");
const {
  readChainAttemptsFromJsonl,
  summarizeChainAttempts,
} = require("./chain-attempts.js");
const {
  sessionDir,
  statePath,
} = require("./paths.js");
const {
  readJsonFile,
} = require("./storage.js");
const {
  loadWaveAssignments,
} = require("./assignments.js");
const {
  readHandoffSigningKey,
} = require("./handoff-signing-key.js");
const {
  assignmentRequiresToken,
  validateHandoffProvenance,
} = require("./wave-handoff-contracts.js");
const {
  currentBlockers,
  currentClosures,
  currentSurfaces,
} = require("./frontier-projections.js");

// Read the session's handoff_provenance_required flag directly from state.json
// (no normalization, no lock — call sites are read-only). See wave-handoff-store
// for the equivalent helper; we duplicate rather than circular-import.
function readHandoffProvenanceRequired(domain) {
  try {
    const raw = readJsonFile(statePath(domain));
    return raw && raw.handoff_provenance_required === true;
  } catch {
    return false;
  }
}

// Closures and blockers are read from frontier-projections (Cycle F.3): the
// frontier-events.jsonl ledger is the authoritative source for surface-level
// closure / blocker truth. The state.json arrays (state.explored,
// state.terminally_blocked) are still written by applyWaveMerge under Pact P2
// (dual-write before deletion) and the projection falls back to them when no
// authoritative surface-level event has been emitted. D.3 deletes both the
// state arrays and the fallback once waves.js emits authoritative
// surface_fully_explored / terminally_blocked frontier events.
function exploredSurfaceIdsForDomain(domain) {
  return currentClosures(domain).map((closure) => closure.surface_id);
}

function terminallyBlockedSurfaceIdsForDomain(domain) {
  return currentBlockers(domain).map((entry) => entry.surface_id);
}

function compactErrorMessage(error) {
  return error && error.message ? error.message : String(error);
}

function surfaceLeadsLib() {
  return require("./surface-leads.js");
}

function blocker(code, message, fields = {}) {
  return {
    code,
    message,
    ...fields,
  };
}

function pushUnique(target, seen, value) {
  if (!value || seen.has(value)) return;
  seen.add(value);
  target.push(value);
}

// Surface-level "open" status is governed by frontier-projections derived
// from `closure.recorded` and `blocker.asserted` events (Cycle F.3), not by
// per-endpoint coverage rows. A complete handoff says the evaluator declared
// the surface done; a terminally-blocked surface has been classified as
// blocked-by-prereq across waves and should not requeue until an operator
// clears it. An old coverage row with status=requeue from an earlier wave is
// endpoint-level history, not the surface's current state. Options-bag
// signature so additional closure reasons in future cycles do not shift
// positional arg meaning.
function computeOpenRequeueSurfaceIds(records, options = {}) {
  const exploredSet = new Set(options.exploredSurfaceIds || []);
  const terminallyBlockedSet = new Set(options.terminallyBlockedSurfaceIds || []);
  const latestRecords = Array.from(latestCoverageRecordsByKey(records).values());
  const surfaceIds = [];
  const seen = new Set();

  for (const record of latestRecords) {
    if (!COVERAGE_UNFINISHED_STATUS_VALUES.includes(record.status)) continue;
    if (exploredSet.has(record.surface_id)) continue;
    if (terminallyBlockedSet.has(record.surface_id)) continue;
    pushUnique(surfaceIds, seen, record.surface_id);
  }

  return surfaceIds.sort((a, b) => a.localeCompare(b));
}

function computeAttackSurfaceCoverage(surfaces, exploredSurfaceIds, terminallyBlockedSurfaceIds, openRequeueSurfaceIds) {
  const exploredSet = new Set(exploredSurfaceIds || []);
  const terminallyBlockedSet = new Set(terminallyBlockedSurfaceIds || []);
  const isHighOrCritical = (surface) =>
    ["CRITICAL", "HIGH"].includes(String(surface.priority || "").toUpperCase());
  const nonLowSurfaces = surfaces.filter(
    (surface) => surface.priority && String(surface.priority).toUpperCase() !== "LOW",
  );
  const nonLowExplored = nonLowSurfaces.filter((surface) => exploredSet.has(surface.id)).length;
  const nonLowTerminallyBlocked = nonLowSurfaces.filter((surface) => terminallyBlockedSet.has(surface.id)).length;
  // unexplored_high is the operator-actionable HIGH/CRITICAL set: surfaces
  // that are neither explored nor terminally_blocked. blocked_high is the
  // separately-actionable set: HIGH/CRITICAL surfaces classified blocked
  // by the merge promotion. Each demands a different operator response, so
  // they are surfaced as distinct fields rather than collapsed into one
  // "non-explored" list.
  const unexploredHighSurfaceIds = surfaces
    .filter((surface) => (
      isHighOrCritical(surface) &&
      !exploredSet.has(surface.id) &&
      !terminallyBlockedSet.has(surface.id)
    ))
    .map((surface) => surface.id);
  const blockedHighSurfaceIds = surfaces
    .filter((surface) => isHighOrCritical(surface) && terminallyBlockedSet.has(surface.id))
    .map((surface) => surface.id);

  return {
    total_surfaces: surfaces.length,
    non_low_total: nonLowSurfaces.length,
    non_low_explored: nonLowExplored,
    non_low_terminally_blocked: nonLowTerminallyBlocked,
    non_low_closed: nonLowExplored + nonLowTerminallyBlocked,
    // coverage_pct keeps the explored-only meaning for back-compat with
    // existing analytics/report consumers. closed_pct includes
    // terminally-blocked surfaces (which are closed for the purposes of
    // EVALUATE -> CHAIN gating), so it represents "how much work is actually
    // off the queue" — neglected gap is non_low_total - non_low_closed.
    coverage_pct: nonLowSurfaces.length > 0
      ? Math.round((nonLowExplored / nonLowSurfaces.length) * 100)
      : 100,
    closed_pct: nonLowSurfaces.length > 0
      ? Math.round(((nonLowExplored + nonLowTerminallyBlocked) / nonLowSurfaces.length) * 100)
      : 100,
    unexplored_high: unexploredHighSurfaceIds.length,
    unexplored_high_surface_ids: unexploredHighSurfaceIds,
    blocked_high: blockedHighSurfaceIds.length,
    blocked_high_surface_ids: blockedHighSurfaceIds,
    open_requeue_surface_ids: openRequeueSurfaceIds,
  };
}

function computeEvaluationToChainGate(domain, state) {
  const blockers = [];
  if (state.pending_wave !== null) {
    blockers.push(blocker(
      "pending_wave",
      `pending_wave is still set to ${state.pending_wave}`,
      { pending_wave: state.pending_wave },
    ));
  }

  let surfaces = null;
  let rankedSurfaces = null;
  try {
    rankedSurfaces = rankAttackSurfaces(domain)?.surfaces || null;
  } catch {}
  // Surface coverage reads from currentSurfaces (Cycle F.5): surface-index.json
  // is authoritative when present and falls back to attack_surface.json for
  // legacy sessions only via the explicit projection. D.3 removes the fallback.
  try {
    if (rankedSurfaces) {
      surfaces = rankedSurfaces;
    } else {
      const projection = currentSurfaces(domain);
      if (projection.source === "missing") {
        blockers.push(blocker(
          "attack_surface_unavailable",
          "attack surface could not be read for EVALUATE -> CHAIN gating",
          { error: `Missing attack surface JSON: ${projection.path}` },
        ));
      } else {
        surfaces = projection.surfaces;
      }
    }
  } catch (error) {
    blockers.push(blocker(
      "attack_surface_unavailable",
      "attack surface could not be read for EVALUATE -> CHAIN gating",
      { error: compactErrorMessage(error) },
    ));
  }

  const exploredSurfaceIds = exploredSurfaceIdsForDomain(domain);
  const terminallyBlockedSurfaceIds = terminallyBlockedSurfaceIdsForDomain(domain);

  let openRequeueSurfaceIds = [];
  try {
    openRequeueSurfaceIds = computeOpenRequeueSurfaceIds(
      readCoverageRecordsFromJsonl(domain),
      {
        exploredSurfaceIds,
        terminallyBlockedSurfaceIds,
      },
    );
  } catch (error) {
    blockers.push(blocker(
      "coverage_unavailable",
      "coverage could not be read for EVALUATE -> CHAIN gating",
      { error: compactErrorMessage(error) },
    ));
  }

  let coverage = null;
  if (surfaces) {
    coverage = computeAttackSurfaceCoverage(
      surfaces,
      exploredSurfaceIds,
      terminallyBlockedSurfaceIds,
      openRequeueSurfaceIds,
    );
    if (coverage.unexplored_high_surface_ids.length > 0) {
      blockers.push(blocker(
        "unexplored_high_surfaces",
        "HIGH or CRITICAL attack surfaces remain unexplored",
        { surface_ids: coverage.unexplored_high_surface_ids },
      ));
    }
    if (coverage.blocked_high_surface_ids.length > 0) {
      blockers.push(blocker(
        "blocked_high_surfaces",
        "HIGH or CRITICAL surfaces are terminally blocked by missing prerequisites; add the registered material and clear via bob_clear_terminal_block, or accept the gap with override_reason",
        { surface_ids: coverage.blocked_high_surface_ids },
      ));
    }
  }

  if (openRequeueSurfaceIds.length > 0) {
    blockers.push(blocker(
      "open_requeue_coverage",
      "latest coverage has unfinished promising, needs_auth, or requeue work",
      { surface_ids: openRequeueSurfaceIds },
    ));
  }

  if (state.deep_mode === true) {
    try {
      const preview = surfaceLeadsLib().previewSurfaceLeadPromotion(domain, {
        limit: 8,
        min_score: 60,
        include_medium: false,
      });
      if (preview.would_promote_lead_ids.length > 0) {
        blockers.push(blocker(
          "promotable_surface_leads",
          "deep mode has assignable unpromoted surface leads; call bob_start_next_wave to promote and assign the next runtime-owned wave",
          { lead_ids: preview.would_promote_lead_ids },
        ));
      }
    } catch (error) {
      blockers.push(blocker(
        "surface_leads_unavailable",
        "surface leads could not be read for deep-mode EVALUATE -> CHAIN gating",
        { error: compactErrorMessage(error) },
      ));
    }
  }

  return {
    coverage,
    transition_blockers: blockers,
  };
}

function readStructuredHandoffChainNotes(domain) {
  const dir = sessionDir(domain);
  if (!fs.existsSync(dir)) {
    return [];
  }

  const requireProvenance = readHandoffProvenanceRequired(domain);
  const refs = [];
  const assignmentContexts = new Map();

  function contextFor(wave, agent) {
    if (!assignmentContexts.has(wave)) {
      const waveNumber = Number(wave.slice(1));
      const artifacts = loadWaveAssignments(domain, waveNumber);
      const signingKey = artifacts.assignments.some((assignment) => assignmentRequiresToken(assignment))
        ? readHandoffSigningKey(domain)
        : null;
      assignmentContexts.set(wave, { artifacts, signingKey });
    }
    const context = assignmentContexts.get(wave);
    const assignment = context.artifacts.assignmentByAgent.get(agent);
    if (!assignment) throw new Error(`Unexpected handoff agent ${agent} in ${wave}`);
    return { assignment, signingKey: context.signingKey };
  }

  for (const fileName of fs.readdirSync(dir).sort()) {
    const match = fileName.match(/^handoff-(w[1-9][0-9]*)-(a[1-9][0-9]*)\.json$/);
    if (!match) continue;
    let document;
    try {
      document = readJsonFile(path.join(dir, fileName), { label: fileName });
    } catch {
      continue;
    }
    if (!document || typeof document !== "object" || Array.isArray(document)) continue;
    let assignment;
    try {
      const context = contextFor(match[1], match[2]);
      assignment = context.assignment;
      if (document.target_domain != null && document.target_domain !== domain) continue;
      if (document.wave !== match[1] || document.agent !== match[2] || document.surface_id !== assignment.surface_id) continue;
      validateHandoffProvenance(document, assignment, { signingKey: context.signingKey, requireProvenance });
    } catch {
      continue;
    }
    const chainNotes = Array.isArray(document.chain_notes)
      ? document.chain_notes.filter((note) => typeof note === "string" && note.trim())
      : [];
    if (chainNotes.length === 0) continue;
    refs.push({
      wave: match[1],
      agent: match[2],
      surface_id: typeof document.surface_id === "string" ? document.surface_id.trim() : null,
      chain_notes_count: chainNotes.length,
    });
  }
  return refs;
}

function computeChainRequirement(domain) {
  const findings = readFindingsFromJsonl(domain);
  const handoffChainNotes = readStructuredHandoffChainNotes(domain);
  const reasons = [];
  if (findings.length >= 2) reasons.push("multiple_findings");
  if (handoffChainNotes.length > 0) reasons.push("handoff_chain_notes");

  return {
    required: reasons.length > 0,
    reasons,
    findings_count: findings.length,
    finding_ids: findings.map((finding) => finding.id),
    handoff_chain_notes_count: handoffChainNotes.reduce((total, handoff) => total + handoff.chain_notes_count, 0),
    handoff_refs: handoffChainNotes,
  };
}

function computeChainToVerifyGate(domain) {
  const blockers = [];
  let requirement = null;
  let attempts = [];
  let attemptsSummary = null;

  try {
    requirement = computeChainRequirement(domain);
  } catch (error) {
    blockers.push(blocker(
      "chain_context_unavailable",
      "chain context could not be read for CHAIN -> VERIFY gating",
      { error: compactErrorMessage(error) },
    ));
  }

  try {
    attempts = readChainAttemptsFromJsonl(domain);
    attemptsSummary = summarizeChainAttempts(attempts);
  } catch (error) {
    blockers.push(blocker(
      "chain_attempts_unavailable",
      "chain attempts could not be read for CHAIN -> VERIFY gating",
      { error: compactErrorMessage(error) },
    ));
  }

  const terminalAttempts = attempts.filter((attempt) => (
    CHAIN_ATTEMPT_TERMINAL_OUTCOME_VALUES.includes(attempt.outcome)
  ));

  if (requirement && requirement.required && attemptsSummary && terminalAttempts.length === 0) {
    blockers.push(blocker(
      "chain_attempts_missing",
      "CHAIN phase requires at least one terminal chain attempt before VERIFY",
      {
        findings_count: requirement.findings_count,
        handoff_chain_notes_count: requirement.handoff_chain_notes_count,
        outcomes: attemptsSummary.by_outcome,
      },
    ));
  }

  return {
    chain: {
      requirement,
      attempts: {
        total: attempts.length,
        terminal: terminalAttempts.length,
        by_outcome: attemptsSummary
          ? attemptsSummary.by_outcome
          : null,
      },
    },
    transition_blockers: blockers,
  };
}

function computeVerifyToGradeGate(domain) {
  const blockers = [];
  let evidence = null;
  let verification = null;

  try {
    const validation = requireVerificationCompleteForGrade(domain);
    const evidenceValidation = validation.evidence;
    evidence = {
      valid: true,
      skipped: evidenceValidation.skipped,
      packs_count: evidenceValidation.packs_count,
      representative_samples_count: evidenceValidation.representative_samples_count,
      final_reportable_count: evidenceValidation.final_reportable_count,
      reportable_findings_covered: evidenceValidation.reportable_findings_covered,
      missing_finding_ids: evidenceValidation.missing_finding_ids,
    };
    if (validation.schema_version === 2) {
      verification = {
        schema_version: 2,
        verification_attempt_id: validation.verification_attempt_id,
        verification_snapshot_hash: validation.verification_snapshot_hash,
        adjudication_plan_hash: validation.adjudication_plan_hash,
        final_verification_hash: validation.final_verification_hash,
        counts: validation.counts,
      };
    }
  } catch (error) {
    const message = compactErrorMessage(error);
    const evidenceLike = /Evidence packs|evidence packs|Missing evidence packs|final reportable/i.test(message);
    blockers.push(blocker(
      evidenceLike ? "evidence_packs_invalid" : "verification_chain_incomplete",
      evidenceLike
        ? "evidence packs are missing or invalid for final reportable findings"
        : "verification v2 chain is incomplete or stale",
      { error: message },
    ));
  }

  return {
    evidence,
    verification,
    transition_blockers: blockers,
  };
}

function formatTransitionBlockers(blockers) {
  return blockers.map((item) => {
    if (Array.isArray(item.surface_ids) && item.surface_ids.length > 0) {
      return `${item.message}: ${item.surface_ids.join(", ")}`;
    }
    if (item.outcomes) {
      return `${item.message}: ${JSON.stringify(item.outcomes)}`;
    }
    if (item.pending_wave != null) {
      return item.message;
    }
    if (item.error) {
      return `${item.message}: ${item.error}`;
    }
    return item.message;
  }).join("; ");
}

module.exports = {
  computeChainRequirement,
  computeChainToVerifyGate,
  computeEvaluationToChainGate,
  computeOpenRequeueSurfaceIds,
  computeVerifyToGradeGate,
  formatTransitionBlockers,
  readStructuredHandoffChainNotes,
};
