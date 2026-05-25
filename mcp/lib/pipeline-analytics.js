"use strict";

const fs = require("fs");
const {
  PHASE_VALUES,
  VERIFICATION_ROUND_VALUES,
} = require("./constants.js");
const {
  assertNonEmptyString,
} = require("./validation.js");
const {
  findingsIndexJsonlPath,
  findingsJsonlPath,
  httpAuditJsonlPath,
  pipelineEventsJsonlPath,
  reportMarkdownPath,
  sessionDir,
  sessionsRoot,
  statePath,
} = require("./paths.js");
const {
  readAgentRunTelemetryEvents,
  readToolTelemetryEvents,
  summarizeToolTelemetryEvents,
} = require("./tool-telemetry.js");
const {
  HANDOFF_ANALYTICS_MAX_FILES,
  WAVE_READINESS_MAX_ASSIGNMENT_FILES,
  readSessionArtifactSummary,
} = require("./pipeline-session-artifacts.js");
const PIPELINE_ANALYTICS_VERSION = 1;
const PIPELINE_EVENT_READ_MAX_BYTES = 16 * 1024 * 1024;
const DEFAULT_WINDOW_DAYS = 30;
const MAX_WINDOW_DAYS = 365;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const CROSS_SESSION_ANALYTICS_MAX_SESSIONS = 200;
const STALE_PENDING_WAVE_MS = 2 * 60 * 60 * 1000;
const HIGH_TOOL_FAILURE_RATE = 0.2;
const HIGH_TOOL_FAILURE_MIN_FAILURES = 3;
const AUTHORITY_DERIVED_EVENT_FIELDS = Object.freeze([
  "checkpoint_mode",
  "block_internal_hosts",
  "block_internal_hosts_source",
  "egress_profile",
  "egress_region",
  "proxy_configured",
  "egress_profile_identity_hash",
  "egress_profile_identity_version",
]);
const {
  PIPELINE_EVENT_TYPES,
  PIPELINE_EVENT_VERSION,
  appendPipelineEventDirect,
  capString,
  normalizePipelineEvent,
  normalizePipelineEventForRead,
  normalizePositiveInteger,
  pipelineAnalyticsEnabled,
  safeAppendPipelineEventDirect,
  safeAppendPipelineEventWithSessionLock,
  safeRecordHunterStoppedPipelineEvent,
  timestampMs,
} = require("./pipeline-events.js");

function readPipelineEventJsonlSafe(filePath) {
  const label = "pipeline-events.jsonl";
  const result = {
    records: [],
    malformed_lines: 0,
    error: null,
  };
  let content;
  try {
    const stats = fs.statSync(filePath);
    if (stats.size > PIPELINE_EVENT_READ_MAX_BYTES) {
      throw new Error(`${label} exceeds read cap of ${PIPELINE_EVENT_READ_MAX_BYTES} bytes: ${filePath}`);
    }
    content = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    result.error = `Unreadable ${label}: ${error.message || String(error)}`;
    return result;
  }
  const lines = content.split(/\r?\n/);
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
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

function buildBackfillEvents(targetDomain, artifacts) {
  const source = "artifact_backfill";
  const ts = artifacts.latest_artifact_ts || new Date().toISOString();
  const egressFields = {
    egress_profile: artifacts.state.egress_profile,
    egress_region: artifacts.state.egress_region,
    proxy_configured: artifacts.state.proxy_configured,
    egress_profile_identity_hash: artifacts.state.egress_profile_identity_hash,
    egress_profile_identity_version: artifacts.state.egress_profile_identity_version,
    checkpoint_mode: artifacts.state.checkpoint_mode,
    block_internal_hosts: artifacts.state.block_internal_hosts,
    block_internal_hosts_source: artifacts.state.block_internal_hosts_source,
  };
  const events = [];
  events.push(normalizePipelineEvent(targetDomain, "session_started", {
    ts: artifacts.state.mtime || ts,
    phase: "RECON",
    source,
    ...egressFields,
  }));
  if (artifacts.state.phase && artifacts.state.phase !== "RECON") {
    events.push(normalizePipelineEvent(targetDomain, "phase_transitioned", {
      ts: artifacts.state.mtime || ts,
      to_phase: artifacts.state.phase,
      status: "current",
      source,
      ...egressFields,
    }));
  }
  for (const wave of artifacts.waves) {
    events.push(normalizePipelineEvent(targetDomain, "wave_started", {
      ts,
      wave_number: wave.wave_number,
      status: wave.error ? "invalid" : "started",
      counts: { assignments: wave.assignments_total },
      source,
      ...egressFields,
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
        ...egressFields,
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
        ...egressFields,
      }));
    }
  }
  if (artifacts.coverage.total_records > 0) {
    events.push(normalizePipelineEvent(targetDomain, "coverage_logged", {
      ts: artifacts.coverage.mtime || ts,
      status: "backfilled",
      counts: { records: artifacts.coverage.total_records, surfaces: artifacts.coverage.surface_count },
      source,
      ...egressFields,
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
      ...egressFields,
    }));
  }
  if (artifacts.findings.total > 0) {
    events.push(normalizePipelineEvent(targetDomain, "finding_recorded", {
      ts: artifacts.findings.mtime || ts,
      status: "backfilled",
      counts: { findings: artifacts.findings.total },
      source,
      ...egressFields,
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
      ...egressFields,
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
      ...egressFields,
    }));
  }
  if (artifacts.grade.exists) {
    events.push(normalizePipelineEvent(targetDomain, "grade_written", {
      ts: artifacts.grade.mtime || ts,
      status: artifacts.grade.verdict || "unknown",
      counts: { findings: artifacts.grade.findings_count, total_score: artifacts.grade.total_score || 0 },
      source,
      ...egressFields,
    }));
  }
  return events.sort((a, b) => timestampMs(a.ts) - timestampMs(b.ts));
}

function egressFieldsFromArtifactState(artifacts) {
  const state = artifacts && artifacts.state ? artifacts.state : {};
  return {
    egress_profile: state.egress_profile,
    egress_region: state.egress_region,
    proxy_configured: state.proxy_configured,
    egress_profile_identity_hash: state.egress_profile_identity_hash,
    egress_profile_identity_version: state.egress_profile_identity_version,
    checkpoint_mode: state.checkpoint_mode,
    block_internal_hosts: state.block_internal_hosts,
    block_internal_hosts_source: state.block_internal_hosts_source,
  };
}

function enrichEventWithSessionEgress(event, egressFields) {
  if (!event || !egressFields) return event;
  const hasEgressFields = [
    "egress_profile",
    "egress_region",
    "egress_profile_identity_hash",
    "checkpoint_mode",
    "block_internal_hosts_source",
  ].some((field) => Boolean(egressFields[field]))
    || typeof egressFields.proxy_configured === "boolean"
    || typeof egressFields.block_internal_hosts === "boolean"
    || Number.isInteger(egressFields.egress_profile_identity_version);
  if (!hasEgressFields) return event;
  const enriched = { ...event };
  for (const field of ["egress_profile", "egress_region", "egress_profile_identity_hash", "checkpoint_mode", "block_internal_hosts_source"]) {
    if (!enriched[field] && egressFields[field]) {
      enriched[field] = egressFields[field];
    }
  }
  if (typeof enriched.proxy_configured !== "boolean" && typeof egressFields.proxy_configured === "boolean") {
    enriched.proxy_configured = egressFields.proxy_configured;
  }
  if (typeof enriched.block_internal_hosts !== "boolean" && typeof egressFields.block_internal_hosts === "boolean") {
    enriched.block_internal_hosts = egressFields.block_internal_hosts;
  }
  if (
    !Number.isInteger(enriched.egress_profile_identity_version) &&
    Number.isInteger(egressFields.egress_profile_identity_version) &&
    egressFields.egress_profile_identity_version > 0
  ) {
    enriched.egress_profile_identity_version = egressFields.egress_profile_identity_version;
  }
  return enriched;
}

function readPipelineEvents(targetDomain, { allowBackfill = true, validateAuthority = false } = {}) {
  const filePath = pipelineEventsJsonlPath(targetDomain);
  let artifactSummary = null;
  let sessionEgressFields = null;
  const result = {
    enabled: pipelineAnalyticsEnabled(),
    events_path: filePath,
    exists: fs.existsSync(filePath),
    events: [],
    malformed_lines: 0,
    error: null,
    backfilled: false,
  };

  if (result.exists) {
    artifactSummary = readSessionArtifactSummary(targetDomain, { validateAuthority });
    const authorityInvalid = sessionAuthorityInvalid(artifactSummary);
    sessionEgressFields = authorityInvalid ? null : egressFieldsFromArtifactState(artifactSummary);
    const read = readPipelineEventJsonlSafe(filePath);
    result.error = read.error;
    result.malformed_lines = read.malformed_lines;
    if (!read.error) {
      for (const record of read.records) {
        const event = normalizePipelineEventForRead(record, targetDomain);
        if (event) {
          const enriched = enrichEventWithSessionEgress(event, sessionEgressFields);
          result.events.push(authorityInvalid ? stripAuthorityDerivedEventFields(enriched) : enriched);
        } else {
          result.malformed_lines += 1;
        }
      }
    }
  }

  if (allowBackfill && !result.exists && result.events.length === 0) {
    result.events = buildBackfillEvents(
      targetDomain,
      artifactSummary || readSessionArtifactSummary(targetDomain, { validateAuthority }),
    );
    result.backfilled = true;
  }

  result.events.sort((a, b) => timestampMs(a.ts) - timestampMs(b.ts));
  return result;
}

function sessionAuthorityInvalid(artifactSummary) {
  return !!(
    artifactSummary &&
    Array.isArray(artifactSummary.artifact_errors) &&
    artifactSummary.artifact_errors.some((error) => /^Session authority invalid:/.test(error))
  );
}

function stripAuthorityDerivedEventFields(event) {
  const stripped = { ...event };
  for (const field of AUTHORITY_DERIVED_EVENT_FIELDS) {
    delete stripped[field];
  }
  return stripped;
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
  for (const field of ["phase", "from_phase", "to_phase", "wave_number", "agent", "surface_id", "status", "block_code", "counts", "source", "force_merge", "force_merge_reason", "override", "override_reason", "legacy_migration", "kind", "identifier_hint", "verification_attempt_id", "verification_snapshot_hash", "adjudication_plan_hash", "final_verification_hash", "capability_pack", "lease_scope", "replay_purpose", "started_by", "checkpoint_mode", "block_internal_hosts", "block_internal_hosts_source", "egress_profile", "egress_region", "proxy_configured", "egress_profile_identity_hash", "egress_profile_identity_version"]) {
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

function filterTelemetryReadResult(readResult, { targetDomain = null, cutoffMs = null, predicate = null } = {}) {
  const events = filterByWindow(readResult.events, cutoffMs)
    .filter((event) => (targetDomain ? event.target_domain === targetDomain : true))
    .filter((event) => (predicate ? predicate(event) : true));
  return { ...readResult, events };
}

function buildToolHealth({ targetDomain = null, cutoffMs = null, limit = DEFAULT_LIMIT, env = process.env, readResult = null } = {}) {
  const baseRead = readResult || readToolTelemetryEvents({ target_domain: targetDomain, env });
  const filtered = readResult
    ? filterTelemetryReadResult(baseRead, { targetDomain, cutoffMs })
    : { ...baseRead, events: filterByWindow(baseRead.events, cutoffMs) };
  return slimToolHealth(filtered, filtered.events, limit);
}

function buildHunterHealth({ targetDomain = null, cutoffMs = null, limit = DEFAULT_LIMIT, env = process.env, readResult = null } = {}) {
  const baseRead = readResult || readAgentRunTelemetryEvents({
    target_domain: targetDomain,
    agent_run_type: "hunter",
    env,
  });
  const filtered = readResult
    ? filterTelemetryReadResult(baseRead, {
      targetDomain,
      cutoffMs,
      predicate: (event) => event.run_type === "hunter",
    })
    : { ...baseRead, events: filterByWindow(baseRead.events, cutoffMs) };
  const events = filtered.events;
  const byStatus = { allowed: 0, blocked: 0 };
  const byBlockCode = {};
  for (const event of events) {
    byStatus[event.status] = (byStatus[event.status] || 0) + 1;
    if (event.status === "blocked" && event.block_code) {
      byBlockCode[event.block_code] = (byBlockCode[event.block_code] || 0) + 1;
    }
  }
  return {
    enabled: filtered.enabled,
    telemetry_path: filtered.telemetry_path,
    total_runs: events.length,
    malformed_lines: filtered.malformed_lines,
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

function analyzeSession(targetDomain, {
  cutoffMs = null,
  limit = DEFAULT_LIMIT,
  env = process.env,
  telemetryCache = null,
  validateAuthority = false,
} = {}) {
  const artifacts = readSessionArtifactSummary(targetDomain, { validateAuthority });
  const eventRead = readPipelineEvents(targetDomain, { validateAuthority });
  const events = filterByWindow(eventRead.events, cutoffMs);
  const allEvents = eventRead.events;
  const toolHealth = buildToolHealth({
    targetDomain,
    cutoffMs,
    limit,
    env,
    readResult: telemetryCache ? telemetryCache.toolRead : null,
  });
  const hunterHealth = buildHunterHealth({
    targetDomain,
    cutoffMs,
    limit,
    env,
    readResult: telemetryCache ? telemetryCache.hunterRead : null,
  });
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

  const findingIndexFailures = allEvents.filter((event) => event.type === "finding_index_failed");
  if (findingIndexFailures.length > 0) {
    issues.push(issue("finding_index_failed", "needs_attention", "Finding index refresh failed after a finding was recorded.", {
      failures: findingIndexFailures.length,
      latest_event: compactEvent(findingIndexFailures[findingIndexFailures.length - 1]),
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
    const submitWithoutCanonicalReport = artifacts.grade.verdict === "SUBMIT";
    issues.push(issue(
      submitWithoutCanonicalReport ? "report_pending_canonical_path" : "missing_report",
      "needs_attention",
      submitWithoutCanonicalReport
        ? "Session reached REPORT with SUBMIT grade, but canonical report.md is not present."
        : "Session reached REPORT but report.md is not present.",
      {
        phase: artifacts.state.phase,
        grade_verdict: artifacts.grade.verdict,
        canonical_report_path: artifacts.report.path,
      },
    ));
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
    checkpoint_mode: artifacts.state.checkpoint_mode,
    block_internal_hosts: artifacts.state.block_internal_hosts,
    block_internal_hosts_source: artifacts.state.block_internal_hosts_source,
    egress_profile_identity: {
      egress_profile: artifacts.state.egress_profile,
      egress_region: artifacts.state.egress_region,
      proxy_configured: artifacts.state.proxy_configured,
      egress_profile_identity_hash: artifacts.state.egress_profile_identity_hash,
      egress_profile_identity_version: artifacts.state.egress_profile_identity_version,
    },
    waves: {
      hunt_wave: artifacts.state.hunt_wave,
      pending_wave: artifacts.state.pending_wave,
      assignment_files: artifacts.waves.length,
      assignment_files_total: artifacts.wave_bounds.assignment_files_total,
      assignment_files_omitted: artifacts.wave_bounds.waves_omitted,
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
      block_internal_hosts: artifacts.http_audit.block_internal_hosts,
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
    report_pending_canonical_path: "Write or move the consolidated report to the canonical session report.md path, then call bounty_report_written.",
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

function sessionActivityMtimeMs(targetDomain) {
  const candidates = [
    statePath(targetDomain),
    pipelineEventsJsonlPath(targetDomain),
    findingsIndexJsonlPath(targetDomain),
    httpAuditJsonlPath(targetDomain),
    findingsJsonlPath(targetDomain),
    reportMarkdownPath(targetDomain),
  ];
  let latest = 0;
  for (const filePath of candidates) {
    try {
      const stat = fs.statSync(filePath);
      if (stat.mtimeMs > latest) latest = stat.mtimeMs;
    } catch {}
  }
  return latest;
}

function listRecentSessionDomainCandidates({ cutoffMs = null, limit = CROSS_SESSION_ANALYTICS_MAX_SESSIONS } = {}) {
  const domains = listSessionDomains()
    .map((targetDomain) => ({
      targetDomain,
      activityMs: sessionActivityMtimeMs(targetDomain),
    }))
    .filter((entry) => !cutoffMs || entry.activityMs >= cutoffMs)
    .sort((a, b) => b.activityMs - a.activityMs || a.targetDomain.localeCompare(b.targetDomain));
  const normalizedLimit = Number.isInteger(limit) && limit > 0 ? limit : CROSS_SESSION_ANALYTICS_MAX_SESSIONS;
  return {
    total_available: domains.length,
    limit: normalizedLimit,
    truncated: domains.length > normalizedLimit,
    domains: domains.slice(0, normalizedLimit).map((entry) => entry.targetDomain),
  };
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

function readPipelineAnalytics(args = {}, { env = process.env, validateAuthority = false } = {}) {
  const options = normalizeReadArgs(args);
  const cutoffMs = Date.now() - options.window_days * 24 * 60 * 60 * 1000;

  if (options.target_domain) {
    const analysis = analyzeSession(options.target_domain, {
      cutoffMs: null,
      limit: options.limit,
      env,
      validateAuthority,
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
      analytics_bounds: {
        session_scan_limit: 1,
        sessions_available: 1,
        sessions_considered: 1,
        sessions_truncated: false,
        telemetry_reads_reused: false,
        tool_events_loaded: analysis.tool_health.total_events,
        hunter_events_loaded: analysis.hunter_health.total_runs,
      },
    };
    if (options.include_events) {
      response.events = analysis.event_read.events.slice(-options.limit).map(compactEvent);
    }
    return JSON.stringify(response);
  }

  const candidates = listRecentSessionDomainCandidates({
    cutoffMs,
    limit: CROSS_SESSION_ANALYTICS_MAX_SESSIONS,
  });
  const telemetryCache = {
    toolRead: readToolTelemetryEvents({ env }),
    hunterRead: readAgentRunTelemetryEvents({
      agent_run_type: "hunter",
      env,
    }),
  };
  const analyses = candidates.domains
    .map((targetDomain) => analyzeSession(targetDomain, {
      cutoffMs,
      limit: options.limit,
      env,
      telemetryCache,
      validateAuthority: true,
    }))
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
    tool_health: buildToolHealth({ cutoffMs, limit: options.limit, env, readResult: telemetryCache.toolRead }),
    hunter_health: buildHunterHealth({ cutoffMs, limit: options.limit, env, readResult: telemetryCache.hunterRead }),
    analytics_bounds: {
      session_scan_limit: candidates.limit,
      sessions_available: candidates.total_available,
      sessions_considered: candidates.domains.length,
      sessions_truncated: candidates.truncated,
      telemetry_reads_reused: true,
      tool_events_loaded: telemetryCache.toolRead.events.length,
      hunter_events_loaded: telemetryCache.hunterRead.events.length,
    },
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
  CROSS_SESSION_ANALYTICS_MAX_SESSIONS,
  HANDOFF_ANALYTICS_MAX_FILES,
  WAVE_READINESS_MAX_ASSIGNMENT_FILES,
  PIPELINE_EVENT_TYPES,
  PIPELINE_EVENT_VERSION,
  buildBackfillEvents,
  listSessionDomains,
  normalizePipelineEvent,
  pipelineAnalyticsEnabled,
  readPipelineAnalytics,
  readPipelineEvents,
  readSessionArtifactSummary,
  // Re-exported from ./pipeline-events.js for backwards compatibility. Prefer
  // importing these from pipeline-events.js directly in new code.
  appendPipelineEventDirect,
  safeAppendPipelineEventDirect,
  safeAppendPipelineEventWithSessionLock,
  safeRecordHunterStoppedPipelineEvent,
};
