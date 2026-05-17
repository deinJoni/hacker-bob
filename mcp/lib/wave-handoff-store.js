"use strict";

const fs = require("fs");
const path = require("path");
const {
  assertNonEmptyString,
  compareAgentLabels,
  normalizeStringArray,
  parseWaveNumber,
  pushUnique,
} = require("./validation.js");
const {
  liveDeadEndsJsonlPath,
  sessionDir,
} = require("./paths.js");
const {
  readFileUtf8,
  readJsonFile,
} = require("./storage.js");
const {
  loadWaveAssignments,
} = require("./assignments.js");
const {
  readFindingsFromJsonl,
} = require("./finding-store.js");
const {
  readHandoffSigningKey,
} = require("./handoff-signing-key.js");
const {
  assignmentRequiresToken,
  attachHandoffOrigin,
  groupBlockedHarnessRuns,
  groupBlockedPrereqs,
  groupBypassAttempts,
  validateHandoffProvenance,
  validateWaveHandoffPayload,
} = require("./wave-handoff-contracts.js");

const WAVE_ARTIFACT_KEYS = Object.freeze([
  "dir",
  "wave",
  "assignmentsPath",
  "assignments",
  "assignmentByAgent",
  "handoffFiles",
  "handoffPathByAgent",
  "unexpectedAgents",
]);

function listWaveHandoffFiles(dir, wave) {
  const handoffPrefix = `handoff-${wave}-`;
  // Readiness intentionally indexes only structured handoff JSON. Markdown handoffs are for humans/debugging.
  return fs.existsSync(dir)
    ? fs.readdirSync(dir)
        .filter((name) => name.startsWith(handoffPrefix) && name.endsWith(".json"))
        .sort()
    : [];
}

function buildWaveHandoffFileIndex(dir, wave, assignmentByAgent) {
  const handoffFiles = listWaveHandoffFiles(dir, wave);
  const handoffPathByAgent = new Map();
  const unexpectedAgentSet = new Set();

  for (const fileName of handoffFiles) {
    const rawAgent = fileName.slice(`handoff-${wave}-`.length, -".json".length);
    if (!assignmentByAgent.has(rawAgent)) {
      unexpectedAgentSet.add(rawAgent);
      continue;
    }
    handoffPathByAgent.set(rawAgent, path.join(dir, fileName));
  }

  return {
    handoffFiles,
    handoffPathByAgent,
    unexpectedAgents: Array.from(unexpectedAgentSet).sort(compareAgentLabels),
  };
}

function loadWaveArtifacts(domain, waveNumber) {
  const assignmentsInfo = loadWaveAssignments(domain, waveNumber);
  const handoffInfo = buildWaveHandoffFileIndex(
    assignmentsInfo.dir,
    assignmentsInfo.wave,
    assignmentsInfo.assignmentByAgent,
  );

  return {
    ...assignmentsInfo,
    ...handoffInfo,
  };
}

function readSigningKeyForArtifacts(domain, artifacts) {
  return artifacts.assignments.some((assignment) => assignmentRequiresToken(assignment))
    ? readHandoffSigningKey(domain)
    : null;
}

function buildWaveReadiness(artifacts) {
  const receivedAgents = [];
  const missingAgents = [];

  for (const assignment of artifacts.assignments) {
    if (artifacts.handoffPathByAgent.has(assignment.agent)) {
      receivedAgents.push(assignment.agent);
    } else {
      missingAgents.push(assignment.agent);
    }
  }

  return {
    assignments_total: artifacts.assignments.length,
    handoffs_total: artifacts.handoffFiles.length,
    received_agents: receivedAgents,
    missing_agents: missingAgents,
    unexpected_agents: artifacts.unexpectedAgents,
    is_complete: missingAgents.length === 0,
  };
}

function buildSuspicionFlags({ smartContractCompletedSurfaceIds, bypassAttemptsForCompletedSurfaces, recordedFindingsBySurface }) {
  const flags = [];
  for (const surfaceId of smartContractCompletedSurfaceIds) {
    const findings = recordedFindingsBySurface.get(surfaceId) || [];
    const attempts = bypassAttemptsForCompletedSurfaces.get(surfaceId) || [];
    if (findings.length > 0) continue;
    if (attempts.length === 0) continue;
    const hasSubstantiveOutcome = attempts.some((attempt) => (
      attempt.outcome === "partial_evidence" || attempt.outcome === "finding_recorded"
    ));
    if (hasSubstantiveOutcome) continue;
    flags.push({
      flag: "sc_complete_with_zero_evidence",
      surface_id: surfaceId,
      reason: "smart_contract surface marked complete with no recorded finding and no bypass_attempts entry produced partial_evidence or finding_recorded; review for low-effort attestation",
    });
  }
  return flags;
}

function mergeWaveHandoffsInternal(domain, waveNumber) {
  const artifacts = loadWaveArtifacts(domain, waveNumber);
  const readiness = buildWaveReadiness(artifacts);

  const receivedAgents = [];
  const invalidAgents = [];
  const invalidHandoffs = [];
  const completedSurfaceIds = [];
  const partialSurfaceIds = [];
  const missingSurfaceIds = [];
  const deadEnds = [];
  const wafBlockedEndpoints = [];
  const leadSurfaceIds = [];
  const blockedHarnessRuns = [];
  const blockedPrereqs = [];
  const bypassAttempts = [];
  const provenance = {
    verified_agents: [],
    legacy_unverified_agents: [],
  };

  const deadEndSet = new Set();
  const wafSet = new Set();
  const leadSet = new Set();

  const allFindings = readFindingsFromJsonl(domain);
  const findingsByRun = new Map();
  const recordedFindingsBySurface = new Map();
  for (const finding of allFindings) {
    if (finding.wave === artifacts.wave) {
      const runKey = `${finding.wave}\u0000${finding.agent}\u0000${finding.surface_id}`;
      if (!findingsByRun.has(runKey)) findingsByRun.set(runKey, []);
      findingsByRun.get(runKey).push(finding);
      if (!recordedFindingsBySurface.has(finding.surface_id)) recordedFindingsBySurface.set(finding.surface_id, []);
      recordedFindingsBySurface.get(finding.surface_id).push(finding);
    }
  }

  const smartContractCompletedSurfaceIds = [];
  const bypassAttemptsForCompletedSurfaces = new Map();
  const signingKey = readSigningKeyForArtifacts(domain, artifacts);

  for (const assignment of artifacts.assignments) {
    const filePath = artifacts.handoffPathByAgent.get(assignment.agent);
    if (!filePath) {
      missingSurfaceIds.push(assignment.surface_id);
      continue;
    }

    try {
      const handoffJson = readJsonFile(filePath);
      const runKey = `${artifacts.wave}\u0000${assignment.agent}\u0000${assignment.surface_id}`;
      const findingsForRun = findingsByRun.get(runKey) || [];
      const effectiveSurfaceType = assignment.surface_type || null;
      const payload = validateWaveHandoffPayload(handoffJson, {
        targetDomain: domain,
        wave: artifacts.wave,
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
        effectiveSurfaceType,
        findingsForRun,
      });
      const provenanceStatus = validateHandoffProvenance(handoffJson, assignment, { signingKey });

      receivedAgents.push(assignment.agent);
      if (provenanceStatus === "verified") {
        provenance.verified_agents.push(assignment.agent);
      } else {
        provenance.legacy_unverified_agents.push(assignment.agent);
      }
      if (payload.surface_status === "complete") {
        completedSurfaceIds.push(assignment.surface_id);
        if (effectiveSurfaceType === "smart_contract") {
          smartContractCompletedSurfaceIds.push(assignment.surface_id);
          bypassAttemptsForCompletedSurfaces.set(assignment.surface_id, payload.bypass_attempts || []);
        }
      } else {
        partialSurfaceIds.push(assignment.surface_id);
      }
      pushUnique(deadEnds, deadEndSet, payload.dead_ends);
      pushUnique(wafBlockedEndpoints, wafSet, payload.waf_blocked_endpoints);
      pushUnique(leadSurfaceIds, leadSet, payload.lead_surface_ids);
      blockedHarnessRuns.push(...attachHandoffOrigin(payload.blocked_harness_runs || [], {
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
      }));
      blockedPrereqs.push(...attachHandoffOrigin(payload.blocked_prereqs || [], {
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
      }));
      bypassAttempts.push(...attachHandoffOrigin(payload.bypass_attempts || [], {
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
      }));
    } catch (error) {
      invalidAgents.push(assignment.agent);
      invalidHandoffs.push({
        agent: assignment.agent,
        surface_id: assignment.surface_id,
        error: error.message || String(error),
      });
    }
  }

  const suspicionFlags = buildSuspicionFlags({
    smartContractCompletedSurfaceIds,
    bypassAttemptsForCompletedSurfaces,
    recordedFindingsBySurface,
  });

  for (const assignment of artifacts.assignments) {
    const logPath = liveDeadEndsJsonlPath(domain, artifacts.wave, assignment.agent);
    if (!fs.existsSync(logPath)) continue;
    let raw;
    try {
      raw = readFileUtf8(logPath, { label: path.basename(logPath) });
    } catch {
      continue;
    }
    const lines = raw.trim().split("\n");
    for (const line of lines) {
      if (!line) continue;
      try {
        const record = JSON.parse(line);
        if (record.surface_id !== assignment.surface_id) continue;
        pushUnique(deadEnds, deadEndSet, normalizeStringArray(record.dead_ends, "live_dead_ends"));
        pushUnique(wafBlockedEndpoints, wafSet, normalizeStringArray(record.waf_blocked_endpoints, "live_waf_blocked"));
      } catch {
        // Skip malformed line, keep processing remaining records.
      }
    }
  }

  return {
    artifacts,
    readiness,
    merge: {
      received_agents: receivedAgents,
      invalid_agents: invalidAgents,
      invalid_handoffs: invalidHandoffs,
      unexpected_agents: readiness.unexpected_agents,
      completed_surface_ids: completedSurfaceIds,
      partial_surface_ids: partialSurfaceIds,
      missing_surface_ids: missingSurfaceIds,
      dead_ends: deadEnds,
      waf_blocked_endpoints: wafBlockedEndpoints,
      lead_surface_ids: leadSurfaceIds,
      blocked_harness_runs: blockedHarnessRuns,
      blocked_harness_runs_grouped: groupBlockedHarnessRuns(blockedHarnessRuns),
      blocked_prereqs: blockedPrereqs,
      blocked_prereqs_grouped: groupBlockedPrereqs(blockedPrereqs),
      bypass_attempts: bypassAttempts,
      bypass_attempts_grouped: groupBypassAttempts(bypassAttempts),
      suspicion_flags: suspicionFlags,
      provenance,
    },
  };
}

function mergeWaveHandoffs(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  const { readiness, merge } = mergeWaveHandoffsInternal(domain, waveNumber);

  return JSON.stringify({
    assignments_total: readiness.assignments_total,
    handoffs_total: readiness.handoffs_total,
    received_agents: merge.received_agents,
    invalid_agents: merge.invalid_agents,
    invalid_handoffs: merge.invalid_handoffs,
    unexpected_agents: merge.unexpected_agents,
    completed_surface_ids: merge.completed_surface_ids,
    partial_surface_ids: merge.partial_surface_ids,
    missing_surface_ids: merge.missing_surface_ids,
    dead_ends: merge.dead_ends,
    waf_blocked_endpoints: merge.waf_blocked_endpoints,
    lead_surface_ids: merge.lead_surface_ids,
    blocked_harness_runs: merge.blocked_harness_runs,
    blocked_harness_runs_grouped: merge.blocked_harness_runs_grouped,
    blocked_prereqs: merge.blocked_prereqs,
    blocked_prereqs_grouped: merge.blocked_prereqs_grouped,
    bypass_attempts: merge.bypass_attempts,
    bypass_attempts_grouped: merge.bypass_attempts_grouped,
    suspicion_flags: merge.suspicion_flags,
    provenance: merge.provenance,
  });
}

function listWaveAssignmentNumbers(domain) {
  const dir = sessionDir(domain);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .map((fileName) => {
      const match = fileName.match(/^wave-([1-9][0-9]*)-assignments\.json$/);
      return match ? Number(match[1]) : null;
    })
    .filter((waveNumber) => Number.isInteger(waveNumber))
    .sort((a, b) => a - b);
}

function buildWaveHandoffsDocument(domain, waveNumbers) {
  const handoffs = [];
  const missingHandoffs = [];
  const invalidHandoffs = [];
  const unexpectedHandoffs = [];

  const allFindings = readFindingsFromJsonl(domain);
  const findingsByRun = new Map();
  for (const finding of allFindings) {
    const runKey = `${finding.wave} ${finding.agent} ${finding.surface_id}`;
    if (!findingsByRun.has(runKey)) findingsByRun.set(runKey, []);
    findingsByRun.get(runKey).push(finding);
  }

  for (const waveNumber of waveNumbers) {
    const artifacts = loadWaveArtifacts(domain, waveNumber);
    let signingKey = null;
    let signingKeyError = null;
    try {
      signingKey = readSigningKeyForArtifacts(domain, artifacts);
    } catch (error) {
      signingKeyError = error;
    }
    for (const agent of artifacts.unexpectedAgents) {
      unexpectedHandoffs.push({ wave: artifacts.wave, agent });
    }

    for (const assignment of artifacts.assignments) {
      const filePath = artifacts.handoffPathByAgent.get(assignment.agent);
      if (!filePath) {
        missingHandoffs.push({
          wave: artifacts.wave,
          agent: assignment.agent,
          surface_id: assignment.surface_id,
        });
        continue;
      }

      try {
        if (assignmentRequiresToken(assignment) && signingKeyError) {
          throw signingKeyError;
        }
        const handoffJson = readJsonFile(filePath);
        const runKey = `${artifacts.wave} ${assignment.agent} ${assignment.surface_id}`;
        const findingsForRun = findingsByRun.get(runKey) || [];
        const effectiveSurfaceType = assignment.surface_type || null;
        const payload = validateWaveHandoffPayload(handoffJson, {
          targetDomain: domain,
          wave: artifacts.wave,
          agent: assignment.agent,
          surfaceId: assignment.surface_id,
          effectiveSurfaceType,
          findingsForRun,
        });
        const provenance = validateHandoffProvenance(handoffJson, assignment, { signingKey });
        const handoff = {
          wave: artifacts.wave,
          agent: assignment.agent,
          surface_id: assignment.surface_id,
          surface_type: payload.surface_type,
          surface_status: payload.surface_status,
          provenance,
          summary: payload.summary,
          chain_notes: payload.chain_notes,
          blocked_harness_runs: payload.blocked_harness_runs,
          blocked_prereqs: payload.blocked_prereqs,
          bypass_attempts: payload.bypass_attempts,
          dead_ends: payload.dead_ends,
          waf_blocked_endpoints: payload.waf_blocked_endpoints,
          lead_surface_ids: payload.lead_surface_ids,
        };
        if (payload.surface_lead_ids.length > 0) {
          handoff.surface_lead_ids = payload.surface_lead_ids;
        }
        handoffs.push(handoff);
      } catch (error) {
        invalidHandoffs.push({
          wave: artifacts.wave,
          agent: assignment.agent,
          surface_id: assignment.surface_id,
          error: error.message || String(error),
        });
      }
    }
  }

  return {
    version: 1,
    target_domain: domain,
    wave_numbers: waveNumbers,
    handoffs,
    missing_handoffs: missingHandoffs,
    invalid_handoffs: invalidHandoffs,
    unexpected_handoffs: unexpectedHandoffs,
  };
}

function readWaveHandoffs(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumbers = args.wave_number == null
    ? listWaveAssignmentNumbers(domain)
    : [parseWaveNumber(args.wave_number)];

  return JSON.stringify(buildWaveHandoffsDocument(domain, waveNumbers));
}

function waveHandoffStatus(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  return JSON.stringify(buildWaveReadiness(loadWaveArtifacts(domain, waveNumber)));
}

module.exports = {
  WAVE_ARTIFACT_KEYS,
  buildSuspicionFlags,
  buildWaveHandoffFileIndex,
  buildWaveHandoffsDocument,
  buildWaveReadiness,
  listWaveAssignmentNumbers,
  listWaveHandoffFiles,
  loadWaveArtifacts,
  mergeWaveHandoffs,
  mergeWaveHandoffsInternal,
  readSigningKeyForArtifacts,
  readWaveHandoffs,
  waveHandoffStatus,
};
