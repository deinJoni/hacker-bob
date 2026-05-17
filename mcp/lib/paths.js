"use strict";

const os = require("os");
const path = require("path");
const {
  SESSION_LOCK_NAME,
  STATIC_ARTIFACT_ID_RE,
  VERIFICATION_ROUND_FILE_MAP,
  VERIFICATION_ROUND_VALUES,
} = require("./constants.js");
const {
  assertEnumValue,
  assertNonEmptyString,
} = require("./validation.js");

function assertSafeDomain(domain) {
  const trimmed = assertNonEmptyString(domain, "target_domain");
  if (/[\/\\]/.test(trimmed) || /(?:^|\.)\.\.(?:\.|$)/.test(trimmed)) {
    throw new Error(`target_domain contains invalid path characters: ${trimmed}`);
  }
  return trimmed;
}

function sessionDir(domain) {
  const safe = assertSafeDomain(domain);
  return path.join(sessionsRoot(), safe);
}

function sessionsRoot() {
  return path.join(os.homedir(), "bounty-agent-sessions");
}

function statePath(domain) {
  return path.join(sessionDir(domain), "state.json");
}

function attackSurfacePath(domain) {
  return path.join(sessionDir(domain), "attack_surface.json");
}

function surfaceLeadsPath(domain) {
  return path.join(sessionDir(domain), "surface-leads.json");
}

function surfaceRoutesPath(domain) {
  return path.join(sessionDir(domain), "surface-routes.json");
}

function sessionLockPath(domain) {
  return path.join(sessionDir(domain), SESSION_LOCK_NAME);
}

function waveAssignmentsPath(domain, waveNumber) {
  return path.join(sessionDir(domain), `wave-${waveNumber}-assignments.json`);
}

function liveDeadEndsJsonlPath(domain, wave, agent) {
  return path.join(sessionDir(domain), `live-dead-ends-${wave}-${agent}.jsonl`);
}

function handoffSigningKeyPath(domain) {
  return path.join(sessionDir(domain), ".handoff-signing-key.json");
}

function scopeWarningsPath(domain) {
  return path.join(sessionDir(domain), "scope-warnings.log");
}

function findingsJsonlPath(domain) {
  return path.join(sessionDir(domain), "findings.jsonl");
}

function findingsMarkdownPath(domain) {
  return path.join(sessionDir(domain), "findings.md");
}

function coverageJsonlPath(domain) {
  return path.join(sessionDir(domain), "coverage.jsonl");
}

function techniqueAttemptsJsonlPath(domain) {
  return path.join(sessionDir(domain), "technique-attempts.jsonl");
}

function techniquePackReadsJsonlPath(domain) {
  return path.join(sessionDir(domain), "technique-pack-reads.jsonl");
}

function chainAttemptsJsonlPath(domain) {
  return path.join(sessionDir(domain), "chain-attempts.jsonl");
}

function pipelineEventsJsonlPath(domain) {
  return path.join(sessionDir(domain), "pipeline-events.jsonl");
}

function httpAuditJsonlPath(domain) {
  return path.join(sessionDir(domain), "http-audit.jsonl");
}

function trafficJsonlPath(domain) {
  return path.join(sessionDir(domain), "traffic.jsonl");
}

function publicIntelPath(domain) {
  return path.join(sessionDir(domain), "public-intel.json");
}

function bobSpecPath(domain) {
  return path.join(sessionDir(domain), "bob-spec.json");
}

function assertStaticArtifactId(artifactId) {
  const normalized = assertNonEmptyString(artifactId, "artifact_id");
  if (!STATIC_ARTIFACT_ID_RE.test(normalized)) {
    throw new Error("artifact_id must match SA-N");
  }
  return normalized;
}

function staticArtifactImportDir(domain) {
  return path.join(sessionDir(domain), "static-imports");
}

function staticArtifactPath(domain, artifactId) {
  return path.join(staticArtifactImportDir(domain), `${assertStaticArtifactId(artifactId)}.txt`);
}

function staticArtifactsJsonlPath(domain) {
  return path.join(sessionDir(domain), "static-artifacts.jsonl");
}

function schemaContractsJsonlPath(domain) {
  return path.join(sessionDir(domain), "schema-contracts.jsonl");
}

function docDeltaResultsPath(domain) {
  return path.join(sessionDir(domain), "doc-delta-results.json");
}

function authDifferentialResultsPath(domain) {
  return path.join(sessionDir(domain), "auth-differential-results.json");
}

function findingsIndexJsonlPath(domain) {
  return path.join(sessionDir(domain), "findings-index.jsonl");
}

function surfaceGraphJsonlPath(domain) {
  return path.join(sessionDir(domain), "surface-graph.jsonl");
}

function chainTreeJsonlPath(domain) {
  return path.join(sessionDir(domain), "chain-tree.jsonl");
}

function auditReportsJsonlPath(domain) {
  return path.join(sessionDir(domain), "audit-reports.jsonl");
}

function invariantRunsJsonlPath(domain) {
  return path.join(sessionDir(domain), "invariant-runs.jsonl");
}

function symbolSurfaceIndexPath(domain) {
  return path.join(sessionDir(domain), "symbol-surface-index.json");
}

function staticScanResultsJsonlPath(domain) {
  return path.join(sessionDir(domain), "static-scan-results.jsonl");
}

function verificationRoundPaths(domain, round) {
  const normalizedRound = assertEnumValue(round, VERIFICATION_ROUND_VALUES, "round");
  const fileNames = VERIFICATION_ROUND_FILE_MAP[normalizedRound];
  const dir = sessionDir(domain);
  return {
    round: normalizedRound,
    json: path.join(dir, fileNames.json),
    markdown: path.join(dir, fileNames.markdown),
  };
}

function gradeArtifactPaths(domain) {
  const dir = sessionDir(domain);
  return {
    json: path.join(dir, "grade.json"),
    markdown: path.join(dir, "grade.md"),
  };
}

function evidencePackPaths(domain) {
  const dir = sessionDir(domain);
  return {
    json: path.join(dir, "evidence-packs.json"),
    markdown: path.join(dir, "evidence-packs.md"),
  };
}

function verificationSnapshotPath(domain) {
  return path.join(sessionDir(domain), "verification-input-snapshot.json");
}

function verificationAdjudicationPath(domain) {
  return path.join(sessionDir(domain), "verification-adjudication.json");
}

function verificationManifestPath(domain) {
  return path.join(sessionDir(domain), "verification-manifest.json");
}

function verificationAttemptsDir(domain) {
  return path.join(sessionDir(domain), "verification-attempts");
}

function verificationReplayLeaseDir(domain) {
  return path.join(sessionDir(domain), "verification-replay-leases");
}

function reportMarkdownPath(domain) {
  return path.join(sessionDir(domain), "report.md");
}

module.exports = {
  assertSafeDomain,
  assertStaticArtifactId,
  attackSurfacePath,
  bobSpecPath,
  chainAttemptsJsonlPath,
  coverageJsonlPath,
  evidencePackPaths,
  findingsJsonlPath,
  findingsMarkdownPath,
  gradeArtifactPaths,
  httpAuditJsonlPath,
  liveDeadEndsJsonlPath,
  pipelineEventsJsonlPath,
  publicIntelPath,
  reportMarkdownPath,
  scopeWarningsPath,
  sessionDir,
  sessionLockPath,
  sessionsRoot,
  statePath,
  surfaceLeadsPath,
  surfaceRoutesPath,
  techniqueAttemptsJsonlPath,
  techniquePackReadsJsonlPath,
  handoffSigningKeyPath,
  auditReportsJsonlPath,
  authDifferentialResultsPath,
  chainTreeJsonlPath,
  docDeltaResultsPath,
  findingsIndexJsonlPath,
  invariantRunsJsonlPath,
  schemaContractsJsonlPath,
  surfaceGraphJsonlPath,
  symbolSurfaceIndexPath,
  staticArtifactImportDir,
  staticArtifactPath,
  staticArtifactsJsonlPath,
  staticScanResultsJsonlPath,
  trafficJsonlPath,
  verificationAdjudicationPath,
  verificationAttemptsDir,
  verificationManifestPath,
  verificationReplayLeaseDir,
  verificationRoundPaths,
  verificationSnapshotPath,
  waveAssignmentsPath,
};
