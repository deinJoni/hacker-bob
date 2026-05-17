"use strict";

const fs = require("fs");
const {
  GRADE_HOLD_MIN_SCORE,
  GRADE_SUBMIT_MIN_SCORE,
  GRADE_VERDICT_VALUES,
} = require("./constants.js");
const {
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  normalizeOptionalText,
  parseFindingId,
} = require("./validation.js");
const {
  gradeArtifactPaths,
  verificationRoundPaths,
} = require("./paths.js");
const {
  loadJsonDocumentStrict,
  withSessionLock,
  writeFileAtomic,
  writeMarkdownMirror,
} = require("./storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  safeAppendPipelineEventDirect,
} = require("./pipeline-events.js");
const {
  readFindingIdSet,
} = require("./finding-store.js");
const {
  normalizeVerificationRoundDocument,
} = require("./verification-round-store.js");

function verificationLib() {
  return require("./verification.js");
}

function normalizeGradeFinding(result, findingIdSet) {
  if (result == null || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("findings entries must be objects");
  }

  const findingId = parseFindingId(result.finding_id);
  if (!findingIdSet.has(findingId)) {
    throw new Error(`Unknown finding_id: ${findingId}`);
  }

  const normalized = {
    finding_id: findingId,
    impact: assertInteger(result.impact, "impact", { min: 0, max: 30 }),
    proof_quality: assertInteger(result.proof_quality, "proof_quality", { min: 0, max: 25 }),
    severity_accuracy: assertInteger(result.severity_accuracy, "severity_accuracy", { min: 0, max: 15 }),
    chain_potential: assertInteger(result.chain_potential, "chain_potential", { min: 0, max: 15 }),
    report_quality: assertInteger(result.report_quality, "report_quality", { min: 0, max: 15 }),
    total_score: assertInteger(result.total_score, "total_score", { min: 0 }),
    feedback: normalizeOptionalText(result.feedback, "feedback"),
  };

  const expectedTotal = normalized.impact
    + normalized.proof_quality
    + normalized.severity_accuracy
    + normalized.chain_potential
    + normalized.report_quality;
  if (normalized.total_score !== expectedTotal) {
    throw new Error(`finding ${findingId} total_score must equal the sum of rubric scores`);
  }

  return normalized;
}

function normalizeGradeVerdictDocument(document, { expectedDomain = null, findingIdSet = null } = {}) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("grade verdict document must be an object");
  }

  const normalized = {
    version: assertInteger(document.version, "version", { min: 1, max: 1 }),
    target_domain: assertNonEmptyString(document.target_domain, "target_domain"),
    verdict: assertEnumValue(document.verdict, GRADE_VERDICT_VALUES, "verdict"),
    total_score: assertInteger(document.total_score, "total_score", { min: 0 }),
    findings: [],
    feedback: normalizeOptionalText(document.feedback, "feedback"),
  };

  if (!Array.isArray(document.findings)) {
    throw new Error("findings must be an array");
  }

  const seenIds = new Set();
  for (const finding of document.findings) {
    const normalizedFinding = normalizeGradeFinding(
      finding,
      findingIdSet ?? new Set([parseFindingId(finding.finding_id)]),
    );
    if (seenIds.has(normalizedFinding.finding_id)) {
      throw new Error(`Duplicate finding_id in findings: ${normalizedFinding.finding_id}`);
    }
    seenIds.add(normalizedFinding.finding_id);
    normalized.findings.push(normalizedFinding);
  }

  if (expectedDomain != null && normalized.target_domain !== expectedDomain) {
    throw new Error(`grade verdict target_domain mismatch: expected ${expectedDomain}`);
  }

  enforceGradeVerdictConsistency(normalized, {
    finalReportableSeveritySet: expectedDomain == null ? null : requireFinalReportableSeveritySet(expectedDomain, findingIdSet),
  });

  return normalized;
}

function isMediumOrHigher(severity) {
  return ["medium", "high", "critical"].includes(severity);
}

function requireFinalReportableSeveritySet(domain, findingIdSet) {
  const paths = verificationRoundPaths(domain, "final");
  let normalized;
  try {
    const document = loadJsonDocumentStrict(paths.json, "final verification round JSON");
    let effectiveFindingIdSet = findingIdSet;
    let v2Current = null;
    if (document && document.version === 2) {
      v2Current = verificationLib().requireV2State(domain);
      effectiveFindingIdSet = new Set(v2Current.snapshot.finding_ids);
    }
    normalized = normalizeVerificationRoundDocument(document, {
      expectedDomain: domain,
      expectedRound: "final",
      findingIdSet: effectiveFindingIdSet,
    });
    if (normalized.version === 2) {
      verificationLib().assertCurrentV2RoundDocument(domain, normalized, {
        expectedRound: "final",
        state: v2Current.state,
        snapshot: v2Current.snapshot,
      });
    }
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Final verification must exist and be valid before grading: ${error.message || String(error)}`,
    );
  }
  return new Set(
    normalized.results
      .filter((result) => result.reportable && isMediumOrHigher(result.severity))
      .map((result) => result.finding_id),
  );
}

function requireEvidencePacksForGrading(domain, findingIdSet) {
  const {
    requireValidEvidencePacksForFinalReportableFindings,
  } = require("./evidence.js");
  return requireValidEvidencePacksForFinalReportableFindings(domain, { findingIdSet });
}

function enforceGradeVerdictConsistency(document, { finalReportableSeveritySet: reportableSet = null } = {}) {
  const maxFindingScore = document.findings.reduce(
    (maxScore, finding) => Math.max(maxScore, finding.total_score),
    0,
  );
  if (document.total_score !== maxFindingScore) {
    throw new Error(`grade total_score must equal the maximum per-finding score (${maxFindingScore})`);
  }

  const hasReportableMedium = reportableSet == null
    ? document.findings.length > 0
    : document.findings.some((finding) => reportableSet.has(finding.finding_id));

  let expectedVerdict;
  if (!hasReportableMedium || document.total_score < GRADE_HOLD_MIN_SCORE) {
    expectedVerdict = "SKIP";
  } else if (document.total_score < GRADE_SUBMIT_MIN_SCORE) {
    expectedVerdict = "HOLD";
  } else {
    expectedVerdict = "SUBMIT";
  }

  if (document.verdict !== expectedVerdict) {
    throw new Error(
      `grade verdict ${document.verdict} does not match total_score ${document.total_score} and reportable findings; expected ${expectedVerdict}`,
    );
  }
}

function renderGradeVerdictMarkdown(document) {
  const lines = [
    "# Grade Verdict",
    `- Target: ${document.target_domain}`,
    `- Verdict: ${document.verdict}`,
    `- Total Score: ${document.total_score}`,
    `- Feedback: ${document.feedback || "N/A"}`,
    "",
  ];

  if (document.findings.length === 0) {
    lines.push("No graded findings.");
    lines.push("");
    return `${lines.join("\n")}\n`;
  }

  for (const finding of document.findings) {
    lines.push(`## ${finding.finding_id}`);
    lines.push(`- Impact: ${finding.impact}`);
    lines.push(`- Proof Quality: ${finding.proof_quality}`);
    lines.push(`- Severity Accuracy: ${finding.severity_accuracy}`);
    lines.push(`- Chain Potential: ${finding.chain_potential}`);
    lines.push(`- Report Quality: ${finding.report_quality}`);
    lines.push(`- Total Score: ${finding.total_score}`);
    lines.push(`- Feedback: ${finding.feedback || "N/A"}`);
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

function writeGradeVerdict(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  return withSessionLock(domain, () => {
  const verdict = assertEnumValue(args.verdict, GRADE_VERDICT_VALUES, "verdict");
  const totalScore = assertInteger(args.total_score, "total_score", { min: 0 });
  const feedback = normalizeOptionalText(args.feedback, "feedback");
  if (!Array.isArray(args.findings)) {
    throw new Error("findings must be an array");
  }

  const findingIdSet = readFindingIdSet(domain);
  const seenIds = new Set();
  const findings = args.findings.map((finding) => {
    const normalizedFinding = normalizeGradeFinding(finding, findingIdSet);
    if (seenIds.has(normalizedFinding.finding_id)) {
      throw new Error(`Duplicate finding_id in findings: ${normalizedFinding.finding_id}`);
    }
    seenIds.add(normalizedFinding.finding_id);
    return normalizedFinding;
  });

  const document = {
    version: 1,
    target_domain: domain,
    verdict,
    total_score: totalScore,
    findings,
    feedback,
  };
  enforceGradeVerdictConsistency(document, {
    finalReportableSeveritySet: requireFinalReportableSeveritySet(domain, findingIdSet),
  });
  verificationLib().requireVerificationCompleteForGrade(domain, { findingIdSet });

  const paths = gradeArtifactPaths(domain);
  writeFileAtomic(paths.json, JSON.stringify(document, null, 2) + "\n");

  const response = {
    verdict,
    findings_count: findings.length,
    written_json: paths.json,
  };
  writeMarkdownMirror(paths.markdown, renderGradeVerdictMarkdown(document), response);
  safeAppendPipelineEventDirect(domain, "grade_written", {
    phase: "GRADE",
    status: verdict,
    source: "bounty_write_grade_verdict",
    counts: {
      findings: findings.length,
      total_score: totalScore,
    },
  });
  return JSON.stringify(response);
  });
}

function readGradeVerdict(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const paths = gradeArtifactPaths(domain);
  const document = loadJsonDocumentStrict(paths.json, "grade verdict JSON");
  const findingIdSet = readFindingIdSet(domain);
  const normalized = normalizeGradeVerdictDocument(document, {
    expectedDomain: domain,
    findingIdSet,
  });
  requireEvidencePacksForGrading(domain, findingIdSet);
  return JSON.stringify(normalized);
}

function fileMtimeIso(filePath) {
  try {
    return new Date(fs.statSync(filePath).mtimeMs).toISOString();
  } catch {
    return null;
  }
}

function summarizeGradeVerdictArtifact(targetDomain) {
  const domain = assertNonEmptyString(targetDomain, "target_domain");
  const paths = gradeArtifactPaths(domain);
  const summary = {
    exists: fs.existsSync(paths.json),
    valid: false,
    legacy_summary: false,
    verdict: null,
    total_score: null,
    findings_count: 0,
    error: null,
    mtime: fileMtimeIso(paths.json),
  };
  if (!summary.exists) return summary;

  let document = null;
  try {
    document = loadJsonDocumentStrict(paths.json, "grade verdict JSON");
    if (document && typeof document === "object" && !Array.isArray(document)) {
      summary.verdict = typeof document.verdict === "string" ? document.verdict.slice(0, 40) : null;
      summary.total_score = Number.isFinite(document.total_score) ? Math.trunc(document.total_score) : null;
      summary.findings_count = Array.isArray(document.findings) ? document.findings.length : 0;
    }
    const normalized = JSON.parse(readGradeVerdict({ target_domain: domain }));
    summary.valid = true;
    summary.legacy_summary = false;
    summary.verdict = normalized.verdict;
    summary.total_score = normalized.total_score;
    summary.findings_count = normalized.findings.length;
  } catch (error) {
    if (isLegacyGradeSummaryDocument(document, domain)) {
      summary.valid = true;
      summary.legacy_summary = true;
      summary.error = null;
    } else {
      summary.valid = false;
      summary.error = error.message || String(error);
    }
  }
  return summary;
}

function isLegacyGradeSummaryDocument(document, domain) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) return false;
  if (document.target_domain !== domain) return false;
  if (!GRADE_VERDICT_VALUES.includes(document.verdict)) return false;
  if (!Number.isInteger(document.total_score) || document.total_score < 0) return false;
  if (!Array.isArray(document.findings)) return false;
  return document.findings.every((finding) => {
    if (finding == null || typeof finding !== "object" || Array.isArray(finding)) return false;
    try {
      parseFindingId(finding.finding_id);
    } catch {
      return false;
    }
    if (!Number.isInteger(finding.total_score) || finding.total_score < 0) return false;
    return (
      finding.impact == null &&
      finding.proof_quality == null &&
      finding.severity_accuracy == null &&
      finding.chain_potential == null &&
      finding.report_quality == null
    );
  });
}

module.exports = {
  enforceGradeVerdictConsistency,
  normalizeGradeFinding,
  normalizeGradeVerdictDocument,
  readGradeVerdict,
  renderGradeVerdictMarkdown,
  requireFinalReportableSeveritySet,
  summarizeGradeVerdictArtifact,
  writeGradeVerdict,
};
