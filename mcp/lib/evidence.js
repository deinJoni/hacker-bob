"use strict";

const fs = require("fs");
const {
  assertInteger,
  assertNonEmptyString,
  assertRequiredText,
  normalizeOptionalText,
  parseFindingId,
} = require("./validation.js");
const {
  evidencePackPaths,
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
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");
const {
  readFindingIdSet: readCanonicalFindingIdSet,
} = require("./finding-store.js");
const {
  normalizeVerificationRoundDocument,
} = require("./verification-round-store.js");

const EVIDENCE_PACKS_VERSION = 1;
const MAX_SAMPLE_COUNT = 1000;
const MAX_REPRESENTATIVE_SAMPLES = 10;
const MAX_SENSITIVE_CLUSTERS = 20;
const MAX_TEXT_CHARS = 4000;
const MAX_REPLAY_SUMMARY_CHARS = 2000;
const MAX_REDACTION_NOTES_CHARS = 1000;
const MAX_JSON_VALUE_CHARS = 8000;

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function assertMaxChars(text, fieldName, maxChars) {
  if (text.length > maxChars) {
    throw new Error(`${fieldName} must be at most ${maxChars} characters`);
  }
  return text;
}

function cloneJsonValue(value, fieldName) {
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch (error) {
    throw new Error(`${fieldName} must be JSON-serializable`);
  }
  if (serialized == null) {
    throw new Error(`${fieldName} must be JSON-serializable`);
  }
  if (serialized.length > MAX_JSON_VALUE_CHARS) {
    throw new Error(`${fieldName} is too large; keep evidence samples bounded`);
  }
  return JSON.parse(serialized);
}

function normalizeAggregateCounts(value) {
  if (!isPlainObject(value)) {
    throw new Error("aggregate_counts must be an object");
  }
  validateNoSensitiveMaterial(value, "aggregate_counts");
  const normalized = {};
  for (const [key, count] of Object.entries(value)) {
    const safeKey = assertNonEmptyString(key, "aggregate_counts key");
    if (!Number.isInteger(count) || count < 0) {
      throw new Error(`aggregate_counts.${safeKey} must be a non-negative integer`);
    }
    normalized[safeKey] = count;
  }
  return normalized;
}

function normalizeRepresentativeSamples(value) {
  if (!Array.isArray(value)) {
    throw new Error("representative_samples must be an array");
  }
  if (value.length > MAX_REPRESENTATIVE_SAMPLES) {
    throw new Error(`representative_samples must contain at most ${MAX_REPRESENTATIVE_SAMPLES} items`);
  }
  return value.map((sample, index) => {
    if (!isPlainObject(sample)) {
      throw new Error(`representative_samples[${index}] must be an object`);
    }
    validateNoSensitiveMaterial(sample, `representative_samples[${index}]`);
    return cloneJsonValue(sample, `representative_samples[${index}]`);
  });
}

function normalizeSensitiveClusters(value) {
  if (!Array.isArray(value)) {
    throw new Error("sensitive_clusters must be an array");
  }
  if (value.length > MAX_SENSITIVE_CLUSTERS) {
    throw new Error(`sensitive_clusters must contain at most ${MAX_SENSITIVE_CLUSTERS} items`);
  }
  return value.map((cluster, index) => {
    if (typeof cluster !== "string" && !isPlainObject(cluster)) {
      throw new Error(`sensitive_clusters[${index}] must be a string or object`);
    }
    validateNoSensitiveMaterial(cluster, `sensitive_clusters[${index}]`);
    return cloneJsonValue(cluster, `sensitive_clusters[${index}]`);
  });
}

function pipelineEventsLib() {
  return require("./pipeline-events.js");
}

function verificationLib() {
  return require("./verification.js");
}

function readFindingIdSet(domain) {
  return readCanonicalFindingIdSet(domain);
}

function loadFinalVerification(domain, findingIdSet, action = "evidence validation") {
  const paths = verificationRoundPaths(domain, "final");
  let document;
  try {
    document = loadJsonDocumentStrict(paths.json, "final verification round JSON");
    let effectiveFindingIdSet = findingIdSet;
    let v2Current = null;
    if (document && document.version === 2) {
      v2Current = verificationLib().requireV2State(domain);
      effectiveFindingIdSet = new Set(v2Current.snapshot.finding_ids);
    }
    const normalized = normalizeVerificationRoundDocument(document, {
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
    return normalized;
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Final verification must exist and be valid before ${action}: ${error.message || String(error)}`,
    );
  }
}

function finalReportableIds(document) {
  return document.results
    .filter((result) => result.reportable === true)
    .map((result) => result.finding_id);
}

function normalizeEvidencePack(pack, { findingIdSet, finalReportableIdSet }) {
  if (!isPlainObject(pack)) {
    throw new Error("packs entries must be objects");
  }
  const findingId = parseFindingId(pack.finding_id);
  if (!findingIdSet.has(findingId)) {
    throw new Error(`Unknown finding_id: ${findingId}`);
  }
  if (!finalReportableIdSet.has(findingId)) {
    throw new Error(`Evidence pack references non-reportable final finding_id: ${findingId}`);
  }

  const sampleType = assertMaxChars(assertRequiredText(pack.sample_type, "sample_type"), "sample_type", 80);
  const sampleCount = assertInteger(pack.sample_count, "sample_count", { min: 0, max: MAX_SAMPLE_COUNT });
  const representativeSamples = normalizeRepresentativeSamples(pack.representative_samples);
  if (sampleCount < representativeSamples.length) {
    throw new Error(`sample_count for ${findingId} must be >= representative_samples length`);
  }

  const replaySummary = assertMaxChars(
    assertRequiredText(pack.replay_summary, "replay_summary"),
    "replay_summary",
    MAX_REPLAY_SUMMARY_CHARS,
  );
  const redactionNotes = pack.redaction_notes == null
    ? null
    : assertMaxChars(normalizeOptionalText(pack.redaction_notes, "redaction_notes") || "", "redaction_notes", MAX_REDACTION_NOTES_CHARS);
  const reportSnippet = assertMaxChars(
    assertRequiredText(pack.report_snippet, "report_snippet"),
    "report_snippet",
    MAX_TEXT_CHARS,
  );

  validateNoSensitiveMaterial(replaySummary, "replay_summary");
  if (redactionNotes) validateNoSensitiveMaterial(redactionNotes, "redaction_notes");
  validateNoSensitiveMaterial(reportSnippet, "report_snippet");

  return {
    finding_id: findingId,
    sample_type: sampleType,
    sample_count: sampleCount,
    aggregate_counts: normalizeAggregateCounts(pack.aggregate_counts),
    representative_samples: representativeSamples,
    sensitive_clusters: normalizeSensitiveClusters(pack.sensitive_clusters),
    replay_summary: replaySummary,
    redaction_notes: redactionNotes,
    report_snippet: reportSnippet,
  };
}

function normalizeEvidencePacksDocument(document, {
  expectedDomain = null,
  findingIdSet = null,
  finalReportableIdSet = null,
  verificationBinding = null,
} = {}) {
  if (!isPlainObject(document)) {
    throw new Error("evidence packs document must be an object");
  }

  const domain = assertNonEmptyString(document.target_domain, "target_domain");
  if (expectedDomain != null && domain !== expectedDomain) {
    throw new Error(`evidence packs target_domain mismatch: expected ${expectedDomain}`);
  }
  if (!Array.isArray(document.packs)) {
    throw new Error("packs must be an array");
  }

  const normalized = {
    version: assertInteger(document.version, "version", { min: 1, max: 1 }),
    target_domain: domain,
    packs: [],
  };

  for (const field of ["verification_attempt_id", "verification_snapshot_hash", "final_verification_hash"]) {
    if (verificationBinding) {
      const actual = assertNonEmptyString(document[field], field);
      if (actual !== verificationBinding[field]) {
        throw new Error(`${field} does not match current final verification`);
      }
      normalized[field] = actual;
    } else if (document[field] != null) {
      normalized[field] = assertNonEmptyString(document[field], field);
    }
  }

  const knownFindingIds = findingIdSet || new Set(document.packs.map((pack) => parseFindingId(pack.finding_id)));
  const reportableIds = finalReportableIdSet || knownFindingIds;
  const seen = new Set();
  for (const pack of document.packs) {
    const normalizedPack = normalizeEvidencePack(pack, {
      findingIdSet: knownFindingIds,
      finalReportableIdSet: reportableIds,
    });
    if (seen.has(normalizedPack.finding_id)) {
      throw new Error(`Duplicate finding_id in evidence packs: ${normalizedPack.finding_id}`);
    }
    seen.add(normalizedPack.finding_id);
    normalized.packs.push(normalizedPack);
  }

  const missing = [...reportableIds].filter((id) => !seen.has(id));
  if (missing.length > 0) {
    throw new Error(`Evidence packs missing final reportable finding(s): ${missing.join(", ")}`);
  }

  return normalized;
}

function evidenceValidationError(message) {
  return new ToolError(
    ERROR_CODES.STATE_CONFLICT,
    `Evidence packs are required for final reportable findings and must be valid: ${message}`,
  );
}

function buildEvidenceValidationResult(domain, paths, document, finalReportableIds, { skipped = false } = {}) {
  return {
    valid: true,
    skipped,
    exists: fs.existsSync(paths.json),
    path: paths.json,
    document,
    packs_count: document.packs.length,
    representative_samples_count: document.packs.reduce(
      (total, pack) => total + pack.representative_samples.length,
      0,
    ),
    final_reportable_count: finalReportableIds.length,
    reportable_findings_covered: finalReportableIds.length,
    missing_finding_ids: [],
    duplicate_finding_ids: [],
    extra_finding_ids: [],
    target_domain: domain,
  };
}

function requireValidEvidencePacksForFinalReportableFindings(domain, { findingIdSet = null } = {}) {
  const normalizedDomain = assertNonEmptyString(domain, "target_domain");
  const knownFindingIds = findingIdSet || readFindingIdSet(normalizedDomain);
  const finalRound = loadFinalVerification(normalizedDomain, knownFindingIds);
  const verificationBinding = finalRound.version === 2
    ? verificationLib().evidenceBindingForFinal(normalizedDomain, finalRound)
    : null;
  const reportableIds = finalReportableIds(finalRound);
  const reportableIdSet = new Set(reportableIds);
  const paths = evidencePackPaths(normalizedDomain);

  if (!fs.existsSync(paths.json)) {
    if (reportableIds.length === 0) {
      const document = {
        version: EVIDENCE_PACKS_VERSION,
        target_domain: normalizedDomain,
        ...(verificationBinding || {}),
        packs: [],
      };
      return buildEvidenceValidationResult(normalizedDomain, paths, document, reportableIds, {
        skipped: true,
      });
    }
    throw evidenceValidationError(`Missing evidence packs JSON: ${paths.json}`);
  }

  let document;
  try {
    document = loadJsonDocumentStrict(paths.json, "evidence packs JSON");
    const normalized = normalizeEvidencePacksDocument(document, {
      expectedDomain: normalizedDomain,
      findingIdSet: knownFindingIds,
      finalReportableIdSet: reportableIdSet,
      verificationBinding,
    });
    if (verificationBinding) {
      verificationLib().assertEvidenceMatchesFinal(normalizedDomain, normalized, finalRound);
    }
    return buildEvidenceValidationResult(normalizedDomain, paths, normalized, reportableIds);
  } catch (error) {
    if (error instanceof ToolError) throw error;
    throw evidenceValidationError(error.message || String(error));
  }
}

function renderEvidencePacksMarkdown(document) {
  const lines = [
    "# Evidence Packs",
    `- Target: ${document.target_domain}`,
    ...(document.verification_attempt_id
      ? [
        `- Verification Attempt: ${document.verification_attempt_id}`,
        `- Verification Snapshot: ${document.verification_snapshot_hash}`,
        `- Final Verification Hash: ${document.final_verification_hash}`,
      ]
      : []),
    `- Packs: ${document.packs.length}`,
    "",
  ];

  if (document.packs.length === 0) {
    lines.push("No final reportable findings required evidence packs.");
    lines.push("");
    return `${lines.join("\n")}\n`;
  }

  for (const pack of document.packs) {
    lines.push(`## ${pack.finding_id}`);
    lines.push(`- Sample Type: ${pack.sample_type}`);
    lines.push(`- Sample Count: ${pack.sample_count}`);
    lines.push(`- Aggregate Counts: ${JSON.stringify(pack.aggregate_counts)}`);
    lines.push(`- Replay Summary: ${pack.replay_summary}`);
    lines.push(`- Redaction Notes: ${pack.redaction_notes || "N/A"}`);
    lines.push("- Representative Samples:");
    lines.push("```json");
    lines.push(JSON.stringify(pack.representative_samples, null, 2));
    lines.push("```");
    lines.push("- Sensitive Clusters:");
    lines.push("```json");
    lines.push(JSON.stringify(pack.sensitive_clusters, null, 2));
    lines.push("```");
    lines.push("- Report Snippet:");
    lines.push("```");
    lines.push(pack.report_snippet);
    lines.push("```");
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

function writeEvidencePacks(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  if (!Array.isArray(args.packs)) {
    throw new Error("packs must be an array");
  }

  return withSessionLock(domain, () => {
    const findingIdSet = readFindingIdSet(domain);
    const finalRound = loadFinalVerification(domain, findingIdSet, "evidence collection");
    const verificationBinding = finalRound.version === 2
      ? verificationLib().evidenceBindingForFinal(domain, finalRound)
      : null;
    const reportableIds = finalReportableIds(finalRound);
    const finalReportableIdSet = new Set(reportableIds);
    const document = normalizeEvidencePacksDocument({
      version: EVIDENCE_PACKS_VERSION,
      target_domain: domain,
      ...(verificationBinding || {}),
      packs: args.packs,
    }, {
      expectedDomain: domain,
      findingIdSet,
      finalReportableIdSet,
      verificationBinding,
    });
    if (verificationBinding) {
      verificationLib().assertEvidenceMatchesFinal(domain, document, finalRound);
    }

    const paths = evidencePackPaths(domain);
    writeFileAtomic(paths.json, `${JSON.stringify(document, null, 2)}\n`);
    const response = {
      packs_count: document.packs.length,
      representative_samples_count: document.packs.reduce((total, pack) => total + pack.representative_samples.length, 0),
      reportable_findings_covered: reportableIds.length,
      written_json: paths.json,
    };
    if (verificationBinding) {
      response.verification_attempt_id = verificationBinding.verification_attempt_id;
      response.verification_snapshot_hash = verificationBinding.verification_snapshot_hash;
      response.final_verification_hash = verificationBinding.final_verification_hash;
    }
    writeMarkdownMirror(paths.markdown, renderEvidencePacksMarkdown(document), response);
    pipelineEventsLib().safeAppendPipelineEventDirect(domain, "evidence_written", {
      phase: "VERIFY",
      status: document.packs.length === 0 ? "empty" : "written",
      source: "bounty_write_evidence_packs",
      verification_attempt_id: verificationBinding ? verificationBinding.verification_attempt_id : undefined,
      verification_snapshot_hash: verificationBinding ? verificationBinding.verification_snapshot_hash : undefined,
      final_verification_hash: verificationBinding ? verificationBinding.final_verification_hash : undefined,
      counts: {
        packs: document.packs.length,
        representative_samples: response.representative_samples_count,
        reportable_findings_covered: reportableIds.length,
      },
    });
    if (verificationBinding) verificationLib().refreshVerificationManifest(domain, { throw_on_error: true });
    return JSON.stringify(response);
  });
}

function readEvidencePacks(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const validation = requireValidEvidencePacksForFinalReportableFindings(domain);
  if (validation.skipped) {
    return JSON.stringify({
      ...validation.document,
      skipped: true,
    });
  }
  return JSON.stringify(validation.document);
}

module.exports = {
  EVIDENCE_PACKS_VERSION,
  normalizeEvidencePacksDocument,
  readEvidencePacks,
  requireValidEvidencePacksForFinalReportableFindings,
  renderEvidencePacksMarkdown,
  writeEvidencePacks,
};
