"use strict";

const fs = require("fs");
const { StringDecoder } = require("string_decoder");
const {
  assertNonEmptyString,
  parseAgentId,
  parseWaveId,
} = require("./validation.js");
const {
  findingsJsonlPath,
  findingsMarkdownPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  appendMarkdownMirror,
  withSessionLock,
} = require("./storage.js");
const {
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");
const {
  validateAssignedWaveAgentSurface,
} = require("./assignments.js");
const {
  safeAppendPipelineEventDirect,
} = require("./pipeline-events.js");
const {
  normalizeFindingRecord,
  renderFindingMarkdownEntry,
} = require("./finding-contracts.js");

const FINDINGS_JSONL_READ_CHUNK_BYTES = 64 * 1024;
const FINDING_TEXT_LIMITS = Object.freeze({
  title: 300,
  cwe: 120,
  endpoint: 2000,
  description: 4000,
  proof_of_concept: 4000,
  response_evidence: 4000,
  impact: 4000,
  auth_profile: 200,
});

function fileMtimeIso(filePath) {
  try {
    return new Date(fs.statSync(filePath).mtimeMs).toISOString();
  } catch {
    return null;
  }
}

function normalizeFindingJsonlLine(line, domain, lineNumber) {
  let parsed;
  try {
    parsed = JSON.parse(line);
  } catch (error) {
    throw new Error(`Malformed findings.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
  return normalizeFindingRecord(parsed, {
    expectedDomain: domain,
    lineNumber,
  });
}

function scanFindingsJsonl(domain, visitor = null, { tolerant = false } = {}) {
  const filePath = findingsJsonlPath(domain);
  const stats = {
    exists: fs.existsSync(filePath),
    path: filePath,
    total: 0,
    malformed_lines: 0,
    error: null,
    mtime: fileMtimeIso(filePath),
  };
  if (!stats.exists) {
    return stats;
  }

  const fd = fs.openSync(filePath, "r");
  const decoder = new StringDecoder("utf8");
  const buffer = Buffer.allocUnsafe(FINDINGS_JSONL_READ_CHUNK_BYTES);
  let pending = "";
  let lineNumber = 0;

  const processLine = (rawLine) => {
    lineNumber += 1;
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (!line.trim()) return;
    try {
      const finding = normalizeFindingJsonlLine(line, domain, lineNumber);
      stats.total += 1;
      if (visitor) visitor(finding, lineNumber);
    } catch (error) {
      if (!tolerant) throw error;
      stats.malformed_lines += 1;
      if (!stats.error) stats.error = error.message || String(error);
    }
  };

  try {
    while (true) {
      const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      pending += decoder.write(buffer.subarray(0, bytesRead));
      let newlineIndex;
      while ((newlineIndex = pending.indexOf("\n")) >= 0) {
        const line = pending.slice(0, newlineIndex);
        pending = pending.slice(newlineIndex + 1);
        processLine(line);
      }
    }
    pending += decoder.end();
    if (pending.length > 0) processLine(pending);
  } finally {
    fs.closeSync(fd);
  }

  return stats;
}

function readFindingsFromJsonl(domain) {
  const findings = [];
  scanFindingsJsonl(domain, (finding) => findings.push(finding));
  return findings;
}

function summarizeFindingsFile(domain) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const stats = scanFindingsJsonl(domain, (finding) => {
    if (Object.prototype.hasOwnProperty.call(bySeverity, finding.severity)) {
      bySeverity[finding.severity] += 1;
    }
  }, { tolerant: true });
  return {
    exists: stats.exists,
    total: stats.total,
    by_severity: bySeverity,
    malformed_lines: stats.malformed_lines,
    error: stats.error,
    mtime: stats.mtime,
  };
}

function readFindingIdSet(domain) {
  const ids = new Set();
  scanFindingsJsonl(domain, (finding) => ids.add(finding.id));
  return ids;
}

function findingIdNumber(findingId) {
  const match = typeof findingId === "string" ? findingId.match(/^F-([1-9]\d*)$/) : null;
  return match ? Number(match[1]) : 0;
}

function validateFindingForPersistence(finding) {
  for (const [field, maxTextChars] of Object.entries(FINDING_TEXT_LIMITS)) {
    if (finding[field] == null) continue;
    validateNoSensitiveMaterial(finding[field], field, { maxTextChars });
  }
}

function buildFindingRecord(args, context, id) {
  return normalizeFindingRecord({
    id,
    target_domain: context.domain,
    title: args.title,
    severity: args.severity,
    cwe: args.cwe,
    endpoint: args.endpoint,
    description: args.description,
    proof_of_concept: args.proof_of_concept,
    response_evidence: args.response_evidence,
    impact: args.impact,
    validated: args.validated,
    wave: context.wave,
    agent: context.agent,
    surface_id: context.surfaceId,
    surface_type: context.surfaceType,
    capability_pack: context.capabilityPack,
    hunter_agent: context.hunterAgent,
    brief_profile: context.briefProfile,
    sc_evidence: args.sc_evidence,
    dedupe_key: args.dedupe_key,
    auth_profile: args.auth_profile,
    force_record: args.force_record === true,
  }, { expectedDomain: context.domain });
}

function recordFinding(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const hasWave = args.wave != null;
  const hasAgent = args.agent != null;
  if (hasWave !== hasAgent) {
    throw new Error("wave and agent must either both be provided or both be omitted");
  }

  let wave = null;
  let agent = null;
  let surfaceId = null;
  let surfaceType = null;
  let capabilityPack = null;
  let hunterAgent = null;
  let briefProfile = null;
  if (hasWave) {
    wave = parseWaveId(args.wave);
    agent = parseAgentId(args.agent);
    surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
    const assignment = validateAssignedWaveAgentSurface(domain, wave, agent, surfaceId);
    const rawSurfaceType = assignment && assignment.surface_type ? assignment.surface_type : null;
    surfaceType = rawSurfaceType === "smart_contract" ? "smart_contract" : "web";
    capabilityPack = assignment.capability_pack || null;
    hunterAgent = assignment.hunter_agent || null;
    briefProfile = assignment.brief_profile || null;
  } else {
    surfaceId = args.surface_id == null ? null : assertNonEmptyString(args.surface_id, "surface_id");
    if (args.sc_evidence != null) {
      throw new Error("sc_evidence findings must be recorded with wave and agent so the routed capability pack is captured from the assignment");
    }
    surfaceType = "web";
    capabilityPack = "web";
    hunterAgent = "hunter-agent";
    briefProfile = "web";
  }

  return withSessionLock(domain, () => {
    const structuredPath = findingsJsonlPath(domain);
    const context = {
      domain,
      wave,
      agent,
      surfaceId,
      surfaceType,
      capabilityPack,
      hunterAgent,
      briefProfile,
    };
    const preliminary = buildFindingRecord(args, context, "F-1");
    validateFindingForPersistence(preliminary);

    let duplicate = null;
    let maxFindingNumber = 0;
    const scan = scanFindingsJsonl(domain, (existing) => {
      maxFindingNumber = Math.max(maxFindingNumber, findingIdNumber(existing.id));
      if (!duplicate && existing.dedupe_key === preliminary.dedupe_key) {
        duplicate = existing;
      }
    });
    const counter = maxFindingNumber + 1;
    if (duplicate && args.force_record !== true) {
      return JSON.stringify({
        recorded: false,
        duplicate: true,
        finding_id: duplicate.id,
        existing_finding_id: duplicate.id,
        dedupe_key: duplicate.dedupe_key,
        total: scan.total,
        written_jsonl: structuredPath,
      });
    }

    const finding = buildFindingRecord(args, context, `F-${counter}`);
    validateFindingForPersistence(finding);
    appendJsonlLine(structuredPath, finding);

    const response = {
      recorded: true,
      finding_id: finding.id,
      total: scan.total + 1,
      finding_sequence: counter,
      dedupe_key: finding.dedupe_key,
      written_jsonl: structuredPath,
    };
    if (finding.force_record) {
      response.force_record = true;
    }

    appendMarkdownMirror(findingsMarkdownPath(domain), renderFindingMarkdownEntry(finding), response);
    safeAppendPipelineEventDirect(domain, "finding_recorded", {
      wave,
      agent,
      surface_id: surfaceId,
      status: finding.severity,
      source: "bounty_record_finding",
      counts: {
        findings: scan.total + 1,
        validated: finding.validated ? 1 : 0,
      },
    });
    try {
      const { indexFinding } = require("./findings-index.js");
      indexFinding({
        target_domain: domain,
        finding: {
          finding_id: finding.id,
          title: finding.title,
          description: finding.description,
          severity: finding.severity,
          attack_class: finding.attack_class,
          cwe: finding.cwe,
          endpoint: finding.endpoint,
          surface_id: finding.surface_id,
          surface_type: finding.surface_type,
          tech_stack: finding.tech_stack,
          evidence_summary: finding.evidence_summary || finding.response_evidence,
          proof_of_concept: finding.proof_of_concept,
        },
      });
    } catch (_err) {
      safeAppendPipelineEventDirect(domain, "finding_index_failed", {
        wave,
        agent,
        surface_id: surfaceId,
        status: finding.severity,
        source: "bounty_record_finding",
        counts: {
          findings: scan.total + 1,
          validated: finding.validated ? 1 : 0,
        },
      });
    }
    return JSON.stringify(response);
  });
}

function readFindings(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    findings: readFindingsFromJsonl(domain),
  });
}

function listFindings(args) {
  const findings = [];
  const stats = scanFindingsJsonl(assertNonEmptyString(args.target_domain, "target_domain"), (finding) => {
    findings.push({
      id: finding.id,
      severity: finding.severity,
      title: finding.title,
      endpoint: finding.endpoint,
    });
  });
  return JSON.stringify({
    count: stats.total,
    findings,
  });
}

module.exports = {
  listFindings,
  readFindings,
  readFindingIdSet,
  readFindingsFromJsonl,
  recordFinding,
  scanFindingsJsonl,
  summarizeFindingsFile,
};
