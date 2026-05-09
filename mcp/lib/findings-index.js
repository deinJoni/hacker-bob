"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const {
  assertSafeDomain,
  findingsIndexJsonlPath,
  sessionDir,
  sessionsRoot,
} = require("./paths.js");

const FEATURE_DIMENSION = 256;
const STOP_WORDS = new Set([
  "the", "a", "an", "and", "or", "but", "for", "with", "without", "on", "in",
  "of", "to", "is", "are", "was", "were", "be", "been", "being", "as", "at",
  "by", "from", "this", "that", "these", "those", "it", "its", "into", "such",
  "than", "then", "via", "per", "any", "all", "no", "not", "yes",
]);
const TOKEN_PATTERN = /[a-z0-9]+/g;
const NGRAM_SIZE = 2;

function tokenize(text) {
  if (typeof text !== "string" || text.length === 0) return [];
  const tokens = (text.toLowerCase().match(TOKEN_PATTERN) || [])
    .filter((token) => token.length >= 2 && !STOP_WORDS.has(token));
  if (tokens.length < NGRAM_SIZE) return tokens;
  const ngrams = [];
  for (let i = 0; i + NGRAM_SIZE <= tokens.length; i++) {
    ngrams.push(tokens.slice(i, i + NGRAM_SIZE).join(" "));
  }
  return [...tokens, ...ngrams];
}

function tokenSlot(token, dimension) {
  const hash = crypto.createHash("sha256").update(token).digest();
  const value = (hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3];
  return Math.abs(value) % dimension;
}

function hashedFeatureVector(text, dimension) {
  const dim = Number.isInteger(dimension) && dimension > 0 ? dimension : FEATURE_DIMENSION;
  const tokens = tokenize(text);
  const vec = {};
  for (const token of tokens) {
    const slot = tokenSlot(token, dim);
    vec[slot] = (vec[slot] || 0) + 1;
  }
  return { dimension: dim, slots: vec };
}

function vectorNorm(vec) {
  let sum = 0;
  for (const value of Object.values(vec.slots)) {
    sum += value * value;
  }
  return Math.sqrt(sum);
}

function cosineSimilarity(a, b) {
  if (a == null || b == null) return 0;
  if (a.dimension !== b.dimension) return 0;
  const slotsA = a.slots || {};
  const slotsB = b.slots || {};
  const normA = vectorNorm(a);
  const normB = vectorNorm(b);
  if (normA === 0 || normB === 0) return 0;
  let dot = 0;
  for (const slot of Object.keys(slotsA)) {
    if (slot in slotsB) dot += slotsA[slot] * slotsB[slot];
  }
  return dot / (normA * normB);
}

function indexableFindingSummary(finding) {
  if (finding == null || typeof finding !== "object") return "";
  const parts = [];
  if (typeof finding.title === "string") parts.push(finding.title);
  if (typeof finding.description === "string") parts.push(finding.description);
  if (typeof finding.attack_class === "string") parts.push(finding.attack_class);
  if (typeof finding.cwe === "string") parts.push(`cwe ${finding.cwe}`);
  if (typeof finding.endpoint === "string") parts.push(finding.endpoint);
  if (typeof finding.surface_id === "string") parts.push(finding.surface_id);
  if (typeof finding.surface_type === "string") parts.push(finding.surface_type);
  if (Array.isArray(finding.tech_stack)) parts.push(finding.tech_stack.join(" "));
  if (typeof finding.evidence_summary === "string") parts.push(finding.evidence_summary);
  if (typeof finding.proof_of_concept === "string") {
    parts.push(finding.proof_of_concept.slice(0, 1000));
  }
  return parts.join(" \n ");
}

function featureVectorForFinding(finding, dimension) {
  return hashedFeatureVector(indexableFindingSummary(finding), dimension);
}

function ensureSessionDir(domain) {
  const dir = sessionDir(domain);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function readJsonlFindingsIndex(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const raw = fs.readFileSync(filePath, "utf8");
  const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const records = [];
  for (let i = 0; i < lines.length; i++) {
    try {
      records.push(JSON.parse(lines[i]));
    } catch (err) {
      throw new Error(`Malformed findings-index.jsonl at line ${i + 1}: ${err.message || String(err)}`);
    }
  }
  return records;
}

function writeJsonlFindingsIndex(filePath, records) {
  const sorted = records.slice().sort((a, b) => {
    const aId = typeof a.finding_id === "string" ? a.finding_id : "";
    const bId = typeof b.finding_id === "string" ? b.finding_id : "";
    return aId.localeCompare(bId);
  });
  const body = sorted.map((record) => JSON.stringify(record)).join("\n");
  fs.writeFileSync(filePath, body.length > 0 ? body + "\n" : "", "utf8");
}

function indexFinding({ target_domain, finding, calibration_label }) {
  const domain = assertSafeDomain(target_domain);
  if (finding == null || typeof finding !== "object") {
    throw new Error("finding must be an object");
  }
  if (typeof finding.finding_id !== "string" || finding.finding_id.length === 0) {
    throw new Error("finding.finding_id must be a non-empty string");
  }
  ensureSessionDir(domain);
  const filePath = findingsIndexJsonlPath(domain);
  const existing = readJsonlFindingsIndex(filePath);
  const byId = new Map();
  for (const record of existing) {
    if (record && typeof record.finding_id === "string") {
      byId.set(record.finding_id, record);
    }
  }
  const vector = featureVectorForFinding(finding);
  const record = {
    finding_id: finding.finding_id,
    target_domain: domain,
    title: typeof finding.title === "string" ? finding.title : null,
    severity: typeof finding.severity === "string" ? finding.severity : null,
    attack_class: typeof finding.attack_class === "string" ? finding.attack_class : null,
    surface_type: typeof finding.surface_type === "string" ? finding.surface_type : null,
    endpoint: typeof finding.endpoint === "string" ? finding.endpoint : null,
    tech_stack: Array.isArray(finding.tech_stack) ? finding.tech_stack.slice(0, 8) : null,
    calibration_label: typeof calibration_label === "string" && calibration_label.length > 0
      ? calibration_label
      : null,
    indexed_at: new Date().toISOString(),
    feature_vector: vector,
  };
  byId.set(finding.finding_id, record);
  writeJsonlFindingsIndex(filePath, Array.from(byId.values()));
  return {
    finding_id: finding.finding_id,
    target_domain: domain,
    new_record: !existing.some((r) => r.finding_id === finding.finding_id),
    total_in_index: byId.size,
  };
}

function queryFindingsForTarget({ target_domain, query_text, top_k, severity_filter, attack_class_filter }) {
  const domain = assertSafeDomain(target_domain);
  if (typeof query_text !== "string" || query_text.length === 0) {
    throw new Error("query_text must be a non-empty string");
  }
  const limit = Number.isInteger(top_k) && top_k > 0 ? Math.min(top_k, 50) : 5;
  const filePath = findingsIndexJsonlPath(domain);
  const records = readJsonlFindingsIndex(filePath);
  if (records.length === 0) {
    return { matches: [], total_in_index: 0, query_dimension: FEATURE_DIMENSION };
  }
  const queryVector = hashedFeatureVector(query_text);
  const scored = [];
  for (const record of records) {
    if (record == null) continue;
    if (severity_filter && record.severity !== severity_filter) continue;
    if (attack_class_filter && record.attack_class !== attack_class_filter) continue;
    if (record.feature_vector == null) continue;
    const score = cosineSimilarity(queryVector, record.feature_vector);
    if (score <= 0) continue;
    scored.push({
      finding_id: record.finding_id,
      target_domain: record.target_domain,
      title: record.title,
      severity: record.severity,
      attack_class: record.attack_class,
      surface_type: record.surface_type,
      endpoint: record.endpoint,
      tech_stack: record.tech_stack,
      calibration_label: record.calibration_label,
      similarity: Number(score.toFixed(4)),
    });
  }
  scored.sort((a, b) => {
    if (b.similarity !== a.similarity) return b.similarity - a.similarity;
    return a.finding_id.localeCompare(b.finding_id);
  });
  return {
    matches: scored.slice(0, limit),
    total_in_index: records.length,
    query_dimension: queryVector.dimension,
    matched_total: scored.length,
  };
}

function queryFindingsCrossTarget({ query_text, top_k, severity_filter, attack_class_filter }) {
  if (typeof query_text !== "string" || query_text.length === 0) {
    throw new Error("query_text must be a non-empty string");
  }
  const limit = Number.isInteger(top_k) && top_k > 0 ? Math.min(top_k, 50) : 5;
  const root = sessionsRoot();
  if (!fs.existsSync(root)) {
    return { matches: [], total_in_index: 0, query_dimension: FEATURE_DIMENSION, domains_scanned: 0 };
  }
  const queryVector = hashedFeatureVector(query_text);
  const scored = [];
  let totalRecords = 0;
  let domainsScanned = 0;
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith(".")) continue;
    const filePath = path.join(root, entry.name, "findings-index.jsonl");
    if (!fs.existsSync(filePath)) continue;
    domainsScanned += 1;
    let records;
    try {
      records = readJsonlFindingsIndex(filePath);
    } catch (_err) {
      continue;
    }
    totalRecords += records.length;
    for (const record of records) {
      if (record == null) continue;
      if (severity_filter && record.severity !== severity_filter) continue;
      if (attack_class_filter && record.attack_class !== attack_class_filter) continue;
      if (record.feature_vector == null) continue;
      const score = cosineSimilarity(queryVector, record.feature_vector);
      if (score <= 0) continue;
      scored.push({
        finding_id: record.finding_id,
        target_domain: record.target_domain,
        title: record.title,
        severity: record.severity,
        attack_class: record.attack_class,
        surface_type: record.surface_type,
        endpoint: record.endpoint,
        tech_stack: record.tech_stack,
        calibration_label: record.calibration_label,
        similarity: Number(score.toFixed(4)),
      });
    }
  }
  scored.sort((a, b) => {
    if (b.similarity !== a.similarity) return b.similarity - a.similarity;
    return a.finding_id.localeCompare(b.finding_id);
  });
  return {
    matches: scored.slice(0, limit),
    total_in_index: totalRecords,
    query_dimension: queryVector.dimension,
    domains_scanned: domainsScanned,
    matched_total: scored.length,
  };
}

const PRIORS_SLICE_DEFAULT_LIMIT = 5;
const PRIORS_SLICE_MAX_LIMIT = 15;

function indexableSurfaceQuery(surfaceObj) {
  if (surfaceObj == null || typeof surfaceObj !== "object") return "";
  const parts = [];
  if (typeof surfaceObj.endpoint === "string") parts.push(surfaceObj.endpoint);
  if (typeof surfaceObj.endpoint_pattern === "string") parts.push(surfaceObj.endpoint_pattern);
  if (Array.isArray(surfaceObj.endpoints)) parts.push(surfaceObj.endpoints.join(" "));
  if (typeof surfaceObj.surface_type === "string") parts.push(surfaceObj.surface_type);
  if (typeof surfaceObj.bug_class === "string") parts.push(surfaceObj.bug_class);
  if (Array.isArray(surfaceObj.bug_classes)) parts.push(surfaceObj.bug_classes.join(" "));
  if (Array.isArray(surfaceObj.tech_stack)) parts.push(surfaceObj.tech_stack.join(" "));
  if (typeof surfaceObj.notes === "string") parts.push(surfaceObj.notes);
  if (typeof surfaceObj.title === "string") parts.push(surfaceObj.title);
  if (typeof surfaceObj.description === "string") parts.push(surfaceObj.description);
  if (typeof surfaceObj.chain_family === "string") parts.push(surfaceObj.chain_family);
  if (typeof surfaceObj.chain_id !== "undefined" && surfaceObj.chain_id != null) {
    parts.push(String(surfaceObj.chain_id));
  }
  if (typeof surfaceObj.contract_address === "string") parts.push(surfaceObj.contract_address);
  return parts.filter((part) => typeof part === "string" && part.length > 0).join(" ");
}

function compactPriorRecord(record) {
  if (record == null || typeof record !== "object") return null;
  return {
    finding_id: record.finding_id,
    target_domain: record.target_domain,
    title: record.title,
    severity: record.severity,
    attack_class: record.attack_class,
    surface_type: record.surface_type,
    endpoint: record.endpoint,
    tech_stack: record.tech_stack,
    calibration_label: record.calibration_label,
    similarity: record.similarity,
  };
}

function summarizePriorFindingsForSurface(domain, surfaceObj, options) {
  const opts = options || {};
  const requestedLimit = Number.isInteger(opts.limit) && opts.limit > 0
    ? opts.limit
    : PRIORS_SLICE_DEFAULT_LIMIT;
  const limit = Math.min(requestedLimit, PRIORS_SLICE_MAX_LIMIT);
  const queryText = indexableSurfaceQuery(surfaceObj);
  if (queryText.length === 0) return null;
  let crossTarget;
  try {
    crossTarget = queryFindingsCrossTarget({
      query_text: queryText,
      top_k: limit,
    });
  } catch (_err) {
    return null;
  }
  if (crossTarget.matches.length === 0) {
    return null;
  }
  const sameTargetMatches = crossTarget.matches.filter((m) => m.target_domain === domain);
  const otherTargetMatches = crossTarget.matches.filter((m) => m.target_domain !== domain);
  return {
    total_in_corpus: crossTarget.total_in_index,
    domains_scanned: crossTarget.domains_scanned,
    matched_total: crossTarget.matched_total,
    same_target_count: sameTargetMatches.length,
    other_target_count: otherTargetMatches.length,
    priors: crossTarget.matches.slice(0, limit).map(compactPriorRecord).filter((entry) => entry != null),
    limit,
  };
}

module.exports = {
  tokenize,
  hashedFeatureVector,
  cosineSimilarity,
  featureVectorForFinding,
  indexFinding,
  queryFindingsForTarget,
  queryFindingsCrossTarget,
  summarizePriorFindingsForSurface,
  FEATURE_DIMENSION,
};
