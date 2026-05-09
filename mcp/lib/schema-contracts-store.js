"use strict";

const fs = require("fs");
const { parseSchemaDoc } = require("./schema-contracts.js");
const {
  assertSafeDomain,
  schemaContractsJsonlPath,
  sessionDir,
} = require("./paths.js");

function ensureSessionDir(domain) {
  const dir = sessionDir(domain);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return dir;
}

function readJsonlContracts(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const raw = fs.readFileSync(filePath, "utf8");
  const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const records = [];
  for (let i = 0; i < lines.length; i++) {
    try {
      records.push(JSON.parse(lines[i]));
    } catch (err) {
      throw new Error(
        `Malformed schema-contracts.jsonl at line ${i + 1}: ${err.message || String(err)}`,
      );
    }
  }
  return records;
}

function writeJsonlContracts(filePath, records) {
  const sorted = records.slice().sort((a, b) => {
    const aHash = typeof a.contract_hash === "string" ? a.contract_hash : "";
    const bHash = typeof b.contract_hash === "string" ? b.contract_hash : "";
    if (aHash < bHash) return -1;
    if (aHash > bHash) return 1;
    return 0;
  });
  const body = sorted.map((record) => JSON.stringify(record)).join("\n");
  fs.writeFileSync(filePath, body.length > 0 ? body + "\n" : "", "utf8");
}

function ingestSchemaDoc({ target_domain, raw_doc, source_uri }) {
  const domain = assertSafeDomain(target_domain);
  if (typeof raw_doc !== "string" || raw_doc.length === 0) {
    throw new Error("raw_doc must be a non-empty string");
  }
  const sourceUri = typeof source_uri === "string" && source_uri.length > 0 ? source_uri : null;
  const ingestedAt = new Date().toISOString();
  const parsed = parseSchemaDoc(raw_doc);
  if (!parsed.schema_format) {
    return {
      schema_format: null,
      contract_count: 0,
      new_count: 0,
      replaced_count: 0,
      source_doc_hash: parsed.source_doc_hash,
      source_uri: sourceUri,
      total_in_corpus: 0,
      parser_warnings: parsed.parser_warnings,
    };
  }
  ensureSessionDir(domain);
  const filePath = schemaContractsJsonlPath(domain);
  const existing = readJsonlContracts(filePath);
  const byHash = new Map();
  for (const record of existing) {
    if (record && typeof record.contract_hash === "string") {
      byHash.set(record.contract_hash, record);
    }
  }
  let newCount = 0;
  let replacedCount = 0;
  for (const contract of parsed.contracts) {
    const record = {
      ...contract,
      schema_format: parsed.schema_format,
      source_doc_hash: parsed.source_doc_hash,
      source_uri: sourceUri,
      ingested_at: ingestedAt,
    };
    if (byHash.has(contract.contract_hash)) {
      replacedCount += 1;
    } else {
      newCount += 1;
    }
    byHash.set(contract.contract_hash, record);
  }
  const records = Array.from(byHash.values());
  writeJsonlContracts(filePath, records);
  return {
    schema_format: parsed.schema_format,
    contract_count: parsed.contracts.length,
    new_count: newCount,
    replaced_count: replacedCount,
    source_doc_hash: parsed.source_doc_hash,
    source_uri: sourceUri,
    total_in_corpus: records.length,
    parser_warnings: parsed.parser_warnings,
  };
}

function querySchemaContracts({ target_domain, endpoint_pattern, method, limit }) {
  const domain = assertSafeDomain(target_domain);
  const filePath = schemaContractsJsonlPath(domain);
  if (!fs.existsSync(filePath)) {
    return { contracts: [], total_matched: 0, source_count: 0, total_in_corpus: 0 };
  }
  const records = readJsonlContracts(filePath);
  const methodFilter = typeof method === "string" && method.length > 0
    ? method.toUpperCase()
    : null;
  const patternFilter = typeof endpoint_pattern === "string" && endpoint_pattern.length > 0
    ? endpoint_pattern
    : null;
  const matched = [];
  const sourceSet = new Set();
  for (const record of records) {
    if (record == null || typeof record !== "object") continue;
    if (typeof record.source_doc_hash === "string") {
      sourceSet.add(record.source_doc_hash);
    }
    if (methodFilter && record.method !== methodFilter) continue;
    if (patternFilter
      && (typeof record.endpoint !== "string" || !record.endpoint.includes(patternFilter))) {
      continue;
    }
    matched.push(record);
  }
  const cap = Number.isInteger(limit) && limit > 0 ? limit : matched.length;
  return {
    contracts: matched.slice(0, cap),
    total_matched: matched.length,
    source_count: sourceSet.size,
    total_in_corpus: records.length,
  };
}

module.exports = {
  ingestSchemaDoc,
  querySchemaContracts,
};
