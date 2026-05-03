"use strict";

const fs = require("fs");
const path = require("path");
const {
  TECHNIQUE_ATTEMPT_LOG_MAX_RECORDS,
  TECHNIQUE_ATTEMPT_STATUS_VALUES,
  TECHNIQUE_PACK_READ_LOG_MAX_RECORDS,
} = require("./constants.js");
const {
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  assertRequiredText,
  normalizeOptionalInteger,
  normalizeOptionalText,
  parseAgentId,
  parseWaveId,
} = require("./validation.js");
const {
  readAttackSurfaceStrict,
} = require("./attack-surface.js");
const {
  validateAssignedWaveAgentSurface,
} = require("./assignments.js");
const {
  techniqueAttemptsJsonlPath,
  techniquePackReadsJsonlPath,
  surfaceRoutesPath,
} = require("./paths.js");
const {
  classifySurfaceCapability,
  getCapabilityPack,
  normalizeContextBudget,
} = require("./capability-packs.js");
const {
  readSurfaceRoutesStrict,
} = require("./surface-router.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("./storage.js");
const {
  safeAppendPipelineEventDirect,
} = require("./pipeline-analytics.js");
const {
  resourceCandidatePaths,
} = require("./runtime-resources.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");

const HUNTER_KNOWLEDGE_FILE = Object.freeze(["knowledge", "hunter-techniques.json"]);
const HUNTER_KNOWLEDGE_DEFAULT_ID = "generic-rest-api";
const HUNTER_KNOWLEDGE_MAX_ENTRIES = 4;
const HUNTER_KNOWLEDGE_MAX_CHARS = 4500;
const TECHNIQUE_PACK_ID_RE = /^[A-Za-z][A-Za-z0-9_-]{0,127}$/;
const DEFAULT_SUMMARY_ESTIMATED_TOKENS = 500;
const DEFAULT_FULL_ESTIMATED_TOKENS = 1500;
const TECHNIQUE_SUMMARY_ITEMS_PER_KIND = 4;
const TECHNIQUE_SUMMARY_ITEM_MAX_CHARS = 240;
const TECHNIQUE_FULL_ITEMS_PER_KIND = 12;
const TECHNIQUE_FULL_ITEM_MAX_CHARS = 900;
const TECHNIQUE_SELECTION_MAX_CHARS = 6000;

function registryWarning(source, { entryIndex = null, entryId = null, reason }) {
  const warning = {
    source: source ? path.basename(source) : HUNTER_KNOWLEDGE_FILE[HUNTER_KNOWLEDGE_FILE.length - 1],
    reason: String(reason || "invalid technique registry entry"),
  };
  if (entryIndex != null) warning.entry_index = entryIndex;
  if (entryId != null && String(entryId).trim()) {
    warning.entry_id = String(entryId).trim().slice(0, 128);
  }
  return warning;
}

function readableEntryId(entry) {
  if (entry && typeof entry === "object" && !Array.isArray(entry) && entry.id != null) {
    return String(entry.id);
  }
  return null;
}

function hunterKnowledgeCandidatePaths() {
  return resourceCandidatePaths(...HUNTER_KNOWLEDGE_FILE);
}

function loadHunterKnowledge() {
  for (const candidate of hunterKnowledgeCandidatePaths()) {
    if (!candidate || !fs.existsSync(candidate)) continue;
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(candidate, "utf8"));
    } catch (error) {
      return {
        path: candidate,
        version: 1,
        entries: [],
        warnings: [registryWarning(candidate, {
          reason: `Malformed hunter-techniques.json: ${error.message || String(error)}`,
        })],
      };
    }
    const version = parsed && Number.isInteger(parsed.version) ? parsed.version : 1;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || !Array.isArray(parsed.entries)) {
      return {
        path: candidate,
        version,
        entries: [],
        warnings: [registryWarning(candidate, {
          reason: "hunter-techniques.json must be an object with entries[]",
        })],
      };
    }
    return {
      path: candidate,
      version,
      entries: parsed.entries,
      warnings: [],
    };
  }
  return { path: null, version: 1, entries: [], warnings: [] };
}

function lowerStringArray(value) {
  if (value == null) return [];
  const values = Array.isArray(value) ? value : [value];
  return values
    .filter((item) => item != null)
    .map((item) => String(item).toLowerCase());
}

function stringArray(value) {
  if (value == null) return [];
  const values = Array.isArray(value) ? value : [value];
  return values
    .filter((item) => item != null)
    .map((item) => String(item));
}

function capTechniqueString(value, maxChars) {
  const text = String(value);
  if (text.length <= maxChars) {
    return { value: text, truncated: false, total_chars: text.length };
  }
  return {
    value: text.slice(0, maxChars),
    truncated: true,
    total_chars: text.length,
  };
}

function boundedTechniqueStrings(value, { itemLimit, itemMaxChars }) {
  const rawValues = stringArray(value)
    .map((item) => item.trim())
    .filter(Boolean);
  let truncatedValues = 0;
  const values = rawValues.slice(0, itemLimit).map((item) => {
    const capped = capTechniqueString(item, itemMaxChars);
    if (capped.truncated) truncatedValues += 1;
    return capped.value;
  });
  return {
    values,
    limits: {
      item_limit: itemLimit,
      item_max_chars: itemMaxChars,
      shown: values.length,
      total: rawValues.length,
      omitted: Math.max(0, rawValues.length - values.length),
      truncated_values: truncatedValues,
    },
  };
}

function surfaceFieldText(surface, fields) {
  const values = [];
  for (const field of fields) {
    values.push(...lowerStringArray(surface[field]));
  }
  return values.join("\n");
}

function countMatches(patterns, haystack, weight, label) {
  const matches = [];
  let score = 0;
  for (const pattern of lowerStringArray(patterns)) {
    if (!pattern || !haystack.includes(pattern)) continue;
    score += weight;
    matches.push(`${label}:${pattern}`);
  }
  return { score, matches };
}

function countExactMatches(patterns, values, weight, label) {
  const valueSet = new Set(lowerStringArray(values));
  const matches = [];
  let score = 0;
  for (const pattern of lowerStringArray(patterns)) {
    if (!pattern || !valueSet.has(pattern)) continue;
    score += weight;
    matches.push(`${label}:${pattern}`);
  }
  return { score, matches };
}

function scoreTechniqueEntry(entry, surface) {
  const match = entry.match && typeof entry.match === "object" ? entry.match : {};
  const techText = surfaceFieldText(surface, [
    "tech_stack",
    "surface_type",
  ]);
  const endpointText = surfaceFieldText(surface, [
    "endpoints",
    "discovered_endpoints",
    "js_endpoints",
    "hosts",
    "high_value_flows",
    "evidence",
  ]);
  const paramValues = [
    ...lowerStringArray(surface.interesting_params),
    ...lowerStringArray(surface.params),
    ...lowerStringArray(surface.parameters),
  ];
  const hintText = surfaceFieldText(surface, [
    "nuclei_hits",
    "js_hints",
    "security_issues",
    "leaked_secrets",
    "auth_info",
    "surface_type",
    "bug_class_hints",
    "high_value_flows",
    "evidence",
  ]);

  const scored = [
    countMatches(match.tech, techText, 8, "tech"),
    countMatches(match.endpoints, endpointText, 5, "endpoint"),
    countExactMatches(match.params, paramValues, 3, "param"),
    countMatches(match.hints, hintText, 4, "hint"),
  ];

  return scored.reduce(
    (result, item) => ({
      score: result.score + item.score,
      matches: result.matches.concat(item.matches),
    }),
    { score: 0, matches: [] },
  );
}

function normalizeTechniquePackId(value, fieldName = "pack_id") {
  const packId = assertNonEmptyString(value, fieldName);
  if (!TECHNIQUE_PACK_ID_RE.test(packId)) {
    throw new Error(`${fieldName} has invalid format`);
  }
  return packId;
}

function normalizeCapabilityPacks(entry) {
  const packs = stringArray(entry.capability_packs)
    .map((item) => item.trim())
    .filter(Boolean);
  return packs.length > 0 ? Array.from(new Set(packs)) : ["web"];
}

function packEstimatedTokens(entry) {
  const explicit = entry.estimated_tokens && typeof entry.estimated_tokens === "object"
    ? entry.estimated_tokens
    : {};
  return {
    summary: Number.isInteger(explicit.summary) && explicit.summary > 0
      ? explicit.summary
      : DEFAULT_SUMMARY_ESTIMATED_TOKENS,
    full: Number.isInteger(explicit.full) && explicit.full > 0
      ? explicit.full
      : DEFAULT_FULL_ESTIMATED_TOKENS,
  };
}

function normalizeRegistryEntry(entry, registryVersion) {
  if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
    throw new Error("technique pack entry must be an object");
  }
  const id = normalizeTechniquePackId(entry.id || "knowledge-entry", "technique_pack.id");
  const title = assertNonEmptyString(entry.title || entry.id || "Hunter guidance", "technique_pack.title");
  const capabilityPacks = normalizeCapabilityPacks(entry);
  for (const capabilityPack of capabilityPacks) {
    if (!getCapabilityPack(capabilityPack)) {
      throw new Error(`Unknown capability_pack in technique pack ${id}: ${capabilityPack}`);
    }
  }
  return {
    id,
    version: Number.isInteger(entry.version) ? entry.version : registryVersion,
    title,
    capability_packs: capabilityPacks,
    match: entry.match && typeof entry.match === "object" && !Array.isArray(entry.match) ? entry.match : {},
    techniques: stringArray(entry.techniques)
      .map((item) => item.trim())
      .filter(Boolean),
    payload_hints: stringArray(entry.payload_hints)
      .map((item) => item.trim())
      .filter(Boolean),
    estimated_tokens: packEstimatedTokens(entry),
    raw_entry: {
      id,
      title,
      match: entry.match && typeof entry.match === "object" && !Array.isArray(entry.match) ? entry.match : {},
      techniques: stringArray(entry.techniques)
        .map((item) => item.trim())
        .filter(Boolean),
      payload_hints: stringArray(entry.payload_hints)
        .map((item) => item.trim())
        .filter(Boolean),
    },
  };
}

function loadTechniqueRegistry() {
  const knowledge = loadHunterKnowledge();
  const warnings = Array.isArray(knowledge.warnings) ? knowledge.warnings.slice() : [];
  const packs = [];
  const seenIds = new Set();
  for (let index = 0; index < knowledge.entries.length; index += 1) {
    const entry = knowledge.entries[index];
    let normalized;
    try {
      normalized = normalizeRegistryEntry(entry, knowledge.version);
    } catch (error) {
      warnings.push(registryWarning(knowledge.path, {
        entryIndex: index,
        entryId: readableEntryId(entry),
        reason: error.message || String(error),
      }));
      continue;
    }
    if (seenIds.has(normalized.id)) {
      warnings.push(registryWarning(knowledge.path, {
        entryIndex: index,
        entryId: normalized.id,
        reason: `Duplicate technique pack id: ${normalized.id}`,
      }));
      continue;
    }
    seenIds.add(normalized.id);
    packs.push(normalized);
  }
  return {
    source: knowledge.path,
    version: knowledge.version,
    packs,
    warnings,
  };
}

function techniquePackSummary(pack, { matches = [], score = 0, attempt = null } = {}) {
  const guidance = boundedTechniqueStrings(pack.techniques, {
    itemLimit: TECHNIQUE_SUMMARY_ITEMS_PER_KIND,
    itemMaxChars: TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
  });
  const payloadHints = boundedTechniqueStrings(pack.payload_hints, {
    itemLimit: TECHNIQUE_SUMMARY_ITEMS_PER_KIND,
    itemMaxChars: TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
  });
  const summary = {
    id: pack.id,
    version: pack.version,
    title: pack.title,
    capability_packs: pack.capability_packs.slice(),
    matched: matches.slice(0, 8),
    score,
    summary: {
      guidance: guidance.values,
      payload_hints: payloadHints.values,
    },
    summary_limits: {
      guidance: guidance.limits,
      payload_hints: payloadHints.limits,
    },
    estimated_tokens: { ...pack.estimated_tokens },
  };
  if (attempt) {
    summary.attempt = summarizeTechniqueAttempt(attempt);
  }
  return summary;
}

function latestAttemptByPack(attempts) {
  const latest = new Map();
  for (const attempt of attempts || []) {
    latest.set(attempt.pack_id, attempt);
  }
  return latest;
}

function shouldSkipAttemptedPack(attempt, includeAttempted) {
  if (includeAttempted) return false;
  return !!attempt;
}

function fitTechniquePackSummaries(summaries, maxChars = TECHNIQUE_SELECTION_MAX_CHARS, {
  candidateLimit = null,
} = {}) {
  const selected = [];
  for (const summary of summaries) {
    const candidate = selected.concat(summary);
    if (JSON.stringify(candidate).length > maxChars) break;
    selected.push(summary);
  }
  const selectionLimits = {
    max_chars: maxChars,
    selected_chars: JSON.stringify(selected).length,
    selected_count: selected.length,
    candidate_count: summaries.length,
    omitted_due_to_char_limit: Math.max(0, summaries.length - selected.length),
    summary_items_per_kind: TECHNIQUE_SUMMARY_ITEMS_PER_KIND,
    summary_item_max_chars: TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
  };
  if (candidateLimit != null) {
    selectionLimits.candidate_pack_limit = candidateLimit;
  }
  return {
    selected,
    selection_limits: selectionLimits,
  };
}

function selectTechniquePacksForSurface(surface, {
  capabilityPack = "web",
  maxPacks = HUNTER_KNOWLEDGE_MAX_ENTRIES,
  includeAttempted = true,
  attempts = [],
} = {}) {
  const limit = normalizeOptionalInteger(maxPacks, "max_packs", { min: 1, max: 50 }) || HUNTER_KNOWLEDGE_MAX_ENTRIES;
  const registry = loadTechniqueRegistry();
  if (registry.packs.length === 0) {
    return {
      source: registry.source,
      selected: [],
      omitted_attempted: [],
      registry_version: registry.version,
      registry_warnings: registry.warnings.slice(),
      selection_limits: fitTechniquePackSummaries([], TECHNIQUE_SELECTION_MAX_CHARS, {
        candidateLimit: limit,
      }).selection_limits,
    };
  }

  const attemptsByPack = latestAttemptByPack(attempts);
  const scoredPacks = [];
  for (const pack of registry.packs) {
    if (!pack.capability_packs.includes(capabilityPack)) continue;
    const scored = scoreTechniqueEntry(pack, surface || {});
    if (scored.score > 0) {
      scoredPacks.push({ pack, score: scored.score, matches: scored.matches });
    }
  }

  if (scoredPacks.length === 0) {
    const fallback = registry.packs.find(
      (pack) => pack.id === HUNTER_KNOWLEDGE_DEFAULT_ID && pack.capability_packs.includes(capabilityPack),
    );
    if (fallback) {
      scoredPacks.push({ pack: fallback, score: 0, matches: ["fallback:generic-rest-api"] });
    }
  }

  scoredPacks.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return a.pack.id.localeCompare(b.pack.id);
  });

  const selectedCandidates = [];
  const omittedAttempted = [];
  for (const scored of scoredPacks) {
    const attempt = attemptsByPack.get(scored.pack.id) || null;
    if (shouldSkipAttemptedPack(attempt, includeAttempted)) {
      omittedAttempted.push(summarizeTechniqueAttempt(attempt));
      continue;
    }
    selectedCandidates.push(techniquePackSummary(scored.pack, {
      matches: scored.matches,
      score: scored.score,
      attempt,
    }));
    if (selectedCandidates.length >= limit) break;
  }
  const fitted = fitTechniquePackSummaries(selectedCandidates, TECHNIQUE_SELECTION_MAX_CHARS, {
    candidateLimit: limit,
  });

  return {
    source: registry.source,
    selected: fitted.selected,
    omitted_attempted: omittedAttempted,
    registry_version: registry.version,
    registry_warnings: registry.warnings.slice(),
    selection_limits: fitted.selection_limits,
  };
}

function readTechniquePack(packId, { mode = "summary" } = {}) {
  const normalizedPackId = normalizeTechniquePackId(packId);
  const normalizedMode = mode == null ? "summary" : assertEnumValue(mode, ["summary", "full"], "mode");
  const registry = loadTechniqueRegistry();
  const pack = registry.packs.find((entry) => entry.id === normalizedPackId);
  if (!pack) {
    throw new Error(`Unknown technique pack id: ${normalizedPackId}`);
  }
  const summary = techniquePackSummary(pack);
  if (normalizedMode === "summary") {
    return {
      version: 1,
      mode: normalizedMode,
      source: registry.source ? path.basename(registry.source) : null,
      registry_version: registry.version,
      technique_pack: summary,
      summary_limits: summary.summary_limits,
      registry_warnings: registry.warnings.slice(),
    };
  }
  const fullTechniques = boundedTechniqueStrings(pack.techniques, {
    itemLimit: TECHNIQUE_FULL_ITEMS_PER_KIND,
    itemMaxChars: TECHNIQUE_FULL_ITEM_MAX_CHARS,
  });
  const fullPayloadHints = boundedTechniqueStrings(pack.payload_hints, {
    itemLimit: TECHNIQUE_FULL_ITEMS_PER_KIND,
    itemMaxChars: TECHNIQUE_FULL_ITEM_MAX_CHARS,
  });
  const fullLimits = {
    techniques: fullTechniques.limits,
    payload_hints: fullPayloadHints.limits,
  };
  return {
    version: 1,
    mode: normalizedMode,
    source: registry.source ? path.basename(registry.source) : null,
    registry_version: registry.version,
    technique_pack: {
      ...summary,
      full: {
        id: pack.id,
        version: pack.version,
        title: pack.title,
        capability_packs: pack.capability_packs.slice(),
        match: pack.match,
        techniques: fullTechniques.values,
        payload_hints: fullPayloadHints.values,
      },
      full_limits: fullLimits,
    },
    summary_limits: summary.summary_limits,
    full_limits: fullLimits,
    registry_warnings: registry.warnings.slice(),
  };
}

function normalizeOptionalVersionInteger(value, fieldName) {
  if (value == null) return null;
  return assertInteger(value, fieldName, { min: 1, max: 100000 });
}

function addOptionalTechniqueVersionMetadata(normalized, record) {
  const packVersion = normalizeOptionalVersionInteger(record.pack_version, "pack_version");
  const registryVersion = normalizeOptionalVersionInteger(record.registry_version, "registry_version");
  const capabilityPack = normalizeOptionalText(record.capability_pack, "capability_pack");
  const capabilityPackVersion = normalizeOptionalVersionInteger(record.capability_pack_version, "capability_pack_version");

  if (packVersion != null) normalized.pack_version = packVersion;
  if (registryVersion != null) normalized.registry_version = registryVersion;
  if (capabilityPack) {
    if (!getCapabilityPack(capabilityPack)) {
      throw new Error(`Unknown capability_pack: ${capabilityPack}`);
    }
    normalized.capability_pack = capabilityPack;
  }
  if (capabilityPackVersion != null) normalized.capability_pack_version = capabilityPackVersion;
}

function techniqueVersionMetadata(packResult, routeOrAssignment) {
  const packVersion = packResult && packResult.technique_pack
    ? packResult.technique_pack.version
    : null;
  const metadata = {};
  if (Number.isInteger(packVersion) && packVersion > 0) metadata.pack_version = packVersion;
  if (Number.isInteger(packResult && packResult.registry_version) && packResult.registry_version > 0) {
    metadata.registry_version = packResult.registry_version;
  }
  if (routeOrAssignment && routeOrAssignment.capability_pack) {
    metadata.capability_pack = routeOrAssignment.capability_pack;
  }
  if (routeOrAssignment && Number.isInteger(routeOrAssignment.capability_pack_version)) {
    metadata.capability_pack_version = routeOrAssignment.capability_pack_version;
  }
  return metadata;
}

function normalizeTechniquePackReadRecord(record, { expectedDomain = null, lineNumber = null } = {}) {
  if (record == null || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(lineNumber == null
      ? "technique pack read record must be an object"
      : `Malformed technique-pack-reads.jsonl at line ${lineNumber}: expected object`);
  }

  try {
    const read = {
      version: record.version == null
        ? 1
        : assertInteger(record.version, "version", { min: 1, max: 1 }),
      ts: assertNonEmptyString(record.ts, "ts"),
      target_domain: assertNonEmptyString(record.target_domain, "target_domain"),
      wave: parseWaveId(record.wave),
      agent: parseAgentId(record.agent),
      surface_id: assertNonEmptyString(record.surface_id, "surface_id"),
      pack_id: normalizeTechniquePackId(record.pack_id),
      mode: assertEnumValue(record.mode, ["full"], "mode"),
    };
    addOptionalTechniqueVersionMetadata(read, record);
    if (expectedDomain != null && read.target_domain !== expectedDomain) {
      throw new Error("target_domain mismatch");
    }
    return read;
  } catch (error) {
    if (lineNumber == null) {
      throw error;
    }
    throw new Error(`Malformed technique-pack-reads.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
}

function readTechniquePackReadRecordsFromJsonl(domain) {
  const filePath = techniquePackReadsJsonlPath(domain);
  if (!fs.existsSync(filePath)) {
    return [];
  }
  const content = fs.readFileSync(filePath, "utf8");
  if (!content.trim()) {
    return [];
  }

  const records = [];
  const lines = content.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (error) {
      throw new Error(`Malformed technique-pack-reads.jsonl at line ${index + 1}: ${error.message || String(error)}`);
    }
    records.push(normalizeTechniquePackReadRecord(parsed, {
      expectedDomain: domain,
      lineNumber: index + 1,
    }));
  }
  return records;
}

function assertFullReadContext(args) {
  const domain = normalizeOptionalText(args.target_domain, "target_domain");
  const wave = normalizeOptionalText(args.wave, "wave");
  const agent = normalizeOptionalText(args.agent, "agent");
  const surfaceId = normalizeOptionalText(args.surface_id, "surface_id");
  const missing = [];
  if (!domain) missing.push("target_domain");
  if (!wave) missing.push("wave");
  if (!agent) missing.push("agent");
  if (!surfaceId) missing.push("surface_id");
  if (missing.length > 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `mode=full requires ${missing.join(", ")} so full_pack_read_limit can be enforced`,
    );
  }
  return {
    domain,
    wave: parseWaveId(wave),
    agent: parseAgentId(agent),
    surface_id: surfaceId,
  };
}

function assertTechniquePackMatchesCapability(techniquePack, capabilityPack) {
  const capabilityPacks = techniquePack && Array.isArray(techniquePack.capability_packs)
    ? techniquePack.capability_packs
    : [];
  if (!capabilityPacks.includes(capabilityPack)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `technique pack ${techniquePack && techniquePack.id ? techniquePack.id : "(unknown)"} is not compatible with capability_pack ${capabilityPack}`,
    );
  }
}

function assertPackMatchesAssignment(packResult, assignment) {
  assertTechniquePackMatchesCapability(packResult && packResult.technique_pack, assignment.capability_pack);
}

function readTechniquePackForTool(args) {
  const mode = args.mode || "summary";
  if (mode !== "full") {
    return JSON.stringify(readTechniquePack(args.pack_id, { mode }));
  }

  const context = assertFullReadContext(args);
  const packId = normalizeTechniquePackId(args.pack_id);
  const assignment = validateAssignedWaveAgentSurface(
    context.domain,
    context.wave,
    context.agent,
    context.surface_id,
  );
  const full = readTechniquePack(packId, { mode: "full" });
  assertPackMatchesAssignment(full, assignment);

  return withSessionLock(context.domain, () => {
    const existingRecords = readTechniquePackReadRecordsFromJsonl(context.domain);
    const matchingRecords = existingRecords.filter((record) =>
      record.wave === context.wave
      && record.agent === context.agent
      && record.surface_id === context.surface_id
      && record.mode === "full",
    );
    const readPackIds = new Set(matchingRecords.map((record) => record.pack_id));
    const alreadyRead = readPackIds.has(packId);
    const limit = assignment.context_budget.full_pack_read_limit;
    if (!alreadyRead && readPackIds.size >= limit) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `full_pack_read_limit reached for ${context.wave}/${context.agent}/${context.surface_id}: ${readPackIds.size}/${limit}`,
      );
    }

    if (!alreadyRead) {
      appendJsonlLine(techniquePackReadsJsonlPath(context.domain), normalizeTechniquePackReadRecord({
        version: 1,
        ts: new Date().toISOString(),
        target_domain: context.domain,
        wave: context.wave,
        agent: context.agent,
        surface_id: context.surface_id,
        pack_id: packId,
        ...techniqueVersionMetadata(full, assignment),
        mode: "full",
      }, { expectedDomain: context.domain }), { maxRecords: TECHNIQUE_PACK_READ_LOG_MAX_RECORDS });
      readPackIds.add(packId);
    }

    return JSON.stringify({
      ...full,
      full_read_budget: {
        target_domain: context.domain,
        wave: context.wave,
        agent: context.agent,
        surface_id: context.surface_id,
        full_pack_read_limit: limit,
        full_packs_read: readPackIds.size,
        remaining_full_pack_reads: Math.max(0, limit - readPackIds.size),
        already_read: alreadyRead,
        log_path: techniquePackReadsJsonlPath(context.domain),
      },
    });
  });
}

function resolveSurfaceTechniqueRoute(domain, surface, requestedCapabilityPack = null) {
  const routesPath = surfaceRoutesPath(domain);
  let route = null;
  if (fs.existsSync(routesPath)) {
    try {
      const routesInfo = readSurfaceRoutesStrict(domain);
      route = routesInfo.document.routes.find((entry) => entry.surface_id === surface.id) || null;
    } catch {}
  }
  if (!route) {
    route = classifySurfaceCapability(surface);
  }

  const capabilityPack = requestedCapabilityPack || route.capability_pack;
  const pack = getCapabilityPack(capabilityPack);
  if (!pack) {
    throw new Error(`Unknown capability_pack: ${capabilityPack}`);
  }
  if (requestedCapabilityPack && route.capability_pack && requestedCapabilityPack !== route.capability_pack) {
    throw new Error(`surface_id ${surface.id} is routed to capability_pack ${route.capability_pack}`);
  }

  return {
    capability_pack: capabilityPack,
    capability_pack_version: route.capability_pack_version || pack.capability_pack_version,
    brief_profile: route.brief_profile || pack.brief_profile,
    hunter_agent: route.hunter_agent || pack.hunter_agent,
    context_budget: normalizeContextBudget(route.context_budget, pack),
  };
}

function selectTechniquePacks(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  const requestedCapabilityPack = normalizeOptionalText(args.capability_pack, "capability_pack");
  const includeAttempted = args.include_attempted == null ? false : args.include_attempted;
  if (typeof includeAttempted !== "boolean") {
    throw new Error("include_attempted must be a boolean");
  }

  const attackSurface = readAttackSurfaceStrict(domain);
  const surface = attackSurface.document.surfaces.find((entry) => entry && entry.id === surfaceId);
  if (!surface) {
    throw new Error(`Unknown surface_id: ${surfaceId}`);
  }

  const route = resolveSurfaceTechniqueRoute(domain, surface, requestedCapabilityPack);
  const requestedLimit = normalizeOptionalInteger(args.max_packs, "max_packs", { min: 1, max: 50 });
  const maxPacks = Math.min(
    requestedLimit || route.context_budget.candidate_pack_limit,
    route.context_budget.candidate_pack_limit,
  );
  const attempts = readTechniqueAttemptRecordsFromJsonl(domain)
    .filter((record) => record.surface_id === surfaceId);
  const selected = selectTechniquePacksForSurface(surface, {
    capabilityPack: route.capability_pack,
    maxPacks,
    includeAttempted,
    attempts,
  });

  return JSON.stringify({
    version: 1,
    target_domain: domain,
    surface_id: surfaceId,
    capability_pack: route.capability_pack,
    capability_pack_version: route.capability_pack_version,
    brief_profile: route.brief_profile,
    context_budget: route.context_budget,
    max_packs: maxPacks,
    include_attempted: includeAttempted,
    technique_packs: selected.selected,
    selection_limits: selected.selection_limits,
    registry_warnings: selected.registry_warnings,
    attempts_summary: {
      total_for_surface: attempts.length,
      omitted_attempted: selected.omitted_attempted,
    },
  });
}

function fitKnowledgeEntries(entries, maxChars) {
  const selected = [];
  for (const entry of entries) {
    const candidate = selected.concat(entry);
    if (JSON.stringify(candidate).length > maxChars) break;
    selected.push(entry);
  }
  return selected;
}

function resolveHunterKnowledge(surface, {
  capabilityPack = "web",
  maxEntries = HUNTER_KNOWLEDGE_MAX_ENTRIES,
} = {}) {
  const selectedResult = selectTechniquePacksForSurface(surface, {
    capabilityPack,
    maxPacks: maxEntries,
    includeAttempted: true,
  });

  const slimEntries = selectedResult.selected
    .slice(0, maxEntries)
    .map((pack) => ({
      id: pack.id,
      title: pack.title,
      matched: pack.matched.slice(0, 6),
      techniques: pack.summary.guidance.slice(0, 4),
      payload_hints: pack.summary.payload_hints.slice(0, 4),
    }));
  const fittedEntries = fitKnowledgeEntries(slimEntries, HUNTER_KNOWLEDGE_MAX_CHARS);
  let techniques = [];
  let payloadHints = [];
  let charCount = 0;
  while (fittedEntries.length > 0) {
    techniques = fittedEntries.map((entry) => ({
      id: entry.id,
      title: entry.title,
      matched: entry.matched,
      guidance: entry.techniques,
    }));
    payloadHints = fittedEntries
      .filter((entry) => entry.payload_hints.length > 0)
      .map((entry) => ({
        id: entry.id,
        title: entry.title,
        hints: entry.payload_hints,
      }));
    charCount = JSON.stringify({ techniques, payload_hints: payloadHints }).length;
    if (charCount <= HUNTER_KNOWLEDGE_MAX_CHARS) break;
    fittedEntries.pop();
  }
  if (fittedEntries.length === 0) {
    techniques = [];
    payloadHints = [];
    charCount = 0;
  }

  return {
    techniques,
    payload_hints: payloadHints,
    knowledge_summary: {
      source: selectedResult.source ? path.basename(selectedResult.source) : null,
      entries_returned: fittedEntries.length,
      capped: slimEntries.length > fittedEntries.length,
      char_count: charCount,
      max_chars: HUNTER_KNOWLEDGE_MAX_CHARS,
      registry_warnings: selectedResult.registry_warnings,
    },
  };
}

function normalizeTechniqueAttemptRecord(record, { expectedDomain = null, lineNumber = null } = {}) {
  if (record == null || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(lineNumber == null
      ? "technique attempt record must be an object"
      : `Malformed technique-attempts.jsonl at line ${lineNumber}: expected object`);
  }

  try {
    const attempt = {
      version: record.version == null
        ? 1
        : assertInteger(record.version, "version", { min: 1, max: 1 }),
      ts: assertNonEmptyString(record.ts, "ts"),
      target_domain: assertNonEmptyString(record.target_domain, "target_domain"),
      surface_id: assertNonEmptyString(record.surface_id, "surface_id"),
      pack_id: normalizeTechniquePackId(record.pack_id),
      status: assertEnumValue(record.status, TECHNIQUE_ATTEMPT_STATUS_VALUES, "status"),
      evidence: assertRequiredText(record.evidence, "evidence"),
    };
    addOptionalTechniqueVersionMetadata(attempt, record);

    const wave = normalizeOptionalText(record.wave, "wave");
    const agent = normalizeOptionalText(record.agent, "agent");
    const outcome = normalizeOptionalText(record.outcome, "outcome");
    if (wave) attempt.wave = parseWaveId(wave);
    if (agent) attempt.agent = parseAgentId(agent);
    if (outcome) attempt.outcome = outcome;
    if (expectedDomain != null && attempt.target_domain !== expectedDomain) {
      throw new Error("target_domain mismatch");
    }
    return attempt;
  } catch (error) {
    if (lineNumber == null) {
      throw error;
    }
    throw new Error(`Malformed technique-attempts.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
}

function readTechniqueAttemptRecordsFromJsonl(domain) {
  const filePath = techniqueAttemptsJsonlPath(domain);
  if (!fs.existsSync(filePath)) {
    return [];
  }
  const content = fs.readFileSync(filePath, "utf8");
  if (!content.trim()) {
    return [];
  }

  const records = [];
  const lines = content.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (error) {
      throw new Error(`Malformed technique-attempts.jsonl at line ${index + 1}: ${error.message || String(error)}`);
    }
    records.push(normalizeTechniqueAttemptRecord(parsed, {
      expectedDomain: domain,
      lineNumber: index + 1,
    }));
  }
  return records;
}

function summarizeTechniqueAttempt(record) {
  if (!record) return null;
  const summary = {
    pack_id: record.pack_id,
    status: record.status,
    ts: record.ts,
    evidence: record.evidence,
  };
  if (record.outcome) summary.outcome = record.outcome;
  if (record.wave) summary.wave = record.wave;
  if (record.agent) summary.agent = record.agent;
  if (record.surface_id) summary.surface_id = record.surface_id;
  if (record.pack_version != null) summary.pack_version = record.pack_version;
  if (record.registry_version != null) summary.registry_version = record.registry_version;
  if (record.capability_pack) summary.capability_pack = record.capability_pack;
  if (record.capability_pack_version != null) summary.capability_pack_version = record.capability_pack_version;
  return summary;
}

function logTechniqueAttempt(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  const packId = normalizeTechniquePackId(args.pack_id);
  const status = assertEnumValue(args.status, TECHNIQUE_ATTEMPT_STATUS_VALUES, "status");
  const evidence = assertRequiredText(args.evidence, "evidence");
  if (evidence.length > 2000) {
    throw new Error("evidence must be at most 2000 characters");
  }
  const outcome = normalizeOptionalText(args.outcome, "outcome");
  if (outcome && outcome.length > 200) {
    throw new Error("outcome must be at most 200 characters");
  }

  const wave = normalizeOptionalText(args.wave, "wave");
  const agent = normalizeOptionalText(args.agent, "agent");
  if ((wave && !agent) || (agent && !wave)) {
    throw new Error("wave and agent must be provided together");
  }
  const parsedWave = wave ? parseWaveId(wave) : null;
  const parsedAgent = agent ? parseAgentId(agent) : null;

  const packResult = readTechniquePack(packId, { mode: "summary" });
  const attackSurface = readAttackSurfaceStrict(domain);
  const surface = attackSurface.document.surfaces.find((entry) => entry && entry.id === surfaceId);
  if (!surface) {
    throw new Error(`Unknown surface_id: ${surfaceId}`);
  }
  let routeMetadata;
  if (parsedWave && parsedAgent) {
    const assignment = validateAssignedWaveAgentSurface(domain, parsedWave, parsedAgent, surfaceId);
    assertPackMatchesAssignment(packResult, assignment);
    routeMetadata = assignment;
  } else {
    const route = resolveSurfaceTechniqueRoute(domain, surface);
    assertTechniquePackMatchesCapability(packResult.technique_pack, route.capability_pack);
    routeMetadata = route;
  }

  const record = normalizeTechniqueAttemptRecord({
    version: 1,
    ts: new Date().toISOString(),
    target_domain: domain,
    wave: parsedWave,
    agent: parsedAgent,
    surface_id: surfaceId,
    pack_id: packId,
    ...techniqueVersionMetadata(packResult, routeMetadata),
    status,
    outcome,
    evidence,
  }, { expectedDomain: domain });

  return withSessionLock(domain, () => {
    const logPath = techniqueAttemptsJsonlPath(domain);
    appendJsonlLine(logPath, record, { maxRecords: TECHNIQUE_ATTEMPT_LOG_MAX_RECORDS });
    safeAppendPipelineEventDirect(domain, "technique_attempt_logged", {
      wave: parsedWave,
      agent: parsedAgent,
      surface_id: surfaceId,
      status,
      source: "bounty_log_technique_attempt",
      counts: {
        records: 1,
      },
    });
    return JSON.stringify({
      appended: 1,
      log_path: logPath,
      record: summarizeTechniqueAttempt(record),
      registry_warnings: packResult.registry_warnings,
    });
  });
}

module.exports = {
  HUNTER_KNOWLEDGE_FILE,
  HUNTER_KNOWLEDGE_MAX_CHARS,
  HUNTER_KNOWLEDGE_MAX_ENTRIES,
  TECHNIQUE_FULL_ITEM_MAX_CHARS,
  TECHNIQUE_FULL_ITEMS_PER_KIND,
  TECHNIQUE_SELECTION_MAX_CHARS,
  TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
  TECHNIQUE_SUMMARY_ITEMS_PER_KIND,
  hunterKnowledgeCandidatePaths,
  loadHunterKnowledge,
  loadTechniqueRegistry,
  logTechniqueAttempt,
  normalizeTechniqueAttemptRecord,
  readTechniqueAttemptRecordsFromJsonl,
  readTechniquePack,
  readTechniquePackForTool,
  readTechniquePackReadRecordsFromJsonl,
  resolveHunterKnowledge,
  scoreTechniqueEntry,
  selectTechniquePacks,
  selectTechniquePacksForSurface,
  assertTechniquePackMatchesCapability,
  summarizeTechniqueAttempt,
  techniquePackSummary,
};
