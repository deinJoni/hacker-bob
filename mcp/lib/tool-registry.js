"use strict";

const { TOOL_MODULES } = require("./tools/index.js");
const { chainSpecificEvaluatorBundles } = require("./capability-packs.js");

// Cycle P.1 of the frontier-topology realization hypergraph renames the public
// MCP tool surface from `bounty_*` to `bob_*`. Every tool declares a `bob_*`
// primary name in its module and optionally an `aliases: ["bounty_*"]` array.
// The registry materializes one alias entry per alias, routed to the same
// handler with a `deprecated: true` descriptor. Invoking an alias appends a
// `governance.tool_deprecated` event to session-events.jsonl when a
// target_domain is in scope; the alias mechanism lives here so individual
// tool files do not need separate shim modules. Aliases are time-bound to
// the v2.0.0 → v2.1.0 window per hypergraph Part IX.
const ALIAS_DEPRECATION_REPLACEMENT_HINT = "bob_*";

// Cross-cutting role bundles: orchestration, auth, verifier, evidence, etc.
// — not chain-specific. The per-chain evaluator bundles are derived from
// EVALUATOR_ROLES in capability-packs.js so adding a 7th evaluator role extends
// VALID_ROLE_BUNDLES automatically without editing this file.
const CROSS_CUTTING_ROLE_BUNDLES = Object.freeze([
  "auth",
  "chain",
  "evidence",
  "grader",
  "evaluator-shared",
  "evaluator-web",
  "orchestrator",
  "reporter",
  "router",
  "verifier",
]);

const VALID_ROLE_BUNDLES = Object.freeze([
  ...CROSS_CUTTING_ROLE_BUNDLES,
  ...chainSpecificEvaluatorBundles(),
]);
const CAPABILITY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const REMOVED_TOOL_FIELDS = Object.freeze([
  ["hook", "required"].join("_"),
]);
const REQUIRED_FIELDS = Object.freeze([
  "name",
  "description",
  "inputSchema",
  "handler",
  "role_bundles",
  "mutating",
  "global_preapproval",
  "network_access",
  "browser_access",
  "scope_required",
  "sensitive_output",
  "session_artifacts_written",
]);

function assertBooleanField(entry, field) {
  if (typeof entry[field] !== "boolean") {
    throw new Error(`tool registry entry for ${entry.name} has invalid ${field}`);
  }
}

function assertStringArrayField(entry, field, { allowEmpty = true, validValues = null } = {}) {
  const value = entry[field];
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) {
    throw new Error(`tool registry entry for ${entry.name} has invalid ${field}`);
  }
  for (const item of value) {
    if (typeof item !== "string" || !item.trim()) {
      throw new Error(`tool registry entry for ${entry.name} has invalid ${field}`);
    }
    if (validValues && !validValues.includes(item)) {
      throw new Error(`tool registry entry for ${entry.name} has unknown role bundle ${item}`);
    }
  }
}

function cloneJsonCompatible(value) {
  if (Array.isArray(value)) {
    return value.map(cloneJsonCompatible);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, cloneJsonCompatible(child)]));
  }
  return value;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const child of Object.values(value)) {
    deepFreeze(child);
  }
  return Object.freeze(value);
}

function frozenStringArray(value) {
  return Object.freeze(value.slice());
}

function normalizeCapabilityId(entry) {
  if (!Object.prototype.hasOwnProperty.call(entry, "capability_id")) {
    return null;
  }
  if (typeof entry.capability_id !== "string" || !CAPABILITY_ID_PATTERN.test(entry.capability_id)) {
    throw new Error(`tool registry entry for ${entry.name} has invalid capability_id`);
  }
  return entry.capability_id;
}

function normalizeScopeUrlFields(entry) {
  if (!Object.prototype.hasOwnProperty.call(entry, "scope_url_fields")) {
    return [];
  }
  assertStringArrayField(entry, "scope_url_fields");
  const properties = entry.inputSchema && entry.inputSchema.properties && typeof entry.inputSchema.properties === "object"
    ? entry.inputSchema.properties
    : {};
  for (const field of entry.scope_url_fields) {
    if (!Object.prototype.hasOwnProperty.call(properties, field)) {
      throw new Error(`tool registry entry for ${entry.name} has unknown scope_url_fields item ${field}`);
    }
  }
  if (entry.scope_url_fields.length > 0 && entry.scope_required !== true) {
    throw new Error(`tool registry entry for ${entry.name} declares scope_url_fields without scope_required`);
  }
  return Object.freeze(entry.scope_url_fields.slice());
}

function normalizeAliases(entry) {
  if (!Object.prototype.hasOwnProperty.call(entry, "aliases")) {
    return Object.freeze([]);
  }
  if (!Array.isArray(entry.aliases)) {
    throw new Error(`tool registry entry for ${entry.name} has invalid aliases (must be array)`);
  }
  for (const alias of entry.aliases) {
    if (typeof alias !== "string" || !alias.trim()) {
      throw new Error(`tool registry entry for ${entry.name} has invalid alias entry`);
    }
    if (alias === entry.name) {
      throw new Error(`tool registry entry for ${entry.name} aliases itself`);
    }
  }
  return frozenStringArray(entry.aliases);
}

function defineTool(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    throw new Error("tool registry entry must be an object");
  }
  for (const field of REMOVED_TOOL_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(entry, field)) {
      throw new Error(`tool registry entry for ${entry.name || "<unknown>"} declares removed hook authority metadata`);
    }
  }
  for (const field of REQUIRED_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(entry, field)) {
      throw new Error(`tool registry entry for ${entry.name || "<unknown>"} missing ${field}`);
    }
  }
  if (typeof entry.name !== "string" || !entry.name.trim()) {
    throw new Error("tool registry entry has invalid name");
  }
  if (typeof entry.description !== "string" || !entry.description.trim()) {
    throw new Error(`tool registry entry for ${entry.name} has invalid description`);
  }
  if (!entry.inputSchema || typeof entry.inputSchema !== "object" || Array.isArray(entry.inputSchema)) {
    throw new Error(`tool registry entry for ${entry.name} has invalid inputSchema`);
  }
  if (typeof entry.handler !== "function") {
    throw new Error(`tool registry entry for ${entry.name} has no handler`);
  }
  assertStringArrayField(entry, "role_bundles", { allowEmpty: false, validValues: VALID_ROLE_BUNDLES });
  assertBooleanField(entry, "mutating");
  assertBooleanField(entry, "global_preapproval");
  assertBooleanField(entry, "network_access");
  assertBooleanField(entry, "browser_access");
  assertBooleanField(entry, "scope_required");
  assertBooleanField(entry, "sensitive_output");
  assertStringArrayField(entry, "session_artifacts_written");
  return Object.freeze({
    ...entry,
    inputSchema: deepFreeze(cloneJsonCompatible(entry.inputSchema)),
    role_bundles: frozenStringArray(entry.role_bundles),
    session_artifacts_written: frozenStringArray(entry.session_artifacts_written),
    capability_id: normalizeCapabilityId(entry),
    scope_url_fields: normalizeScopeUrlFields(entry),
    aliases: normalizeAliases(entry),
  });
}

function aliasDescriptionFor(primaryName, aliasName, primaryDescription) {
  return `Deprecated alias for ${primaryName}. Prefer ${primaryName}; this entry routes to the same handler and records a governance.tool_deprecated event when invoked. Original description: ${primaryDescription}`;
}

// Lazily require session-events to avoid an import cycle (session-events ->
// validation -> paths -> ... -> tool-registry at module-load time on some
// build paths). The alias handler emits a best-effort telemetry event; if the
// dependency cannot be loaded yet, the alias still executes the primary
// handler. The recorder is wrapped in try/catch so registry boot never fails
// when session-events is mid-construction.
let _appendSessionEvent = null;
function recordToolDeprecation({ aliasName, primaryName, args }) {
  try {
    if (!_appendSessionEvent) {
      _appendSessionEvent = require("./session-events.js").appendSessionEvent;
    }
    const targetDomain = args && typeof args === "object" && !Array.isArray(args)
      ? args.target_domain
      : null;
    if (typeof targetDomain !== "string" || !targetDomain.trim()) {
      return;
    }
    _appendSessionEvent({
      target_domain: targetDomain,
      kind: "governance.tool_deprecated",
      payload: {
        tool: aliasName,
        replacement: primaryName,
        rename_cycle: "P.1",
        removal_release: "v2.1.0",
      },
    });
  } catch {
    // Deprecation telemetry must never break the primary call. The alias is
    // an observational, time-bound compatibility surface.
  }
}

function buildAliasEntry(primary, aliasName) {
  const primaryName = primary.name;
  const aliasHandler = (args) => {
    recordToolDeprecation({ aliasName, primaryName, args });
    return primary.handler(args);
  };
  return Object.freeze({
    name: aliasName,
    description: aliasDescriptionFor(primaryName, aliasName, primary.description),
    inputSchema: primary.inputSchema,
    handler: aliasHandler,
    role_bundles: primary.role_bundles,
    mutating: primary.mutating,
    global_preapproval: primary.global_preapproval,
    network_access: primary.network_access,
    browser_access: primary.browser_access,
    scope_required: primary.scope_required,
    sensitive_output: primary.sensitive_output,
    session_artifacts_written: primary.session_artifacts_written,
    capability_id: primary.capability_id,
    scope_url_fields: primary.scope_url_fields,
    aliases: Object.freeze([]),
    deprecated: true,
    alias_of: primaryName,
  });
}

function buildToolRegistry({
  toolModules = TOOL_MODULES,
} = {}) {
  const seenNames = new Set();
  const entries = [];
  for (const entry of toolModules) {
    const tool = defineTool(entry);
    if (seenNames.has(tool.name)) {
      throw new Error(`Duplicate tool name in registry: ${tool.name}`);
    }
    seenNames.add(tool.name);
    entries.push(tool);
    for (const aliasName of tool.aliases) {
      if (seenNames.has(aliasName)) {
        throw new Error(`Duplicate tool name in registry (alias collision): ${aliasName}`);
      }
      seenNames.add(aliasName);
      entries.push(buildAliasEntry(tool, aliasName));
    }
  }
  return Object.freeze(entries);
}

const TOOL_REGISTRY = buildToolRegistry();

const TOOL_BY_NAME = new Map(TOOL_REGISTRY.map((tool) => [tool.name, tool]));

function getRegisteredTool(name) {
  return TOOL_BY_NAME.get(name) || null;
}

// Cycle P.1 deprecation aliases are routed by the registry but not surfaced in
// the discoverable tool list. Existing clients that hard-coded a bounty_* name
// can still invoke through TOOL_HANDLERS; the public tools/list catalog only
// advertises the canonical bob_* (or the bona fide deprecation-shim tools that
// own their own module).
const TOOLS = Object.freeze(TOOL_REGISTRY
  .filter((tool) => !tool.alias_of)
  .map((tool) => Object.freeze({
    name: tool.name,
    description: tool.description,
    inputSchema: tool.inputSchema,
  })));

// TOOL_MANIFEST surfaces only primary tools (and pre-existing standalone
// deprecation shims like bounty_transition_phase / bounty_report_written that
// each ship as their own module). Cycle P.1 aliases are registry-only
// compatibility entries; they share their primary's metadata so the alias
// manifest entry would be a perfect duplicate. Excluding them keeps tests and
// permission generators that iterate the manifest from double-counting.
const TOOL_MANIFEST = Object.freeze(TOOL_REGISTRY.reduce((manifest, tool) => {
  if (tool.alias_of) return manifest;
  const base = {
    role_bundles: frozenStringArray(tool.role_bundles),
    mutating: tool.mutating,
    global_preapproval: tool.global_preapproval,
    network_access: tool.network_access,
    browser_access: tool.browser_access,
    scope_required: tool.scope_required,
    sensitive_output: tool.sensitive_output,
    session_artifacts_written: frozenStringArray(tool.session_artifacts_written),
    capability_id: tool.capability_id,
    scope_url_fields: frozenStringArray(tool.scope_url_fields),
  };
  if (Array.isArray(tool.aliases) && tool.aliases.length > 0) {
    base.aliases = frozenStringArray(tool.aliases);
  }
  manifest[tool.name] = Object.freeze(base);
  return manifest;
}, {}));

const TOOL_HANDLERS = Object.freeze(TOOL_REGISTRY.reduce((handlers, tool) => {
  handlers[tool.name] = tool.handler;
  return handlers;
}, {}));

function toolNamesForRoleBundle(roleBundle) {
  // Returns only primary tool names. Alias entries inherit the role bundles of
  // their primary so deprecated callers still resolve, but role-bundle
  // permission lists must surface the canonical name to avoid double-counting.
  return TOOL_REGISTRY
    .filter((tool) => !tool.alias_of && tool.role_bundles.includes(roleBundle))
    .map((tool) => tool.name);
}

function isAliasName(toolName) {
  const tool = TOOL_BY_NAME.get(toolName);
  return !!(tool && tool.alias_of);
}

function aliasNamesForTool(toolName) {
  const tool = TOOL_BY_NAME.get(toolName);
  return tool && Array.isArray(tool.aliases) ? tool.aliases.slice() : [];
}

function primaryToolName(toolName) {
  const tool = TOOL_BY_NAME.get(toolName);
  if (!tool) return null;
  return tool.alias_of || tool.name;
}

function capabilityToolMapFromRegistry(registry = TOOL_REGISTRY) {
  const map = {};
  for (const tool of registry) {
    if (tool.capability_id == null) continue;
    if (tool.alias_of) continue;
    if (!Object.prototype.hasOwnProperty.call(map, tool.capability_id)) {
      map[tool.capability_id] = [];
    }
    map[tool.capability_id].push(tool.name);
  }
  for (const capabilityId of Object.keys(map)) {
    map[capabilityId] = Object.freeze(map[capabilityId].slice());
  }
  return Object.freeze(map);
}

module.exports = {
  TOOL_HANDLERS,
  TOOL_MANIFEST,
  TOOL_REGISTRY,
  TOOLS,
  VALID_ROLE_BUNDLES,
  aliasNamesForTool,
  buildToolRegistry,
  capabilityToolMapFromRegistry,
  defineTool,
  getRegisteredTool,
  isAliasName,
  primaryToolName,
  toolNamesForRoleBundle,
};
