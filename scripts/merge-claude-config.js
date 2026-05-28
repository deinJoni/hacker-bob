#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const {
  defaultClaudeSettings,
} = require("../adapters/claude/config.js");
const {
  STALE_HOOK_SCRIPT_NAMES,
} = require("./lib/package-policy.js");

function readJsonIfExists(filePath, fallback) {
  if (!fs.existsSync(filePath)) return fallback;
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function uniqueStrings(values) {
  return Array.from(new Set(values.filter((value) => typeof value === "string" && value.trim())));
}

const STALE_GLOBAL_MCP_PERMISSIONS = Object.freeze([
  "mcp__hacker-bob__bob_merge_wave_handoffs",
  "mcp__bountyagent__bob_merge_wave_handoffs",
]);

// Legacy MCP server key from v1.x installs. v2.0.0 renames the server key to
// `hacker-bob` and rewrites permission strings accordingly. The migration shim
// (`migrateLegacyServerKey`) auto-rewrites existing `.mcp.json` and
// `.claude/settings.json` files on install/update so operator-managed sibling
// servers and custom permissions are preserved.
const LEGACY_SERVER_KEY = "bountyagent";
const CANONICAL_SERVER_KEY = "hacker-bob";
const LEGACY_PERMISSION_PREFIX = `mcp__${LEGACY_SERVER_KEY}__`;
const CANONICAL_PERMISSION_PREFIX = `mcp__${CANONICAL_SERVER_KEY}__`;

function rewriteLegacyPermissionString(value) {
  if (typeof value !== "string") return value;
  if (!value.startsWith(LEGACY_PERMISSION_PREFIX)) return value;
  return `${CANONICAL_PERMISSION_PREFIX}${value.slice(LEGACY_PERMISSION_PREFIX.length)}`;
}

function migrateLegacyMcp(existing) {
  if (!existing || typeof existing !== "object" || Array.isArray(existing)) {
    return { value: existing, migrated: false };
  }
  if (!existing.mcpServers || typeof existing.mcpServers !== "object" || Array.isArray(existing.mcpServers)) {
    return { value: existing, migrated: false };
  }
  if (!Object.prototype.hasOwnProperty.call(existing.mcpServers, LEGACY_SERVER_KEY)) {
    return { value: existing, migrated: false };
  }
  // Idempotency: if the canonical key already exists alongside the legacy key,
  // drop the legacy key without overwriting the operator-current canonical
  // entry.
  const nextServers = { ...existing.mcpServers };
  const legacyEntry = nextServers[LEGACY_SERVER_KEY];
  delete nextServers[LEGACY_SERVER_KEY];
  if (!Object.prototype.hasOwnProperty.call(nextServers, CANONICAL_SERVER_KEY)) {
    nextServers[CANONICAL_SERVER_KEY] = legacyEntry;
  }
  return {
    value: { ...existing, mcpServers: nextServers },
    migrated: true,
  };
}

function migrateLegacySettings(existing) {
  if (!existing || typeof existing !== "object" || Array.isArray(existing)) {
    return { value: existing, migrated: false };
  }
  if (!existing.permissions || typeof existing.permissions !== "object") {
    return { value: existing, migrated: false };
  }
  const allow = Array.isArray(existing.permissions.allow) ? existing.permissions.allow : null;
  if (!allow) {
    return { value: existing, migrated: false };
  }
  let touched = false;
  const rewritten = allow.map((permission) => {
    const next = rewriteLegacyPermissionString(permission);
    if (next !== permission) touched = true;
    return next;
  });
  if (!touched) return { value: existing, migrated: false };
  // Idempotency: dedupe in case both the legacy and canonical permission
  // strings already coexist (e.g. operator added a custom mcp__hacker-bob__*
  // permission before the migration ran).
  const deduped = uniqueStrings(rewritten);
  return {
    value: {
      ...existing,
      permissions: {
        ...existing.permissions,
        allow: deduped,
      },
    },
    migrated: true,
  };
}

function migrateLegacyServerKey({ mcp, settings, logger } = {}) {
  const mcpResult = migrateLegacyMcp(mcp);
  const settingsResult = migrateLegacySettings(settings);
  if (logger && (mcpResult.migrated || settingsResult.migrated)) {
    const surfaces = [];
    if (mcpResult.migrated) surfaces.push(".mcp.json");
    if (settingsResult.migrated) surfaces.push(".claude/settings.json");
    logger(`migrating legacy MCP server key ${LEGACY_SERVER_KEY} -> ${CANONICAL_SERVER_KEY} in: ${surfaces.join(", ")}`);
  }
  return {
    mcp: mcpResult.value,
    settings: settingsResult.value,
    migrated: mcpResult.migrated || settingsResult.migrated,
  };
}

function hookKey(hook) {
  return JSON.stringify({
    type: hook && hook.type,
    command: hook && hook.command,
    timeout: hook && hook.timeout,
  });
}

function hookScriptName(command) {
  const match = String(command || "").match(/\.claude\/hooks\/([^"'\s]+)/);
  return match ? match[1] : null;
}

function isStaleHook(hook) {
  const scriptName = hookScriptName(hook && hook.command);
  return !!scriptName && STALE_HOOK_SCRIPT_NAMES.includes(scriptName);
}

function mergeHookEntries(existingHooks, bobHooks) {
  const byMatcher = new Map();
  for (const entry of [...(Array.isArray(existingHooks) ? existingHooks : [])]) {
    if (!entry || typeof entry.matcher !== "string") continue;
    const existingEntryHooks = Array.isArray(entry.hooks) ? entry.hooks : [];
    const hooks = existingEntryHooks.filter((hook) => !isStaleHook(hook));
    if (existingEntryHooks.length > 0 && hooks.length === 0) continue;
    byMatcher.set(entry.matcher, {
      ...entry,
      hooks,
    });
  }

  for (const bobEntry of bobHooks) {
    const current = byMatcher.get(bobEntry.matcher) || { matcher: bobEntry.matcher, hooks: [] };
    for (const hook of bobEntry.hooks || []) {
      const scriptName = hookScriptName(hook.command);
      if (scriptName) {
        current.hooks = current.hooks.filter((existingHook) => (
          hookScriptName(existingHook.command) !== scriptName ||
          hookKey(existingHook) === hookKey(hook)
        ));
      }
      const seen = new Set(current.hooks.map(hookKey));
      const key = hookKey(hook);
      if (seen.has(key)) continue;
      current.hooks.push({ ...hook });
    }
    byMatcher.set(bobEntry.matcher, current);
  }

  return Array.from(byMatcher.values());
}

function mergePreToolUseHooks(existingHooks, bobHooks) {
  return mergeHookEntries(existingHooks, bobHooks);
}

function mergeHooks(existingHooks, bobHooks) {
  const next = existingHooks && typeof existingHooks === "object" && !Array.isArray(existingHooks)
    ? { ...existingHooks }
    : {};
  const bob = bobHooks && typeof bobHooks === "object" && !Array.isArray(bobHooks)
    ? bobHooks
    : {};

  for (const [eventName, bobEntries] of Object.entries(bob)) {
    next[eventName] = mergeHookEntries(next[eventName], bobEntries);
  }
  return next;
}

function mergeSettings(existing, bobSettings) {
  const migrated = migrateLegacySettings(existing).value;
  const next = migrated && typeof migrated === "object" && !Array.isArray(migrated)
    ? { ...migrated }
    : {};
  const existingPermissions = next.permissions && typeof next.permissions === "object"
    ? next.permissions
    : {};
  const existingAllow = Array.isArray(existingPermissions.allow) ? existingPermissions.allow : [];
  next.permissions = {
    ...existingPermissions,
    allow: uniqueStrings([
      ...existingAllow.filter((permission) => !STALE_GLOBAL_MCP_PERMISSIONS.includes(permission)),
      ...bobSettings.permissions.allow,
    ]),
  };

  const existingHooks = next.hooks && typeof next.hooks === "object" ? next.hooks : {};
  next.hooks = mergeHooks(existingHooks, bobSettings.hooks);
  next.statusLine = bobSettings.statusLine;
  return next;
}

// External adversarial-roast MCP server consumed by the brutalist-verifier
// role. Optional — registered alongside hacker-bob but not required at
// runtime. See prompts/roles/brutalist-verifier.md for the graceful-fallback
// contract.
const BRUTALIST_MCP_SERVER = Object.freeze({
  command: "npx",
  args: ["-y", "@brutalist/mcp@latest"],
});

function mergeMcp(existing, serverPath) {
  const migrated = migrateLegacyMcp(existing).value;
  const next = migrated && typeof migrated === "object" && !Array.isArray(migrated)
    ? { ...migrated }
    : {};
  next.mcpServers = next.mcpServers && typeof next.mcpServers === "object" && !Array.isArray(next.mcpServers)
    ? { ...next.mcpServers }
    : {};
  next.mcpServers[CANONICAL_SERVER_KEY] = {
    command: "node",
    args: [serverPath],
  };
  next.mcpServers.brutalist = { ...BRUTALIST_MCP_SERVER, args: [...BRUTALIST_MCP_SERVER.args] };
  return next;
}

function main() {
  const target = path.resolve(process.argv[2] || ".");
  const serverPath = path.join(target, "mcp", "server.js");
  const mcpPath = path.join(target, ".mcp.json");
  const settingsPath = path.join(target, ".claude", "settings.json");
  const bobSettings = defaultClaudeSettings();

  // Migration shim: rewrite any legacy `bountyagent` server key + permission
  // strings to `hacker-bob` before the regular merge step. Idempotent; no-op
  // when the canonical key is already present.
  const existingMcp = readJsonIfExists(mcpPath, {});
  const existingSettings = readJsonIfExists(settingsPath, {});
  const migration = migrateLegacyServerKey({
    mcp: existingMcp,
    settings: existingSettings,
    logger: (message) => console.log(message),
  });

  writeJson(mcpPath, mergeMcp(migration.mcp, serverPath));
  writeJson(settingsPath, mergeSettings(migration.settings, bobSettings));

  console.log(`merged ${mcpPath}`);
  console.log(`merged ${settingsPath}`);
}

if (require.main === module) {
  main();
}

module.exports = {
  BRUTALIST_MCP_SERVER,
  CANONICAL_SERVER_KEY,
  LEGACY_SERVER_KEY,
  LEGACY_PERMISSION_PREFIX,
  CANONICAL_PERMISSION_PREFIX,
  STALE_GLOBAL_MCP_PERMISSIONS,
  STALE_HOOK_SCRIPT_NAMES,
  hookScriptName,
  mergeMcp,
  mergeHookEntries,
  mergeHooks,
  mergePreToolUseHooks,
  mergeSettings,
  migrateLegacyMcp,
  migrateLegacySettings,
  migrateLegacyServerKey,
  rewriteLegacyPermissionString,
};
