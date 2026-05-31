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
  "mcp__bountyagent__bounty_merge_wave_handoffs",
]);
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
  const next = existing && typeof existing === "object" && !Array.isArray(existing)
    ? { ...existing }
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
// role. Optional — registered alongside bountyagent but not required at
// runtime. See prompts/roles/brutalist-verifier.md for the graceful-fallback
// contract.
const BRUTALIST_MCP_SERVER = Object.freeze({
  command: "npx",
  args: ["-y", "@brutalist/mcp@latest"],
});

function mergeMcp(existing, serverPath) {
  const next = existing && typeof existing === "object" && !Array.isArray(existing)
    ? { ...existing }
    : {};
  next.mcpServers = next.mcpServers && typeof next.mcpServers === "object" && !Array.isArray(next.mcpServers)
    ? { ...next.mcpServers }
    : {};
  next.mcpServers.bountyagent = {
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

  writeJson(mcpPath, mergeMcp(readJsonIfExists(mcpPath, {}), serverPath));
  writeJson(settingsPath, mergeSettings(readJsonIfExists(settingsPath, {}), bobSettings));

  console.log(`merged ${mcpPath}`);
  console.log(`merged ${settingsPath}`);
}

if (require.main === module) {
  main();
}

module.exports = {
  BRUTALIST_MCP_SERVER,
  STALE_GLOBAL_MCP_PERMISSIONS,
  STALE_HOOK_SCRIPT_NAMES,
  hookScriptName,
  mergeMcp,
  mergeHookEntries,
  mergeHooks,
  mergePreToolUseHooks,
  mergeSettings,
};
