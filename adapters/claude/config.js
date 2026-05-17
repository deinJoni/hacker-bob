"use strict";

const {
  TOOL_MANIFEST,
  TOOLS,
  toolNamesForRoleBundle,
} = require("../../mcp/lib/tool-registry.js");
const {
  mcpToolNamesForRole,
} = require("../../mcp/lib/role-model.js");
const {
  hunterAgentNamesForCapabilityPacks,
} = require("../../mcp/lib/capability-packs.js");

const BASE_PERMISSIONS = Object.freeze([
  "Bash(mkdir *)",
  "Bash(test *)",
  "Bash(cat *)",
  "Bash(ls *)",
  "Bash(sort *)",
  "Bash(wc *)",
  "Bash(head *)",
  "Bash(tail *)",
  "Bash(jq *)",
  "Bash(printf *)",
  "Bash(echo *)",
  "Read",
  "Glob",
  "Grep",
]);

const PROJECT_DIR_EXPR = "${CLAUDE_PROJECT_DIR:-$PWD}";

function mcpPermissionForTool(toolName) {
  return `mcp__bountyagent__${toolName}`;
}

function permissionsForAllTools() {
  return TOOLS.map((tool) => mcpPermissionForTool(tool.name));
}

function permissionsForRoleBundle(roleBundle) {
  return toolNamesForRoleBundle(roleBundle).map(mcpPermissionForTool);
}

function permissionsForRoleBundles(roleBundles) {
  return uniqueStrings(roleBundles.flatMap((roleBundle) => permissionsForRoleBundle(roleBundle)));
}

function permissionsForRole(roleId) {
  return mcpToolNamesForRole(roleId).map(mcpPermissionForTool);
}

function uniqueStrings(values) {
  return Array.from(new Set(values.filter((value) => typeof value === "string" && value.trim())));
}

function isOrchestratorOnlyMutator(toolName) {
  const metadata = TOOL_MANIFEST[toolName];
  return !!metadata &&
    metadata.mutating === true &&
    metadata.role_bundles.length === 1 &&
    metadata.role_bundles[0] === "orchestrator";
}

function defaultGlobalMcpPermissions() {
  return TOOLS
    .map((tool) => tool.name)
    .filter((toolName) => TOOL_MANIFEST[toolName].global_preapproval === true)
    .map(mcpPermissionForTool);
}

function defaultPreToolUseHooks() {
  return [
    {
      matcher: "Bash",
      hooks: [
        {
          type: "command",
          command: `bash "${PROJECT_DIR_EXPR}/.claude/hooks/session-write-guard.sh"`,
          timeout: 5,
        },
        {
          type: "command",
          command: `bash "${PROJECT_DIR_EXPR}/.claude/hooks/session-read-guard.sh"`,
          timeout: 5,
        },
      ],
    },
    {
      matcher: "Read",
      hooks: [
        {
          type: "command",
          command: `bash "${PROJECT_DIR_EXPR}/.claude/hooks/session-read-guard.sh"`,
          timeout: 5,
        },
      ],
    },
    {
      matcher: "Write",
      hooks: [
        {
          type: "command",
          command: `bash "${PROJECT_DIR_EXPR}/.claude/hooks/session-write-guard.sh"`,
          timeout: 5,
        },
      ],
    },
  ];
}

function defaultSubagentStopHooks() {
  return hunterAgentNamesForCapabilityPacks().map((hunterAgent) => (
    {
      matcher: hunterAgent,
      hooks: [
        {
          type: "command",
          command: `node "${PROJECT_DIR_EXPR}/.claude/hooks/hunter-subagent-stop.js"`,
          timeout: 10,
        },
      ],
    }
  ));
}

function defaultSessionStartHooks() {
  return [
    {
      matcher: "startup",
      hooks: [
        {
          type: "command",
          command: `node "${PROJECT_DIR_EXPR}/.claude/hooks/bob-check-update.js" "${PROJECT_DIR_EXPR}"`,
          timeout: 2,
        },
      ],
    },
  ];
}

function bountyagentSkillAllowedTools() {
  return uniqueStrings([
    "Task",
    "Read",
    ...permissionsForRole("orchestrator"),
  ]);
}

function defaultClaudeSettings() {
  return {
    permissions: {
      allow: uniqueStrings([
        ...defaultGlobalMcpPermissions(),
        ...BASE_PERMISSIONS,
      ]),
    },
    hooks: {
      PreToolUse: defaultPreToolUseHooks(),
      SessionStart: defaultSessionStartHooks(),
      SubagentStop: defaultSubagentStopHooks(),
    },
    statusLine: {
      type: "command",
      command: `node "${PROJECT_DIR_EXPR}/.claude/hooks/bounty-statusline.js"`,
    },
  };
}

module.exports = {
  BASE_PERMISSIONS,
  bountyagentSkillAllowedTools,
  defaultClaudeSettings,
  defaultGlobalMcpPermissions,
  defaultPreToolUseHooks,
  defaultSessionStartHooks,
  defaultSubagentStopHooks,
  isOrchestratorOnlyMutator,
  mcpPermissionForTool,
  permissionsForAllTools,
  permissionsForRole,
  permissionsForRoleBundle,
  permissionsForRoleBundles,
};
