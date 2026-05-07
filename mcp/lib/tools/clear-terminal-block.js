"use strict";

const { clearTerminalBlock } = require("../session-state.js");

module.exports = Object.freeze({
  name: "bounty_clear_terminal_block",
  description:
    "Remove a surface from state.terminally_blocked and record the clear in state.terminal_block_clear_history. Operator-driven: call this only after the missing prerequisite material (auth profile, egress profile, funded wallet, etc.) has been registered. Rejects surfaces that were never terminally blocked, and rejects clearing while a wave is pending — the operator must merge the current wave first. The reason field (>=20 chars) is durable in state.json, not just the pipeline event. Blocked_prereq_history is retained for debugging; the loop detector uses the clear epoch to ignore pre-clear entries.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "surface_id": { "type": "string", "minLength": 1 },
      "reason": {
        "type": "string",
        "minLength": 20,
        "maxLength": 280,
        "description": "Operator note for the audit trail. Required at >= 20 chars to make the unblock auditable.",
      },
    },
    "required": ["target_domain", "surface_id", "reason"],
  },
  handler: clearTerminalBlock,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["state.json"],
  hook_required: false,
});
