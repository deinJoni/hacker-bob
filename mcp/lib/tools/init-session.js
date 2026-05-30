"use strict";

const { initSession } = require("../session-state.js");
const { ERROR_CODES, ToolError } = require("../envelope.js");

// Cycle O.1: web-mode init_session refuses target_repo with a structured
// pointer to bob_init_repo_session. Cross-mode sessions are opt-in via a
// separate companion-binding tool (out of scope for O.1).
function handler(args) {
  if (args && args.target_repo != null) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "bob_init_session is the web-mode entrypoint; call bob_init_repo_session to bind a repo target",
      { redirect_to_tool: "bob_init_repo_session" },
    );
  }
  return initSession(args);
}

module.exports = Object.freeze({
  name: "bob_init_session",
  aliases: ["bounty_init_session"],
  description:
    "Initialize a new session state.json for a target domain.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "target_url": {
        "type": "string"
      },
      "deep_mode": {
        "type": "boolean"
      },
      "checkpoint_mode": {
        "type": "string",
        "enum": ["normal", "paranoid", "yolo"],
        "description": "Selected checkpoint mode. normal/yolo keep internal-host blocking opt-in; paranoid defaults block_internal_hosts to true on direct/default egress."
      },
      "block_internal_hosts": {
        "type": "boolean",
        "description": "Force strict direct-egress DNS/private/internal-host blocking for this session."
      },
      "allow_internal_hosts": {
        "type": "boolean",
        "description": "Disable paranoid's default internal-host blocking for explicitly authorized internal/lab programs. Cannot be combined with block_internal_hosts."
      },
      "egress_profile": {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        "description": "Egress profile to bind to this session. Defaults to default."
      }
    },
    "required": [
      "target_domain",
      "target_url"
    ]
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["state.json"],
});
