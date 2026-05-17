"use strict";

const { initSession } = require("../session-state.js");

module.exports = Object.freeze({
  name: "bounty_init_session",
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
  handler: initSession,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["state.json"],
});
