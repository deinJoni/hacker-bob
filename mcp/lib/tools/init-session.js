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
      "target_kind": {
        "type": "string",
        "enum": ["web", "repo"],
        "description": "Defaults to web. Repo sessions should normally use bounty_init_repo_session."
      },
      "repo": {
        "type": "object",
        "description": "Repo metadata for target_kind=repo.",
        "properties": {
          "root_path": { "type": "string" },
          "source_url": { "type": "string" },
          "branch": { "type": "string" },
          "commit": { "type": "string" },
          "default_branch": { "type": "string" }
        },
        "required": ["root_path"]
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
  hook_required: false,
});
