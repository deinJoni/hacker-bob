"use strict";

const { initRepoSession } = require("../repo-target.js");

module.exports = Object.freeze({
  name: "bounty_init_repo_session",
  description:
    "Initialize a Hacker Bob repo-target session for local open-source project review. Returns the generated target_domain/session id.",
  inputSchema: {
    "type": "object",
    "properties": {
      "repo_path": {
        "type": "string",
        "description": "Existing local repository directory to review."
      },
      "target_domain": {
        "type": "string",
        "description": "Optional explicit safe session id. If omitted Bob derives repo-<name>-<hash>."
      },
      "target_id": {
        "type": "string",
        "description": "Alias for target_domain."
      },
      "source_url": {
        "type": "string"
      },
      "branch": {
        "type": "string"
      },
      "commit": {
        "type": "string"
      },
      "deep_mode": {
        "type": "boolean"
      }
    },
    "required": [
      "repo_path"
    ]
  },
  handler: initRepoSession,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["state.json"],
  initRepoSession,
});
