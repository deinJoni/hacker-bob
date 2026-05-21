"use strict";

const { repoCheck } = require("../repo-target.js");

module.exports = Object.freeze({
  name: "bounty_repo_check",
  description:
    "Run a bounded read-only repo-local evidence check for OSS-mode findings. Checks file existence and optional pattern presence, then appends repo-checks.jsonl.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "check_type": {
        "type": "string",
        "description": "Short label such as file_exists, file_contains, manifest_script, or verifier_replay."
      },
      "file_path": {
        "type": "string",
        "description": "Repo-relative file path to inspect."
      },
      "pattern": {
        "type": "string",
        "description": "Optional literal or regex pattern to search for."
      },
      "regex": {
        "type": "boolean",
        "description": "Treat pattern as a JavaScript regular expression. Defaults to false."
      }
    },
    "required": [
      "target_domain"
    ]
  },
  handler: repoCheck,
  role_bundles: ["orchestrator", "hunter-web", "verifier", "evidence", "grader", "reporter"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["repo-checks.jsonl"],
  hook_required: false,
  repoCheck,
});
