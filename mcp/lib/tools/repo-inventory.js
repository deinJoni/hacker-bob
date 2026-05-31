"use strict";

const { buildRepoInventory } = require("../repo-target.js");

module.exports = Object.freeze({
  name: "bounty_repo_inventory",
  description:
    "Inventory a local repo-target session and write repo-inventory.json plus a compatible attack_surface.json for OSS-mode routing.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "repo_path": {
        "type": "string",
        "description": "Optional override. Defaults to state.repo.root_path."
      }
    },
    "required": [
      "target_domain"
    ]
  },
  handler: buildRepoInventory,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["repo-inventory.json","attack_surface.json"],
  buildRepoInventory,
});
