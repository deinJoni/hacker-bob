"use strict";

const { listFindings } = require("../finding-store.js");

module.exports = Object.freeze({
  name: "bob_list_candidate_claims",
  aliases: ["bob_list_findings", "bounty_list_findings"],
  description:
    "List all recorded candidate claims (legacy findings) for a target.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      }
    },
    "required": [
      "target_domain"
    ]
  },
  handler: listFindings,
  role_bundles: ["evaluator-shared","orchestrator"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
