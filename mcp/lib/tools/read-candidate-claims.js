"use strict";

const { readFindings } = require("../finding-store.js");

module.exports = Object.freeze({
  name: "bob_read_candidate_claims",
  aliases: ["bob_read_findings", "bounty_read_findings"],
  description:
    "Read all recorded candidate claims (legacy findings) for a target from authoritative structured storage.",
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
  handler: readFindings,
  role_bundles: ["chain","verifier","grader","reporter","evidence"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
