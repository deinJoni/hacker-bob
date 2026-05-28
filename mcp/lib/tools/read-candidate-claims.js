"use strict";

const { assertNonEmptyString } = require("../validation.js");
const { findingPayloadsFromClaims } = require("./record-candidate-claim.js");

function readCandidateClaimsTool(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    findings: findingPayloadsFromClaims(domain),
  });
}

module.exports = Object.freeze({
  name: "bob_read_candidate_claims",
  aliases: ["bob_read_findings", "bounty_read_findings"],
  description:
    "Read all recorded candidate claims for a target. Returns the embedded finding payloads projected off claims.jsonl.",
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
  handler: readCandidateClaimsTool,
  role_bundles: ["chain","verifier","grader","reporter","evidence"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
