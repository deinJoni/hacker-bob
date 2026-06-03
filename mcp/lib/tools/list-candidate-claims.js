"use strict";

const { assertNonEmptyString } = require("../validation.js");
const { findingPayloadsFromClaims } = require("./record-candidate-claim.js");

function listCandidateClaims(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const findings = findingPayloadsFromClaims(domain).map((finding) => ({
    id: finding.id,
    severity: finding.severity,
    title: finding.title,
    endpoint: finding.endpoint,
  }));
  return JSON.stringify({
    count: findings.length,
    findings,
  });
}

module.exports = Object.freeze({
  name: "bob_list_candidate_claims",
  aliases: ["bob_list_findings", "bounty_list_findings"],
  description:
    "List all recorded candidate claims for a target. Each row is projected from the claim's inline finding payload.",
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
  handler: listCandidateClaims,
  role_bundles: ["evaluator-shared","orchestrator"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
