"use strict";

const { assertNonEmptyString } = require("../validation.js");
const { findingPayloadsFromClaims } = require("./record-candidate-claim.js");
const { deriveCvss31 } = require("../cvss31.js");

// Attach a server-derived CVSS v3.1 base summary to each finding in the read
// response. This is read-only and additive: the band is computed at read time
// from the finding's persisted cvss_inputs and placed on a fresh per-finding
// copy, so the hashed finding projected by findingPayloadsFromClaims is never
// mutated and other consumers of that shared projection are unaffected. The
// band is an informational sanity signal for the grader; it never gates or
// scores anything. Findings with absent/incomplete inputs carry the explicit
// insufficient marker that deriveCvss31 returns instead of a fabricated vector.
function withDerivedCvss(finding) {
  if (!finding || typeof finding !== "object") return finding;
  return { ...finding, cvss: deriveCvss31(finding.cvss_inputs) };
}

function readCandidateClaimsTool(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    findings: findingPayloadsFromClaims(domain).map(withDerivedCvss),
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
