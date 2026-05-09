"use strict";

const { indexFinding } = require("../findings-index.js");

function indexFindingHandler(args) {
  return indexFinding({
    target_domain: args.target_domain,
    finding: args.finding,
    calibration_label: args.calibration_label,
  });
}

module.exports = Object.freeze({
  name: "bounty_index_finding",
  description:
    "Compute a hashed-feature-vector embedding for a finding and persist it to findings-index.jsonl. Idempotent by finding_id; later calls upsert the same record. Pass calibration_label after grade adjudication so the same record carries ground-truth signal for future similarity queries.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      finding: {
        type: "object",
        description: "A finding-shaped object with at least finding_id. The vector is built from title, description, attack_class, cwe, endpoint, surface_id, surface_type, tech_stack, evidence_summary, and a truncated proof_of_concept.",
        properties: {
          finding_id: { type: "string" },
          title: { type: "string" },
          description: { type: "string" },
          severity: { type: "string" },
          attack_class: { type: "string" },
          cwe: { type: "string" },
          endpoint: { type: "string" },
          surface_id: { type: "string" },
          surface_type: { type: "string" },
          tech_stack: { type: "array", items: { type: "string" } },
          evidence_summary: { type: "string" },
          proof_of_concept: { type: "string" },
        },
        required: ["finding_id"],
      },
      calibration_label: {
        type: "string",
        description: "Optional ground-truth marker (e.g. 'real', 'rejected_duplicate', 'rejected_intended', 'rejected_oos').",
      },
    },
    required: ["target_domain", "finding"],
  },
  handler: indexFindingHandler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["findings-index.jsonl"],
  hook_required: false,
});
