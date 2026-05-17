"use strict";

const { writeEvidencePacks } = require("../evidence.js");

module.exports = Object.freeze({
  name: "bounty_write_evidence_packs",
  description:
    "Write bounded evidence packs for every final reportable finding to authoritative JSON plus a markdown mirror.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      packs: {
        type: "array",
        items: {
          type: "object",
          properties: {
            finding_id: { type: "string", pattern: "^F-[1-9][0-9]*$" },
            sample_type: { type: "string" },
            sample_count: { type: "number", minimum: 0, maximum: 1000 },
            aggregate_counts: {
              type: "object",
              additionalProperties: { type: "number", minimum: 0 },
            },
            representative_samples: {
              type: "array",
              maxItems: 10,
              items: {
                type: "object",
                additionalProperties: true,
              },
            },
            sensitive_clusters: {
              type: "array",
              maxItems: 20,
              items: {
                oneOf: [
                  { type: "string" },
                  { type: "object", additionalProperties: true },
                ],
              },
            },
            replay_summary: { type: "string" },
            redaction_notes: { type: ["string", "null"] },
            report_snippet: { type: "string" },
          },
          required: [
            "finding_id",
            "sample_type",
            "sample_count",
            "aggregate_counts",
            "representative_samples",
            "sensitive_clusters",
            "replay_summary",
            "redaction_notes",
            "report_snippet",
          ],
        },
      },
    },
    required: ["target_domain", "packs"],
  },
  handler: writeEvidencePacks,
  role_bundles: ["evidence"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["evidence-packs.json", "evidence-packs.md", "verification-manifest.json"],
});
