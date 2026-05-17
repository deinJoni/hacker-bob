"use strict";

const { parseUnifiedDiff } = require("../unified-diff-parser.js");
const { summarizeImpactedSurfacesForDiff } = require("../symbol-surface-index.js");

function summarizeDiffImpactHandler(args) {
  let diffFiles = args.diff_files;
  let parseSummary = null;
  if (typeof args.unified_diff === "string" && args.unified_diff.length > 0) {
    parseSummary = parseUnifiedDiff(args.unified_diff);
    diffFiles = parseSummary.diff_files;
  }
  if (!Array.isArray(diffFiles)) {
    throw new TypeError("diff_files must be an array, or unified_diff must be supplied");
  }
  const result = summarizeImpactedSurfacesForDiff({
    target_domain: args.target_domain,
    diff_files: diffFiles,
  });
  return {
    schema_version: 1,
    target_domain: args.target_domain,
    parse_summary: parseSummary,
    impacted_surface_ids: result.impacted_surface_ids,
    impacted_entries: result.impacted_entries,
    scanned_files: result.scanned_files,
  };
}

module.exports = Object.freeze({
  name: "bounty_summarize_diff_impact",
  description:
    "Given a unified diff (or pre-parsed diff_files) and a target's symbol-surface-index, return the surface IDs the diff touches. Pass unified_diff to let the tool parse + intersect in one call, or pass diff_files: [{file, line_ranges?}] when you've already parsed elsewhere. The orchestrator can feed the returned impacted_surface_ids into bounty_start_wave for a focused diff-aware regression hunt.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      unified_diff: {
        type: "string",
        description: "Raw unified diff text (e.g. output of `git diff <base>..<head>` or a webhook payload).",
      },
      diff_files: {
        type: "array",
        description: "Pre-parsed [{file, line_ranges?}] entries; supplied when the caller has already parsed the diff. line_ranges defaults to whole-file when omitted.",
      },
    },
    required: ["target_domain"],
  },
  handler: summarizeDiffImpactHandler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
