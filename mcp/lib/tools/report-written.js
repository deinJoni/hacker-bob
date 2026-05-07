"use strict";

const { reportWritten } = require("../session-state.js");

module.exports = Object.freeze({
  name: "bounty_report_written",
  description:
    "Mark report.md as written for this session. Verifies the file exists, then emits a report_written pipeline event so analytics distinguishes 'no findings, exhausted' from 'no findings, blocked' from 'no findings, report just written'. Idempotent: subsequent calls re-emit the event without rejecting.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
    },
    "required": ["target_domain"],
  },
  handler: reportWritten,
  role_bundles: ["reporter", "orchestrator"],
  // Appends a row to pipeline-events.jsonl; mutating: true reflects the
  // side effect honestly and surfaces the artifact in
  // session_artifacts_written for audit.
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["pipeline-events.jsonl"],
  hook_required: false,
});
