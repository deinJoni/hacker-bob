"use strict";

const {
  queryFindingsForTarget,
  queryFindingsCrossTarget,
} = require("../findings-index.js");

function queryFindingsIndexHandler(args) {
  const opts = {
    query_text: args.query_text,
    top_k: args.top_k,
    severity_filter: args.severity_filter,
    attack_class_filter: args.attack_class_filter,
  };
  if (args.scope === "cross_target") {
    return queryFindingsCrossTarget(opts);
  }
  return queryFindingsForTarget({
    ...opts,
    target_domain: args.target_domain,
  });
}

module.exports = Object.freeze({
  name: "bounty_query_findings_index",
  description:
    "Query the hashed-feature-vector findings index for top-K similar past findings. Defaults to per-target scope; pass scope: 'cross_target' to walk all session directories. Use this to inject prior-art into a new hunt's brief or to look up similar findings while triaging a candidate.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string", description: "Required for per-target scope; ignored when scope is cross_target." },
      query_text: { type: "string", description: "Free-text query (recon summary, finding draft, surface description). The vector is built from this text the same way finding vectors are." },
      top_k: { type: "integer", minimum: 1, maximum: 50, description: "Maximum matches to return. Default 5; hard cap 50." },
      severity_filter: { type: "string", description: "Optional. Restrict matches to findings with this severity." },
      attack_class_filter: { type: "string", description: "Optional. Restrict matches to findings with this attack_class." },
      scope: {
        type: "string",
        enum: ["target", "cross_target"],
        description: "Default 'target' searches the named target's index; 'cross_target' aggregates across every per-target index.",
      },
    },
    required: ["query_text"],
  },
  handler: queryFindingsIndexHandler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  hook_required: false,
});
