"use strict";

const { queryChainTree } = require("../chain-state-tree.js");

function queryChainTreeHandler(args) {
  return queryChainTree({
    target_domain: args.target_domain,
    parent_state_hash: args.parent_state_hash,
    verdict: args.verdict,
    action_kind: args.action_kind,
    limit: args.limit,
  });
}

module.exports = Object.freeze({
  name: "bounty_query_chain_tree",
  capability_id: "I7_chain_state_tree",
  description:
    "Filter the chain state tree by parent_state_hash, verdict, and action.kind. Use to enumerate the children of a node (pass parent_state_hash) or to inspect every pending / success / pruned attempt across the tree.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      parent_state_hash: { type: "string" },
      verdict: {
        type: "string",
        enum: ["pending", "success", "failure", "pruned", "branched"],
      },
      action_kind: { type: "string" },
      limit: { type: "integer", minimum: 1, maximum: 1000 },
    },
    required: ["target_domain"],
  },
  handler: queryChainTreeHandler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
