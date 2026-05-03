"use strict";

const { readHunterBrief } = require("../hunter-brief.js");

module.exports = Object.freeze({
  name: "bounty_read_hunter_brief",
  description:
    "Return everything a hunter needs to start testing: assigned surface, exclusions, valid surface IDs, coverage summary, ranking summary, run context budget, plus profile-specific context. Web hunters get bypass tables, bounded technique_packs.selected with registry warnings, small legacy technique/payload hint summaries, traffic/audit/circuit-breaker summaries, public intel, and static scan hints. Smart-contract hunters get bob_spec_status (filtered to their surface) and the chain rpc_pool. Hunters call this once on startup instead of receiving everything via spawn prompt.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "wave": {
        "type": "string",
        "pattern": "^w[1-9][0-9]*$"
      },
      "agent": {
        "type": "string",
        "pattern": "^a[1-9][0-9]*$"
      },
      "egress_profile": {
        "type": "string"
      },
      "block_internal_hosts": {
        "type": "boolean"
      }
    },
    "required": [
      "target_domain",
      "wave",
      "agent"
    ]
  },
  handler: readHunterBrief,
  role_bundles: ["hunter-shared"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  hook_required: false,
});
