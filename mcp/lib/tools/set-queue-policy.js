"use strict";

const {
  assertNonEmptyString,
} = require("../validation.js");
const {
  withSessionLock,
} = require("../storage.js");
const {
  normalizeQueuePolicy,
  writeQueuePolicy,
} = require("../queue-policy.js");

function handler(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const policyInput = args.policy == null ? {} : args.policy;
  if (typeof policyInput !== "object" || Array.isArray(policyInput)) {
    throw new Error("policy must be an object");
  }
  const normalized = normalizeQueuePolicy(policyInput);
  const persisted = withSessionLock(domain, () => writeQueuePolicy(domain, normalized));
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    queue_policy: persisted,
  });
}

module.exports = Object.freeze({
  name: "bob_set_queue_policy",
  description:
    "Persist an operator-supplied QueuePolicy override for a target_domain to " +
    "~/bounty-agent-sessions/<domain>/queue-policy.json. The policy is normalized via " +
    "normalizeQueuePolicy and consumed by the wave planner and scheduler. Carries " +
    "max_parallel_tasks, priority_order, stale_after_ms, close_blocked_on_freeze, " +
    "and the wave targets/budgets/lens.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
      },
      policy: {
        type: "object",
        description:
          "Partial or full QueuePolicy. Unspecified fields fall back to DEFAULT_QUEUE_POLICY.",
        properties: {
          max_parallel_tasks: { type: "integer" },
          priority_order: {
            type: "array",
            items: { type: "string", enum: ["critical", "high", "medium", "low"] },
          },
          stale_after_ms: { type: "integer" },
          close_blocked_on_freeze: { type: "boolean" },
          standard_wave_target: { type: "integer" },
          standard_wave_max: { type: "integer" },
          deep_wave_target: { type: "integer" },
          deep_wave_max: { type: "integer" },
          default_wave_task_lens: { type: "string" },
          default_wave_task_budget: {
            type: "object",
            properties: {
              max_steps: { type: "integer" },
              max_context_tokens: { type: "integer" },
            },
          },
        },
      },
    },
    required: ["target_domain", "policy"],
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["queue-policy.json"],
});
