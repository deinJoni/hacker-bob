"use strict";

const fs = require("fs");
const {
  assertBoolean,
  assertEnumValue,
  assertNonEmptyString,
} = require("./validation.js");
const {
  normalizePositiveInteger,
  writeJsonDocument,
} = require("./fabric-common.js");
const {
  normalizeTaskLens,
} = require("./task-lenses.js");

const TASK_PRIORITY_VALUES = Object.freeze(["critical", "high", "medium", "low"]);
const QUEUE_STATUS_VALUES = Object.freeze(["queued", "assigned", "running", "blocked", "closed", "dismissed"]);

const DEFAULT_WAVE_TASK_BUDGET = Object.freeze({
  max_steps: 6,
  max_context_tokens: 24000,
});

const DEFAULT_QUEUE_POLICY = Object.freeze({
  version: 1,
  max_parallel_tasks: 4,
  priority_order: ["critical", "high", "medium", "low"],
  stale_after_ms: 24 * 60 * 60 * 1000,
  close_blocked_on_freeze: false,
  standard_wave_target: 4,
  standard_wave_max: 6,
  deep_wave_target: 6,
  deep_wave_max: 8,
  default_wave_task_lens: "surface_scout",
  default_wave_task_budget: { ...DEFAULT_WAVE_TASK_BUDGET },
});

function normalizeTaskPriority(value, fieldName = "priority") {
  return assertEnumValue(value == null ? "medium" : value, TASK_PRIORITY_VALUES, fieldName);
}

function normalizeQueueStatus(value, fieldName = "status") {
  return assertEnumValue(value == null ? "queued" : value, QUEUE_STATUS_VALUES, fieldName);
}

function normalizeWaveTaskBudget(value, fieldName = "default_wave_task_budget") {
  if (value == null) {
    return { ...DEFAULT_WAVE_TASK_BUDGET };
  }
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const maxSteps = normalizePositiveInteger(value.max_steps, `${fieldName}.max_steps`, {
    defaultValue: DEFAULT_WAVE_TASK_BUDGET.max_steps,
  });
  const maxContextTokens = normalizePositiveInteger(value.max_context_tokens, `${fieldName}.max_context_tokens`, {
    defaultValue: DEFAULT_WAVE_TASK_BUDGET.max_context_tokens,
  });
  return { max_steps: maxSteps, max_context_tokens: maxContextTokens };
}

function normalizeQueuePolicy(input = {}) {
  const policy = {
    version: 1,
    max_parallel_tasks: normalizePositiveInteger(input.max_parallel_tasks, "max_parallel_tasks", {
      defaultValue: DEFAULT_QUEUE_POLICY.max_parallel_tasks,
      max: 128,
    }),
    priority_order: Array.isArray(input.priority_order) && input.priority_order.length > 0
      ? input.priority_order.map((priority, index) => normalizeTaskPriority(priority, `priority_order[${index}]`))
      : DEFAULT_QUEUE_POLICY.priority_order.slice(),
    stale_after_ms: normalizePositiveInteger(input.stale_after_ms, "stale_after_ms", {
      defaultValue: DEFAULT_QUEUE_POLICY.stale_after_ms,
    }),
    close_blocked_on_freeze: input.close_blocked_on_freeze == null
      ? DEFAULT_QUEUE_POLICY.close_blocked_on_freeze
      : assertBoolean(input.close_blocked_on_freeze, "close_blocked_on_freeze"),
    standard_wave_target: normalizePositiveInteger(input.standard_wave_target, "standard_wave_target", {
      defaultValue: DEFAULT_QUEUE_POLICY.standard_wave_target,
      max: 128,
    }),
    standard_wave_max: normalizePositiveInteger(input.standard_wave_max, "standard_wave_max", {
      defaultValue: DEFAULT_QUEUE_POLICY.standard_wave_max,
      max: 128,
    }),
    deep_wave_target: normalizePositiveInteger(input.deep_wave_target, "deep_wave_target", {
      defaultValue: DEFAULT_QUEUE_POLICY.deep_wave_target,
      max: 128,
    }),
    deep_wave_max: normalizePositiveInteger(input.deep_wave_max, "deep_wave_max", {
      defaultValue: DEFAULT_QUEUE_POLICY.deep_wave_max,
      max: 128,
    }),
    default_wave_task_lens: input.default_wave_task_lens == null
      ? DEFAULT_QUEUE_POLICY.default_wave_task_lens
      : normalizeTaskLens(input.default_wave_task_lens, "default_wave_task_lens"),
    default_wave_task_budget: normalizeWaveTaskBudget(input.default_wave_task_budget),
  };
  policy.priority_order = Array.from(new Set(policy.priority_order));
  if (policy.standard_wave_max < policy.standard_wave_target) {
    throw new Error("standard_wave_max must be >= standard_wave_target");
  }
  if (policy.deep_wave_max < policy.deep_wave_target) {
    throw new Error("deep_wave_max must be >= deep_wave_target");
  }
  return policy;
}

function compareQueuedTasks(a, b, policy = DEFAULT_QUEUE_POLICY) {
  const normalizedPolicy = normalizeQueuePolicy(policy);
  const priorityRank = new Map(normalizedPolicy.priority_order.map((priority, index) => [priority, index]));
  const aPriority = priorityRank.get(a.priority) ?? normalizedPolicy.priority_order.length;
  const bPriority = priorityRank.get(b.priority) ?? normalizedPolicy.priority_order.length;
  if (aPriority !== bPriority) return aPriority - bPriority;
  const aCreated = Date.parse(a.created_at || "") || 0;
  const bCreated = Date.parse(b.created_at || "") || 0;
  if (aCreated !== bCreated) return aCreated - bCreated;
  return String(a.task_id || "").localeCompare(String(b.task_id || ""));
}

function loadQueuePolicy(domain) {
  assertNonEmptyString(domain, "target_domain");
  // Require paths lazily to avoid a load-time cycle (paths.js → validation.js).
  const { queuePolicyPath } = require("./paths.js");
  const filePath = queuePolicyPath(domain);
  if (!fs.existsSync(filePath)) {
    return normalizeQueuePolicy(DEFAULT_QUEUE_POLICY);
  }
  let raw;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    throw new Error(`Failed to read queue-policy.json: ${error.message || String(error)}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Malformed queue-policy.json at ${filePath}: ${error.message || String(error)}`);
  }
  return normalizeQueuePolicy(parsed);
}

function writeQueuePolicy(domain, policy) {
  assertNonEmptyString(domain, "target_domain");
  const normalized = normalizeQueuePolicy(policy);
  const { queuePolicyPath } = require("./paths.js");
  writeJsonDocument(queuePolicyPath(domain), normalized);
  return normalized;
}

module.exports = {
  DEFAULT_QUEUE_POLICY,
  DEFAULT_WAVE_TASK_BUDGET,
  QUEUE_STATUS_VALUES,
  TASK_PRIORITY_VALUES,
  compareQueuedTasks,
  loadQueuePolicy,
  normalizeQueuePolicy,
  normalizeQueueStatus,
  normalizeTaskPriority,
  writeQueuePolicy,
};
