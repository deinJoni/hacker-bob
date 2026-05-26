"use strict";

const {
  assertBoolean,
  assertEnumValue,
} = require("./validation.js");
const {
  normalizePositiveInteger,
} = require("./fabric-common.js");

const TASK_PRIORITY_VALUES = Object.freeze(["critical", "high", "medium", "low"]);
const QUEUE_STATUS_VALUES = Object.freeze(["queued", "assigned", "running", "blocked", "closed", "dismissed"]);

const DEFAULT_QUEUE_POLICY = Object.freeze({
  version: 1,
  max_parallel_tasks: 4,
  priority_order: ["critical", "high", "medium", "low"],
  stale_after_ms: 24 * 60 * 60 * 1000,
  close_blocked_on_freeze: false,
});

function normalizeTaskPriority(value, fieldName = "priority") {
  return assertEnumValue(value == null ? "medium" : value, TASK_PRIORITY_VALUES, fieldName);
}

function normalizeQueueStatus(value, fieldName = "status") {
  return assertEnumValue(value == null ? "queued" : value, QUEUE_STATUS_VALUES, fieldName);
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
  };
  policy.priority_order = Array.from(new Set(policy.priority_order));
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

module.exports = {
  DEFAULT_QUEUE_POLICY,
  QUEUE_STATUS_VALUES,
  TASK_PRIORITY_VALUES,
  compareQueuedTasks,
  normalizeQueuePolicy,
  normalizeQueueStatus,
  normalizeTaskPriority,
};
