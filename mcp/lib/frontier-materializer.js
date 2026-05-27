"use strict";

const {
  assertSafeDomain,
  surfaceIndexPath,
  taskQueuePath,
} = require("./paths.js");
const {
  hashDocumentExcluding,
  normalizeOptionalTextArray,
  sortByTextField,
  writeJsonDocument,
} = require("./fabric-common.js");
const {
  readFrontierEvents,
} = require("./frontier-events.js");
const {
  withSessionLock,
} = require("./storage.js");
const {
  normalizeTask,
  taskQueueKey,
} = require("./tasks.js");
const {
  compareQueuedTasks,
  normalizeQueuePolicy,
} = require("./queue-policy.js");
const {
  compareObservationEvents,
  normalizeObservationEvent,
} = require("./frontier-projections.js");

function uniqueSorted(values) {
  return Array.from(new Set(values.filter((value) => typeof value === "string" && value.length > 0))).sort();
}

function addUnique(target, value) {
  if (typeof value === "string" && value.length > 0 && !target.includes(value)) {
    target.push(value);
  }
}

function ensureSurface(surfacesById, domain, surfaceId, ts) {
  if (!surfacesById.has(surfaceId)) {
    surfacesById.set(surfaceId, {
      surface_id: surfaceId,
      target_domain: domain,
      state: "open",
      first_seen_at: ts,
      last_seen_at: ts,
      labels: [],
      source_event_ids: [],
      task_ids: [],
      observation_event_ids: [],
      observations: [],
      control_expectation_event_ids: [],
      blocker_event_ids: [],
      closure_event_ids: [],
    });
  }
  const surface = surfacesById.get(surfaceId);
  if (Date.parse(ts) < Date.parse(surface.first_seen_at)) surface.first_seen_at = ts;
  if (Date.parse(ts) > Date.parse(surface.last_seen_at)) surface.last_seen_at = ts;
  return surface;
}

function applySurfaceFields(surface, event) {
  const payload = event.payload || {};
  for (const field of ["title", "uri", "method", "kind", "owner"]) {
    if (typeof payload[field] === "string" && payload[field].trim()) {
      surface[field] = payload[field].trim();
    }
  }
  for (const label of normalizeOptionalTextArray(payload.labels || event.tags, "labels")) {
    addUnique(surface.labels, label);
  }
  surface.labels.sort();
  addUnique(surface.source_event_ids, event.event_id);
}

function taskInputFromEvent(event) {
  const payload = event.payload || {};
  const taskPayload = payload.task && typeof payload.task === "object" && !Array.isArray(payload.task)
    ? payload.task
    : payload;
  return {
    ...taskPayload,
    target_domain: event.target_domain,
    surface_id: event.surface_id || taskPayload.surface_id,
    lens: taskPayload.lens || "surface_scout",
    priority: taskPayload.priority || "medium",
    status: taskPayload.status || "queued",
    created_at: event.ts,
    source_event_id: event.event_id,
    frontier_item_id: event.frontier_item_id || taskPayload.frontier_item_id,
  };
}

function refreshTaskHash(task) {
  return normalizeTask(task, { targetDomain: task.target_domain, now: new Date(task.created_at) });
}

function markTask(tasksByKey, event, statusField, eventListField) {
  const key = event.frontier_item_id || event.task_id;
  if (!key || !tasksByKey.has(key)) return;
  const task = { ...tasksByKey.get(key) };
  task.status = statusField;
  const refs = Array.isArray(task[eventListField]) ? task[eventListField].slice() : [];
  addUnique(refs, event.event_id);
  task[eventListField] = refs;
  tasksByKey.set(key, refreshTaskHash(task));
}

function materializeFrontierDocument(domain, { write = false, now = new Date(), queuePolicy = {} } = {}) {
  const events = readFrontierEvents(domain);
  const policy = normalizeQueuePolicy(queuePolicy);
  const surfacesById = new Map();
  const tasksByKey = new Map();

  for (const event of events) {
    if (event.surface_id) {
      const surface = ensureSurface(surfacesById, domain, event.surface_id, event.ts);
      addUnique(surface.source_event_ids, event.event_id);
    }

    if (event.kind === "surface.observed" && event.surface_id) {
      applySurfaceFields(ensureSurface(surfacesById, domain, event.surface_id, event.ts), event);
    }

    if (event.kind === "observation.recorded" && event.surface_id) {
      const surface = ensureSurface(surfacesById, domain, event.surface_id, event.ts);
      addUnique(surface.observation_event_ids, event.event_id);
      surface.observations.push(normalizeObservationEvent(event));
    }

    if (event.kind === "control_expectation.recorded" && event.surface_id) {
      const surface = ensureSurface(surfacesById, domain, event.surface_id, event.ts);
      addUnique(surface.control_expectation_event_ids, event.event_id);
    }

    if (event.kind === "frontier.enqueued") {
      const task = normalizeTask(taskInputFromEvent(event), { targetDomain: domain, now: new Date(event.ts) });
      tasksByKey.set(taskQueueKey(task), task);
      const surface = ensureSurface(surfacesById, domain, task.surface_id, event.ts);
      addUnique(surface.task_ids, task.task_id);
      addUnique(surface.source_event_ids, event.event_id);
    }

    if (event.kind === "blocker.asserted") {
      markTask(tasksByKey, event, "blocked", "blocker_event_ids");
      if (event.surface_id) {
        const surface = ensureSurface(surfacesById, domain, event.surface_id, event.ts);
        addUnique(surface.blocker_event_ids, event.event_id);
        if (surface.state !== "closed") surface.state = "blocked";
      }
    }

    if (event.kind === "closure.recorded") {
      markTask(tasksByKey, event, "closed", "closure_event_ids");
      if (event.surface_id) {
        const surface = ensureSurface(surfacesById, domain, event.surface_id, event.ts);
        addUnique(surface.closure_event_ids, event.event_id);
        surface.state = "closed";
      }
    }
  }

  const surfaces = Array.from(surfacesById.values())
    .map((surface) => {
      // Deduplicate observation entries by event_id (events can be referenced
      // by multiple branches of the fold) and order them deterministically by
      // (ts, event_id) so the same event log always yields the same hash.
      const observationsById = new Map();
      for (const observation of surface.observations) {
        if (observation && observation.event_id && !observationsById.has(observation.event_id)) {
          observationsById.set(observation.event_id, observation);
        }
      }
      const observations = Array.from(observationsById.values()).sort(compareObservationEvents);
      return {
        ...surface,
        labels: uniqueSorted(surface.labels),
        source_event_ids: uniqueSorted(surface.source_event_ids),
        task_ids: uniqueSorted(surface.task_ids),
        observation_event_ids: uniqueSorted(surface.observation_event_ids),
        observations,
        control_expectation_event_ids: uniqueSorted(surface.control_expectation_event_ids),
        blocker_event_ids: uniqueSorted(surface.blocker_event_ids),
        closure_event_ids: uniqueSorted(surface.closure_event_ids),
      };
    })
    .sort(sortByTextField("surface_id"));

  const tasks = Array.from(tasksByKey.values()).sort((a, b) => compareQueuedTasks(a, b, policy));
  const materializedAt = now instanceof Date ? now.toISOString() : new Date(now).toISOString();

  const surfaceIndex = {
    version: 1,
    target_domain: domain,
    materialized_at: materializedAt,
    source_event_count: events.length,
    surface_count: surfaces.length,
    surfaces,
  };
  surfaceIndex.surface_index_hash = hashDocumentExcluding(surfaceIndex, [
    "materialized_at",
    "surface_index_hash",
  ]);

  const taskQueue = {
    version: 1,
    target_domain: domain,
    materialized_at: materializedAt,
    source_event_count: events.length,
    policy,
    task_count: tasks.length,
    tasks,
  };
  taskQueue.task_queue_hash = hashDocumentExcluding(taskQueue, [
    "materialized_at",
    "task_queue_hash",
  ]);

  if (write) {
    writeJsonDocument(surfaceIndexPath(domain), surfaceIndex);
    writeJsonDocument(taskQueuePath(domain), taskQueue);
  }

  return {
    surface_index: surfaceIndex,
    task_queue: taskQueue,
  };
}

function materializeFrontier(targetDomain, options = {}) {
  const domain = assertSafeDomain(targetDomain);
  if (options.write) {
    return withSessionLock(domain, () => materializeFrontierDocument(domain, options));
  }
  return materializeFrontierDocument(domain, options);
}

module.exports = {
  materializeFrontier,
};
