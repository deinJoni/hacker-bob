"use strict";

const {
  assertEnumValue,
} = require("./validation.js");

const TASK_LENSES = Object.freeze([
  "seed_mapping",
  "surface_scout",
  "behavior_probe",
  "control_check",
  "claim_development",
  "impact_correlation",
  "reproduction_check",
  "evidence_capture",
  "coverage_closeout",
]);

function normalizeTaskLens(value, fieldName = "lens") {
  return assertEnumValue(value, TASK_LENSES, fieldName);
}

function isTaskLens(value) {
  return TASK_LENSES.includes(value);
}

module.exports = {
  TASK_LENSES,
  isTaskLens,
  normalizeTaskLens,
};
