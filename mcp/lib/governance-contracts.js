"use strict";

const {
  AUTH_STATUS_VALUES,
} = require("./constants.js");
const {
  assertBoolean,
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  normalizeOptionalText,
} = require("./validation.js");
const {
  assertSafeDomain,
} = require("./paths.js");
const {
  blockInternalHostsPolicyFields,
} = require("./session-state-contracts.js");
const {
  hashDocumentExcluding,
  normalizeOptionalObject,
  withDocumentHash,
} = require("./fabric-common.js");
const {
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");

const GOVERNANCE_VERSION = 1;
const LIFECYCLE_STATE_VALUES = Object.freeze([
  "SETUP",
  "OPEN_FRONTIER",
  "CLAIM_FREEZE",
  "VERIFY",
  "GRADE",
  "REPORT",
]);

function normalizeLifecycleState(value, fieldName = "lifecycle_state") {
  return assertEnumValue(value == null ? "SETUP" : value, LIFECYCLE_STATE_VALUES, fieldName);
}

function normalizeScopePolicy(input) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("scope_policy must be an object");
  }
  const targetDomain = assertSafeDomain(input.target_domain);
  const targetUrl = assertNonEmptyString(input.target_url, "target_url");
  validateNoSensitiveMaterial(targetUrl, "target_url", { maxTextChars: 2048 });
  const internalHostPolicy = blockInternalHostsPolicyFields(input);
  return {
    target_domain: targetDomain,
    target_url: targetUrl,
    checkpoint_mode: internalHostPolicy.checkpoint_mode,
    block_internal_hosts: internalHostPolicy.block_internal_hosts,
    block_internal_hosts_source: internalHostPolicy.block_internal_hosts_source,
  };
}

function normalizeEgressIdentity(input = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("egress_identity must be an object");
  }
  const profile = assertNonEmptyString(input.egress_profile || input.name || "default", "egress_profile");
  const identity = {
    egress_profile: profile,
    egress_region: normalizeOptionalText(input.egress_region || input.region, "egress_region"),
    proxy_configured: input.proxy_configured == null
      ? false
      : assertBoolean(input.proxy_configured, "proxy_configured"),
    egress_profile_identity_hash: normalizeOptionalText(
      input.egress_profile_identity_hash,
      "egress_profile_identity_hash",
    ),
    egress_profile_identity_version: input.egress_profile_identity_version == null
      ? null
      : assertInteger(input.egress_profile_identity_version, "egress_profile_identity_version", { min: 1 }),
    egress_profile_identity_source: normalizeOptionalObject(
      input.egress_profile_identity_source,
      "egress_profile_identity_source",
    ),
  };
  validateNoSensitiveMaterial(identity, "egress_identity");
  return identity;
}

function normalizeAuthContext(input = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("auth_context must be an object");
  }
  const context = {
    auth_status: assertEnumValue(input.auth_status || input.status || "pending", AUTH_STATUS_VALUES, "auth_status"),
  };
  const handleCount = input.auth_handle_count == null
    ? null
    : assertInteger(input.auth_handle_count, "auth_handle_count", { min: 0 });
  if (handleCount != null) context.auth_handle_count = handleCount;
  return context;
}

function normalizeOperatorConstraint(input = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("operator_constraint must be an object");
  }
  const note = normalizeOptionalText(input.operator_note, "operator_note");
  if (note != null) {
    validateNoSensitiveMaterial(note, "operator_note", { maxTextChars: 1000 });
  }
  const constraint = {
    handoff_provenance_required: input.handoff_provenance_required == null
      ? true
      : assertBoolean(input.handoff_provenance_required, "handoff_provenance_required"),
  };
  if (note != null) constraint.operator_note = note;
  return constraint;
}

function buildSessionNucleus(input) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("session nucleus input must be an object");
  }
  const scopePolicy = normalizeScopePolicy({
    ...(input.scope_policy || {}),
    target_domain: input.target_domain || (input.scope_policy && input.scope_policy.target_domain),
    target_url: input.target_url || (input.scope_policy && input.scope_policy.target_url),
  });
  const nucleus = {
    version: GOVERNANCE_VERSION,
    target_domain: scopePolicy.target_domain,
    lifecycle_state: normalizeLifecycleState(input.lifecycle_state),
    scope_policy: scopePolicy,
    egress_identity: normalizeEgressIdentity(input.egress_identity),
    auth_context: normalizeAuthContext(input.auth_context),
    operator_constraint: normalizeOperatorConstraint(input.operator_constraint),
  };
  return withDocumentHash(nucleus, "nucleus_hash");
}

function sessionNucleusFromState(state) {
  if (state == null || typeof state !== "object" || Array.isArray(state)) {
    throw new Error("state must be an object");
  }
  return buildSessionNucleus({
    target_domain: state.target,
    target_url: state.target_url,
    scope_policy: {
      target_domain: state.target,
      target_url: state.target_url,
      checkpoint_mode: state.checkpoint_mode,
      block_internal_hosts: state.block_internal_hosts,
      block_internal_hosts_source: state.block_internal_hosts_source,
    },
    egress_identity: {
      egress_profile: state.egress_profile,
      egress_region: state.egress_region,
      proxy_configured: state.proxy_configured,
      egress_profile_identity_hash: state.egress_profile_identity_hash,
      egress_profile_identity_version: state.egress_profile_identity_version,
      egress_profile_identity_source: state.egress_profile_identity_source,
    },
    auth_context: {
      auth_status: state.auth_status,
    },
    operator_constraint: {
      operator_note: state.operator_note,
      handoff_provenance_required: state.handoff_provenance_required,
    },
    lifecycle_state: state.lifecycle_state,
  });
}

function sessionNucleusHash(nucleus) {
  return hashDocumentExcluding(nucleus, ["nucleus_hash"]);
}

module.exports = {
  GOVERNANCE_VERSION,
  LIFECYCLE_STATE_VALUES,
  buildSessionNucleus,
  normalizeAuthContext,
  normalizeEgressIdentity,
  normalizeLifecycleState,
  normalizeOperatorConstraint,
  normalizeScopePolicy,
  sessionNucleusFromState,
  sessionNucleusHash,
};
