"use strict";

const fs = require("fs");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  statePath,
} = require("./paths.js");
const {
  readJsonFile,
} = require("./storage.js");
const {
  assertHttpScopeDomain,
  validateHttpScanScope,
} = require("./scope.js");
const {
  normalizeSessionStateDocument,
} = require("./session-state-contracts.js");

const AUTHORITY_VERSION = 1;
const AUTHORITY_MODE_ENV = "BOB_SESSION_AUTHORITY_MODE";

const AUTHORITY_CLASSES = Object.freeze([
  "bootstrap_session",
  "initialized_session_read",
  "initialized_session_mutation",
  "scoped_http_network",
  "smart_contract_contextual",
  "optional_session_context",
  "cross_session_read",
  "mode_dependent_session",
  "global_read",
  "global_preapproval",
  "legacy_session_compat",
]);

const EXPLICIT_AUTHORITY_CLASS_BY_TOOL = Object.freeze({
  bounty_anchor_run: "smart_contract_contextual",
  bounty_append_chain_node: "initialized_session_mutation",
  bounty_apply_wave_merge: "initialized_session_mutation",
  bounty_aptos_fetch_module: "smart_contract_contextual",
  bounty_aptos_fetch_resource: "smart_contract_contextual",
  bounty_aptos_run: "smart_contract_contextual",
  bounty_auth_store: "initialized_session_mutation",
  bounty_auto_signup: "scoped_http_network",
  bounty_build_surface_graph: "initialized_session_mutation",
  bounty_build_symbol_surface_index: "initialized_session_mutation",
  bounty_build_verification_adjudication: "initialized_session_mutation",
  bounty_chain_ancestry: "initialized_session_read",
  bounty_chain_frontier: "initialized_session_read",
  bounty_clear_operator_note: "initialized_session_mutation",
  bounty_clear_terminal_block: "initialized_session_mutation",
  bounty_cosmwasm_fetch_contract: "smart_contract_contextual",
  bounty_cosmwasm_run: "smart_contract_contextual",
  bounty_cosmwasm_smart_query: "smart_contract_contextual",
  bounty_diff_verification_attempts: "initialized_session_read",
  bounty_evaluate_capabilities: "global_read",
  bounty_evm_call: "global_preapproval",
  bounty_evm_fetch_source: "smart_contract_contextual",
  bounty_evm_role_table: "global_preapproval",
  bounty_evm_storage_read: "global_preapproval",
  bounty_extract_routes: "initialized_session_read",
  bounty_finalize_hunter_run: "initialized_session_mutation",
  bounty_foundry_run: "smart_contract_contextual",
  bounty_get_context_budget: "mode_dependent_session",
  bounty_halmos_run: "smart_contract_contextual",
  bounty_http_scan: "scoped_http_network",
  bounty_import_http_traffic: "scoped_http_network",
  bounty_import_static_artifact: "initialized_session_mutation",
  bounty_index_finding: "initialized_session_mutation",
  bounty_ingest_audit_report: "initialized_session_mutation",
  bounty_ingest_schema_doc: "initialized_session_mutation",
  bounty_init_session: "bootstrap_session",
  bounty_list_auth_profiles: "initialized_session_read",
  bounty_list_findings: "initialized_session_read",
  bounty_log_coverage: "initialized_session_mutation",
  bounty_log_dead_ends: "initialized_session_mutation",
  bounty_log_technique_attempt: "initialized_session_mutation",
  bounty_merge_wave_handoffs: "initialized_session_read",
  bounty_promote_surface_leads: "initialized_session_mutation",
  bounty_public_intel: "scoped_http_network",
  bounty_query_audit_reports: "initialized_session_read",
  bounty_query_chain_tree: "initialized_session_read",
  bounty_query_findings_index: "mode_dependent_session",
  bounty_query_schema_contracts: "initialized_session_read",
  bounty_query_surface_graph: "initialized_session_read",
  bounty_read_auth_differential_results: "initialized_session_read",
  bounty_read_capability_metrics: "mode_dependent_session",
  bounty_read_capability_playbook: "global_read",
  bounty_read_chain_attempts: "initialized_session_read",
  bounty_read_doc_delta_results: "initialized_session_read",
  bounty_read_evidence_packs: "initialized_session_read",
  bounty_read_findings: "initialized_session_read",
  bounty_read_grade_verdict: "initialized_session_read",
  bounty_read_http_audit: "initialized_session_read",
  bounty_read_hunter_brief: "initialized_session_read",
  bounty_read_invariant_runs: "initialized_session_read",
  bounty_read_pipeline_analytics: "mode_dependent_session",
  bounty_read_session_state: "initialized_session_read",
  bounty_read_session_summary: "initialized_session_read",
  bounty_read_state_summary: "initialized_session_read",
  bounty_read_surface_leads: "initialized_session_read",
  bounty_read_surface_routes: "initialized_session_read",
  bounty_read_technique_pack: "mode_dependent_session",
  bounty_read_tool_telemetry: "mode_dependent_session",
  bounty_read_verification_context: "initialized_session_read",
  bounty_read_verification_round: "initialized_session_read",
  bounty_read_wave_handoffs: "initialized_session_read",
  bounty_record_finding: "initialized_session_mutation",
  bounty_record_surface_leads: "initialized_session_mutation",
  bounty_report_written: "initialized_session_mutation",
  bounty_route_surfaces: "initialized_session_mutation",
  bounty_run_auth_differential: "scoped_http_network",
  bounty_run_doc_delta: "scoped_http_network",
  bounty_run_invariant_for_finding: "smart_contract_contextual",
  bounty_select_technique_packs: "initialized_session_read",
  bounty_set_operator_note: "initialized_session_mutation",
  bounty_signup_detect: "scoped_http_network",
  bounty_start_next_wave: "initialized_session_mutation",
  bounty_start_wave: "initialized_session_mutation",
  bounty_static_scan: "initialized_session_mutation",
  bounty_substrate_fetch_runtime: "smart_contract_contextual",
  bounty_substrate_fetch_storage: "smart_contract_contextual",
  bounty_substrate_run: "smart_contract_contextual",
  bounty_suggest_invariants: "global_read",
  bounty_sui_fetch_object: "smart_contract_contextual",
  bounty_sui_fetch_package: "smart_contract_contextual",
  bounty_sui_run: "smart_contract_contextual",
  bounty_summarize_diff_impact: "initialized_session_read",
  bounty_svm_fetch_account: "smart_contract_contextual",
  bounty_svm_fetch_program: "smart_contract_contextual",
  bounty_temp_email: "global_preapproval",
  bounty_transition_phase: "initialized_session_mutation",
  bounty_wave_handoff_status: "initialized_session_read",
  bounty_wave_status: "initialized_session_read",
  bounty_write_chain_attempt: "initialized_session_mutation",
  bounty_write_evidence_packs: "initialized_session_mutation",
  bounty_write_grade_verdict: "initialized_session_mutation",
  bounty_write_handoff: "initialized_session_mutation",
  bounty_write_verification_round: "initialized_session_mutation",
  bounty_write_wave_handoff: "initialized_session_mutation",
});

const LEGACY_DEFAULTABLE_FIELDS = Object.freeze([
  "auth_status",
  "blocked_prereq_history",
  "dead_ends",
  "deep_mode",
  "explored",
  "hold_count",
  "hunt_wave",
  "lead_surface_ids",
  "operator_note",
  "pending_wave",
  "prereq_registry_snapshots",
  "scope_exclusions",
  "terminal_block_clear_history",
  "terminally_blocked",
  "total_findings",
  "waf_blocked_endpoints",
]);

// Fields whose absence is a hard scope/authority failure (not defaultable).
// Egress/checkpoint/verification fields are intentionally NOT in this list:
// normalizeSessionStateDocument backfills safe defaults for them so v1.3.4
// sessions can resume on v1.3.5. The fields below are scope identity and have
// no meaningful default — their per-field checks above this list (raw.target
// drift, target_url drift) emit more specific errors before this list is
// consulted, so this is belt-and-suspenders for that contract.
const LEGACY_FAIL_CLOSED_FIELDS = Object.freeze([
  "target",
  "target_url",
]);

const SESSION_AUTHORITY_CLASSES = new Set([
  "initialized_session_read",
  "initialized_session_mutation",
  "scoped_http_network",
  "smart_contract_contextual",
]);

const SHADOW_MISSING_SESSION_CLASSES = new Set([
  "initialized_session_read",
  "cross_session_read",
]);

let shadowWarningEmitted = false;

function hasOwn(value, key) {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function targetDomainPresent(args) {
  return !!(args && typeof args.target_domain === "string" && args.target_domain.trim());
}

function safeArgumentTargetDomain(args) {
  if (!targetDomainPresent(args)) return null;
  try {
    return assertHttpScopeDomain(args.target_domain);
  } catch {
    return null;
  }
}

function authorityMode(env = process.env) {
  return env[AUTHORITY_MODE_ENV] === "shadow" ? "shadow" : "enforce";
}

function classForTool(toolName) {
  return EXPLICIT_AUTHORITY_CLASS_BY_TOOL[toolName] || null;
}

function modeRule(toolName, args = {}) {
  if (toolName === "bounty_query_findings_index") {
    if (args.scope === "cross_target") {
      return {
        authority_class: "cross_session_read",
        target_domain: "ignored",
        target_url_policy: "index_only_no_target_url_export",
        authority_source: "cross_session",
      };
    }
    return {
      authority_class: "initialized_session_read",
      target_domain: "required",
      target_url_policy: "validate_session_target_url",
      authority_source: "session_state",
    };
  }
  if (toolName === "bounty_get_context_budget") {
    if (args.surface_id != null) {
      return {
        authority_class: "initialized_session_read",
        target_domain: "required",
        target_url_policy: "validate_session_target_url",
        authority_source: "session_state",
      };
    }
    return {
      authority_class: "global_read",
      target_domain: "optional_absent",
      target_url_policy: "not_applicable",
      authority_source: "optional_absent",
    };
  }
  if (toolName === "bounty_read_technique_pack") {
    if (args.mode === "full") {
      return {
        authority_class: "initialized_session_mutation",
        target_domain: "required",
        target_url_policy: "validate_session_target_url",
        authority_source: "session_state",
      };
    }
    return {
      authority_class: "global_read",
      target_domain: "optional_absent",
      target_url_policy: "not_applicable",
      authority_source: "optional_absent",
    };
  }
  if (toolName === "bounty_read_tool_telemetry") {
    if (targetDomainPresent(args)) {
      return {
        authority_class: "initialized_session_read",
        target_domain: "required",
        target_url_policy: "validate_session_target_url",
        authority_source: "session_state",
      };
    }
    return {
      authority_class: "cross_session_read",
      target_domain: "optional_absent",
      target_url_policy: "index_only_no_target_url_export",
      authority_source: "cross_session",
    };
  }
  if (toolName === "bounty_read_pipeline_analytics") {
    if (targetDomainPresent(args)) {
      return {
        authority_class: "initialized_session_read",
        target_domain: "required",
        target_url_policy: "validate_session_target_url",
        authority_source: "session_state",
      };
    }
    return {
      authority_class: "cross_session_read",
      target_domain: "optional_absent",
      target_url_policy: "validate_before_target_url_export",
      authority_source: "cross_session",
    };
  }
  if (toolName === "bounty_read_capability_metrics") {
    if (targetDomainPresent(args)) {
      return {
        authority_class: "initialized_session_read",
        target_domain: "required",
        target_url_policy: "validate_session_target_url",
        authority_source: "session_state",
      };
    }
    return {
      authority_class: "cross_session_read",
      target_domain: "optional_absent",
      target_url_policy: "index_only_no_target_url_export",
      authority_source: "cross_session",
    };
  }
  return null;
}

function baseRuleForTool(tool, args) {
  const defaultClass = classForTool(tool && tool.name);
  if (!defaultClass) {
    return null;
  }
  if (defaultClass === "mode_dependent_session") {
    return modeRule(tool.name, args);
  }
  if (defaultClass === "bootstrap_session") {
    return {
      authority_class: defaultClass,
      target_domain: "required",
      target_url_policy: "validate_input_target_url",
      authority_source: "bootstrap",
    };
  }
  if (defaultClass === "cross_session_read") {
    return {
      authority_class: defaultClass,
      target_domain: "optional_absent",
      target_url_policy: "validate_before_target_url_export",
      authority_source: "cross_session",
    };
  }
  if (defaultClass === "global_read") {
    return {
      authority_class: defaultClass,
      target_domain: "absent",
      target_url_policy: "not_applicable",
      authority_source: "global",
    };
  }
  if (defaultClass === "global_preapproval") {
    return {
      authority_class: defaultClass,
      target_domain: "absent",
      target_url_policy: "not_applicable",
      authority_source: "preapproval_global",
    };
  }
  return {
    authority_class: defaultClass,
    target_domain: "required",
    target_url_policy: "validate_session_target_url",
    authority_source: "session_state",
  };
}

function makeDecision({
  authority_class: authorityClass,
  authority_mode: mode,
  authority_source: source,
  authority_result: result,
  authority_error_code: errorCode = "none",
  authority_block_reason: blockReason = "none",
  authority_target_domain: authorityTargetDomain = null,
  argument_target_domain: argumentTargetDomain = null,
  authority_session_present: sessionPresent = null,
  authority_match: match = null,
  authority_shadowed: shadowed = false,
} = {}) {
  return {
    authority_version: AUTHORITY_VERSION,
    authority_class: authorityClass || null,
    authority_mode: mode || "enforce",
    authority_source: source || "global",
    authority_result: result || "not_applicable",
    authority_error_code: errorCode || "none",
    authority_block_reason: blockReason || errorCode || "none",
    authority_target_domain: authorityTargetDomain || null,
    argument_target_domain: argumentTargetDomain || null,
    authority_session_present: sessionPresent,
    authority_match: match,
    authority_shadowed: shadowed === true,
  };
}

function allowedDecision(rule, args, {
  authorityTargetDomain = null,
  source = null,
  sessionPresent = null,
  match = null,
} = {}) {
  return makeDecision({
    authority_class: rule.authority_class,
    authority_mode: authorityMode(),
    authority_source: source || rule.authority_source,
    authority_result: "allowed",
    authority_target_domain: authorityTargetDomain,
    argument_target_domain: safeArgumentTargetDomain(args),
    authority_session_present: sessionPresent,
    authority_match: match,
  });
}

function blockedDecision(rule, args, {
  errorCode,
  blockReason,
  envelopeCode,
  message,
  authorityTargetDomain = null,
  sessionPresent = null,
  match = null,
  source = null,
  details = null,
}) {
  const decision = makeDecision({
    authority_class: rule && rule.authority_class,
    authority_mode: authorityMode(),
    authority_source: source || (rule && rule.authority_source) || "global",
    authority_result: "blocked",
    authority_error_code: errorCode,
    authority_block_reason: blockReason || errorCode,
    authority_target_domain: authorityTargetDomain,
    argument_target_domain: safeArgumentTargetDomain(args),
    authority_session_present: sessionPresent,
    authority_match: match,
  });
  const error = new ToolError(envelopeCode, message, {
    ...(details || {}),
    authority: decision,
  });
  error.authority = decision;
  return error;
}

function canShadowMissingSession(tool, rule) {
  if (authorityMode() !== "shadow") return false;
  if (!SHADOW_MISSING_SESSION_CLASSES.has(rule.authority_class)) return false;
  if (!tool) return false;
  if (tool.mutating || tool.network_access || tool.browser_access || tool.sensitive_output) return false;
  if (Array.isArray(tool.session_artifacts_written) && tool.session_artifacts_written.length > 0) return false;
  return true;
}

function shadowDecision(error, tool, rule) {
  if (!error || !error.authority || error.authority.authority_error_code !== "no_session") {
    return null;
  }
  if (!canShadowMissingSession(tool, rule)) {
    return null;
  }
  if (!shadowWarningEmitted) {
    shadowWarningEmitted = true;
    process.stderr.write("WARNING: BOB_SESSION_AUTHORITY_MODE=shadow is allowing a missing-session read-only authority block.\n");
  }
  return {
    ...error.authority,
    authority_result: "shadow_blocked",
    authority_shadowed: true,
  };
}

function normalizeArgumentTarget(rule, args) {
  if (rule.target_domain !== "required") {
    return null;
  }
  if (!targetDomainPresent(args)) {
    throw blockedDecision(rule, args, {
      errorCode: "normalization_failed",
      envelopeCode: ERROR_CODES.INVALID_ARGUMENTS,
      message: "target_domain is required for session authority",
      sessionPresent: null,
      match: false,
    });
  }
  try {
    const normalized = assertHttpScopeDomain(args.target_domain);
    args.target_domain = normalized;
    return normalized;
  } catch (error) {
    throw blockedDecision(rule, args, {
      errorCode: "normalization_failed",
      envelopeCode: ERROR_CODES.INVALID_ARGUMENTS,
      message: error.message || String(error),
      sessionPresent: null,
      match: false,
    });
  }
}

function assertLegacyFailClosedFields(raw, rule, args, authorityTargetDomain) {
  for (const field of LEGACY_FAIL_CLOSED_FIELDS) {
    if (!hasOwn(raw, field)) {
      throw blockedDecision(rule, args, {
        errorCode: "legacy_security_field_missing",
        envelopeCode: ERROR_CODES.STATE_CONFLICT,
        message: `session authority field is missing: ${field}`,
        authorityTargetDomain,
        sessionPresent: true,
        match: null,
      });
    }
  }
}

function readRawAuthorityState(authorityTargetDomain, rule, args) {
  const filePath = statePath(authorityTargetDomain);
  if (!fs.existsSync(filePath)) {
    throw blockedDecision(rule, args, {
      errorCode: "no_session",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: `Session authority is missing for ${authorityTargetDomain}; call bounty_init_session first`,
      authorityTargetDomain,
      sessionPresent: false,
      match: false,
    });
  }

  let raw;
  try {
    raw = readJsonFile(filePath, { label: "state.json" });
  } catch {
    throw blockedDecision(rule, args, {
      errorCode: "malformed_state",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: `Session authority state is malformed for ${authorityTargetDomain}`,
      authorityTargetDomain,
      sessionPresent: true,
      match: null,
    });
  }

  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw blockedDecision(rule, args, {
      errorCode: "malformed_state",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: `Session authority state is malformed for ${authorityTargetDomain}`,
      authorityTargetDomain,
      sessionPresent: true,
      match: null,
    });
  }

  if (!hasOwn(raw, "target")) {
    throw blockedDecision(rule, args, {
      errorCode: "legacy_security_field_missing",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: "session authority field is missing: target",
      authorityTargetDomain,
      sessionPresent: true,
      match: false,
    });
  }

  let rawTarget;
  try {
    rawTarget = assertHttpScopeDomain(raw.target);
  } catch {
    throw blockedDecision(rule, args, {
      errorCode: "malformed_state",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: `Session authority target is malformed for ${authorityTargetDomain}`,
      authorityTargetDomain,
      sessionPresent: true,
      match: false,
    });
  }

  if (rawTarget !== authorityTargetDomain) {
    throw blockedDecision(rule, args, {
      errorCode: "raw_target_drift",
      envelopeCode: ERROR_CODES.SCOPE_BLOCKED,
      message: `Session authority target drift for ${authorityTargetDomain}`,
      authorityTargetDomain,
      sessionPresent: true,
      match: false,
    });
  }

  if (!hasOwn(raw, "target_url") || typeof raw.target_url !== "string" || !raw.target_url.trim()) {
    throw blockedDecision(rule, args, {
      errorCode: "legacy_security_field_missing",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: "session authority field is missing: target_url",
      authorityTargetDomain,
      sessionPresent: true,
      match: true,
    });
  }

  try {
    validateHttpScanScope(raw.target_url, authorityTargetDomain);
  } catch {
    throw blockedDecision(rule, args, {
      errorCode: "target_url_drift",
      envelopeCode: ERROR_CODES.SCOPE_BLOCKED,
      message: `Session authority target_url drift for ${authorityTargetDomain}`,
      authorityTargetDomain,
      sessionPresent: true,
      match: true,
    });
  }

  assertLegacyFailClosedFields(raw, rule, args, authorityTargetDomain);

  try {
    normalizeSessionStateDocument(raw, authorityTargetDomain);
  } catch {
    throw blockedDecision(rule, args, {
      errorCode: "malformed_state",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: `Session authority state is malformed for ${authorityTargetDomain}`,
      authorityTargetDomain,
      sessionPresent: true,
      match: true,
    });
  }

  return raw;
}

function authorizeBootstrap(rule, args) {
  const authorityTargetDomain = normalizeArgumentTarget(rule, args);
  if (typeof args.target_url !== "string" || !args.target_url.trim()) {
    throw blockedDecision(rule, args, {
      errorCode: "normalization_failed",
      envelopeCode: ERROR_CODES.INVALID_ARGUMENTS,
      message: "target_url is required for session authority",
      authorityTargetDomain,
      sessionPresent: false,
      match: false,
    });
  }
  try {
    validateHttpScanScope(args.target_url, authorityTargetDomain);
  } catch (error) {
    throw blockedDecision(rule, args, {
      errorCode: "target_url_drift",
      envelopeCode: ERROR_CODES.SCOPE_BLOCKED,
      message: error.message || String(error),
      authorityTargetDomain,
      sessionPresent: false,
      match: false,
      details: error.details,
    });
  }
  return allowedDecision(rule, args, {
    authorityTargetDomain,
    source: "bootstrap",
    sessionPresent: false,
    match: true,
  });
}

function authorizeSessionBound(tool, rule, args) {
  const authorityTargetDomain = normalizeArgumentTarget(rule, args);
  try {
    readRawAuthorityState(authorityTargetDomain, rule, args);
  } catch (error) {
    const shadow = shadowDecision(error, tool, rule);
    if (shadow) return shadow;
    throw error;
  }
  return allowedDecision(rule, args, {
    authorityTargetDomain,
    source: "session_state",
    sessionPresent: true,
    match: true,
  });
}

function validateSessionAuthorityState(targetDomain, {
  authorityClass = "cross_session_read",
  authoritySource = "cross_session",
} = {}) {
  const args = { target_domain: targetDomain };
  const rule = {
    authority_class: authorityClass,
    target_domain: "required",
    target_url_policy: "validate_before_target_url_export",
    authority_source: authoritySource,
  };
  const authorityTargetDomain = normalizeArgumentTarget(rule, args);
  readRawAuthorityState(authorityTargetDomain, rule, args);
  return allowedDecision(rule, args, {
    authorityTargetDomain,
    source: authoritySource,
    sessionPresent: true,
    match: true,
  });
}

function authorizeToolCall(tool, args = {}) {
  const rule = baseRuleForTool(tool, args);
  if (!rule) {
    throw blockedDecision({
      authority_class: null,
      authority_source: "global",
    }, args, {
      errorCode: "class_missing",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: `Missing authority class for ${tool && tool.name ? tool.name : "<unknown>"}`,
      sessionPresent: null,
      match: null,
    });
  }
  if (!AUTHORITY_CLASSES.includes(rule.authority_class)) {
    throw blockedDecision(rule, args, {
      errorCode: "class_missing",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: `Unknown authority class for ${tool.name}: ${rule.authority_class}`,
      sessionPresent: null,
      match: null,
    });
  }
  if (rule.authority_class === "bootstrap_session") {
    return authorizeBootstrap(rule, args);
  }
  if (SESSION_AUTHORITY_CLASSES.has(rule.authority_class)) {
    return authorizeSessionBound(tool, rule, args);
  }
  if (rule.authority_class === "global_preapproval") {
    return allowedDecision(rule, args, {
      source: "preapproval_global",
      sessionPresent: false,
      match: null,
    });
  }
  if (rule.authority_class === "global_read") {
    return allowedDecision(rule, args, {
      source: rule.authority_source || "global",
      sessionPresent: false,
      match: null,
    });
  }
  if (rule.authority_class === "cross_session_read") {
    return allowedDecision(rule, args, {
      source: "cross_session",
      sessionPresent: null,
      match: null,
    });
  }
  throw blockedDecision(rule, args, {
    errorCode: "class_missing",
    envelopeCode: ERROR_CODES.STATE_CONFLICT,
    message: `Unhandled authority class for ${tool.name}: ${rule.authority_class}`,
    sessionPresent: null,
    match: null,
  });
}

function scopedUrlDriftError(baseDecision, field, error) {
  const decision = {
    ...baseDecision,
    authority_result: "blocked",
    authority_error_code: "scoped_url_drift",
    authority_block_reason: "scoped_url_drift",
    authority_shadowed: false,
  };
  const toolError = new ToolError(
    ERROR_CODES.SCOPE_BLOCKED,
    `${field} is outside target scope: ${error.message || String(error)}`,
    {
      ...(error.details || {}),
      authority: decision,
    },
  );
  toolError.authority = decision;
  return toolError;
}

function normalizeAuthorityTelemetry(authority) {
  if (!authority || typeof authority !== "object" || Array.isArray(authority)) {
    return null;
  }
  return makeDecision(authority);
}

module.exports = {
  AUTHORITY_CLASSES,
  AUTHORITY_MODE_ENV,
  AUTHORITY_VERSION,
  EXPLICIT_AUTHORITY_CLASS_BY_TOOL,
  LEGACY_DEFAULTABLE_FIELDS,
  LEGACY_FAIL_CLOSED_FIELDS,
  authorizeToolCall,
  baseRuleForTool,
  classForTool,
  normalizeAuthorityTelemetry,
  scopedUrlDriftError,
  validateSessionAuthorityState,
};
