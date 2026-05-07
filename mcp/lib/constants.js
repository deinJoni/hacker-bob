"use strict";

const FINDING_ID_RE = /^F-([1-9]\d*)$/;
const WAVE_ID_RE = /^w([1-9]\d*)$/;
const AGENT_ID_RE = /^a([1-9]\d*)$/;

const SEVERITY_VALUES = ["critical", "high", "medium", "low", "info"];
const SURFACE_TYPE_VALUES = ["web", "smart_contract"];
const CHAIN_FAMILY_VALUES = ["evm", "svm", "aptos", "sui", "substrate", "cosmwasm"];
const SVM_CLUSTER_VALUES = ["mainnet-beta", "devnet", "testnet"];
// Aptos and Sui both identify networks by string name in tooling and RPC URLs.
// Integer chain IDs exist on Aptos (1, 2, ...), but they're used for replay
// protection — operators key RPC pools by network NAME (mainnet/testnet/etc).
// Sui has no integer chain id at all. Aptos lacks a stable persistent
// "localnet" — the local testnet has a dynamically rotating chain_id.
const APTOS_NETWORK_VALUES = ["mainnet", "testnet", "devnet"];
const SUI_NETWORK_VALUES = ["mainnet", "testnet", "devnet", "localnet"];
// Substrate parachains identify networks by name. Polkadot, Kusama, Astar,
// Shiden, and the testnets (Rococo, Westend) are the common ink! deployment
// targets in 2025-2026. Operators add private parachain chains via env
// override (BOB_SUBSTRATE_RPCS_<NAME>=...). Localnet covers `substrate-contracts-node`
// dev environments running on 127.0.0.1.
const SUBSTRATE_NETWORK_VALUES = [
  "polkadot",
  "kusama",
  "astar",
  "shiden",
  "rococo",
  "westend",
  "localnet",
];
// CosmWasm chains identify networks by chain name. The 2025-2026 active set
// ships with osmosis, juno, neutron, archway, sei, stargaze, terra (terra2),
// and kava. Localnet covers `wasmd`/`junod` dev environments. Operators add
// new chains via env override (BOB_COSMWASM_RPCS_<NAME>=...).
const COSMWASM_NETWORK_VALUES = [
  "osmosis",
  "juno",
  "neutron",
  "archway",
  "sei",
  "stargaze",
  "terra",
  "kava",
  "localnet",
];
const PHASE_VALUES = ["RECON", "AUTH", "HUNT", "CHAIN", "VERIFY", "GRADE", "REPORT", "EXPLORE"];
const AUTH_STATUS_VALUES = ["pending", "authenticated", "unauthenticated"];
const VERIFICATION_ROUND_VALUES = ["brutalist", "balanced", "final"];
const VERIFICATION_DISPOSITION_VALUES = ["confirmed", "denied", "downgraded"];
const GRADE_VERDICT_VALUES = ["SUBMIT", "HOLD", "SKIP"];
const GRADE_HOLD_MIN_SCORE = 20;
const GRADE_SUBMIT_MIN_SCORE = 40;
const CHAIN_ATTEMPT_OUTCOME_VALUES = ["confirmed", "denied", "blocked", "inconclusive", "not_applicable"];
const CHAIN_ATTEMPT_TERMINAL_OUTCOME_VALUES = ["confirmed", "denied", "blocked", "not_applicable"];

const COVERAGE_STATUS_VALUES = ["tested", "blocked", "promising", "needs_auth", "requeue"];
const COVERAGE_UNFINISHED_STATUS_VALUES = ["promising", "needs_auth", "requeue"];
const COVERAGE_SUMMARY_MAX_ITEMS = 40;
const COVERAGE_LOG_MAX_RECORDS = 5_000;
const TECHNIQUE_ATTEMPT_STATUS_VALUES = ["selected", "attempted", "not_applicable", "promising", "validated", "failed", "skipped"];
const TECHNIQUE_ATTEMPT_LOG_MAX_RECORDS = 5_000;
const TECHNIQUE_PACK_READ_LOG_MAX_RECORDS = 5_000;
const HTTP_AUDIT_SUMMARY_MAX_ITEMS = 40;
const HTTP_AUDIT_LOG_MAX_RECORDS = 5_000;
const TRAFFIC_SUMMARY_MAX_ITEMS = 40;
const TRAFFIC_IMPORT_MAX_ENTRIES = 500;
const TRAFFIC_LOG_MAX_RECORDS = 5_000;
const PUBLIC_INTEL_MAX_ITEMS = 10;
const PUBLIC_INTEL_MAX_RESPONSE_BYTES = 300_000;
const STATIC_ARTIFACT_ID_RE = /^SA-([1-9]\d*)$/;
const STATIC_ARTIFACT_TYPE_VALUES = ["evm_token_contract", "solana_token_contract"];
const STATIC_ARTIFACT_MAX_CHARS = 200_000;
const STATIC_ARTIFACT_LOG_MAX_RECORDS = 500;
const STATIC_SCAN_RESULTS_MAX_RECORDS = 1_000;
const STATIC_SCAN_FINDING_MAX_ITEMS = 100;
const STATIC_SCAN_HINT_MAX_ITEMS = 10;
const CIRCUIT_BREAKER_THRESHOLD = 3;

const SESSION_LOCK_NAME = ".session.lock";
const SESSION_LOCK_STALE_MS = 300_000;
const SESSION_PUBLIC_STATE_FIELDS = [
  "target",
  "target_url",
  "deep_mode",
  "phase",
  "hunt_wave",
  "pending_wave",
  "total_findings",
  "explored",
  "terminally_blocked",
  "prereq_registry_snapshots",
  "blocked_prereq_history",
  "terminal_block_clear_history",
  "dead_ends",
  "waf_blocked_endpoints",
  "lead_surface_ids",
  "scope_exclusions",
  "hold_count",
  "auth_status",
  "operator_note",
];

const VERIFICATION_ROUND_FILE_MAP = {
  brutalist: { json: "brutalist.json", markdown: "brutalist.md" },
  balanced: { json: "balanced.json", markdown: "balanced.md" },
  final: { json: "verified-final.json", markdown: "verified-final.md" },
};

module.exports = {
  AGENT_ID_RE,
  APTOS_NETWORK_VALUES,
  AUTH_STATUS_VALUES,
  CHAIN_ATTEMPT_OUTCOME_VALUES,
  CHAIN_ATTEMPT_TERMINAL_OUTCOME_VALUES,
  CHAIN_FAMILY_VALUES,
  CIRCUIT_BREAKER_THRESHOLD,
  COSMWASM_NETWORK_VALUES,
  COVERAGE_LOG_MAX_RECORDS,
  COVERAGE_STATUS_VALUES,
  COVERAGE_SUMMARY_MAX_ITEMS,
  COVERAGE_UNFINISHED_STATUS_VALUES,
  FINDING_ID_RE,
  GRADE_HOLD_MIN_SCORE,
  GRADE_SUBMIT_MIN_SCORE,
  GRADE_VERDICT_VALUES,
  HTTP_AUDIT_LOG_MAX_RECORDS,
  HTTP_AUDIT_SUMMARY_MAX_ITEMS,
  PHASE_VALUES,
  PUBLIC_INTEL_MAX_ITEMS,
  PUBLIC_INTEL_MAX_RESPONSE_BYTES,
  SESSION_LOCK_NAME,
  SESSION_LOCK_STALE_MS,
  SESSION_PUBLIC_STATE_FIELDS,
  SEVERITY_VALUES,
  STATIC_ARTIFACT_ID_RE,
  STATIC_ARTIFACT_LOG_MAX_RECORDS,
  STATIC_ARTIFACT_MAX_CHARS,
  STATIC_ARTIFACT_TYPE_VALUES,
  STATIC_SCAN_FINDING_MAX_ITEMS,
  STATIC_SCAN_HINT_MAX_ITEMS,
  STATIC_SCAN_RESULTS_MAX_RECORDS,
  TECHNIQUE_ATTEMPT_LOG_MAX_RECORDS,
  TECHNIQUE_ATTEMPT_STATUS_VALUES,
  TECHNIQUE_PACK_READ_LOG_MAX_RECORDS,
  SUBSTRATE_NETWORK_VALUES,
  SUI_NETWORK_VALUES,
  SURFACE_TYPE_VALUES,
  SVM_CLUSTER_VALUES,
  TRAFFIC_IMPORT_MAX_ENTRIES,
  TRAFFIC_LOG_MAX_RECORDS,
  TRAFFIC_SUMMARY_MAX_ITEMS,
  VERIFICATION_DISPOSITION_VALUES,
  VERIFICATION_ROUND_FILE_MAP,
  VERIFICATION_ROUND_VALUES,
  WAVE_ID_RE,
};
