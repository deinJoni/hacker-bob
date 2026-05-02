"use strict";

// Capability pack manifest. Each pack is the single source of truth for:
//   id              — string used in surface-routes.json and findings.jsonl
//   hunter_agent    — Claude/Codex subagent name spawned for this pack
//   brief_profile   — selects which buildBriefExtras builder hunter-brief calls
//   role_bundles    — MCP tool bundles the spawned hunter sees
//   completion_gate — wave-handoff completion rule the merge layer enforces
//   verifier        — pack-keyed PoC replay for brutalist/balanced/final verifier
//   evidence        — pack-keyed runner for evidence-agent's pre-grade re-runs
//   spawn           — pack-keyed spawn template strings consumed by both the
//                     Claude and Codex orchestrator-skill renderers
//
// Verifier and evidence consumers look up the pack by finding.capability_pack
// and dispatch on the verifier/evidence blocks instead of branching on
// chain_family in their prompts. The orchestrator hunter spawn template body
// is composed from spawn fields, so adding a chain pack auto-generates its
// catalogue entry without touching any renderer.

const WEB_CAPABILITY_PACK = Object.freeze({
  id: "web",
  hunter_agent: "hunter-agent",
  brief_profile: "web",
  role_bundles: Object.freeze(["hunter-shared", "hunter-web"]),
  completion_gate: "web_wave_handoff",
  verifier: Object.freeze({
    // Web verifier replay is a fresh HTTP call against the same endpoint
    // with the captured auth profile. Verifier extracts the request from
    // the finding's PoC and re-issues via bounty_http_scan.
    replay_tool: "bounty_http_scan",
    sample_type: "http_replay",
    fresh_state_omit_field: null,        // HTTP has no fork concept
    disambiguation: null,                // single endpoint, no chain confusion
  }),
  evidence: Object.freeze({
    runner: "bounty_http_scan",
    sample_type: "http_replay",
  }),
  // Web pack uses a structurally distinct spawn body (web context fields,
  // auth profiles, geofence rule). The renderer recognises profile="web"
  // and emits the legacy SPAWN_HUNTER_AGENT body unchanged.
  spawn: Object.freeze({
    profile: "web",
  }),
});

const SMART_CONTRACT_EVM_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_evm",
  hunter_agent: "hunter-evm-agent",
  brief_profile: "smart_contract_evm",
  role_bundles: Object.freeze(["hunter-shared", "hunter-evm"]),
  completion_gate: "smart_contract_wave_handoff",
  verifier: Object.freeze({
    replay_tool: "bounty_foundry_run",
    sample_type: "evm_foundry_run",
    fresh_state_omit_field: "fork_block",
    // The runner response field carrying the resolved block reference
    // (block / slot / version / checkpoint depending on chain). Final
    // verifier captures this for the report's "verified at block N" line.
    block_reference_field: "fork_block_used",
    block_reference_label: "block",
    // EVM 0x... addresses are unambiguous across EVM chains; chain_id alone
    // fixes the fork RPC. No read-side disambiguation required.
    disambiguation: null,
  }),
  evidence: Object.freeze({
    runner: "bounty_foundry_run",
    sample_type: "evm_foundry_run",
  }),
  spawn: Object.freeze({
    profile: "smart_contract",
    chain_family: "evm",
    role_id: "hunter-evm",
    hunter_name_prefix: "hunter-evm",
    chain_id_description: "the EVM chain id (e.g., 1, 137, 10, 42161)",
    workflow_summary: "bounty_evm_fetch_source -> read sources via Read -> bounty_evm_role_table to map the trust boundary -> scaffold a Foundry test under harness_path/test/ via Write -> bounty_foundry_run with chain_id and pinned fork_block -> record bypass_attempts[] entries citing the actual harness path + test name in attempt_summary.",
    cli_dependency: "forge",
    blocked_harness_kind_options: "foundry_fork or rpc_endpoint",
  }),
});

const SMART_CONTRACT_SVM_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_svm",
  hunter_agent: "hunter-svm-agent",
  brief_profile: "smart_contract_svm",
  role_bundles: Object.freeze(["hunter-shared", "hunter-svm"]),
  completion_gate: "smart_contract_wave_handoff",
  verifier: Object.freeze({
    replay_tool: "bounty_anchor_run",
    sample_type: "svm_anchor_run",
    // The runner-input parameter that pins replay to a specific chain
    // ordering point. sc_evidence persists a single `fork_block` field
    // (findings.js), and the verifier translates it into this runner
    // parameter when calling the runner. Omitting this parameter forces
    // a fresh-state replay against current cluster state.
    fresh_state_omit_field: "fork_slot",
    block_reference_field: "fork_slot_used",
    block_reference_label: "slot",
    disambiguation: null,
  }),
  evidence: Object.freeze({
    runner: "bounty_anchor_run",
    sample_type: "svm_anchor_run",
  }),
  spawn: Object.freeze({
    profile: "smart_contract",
    chain_family: "svm",
    role_id: "hunter-svm",
    hunter_name_prefix: "hunter-svm",
    chain_id_description: "the Solana cluster",
    workflow_summary: "bounty_svm_fetch_program (confirm upgrade authority) -> bounty_svm_fetch_account (read multisig + state accounts) -> scaffold an Anchor test under harness_path/tests/ via Write -> bounty_anchor_run with cluster and optional pinned fork_slot -> record bypass_attempts[] entries citing the actual harness path + test description in attempt_summary.",
    cli_dependency: "anchor",
    blocked_harness_kind_options: "anchor_fork",
  }),
});

// Aptos and Sui are separate packs so verifier dispatch is one runner per
// pack (bounty_aptos_run vs bounty_sui_run). Both packs still route to
// hunter-move-agent — the agent's own tool list covers both bounty_aptos_*
// and bounty_sui_*.
const SMART_CONTRACT_APTOS_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_aptos",
  hunter_agent: "hunter-move-agent",
  brief_profile: "smart_contract_aptos",
  role_bundles: Object.freeze(["hunter-shared", "hunter-move"]),
  completion_gate: "smart_contract_wave_handoff",
  verifier: Object.freeze({
    replay_tool: "bounty_aptos_run",
    sample_type: "aptos_move_test",
    fresh_state_omit_field: "fork_version",
    block_reference_field: "fork_version_used",
    block_reference_label: "ledger_version",
    // Aptos and Sui share the same 0x + 64-hex address space; the runner
    // alone cannot detect a wrong-network record. Verifier must call
    // bounty_aptos_fetch_module to confirm the module exists on the
    // claimed network before passing through.
    disambiguation: Object.freeze({
      tool: "bounty_aptos_fetch_module",
      fail_reason: "address does not resolve on the claimed Aptos network; chain_family/chain_id mismatch suspected",
    }),
  }),
  evidence: Object.freeze({
    runner: "bounty_aptos_run",
    sample_type: "aptos_move_test",
  }),
  spawn: Object.freeze({
    profile: "smart_contract",
    chain_family: "aptos",
    role_id: "hunter-move",
    hunter_name_prefix: "hunter-aptos",
    chain_id_description: "the network name (mainnet/testnet/devnet)",
    workflow_summary: "bounty_aptos_fetch_module (enumerate exposed_functions, structs, friends) -> bounty_aptos_fetch_resource (read capability tokens, ownership records, treasury balances) -> scaffold an `aptos move test` harness under harness_path/sources/ via Write -> bounty_aptos_run with network and optional pinned fork_version -> record bypass_attempts[] citing the actual harness path + test name in attempt_summary.",
    cli_dependency: "aptos",
    blocked_harness_kind_options: "aptos_fork",
  }),
});

const SMART_CONTRACT_SUI_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_sui",
  hunter_agent: "hunter-move-agent",
  brief_profile: "smart_contract_sui",
  role_bundles: Object.freeze(["hunter-shared", "hunter-move"]),
  completion_gate: "smart_contract_wave_handoff",
  verifier: Object.freeze({
    replay_tool: "bounty_sui_run",
    sample_type: "sui_move_test",
    fresh_state_omit_field: "fork_checkpoint",
    block_reference_field: "fork_checkpoint_used",
    block_reference_label: "checkpoint",
    disambiguation: Object.freeze({
      tool: "bounty_sui_fetch_package",
      fail_reason: "package does not resolve on the claimed Sui network; chain_family/chain_id mismatch suspected",
    }),
  }),
  evidence: Object.freeze({
    runner: "bounty_sui_run",
    sample_type: "sui_move_test",
  }),
  spawn: Object.freeze({
    profile: "smart_contract",
    chain_family: "sui",
    role_id: "hunter-move",
    hunter_name_prefix: "hunter-sui",
    chain_id_description: "the network name (mainnet/testnet/devnet/localnet)",
    workflow_summary: "bounty_sui_fetch_package (enumerate entry functions and friend relationships) -> bounty_sui_fetch_object (inspect Owner=Immutable/Shared/AddressOwner/ObjectOwner, Move type, capability fields) -> scaffold a `sui move test` harness under harness_path/sources/ via Write -> bounty_sui_run with network and optional pinned fork_checkpoint -> record bypass_attempts[] citing the actual harness path + test name in attempt_summary.",
    cli_dependency: "sui",
    blocked_harness_kind_options: "sui_fork",
  }),
});

const SMART_CONTRACT_SUBSTRATE_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_substrate",
  hunter_agent: "hunter-substrate-agent",
  brief_profile: "smart_contract_substrate",
  role_bundles: Object.freeze(["hunter-shared", "hunter-substrate"]),
  completion_gate: "smart_contract_wave_handoff",
  verifier: Object.freeze({
    replay_tool: "bounty_substrate_run",
    sample_type: "substrate_ink_test",
    fresh_state_omit_field: "fork_block",
    block_reference_field: "fork_block_used",
    block_reference_label: "block",
    // SS58 addresses share base58 alphabet with chain-specific prefix
    // bytes the validator does not BLAKE2b-check (cost). A Kusama address
    // could be recorded against polkadot. Verifier must read storage on
    // the claimed network before passing through.
    disambiguation: Object.freeze({
      tool: "bounty_substrate_fetch_storage",
      fail_reason: "address does not resolve on the claimed Substrate network; chain_family/chain_id mismatch suspected",
    }),
  }),
  evidence: Object.freeze({
    runner: "bounty_substrate_run",
    sample_type: "substrate_ink_test",
  }),
  spawn: Object.freeze({
    profile: "smart_contract",
    chain_family: "substrate",
    role_id: "hunter-substrate",
    hunter_name_prefix: "hunter-substrate",
    chain_id_description: "the network name (polkadot/kusama/astar/shiden/rococo/westend/localnet)",
    workflow_summary: "bounty_substrate_fetch_runtime (confirm chain identity + spec_version) -> bounty_substrate_fetch_storage (read pallet_contracts.ContractInfoOf for code_hash and admin) -> scaffold an ink! `cargo test` harness under harness_path/ via Write (uses #[ink::test] for unit or #[ink_e2e::test] for E2E) -> bounty_substrate_run with network and optional pinned fork_block -> record bypass_attempts[] citing the actual harness path + test name in attempt_summary.",
    cli_dependency: "cargo or substrate-contracts-node",
    blocked_harness_kind_options: "substrate_fork",
  }),
});

const SMART_CONTRACT_COSMWASM_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_cosmwasm",
  hunter_agent: "hunter-cosmwasm-agent",
  brief_profile: "smart_contract_cosmwasm",
  role_bundles: Object.freeze(["hunter-shared", "hunter-cosmwasm"]),
  completion_gate: "smart_contract_wave_handoff",
  verifier: Object.freeze({
    replay_tool: "bounty_cosmwasm_run",
    sample_type: "cosmwasm_cw_multi_test",
    fresh_state_omit_field: "fork_block",
    block_reference_field: "fork_block_used",
    block_reference_label: "block",
    // bech32 addresses with different HRPs share the bech32 character
    // space — an osmo1... could be recorded against juno. Verifier must
    // call bounty_cosmwasm_fetch_contract on the claimed network.
    disambiguation: Object.freeze({
      tool: "bounty_cosmwasm_fetch_contract",
      fail_reason: "address does not resolve on the claimed CosmWasm network; chain_family/chain_id mismatch suspected",
    }),
  }),
  evidence: Object.freeze({
    runner: "bounty_cosmwasm_run",
    sample_type: "cosmwasm_cw_multi_test",
  }),
  spawn: Object.freeze({
    profile: "smart_contract",
    chain_family: "cosmwasm",
    role_id: "hunter-cosmwasm",
    hunter_name_prefix: "hunter-cosmwasm",
    chain_id_description: "the network name (osmosis/juno/neutron/archway/sei/stargaze/terra/kava/localnet)",
    workflow_summary: "bounty_cosmwasm_fetch_contract (confirm contract exists, capture code_id + admin) -> bounty_cosmwasm_smart_query (inspect public Config / Owner / Balance entrypoints) -> scaffold a cw-multi-test integration test under harness_path/tests/ via Write -> bounty_cosmwasm_run with network and optional pinned fork_block -> record bypass_attempts[] citing the actual harness path + test name in attempt_summary.",
    cli_dependency: "cargo",
    blocked_harness_kind_options: "cosmwasm_fork",
  }),
});

const CAPABILITY_PACKS = Object.freeze({
  web: WEB_CAPABILITY_PACK,
  smart_contract_evm: SMART_CONTRACT_EVM_CAPABILITY_PACK,
  smart_contract_svm: SMART_CONTRACT_SVM_CAPABILITY_PACK,
  smart_contract_aptos: SMART_CONTRACT_APTOS_CAPABILITY_PACK,
  smart_contract_sui: SMART_CONTRACT_SUI_CAPABILITY_PACK,
  smart_contract_substrate: SMART_CONTRACT_SUBSTRATE_CAPABILITY_PACK,
  smart_contract_cosmwasm: SMART_CONTRACT_COSMWASM_CAPABILITY_PACK,
});

// Hunter-role registry — keyed by role_id, deduped across packs. Multiple
// capability packs that share a role_id (Move-family aptos+sui both route
// to hunter-move-agent) collapse to a single role spec here. role-model.js,
// claude-role-renderer.js, codex/role-specs.js, and tool-registry.js all
// derive their hunter role specs from this map. Adding a chain pack means
// adding an entry here and a CAPABILITY_PACKS entry plus a new
// prompts/roles/hunter-X.md, plus the per-chain validation in findings.js.
//
// Cross-cutting roles (orchestrator, recon, deep-recon, surface-router,
// chain, brutalist-verifier, balanced-verifier, final-verifier, evidence,
// grader, reporter, status, debug, hunter [web]) stay defined inside the
// individual consumer modules — they are not chain-specific and there is
// no value in routing them through this registry.
const HUNTER_ROLES = Object.freeze({
  "hunter-evm": Object.freeze({
    role_id: "hunter-evm",
    name: "hunter-evm-agent",
    description: "EVM smart-contract bug bounty hunter — spawned per smart_contract surface, scaffolds and runs Foundry tests against the public RPC ladder",
    color: "magenta",
    role_bundles: Object.freeze(["hunter-shared", "hunter-evm"]),
    prompt_body_filename: "hunter-evm.md",
  }),
  "hunter-svm": Object.freeze({
    role_id: "hunter-svm",
    name: "hunter-svm-agent",
    description: "SVM (Solana) smart-contract bug bounty hunter — spawned per smart_contract surface with chain_family=svm, scaffolds and runs Anchor tests against the public Solana RPC ladder",
    color: "cyan",
    role_bundles: Object.freeze(["hunter-shared", "hunter-svm"]),
    prompt_body_filename: "hunter-svm.md",
  }),
  "hunter-move": Object.freeze({
    role_id: "hunter-move",
    name: "hunter-move-agent",
    description: "Move (Aptos + Sui) smart-contract bug bounty hunter — spawned per smart_contract surface with chain_family in {aptos, sui}, scaffolds and runs aptos move test or sui move test against the public Move RPC ladders",
    color: "blue",
    role_bundles: Object.freeze(["hunter-shared", "hunter-move"]),
    prompt_body_filename: "hunter-move.md",
  }),
  "hunter-substrate": Object.freeze({
    role_id: "hunter-substrate",
    name: "hunter-substrate-agent",
    description: "Substrate / ink! smart-contract bug bounty hunter — spawned per smart_contract surface with chain_family=substrate, scaffolds and runs cargo test on ink! contracts against the public Substrate JSON-RPC ladder",
    color: "pink",
    role_bundles: Object.freeze(["hunter-shared", "hunter-substrate"]),
    prompt_body_filename: "hunter-substrate.md",
  }),
  "hunter-cosmwasm": Object.freeze({
    role_id: "hunter-cosmwasm",
    name: "hunter-cosmwasm-agent",
    description: "CosmWasm smart-contract bug bounty hunter — spawned per smart_contract surface with chain_family=cosmwasm, scaffolds and runs cargo test with cw-multi-test against the public CosmWasm REST ladder",
    color: "yellow",
    role_bundles: Object.freeze(["hunter-shared", "hunter-cosmwasm"]),
    prompt_body_filename: "hunter-cosmwasm.md",
  }),
});

const WEB_SURFACE_TYPES = Object.freeze([
  "admin",
  "api",
  "auth",
  "billing",
  "ci_cd",
  "cms",
  "graphql",
  "js_endpoint",
  "mobile_api",
  "secrets",
  "static",
  "unknown",
  "upload",
]);

const WEB_SURFACE_TYPE_SET = new Set(WEB_SURFACE_TYPES);

// Smart-contract surfaces are routed by `chain_family`. Aptos and Sui have
// distinct packs (so verifier dispatch is one runner per pack) but both
// route to hunter-move-agent — the agent's tool list covers both
// bounty_aptos_* and bounty_sui_*.
const SMART_CONTRACT_CHAIN_FAMILY_TO_PACK = Object.freeze({
  evm: SMART_CONTRACT_EVM_CAPABILITY_PACK,
  svm: SMART_CONTRACT_SVM_CAPABILITY_PACK,
  aptos: SMART_CONTRACT_APTOS_CAPABILITY_PACK,
  sui: SMART_CONTRACT_SUI_CAPABILITY_PACK,
  substrate: SMART_CONTRACT_SUBSTRATE_CAPABILITY_PACK,
  cosmwasm: SMART_CONTRACT_COSMWASM_CAPABILITY_PACK,
});

function normalizeSurfaceType(value) {
  if (value == null) return null;
  const normalized = String(value).trim().toLowerCase().replace(/[\s-]+/g, "_");
  return normalized || null;
}

function getCapabilityPack(packId) {
  return CAPABILITY_PACKS[packId] || null;
}

function hunterAgentNamesForCapabilityPacks() {
  return Array.from(new Set(
    Object.values(CAPABILITY_PACKS)
      .map((pack) => pack && pack.hunter_agent)
      .filter((value) => typeof value === "string" && value.trim()),
  ));
}

// Spawn-template iteration helper consumed by Claude/Codex
// orchestrator-skill renderers.
function smartContractCapabilityPacks() {
  return Object.values(CAPABILITY_PACKS).filter(
    (pack) => pack && pack.spawn && pack.spawn.profile === "smart_contract",
  );
}

function hunterRoleSpec(roleId) {
  const spec = HUNTER_ROLES[roleId];
  if (!spec) throw new Error(`Unknown hunter role id: ${roleId}`);
  return spec;
}

function hunterRoleSpecs() {
  return Object.values(HUNTER_ROLES);
}

// Chain-specific role bundles derived from HUNTER_ROLES, used by
// tool-registry.js to build VALID_ROLE_BUNDLES at module load. Adding a
// hunter role automatically adds its role bundle here. role_bundles[0]
// is "hunter-shared" across every role; role_bundles[1+] are the
// chain-specific bundles.
function chainSpecificHunterBundles() {
  const bundles = new Set();
  for (const role of hunterRoleSpecs()) {
    for (const bundle of role.role_bundles) {
      if (bundle === "hunter-shared") continue;
      bundles.add(bundle);
    }
  }
  return Array.from(bundles).sort();
}

function defaultWebRouteMetadata() {
  return {
    capability_pack: WEB_CAPABILITY_PACK.id,
    hunter_agent: WEB_CAPABILITY_PACK.hunter_agent,
    brief_profile: WEB_CAPABILITY_PACK.brief_profile,
  };
}

function classifySurfaceCapability(surface) {
  const rawSurfaceType = surface && typeof surface === "object" ? surface.surface_type : null;
  const normalizedType = normalizeSurfaceType(rawSurfaceType);
  const surfaceType = normalizedType || "unknown";
  const reasons = normalizedType ? [`surface_type:${surfaceType}`] : ["surface_type:missing"];

  if (normalizedType === "smart_contract") {
    const rawChainFamily = surface && typeof surface === "object" ? surface.chain_family : null;
    const normalizedChainFamily = normalizeSurfaceType(rawChainFamily);
    if (normalizedChainFamily) {
      const pack = SMART_CONTRACT_CHAIN_FAMILY_TO_PACK[normalizedChainFamily];
      if (pack) {
        reasons.push(`chain_family:${normalizedChainFamily}`);
        return {
          surface_type: surfaceType,
          capability_pack: pack.id,
          hunter_agent: pack.hunter_agent,
          brief_profile: pack.brief_profile,
          confidence: "high",
          reasons,
        };
      }
      // Smart-contract surface with an unrecognised chain_family. Falling
      // back to the web pack would create a contradiction (surface_type=smart_contract
      // routed to a hunter that has no on-chain tools); fail loudly so the
      // operator either fixes the surface or registers the missing pack.
      throw new Error(
        `smart_contract surface ${surface && surface.id ? surface.id : "(unknown)"} has unsupported chain_family ${normalizedChainFamily}; register a capability pack or correct the surface`,
      );
    }
    throw new Error(
      `smart_contract surface ${surface && surface.id ? surface.id : "(unknown)"} is missing chain_family; capability routing requires it`,
    );
  }

  const knownWebType = normalizedType == null || WEB_SURFACE_TYPE_SET.has(surfaceType);
  if (!knownWebType) {
    reasons.push("fallback:web");
  }

  return {
    surface_type: surfaceType,
    capability_pack: WEB_CAPABILITY_PACK.id,
    hunter_agent: WEB_CAPABILITY_PACK.hunter_agent,
    brief_profile: WEB_CAPABILITY_PACK.brief_profile,
    confidence: knownWebType ? "high" : "medium",
    reasons,
  };
}

function assertPackString(value, fieldName) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`assignment route metadata has invalid ${fieldName}`);
  }
  const normalized = value.trim();
  if (!/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(normalized)) {
    throw new Error(`assignment route metadata has invalid ${fieldName}`);
  }
  return normalized;
}

function normalizeAssignmentRouteMetadata(assignment) {
  const hasRouteMetadata = !!assignment && (
    assignment.capability_pack != null ||
    assignment.hunter_agent != null ||
    assignment.brief_profile != null
  );
  if (!hasRouteMetadata) {
    // Legacy assignment files (pre-router) carry no route metadata. Default
    // to the web pack — but ONLY if the captured surface_type is non-SC. A
    // smart_contract assignment with no route triple would otherwise be
    // silently stamped as a web hunter; that contradicts surface_type and
    // sends pack-keyed consumers into the wrong pipeline.
    const surfaceType = assignment && typeof assignment === "object"
      ? assignment.surface_type
      : null;
    if (surfaceType === "smart_contract") {
      throw new Error(
        "assignment with surface_type=smart_contract is missing capability_pack/hunter_agent/brief_profile; route the surface via bounty_route_surfaces before starting the wave",
      );
    }
    return defaultWebRouteMetadata();
  }

  const capabilityPack = assertPackString(assignment.capability_pack, "capability_pack");
  const hunterAgent = assertPackString(assignment.hunter_agent, "hunter_agent");
  const briefProfile = assertPackString(assignment.brief_profile, "brief_profile");
  const pack = getCapabilityPack(capabilityPack);
  if (!pack) {
    throw new Error(`assignment route metadata references unknown capability_pack: ${capabilityPack}`);
  }
  if (hunterAgent !== pack.hunter_agent) {
    throw new Error(`assignment route metadata hunter_agent ${hunterAgent} does not match pack ${capabilityPack}`);
  }
  if (briefProfile !== pack.brief_profile) {
    throw new Error(`assignment route metadata brief_profile ${briefProfile} does not match pack ${capabilityPack}`);
  }

  return {
    capability_pack: capabilityPack,
    hunter_agent: hunterAgent,
    brief_profile: briefProfile,
  };
}

// Read-side backfill for legacy findings.jsonl rows written before
// bounty_record_finding persisted the route triple. Legacy rows carry
// surface_type and (for SC findings) sc_evidence.chain_family but no
// capability_pack/hunter_agent/brief_profile. Reconstructing the triple
// at read time keeps verifier/evidence/grader/reporter consumers from
// each having to implement the same fallback. Returns null when the
// record carries no usable signal.
function capabilityPackForLegacyFinding({ surface_type: surfaceType, sc_evidence: scEvidence } = {}) {
  if (surfaceType === "smart_contract") {
    const chainFamily = scEvidence && typeof scEvidence === "object" ? scEvidence.chain_family : null;
    const normalized = normalizeSurfaceType(chainFamily);
    if (normalized) {
      const pack = SMART_CONTRACT_CHAIN_FAMILY_TO_PACK[normalized];
      if (pack) {
        return {
          capability_pack: pack.id,
          hunter_agent: pack.hunter_agent,
          brief_profile: pack.brief_profile,
        };
      }
    }
    // SC row whose chain_family no longer maps to a registered pack.
    // Caller decides whether to leave nulls or treat as malformed.
    return null;
  }
  // Any non-SC legacy row maps to the web pack.
  return defaultWebRouteMetadata();
}

module.exports = {
  CAPABILITY_PACKS,
  HUNTER_ROLES,
  WEB_SURFACE_TYPES,
  capabilityPackForLegacyFinding,
  chainSpecificHunterBundles,
  classifySurfaceCapability,
  defaultWebRouteMetadata,
  getCapabilityPack,
  hunterAgentNamesForCapabilityPacks,
  hunterRoleSpec,
  hunterRoleSpecs,
  normalizeAssignmentRouteMetadata,
  normalizeSurfaceType,
  smartContractCapabilityPacks,
};
