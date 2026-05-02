"use strict";

const WEB_CAPABILITY_PACK = Object.freeze({
  id: "web",
  hunter_agent: "hunter-agent",
  brief_profile: "web",
  role_bundles: Object.freeze(["hunter-shared", "hunter-web"]),
  completion_gate: "web_wave_handoff",
});

const SMART_CONTRACT_EVM_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_evm",
  hunter_agent: "hunter-evm-agent",
  brief_profile: "smart_contract_evm",
  role_bundles: Object.freeze(["hunter-shared", "hunter-evm"]),
  completion_gate: "smart_contract_wave_handoff",
});

const SMART_CONTRACT_SVM_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_svm",
  hunter_agent: "hunter-svm-agent",
  brief_profile: "smart_contract_svm",
  role_bundles: Object.freeze(["hunter-shared", "hunter-svm"]),
  completion_gate: "smart_contract_wave_handoff",
});

const SMART_CONTRACT_MOVE_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_move",
  hunter_agent: "hunter-move-agent",
  brief_profile: "smart_contract_move",
  role_bundles: Object.freeze(["hunter-shared", "hunter-move"]),
  completion_gate: "smart_contract_wave_handoff",
});

const SMART_CONTRACT_SUBSTRATE_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_substrate",
  hunter_agent: "hunter-substrate-agent",
  brief_profile: "smart_contract_substrate",
  role_bundles: Object.freeze(["hunter-shared", "hunter-substrate"]),
  completion_gate: "smart_contract_wave_handoff",
});

const SMART_CONTRACT_COSMWASM_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_cosmwasm",
  hunter_agent: "hunter-cosmwasm-agent",
  brief_profile: "smart_contract_cosmwasm",
  role_bundles: Object.freeze(["hunter-shared", "hunter-cosmwasm"]),
  completion_gate: "smart_contract_wave_handoff",
});

const CAPABILITY_PACKS = Object.freeze({
  web: WEB_CAPABILITY_PACK,
  smart_contract_evm: SMART_CONTRACT_EVM_CAPABILITY_PACK,
  smart_contract_svm: SMART_CONTRACT_SVM_CAPABILITY_PACK,
  smart_contract_move: SMART_CONTRACT_MOVE_CAPABILITY_PACK,
  smart_contract_substrate: SMART_CONTRACT_SUBSTRATE_CAPABILITY_PACK,
  smart_contract_cosmwasm: SMART_CONTRACT_COSMWASM_CAPABILITY_PACK,
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

// Smart-contract surfaces are routed by `chain_family`. Aptos and Sui share
// the Move pack because hunter-move-agent dispatches between
// bounty_aptos_* and bounty_sui_* tools internally.
const SMART_CONTRACT_CHAIN_FAMILY_TO_PACK = Object.freeze({
  evm: SMART_CONTRACT_EVM_CAPABILITY_PACK,
  svm: SMART_CONTRACT_SVM_CAPABILITY_PACK,
  aptos: SMART_CONTRACT_MOVE_CAPABILITY_PACK,
  sui: SMART_CONTRACT_MOVE_CAPABILITY_PACK,
  move: SMART_CONTRACT_MOVE_CAPABILITY_PACK,
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
    // sends Phase D consumers into the wrong pipeline.
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

// Read-side backfill for legacy findings.jsonl rows written before Phase C.
// Pre-Phase-C rows carry surface_type and (for SC findings) sc_evidence.chain_family
// but no capability_pack/hunter_agent/brief_profile. Reconstructing the pack triple
// at read time keeps Phase D consumers from each having to implement the same
// fallback. Returns null when the record carries no usable signal.
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
  WEB_SURFACE_TYPES,
  capabilityPackForLegacyFinding,
  classifySurfaceCapability,
  defaultWebRouteMetadata,
  getCapabilityPack,
  hunterAgentNamesForCapabilityPacks,
  normalizeAssignmentRouteMetadata,
  normalizeSurfaceType,
};
