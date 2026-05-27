"use strict";

const { recordFinding, readFindingsFromJsonl } = require("../finding-store.js");
const { appendCandidateClaim } = require("../claims.js");
const { appendFrontierEvent } = require("../frontier-events.js");
const { scheduleMaterialization } = require("../frontier-materialize-debounce.js");
const { hashCanonicalJson } = require("../verification-contracts.js");

// C.2 dual-write shim: after recordFinding succeeds, mirror the Finding into a
// CandidateClaim and emit a claim.candidate.linked frontier event so the claim
// plane sees the same evidence the legacy findings store does. Best-effort:
// the Finding remains authoritative; a claim-plane failure must not regress the
// Finding write.

function deriveSubjectId(finding) {
  if (finding && finding.sc_evidence && typeof finding.sc_evidence.contract_address === "string") {
    return finding.sc_evidence.contract_address;
  }
  if (finding && typeof finding.endpoint === "string" && finding.endpoint.trim()) {
    return finding.endpoint;
  }
  return null;
}

function deriveAttackClass(finding) {
  if (!finding) return null;
  if (typeof finding.attack_class === "string" && finding.attack_class.trim()) {
    return finding.attack_class;
  }
  if (typeof finding.cwe === "string" && finding.cwe.trim()) {
    return finding.cwe;
  }
  return null;
}

function severityForClaim(severity) {
  // Findings use "info" while claims use "informational"; map otherwise pass through.
  if (severity === "info") return "informational";
  return severity;
}

function buildClaimPayloadFromFinding(finding, findingContentHash, args) {
  const payload = {};
  const subjectId = deriveSubjectId(finding);
  if (subjectId) payload.subject_id = subjectId;
  const attackClass = deriveAttackClass(finding);
  if (attackClass) payload.attack_class = attackClass;
  if (typeof finding.auth_profile === "string" && finding.auth_profile.trim()) {
    payload.auth_profile_ref = finding.auth_profile;
  }
  if (typeof finding.surface_id === "string" && finding.surface_id.trim()) {
    payload.surface_ref = finding.surface_id;
  }

  const claim = {
    target_domain: finding.target_domain,
    title: finding.title,
    summary: typeof finding.description === "string" && finding.description.trim()
      ? finding.description
      : finding.title,
    severity: severityForClaim(finding.severity),
    status: "candidate",
    created_at: typeof args.created_at === "string" && args.created_at.trim()
      ? args.created_at
      : new Date().toISOString(),
    evidence_refs: [{
      kind: "finding",
      artifact_path: "findings.jsonl",
      finding_id: finding.id,
      content_hash: findingContentHash,
    }],
  };
  if (typeof finding.surface_id === "string" && finding.surface_id.trim()) {
    claim.surface_ids = [finding.surface_id];
  }
  if (typeof finding.impact === "string" && finding.impact.trim()) {
    claim.impact = finding.impact;
  }
  if (Object.keys(payload).length > 0) {
    claim.payload = payload;
  }
  return claim;
}

function dualWriteClaimForFinding(args, recordResponseJson) {
  let response;
  try {
    response = JSON.parse(recordResponseJson);
  } catch {
    return recordResponseJson;
  }
  if (!response || response.recorded !== true || typeof response.finding_id !== "string") {
    return recordResponseJson;
  }
  const domain = args && typeof args.target_domain === "string" ? args.target_domain : null;
  if (!domain) return recordResponseJson;
  try {
    const findings = readFindingsFromJsonl(domain);
    const finding = findings.find((entry) => entry && entry.id === response.finding_id);
    if (!finding) return recordResponseJson;
    const contentHash = hashCanonicalJson(finding);
    const claimInput = buildClaimPayloadFromFinding(finding, contentHash, args || {});
    const claim = appendCandidateClaim(claimInput);
    appendFrontierEvent({
      target_domain: domain,
      kind: "claim.candidate.linked",
      payload: {
        claim_id: claim.claim_id,
        finding_id: finding.id,
        surface_id: finding.surface_id || null,
      },
      surface_id: finding.surface_id || null,
      claim_id: claim.claim_id,
      source: { artifact: "claims.jsonl", tool: "bounty_record_finding" },
    });
    scheduleMaterialization(domain);
  } catch {
    // Claim plane is dual-write best-effort during the deprecation window; the
    // Finding remains authoritative and the original response must be returned.
  }
  return recordResponseJson;
}

function recordFindingHandler(args) {
  const result = recordFinding(args);
  return dualWriteClaimForFinding(args, result);
}

module.exports = Object.freeze({
  name: "bounty_record_finding",
  description:
    "Record a validated security finding to structured disk artifacts. Survives context rotation.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "title": {
        "type": "string"
      },
      "severity": {
        "type": "string",
        "enum": [
          "critical",
          "high",
          "medium",
          "low",
          "info"
        ]
      },
      "cwe": {
        "type": "string"
      },
      "endpoint": {
        "type": "string"
      },
      "description": {
        "type": "string"
      },
      "proof_of_concept": {
        "type": "string"
      },
      "response_evidence": {
        "type": "string"
      },
      "impact": {
        "type": "string"
      },
      "auth_profile": {
        "type": "string"
      },
      "surface_id": {
        "type": "string"
      },
      "validated": {
        "type": "boolean"
      },
      "wave": {
        "type": "string",
        "pattern": "^w[1-9][0-9]*$"
      },
      "agent": {
        "type": "string",
        "pattern": "^a[1-9][0-9]*$"
      },
      "force_record": {
        "type": "boolean",
        "description": "Intentionally record a duplicate finding instead of returning the existing finding ID."
      },
      "sc_evidence": {
        "type": "object",
        "description": "Structured re-run handle for smart-contract findings. Required when the assigned surface is a smart contract; rejected otherwise so the verifier can re-run via bounty_foundry_run (EVM) or bounty_anchor_run (SVM) with no string-parsing of the prose PoC.",
        "properties": {
          "chain_family": {
            "type": "string",
            "enum": ["evm", "svm", "aptos", "sui", "substrate", "cosmwasm"],
            "description": "Discriminator for cross-family validation. Defaults to 'evm' when omitted for back-compat with legacy findings."
          },
          "chain_id": {
            "oneOf": [
              { "type": "integer", "minimum": 1, "maximum": 9007199254740991 },
              { "type": "string", "minLength": 1, "maxLength": 64 }
            ],
            "description": "EVM: positive integer chain ID (e.g., 1, 137). SVM: cluster string from {mainnet-beta, devnet, testnet}. Aptos: network string from {mainnet, testnet, devnet}. Sui: network string from {mainnet, testnet, devnet, localnet}. Substrate: network string from {polkadot, kusama, astar, shiden, rococo, westend, localnet}. CosmWasm: network string from {osmosis, juno, neutron, archway, sei, stargaze, terra, kava, localnet}."
          },
          "contract_address": {
            "type": "string",
            "minLength": 1,
            "maxLength": 90,
            "description": "EVM: 0x-prefixed 40-hex address. SVM: base58 32-44 char Solana program ID. Aptos: 0x-prefixed hex module address (1-64 hex chars, normalized to 64). Sui: 0x-prefixed hex package ID (1-64 hex chars, normalized to 64). Substrate: SS58-encoded base58 address (45-52 chars). CosmWasm: bech32 with chain HRP (e.g., osmo1..., juno1...). Validated against chain_family."
          },
          "harness_path": {
            "type": "string",
            "description": "Foundry/Anchor project root for the recorded test. Must live under the user's home directory at re-run time."
          },
          "match_test": {
            "type": "string",
            "minLength": 1,
            "maxLength": 200,
            "description": "Test function selector passed to forge --match-test (EVM) or anchor's mocha grep (SVM). Convention: a passing test asserts the bug exists, so PASS=reproduced."
          },
          "match_contract": {
            "type": "string",
            "minLength": 1,
            "maxLength": 200,
            "description": "Optional contract / program selector. EVM uses --match-contract; SVM ignores this and uses the anchor program directory layout."
          },
          "fork_block": {
            "type": "integer",
            "minimum": 0,
            "maximum": 9007199254740991,
            "description": "Pinned chain reference at recording time. EVM: block number. SVM: slot. Aptos: ledger version. Sui: checkpoint sequence number. Substrate: block number. CosmWasm: block height. Verifiers re-run WITHOUT pinning to confirm the bug still reproduces on current state."
          },
          "function_signature": {
            "type": "string",
            "minLength": 1,
            "maxLength": 200,
            "description": "Affected function / instruction signature (e.g., borrow(uint256), Deposit{amount: u64}). Optional; surfaces in the report header."
          }
        },
        "required": ["chain_id", "contract_address", "harness_path", "match_test"]
      }
    },
    "required": [
      "target_domain",
      "title",
      "severity",
      "endpoint",
      "description",
      "proof_of_concept",
      "validated"
    ]
  },
  handler: recordFindingHandler,
  role_bundles: ["evaluator-shared", "orchestrator"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["findings.jsonl","findings.md","claims.jsonl","frontier-events.jsonl"],
});
