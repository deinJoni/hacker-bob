"use strict";

const { recordFinding } = require("../findings.js");

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
  handler: recordFinding,
  role_bundles: ["hunter-shared"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["findings.jsonl","findings.md"],
  hook_required: false,
});
