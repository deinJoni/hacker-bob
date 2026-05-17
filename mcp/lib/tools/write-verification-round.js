"use strict";

const { writeVerificationRound } = require("../verification-round-store.js");

module.exports = Object.freeze({
  name: "bounty_write_verification_round",
  description:
    "Write one verifier round to authoritative JSON plus a markdown mirror.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "round": {
        "type": "string",
        "enum": [
          "brutalist",
          "balanced",
          "final"
        ]
      },
      "notes": {
        "type": [
          "string",
          "null"
        ]
      },
      "verification_attempt_id": {
        "type": "string"
      },
      "verification_snapshot_hash": {
        "type": "string"
      },
      "round_profile": {
        "type": "string"
      },
      "adjudication_plan_hash": {
        "type": "string"
      },
      "results": {
        "type": "array",
        "items": {
          "type": "object",
          "properties": {
            "finding_id": {
              "type": "string"
            },
            "disposition": {
              "type": "string",
              "enum": [
                "confirmed",
                "denied",
                "downgraded"
              ]
            },
            "severity": {
              "enum": [
                "critical",
                "high",
                "medium",
                "low",
                "info",
                null
              ]
            },
            "reportable": {
              "type": "boolean"
            },
            "reasoning": {
              "type": "string"
            },
            "confidence": {
              "type": "string",
              "enum": [
                "high",
                "medium",
                "low"
              ]
            },
            "confidence_reasons": {
              "type": "array",
              "items": {
                "type": "string",
                "enum": [
                  "fresh_replay_passed",
                  "auth_expired",
                  "tooling_blocked",
                  "state_changed",
                  "manual_inference",
                  "roast_disagreement",
                  "disambiguation_failed",
                  "agreement_not_replayed"
                ]
              }
            },
            "state_sensitive": {
              "type": "boolean"
            },
            "artifact_hashes": {
              "type": "object",
              "maxProperties": 20,
              "additionalProperties": {
                "type": "string",
                "pattern": "^[a-f0-9]{64}$"
              }
            },
            "inherited_confidence_reasons": {
              "type": "array",
              "items": {
                "type": "string",
                "enum": [
                  "fresh_replay_passed",
                  "auth_expired",
                  "tooling_blocked",
                  "state_changed",
                  "manual_inference",
                  "roast_disagreement",
                  "disambiguation_failed",
                  "agreement_not_replayed"
                ]
              }
            },
            "resolved_confidence_reasons": {
              "type": "array",
              "items": {
                "type": "string",
                "enum": [
                  "fresh_replay_passed",
                  "auth_expired",
                  "tooling_blocked",
                  "state_changed",
                  "manual_inference",
                  "roast_disagreement",
                  "disambiguation_failed",
                  "agreement_not_replayed"
                ]
              }
            }
          },
          "required": [
            "finding_id",
            "disposition",
            "severity",
            "reportable",
            "reasoning"
          ]
        }
      }
    },
    "required": [
      "target_domain",
      "round",
      "notes",
      "results"
    ]
  },
  handler: writeVerificationRound,
  role_bundles: ["verifier"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["brutalist.json","balanced.json","verified-final.json","verification-manifest.json"],
});
