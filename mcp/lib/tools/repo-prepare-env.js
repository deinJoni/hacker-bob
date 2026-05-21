"use strict";

const { prepareRepoEnv } = require("../repo-env.js");

module.exports = Object.freeze({
  name: "bounty_repo_prepare_env",
  description:
    "Prepare a session-owned Docker environment plan for an OSS repo session. Writes Dockerfile.bob and repo-env.json, and optionally builds the Docker image when explicitly requested.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "build_image": {
        "type": "boolean",
        "description": "When true, run docker build for the generated session-owned image."
      },
      "dry_run": {
        "type": "boolean",
        "description": "When true, write the plan and Dockerfile but do not execute docker build."
      },
      "allow_network": {
        "type": "boolean",
        "description": "When true, allow network during docker build. Defaults to false."
      },
      "base_image": {
        "type": "string",
        "description": "Optional Docker base image. Defaults to ubuntu:24.04."
      },
      "image_tag": {
        "type": "string",
        "description": "Optional Docker image tag. Defaults to bob-oss-<target>:<repo-hash>."
      },
      "timeout_ms": {
        "type": "integer",
        "description": "Optional build timeout, 1000..600000 ms."
      }
    },
    "required": [
      "target_domain"
    ]
  },
  handler: prepareRepoEnv,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: true,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["Dockerfile.bob", "repo-env.json"],
  hook_required: false,
  prepareRepoEnv,
});
