"use strict";

const { repoDockerRun } = require("../repo-env.js");
const { REPLAY_CONTEXT_SCHEMA } = require("./replay-context-schema.js");

module.exports = Object.freeze({
  name: "bounty_repo_docker_run",
  description:
    "Run a bounded Docker command for an OSS repo session. Mounts the repo at /src read-only by default, mounts a session-owned writable /work directory, and appends repo-command-runs.jsonl.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "command": {
        "type": "array",
        "description": "Command argv to run inside the container, for example [\"sh\", \"-lc\", \"cmake -S /src -B /work/build && cmake --build /work/build\"].",
        "items": {
          "type": "string"
        },
        "minItems": 1
      },
      "dry_run": {
        "type": "boolean",
        "description": "When true, record and return the docker command without executing it."
      },
      "allow_network": {
        "type": "boolean",
        "description": "When true, run with Docker bridge networking. Defaults to --network none."
      },
      "repo_mount_mode": {
        "type": "string",
        "enum": [
          "read_only",
          "read_write"
        ],
        "description": "How to mount the target repo at /src. Defaults to read_only."
      },
      "image_tag": {
        "type": "string",
        "description": "Optional Docker image tag. Defaults to repo-env.json image_tag."
      },
      "timeout_ms": {
        "type": "integer",
        "description": "Optional run timeout, 1000..600000 ms."
      },
      "replay_context": REPLAY_CONTEXT_SCHEMA
    },
    "required": [
      "target_domain",
      "command"
    ]
  },
  handler: repoDockerRun,
  role_bundles: ["orchestrator", "hunter-web", "verifier", "evidence"],
  mutating: true,
  global_preapproval: false,
  network_access: true,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["repo-command-runs.jsonl"],
  repoDockerRun,
});
