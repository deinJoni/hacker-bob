"use strict";

const { extractRoutesFromFiles } = require("../route-extractor.js");

function extractRoutesHandler(args) {
  const routes = extractRoutesFromFiles(args.files);
  return {
    schema_version: 1,
    target_domain: args.target_domain,
    file_count: Array.isArray(args.files) ? args.files.length : 0,
    route_count: routes.length,
    routes,
  };
}

module.exports = Object.freeze({
  name: "bounty_extract_routes",
  description:
    "Run regex-based HTTP route extraction across one or more source files. Supports Express, Koa, Fastify, NestJS (JS/TS), Flask, Django (Python), and Spring (Java/Kotlin). Each emitted route carries (framework, method, path, file, line, handler_hint, edge_kind). Output sorted deterministically; tuple-deduped. Pass to bounty_build_symbol_surface_index to derive the file:line -> surface index.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      files: {
        type: "array",
        description: "Array of {file, source, language?} entries. language auto-detects from file extension when omitted.",
        items: {
          type: "object",
          properties: {
            file: { type: "string" },
            source: { type: "string" },
            language: { type: "string" },
          },
          required: ["source"],
        },
      },
    },
    required: ["target_domain", "files"],
  },
  handler: extractRoutesHandler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
