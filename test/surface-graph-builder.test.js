"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  buildSurfaceGraph,
  edgesFromAttackSurface,
  edgesFromSchemaCorpus,
} = require("../mcp/lib/surface-graph-builder.js");
const { queryEdges } = require("../mcp/lib/surface-graph.js");
const { ingestSchemaDoc } = require("../mcp/lib/schema-contracts-store.js");

function uniqueDomain(prefix = "bob-graph-builder-test") {
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${prefix}-${suffix}.local`;
}

function domainDir(domain) {
  return path.join(os.homedir(), "hacker-bob-sessions", domain);
}

function cleanupDomain(domain) {
  const dir = domainDir(domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

function writeAttackSurface(domain, surfaces) {
  const dir = domainDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "attack_surface.json"),
    JSON.stringify({ surfaces }, null, 2),
  );
}

const SAMPLE_SURFACE = Object.freeze({
  id: "S-1",
  hosts: ["api.example.com", "auth.example.com"],
  endpoints: ["/users", "/users/{id}", "/admin"],
  tech_stack: ["express", "node"],
  js_hints: ["main.bundle.js"],
  leaked_secrets: ["sk_live_abcd1234"],
});

test("edgesFromAttackSurface emits surface-contains-endpoint, host-hosts-endpoint, surface-references-tech, and leaks edges", () => {
  const edges = edgesFromAttackSurface({ surfaces: [SAMPLE_SURFACE] });
  const types = new Set(edges.map((e) => `${e.source.type}/${e.target.type}/${e.edge_type}`));
  assert.ok(types.has("surface/endpoint/contains"));
  assert.ok(types.has("subdomain/endpoint/hosts"));
  assert.ok(types.has("surface/subdomain/contains"));
  assert.ok(types.has("surface/tech/references"));
  assert.ok(types.has("surface/js_file/references"));
  assert.ok(types.has("surface/secret_marker/leaks"));
  const secretEdge = edges.find((e) => e.target.type === "secret_marker");
  assert.match(secretEdge.target.id, /^secret-[a-f0-9]{16}$/);
  assert.notEqual(secretEdge.target.id, SAMPLE_SURFACE.leaked_secrets[0]);
});

test("edgesFromAttackSurface emits hosts edges for each (host, endpoint) pair", () => {
  const edges = edgesFromAttackSurface({ surfaces: [SAMPLE_SURFACE] });
  const hostEdges = edges.filter((e) =>
    e.source.type === "subdomain" && e.target.type === "endpoint" && e.edge_type === "hosts");
  // 2 hosts × 3 endpoints
  assert.equal(hostEdges.length, 6);
});

test("edgesFromAttackSurface skips malformed entries without throwing", () => {
  const edges = edgesFromAttackSurface({
    surfaces: [
      null,
      "not-a-surface",
      { id: "" },
      { id: "S-1", endpoints: ["/x"] },
    ],
  });
  // Only the last surface should produce edges
  const validEdges = edges.filter((e) => e.source.type === "surface" && e.source.id === "S-1");
  assert.ok(validEdges.length >= 1);
});

test("edgesFromSchemaCorpus emits openapi_spec-documents-endpoint and endpoint-claims_auth-scheme edges", () => {
  const domain = uniqueDomain();
  try {
    const doc = JSON.stringify({
      openapi: "3.0.3",
      paths: {
        "/users": {
          get: {
            security: [{ bearerAuth: [] }],
            responses: { "200": { description: "ok" } },
          },
        },
      },
    });
    ingestSchemaDoc({
      target_domain: domain,
      raw_doc: doc,
      source_uri: "https://example.com/openapi.json",
    });
    const edges = edgesFromSchemaCorpus(domain);
    const docEdge = edges.find((e) =>
      e.source.type === "openapi_spec"
      && e.target.type === "endpoint"
      && e.target.id === "/users"
      && e.edge_type === "documents");
    assert.ok(docEdge);
    assert.equal(docEdge.source.id, "https://example.com/openapi.json");
    const authEdge = edges.find((e) =>
      e.source.type === "endpoint"
      && e.target.type === "auth_scheme"
      && e.edge_type === "claims_auth");
    assert.ok(authEdge);
    assert.equal(authEdge.target.id, "bearerAuth");
  } finally {
    cleanupDomain(domain);
  }
});

test("buildSurfaceGraph reads attack_surface.json and the schema corpus and persists merged edges", () => {
  const domain = uniqueDomain();
  try {
    writeAttackSurface(domain, [SAMPLE_SURFACE]);
    ingestSchemaDoc({
      target_domain: domain,
      raw_doc: JSON.stringify({
        openapi: "3.0.3",
        paths: {
          "/users": {
            get: {
              security: [{ bearerAuth: [] }],
              responses: { "200": { description: "ok" } },
            },
          },
        },
      }),
      source_uri: "https://example.com/openapi.json",
    });
    const result = buildSurfaceGraph({ target_domain: domain });
    assert.ok(result.new_count > 0);
    assert.ok(result.total_in_graph > 0);
    assert.equal(result.sources_used.length, 2);
    assert.equal(result.sources_used.find((s) => s.source === "attack_surface").edge_count > 0, true);
    assert.equal(result.sources_used.find((s) => s.source === "schema_corpus").edge_count > 0, true);

    // re-running is idempotent: replaced_count > 0, no growth
    const second = buildSurfaceGraph({ target_domain: domain });
    assert.equal(second.new_count, 0);
    assert.equal(second.replaced_count, result.total_in_graph);
    assert.equal(second.total_in_graph, result.total_in_graph);
  } finally {
    cleanupDomain(domain);
  }
});

test("buildSurfaceGraph honors the sources filter", () => {
  const domain = uniqueDomain();
  try {
    writeAttackSurface(domain, [SAMPLE_SURFACE]);
    const result = buildSurfaceGraph({
      target_domain: domain,
      sources: ["attack_surface"],
    });
    assert.equal(result.sources_used.length, 1);
    assert.equal(result.sources_used[0].source, "attack_surface");
  } finally {
    cleanupDomain(domain);
  }
});

test("buildSurfaceGraph reports missing attack_surface.json without throwing", () => {
  const domain = uniqueDomain();
  try {
    const result = buildSurfaceGraph({ target_domain: domain });
    const attackEntry = result.sources_used.find((s) => s.source === "attack_surface");
    assert.equal(attackEntry.missing, true);
    assert.equal(attackEntry.edge_count, 0);
  } finally {
    cleanupDomain(domain);
  }
});

test("queried edges from buildSurfaceGraph are queryable via queryEdges", () => {
  const domain = uniqueDomain();
  try {
    writeAttackSurface(domain, [SAMPLE_SURFACE]);
    buildSurfaceGraph({ target_domain: domain });
    const containsEdges = queryEdges({ target_domain: domain, edge_type: "contains" });
    assert.ok(containsEdges.total_matched > 0);
    const usersEndpoint = queryEdges({ target_domain: domain, target_id: "/users" });
    assert.ok(usersEndpoint.total_matched > 0);
  } finally {
    cleanupDomain(domain);
  }
});
