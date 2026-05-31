"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  attackSurfacePath,
  sessionDir,
  statePath,
} = require("../mcp/lib/paths.js");
const {
  readHunterBrief,
  HUNTER_BRIEF_SLICE_REGISTRY,
  slimSurfaceForBrief,
} = require("../mcp/lib/hunter-brief.js");
const {
  startWave,
} = require("../mcp/lib/waves.js");
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");
const {
  ingestSchemaDoc,
} = require("../mcp/lib/schema-contracts-store.js");
const {
  indexFinding,
} = require("../mcp/lib/findings-index.js");
const {
  appendEdges,
} = require("../mcp/lib/surface-graph.js");

const BRIEF_SIZE_BUDGET_CHARS = 30_000;

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-brief-size-"));
  process.env.HOME = tempHome;

  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

function uniqueDomain(prefix) {
  return `${prefix}-${crypto.randomBytes(4).toString("hex")}.example`;
}

function seedSessionState(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeFileAtomic(statePath(domain), `${JSON.stringify({
    target: domain,
    target_url: `https://${domain}`,
    deep_mode: false,
    phase: "HUNT",
    hunt_wave: 0,
    pending_wave: null,
    total_findings: 0,
    explored: [],
    terminally_blocked: [],
    prereq_registry_snapshots: [],
    blocked_prereq_history: [],
    terminal_block_clear_history: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    scope_exclusions: [],
    hold_count: 0,
    auth_status: "pending",
    operator_note: null,
    verification_schema_version: null,
    verification_attempt_id: null,
    verification_snapshot_hash: null,
    verification_entered_at: null,
  }, null, 2)}\n`);
}

function seedAttackSurface(domain, surfaces) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

function startSingleSurfaceWave(domain, surfaceId) {
  return JSON.parse(startWave({
    target_domain: domain,
    wave_number: 1,
    assignments: [{ agent: "a1", surface_id: surfaceId }],
  }));
}

function assertBriefWithinBudget(label, args) {
  const brief = JSON.parse(readHunterBrief(args));
  const size = JSON.stringify(brief).length;
  assert.ok(
    size <= BRIEF_SIZE_BUDGET_CHARS,
    `${label} hunter brief is ${size} chars, exceeds ${BRIEF_SIZE_BUDGET_CHARS}`,
  );
  return brief;
}

test("hunter brief slice registry is explicit and budgeted per profile", () => {
  assert.deepEqual(HUNTER_BRIEF_SLICE_REGISTRY.web.map((slice) => slice.key), [
    "bypass_table",
    "techniques",
    "payload_hints",
    "knowledge_summary",
    "technique_packs",
    "traffic_summary",
    "audit_summary",
    "circuit_breaker_summary",
    "intel_hints",
    "static_scan_hints",
    "schema_slice",
    "priors_slice",
    "surface_graph_slice",
    "auth_profiles_hint",
  ]);
  assert.deepEqual(HUNTER_BRIEF_SLICE_REGISTRY.smart_contract.map((slice) => slice.key), [
    "bob_spec_status",
    "rpc_pool",
    "priors_slice",
    "surface_graph_slice",
  ]);
  for (const [profile, slices] of Object.entries(HUNTER_BRIEF_SLICE_REGISTRY)) {
    assert.ok(Array.isArray(slices), `${profile} slice registry must be an array`);
    for (const slice of slices) {
      assert.equal(typeof slice.key, "string");
      assert.equal(typeof slice.budget_chars, "number");
      assert.ok(slice.budget_chars > 0, `${profile}.${slice.key} must declare a positive budget`);
      assert.equal(typeof slice.read, "function");
    }
  }
});

function webOpenApiFixture() {
  return JSON.stringify({
    openapi: "3.0.3",
    security: [{ bearerAuth: [] }],
    paths: {
      "/api/users": {
        get: {
          responses: {
            "200": {
              description: "ok",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["id", "email"],
                    properties: {
                      id: { type: "string" },
                      email: { type: "string" },
                      role: { type: "string" },
                    },
                  },
                },
              },
            },
          },
        },
      },
      "/api/users/{id}": {
        get: {
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          responses: { "200": { description: "ok" }, "404": { description: "missing" } },
        },
      },
      "/api/admin/audit": {
        get: {
          security: [{ apiKey: [] }],
          responses: { "200": { description: "ok" }, "403": { description: "forbidden" } },
        },
      },
      "/api/billing/export": {
        post: {
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["account_id"],
                  properties: { account_id: { type: "string" } },
                },
              },
            },
          },
          responses: { "202": { description: "accepted" } },
        },
      },
      "/api/oauth/callback": {
        get: {
          security: [{}],
          responses: { "302": { description: "redirect" } },
        },
      },
    },
  });
}

function seedWebSlices(domain, surfaceId) {
  ingestSchemaDoc({
    target_domain: domain,
    raw_doc: webOpenApiFixture(),
    source_uri: `https://${domain}/openapi.json`,
  });
  indexFinding({
    target_domain: domain,
    finding: {
      finding_id: "F-1",
      title: "IDOR on user profile endpoint",
      description: "Broken object level authorization on Express user APIs.",
      severity: "high",
      attack_class: "idor",
      endpoint: "/api/users/{id}",
      tech_stack: ["express", "postgres"],
    },
    calibration_label: "real",
  });
  appendEdges({
    target_domain: domain,
    edges: [
      { source: { type: "surface", id: surfaceId }, target: { type: "endpoint", id: "/api/users" }, edge_type: "contains" },
      { source: { type: "surface", id: surfaceId }, target: { type: "endpoint", id: "/api/admin/audit" }, edge_type: "contains" },
      { source: { type: "surface", id: surfaceId }, target: { type: "subdomain", id: `api.${domain}` }, edge_type: "contains" },
      { source: { type: "surface", id: surfaceId }, target: { type: "tech", id: "express" }, edge_type: "references" },
      { source: { type: "surface", id: surfaceId }, target: { type: "js_file", id: "main.bundle.js" }, edge_type: "references" },
      { source: { type: "endpoint", id: "/api/users" }, target: { type: "auth_scheme", id: "bearerAuth" }, edge_type: "claims_auth" },
    ],
  });
}

function seedSmartContractSlices(domain, surfaceId) {
  indexFinding({
    target_domain: domain,
    finding: {
      finding_id: "F-evm-1",
      title: "Reentrancy in vault withdraw",
      description: "External call before accounting update in a Solidity vault.",
      severity: "high",
      attack_class: "reentrancy",
      surface_type: "smart_contract",
      tech_stack: ["solidity", "foundry"],
    },
    calibration_label: "real",
  });
  appendEdges({
    target_domain: domain,
    edges: [
      { source: { type: "surface", id: surfaceId }, target: { type: "endpoint", id: "withdraw(uint256)" }, edge_type: "contains" },
      { source: { type: "surface", id: surfaceId }, target: { type: "endpoint", id: "setOperator(address)" }, edge_type: "contains" },
      { source: { type: "surface", id: surfaceId }, target: { type: "tech", id: "solidity" }, edge_type: "references" },
      { source: { type: "surface", id: surfaceId }, target: { type: "tech", id: "foundry" }, edge_type: "references" },
      { source: { type: "surface", id: surfaceId }, target: { type: "secret_marker", id: "admin-role" }, edge_type: "leaks" },
    ],
  });
}

test("web hunter brief stays within 30k with representative slice fixtures", () => {
  withTempHome(() => {
    const domain = uniqueDomain("brief-web");
    const surfaceId = "web-api";
    seedSessionState(domain);
    seedAttackSurface(domain, [{
      id: surfaceId,
      surface_type: "api",
      hosts: [`https://api.${domain}`, `https://app.${domain}`],
      title: "User and billing API",
      description: "Express API handling user profiles, billing exports, OAuth callback handling, and admin audit reads.",
      endpoint_pattern: "/api",
      tech_stack: ["Express", "GraphQL", "Next.js", "OAuth", "PostgreSQL", "Redis"],
      endpoints: ["/api/users", "/api/users/{id}", "/api/admin/audit", "/api/billing/export", "/api/oauth/callback"],
      interesting_params: ["id", "account_id", "redirect_uri", "role", "cursor", "export_format"],
      nuclei_hits: ["exposed-graphql-introspection", "missing-security-headers"],
      bug_class_hints: ["idor", "authz", "oauth", "ssrf", "business_logic"],
      high_value_flows: ["profile read", "billing export", "admin audit search", "oauth callback"],
      evidence: ["OpenAPI advertises bearer auth", "traffic shows account_id access pattern", "frontend bundle references admin audit route"],
    }]);
    seedWebSlices(domain, surfaceId);
    startSingleSurfaceWave(domain, surfaceId);

    const brief = assertBriefWithinBudget("web", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      egress_profile: "default",
      block_internal_hosts: false,
    });
    assert.ok(brief.schema_slice && brief.schema_slice.contracts.length > 0);
    assert.ok(brief.priors_slice && brief.priors_slice.priors.length > 0);
    assert.ok(brief.surface_graph_slice && brief.surface_graph_slice.related_endpoints.length > 0);
  });
});

test("smart-contract hunter brief stays within 30k with representative slice fixtures", () => {
  withTempHome(() => {
    const domain = uniqueDomain("brief-sc");
    const surfaceId = "evm-vault";
    seedSessionState(domain);
    seedAttackSurface(domain, [{
      id: surfaceId,
      surface_type: "smart_contract",
      chain_family: "evm",
      chain_id: "1",
      hosts: ["https://etherscan.io/address/0x1111111111111111111111111111111111111111"],
      title: "EVM vault contract",
      description: "Upgradeable Solidity vault with withdrawal, operator, and accounting flows.",
      contract_address: "0x1111111111111111111111111111111111111111",
      foundry_harness_path: "/tmp/bob-fixtures/foundry-vault",
      tech_stack: ["Solidity", "OpenZeppelin", "Foundry"],
      bug_classes: ["reentrancy", "access_control", "accounting"],
      bug_class_hints: ["reentrancy", "role bypass", "oracle staleness"],
      high_value_flows: ["withdraw", "setOperator", "sweepFees"],
      evidence: ["Audit notes mention withdraw accounting", "Contract exposes operator-controlled sweep"],
    }]);
    seedSmartContractSlices(domain, surfaceId);
    startSingleSurfaceWave(domain, surfaceId);

    const brief = assertBriefWithinBudget("smart-contract", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
    });
    assert.equal(brief.run_context.capability_pack, "smart_contract_evm");
    assert.ok(brief.bob_spec_status);
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "rpc_pool"));
    assert.ok(brief.priors_slice && brief.priors_slice.priors.length > 0);
    assert.ok(brief.surface_graph_slice && brief.surface_graph_slice.related_endpoints.length > 0);
  });
});

test("slimSurfaceForBrief carries the network_reachable triage field through the whitelist", () => {
  // The hunter/orchestrator prompts name severity_ceiling, attack_vector, AND
  // network_reachable as fields the surface carries. slimSurfaceForBrief copies
  // only whitelisted scalars, so all three must survive (booleans coerce to the
  // string "true"/"false") — otherwise the documented field reads undefined.
  const networked = slimSurfaceForBrief({
    id: "OSS-NATIVE-CODE",
    surface_type: "oss_native_code",
    attack_vector: "network",
    severity_ceiling: "critical",
    network_reachable: true,
  }).surface;
  assert.equal(networked.attack_vector, "network");
  assert.equal(networked.severity_ceiling, "critical");
  assert.equal(networked.network_reachable, "true");

  // A false value must still be carried, not dropped — the hunter needs to read
  // the AV:L signal too, not just infer it from a missing field.
  const local = slimSurfaceForBrief({ id: "OSS-NATIVE-CODE", network_reachable: false }).surface;
  assert.equal(local.network_reachable, "false");
});

test("slimSurfaceForBrief forwards unknown surface fields by default and drops denylisted ones", () => {
  // Copy-by-default: a brand-new surface field (in no *_LIMITS map) must reach the
  // hunter automatically — the inversion of the closed whitelist that silently
  // dropped network_reachable. Secrets/raw bodies and nested objects stay out.
  const slim = slimSurfaceForBrief({
    id: "OSS-NATIVE-CODE",
    reachability_confidence: "high",                          // new unknown scalar
    network_entrypoints: ["daemon/server.c", "rpc/stub.c"],   // new unknown array
    cookies: "session=secret",                                // denylisted
    auth: { token: "t" },                                     // denylisted
    nested_obj: { a: 1 },                                     // non-ranking object → skipped
  }).surface;
  assert.equal(slim.reachability_confidence, "high");
  assert.deepEqual(slim.network_entrypoints, ["daemon/server.c", "rpc/stub.c"]);
  assert.equal(slim.cookies, undefined);
  assert.equal(slim.auth, undefined);
  assert.equal(slim.nested_obj, undefined);

  // The generic default cap still bounds an unknown scalar (no unbounded passthrough).
  const big = slimSurfaceForBrief({ id: "X", scratch: "y".repeat(5000) }).surface;
  assert.equal(big.scratch.length, 200);
});
