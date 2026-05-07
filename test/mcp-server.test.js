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
  TECHNIQUE_FULL_ITEM_MAX_CHARS,
  TECHNIQUE_FULL_ITEMS_PER_KIND,
  TECHNIQUE_SELECTION_MAX_CHARS,
  TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
  TECHNIQUE_SUMMARY_ITEMS_PER_KIND,
} = require("../mcp/lib/technique-packs.js");
const egressProfiles = require("../mcp/lib/egress-profiles.js");
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

const ROOT = path.join(__dirname, "..");

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
  chainAttemptsJsonlPath,
  coverageJsonlPath,
  evidencePackPaths,
  executeTool,
  finalizeHunterRun,
  findingsJsonlPath,
  findingsMarkdownPath,
  getContextBudget,
  gradeArtifactPaths,
  initSession,
  importHttpTraffic,
  logCoverage,
  migrateAuthJson,
  normalizeEvidencePacksDocument,
  bountyPublicIntel,
  readChainAttempts,
  readChainAttemptsFromJsonl,
  readEvidencePacks,
  readScopeExclusions,
  readSessionSummary,
  readSessionState,
  readStateSummary,
  routeSurfaces,
  setOperatorNote,
  clearOperatorNote,
  clearTerminalBlock,
  reportWritten,
  readCoverageRecordsFromJsonl,
  readHttpAudit,
  readHttpAuditRecordsFromJsonl,
  readPipelineAnalytics,
  readPipelineEvents,
  readSessionArtifactSummary,
  readSurfaceLeads,
  readTrafficRecordsFromJsonl,
  compactSessionState,
  listFindings,
  listAuthProfiles,
  loadTechniqueRegistry,
  mergeWaveHandoffs,
  logTechniqueAttempt,
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
  recordSurfaceLeads,
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
  surfaceLeadsPath,
  surfaceRoutesPath,
  tempEmail,
  transitionPhase,
  trafficJsonlPath,
  verificationRoundPaths,
  waveHandoffStatus,
  waveStatus,
  writeChainAttempt,
  writeEvidencePacks,
  writeFileAtomic,
  writeGradeVerdict,
  writeHandoff,
  writeVerificationRound,
  writeWaveHandoff,
  filterExclusionsByHosts,
  readHunterBrief,
  readStaticArtifactRecordsFromJsonl,
  readStaticScanResultsFromJsonl,
  readTechniqueAttemptRecordsFromJsonl,
  readTechniquePack,
  readTechniquePackReadRecordsFromJsonl,
  promoteSurfaceLeads,
  selectTechniquePacks,
  techniqueAttemptsJsonlPath,
  techniquePackReadsJsonlPath,
} = serverModule;

const EXPECTED_TOOL_NAMES = [
  "bounty_http_scan",
  "bounty_read_http_audit",
  "bounty_start_wave",
  "bounty_route_surfaces",
  "bounty_read_surface_routes",
  "bounty_import_http_traffic",
  "bounty_public_intel",
  "bounty_import_static_artifact",
  "bounty_static_scan",
  "bounty_record_finding",
  "bounty_read_findings",
  "bounty_list_findings",
  "bounty_write_chain_attempt",
  "bounty_read_chain_attempts",
  "bounty_write_verification_round",
  "bounty_read_verification_round",
  "bounty_write_evidence_packs",
  "bounty_read_evidence_packs",
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
  "bounty_read_session_summary",
  "bounty_set_operator_note",
  "bounty_clear_operator_note",
  "bounty_clear_terminal_block",
  "bounty_report_written",
  "bounty_read_hunter_brief",
  "bounty_get_context_budget",
  "bounty_select_technique_packs",
  "bounty_read_technique_pack",
  "bounty_log_technique_attempt",
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
  "bounty_record_surface_leads",
  "bounty_read_surface_leads",
  "bounty_promote_surface_leads",
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

function withTempTechniqueKnowledge(document, fn) {
  return withTempTechniqueKnowledgeText(`${JSON.stringify(document, null, 2)}\n`, fn);
}

function withTempTechniqueKnowledgeText(contents, fn) {
  const previousProjectDir = process.env.CLAUDE_PROJECT_DIR;
  const previousBobResourceDir = process.env.BOB_RESOURCE_DIR;
  const previousBobProjectDir = process.env.BOB_PROJECT_DIR;
  const tempProjectDir = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-techniques-"));
  const knowledgeDir = path.join(tempProjectDir, ".claude", "knowledge");
  fs.mkdirSync(knowledgeDir, { recursive: true });
  fs.writeFileSync(
    path.join(knowledgeDir, "hunter-techniques.json"),
    contents,
    "utf8",
  );
  process.env.CLAUDE_PROJECT_DIR = tempProjectDir;
  delete process.env.BOB_RESOURCE_DIR;
  delete process.env.BOB_PROJECT_DIR;

  const cleanup = () => {
    if (previousProjectDir === undefined) {
      delete process.env.CLAUDE_PROJECT_DIR;
    } else {
      process.env.CLAUDE_PROJECT_DIR = previousProjectDir;
    }
    if (previousBobResourceDir === undefined) {
      delete process.env.BOB_RESOURCE_DIR;
    } else {
      process.env.BOB_RESOURCE_DIR = previousBobResourceDir;
    }
    if (previousBobProjectDir === undefined) {
      delete process.env.BOB_PROJECT_DIR;
    } else {
      process.env.BOB_PROJECT_DIR = previousBobProjectDir;
    }
    fs.rmSync(tempProjectDir, { recursive: true, force: true });
  };

  try {
    const result = fn(tempProjectDir);
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

function oversizedTechniqueKnowledge({
  packCount = 8,
  itemCount = 20,
  itemChars = 1500,
} = {}) {
  return {
    version: 99,
    entries: Array.from({ length: packCount }, (_, packIndex) => ({
      id: `oversized-${packIndex}`,
      version: 99,
      title: `Oversized ${packIndex}`,
      capability_packs: ["web"],
      match: {
        tech: ["OversizedStack"],
        endpoints: ["/oversized"],
        params: ["oversized_id"],
        hints: ["oversized-hint"],
      },
      techniques: Array.from(
        { length: itemCount },
        (_, itemIndex) => `technique ${packIndex}-${itemIndex} ${"T".repeat(itemChars)}`,
      ),
      payload_hints: Array.from(
        { length: itemCount },
        (_, itemIndex) => `payload ${packIndex}-${itemIndex} ${"P".repeat(itemChars)}`,
      ),
    })),
  };
}

function withRepoEgressConfig(document, fn) {
  const filePath = egressProfiles.egressProfilesPath(ROOT);
  const existed = fs.existsSync(filePath);
  const previous = existed ? fs.readFileSync(filePath, "utf8") : null;
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(document, null, 2)}\n`, "utf8");

  const cleanup = () => {
    if (existed) {
      fs.writeFileSync(filePath, previous, "utf8");
    } else {
      fs.rmSync(filePath, { force: true });
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
    deep_mode: false,
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
    operator_note: null,
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
  const surfaceById = new Map();
  try {
    const surfaceDoc = JSON.parse(fs.readFileSync(surfacePath, "utf8"));
    for (const surface of surfaceDoc.surfaces || []) {
      if (!surface || typeof surface !== "object") continue;
      surfaceById.set(surface.id, surface);
    }
  } catch {}
  // Also mirror startWave's call to routeSurfacesInternal: classify each
  // surface to derive capability_pack/hunter_agent/brief_profile so the
  // assignment file is shaped exactly as production writes it. Without
  // this, normalizeAssignmentRouteMetadata throws on any SC assignment.
  // Test cases that explicitly want to forge alternate route metadata
  // pass it directly on the assignment and we preserve it.
  const { classifySurfaceCapability } = require("../mcp/lib/capability-packs.js");
  const persistedAssignments = assignments.map((assignment) => {
    const surface = surfaceById.get(assignment.surface_id);
    const surfaceTypeRaw = surface && typeof surface.surface_type === "string"
      ? surface.surface_type.trim()
      : "";
    const surfaceType = surfaceTypeRaw !== "" ? surfaceTypeRaw : null;
    const persisted = { ...assignment };
    if (surfaceType && persisted.surface_type == null) {
      persisted.surface_type = surfaceType;
    }
    if (surface
      && persisted.capability_pack == null
      && persisted.hunter_agent == null
      && persisted.brief_profile == null
    ) {
      const route = classifySurfaceCapability(surface);
      persisted.capability_pack = route.capability_pack;
      persisted.hunter_agent = route.hunter_agent;
      persisted.brief_profile = route.brief_profile;
    }
    return persisted;
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

function expectedWebContextBudget() {
  return {
    candidate_pack_limit: 5,
    full_pack_read_limit: 2,
    attempt_log_required: true,
  };
}

function expectedSmartContractContextBudget() {
  return {
    candidate_pack_limit: 5,
    full_pack_read_limit: 2,
    attempt_log_required: false,
  };
}

function seedTechniqueAttempt(domain, {
  wave = "w1",
  agent = "a1",
  surface_id = "surface-a",
  pack_id = "generic-rest-api",
  status = "attempted",
  evidence = "Technique attempt recorded before finalization.",
} = {}) {
  return JSON.parse(logTechniqueAttempt({
    target_domain: domain,
    wave,
    agent,
    surface_id,
    pack_id,
    status,
    evidence,
  }));
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

function evidencePack(findingId = "F-1", overrides = {}) {
  return {
    finding_id: findingId,
    sample_type: "cross-account replay",
    sample_count: 1,
    aggregate_counts: { affected_objects_sampled: 1 },
    representative_samples: [{
      request_ref: "http-audit:1",
      endpoint: "/api/export",
      auth_profile: "attacker",
      status: 200,
      observed_fields: ["account_id", "email"],
      redacted_object_id: "acct_...002",
    }],
    sensitive_clusters: ["profile metadata"],
    replay_summary: "Fresh replay returned another account's private metadata.",
    redaction_notes: "Object IDs and personal values redacted; auth material omitted.",
    report_snippet: "An attacker can retrieve another account's private metadata by changing the account ID.",
    ...overrides,
  };
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
    "chainAttemptsJsonlPath",
    "clearOperatorNote",
    "clearTerminalBlock",
    "compactSessionState",
    "computeCoverageRequeueSurfaceIds",
    "coverageJsonlPath",
    "evidencePackPaths",
    "executeTool",
    "filterExclusionsByHosts",
    "finalizeHunterRun",
    "findingsJsonlPath",
    "findingsMarkdownPath",
    "getContextBudget",
    "gradeArtifactPaths",
    "httpAuditJsonlPath",
    "importHttpTraffic",
    "importStaticArtifact",
    "initSession",
    "listAuthProfiles",
    "listFindings",
    "loadTechniqueRegistry",
    "logCoverage",
    "logTechniqueAttempt",
    "mergeWaveHandoffs",
    "migrateAuthJson",
    "normalizeCoverageRecord",
    "normalizeEvidencePacksDocument",
    "normalizeFindingRecord",
    "normalizeGradeVerdictDocument",
    "normalizeHttpAuditRecord",
    "normalizeSessionStateDocument",
    "normalizeStringArray",
    "normalizeTrafficRecord",
    "pipelineEventsJsonlPath",
    "promoteSurfaceLeads",
    "publicIntelPath",
    "rankAttackSurfaces",
    "readAuthJson",
    "readChainAttempts",
    "readChainAttemptsFromJsonl",
    "readCoverageRecordsFromJsonl",
    "readEvidencePacks",
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
    "readSessionSummary",
    "readStateSummary",
    "readStaticArtifactRecordsFromJsonl",
    "readStaticScanResultsFromJsonl",
    "readSurfaceLeads",
    "readTechniqueAttemptRecordsFromJsonl",
    "readTechniquePack",
    "readTechniquePackReadRecordsFromJsonl",
    "readTrafficRecordsFromJsonl",
    "readVerificationRound",
    "readWaveHandoffs",
    "recordFinding",
    "recordSurfaceLeads",
    "redactUrlSensitiveValues",
    "renderEvidencePacksMarkdown",
    "renderFindingMarkdownEntry",
    "renderGradeVerdictMarkdown",
    "renderVerificationRoundMarkdown",
    "reportMarkdownPath",
    "reportWritten",
    "resolveAuthJsonPath",
    "resolveHunterKnowledge",
    "routeSurfaces",
    "selectTechniquePacks",
    "sessionDir",
    "sessionLockPath",
    "sessionsRoot",
    "setOperatorNote",
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
    "surfaceLeadsPath",
    "surfaceRoutesPath",
    "techniqueAttemptsJsonlPath",
    "techniquePackReadsJsonlPath",
    "tempEmail",
    "trafficJsonlPath",
    "transitionPhase",
    "validateScanUrl",
    "verificationRoundPaths",
    "waveHandoffStatus",
    "waveStatus",
    "writeChainAttempt",
    "writeEvidencePacks",
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
  assert.deepEqual(TOOL_MANIFEST.bounty_route_surfaces.role_bundles, ["orchestrator", "router"]);
  assert.equal(TOOL_MANIFEST.bounty_route_surfaces.mutating, true);
  assert.equal(TOOL_MANIFEST.bounty_route_surfaces.global_preapproval, false);
  assert.equal(TOOL_MANIFEST.bounty_route_surfaces.network_access, false);
  assert.equal(TOOL_MANIFEST.bounty_route_surfaces.browser_access, false);
  assert.equal(TOOL_MANIFEST.bounty_route_surfaces.sensitive_output, false);
  assert.deepEqual(TOOL_MANIFEST.bounty_route_surfaces.session_artifacts_written, ["surface-routes.json"]);
  assert.equal(byName.get("bounty_http_scan").inputSchema.properties.url.type, "string");
  assert.equal(byName.get("bounty_http_scan").inputSchema.properties.egress_profile.type, "string");
  assert.deepEqual(byName.get("bounty_http_scan").inputSchema.required, ["method", "url", "target_domain"]);
  assert.equal(TOOL_MANIFEST.bounty_read_http_audit.mutating, false);
  assert.equal(byName.get("bounty_write_chain_attempt").inputSchema.properties.outcome.enum.includes("inconclusive"), true);
  assert.deepEqual(TOOL_MANIFEST.bounty_write_chain_attempt.role_bundles, ["chain"]);
  assert.deepEqual(TOOL_MANIFEST.bounty_read_chain_attempts.role_bundles, ["chain", "verifier", "grader", "reporter", "orchestrator"]);
  assert.equal(byName.get("bounty_write_evidence_packs").inputSchema.properties.packs.items.properties.finding_id.pattern, "^F-[1-9][0-9]*$");
  assert.deepEqual(TOOL_MANIFEST.bounty_write_evidence_packs.role_bundles, ["evidence"]);
  assert.deepEqual(TOOL_MANIFEST.bounty_read_evidence_packs.role_bundles, ["evidence", "grader", "reporter", "orchestrator"]);
  assert.equal(TOOL_MANIFEST.bounty_start_wave.mutating, true);
  assert.equal(TOOL_MANIFEST.bounty_start_wave.global_preapproval, false);
  assert.deepEqual(TOOL_MANIFEST.bounty_start_wave.session_artifacts_written, [
    "surface-routes.json",
    "wave-N-assignments.json",
    "state.json",
  ]);
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
  assert.deepEqual(TOOL_MANIFEST.bounty_finalize_hunter_run.role_bundles, ["hunter-shared"]);
  assert.deepEqual(TOOL_MANIFEST.bounty_record_surface_leads.role_bundles, ["hunter-web", "orchestrator"]);
  assert.equal(TOOL_MANIFEST.bounty_record_surface_leads.mutating, true);
  assert.equal(TOOL_MANIFEST.bounty_record_surface_leads.global_preapproval, true);
  assert.equal(TOOL_MANIFEST.bounty_record_surface_leads.network_access, false);
  assert.equal(TOOL_MANIFEST.bounty_record_surface_leads.browser_access, false);
  assert.equal(TOOL_MANIFEST.bounty_record_surface_leads.scope_required, false);
  assert.equal(TOOL_MANIFEST.bounty_record_surface_leads.sensitive_output, false);
  assert.equal(TOOL_MANIFEST.bounty_record_surface_leads.hook_required, false);
  assert.deepEqual(TOOL_MANIFEST.bounty_record_surface_leads.session_artifacts_written, ["surface-leads.json"]);
  assert.deepEqual(TOOL_MANIFEST.bounty_read_surface_leads.role_bundles, ["hunter-web", "orchestrator"]);
  assert.equal(TOOL_MANIFEST.bounty_read_surface_leads.mutating, false);
  assert.equal(TOOL_MANIFEST.bounty_read_surface_leads.global_preapproval, true);
  assert.equal(TOOL_MANIFEST.bounty_read_surface_leads.network_access, false);
  assert.equal(TOOL_MANIFEST.bounty_read_surface_leads.browser_access, false);
  assert.equal(TOOL_MANIFEST.bounty_read_surface_leads.scope_required, false);
  assert.equal(TOOL_MANIFEST.bounty_read_surface_leads.sensitive_output, false);
  assert.equal(TOOL_MANIFEST.bounty_read_surface_leads.hook_required, false);
  assert.deepEqual(TOOL_MANIFEST.bounty_read_surface_leads.session_artifacts_written, []);
  assert.deepEqual(TOOL_MANIFEST.bounty_promote_surface_leads.role_bundles, ["orchestrator"]);
  assert.equal(TOOL_MANIFEST.bounty_promote_surface_leads.mutating, true);
  assert.equal(TOOL_MANIFEST.bounty_promote_surface_leads.global_preapproval, false);
  assert.equal(TOOL_MANIFEST.bounty_promote_surface_leads.network_access, false);
  assert.equal(TOOL_MANIFEST.bounty_promote_surface_leads.browser_access, false);
  assert.equal(TOOL_MANIFEST.bounty_promote_surface_leads.scope_required, false);
  assert.equal(TOOL_MANIFEST.bounty_promote_surface_leads.sensitive_output, false);
  assert.equal(TOOL_MANIFEST.bounty_promote_surface_leads.hook_required, false);
  assert.deepEqual(TOOL_MANIFEST.bounty_promote_surface_leads.session_artifacts_written, ["surface-leads.json", "attack_surface.json", "state.json"]);
  assert.deepEqual(TOOL_MANIFEST.bounty_get_context_budget.role_bundles, ["hunter-shared", "orchestrator"]);
  assert.equal(TOOL_MANIFEST.bounty_get_context_budget.mutating, false);
  assert.equal(TOOL_MANIFEST.bounty_get_context_budget.network_access, false);
  assert.equal(TOOL_MANIFEST.bounty_get_context_budget.browser_access, false);
  assert.equal(TOOL_MANIFEST.bounty_get_context_budget.scope_required, false);
  assert.deepEqual(TOOL_MANIFEST.bounty_get_context_budget.session_artifacts_written, []);
  assert.deepEqual(TOOL_MANIFEST.bounty_select_technique_packs.role_bundles, ["hunter-web", "orchestrator"]);
  assert.equal(TOOL_MANIFEST.bounty_select_technique_packs.mutating, false);
  assert.deepEqual(TOOL_MANIFEST.bounty_read_technique_pack.role_bundles, ["hunter-web", "orchestrator"]);
  assert.equal(TOOL_MANIFEST.bounty_read_technique_pack.mutating, true);
  assert.equal(byName.get("bounty_read_technique_pack").inputSchema.properties.mode.enum.includes("full"), true);
  assert.deepEqual(TOOL_MANIFEST.bounty_read_technique_pack.session_artifacts_written, ["technique-pack-reads.jsonl"]);
  assert.deepEqual(TOOL_MANIFEST.bounty_log_technique_attempt.role_bundles, ["hunter-web", "orchestrator"]);
  assert.equal(TOOL_MANIFEST.bounty_log_technique_attempt.mutating, true);
  assert.equal(TOOL_MANIFEST.bounty_log_technique_attempt.network_access, false);
  assert.equal(TOOL_MANIFEST.bounty_log_technique_attempt.browser_access, false);
  assert.equal(TOOL_MANIFEST.bounty_log_technique_attempt.scope_required, false);
  assert.equal(TOOL_MANIFEST.bounty_log_technique_attempt.sensitive_output, false);
  assert.deepEqual(TOOL_MANIFEST.bounty_log_technique_attempt.session_artifacts_written, ["technique-attempts.jsonl"]);
  assert.equal(TOOL_MANIFEST.bounty_read_session_summary.mutating, false);
  assert.equal(TOOL_MANIFEST.bounty_read_session_summary.global_preapproval, true);
  assert.deepEqual(TOOL_MANIFEST.bounty_read_session_summary.role_bundles, ["orchestrator", "reporter"]);
  assert.equal(TOOL_MANIFEST.bounty_set_operator_note.mutating, true);
  assert.equal(TOOL_MANIFEST.bounty_set_operator_note.global_preapproval, false);
  assert.deepEqual(TOOL_MANIFEST.bounty_set_operator_note.role_bundles, ["orchestrator"]);
  assert.equal(TOOL_MANIFEST.bounty_clear_operator_note.mutating, true);
  assert.equal(TOOL_MANIFEST.bounty_clear_operator_note.global_preapproval, false);
  assert.deepEqual(TOOL_MANIFEST.bounty_clear_operator_note.role_bundles, ["orchestrator"]);
});

test("MCP tool registry validation rejects incomplete or inconsistent entries", () => {
  const completeModule = {
    name: "bounty_test_tool",
    description: "Test tool.",
    inputSchema: { type: "object", properties: {} },
    handler: () => ({}),
    role_bundles: ["hunter-shared"],
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
    const rawTechniqueSecret = "pipeline-raw-technique-attempt-secret";
    const rawEvidenceText = "metadata-only analytics must not copy this evidence pack text";

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
    JSON.parse(logTechniqueAttempt({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      status: "attempted",
      outcome: "no_finding",
      evidence: rawTechniqueSecret,
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
    JSON.parse(writeChainAttempt({
      target_domain: domain,
      finding_ids: ["F-1"],
      surface_ids: ["surface-a"],
      hypothesis: "Single finding plus chain note does not produce an exploitable chain.",
      steps: ["Reviewed chain note and replay context."],
      outcome: "not_applicable",
      evidence_summary: "No second issue or request sequence amplifies F-1.",
    }));
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
    JSON.parse(writeEvidencePacks({
      target_domain: domain,
      packs: [{
        finding_id: "F-1",
        sample_type: "cross-account export",
        sample_count: 1,
        aggregate_counts: { private_exports_sampled: 1 },
        representative_samples: [{
          request_ref: "http-audit:1",
          endpoint: "/api/export",
          auth_profile: "attacker",
          status: 200,
          observed_fields: ["account_id"],
          redacted_object_id: "acct_...002",
        }],
        sensitive_clusters: ["account export metadata"],
        replay_summary: "Fresh replay returned another account export.",
        redaction_notes: "Object IDs and personal values redacted; auth material omitted.",
        report_snippet: rawEvidenceText,
      }],
    }));
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
      "technique_attempt_logged",
      "finding_recorded",
      "wave_merged",
      "verification_written",
      "evidence_written",
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
    assert.equal(analytics.sessions[0].chain_attempts_count, 1);
    assert.equal(analytics.sessions[0].chain_attempts_by_outcome.not_applicable, 1);
    assert.equal(analytics.sessions[0].technique_attempts.total, 1);
    assert.equal(analytics.sessions[0].technique_attempts.by_status.attempted, 1);
    assert.equal(analytics.sessions[0].technique_attempts.surface_count, 1);
    assert.equal(analytics.sessions[0].technique_attempts.pack_count, 1);
    assert.equal(typeof analytics.sessions[0].chain_phase_duration_ms, "number");
    assert.equal(analytics.sessions[0].final_verification_count, 1);
    assert.equal(analytics.sessions[0].evidence.valid, true);
    assert.equal(analytics.sessions[0].evidence.packs_count, 1);
    assert.equal(analytics.sessions[0].grade_verdict, "SUBMIT");
    assert.equal(analytics.sessions[0].report_present, true);
    assert.equal(analytics.funnel.reached.REPORT, 1);
    assert.equal(analytics.bottlenecks.length, 0);

    for (const forbidden of [rawPocSecret, rawHandoffSecret, rawCoverageSecret, rawTechniqueSecret, "metadata-only analytics must not copy this evidence", rawEvidenceText]) {
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
    writeFileAtomic(findingsJsonlPath(domain), `${JSON.stringify({
      id: "F-1",
      target_domain: domain,
      title: "Legacy IDOR",
      severity: "high",
      cwe: "CWE-639",
      endpoint: "/api/export",
      description: "Legacy finding migrated from an older run.",
      proof_of_concept: "curl https://legacy.example/api/export?account_id=2",
      response_evidence: "200 OK with redacted account metadata",
      impact: "Cross-account metadata disclosure.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    })}\n`);
    writeFileAtomic(techniqueAttemptsJsonlPath(domain), `${JSON.stringify({
      version: 1,
      ts: "2026-01-01T00:00:00.000Z",
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      pack_version: 1,
      registry_version: 1,
      capability_pack: "web",
      capability_pack_version: 1,
      status: "attempted",
      outcome: "no_finding",
      evidence: "Legacy session attempted the generic REST API pack.",
    })}\n`);
    writeFileAtomic(techniquePackReadsJsonlPath(domain), `${JSON.stringify({
      version: 1,
      ts: "2026-01-01T00:00:00.000Z",
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      pack_version: 1,
      registry_version: 1,
      capability_pack: "web",
      capability_pack_version: 1,
      mode: "full",
    })}\n`);
    for (const round of ["brutalist", "balanced", "final"]) {
      writeFileAtomic(verificationRoundPaths(domain, round).json, `${JSON.stringify({
        version: 1,
        target_domain: domain,
        round,
        results: [{
          finding_id: "F-1",
          disposition: "confirmed",
          severity: "high",
          reportable: true,
          reasoning: "Legacy verification confirmed the finding.",
        }],
      }, null, 2)}\n`);
    }
    writeFileAtomic(evidencePackPaths(domain).json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      packs: [{
        finding_id: "F-1",
        sample_type: "legacy sample",
        sample_count: 1,
        aggregate_counts: { examples: 1 },
        representative_samples: [{ request_ref: "legacy:1", status: 200 }],
        sensitive_clusters: ["redacted private metadata"],
        replay_summary: "Legacy evidence was collected before grading.",
        redaction_notes: "Values redacted.",
        report_snippet: "Legacy evidence pack covers F-1.",
      }],
    }, null, 2)}\n`);
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

    const artifactSummary = readSessionArtifactSummary(domain);
    assert.equal(artifactSummary.technique_attempts.total_records, 1);
    assert.equal(artifactSummary.technique_attempts.by_status.attempted, 1);
    assert.equal(artifactSummary.technique_pack_reads.full_reads, 1);

    const eventRead = readPipelineEvents(domain);
    assert.equal(eventRead.backfilled, true);
    assert.equal(eventRead.events.some((event) => event.source === "artifact_backfill"), true);
    assert.equal(eventRead.events.some((event) => event.type === "technique_attempt_logged" && event.source === "artifact_backfill"), true);

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain, include_events: true }));
    assert.equal(analytics.event_log.backfilled, true);
    assert.equal(analytics.sessions[0].health.status, "healthy");
    assert.equal(analytics.sessions[0].report_present, true);
    assert.equal(analytics.sessions[0].technique_attempts.total, 1);
    assert.equal(analytics.sessions[0].technique_attempts.by_status.attempted, 1);
    assert.equal(analytics.sessions[0].technique_pack_reads.full_reads, 1);
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

test("pipeline analytics uses recent technique-pack read artifacts as pending-wave activity", () => {
  withTempHome(() => {
    const domain = "recent-pack-read.example";
    const oldDate = new Date(Date.now() - 4 * 60 * 60 * 1000);
    const oldIso = oldDate.toISOString();
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1, hunt_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    fs.appendFileSync(pipelineEventsJsonlPath(domain), `${JSON.stringify({
      version: 1,
      ts: oldIso,
      target_domain: domain,
      type: "wave_started",
      wave_number: 1,
      status: "started",
      source: "test",
      counts: { assignments: 1 },
    })}\n`, "utf8");
    fs.utimesSync(statePath(domain), oldDate, oldDate);
    fs.utimesSync(attackSurfacePath(domain), oldDate, oldDate);

    writeFileAtomic(techniquePackReadsJsonlPath(domain), `${JSON.stringify({
      version: 1,
      ts: new Date().toISOString(),
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      pack_version: 1,
      registry_version: 1,
      capability_pack: "web",
      capability_pack_version: 1,
      mode: "full",
    })}\n`);

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain, include_events: true }));
    const row = analytics.sessions[0];
    assert.equal(row.technique_pack_reads.full_reads, 1);
    assert.ok(row.health.reasons.includes("hunter_handoff_failures"));
    assert.equal(row.health.reasons.includes("stale_pending_wave"), false);
    assert.equal(row.latest_event.ts, oldIso);
    assert.ok(Date.now() - Date.parse(row.latest_activity_ts) < 60_000);
  });
});

test("pipeline analytics reports chain attempts, chain duration, and no-attempt bottleneck", () => {
  withTempHome(() => {
    const domain = "chain-analytics.example.com";
    seedSessionState(domain, { phase: "VERIFY" });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" },
    ]);
    seedFinding(domain, { title: "IDOR export", endpoint: "/api/export" });
    seedFinding(domain, { title: "Open redirect", endpoint: "/oauth/callback" });
    JSON.parse(writeChainAttempt({
      target_domain: domain,
      finding_ids: ["F-1", "F-2"],
      surface_ids: ["surface-a"],
      hypothesis: "Open redirect may amplify export access.",
      steps: ["Started replay but could not complete before auth expired."],
      outcome: "inconclusive",
      evidence_summary: "Auth expired before a terminal result.",
    }));
    writeFileAtomic(pipelineEventsJsonlPath(domain), [
      {
        version: 1,
        ts: "2026-04-24T00:00:00.000Z",
        target_domain: domain,
        type: "phase_transitioned",
        from_phase: "HUNT",
        to_phase: "CHAIN",
        phase: "CHAIN",
      },
      {
        version: 1,
        ts: "2026-04-24T00:01:00.000Z",
        target_domain: domain,
        type: "phase_transitioned",
        from_phase: "CHAIN",
        to_phase: "VERIFY",
        phase: "VERIFY",
      },
    ].map((event) => JSON.stringify(event)).join("\n") + "\n");

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain, include_events: true }));
    assert.equal(analytics.sessions[0].chain_attempts_count, 1);
    assert.equal(analytics.sessions[0].chain_attempts_by_outcome.inconclusive, 1);
    assert.equal(analytics.sessions[0].chain_phase_duration_ms, 60_000);
    assert.equal(analytics.sessions[0].health.status, "blocked");
    assert.ok(analytics.sessions[0].health.reasons.includes("chain_phase_no_attempts"));
    assert.ok(analytics.bottlenecks.some((bottleneck) => bottleneck.code === "chain_phase_no_attempts"));
  });
});

test("pipeline analytics flags missing evidence only for final reportable findings", () => {
  withTempHome(() => {
    const domain = "missing-evidence.example.com";
    seedSessionState(domain, { phase: "GRADE" });
    seedFinding(domain);
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain, include_events: true }));
    assert.equal(analytics.sessions[0].evidence.valid, false);
    assert.deepEqual(analytics.sessions[0].evidence.missing_finding_ids, ["F-1"]);
    assert.ok(analytics.sessions[0].health.reasons.includes("missing_evidence"));
    assert.ok(analytics.bottlenecks.some((bottleneck) => bottleneck.code === "missing_evidence"));

    const noReportableDomain = "no-evidence-needed.example.com";
    seedSessionState(noReportableDomain, { phase: "GRADE" });
    seedFinding(noReportableDomain);
    seedVerificationPipeline(noReportableDomain, [{
      finding_id: "F-1",
      disposition: "denied",
      severity: null,
      reportable: false,
      reasoning: "Not reproducible.",
    }]);

    const noReportable = JSON.parse(readPipelineAnalytics({ target_domain: noReportableDomain, include_events: true }));
    assert.equal(noReportable.sessions[0].evidence.valid, true);
    assert.equal(noReportable.sessions[0].evidence.skipped, undefined);
    assert.ok(!noReportable.sessions[0].health.reasons.includes("missing_evidence"));
    assert.ok(!noReportable.bottlenecks.some((bottleneck) => bottleneck.code === "missing_evidence"));
  });
});

test("pipeline analytics flags only HOLD as needs_attention; both SKIP variants are healthy by construction", () => {
  // writeGradeVerdict rejects any SKIP that does not satisfy
  // `!hasReportableMedium || total_score < GRADE_HOLD_MIN_SCORE`. SKIP at
  // read time is therefore either "no reportables" (clean exit) or
  // "low-score reportables below the HOLD threshold" (grader correctly
  // applied its scoring rule). Neither is anomalous — only HOLD asks for
  // operator action.
  withTempHome(() => {
    const skipCleanDomain = "skip-clean.example.com";
    seedSessionState(skipCleanDomain, { phase: "REPORT" });
    seedVerificationPipeline(skipCleanDomain, []);
    writeGradeVerdict({
      target_domain: skipCleanDomain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
    });
    const skipClean = JSON.parse(readPipelineAnalytics({ target_domain: skipCleanDomain, include_events: true }));
    assert.ok(!skipClean.sessions[0].health.reasons.includes("grade_hold"));
    assert.ok(!skipClean.sessions[0].health.reasons.includes("grade_hold_skip"));
    assert.ok(!skipClean.bottlenecks.some((bottleneck) => bottleneck.code.startsWith("grade_")));

    const skipLowScoreDomain = "skip-low-score.example.com";
    seedSessionState(skipLowScoreDomain, { phase: "REPORT" });
    seedFinding(skipLowScoreDomain);
    seedVerificationPipeline(skipLowScoreDomain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed by replay.",
    }]);
    writeEvidencePacks({ target_domain: skipLowScoreDomain, packs: [evidencePack("F-1")] });
    writeGradeVerdict({
      target_domain: skipLowScoreDomain,
      verdict: "SKIP",
      total_score: 5,
      findings: [{
        finding_id: "F-1",
        impact: 1,
        proof_quality: 1,
        severity_accuracy: 1,
        chain_potential: 1,
        report_quality: 1,
        total_score: 5,
        feedback: "Below HOLD_MIN_SCORE despite confirmation; grader contract.",
      }],
    });
    const skipLowScore = JSON.parse(readPipelineAnalytics({ target_domain: skipLowScoreDomain, include_events: true }));
    assert.ok(!skipLowScore.sessions[0].health.reasons.includes("grade_hold"));
    assert.ok(!skipLowScore.bottlenecks.some((bottleneck) => bottleneck.code.startsWith("grade_")));

    const holdDomain = "grade-hold.example.com";
    seedSessionState(holdDomain, { phase: "GRADE" });
    seedFinding(holdDomain);
    seedVerificationPipeline(holdDomain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);
    writeEvidencePacks({ target_domain: holdDomain, packs: [evidencePack("F-1")] });
    writeGradeVerdict({
      target_domain: holdDomain,
      verdict: "HOLD",
      total_score: 30,
      findings: [{
        finding_id: "F-1",
        impact: 10,
        proof_quality: 5,
        severity_accuracy: 5,
        chain_potential: 5,
        report_quality: 5,
        total_score: 30,
        feedback: "Promising but needs deeper repro.",
      }],
    });
    const hold = JSON.parse(readPipelineAnalytics({ target_domain: holdDomain, include_events: true }));
    assert.ok(hold.sessions[0].health.reasons.includes("grade_hold"));
    assert.ok(hold.bottlenecks.some((bottleneck) => bottleneck.code === "grade_hold"));
  });
});

test("pipeline analytics treats malformed evidence packs as invalid metadata", () => {
  withTempHome(() => {
    const domain = "malformed-evidence.example.com";
    seedSessionState(domain, { phase: "GRADE" });
    seedFinding(domain);
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);
    writeFileAtomic(evidencePackPaths(domain).json, `${JSON.stringify({
      packs: [{ finding_id: "F-1" }],
    }, null, 2)}\n`);

    const artifactSummary = readSessionArtifactSummary(domain);
    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain, include_events: true }));
    assert.equal(analytics.sessions[0].evidence.valid, false);
    assert.equal(analytics.sessions[0].evidence.packs_count, 1);
    assert.equal(analytics.sessions[0].evidence.reportable_findings_covered, 1);
    assert.ok(analytics.sessions[0].health.reasons.includes("missing_evidence"));
    assert.ok(analytics.bottlenecks.some((bottleneck) => bottleneck.code === "missing_evidence"));
    assert.match(artifactSummary.evidence.error, /Evidence packs.*target_domain|version/);
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
      deep_mode: false,
      phase: "RECON",
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

    const deepDomain = "deep.example.com";
    const deepCreated = JSON.parse(initSession({
      target_domain: deepDomain,
      target_url: "https://deep.example.com",
      deep_mode: true,
    }));
    assert.equal(deepCreated.state.deep_mode, true);
    assert.equal(JSON.parse(readStateSummary({ target_domain: deepDomain })).state.deep_mode, true);
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
        deep_mode: false,
        phase: "RECON",
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

test("operator note set read and clear works and rejects secret-looking values", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT" });

    const set = JSON.parse(setOperatorNote({
      target_domain: domain,
      operator_note: "Use operator-approved EU egress on the next resume.",
    }));
    assert.equal(set.updated, true);
    assert.equal(set.state.operator_note, "Use operator-approved EU egress on the next resume.");
    assert.equal(
      JSON.parse(readStateSummary({ target_domain: domain })).state.operator_note,
      "Use operator-approved EU egress on the next resume.",
    );

    assert.throws(
      () => setOperatorNote({
        target_domain: domain,
        operator_note: "Authorization: Bearer abcdefghijklmnop",
      }),
      /secrets, auth headers, cookies, or tokens/,
    );

    const cleared = JSON.parse(clearOperatorNote({ target_domain: domain }));
    assert.equal(cleared.cleared, true);
    assert.equal(JSON.parse(readStateSummary({ target_domain: domain })).state.operator_note, null);
  });
});

test("bounty_read_session_summary derives compact status without raw proof evidence or report text", () => {
  withTempHome(() => {
    const domain = "summary.example.com";
    const rawPoc = "raw-poc-text-that-must-not-escape";
    const rawEvidence = "raw-evidence-text-that-must-not-escape";
    const fullReport = "full report text that the summary must not include";
    seedSessionState(domain, {
      phase: "REPORT",
      hunt_wave: 2,
      auth_status: "authenticated",
      operator_note: "Summarize only.",
    });
    seedFinding(domain, {
      proof_of_concept: rawPoc,
      response_evidence: rawEvidence,
    });
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);
    JSON.parse(writeEvidencePacks({
      target_domain: domain,
      packs: [evidencePack("F-1", {
        replay_summary: "Bounded replay returned private metadata.",
        report_snippet: "Private metadata exposure.",
      })],
    }));
    JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 40,
      findings: [{
        finding_id: "F-1",
        impact: 20,
        proof_quality: 10,
        severity_accuracy: 5,
        chain_potential: 0,
        report_quality: 5,
        total_score: 40,
        feedback: null,
      }],
      feedback: null,
    }));
    fs.writeFileSync(reportMarkdownPath(domain), fullReport, "utf8");

    const result = JSON.parse(readSessionSummary({ target_domain: domain }));
    assert.equal(result.version, 1);
    assert.equal(result.summary.target, domain);
    assert.equal(result.summary.phase, "REPORT");
    assert.equal(result.summary.auth_status, "authenticated");
    assert.equal(result.summary.waves_run, 2);
    assert.equal(result.summary.finding_total, 1);
    assert.equal(result.summary.final_reportable_count, 1);
    assert.equal(result.summary.evidence_status.status, "valid");
    assert.equal(result.summary.grade_verdict, "SUBMIT");
    assert.equal(result.summary.report.present, true);
    assert.equal(result.summary.report.path, reportMarkdownPath(domain));
    assert.equal(result.summary.operator_note, "Summarize only.");
    assert.deepEqual(result.summary.blockers, []);
    assert.doesNotMatch(JSON.stringify(result), new RegExp(rawPoc));
    assert.doesNotMatch(JSON.stringify(result), new RegExp(rawEvidence));
    assert.doesNotMatch(JSON.stringify(result), new RegExp(fullReport));
    assert.doesNotMatch(JSON.stringify(result), /representative_samples/);
  });
});

test("bounty_read_session_summary aggregates blocked_prereqs by (kind, identifier_hint)", () => {
  withTempHome(() => {
    const domain = "summary-blocked.example.com";
    seedSessionState(domain, {
      phase: "REPORT",
      hunt_wave: 3,
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-a", "auth_missing", "attacker", { reason: "no attacker profile registered" }),
        buildTerminallyBlockedEntry("surface-b", "auth_missing", "attacker", { reason: "blocked second surface" }),
        buildTerminallyBlockedEntry("surface-c", "egress_unreachable", null, { reason: "default egress unreachable" }),
      ],
    });
    const summary = JSON.parse(readSessionSummary({ target_domain: domain })).summary;
    assert.equal(summary.blocked_prereqs.total_blocked_surfaces, 3);
    // by_kind ordered by actionability: auth_missing (rank 0) before egress_unreachable (rank 1).
    assert.equal(summary.blocked_prereqs.by_kind[0].kind, "auth_missing");
    assert.equal(summary.blocked_prereqs.by_kind[1].kind, "egress_unreachable");
    const authGroup = summary.blocked_prereqs.by_kind.find((g) => g.kind === "auth_missing" && g.identifier_hint === "attacker");
    assert.ok(authGroup, "expected auth_missing/attacker group");
    assert.equal(authGroup.surface_count, 2);
    assert.deepEqual(authGroup.surface_ids.sort(), ["surface-a", "surface-b"]);
    assert.match(authGroup.latest_reason || "", /blocked second surface|no attacker profile/);
    const egressGroup = summary.blocked_prereqs.by_kind.find((g) => g.kind === "egress_unreachable");
    assert.ok(egressGroup, "expected egress_unreachable group");
    assert.equal(egressGroup.identifier_hint, null);
    assert.equal(egressGroup.surface_count, 1);
  });
});

test("bounty_write_chain_attempt records normalized attempts and bounty_read_chain_attempts summarizes outcomes", async () => {
  await withTempHome(async () => {
    const domain = "chain-attempt.example.com";
    seedSessionState(domain, { phase: "CHAIN" });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" },
    ]);
    seedFinding(domain, { title: "IDOR export", endpoint: "/api/export" });
    seedFinding(domain, { title: "OAuth redirect", endpoint: "/oauth/callback" });

    const written = JSON.parse(writeChainAttempt({
      target_domain: domain,
      finding_ids: ["F-1", "F-2"],
      surface_ids: ["surface-a"],
      hypothesis: "F-2 open redirect can capture a token that amplifies F-1 export.",
      steps: [
        "Reviewed finding PoCs and handoff notes.",
        "Replayed redirect with attacker profile and checked whether token material was exposed.",
      ],
      outcome: "denied",
      evidence_summary: "Redirect does not receive token material, so the chain is denied.",
      request_refs: ["http-audit:C-1"],
      auth_profiles: ["attacker"],
    }));

    assert.equal(written.written, true);
    assert.equal(written.attempt_id, "C-1");
    assert.equal(written.summary.total, 1);
    assert.equal(written.summary.by_outcome.denied, 1);
    assert.ok(fs.existsSync(chainAttemptsJsonlPath(domain)));

    const directRead = JSON.parse(readChainAttempts({ target_domain: domain }));
    assert.equal(directRead.attempts.length, 1);
    assert.equal(directRead.summary.terminal_count, 1);
    assert.equal(directRead.summary.has_terminal_attempt, true);
    assert.deepEqual(readChainAttemptsFromJsonl(domain).map((attempt) => attempt.attempt_id), ["C-1"]);

    const envelope = await executeTool("bounty_read_chain_attempts", { target_domain: domain });
    assert.equal(envelope.ok, true);
    assert.equal(envelope.data.summary.by_outcome.denied, 1);
  });
});

test("bounty_write_chain_attempt rejects malformed references and invalid outcomes", async () => {
  await withTempHome(async () => {
    const domain = "chain-validation.example.com";
    seedSessionState(domain, { phase: "CHAIN" });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" },
    ]);
    seedFinding(domain, { title: "IDOR export", endpoint: "/api/export" });

    const base = {
      target_domain: domain,
      finding_ids: ["F-1"],
      surface_ids: ["surface-a"],
      hypothesis: "F-1 may combine with another weakness.",
      steps: ["Reviewed evidence and attempted a replay."],
      outcome: "blocked",
      evidence_summary: "Replay was blocked by expired auth.",
    };

    assert.throws(
      () => writeChainAttempt({ ...base, finding_ids: ["finding-1"] }),
      /finding_ids must match F-N/,
    );
    assert.throws(
      () => writeChainAttempt({ ...base, finding_ids: ["F-999"] }),
      /unknown finding_id: F-999/,
    );
    assert.throws(
      () => writeChainAttempt({ ...base, hypothesis: " " }),
      /hypothesis must be a non-empty string/,
    );
    assert.throws(
      () => writeChainAttempt({ ...base, surface_ids: ["surface-missing"] }),
      /unknown surface_id: surface-missing/,
    );

    const invalidOutcome = await executeTool("bounty_write_chain_attempt", {
      ...base,
      outcome: "maybe",
    });
    assert.equal(invalidOutcome.ok, false);
    assert.equal(invalidOutcome.error.code, "INVALID_ARGUMENTS");
    assert.match(invalidOutcome.error.message, /outcome must be one of/);

    const wrongDomain = "chain-wrong-domain.example.com";
    appendJsonlLine(chainAttemptsJsonlPath(wrongDomain), {
      version: 1,
      ts: new Date().toISOString(),
      attempt_id: "C-1",
      target_domain: "other.example.com",
      finding_ids: [],
      surface_ids: [],
      hypothesis: "No chain applies.",
      steps: ["Checked candidates."],
      outcome: "not_applicable",
      evidence_summary: "Wrong-domain fixture.",
      request_refs: [],
      auth_profiles: [],
    });
    assert.throws(
      () => readChainAttemptsFromJsonl(wrongDomain),
      /target_domain mismatch/,
    );
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
      const stateOverrides = {
        phase: scenario.from,
        hold_count: scenario.hold_count ?? 0,
      };
      if (scenario.from === "HUNT" && scenario.to === "CHAIN") {
        stateOverrides.explored = ["surface-a"];
        seedAttackSurfaces(domain, [
          { id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" },
        ]);
      }
      seedSessionState(domain, stateOverrides);
      if (
        (scenario.from === "VERIFY" && scenario.to === "GRADE") ||
        (scenario.from === "GRADE" && scenario.to === "REPORT")
      ) {
        if (!fs.existsSync(findingsJsonlPath(domain))) {
          seedFinding(domain);
        }
        seedVerificationPipeline(domain, [{
          finding_id: "F-1",
          disposition: "denied",
          severity: null,
          reportable: false,
          reasoning: "No reportable findings in the edge smoke fixture.",
        }]);
      }

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

test("bounty_transition_phase blocks HUNT -> CHAIN while a wave is pending", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      pending_wave: 1,
      explored: ["surface-a"],
    });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" },
    ]);

    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "CHAIN" }),
      /HUNT -> CHAIN blocked: .*pending_wave is still set to 1/,
    );
  });
});

test("bounty_transition_phase blocks HUNT -> CHAIN with unexplored HIGH or CRITICAL surfaces", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      pending_wave: null,
      explored: ["surface-a"],
    });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "CRITICAL" },
      { id: "surface-b", hosts: [`https://api.${domain}`], priority: "HIGH" },
    ]);

    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "CHAIN" }),
      /HUNT -> CHAIN blocked: .*surface-b/,
    );
  });
});

test("bounty_transition_phase blocks HUNT -> CHAIN with unfinished latest coverage on an unexplored surface", () => {
  withTempHome(() => {
    for (const status of ["promising", "needs_auth", "requeue"]) {
      const domain = `${status.replace("_", "-")}.example.com`;
      // Note: surface-a is intentionally NOT in `explored`. An unfinished
      // coverage row on a surface whose `surface_status: complete` handoff
      // has not yet merged is the canonical "still has work" signal.
      seedSessionState(domain, {
        phase: "HUNT",
        pending_wave: null,
        explored: [],
      });
      seedAttackSurfaces(domain, [
        { id: "surface-a", hosts: [`https://${domain}`], priority: "MEDIUM" },
      ]);
      seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
      logCoverage({
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        entries: [{
          endpoint: "/api/export",
          method: "GET",
          bug_class: "idor",
          status,
          evidence_summary: `${status} evidence`,
        }],
      });

      assert.throws(
        () => transitionPhase({ target_domain: domain, to_phase: "CHAIN" }),
        /HUNT -> CHAIN blocked: .*surface-a/,
      );
    }
  });
});

test("bounty_transition_phase allows HUNT -> CHAIN when unfinished coverage rows exist on explored surfaces", () => {
  // state.explored is populated from `surface_status: complete` handoffs
  // by applyWaveMerge. Once a complete handoff merges, the surface is
  // closed regardless of older endpoint-level coverage rows whose latest
  // status was promising/needs_auth/requeue. The HUNT -> CHAIN gate must
  // not refuse the transition over such stale rows.
  withTempHome(() => {
    const domain = "explored-with-stale-coverage.example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      pending_wave: null,
      explored: ["surface-a"],
      hunt_wave: 1,
    });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "MEDIUM" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [{
        endpoint: "/api/legacy",
        method: "GET",
        bug_class: "idor",
        status: "requeue",
        evidence_summary: "endpoint-level requeue from earlier wave; surface later closed by complete handoff",
      }],
    });

    transitionPhase({ target_domain: domain, to_phase: "CHAIN" });
    const summary = JSON.parse(readStateSummary({ target_domain: domain }));
    assert.equal(summary.state.phase, "CHAIN");
  });
});

test("bounty_transition_phase treats missing attack surface or malformed coverage as HUNT -> CHAIN blockers", () => {
  withTempHome(() => {
    const missingSurfaceDomain = "missing-surface.example.com";
    seedSessionState(missingSurfaceDomain, {
      phase: "HUNT",
      pending_wave: null,
    });
    assert.throws(
      () => transitionPhase({ target_domain: missingSurfaceDomain, to_phase: "CHAIN" }),
      /HUNT -> CHAIN blocked: .*attack surface could not be read/,
    );

    const malformedCoverageDomain = "malformed-coverage.example.com";
    seedSessionState(malformedCoverageDomain, {
      phase: "HUNT",
      pending_wave: null,
      explored: ["surface-a"],
    });
    seedAttackSurfaces(malformedCoverageDomain, [
      { id: "surface-a", hosts: [`https://${malformedCoverageDomain}`], priority: "HIGH" },
    ]);
    writeFileAtomic(coverageJsonlPath(malformedCoverageDomain), "{bad json\n");

    assert.throws(
      () => transitionPhase({ target_domain: malformedCoverageDomain, to_phase: "CHAIN" }),
      /HUNT -> CHAIN blocked: .*coverage could not be read/,
    );
  });
});

test("bounty_transition_phase override_reason allows HUNT -> CHAIN and is persisted in pipeline events", () => {
  withTempHome(() => {
    const domain = "example.com";
    const overrideReason = "Operator accepts pending wave risk for urgent chain validation.";
    seedSessionState(domain, {
      phase: "HUNT",
      pending_wave: 1,
      explored: ["surface-a"],
    });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" },
    ]);

    const result = JSON.parse(transitionPhase({
      target_domain: domain,
      to_phase: "CHAIN",
      override_reason: overrideReason,
    }));
    assert.equal(result.transitioned, true);
    assert.equal(result.to_phase, "CHAIN");

    const rows = readJsonl(pipelineEventsJsonlPath(domain));
    const event = rows.find((row) => row.type === "phase_transitioned" && row.to_phase === "CHAIN");
    assert.equal(event.override, true);
    assert.equal(event.override_reason, overrideReason);
    assert.equal(event.counts.transition_blockers, 1);

    const normalizedEvent = readPipelineEvents(domain).events
      .find((row) => row.type === "phase_transitioned" && row.to_phase === "CHAIN");
    assert.equal(normalizedEvent.override, true);
    assert.equal(normalizedEvent.override_reason, overrideReason);
  });
});

test("bounty_transition_phase rejects override_reason outside gated transitions", () => {
  withTempHome(() => {
    const domain = "example.com";
    const overrideReason = "This override reason is long enough to pass length validation.";
    const cases = [
      { from: "RECON", to: "AUTH" },
      { from: "AUTH", to: "HUNT", auth_status: "authenticated" },
      { from: "VERIFY", to: "GRADE" },
      { from: "GRADE", to: "REPORT" },
      { from: "GRADE", to: "HUNT" },
      { from: "REPORT", to: "EXPLORE" },
      { from: "EXPLORE", to: "CHAIN" },
    ];

    for (const scenario of cases) {
      seedSessionState(domain, { phase: scenario.from });
      assert.throws(
        () => transitionPhase({
          target_domain: domain,
          to_phase: scenario.to,
          auth_status: scenario.auth_status,
          override_reason: overrideReason,
        }),
        /override_reason is only allowed for HUNT -> CHAIN or CHAIN -> VERIFY/,
      );
    }
  });
});

test("bounty_transition_phase rejects short HUNT -> CHAIN override_reason", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      pending_wave: 1,
      explored: ["surface-a"],
    });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" },
    ]);

    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "CHAIN", override_reason: "too short" }),
      /override_reason must be at least 20 characters/,
    );
  });
});

test("bounty_transition_phase blocks CHAIN -> VERIFY when required chain work has no terminal attempts", () => {
  withTempHome(() => {
    const domain = "chain-gate.example.com";
    seedSessionState(domain, { phase: "CHAIN" });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" },
    ]);
    seedFinding(domain, { title: "IDOR export", endpoint: "/api/export" });
    seedFinding(domain, { title: "Open redirect", endpoint: "/oauth/callback" });

    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "VERIFY" }),
      /CHAIN -> VERIFY blocked: .*terminal chain attempt/,
    );

    JSON.parse(writeChainAttempt({
      target_domain: domain,
      finding_ids: ["F-1", "F-2"],
      surface_ids: ["surface-a"],
      hypothesis: "Open redirect may amplify export access.",
      steps: ["Checked redirect behavior but auth expired before replay."],
      outcome: "inconclusive",
      evidence_summary: "Auth expired before a fair test.",
      auth_profiles: ["attacker"],
    }));

    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "VERIFY" }),
      /CHAIN -> VERIFY blocked: .*inconclusive/,
    );
  });
});

test("bounty_transition_phase allows CHAIN -> VERIFY when a terminal attempt exists", () => {
  withTempHome(() => {
    const domain = "chain-terminal.example.com";
    seedSessionState(domain, { phase: "CHAIN" });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" },
    ]);
    seedFinding(domain, { title: "IDOR export", endpoint: "/api/export" });
    seedFinding(domain, { title: "Open redirect", endpoint: "/oauth/callback" });
    JSON.parse(writeChainAttempt({
      target_domain: domain,
      finding_ids: ["F-1", "F-2"],
      surface_ids: ["surface-a"],
      hypothesis: "Open redirect may amplify export access.",
      steps: ["Replayed redirect and export sequence."],
      outcome: "denied",
      evidence_summary: "Redirect never exposes a token or reusable credential.",
      request_refs: ["http-audit:C-1"],
    }));

    const result = JSON.parse(transitionPhase({ target_domain: domain, to_phase: "VERIFY" }));
    assert.equal(result.transitioned, true);
    assert.equal(result.from_phase, "CHAIN");
    assert.equal(result.to_phase, "VERIFY");
  });
});

test("bounty_transition_phase CHAIN -> VERIFY gate treats handoff chain_notes as required chain work", () => {
  withTempHome(() => {
    const domain = "twilio-shape.example.com";
    seedSessionState(domain, { phase: "CHAIN" });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    for (let index = 0; index < 5; index += 1) {
      seedFinding(domain, {
        title: `Finding ${index + 1}`,
        endpoint: `/api/finding-${index + 1}`,
      });
    }
    writeFileAtomic(path.join(sessionDir(domain), "handoff-w1-a1.json"), `${JSON.stringify({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      chain_notes: ["F-1 may combine with F-2 for account takeover."],
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
    }, null, 2)}\n`);

    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "VERIFY" }),
      /CHAIN -> VERIFY blocked: .*terminal chain attempt/,
    );
  });
});

test("bounty_transition_phase override_reason allows CHAIN -> VERIFY and is persisted in pipeline events", () => {
  withTempHome(() => {
    const domain = "chain-override.example.com";
    const overrideReason = "Operator reviewed chain handoff notes and accepts proceeding without terminal chain attempts.";
    seedSessionState(domain, { phase: "CHAIN" });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" },
    ]);
    seedFinding(domain, { title: "IDOR export", endpoint: "/api/export" });
    seedFinding(domain, { title: "Open redirect", endpoint: "/oauth/callback" });

    const result = JSON.parse(transitionPhase({
      target_domain: domain,
      to_phase: "VERIFY",
      override_reason: overrideReason,
    }));
    assert.equal(result.transitioned, true);
    assert.equal(result.to_phase, "VERIFY");

    const event = readJsonl(pipelineEventsJsonlPath(domain))
      .find((row) => row.type === "phase_transitioned" && row.to_phase === "VERIFY");
    assert.equal(event.override, true);
    assert.equal(event.override_reason, overrideReason);
    assert.equal(event.counts.transition_blockers, 1);
  });
});

test("bounty_transition_phase VERIFY -> GRADE requires valid evidence for final reportables", () => {
  withTempHome(() => {
    const domain = "verify-grade-evidence.example.com";
    seedSessionState(domain, { phase: "VERIFY" });
    seedFinding(domain);
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);

    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "GRADE" }),
      /VERIFY -> GRADE blocked: .*Evidence packs.*Missing evidence packs JSON/i,
    );
  });
});

test("bounty_transition_phase VERIFY -> GRADE succeeds with valid evidence", () => {
  withTempHome(() => {
    const domain = "verify-grade-valid-evidence.example.com";
    seedSessionState(domain, { phase: "VERIFY" });
    seedFinding(domain);
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);
    JSON.parse(writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] }));

    const result = JSON.parse(transitionPhase({ target_domain: domain, to_phase: "GRADE" }));
    assert.equal(result.transitioned, true);
    assert.equal(result.from_phase, "VERIFY");
    assert.equal(result.to_phase, "GRADE");
  });
});

test("bounty_transition_phase VERIFY -> GRADE succeeds without evidence when final has no reportables", () => {
  withTempHome(() => {
    const domain = "verify-grade-no-reportables.example.com";
    seedSessionState(domain, { phase: "VERIFY" });
    seedFinding(domain);
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "denied",
      severity: null,
      reportable: false,
      reasoning: "Not reproducible.",
    }]);

    const result = JSON.parse(transitionPhase({ target_domain: domain, to_phase: "GRADE" }));
    assert.equal(result.transitioned, true);
    assert.equal(result.to_phase, "GRADE");
  });
});

test("bounty_transition_phase GRADE -> REPORT requires valid evidence for final reportables", () => {
  withTempHome(() => {
    const domain = "grade-report-evidence.example.com";
    seedSessionState(domain, { phase: "GRADE" });
    seedFinding(domain);
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);

    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "REPORT" }),
      /GRADE -> REPORT blocked: .*Evidence packs.*Missing evidence packs JSON/i,
    );
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

test("capability routing maps current web surface types to the web pack", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "S-api", surface_type: "api", hosts: [`https://api.${domain}`] },
      { id: "S-graphql", surface_type: "GraphQL", hosts: [`https://app.${domain}`] },
      { id: "S-upload", surface_type: "upload", hosts: [`https://app.${domain}`] },
      { id: "S-billing", surface_type: "billing", hosts: [`https://app.${domain}`] },
      { id: "S-unknown", surface_type: "unknown", hosts: [`https://app.${domain}`] },
      { id: "S-missing", hosts: [`https://app.${domain}`] },
    ]);

    const result = JSON.parse(routeSurfaces({ target_domain: domain }));
    assert.equal(result.routed, true);
    assert.equal(result.surface_count, 6);
    assert.deepEqual(result.counts, { web: 6 });
    assert.equal(result.surface_routes_path, surfaceRoutesPath(domain));

    const routes = JSON.parse(fs.readFileSync(surfaceRoutesPath(domain), "utf8")).routes;
    assert.deepEqual(routes.map((route) => route.capability_pack), Array(6).fill("web"));
    assert.deepEqual(routes.map((route) => route.capability_pack_version), Array(6).fill(1));
    assert.deepEqual(routes.map((route) => route.hunter_agent), Array(6).fill("hunter-agent"));
    assert.deepEqual(routes.map((route) => route.brief_profile), Array(6).fill("web"));
    for (const route of routes) {
      assert.deepEqual(route.context_budget, expectedWebContextBudget());
    }
    assert.equal(routes.find((route) => route.surface_id === "S-graphql").surface_type, "graphql");
    assert.deepEqual(routes.find((route) => route.surface_id === "S-api").reasons, ["surface_type:api"]);
    assert.deepEqual(routes.find((route) => route.surface_id === "S-missing").reasons, ["surface_type:missing"]);
  });
});

test("bounty_route_surfaces writes bounded current routes and removes stale routes", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{
      id: "S-1",
      surface_type: "api",
      hosts: [`https://api.${domain}`],
      endpoints: ["/api/private/export?token=secret"],
      evidence: ["large recon details that should not be copied into surface-routes.json"],
    }]);

    JSON.parse(routeSurfaces({ target_domain: domain }));
    let routeText = fs.readFileSync(surfaceRoutesPath(domain), "utf8");
    assert.doesNotMatch(routeText, /private\/export|large recon details/);
    assert.deepEqual(JSON.parse(routeText).routes.map((route) => Object.keys(route).sort()), [[
      "brief_profile",
      "capability_pack",
      "capability_pack_version",
      "confidence",
      "context_budget",
      "hunter_agent",
      "reasons",
      "surface_id",
      "surface_type",
    ]]);

    seedAttackSurfaces(domain, [{ id: "S-2", surface_type: "admin", hosts: [`https://admin.${domain}`] }]);
    const result = JSON.parse(routeSurfaces({ target_domain: domain }));
    routeText = fs.readFileSync(surfaceRoutesPath(domain), "utf8");
    assert.deepEqual(result.counts, { web: 1 });
    assert.deepEqual(JSON.parse(routeText).routes.map((route) => route.surface_id), ["S-2"]);
    assert.doesNotMatch(routeText, /S-1/);
  });
});

test("bounty_route_surfaces reports missing or malformed attack surface without writing routes", () => {
  withTempHome(() => {
    const domain = "example.com";
    assert.throws(
      () => routeSurfaces({ target_domain: domain }),
      /Missing attack surface JSON:/,
    );
    assert.equal(fs.existsSync(surfaceRoutesPath(domain)), false);

    fs.mkdirSync(sessionDir(domain), { recursive: true });
    writeFileAtomic(attackSurfacePath(domain), "{bad json");
    assert.throws(
      () => routeSurfaces({ target_domain: domain }),
      /Malformed attack surface JSON:/,
    );
    assert.equal(fs.existsSync(surfaceRoutesPath(domain)), false);
  });
});

test("bounty_start_wave validates inputs, writes assignments, and updates pending_wave", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1 });
    seedAttackSurface(domain, ["surface-a", "surface-b"]);
    const expectedState = {
      target: domain,
      deep_mode: false,
      phase: "HUNT",
      hunt_wave: 1,
      pending_wave: 2,
      total_findings: 0,
      explored_count: 0,
      terminally_blocked_count: 0,
      dead_ends_count: 0,
      waf_blocked_count: 0,
      lead_surface_ids: [],
      hold_count: 0,
      auth_status: "pending",
      operator_note: null,
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
        {
          agent: "a1",
          surface_id: "surface-a",
          capability_pack: "web",
          capability_pack_version: 1,
          hunter_agent: "hunter-agent",
          brief_profile: "web",
          context_budget: expectedWebContextBudget(),
        },
        {
          agent: "a2",
          surface_id: "surface-b",
          capability_pack: "web",
          capability_pack_version: 1,
          hunter_agent: "hunter-agent",
          brief_profile: "web",
          context_budget: expectedWebContextBudget(),
        },
      ],
      assignments_path: path.join(sessionDir(domain), "wave-2-assignments.json"),
      state: expectedState,
    });
    const assignmentDoc = JSON.parse(fs.readFileSync(path.join(sessionDir(domain), "wave-2-assignments.json"), "utf8"));
    assert.ok(assignmentDoc.assignments.every((assignment) => /^[a-f0-9]{64}$/.test(assignment.handoff_token_sha256)));
    assert.ok(assignmentDoc.assignments.every((assignment) => assignment.capability_pack === "web"));
    assert.ok(assignmentDoc.assignments.every((assignment) => assignment.capability_pack_version === 1));
    assert.ok(assignmentDoc.assignments.every((assignment) => assignment.hunter_agent === "hunter-agent"));
    assert.ok(assignmentDoc.assignments.every((assignment) => assignment.brief_profile === "web"));
    for (const assignment of assignmentDoc.assignments) {
      assert.deepEqual(assignment.context_budget, expectedWebContextBudget());
    }
    assert.doesNotMatch(JSON.stringify(assignmentDoc), new RegExp(result.assignments[0].handoff_token));
    assert.deepEqual(
      JSON.parse(fs.readFileSync(surfaceRoutesPath(domain), "utf8")).routes.map((route) => route.surface_id),
      ["surface-a", "surface-b"],
    );
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

function setStatePendingWave(domain, waveNumber) {
  const stateFilePath = statePath(domain);
  const stateDoc = JSON.parse(fs.readFileSync(stateFilePath, "utf8"));
  stateDoc.pending_wave = waveNumber;
  fs.writeFileSync(stateFilePath, JSON.stringify(stateDoc, null, 2) + "\n");
}

function seedPrereqSnapshot(domain, wave, { auth_handles = [], egress_handles = [] } = {}) {
  const stateFilePath = statePath(domain);
  const stateDoc = JSON.parse(fs.readFileSync(stateFilePath, "utf8"));
  stateDoc.prereq_registry_snapshots = [
    ...((stateDoc.prereq_registry_snapshots || []).filter((s) => s.wave !== wave)),
    { wave, auth_handles, egress_handles },
  ].sort((a, b) => a.wave - b.wave);
  fs.writeFileSync(stateFilePath, JSON.stringify(stateDoc, null, 2) + "\n");
}

function buildTerminallyBlockedEntry(surfaceId, kind, identifierHint, options = {}) {
  return {
    surface_id: surfaceId,
    blocked_at_wave: options.blocked_at_wave || 2,
    blockers: [
      {
        kind,
        ...(identifierHint != null ? { identifier_hint: identifierHint } : {}),
        ...(options.reason ? { reason: options.reason } : {}),
      },
    ],
  };
}

test("compactSessionState exposes terminally_blocked_count and round-trips state.terminally_blocked", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-a", "auth_missing", "attacker", { reason: "no attacker profile registered" }),
        buildTerminallyBlockedEntry("surface-b", "egress_unreachable", null, { reason: "default egress unreachable" }),
      ],
    });
    const summary = JSON.parse(readStateSummary({ target_domain: domain }));
    assert.equal(summary.state.terminally_blocked_count, 2);
    const fullState = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    assert.equal(fullState.terminally_blocked.length, 2);
    assert.equal(fullState.terminally_blocked[0].surface_id, "surface-a");
    assert.equal(fullState.terminally_blocked[0].blockers[0].kind, "auth_missing");
    assert.equal(fullState.terminally_blocked[0].blockers[0].identifier_hint, "attacker");
    assert.equal(fullState.terminally_blocked[1].blockers[0].identifier_hint, undefined);
  });
});

test("compactSessionState reports terminally_blocked_count: 0 when state pre-dates the field (migration safety)", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1 });
    const stateFilePath = statePath(domain);
    const stateDoc = JSON.parse(fs.readFileSync(stateFilePath, "utf8"));
    delete stateDoc.terminally_blocked;
    fs.writeFileSync(stateFilePath, JSON.stringify(stateDoc, null, 2) + "\n");
    const summary = JSON.parse(readStateSummary({ target_domain: domain }));
    assert.equal(summary.state.terminally_blocked_count, 0);
  });
});

test("normalizeSessionStateDocument rejects state with explored / terminally_blocked overlap", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      explored: ["surface-a"],
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-a", "auth_missing", "attacker"),
      ],
    });
    assert.throws(() => readStateSummary({ target_domain: domain }), /must be disjoint/);
  });
});

test("normalizeSessionStateDocument rejects duplicate surface_id in terminally_blocked", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-a", "auth_missing", "attacker"),
        buildTerminallyBlockedEntry("surface-a", "egress_unreachable", null),
      ],
    });
    assert.throws(() => readStateSummary({ target_domain: domain }), /duplicate surface_id surface-a/);
  });
});

test("computeOpenRequeueSurfaceIds excludes terminally_blocked surfaces (options-bag signature)", () => {
  const { computeOpenRequeueSurfaceIds } = require("../mcp/lib/phase-gates.js");
  const records = [
    { surface_id: "surface-a", endpoint: "GET /a", status: "requeue", logged_at: "2026-05-02T00:00:00Z", wave: "w1", agent: "a1" },
    { surface_id: "surface-b", endpoint: "GET /b", status: "requeue", logged_at: "2026-05-02T00:00:00Z", wave: "w1", agent: "a1" },
    { surface_id: "surface-c", endpoint: "GET /c", status: "needs_auth", logged_at: "2026-05-02T00:00:00Z", wave: "w1", agent: "a1" },
  ];
  const result = computeOpenRequeueSurfaceIds(records, {
    exploredSurfaceIds: ["surface-a"],
    terminallyBlockedSurfaceIds: ["surface-c"],
  });
  assert.deepEqual(result, ["surface-b"]);
});

test("HUNT -> CHAIN gate exposes blocked_high_surface_ids and blocks transition on it", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" },
      { id: "surface-b", hosts: [`https://${domain}`], priority: "HIGH" },
      { id: "surface-c", hosts: [`https://${domain}`], priority: "HIGH" },
    ]);
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      explored: ["surface-a"],
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-b", "auth_missing", "attacker", { reason: "no profile" }),
      ],
    });
    const { computeHuntToChainGate } = require("../mcp/lib/phase-gates.js");
    const fullState = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    const gate = computeHuntToChainGate(domain, fullState);
    assert.equal(gate.coverage.non_low_explored, 1);
    assert.equal(gate.coverage.non_low_terminally_blocked, 1);
    assert.equal(gate.coverage.non_low_closed, 2);
    assert.deepEqual(gate.coverage.unexplored_high_surface_ids, ["surface-c"]);
    assert.deepEqual(gate.coverage.blocked_high_surface_ids, ["surface-b"]);
    assert.equal(gate.coverage.coverage_pct, 33);
    assert.equal(gate.coverage.closed_pct, 67);
    // Both unexplored and blocked HIGH surfaces produce distinct blockers.
    const codes = gate.transition_blockers.map((b) => b.code);
    assert.ok(codes.includes("unexplored_high_surfaces"), "expected unexplored_high_surfaces blocker");
    assert.ok(codes.includes("blocked_high_surfaces"), "expected blocked_high_surfaces blocker");
  });
});

test("bounty_start_wave rejects assignment of terminally_blocked surfaces", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurface(domain, ["surface-a", "surface-b"]);
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-a", "auth_missing", "attacker", { reason: "missing" }),
      ],
    });
    assert.throws(() => startWave({
      target_domain: domain,
      wave_number: 2,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
    }), /Cannot assign terminally-blocked surfaces.*surface-a/);
  });
});

test("bounty_apply_wave_merge adds surface_status: complete surfaces to state.explored even when coverage rows are unfinished", () => {
  // The structured handoff is the contract. Coverage rows are advisory
  // history. A hunter that wrote `surface_status: complete` AND has stale
  // unfinished coverage rows for the same wave is internally inconsistent,
  // but the merge layer trusts the handoff — silently downgrading
  // complete to "still requeued" stranded the surface in HUNT forever
  // (the veda.tech regression).
  withTempHome(() => {
    const domain = "trust-handoff.example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      pending_wave: 1,
    });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [{
        endpoint: "/api/legacy",
        method: "GET",
        bug_class: "idor",
        status: "requeue",
        evidence_summary: "endpoint-level requeue logged earlier in the wave",
      }],
    });
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Surface tested; one endpoint marked requeue while triaging others, then closed.",
      content: "# A1",
    });

    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));
    assert.equal(result.status, "merged");
    assert.equal(result.state.explored_count, 1);
    // Verify the surface really landed in state.explored (not just counted).
    const fullState = JSON.parse(readSessionState({ target_domain: domain }));
    assert.deepEqual(fullState.state.explored, ["surface-a"]);
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
      blocked_prereqs: [],
      blocked_prereqs_grouped: [],
      terminally_blocked_promoted: [],
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

test("surface leads are compact, promotable, and wave assignable", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", deep_mode: true });
    seedAttackSurfaces(domain, [
      {
        id: "surface-a",
        hosts: [`https://${domain}`],
        tech_stack: [],
        endpoints: [],
        interesting_params: [],
        nuclei_hits: [],
        priority: "LOW",
      },
    ]);

    const recorded = JSON.parse(recordSurfaceLeads({
      target_domain: domain,
      source: "test",
      leads: [{
        title: "Admin API from JS bundle",
        hosts: [`https://admin.${domain}`],
        endpoints: ["/api/admin/users?account_id=1"],
        interesting_params: ["account_id"],
        tech_stack: ["Next.js"],
        priority: "HIGH",
        surface_type: "admin",
        bug_class_hints: ["idor", "authz"],
        high_value_flows: ["admin", "exports"],
        evidence: ["JS bundle references /api/admin/users?account_id="],
        confidence: "high",
        score: 86,
      }],
    }));
    assert.equal(recorded.recorded, 1);
    assert.ok(fs.existsSync(surfaceLeadsPath(domain)));

    const leads = JSON.parse(readSurfaceLeads({ target_domain: domain, limit: 5 }));
    assert.equal(leads.total, 1);
    assert.equal(leads.high_confidence_unpromoted, 1);
    assert.equal(leads.leads[0].id, "SL-1");

    const promoted = JSON.parse(promoteSurfaceLeads({ target_domain: domain, limit: 3, min_score: 60 }));
    assert.deepEqual(promoted.promoted_surface_ids, ["lead-admin-api-from-js-bundle"]);
    const promotedSurfaceId = promoted.promoted_surface_ids[0];
    const state = JSON.parse(readStateSummary({ target_domain: domain })).state;
    assert.deepEqual(state.lead_surface_ids, [promotedSurfaceId]);

    const attackSurface = JSON.parse(fs.readFileSync(attackSurfacePath(domain), "utf8"));
    assert.ok(attackSurface.surfaces.some((surface) => surface.id === promotedSurfaceId));
    const started = JSON.parse(startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: promotedSurfaceId }],
    }));
    assert.equal(started.assignments[0].surface_id, promotedSurfaceId);
  });
});

test("explicit medium surface lead promotion stays MEDIUM while becoming wave assignable", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", deep_mode: true });
    seedAttackSurfaces(domain, [
      {
        id: "surface-a",
        hosts: [`https://${domain}`],
        tech_stack: [],
        endpoints: [],
        interesting_params: [],
        nuclei_hits: [],
        priority: "LOW",
      },
    ]);

    const recorded = JSON.parse(recordSurfaceLeads({
      target_domain: domain,
      source: "test",
      leads: [{
        title: "Brand-linked sibling properties lightly probed",
        hosts: ["https://brand-example.com"],
        priority: "MEDIUM",
        surface_type: "unknown",
        evidence: ["https://brand-example.com [200] [Cloudflare] Brand login"],
        confidence: "medium",
        score: 55,
        promote: true,
      }],
    }));
    assert.equal(recorded.recorded, 1);

    const promoted = JSON.parse(promoteSurfaceLeads({ target_domain: domain, limit: 3, min_score: 60 }));
    assert.equal(promoted.promoted, 1);
    assert.deepEqual(promoted.promoted_surface_ids, ["lead-brand-linked-sibling-properties-lightly-probed"]);
    const promotedSurfaceId = promoted.promoted_surface_ids[0];

    const state = JSON.parse(readStateSummary({ target_domain: domain })).state;
    assert.deepEqual(state.lead_surface_ids, [promotedSurfaceId]);

    const attackSurface = JSON.parse(fs.readFileSync(attackSurfacePath(domain), "utf8"));
    const promotedSurface = attackSurface.surfaces.find((surface) => surface.id === promotedSurfaceId);
    assert.ok(promotedSurface);
    assert.equal(promotedSurface.priority, "MEDIUM");
    assert.equal(promotedSurface.ranking.score, 55);
  });
});

test("unassignable high-confidence surface leads are not promoted or counted as deep lead debt", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", deep_mode: true });
    seedAttackSurfaces(domain, [
      {
        id: "surface-a",
        hosts: [`https://${domain}`],
        tech_stack: [],
        endpoints: [],
        interesting_params: [],
        nuclei_hits: [],
        priority: "LOW",
      },
    ]);

    const recorded = JSON.parse(recordSurfaceLeads({
      target_domain: domain,
      source: "test",
      leads: [{
        title: "Vague external research note",
        evidence: ["High confidence prose without an assignable host or endpoint."],
        confidence: "high",
        score: 95,
        promote: true,
      }],
    }));
    assert.equal(recorded.recorded, 1);

    const leads = JSON.parse(readSurfaceLeads({ target_domain: domain, limit: 5 }));
    assert.equal(leads.total, 1);
    assert.equal(leads.high_confidence_unpromoted, 0);

    const promoted = JSON.parse(promoteSurfaceLeads({ target_domain: domain, limit: 3, min_score: 60 }));
    assert.deepEqual(promoted.promoted_surface_ids, []);
    assert.equal(promoted.promoted, 0);

    const attackSurface = JSON.parse(fs.readFileSync(attackSurfacePath(domain), "utf8"));
    assert.deepEqual(attackSurface.surfaces.map((surface) => surface.id), ["surface-a"]);

    const status = JSON.parse(waveStatus({ target_domain: domain }));
    assert.deepEqual(status.surface_leads, {
      total: 1,
      high_confidence_unpromoted: 0,
      promoted: 0,
    });
    assert.deepEqual(status.transition_blockers, []);
  });
});

test("bounty_write_wave_handoff persists hunter surface_leads through the session lock", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    const release = acquireSessionLock(domain);
    try {
      assert.throws(
        () => writeWaveHandoff({
          target_domain: domain,
          wave: "w1",
          agent: "a1",
          surface_id: "surface-a",
          surface_status: "complete",
          summary: "a1 complete",
          content: "# a1",
          surface_leads: [{
            title: "Locked lead should not be written",
            hosts: [`https://locked.${domain}`],
            confidence: "high",
            score: 80,
          }],
        }),
        /Session lock busy/,
      );
    } finally {
      release();
    }
    assert.ok(!fs.existsSync(path.join(sessionDir(domain), "handoff-w1-a1.json")));
    assert.equal(fs.existsSync(surfaceLeadsPath(domain)), false);

    const first = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "a1 complete",
      content: "# a1",
      surface_leads: [{
        title: "Admin API from a1",
        hosts: [`https://admin.${domain}`],
        endpoints: ["/api/admin/users"],
        confidence: "high",
        score: 82,
      }],
    }));
    const second = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      surface_status: "complete",
      summary: "a2 complete",
      content: "# a2",
      surface_leads: [{
        title: "Billing API from a2",
        hosts: [`https://billing.${domain}`],
        endpoints: ["/api/billing/invoices"],
        confidence: "high",
        score: 81,
      }],
    }));

    assert.deepEqual(first.surface_lead_ids, ["SL-1"]);
    assert.deepEqual(second.surface_lead_ids, ["SL-2"]);

    const leads = JSON.parse(readSurfaceLeads({ target_domain: domain, limit: 10 }));
    assert.equal(leads.total, 2);
    assert.deepEqual(
      leads.leads.map((lead) => lead.title).sort(),
      ["Admin API from a1", "Billing API from a2"],
    );
    assert.deepEqual(
      JSON.parse(fs.readFileSync(path.join(sessionDir(domain), "handoff-w1-a1.json"), "utf8")).surface_lead_ids,
      ["SL-1"],
    );
    assert.deepEqual(
      JSON.parse(fs.readFileSync(path.join(sessionDir(domain), "handoff-w1-a2.json"), "utf8")).surface_lead_ids,
      ["SL-2"],
    );
  });
});

test("deep wave merge promotes high-confidence handoff surface leads into lead_surface_ids", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1, deep_mode: true });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Found sibling GraphQL lead.",
      content: "# A1",
      surface_leads: [{
        title: "Sibling GraphQL API",
        hosts: [`https://api.${domain}`],
        endpoints: ["/graphql"],
        priority: "HIGH",
        surface_type: "graphql",
        bug_class_hints: ["graphql", "authz"],
        evidence: ["Assigned surface links to api.example.com/graphql"],
        confidence: "high",
        score: 78,
      }],
    });

    const merged = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));
    assert.deepEqual(merged.merge.deep_promoted_surface_ids, ["lead-sibling-graphql-api"]);
    assert.deepEqual(merged.state.lead_surface_ids, ["lead-sibling-graphql-api"]);
    const leads = JSON.parse(readSurfaceLeads({ target_domain: domain, limit: 5 }));
    assert.equal(leads.high_confidence_unpromoted, 0);
    assert.equal(leads.leads[0].status, "promoted");
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
    // Coverage-derived requeue is the next-wave assignment hint: a, d, e
    // each have at least one promising/needs_auth/requeue endpoint row, so
    // the orchestrator may re-queue them for a fresh look.
    assert.deepEqual(result.merge.requeue_surface_ids, ["surface-a", "surface-d", "surface-e"]);

    // state.explored is "surfaces with a complete handoff this run." All
    // five hunters declared complete, so all five are explored. Re-queueing
    // a surface in a later wave is independent — the orchestrator can
    // assign an explored surface to a fresh hunter without contradiction.
    const fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    assert.deepEqual(fullState.explored, ["surface-a", "surface-b", "surface-c", "surface-d", "surface-e"]);
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
      force_merge_reason: "a1 handoff is malformed and a2 handoff is missing after agent termination; merge is safe because both surfaces are requeued.",
    }));

    assert.equal(result.status, "merged");
    assert.equal(result.force_merge, true);
    assert.match(result.force_merge_reason, /a1 handoff is malformed/);
    assert.deepEqual(result.merge.invalid_agents, ["a1"]);
    assert.deepEqual(result.merge.missing_surface_ids, ["surface-b"]);
    assert.deepEqual(result.merge.partial_surface_ids, ["surface-c"]);
    assert.deepEqual(result.merge.requeue_surface_ids, ["surface-c", "surface-b", "surface-a"]);
    assert.equal(result.state.pending_wave, null);
    assert.equal(result.state.hunt_wave, 2);

    const rows = readJsonl(pipelineEventsJsonlPath(domain));
    const mergeEvent = rows.find((row) => row.type === "wave_merged" && row.wave_number === 2);
    assert.equal(mergeEvent.force_merge, true);
    assert.match(mergeEvent.force_merge_reason, /a2 handoff is missing/);

    const normalizedEvent = readPipelineEvents(domain).events
      .find((row) => row.type === "wave_merged" && row.wave_number === 2);
    assert.equal(normalizedEvent.force_merge, true);
    assert.match(normalizedEvent.force_merge_reason, /merge is safe/);
  });
});

test("bounty_apply_wave_merge requires a force_merge_reason for forced reconciliation", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1 });
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
    ]);
    seedAttackSurface(domain, ["surface-a"]);

    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: true }),
      /force_merge_reason is required/,
    );
    assert.throws(
      () => applyWaveMerge({
        target_domain: domain,
        wave_number: 1,
        force_merge: false,
        force_merge_reason: "not used for normal pending checks",
      }),
      /force_merge_reason is only allowed/,
    );
  });
});

test("bounty_apply_wave_merge promotes recurring blocked_prereqs to state.terminally_blocked when registry is unchanged", () => {
  withTempHome(() => {
    const domain = "promote.example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-auth", hosts: [`https://${domain}/auth`], priority: "HIGH" },
    ]);
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1, hunt_wave: 0 });
    seedPrereqSnapshot(domain, 1, { auth_handles: [], egress_handles: [] });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "auth profile not registered; cannot test org-scoped IDOR",
      content: "# A1",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "no attacker profile registered" },
      ],
    });
    JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }));
    let fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    assert.equal(fullState.terminally_blocked.length, 0);
    assert.equal(fullState.blocked_prereq_history.length, 1);

    setStatePendingWave(domain, 2);
    seedPrereqSnapshot(domain, 2, { auth_handles: [], egress_handles: [] });
    seedAssignments(domain, 2, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "still no attacker profile registered after wave 1; same blocker",
      content: "# A1 wave 2",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "no attacker profile registered" },
      ],
    });
    const result = JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 2, force_merge: false }));
    assert.equal(result.merge.terminally_blocked_promoted.length, 1);
    assert.equal(result.merge.terminally_blocked_promoted[0].surface_id, "surface-auth");
    assert.equal(result.merge.terminally_blocked_promoted[0].blockers[0].kind, "auth_missing");
    assert.equal(result.merge.terminally_blocked_promoted[0].blockers[0].identifier_hint, "attacker");

    fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    assert.equal(fullState.terminally_blocked.length, 1);
    assert.equal(fullState.terminally_blocked[0].surface_id, "surface-auth");
    assert.equal(fullState.terminally_blocked[0].blocked_at_wave, 2);
    assert.equal(fullState.blocked_prereq_history.length, 2);
    assert.ok(!result.merge.requeue_surface_ids.includes("surface-auth"));
  });
});

test("bounty_apply_wave_merge does NOT promote auth_missing when the named handle was added between waves", () => {
  withTempHome(() => {
    const domain = "registry-grew.example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-auth", hosts: [`https://${domain}/auth`], priority: "HIGH" },
    ]);
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1, hunt_wave: 0 });
    seedPrereqSnapshot(domain, 1, { auth_handles: [], egress_handles: [] });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "auth profile not registered; cannot test org-scoped IDOR",
      content: "# A1",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "no attacker profile registered" },
      ],
    });
    JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }));

    setStatePendingWave(domain, 2);
    // Operator added the SPECIFIC handle the blocker named ("attacker") between waves.
    seedPrereqSnapshot(domain, 2, { auth_handles: ["attacker"], egress_handles: [] });
    seedAssignments(domain, 2, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "marker repeated even though attacker profile was added between waves",
      content: "# A1 wave 2",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "marker repeated" },
      ],
    });
    const result = JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 2, force_merge: false }));
    assert.equal(result.merge.terminally_blocked_promoted.length, 0);
    const fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    assert.equal(fullState.terminally_blocked.length, 0);
  });
});

test("bounty_apply_wave_merge DOES promote auth_missing when an unrelated handle was added (closes count-based amnesty bug)", () => {
  withTempHome(() => {
    const domain = "unrelated-handle.example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-auth", hosts: [`https://${domain}/auth`], priority: "HIGH" },
    ]);
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1, hunt_wave: 0 });
    seedPrereqSnapshot(domain, 1, { auth_handles: [], egress_handles: [] });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "needs attacker profile to test org-scoped IDOR",
      content: "# A1",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "attacker profile required" },
      ],
    });
    JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }));

    setStatePendingWave(domain, 2);
    // Operator added "victim" — UNRELATED to the "attacker" blocker.
    // The previous count-based delta would have given amnesty (count grew
    // 0 -> 1) and silently skipped promotion. The handle-set check refuses.
    seedPrereqSnapshot(domain, 2, { auth_handles: ["victim"], egress_handles: [] });
    seedAssignments(domain, 2, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "attacker still missing in wave 2",
      content: "# A1 wave 2",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "attacker still missing" },
      ],
    });
    const result = JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 2, force_merge: false }));
    assert.equal(result.merge.terminally_blocked_promoted.length, 1);
    assert.equal(result.merge.terminally_blocked_promoted[0].blockers[0].identifier_hint, "attacker");
  });
});

test("bounty_apply_wave_merge promotes funded_wallet_missing on 2-wave recurrence (no registry-delta path)", () => {
  withTempHome(() => {
    const domain = "wallet-blocked.example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-siwe", hosts: [`https://${domain}/siwe`], priority: "HIGH" },
    ]);
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1, hunt_wave: 0 });
    seedPrereqSnapshot(domain, 1, { auth_handles: [], egress_handles: [] });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-siwe" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-siwe",
      surface_status: "partial",
      summary: "SIWE flow reaches verified-address balance gate; no funded wallet",
      content: "# A1",
      blocked_prereqs: [
        { kind: "funded_wallet_missing", identifier_hint: "sepolia.funded", reason: "balance gate requires funded wallet" },
      ],
    });
    JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }));

    setStatePendingWave(domain, 2);
    seedPrereqSnapshot(domain, 2, { auth_handles: [], egress_handles: [] });
    seedAssignments(domain, 2, [{ agent: "a1", surface_id: "surface-siwe" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a1",
      surface_id: "surface-siwe",
      surface_status: "partial",
      summary: "second wave still lacks the funded wallet so the gate cannot be probed",
      content: "# A1 wave 2",
      blocked_prereqs: [
        { kind: "funded_wallet_missing", identifier_hint: "sepolia.funded", reason: "still no funded wallet" },
      ],
    });
    const result = JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 2, force_merge: false }));
    assert.equal(result.merge.terminally_blocked_promoted.length, 1);
    assert.equal(result.merge.terminally_blocked_promoted[0].blockers[0].kind, "funded_wallet_missing");
  });
});

test("bounty_clear_terminal_block removes a surface from terminally_blocked and records the clear in state", () => {
  withTempHome(() => {
    const domain = "clear-block.example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 2,
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-auth", "auth_missing", "attacker", { reason: "no profile registered", blocked_at_wave: 2 }),
      ],
      blocked_prereq_history: [
        { wave: 1, surface_id: "surface-auth", kind: "auth_missing", identifier_hint: "attacker", reason: "no profile" },
        { wave: 2, surface_id: "surface-auth", kind: "auth_missing", identifier_hint: "attacker", reason: "still no profile" },
        { wave: 1, surface_id: "surface-other", kind: "egress_unreachable", identifier_hint: "us-west", reason: "default egress unreachable" },
      ],
    });

    const result = JSON.parse(clearTerminalBlock({
      target_domain: domain,
      surface_id: "surface-auth",
      reason: "operator added attacker auth profile via auth_store",
    }));
    assert.equal(result.cleared, true);
    assert.equal(result.surface_id, "surface-auth");
    assert.equal(result.cleared_at_wave, 2);
    assert.equal(result.previously_blocked_at_wave, 2);
    assert.equal(result.previous_blockers[0].kind, "auth_missing");
    assert.equal(result.state.terminally_blocked_count, 0);

    const fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    assert.equal(fullState.terminally_blocked.length, 0);
    // History is RETAINED for debugging; loop detector uses clear epoch.
    assert.equal(fullState.blocked_prereq_history.length, 3);
    // Clear is recorded durably in state, not just in pipeline event.
    assert.equal(fullState.terminal_block_clear_history.length, 1);
    assert.equal(fullState.terminal_block_clear_history[0].surface_id, "surface-auth");
    assert.equal(fullState.terminal_block_clear_history[0].cleared_at_wave, 2);
    assert.match(fullState.terminal_block_clear_history[0].reason, /attacker auth profile/);
    assert.equal(fullState.terminal_block_clear_history[0].previous_blockers[0].kind, "auth_missing");
  });
});

test("bounty_clear_terminal_block rejects clearing while a wave is pending", () => {
  withTempHome(() => {
    const domain = "pending-clear.example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      pending_wave: 2,
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-a", "auth_missing", "attacker", { reason: "no profile" }),
      ],
    });
    assert.throws(() => clearTerminalBlock({
      target_domain: domain,
      surface_id: "surface-a",
      reason: "operator wants to clear during a pending wave",
    }), /Cannot clear a terminal block while wave 2 is pending/);
  });
});

test("bounty_clear_terminal_block rejects clearing a surface that was never terminally blocked", () => {
  withTempHome(() => {
    const domain = "never-blocked.example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      terminally_blocked: [],
    });
    assert.throws(() => clearTerminalBlock({
      target_domain: domain,
      surface_id: "surface-z",
      reason: "operator wants to clear a non-blocked surface",
    }), /not in state\.terminally_blocked/);
  });
});

test("bounty_clear_terminal_block rejects a reason that contains credentials", () => {
  withTempHome(() => {
    const domain = "secret-reason.example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-a", "auth_missing", "attacker", { reason: "no profile" }),
      ],
    });
    assert.throws(() => clearTerminalBlock({
      target_domain: domain,
      surface_id: "surface-a",
      reason: "Authorization: Bearer eyJabcdefghij.eyJklmnopqr.sigabcdefghij was added",
    }), /appears to contain secrets/);
  });
});

test("bounty_clear_terminal_block requires a reason of at least 20 characters", () => {
  withTempHome(() => {
    const domain = "short-reason.example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-a", "auth_missing", "attacker", { reason: "no profile" }),
      ],
    });
    assert.throws(() => clearTerminalBlock({
      target_domain: domain,
      surface_id: "surface-a",
      reason: "too short",
    }), /reason is required and must be at least 20 characters/);
  });
});

test("bounty_apply_wave_merge emits a surface_terminally_blocked event per (surface, blocker) pair on promotion", () => {
  withTempHome(() => {
    const domain = "promote-event.example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-auth", hosts: [`https://${domain}/auth`], priority: "HIGH" },
    ]);
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1, hunt_wave: 0 });
    seedPrereqSnapshot(domain, 1, { auth_handles: [], egress_handles: [] });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "missing attacker profile",
      content: "# A1",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "no profile" },
      ],
    });
    JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }));

    setStatePendingWave(domain, 2);
    seedPrereqSnapshot(domain, 2, { auth_handles: [], egress_handles: [] });
    seedAssignments(domain, 2, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "still missing attacker profile",
      content: "# A1 wave 2",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "still none" },
      ],
    });
    JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 2, force_merge: false }));

    const eventsResult = readPipelineEvents(domain);
    const events = eventsResult.events.filter((e) => e.type === "surface_terminally_blocked");
    assert.equal(events.length, 1);
    assert.equal(events[0].surface_id, "surface-auth");
    assert.equal(events[0].kind, "auth_missing");
    assert.equal(events[0].identifier_hint, "attacker");
    assert.equal(events[0].wave_number, 2);
  });
});

test("bounty_report_written emits report_written when report.md is present", () => {
  withTempHome(() => {
    const domain = "report-event.example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    seedSessionState(domain, { phase: "REPORT", hunt_wave: 1 });
    fs.writeFileSync(path.join(dir, "report.md"), "# Report\n\nNo findings.\n");

    const result = JSON.parse(reportWritten({ target_domain: domain }));
    assert.equal(result.report_written, true);
    assert.ok(result.size_bytes > 0);

    const eventsResult = readPipelineEvents(domain);
    const events = eventsResult.events.filter((e) => e.type === "report_written");
    assert.equal(events.length, 1);
    assert.ok(events[0].counts.report_size_bytes > 0);
  });
});

test("bounty_report_written rejects when report.md is absent", () => {
  withTempHome(() => {
    const domain = "no-report.example.com";
    seedSessionState(domain, { phase: "REPORT", hunt_wave: 1 });
    assert.throws(() => reportWritten({ target_domain: domain }), /report\.md is not present/);
  });
});

test("low_coverage analytics fires on closed_pct (not coverage_pct) so terminally_blocked surfaces count as closed", () => {
  withTempHome(() => {
    const domain = "low-cov.example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}/a`], priority: "HIGH" },
      { id: "surface-b", hosts: [`https://${domain}/b`], priority: "HIGH" },
    ]);
    seedSessionState(domain, {
      phase: "CHAIN",
      hunt_wave: 1,
      explored: ["surface-a"],
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-b", "auth_missing", "attacker", { reason: "no profile", blocked_at_wave: 1 }),
      ],
    });

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain }));
    const lowCoverage = analytics.bottlenecks.find((b) => b.code === "low_coverage");
    // 1 explored + 1 terminally_blocked out of 2 non-low surfaces = 100% closed.
    // Old (count-based) coverage_pct would be 50% (only explored). New
    // closed_pct is 100%, so low_coverage does NOT fire.
    assert.equal(lowCoverage, undefined, "low_coverage should not fire when all non-low surfaces are explored or terminally_blocked");
  });
});

test("bounty_clear_terminal_block lets a re-blocked surface start fresh recurrence count via clear epoch", () => {
  withTempHome(() => {
    const domain = "reblock.example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-auth", hosts: [`https://${domain}/auth`], priority: "HIGH" },
    ]);
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 2,
      pending_wave: null,
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-auth", "auth_missing", "attacker", { blocked_at_wave: 2, reason: "no profile" }),
      ],
      blocked_prereq_history: [
        { wave: 1, surface_id: "surface-auth", kind: "auth_missing", identifier_hint: "attacker", reason: "no profile" },
        { wave: 2, surface_id: "surface-auth", kind: "auth_missing", identifier_hint: "attacker", reason: "still none" },
      ],
    });

    JSON.parse(clearTerminalBlock({
      target_domain: domain,
      surface_id: "surface-auth",
      reason: "operator registered attacker profile and is unblocking",
    }));

    // Wave 3 still hits the same blocker (e.g., the new profile didn't help).
    setStatePendingWave(domain, 3);
    seedPrereqSnapshot(domain, 3, { auth_handles: ["attacker"], egress_handles: [] });
    seedAssignments(domain, 3, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w3",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "still blocked even after profile added",
      content: "# A1 wave 3",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "blocker reappeared" },
      ],
    });
    const result = JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 3, force_merge: false }));
    // After the clear, history is RETAINED but the loop detector ignores
    // entries from waves <= cleared_at_wave (which was 2). Wave 3's
    // blocker has no qualifying prior, so no promotion. History is still
    // available for debugging.
    assert.equal(result.merge.terminally_blocked_promoted.length, 0);
    const fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    assert.ok(fullState.blocked_prereq_history.length >= 2, "history should be retained, not pruned");
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
      blocked_prereqs: [],
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

test("bounty_write_wave_handoff accepts surface_status: partial with blocked_prereqs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const result = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Blocked by missing auth profiles.",
      content: "# Handoff\n",
      blocked_prereqs: [
        {
          kind: "auth_missing",
          identifier_hint: "attacker",
          reason: "Org-scoped IDOR test requires attacker session; bounty_list_auth_profiles returned []",
          needed_for: "cross-org dashboard authz check",
        },
        {
          kind: "egress_unreachable",
          identifier_hint: "us-west-egress",
          reason: "thegraph.kiln.fi returned ECONNREFUSED across 5 attempts on default egress",
          evidence_summary: "circuit-breaker reports 5 failures past threshold for thegraph.kiln.fi",
        },
      ],
    }));
    const payload = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.equal(payload.surface_status, "partial");
    assert.equal(payload.blocked_prereqs.length, 2);
    assert.equal(payload.blocked_prereqs[0].kind, "auth_missing");
    assert.equal(payload.blocked_prereqs[0].identifier_hint, "attacker");
    assert.equal(payload.blocked_prereqs[0].needed_for, "cross-org dashboard authz check");
    assert.equal(payload.blocked_prereqs[1].kind, "egress_unreachable");
    assert.equal(payload.blocked_prereqs[1].identifier_hint, "us-west-egress");
    assert.match(payload.blocked_prereqs[1].evidence_summary, /circuit-breaker/);
  });
});

test("bounty_write_wave_handoff rejects surface_status: complete with blocked_prereqs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Pretending to be done despite missing material.",
      content: "# Handoff\n",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "no profile loaded" },
      ],
    }), /surface_status cannot be 'complete' when blocked_prereqs is non-empty/);
  });
});

test("bounty_write_wave_handoff rejects blocked_prereqs with unknown kind", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Trying a kind that does not exist in the registry.",
      content: "# Handoff\n",
      blocked_prereqs: [
        { kind: "captcha_missing", identifier_hint: "captcha", reason: "captcha solver not configured" },
      ],
    }), /blocked_prereqs\[0\]\.kind must be one of/);
  });
});

test("bounty_write_wave_handoff rejects blocked_prereqs identifier_hint that looks like a secret", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    // Mixed-case JWT shape rejected by the format regex.
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Operator pasted a credential into identifier_hint by accident.",
      content: "# Handoff\n",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0", reason: "JWT token leaked into hint" },
      ],
    }), /identifier_hint must match/);
    // Lowercase JWT shape passes the format regex but the sensitive-material
    // validator catches the dotted JWT structure.
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Operator pasted a lowercase JWT into identifier_hint.",
      content: "# Handoff\n",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "eyjabcdefghij.eyjklmnopqr.sigabcdefghij", reason: "lowercase JWT" },
      ],
    }), /appears to contain secrets/);
    // 64-char lowercase hex (private key / SHA-256 shape) rejected by the
    // long-hex screen even though the format regex accepts it.
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Operator pasted a hex hash into identifier_hint.",
      content: "# Handoff\n",
      blocked_prereqs: [
        { kind: "key_material_missing", identifier_hint: "a".repeat(64), reason: "hex hash leaked" },
      ],
    }), /looks like a hex private key, address, or hash/);
    // 65-char lowercase still rejected because of maxLength.
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Operator pasted a long lowercase token into identifier_hint.",
      content: "# Handoff\n",
      blocked_prereqs: [
        { kind: "key_material_missing", identifier_hint: "a".repeat(65), reason: "long lowercase token" },
      ],
    }), /identifier_hint must be at most 64 characters/);
    // Leading hyphen / non-alphanumeric start rejected.
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Operator used leading hyphen.",
      content: "# Handoff\n",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "-attacker", reason: "leading hyphen" },
      ],
    }), /identifier_hint must match/);
  });
});

test("bounty_write_wave_handoff accepts blocked_prereqs without identifier_hint", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const result = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Egress unreachable; no specific egress profile would obviously help.",
      content: "# Handoff\n",
      blocked_prereqs: [
        {
          kind: "egress_unreachable",
          reason: "thegraph.kiln.fi unreachable across 5 attempts on default egress",
        },
      ],
    }));
    const payload = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.equal(payload.blocked_prereqs.length, 1);
    assert.equal(payload.blocked_prereqs[0].kind, "egress_unreachable");
    assert.equal(payload.blocked_prereqs[0].identifier_hint, undefined);
  });
});

test("bounty_write_wave_handoff rejects blocked_prereqs reason with embedded secrets", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Reason field contains a leaked credential.",
      content: "# Handoff\n",
      blocked_prereqs: [
        {
          kind: "auth_missing",
          reason: "Tried Authorization: Bearer eyJabcdefghij.eyJklmnopqr.sigabcdefghij from previous run",
        },
      ],
    }), /appears to contain secrets/);
  });
});

test("bounty_write_wave_handoff rejects blocked_prereqs reason past 240 chars", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Reason is too long.",
      content: "# Handoff\n",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "x".repeat(241) },
      ],
    }), /blocked_prereqs\[0\]\.reason must be at most 240 characters/);
  });
});

test("bounty_write_wave_handoff rejects more than 20 blocked_prereqs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const overflow = Array.from({ length: 21 }, (_, i) => ({
      kind: "auth_missing",
      identifier_hint: `attacker${i}`,
      reason: `entry ${i}`,
    }));
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Too many blocked_prereqs entries.",
      content: "# Handoff\n",
      blocked_prereqs: overflow,
    }), /blocked_prereqs must contain at most 20 entries/);
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

test("bounty_finalize_hunter_run blocks unreadable wave assignments and records telemetry", async () => {
  await withTempHome(async () => {
    const domain = "unreadable-assignments.example";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });

    const missing = await executeTool("bounty_finalize_hunter_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(missing.ok, false);
    assert.equal(missing.error.code, "STATE_CONFLICT");
    assert.equal(missing.error.details.block_code, "unreadable_wave_assignments");
    assert.match(missing.error.message, /could not read wave assignments/);

    writeFileAtomic(path.join(sessionDir(domain), "wave-1-assignments.json"), "{bad json");
    const malformed = await executeTool("bounty_finalize_hunter_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(malformed.ok, false);
    assert.equal(malformed.error.code, "STATE_CONFLICT");
    assert.equal(malformed.error.details.block_code, "unreadable_wave_assignments");

    const rows = readJsonl(agentRunTelemetryPath());
    assert.deepEqual(rows.map((row) => row.status), ["blocked", "blocked"]);
    assert.deepEqual(rows.map((row) => row.block_code), [
      "unreadable_wave_assignments",
      "unreadable_wave_assignments",
    ]);
    assert.ok(rows.every((row) => row.telemetry_source === "bounty_finalize_hunter_run"));

    const pipelineRows = readJsonl(pipelineEventsJsonlPath(domain));
    assert.deepEqual(
      pipelineRows.filter((row) => row.type === "hunter_stopped").map((row) => row.block_code),
      ["unreadable_wave_assignments", "unreadable_wave_assignments"],
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
    seedTechniqueAttempt(domain);

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

test("bounty_finalize_hunter_run enforces web technique attempt requirement", async () => {
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
      content: "# a1",
    });

    const blocked = await executeTool("bounty_finalize_hunter_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(blocked.ok, false);
    assert.equal(blocked.error.code, "STATE_CONFLICT");
    assert.equal(blocked.error.details.block_code, "missing_technique_attempt_log");
    assert.match(blocked.error.message, /bounty_log_technique_attempt/);

    seedTechniqueAttempt(domain, {
      status: "selected",
      evidence: "Selected a candidate technique pack but did not execute it yet.",
    });
    const selectedOnly = await executeTool("bounty_finalize_hunter_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(selectedOnly.ok, false);
    assert.equal(selectedOnly.error.code, "STATE_CONFLICT");
    assert.equal(selectedOnly.error.details.block_code, "missing_technique_attempt_log");
    assert.match(selectedOnly.error.message, /real attempt outcome/);

    seedTechniqueAttempt(domain);
    const allowed = await executeTool("bounty_finalize_hunter_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(allowed.ok, true);
    assert.equal(allowed.data.status, "allowed");

    const rows = readJsonl(agentRunTelemetryPath());
    assert.deepEqual(rows.map((row) => row.status), ["blocked", "blocked", "allowed"]);
    assert.deepEqual(rows.map((row) => row.block_code), ["missing_technique_attempt_log", "missing_technique_attempt_log", null]);
  });
});

test("bounty_finalize_hunter_run allows smart-contract handoff without technique attempts", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-evm-1",
      surface_type: "smart_contract",
      chain_family: "evm",
      chain_id: "1",
      hosts: [`https://${domain}`],
      foundry_harness_path: "/tmp/harness/evm",
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-evm-1" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.run_context.capability_pack, "smart_contract_evm");
    assert.deepEqual(brief.run_context.context_budget, expectedSmartContractContextBudget());

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-evm-1",
      surface_status: "complete",
      summary: "EVM surface complete.",
      content: "# evm",
      bypass_attempts: [{
        condition: "oracle_staleness",
        attempt_summary: "Ran a forked oracle staleness harness and confirmed no exploitable stale-price path.",
        outcome: "no_finding",
      }],
    });

    const direct = JSON.parse(finalizeHunterRun({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-evm-1",
    }));
    assert.equal(direct.status, "allowed");
    assert.equal(readTechniqueAttemptRecordsFromJsonl(domain).length, 0);
  });
});

test("executeTool smoke path uses envelopes for init, wave, handoff, attempt, and merge", async () => {
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

    const attempt = await executeTool("bounty_log_technique_attempt", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      status: "attempted",
      evidence: "Smoke test recorded a bounded web technique attempt before finalization.",
    });
    assert.equal(attempt.ok, true);

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

test("hunter SubagentStop hook allows post-report evidence markers without wave handoffs", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "REPORT", hunt_wave: 2 });

    const result = runHunterSubagentStop({
      last_assistant_message: 'Catalog complete. BOB_HUNTER_DONE {"target_domain":"example.com","mode":"evidence","surface_id":"F-1","summary":"cataloged exposed records"}',
    }, { home: tempHome });

    assert.equal(result.status, 0);
    assert.match(result.stdout, /post-report evidence run accepted/);

    const rows = readJsonl(agentRunTelemetryPath());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].run_type, "evidence");
    assert.equal(rows[0].status, "allowed");
    assert.equal(rows[0].target_domain, domain);
    assert.equal(rows[0].wave, null);
    assert.equal(rows[0].agent, null);
    assert.equal(rows[0].surface_id, "F-1");
    assert.equal(rows[0].handoff.present, false);
    assert.equal(rows[0].handoff.valid, true);
    assert.equal(rows[0].handoff.provenance, "post_report_evidence");
    assert.equal(rows[0].handoff.surface_status, "evidence");
    assert.equal(rows[0].telemetry_source, "hunter-evidence-stop");

    const pipelineRows = readJsonl(pipelineEventsJsonlPath(domain));
    const stopped = pipelineRows.find((row) => row.type === "hunter_stopped");
    assert.ok(stopped);
    assert.equal(stopped.status, "allowed");
    assert.equal(stopped.source, "hunter-evidence-stop");
    assert.equal(Object.prototype.hasOwnProperty.call(stopped, "wave_number"), false);
    assert.equal(stopped.surface_id, "F-1");
  });
});

test("hunter SubagentStop hook blocks evidence markers before REPORT or EXPLORE", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1 });

    const result = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","mode":"evidence","surface_id":"F-1","summary":"too early"}',
    }, { home: tempHome });

    assert.equal(result.status, 2);
    assert.match(result.stderr, /REPORT or EXPLORE/);

    const rows = readJsonl(agentRunTelemetryPath());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].run_type, "evidence");
    assert.equal(rows[0].status, "blocked");
    assert.equal(rows[0].block_code, "evidence_phase_mismatch");
    assert.equal(rows[0].target_domain, domain);
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
    seedTechniqueAttempt(domain);

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
    seedTechniqueAttempt(domain);

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
    seedTechniqueAttempt(domain);
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
    seedTechniqueAttempt(domain);

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
    seedTechniqueAttempt(domain);
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
      blocked_prereqs: [],
      blocked_prereqs_grouped: [],
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
      blocked_prereqs: [],
      blocked_prereqs_grouped: [],
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
      blocked_prereqs: [],
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
          capability_pack: "web",
          hunter_agent: "hunter-agent",
          brief_profile: "web",
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
          capability_pack: "web",
          hunter_agent: "hunter-agent",
          brief_profile: "web",
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

test("bounty_record_finding persists capability_pack metadata from the assignment", () => {
  // Web hunter: the assignment carries the web pack triple and recordFinding
  // must persist all three fields verbatim into findings.jsonl.
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-web", hosts: [`https://${domain}`], surface_type: "api" },
    ]);
    seedAssignments(domain, 1, [{
      agent: "a1",
      surface_id: "surface-web",
      capability_pack: "web",
      hunter_agent: "hunter-agent",
      brief_profile: "web",
    }]);
    JSON.parse(recordFinding({
      target_domain: domain,
      title: "IDOR on account export",
      severity: "high",
      cwe: "CWE-639",
      endpoint: "/api/export",
      description: "Cross-account export.",
      proof_of_concept: "curl ...",
      response_evidence: "{}",
      impact: "PII.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-web",
    }));
    const finding = JSON.parse(readFindings({ target_domain: domain })).findings[0];
    assert.equal(finding.capability_pack, "web");
    assert.equal(finding.hunter_agent, "hunter-agent");
    assert.equal(finding.brief_profile, "web");
    assert.equal(finding.surface_type, "web");
  });
});

test("bounty_record_finding persists smart_contract_evm pack metadata for an EVM hunter wave", () => {
  // SC hunter: the routed pack is smart_contract_evm. Persisting it on the
  // finding lets verifier/grader/reporter dispatch on the routed decision
  // rather than re-deriving from sc_evidence.chain_family.
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-evm", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" },
    ]);
    seedAssignments(domain, 1, [{
      agent: "a1",
      surface_id: "surface-evm",
      capability_pack: "smart_contract_evm",
      hunter_agent: "hunter-evm-agent",
      brief_profile: "smart_contract_evm",
    }]);
    JSON.parse(recordFinding({
      target_domain: domain,
      title: "Reentrancy in Vault.borrow",
      severity: "high",
      cwe: "CWE-841",
      endpoint: "0x" + "11".repeat(20) + ":borrow(uint256)",
      description: "Reentrancy via callback before balance update.",
      proof_of_concept: "See harness test",
      response_evidence: "Drained 1000 ETH",
      impact: "Loss of vault funds.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-evm",
      sc_evidence: {
        chain_family: "evm",
        chain_id: 1,
        contract_address: "0x" + "11".repeat(20),
        harness_path: os.homedir(),
        match_test: "test_borrow_reentrancy",
      },
    }));
    const finding = JSON.parse(readFindings({ target_domain: domain })).findings[0];
    assert.equal(finding.capability_pack, "smart_contract_evm");
    assert.equal(finding.hunter_agent, "hunter-evm-agent");
    assert.equal(finding.brief_profile, "smart_contract_evm");
    assert.equal(finding.surface_type, "smart_contract");
  });
});

test("bounty_record_finding persists smart_contract_substrate pack metadata for a Substrate hunter wave", () => {
  // Sanity that non-EVM SC packs round-trip too.
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-sub", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "substrate" },
    ]);
    seedAssignments(domain, 1, [{
      agent: "a1",
      surface_id: "surface-sub",
      capability_pack: "smart_contract_substrate",
      hunter_agent: "hunter-substrate-agent",
      brief_profile: "smart_contract_substrate",
    }]);
    JSON.parse(recordFinding({
      target_domain: domain,
      title: "Selector collision in ink contract",
      severity: "medium",
      cwe: "CWE-840",
      endpoint: "5GrwvaEF...:transfer(u128)",
      description: "Two messages share the same 4-byte selector.",
      proof_of_concept: "See cargo test",
      response_evidence: "wrong message dispatched",
      impact: "Incorrect call routing.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-sub",
      sc_evidence: {
        chain_family: "substrate",
        chain_id: "polkadot",
        contract_address: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        harness_path: os.homedir(),
        match_test: "test_selector_collision",
      },
    }));
    const finding = JSON.parse(readFindings({ target_domain: domain })).findings[0];
    assert.equal(finding.capability_pack, "smart_contract_substrate");
    assert.equal(finding.hunter_agent, "hunter-substrate-agent");
    assert.equal(finding.brief_profile, "smart_contract_substrate");
  });
});

test("normalizeFindingRecord backfills capability_pack metadata for legacy web rows", () => {
  // Old findings.jsonl rows from before routing-metadata existed did not
  // carry capability_pack. Read-side derives the pack triple from
  // surface_type so downstream consumers never see null and don't need to
  // re-implement the surface_type→pack mapping.
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  const legacyFinding = normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "Legacy IDOR",
    severity: "high",
    endpoint: "/api/x",
    description: "Legacy row written by an older Bob version.",
    proof_of_concept: "curl ...",
    validated: true,
    wave: "w1",
    agent: "a1",
    surface_id: "surface-a",
    surface_type: "web",
  });
  assert.equal(legacyFinding.capability_pack, "web");
  assert.equal(legacyFinding.hunter_agent, "hunter-agent");
  assert.equal(legacyFinding.brief_profile, "web");
  assert.equal(legacyFinding.surface_type, "web");
});

test("normalizeFindingRecord backfills capability_pack metadata for legacy SC rows from chain_family", () => {
  // Legacy SC findings carry sc_evidence.chain_family. Backfill must derive
  // the right pack — smart_contract_evm for chain_family="evm",
  // smart_contract_substrate for chain_family="substrate", etc.
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  const legacyEvm = normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "Legacy reentrancy",
    severity: "high",
    endpoint: "0x" + "ab".repeat(20) + ":withdraw()",
    description: "Pre-Phase-C SC row.",
    proof_of_concept: "See harness",
    validated: true,
    wave: "w1",
    agent: "a1",
    surface_id: "surface-evm",
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "evm",
      chain_id: 1,
      contract_address: "0x" + "ab".repeat(20),
      harness_path: os.homedir(),
      match_test: "test_reentrancy",
    },
  });
  assert.equal(legacyEvm.capability_pack, "smart_contract_evm");
  assert.equal(legacyEvm.hunter_agent, "hunter-evm-agent");
  assert.equal(legacyEvm.brief_profile, "smart_contract_evm");

  const legacySvm = normalizeFindingRecord({
    id: "F-2",
    target_domain: "example.com",
    title: "Legacy SVM",
    severity: "medium",
    endpoint: "Programs:11111111111111111111111111111111:transfer",
    description: "Pre-Phase-C SVM row.",
    proof_of_concept: "See harness",
    validated: true,
    wave: "w1",
    agent: "a2",
    surface_id: "surface-svm",
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "svm",
      chain_id: "mainnet-beta",
      contract_address: "11111111111111111111111111111111",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  });
  assert.equal(legacySvm.capability_pack, "smart_contract_svm");
  assert.equal(legacySvm.hunter_agent, "hunter-svm-agent");
  assert.equal(legacySvm.brief_profile, "smart_contract_svm");
});

test("bounty_record_finding rejects sc_evidence in the no-wave/no-agent path so SC findings stay routed", () => {
  // The no-wave path hardcodes the web pack triple. If a future caller
  // tries to record SC evidence without wave/agent, the routed pack would
  // silently be web — downstream verifier/evidence dispatch would route to
  // hunter-agent for an SC finding. Local assert keeps the invariant honest
  // at the call site.
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT" });
    seedAttackSurfaces(domain, [
      { id: "surface-evm", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" },
    ]);
    assert.throws(() => recordFinding({
      target_domain: domain,
      title: "SC finding via no-wave",
      severity: "high",
      cwe: "CWE-841",
      endpoint: "0x" + "ab".repeat(20) + ":withdraw()",
      description: "should be rejected",
      proof_of_concept: "x",
      response_evidence: "x",
      impact: "x",
      validated: true,
      sc_evidence: {
        chain_family: "evm",
        chain_id: 1,
        contract_address: "0x" + "ab".repeat(20),
        harness_path: os.homedir(),
        match_test: "test_x",
      },
    }), /sc_evidence findings must be recorded with wave and agent/);
  });
});

test("classifySurfaceCapability throws on smart_contract surface with missing or unsupported chain_family", () => {
  // Pre-fix the router silently fell back to the web pack for SC surfaces
  // with no chain_family, producing surface_type="smart_contract" routed to
  // hunter-agent (a contradiction). Now the router fails loudly so the
  // operator either fixes the surface or registers the missing pack.
  const { classifySurfaceCapability } = require("../mcp/lib/capability-packs.js");
  assert.throws(
    () => classifySurfaceCapability({ id: "surface-mystery", surface_type: "smart_contract" }),
    /missing chain_family/,
  );
  assert.throws(
    () => classifySurfaceCapability({ id: "surface-near", surface_type: "smart_contract", chain_family: "near" }),
    /unsupported chain_family/,
  );
});

test("normalizeAssignmentRouteMetadata throws on smart_contract assignment without route metadata", () => {
  // The all-null shortcut used to silently substitute web defaults for any
  // assignment lacking the triple. That meant a smart_contract assignment
  // whose route metadata had been dropped (forged file, half-rolled-back
  // upgrade, etc.) got rubber-stamped as web. Fail loudly instead.
  const { normalizeAssignmentRouteMetadata } = require("../mcp/lib/capability-packs.js");
  assert.throws(
    () => normalizeAssignmentRouteMetadata({
      agent: "a1",
      surface_id: "surface-evm",
      surface_type: "smart_contract",
    }),
    /surface_type=smart_contract is missing capability_pack/,
  );
  assert.throws(
    () => normalizeAssignmentRouteMetadata({
      agent: "a1",
      surface_id: "surface-web",
      surface_type: "api",
      capability_pack_version: 1,
    }),
    /assignment route metadata has invalid capability_pack/,
  );
  assert.throws(
    () => normalizeAssignmentRouteMetadata({
      agent: "a1",
      surface_id: "surface-web",
      surface_type: "api",
      context_budget: expectedWebContextBudget(),
    }),
    /assignment route metadata has invalid capability_pack/,
  );
  // Web assignment with no route metadata still legitimately defaults to web.
  const webMeta = normalizeAssignmentRouteMetadata({
    agent: "a1",
    surface_id: "surface-web",
    surface_type: "api",
  });
  assert.equal(webMeta.capability_pack, "web");
});

test("findings.md mirror surfaces the routed capability pack for triage", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-evm", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" },
    ]);
    seedAssignments(domain, 1, [{
      agent: "a1",
      surface_id: "surface-evm",
      capability_pack: "smart_contract_evm",
      hunter_agent: "hunter-evm-agent",
      brief_profile: "smart_contract_evm",
    }]);
    JSON.parse(recordFinding({
      target_domain: domain,
      title: "EVM reentrancy",
      severity: "critical",
      cwe: "CWE-841",
      endpoint: "0x" + "ab".repeat(20) + ":withdraw()",
      description: "Reentrancy on withdraw.",
      proof_of_concept: "See harness",
      response_evidence: "Drained.",
      impact: "Funds loss.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-evm",
      sc_evidence: {
        chain_family: "evm",
        chain_id: 1,
        contract_address: "0x" + "ab".repeat(20),
        harness_path: os.homedir(),
        match_test: "test_reentrancy",
      },
    }));
    const md = fs.readFileSync(findingsMarkdownPath(domain), "utf8");
    assert.match(md, /Capability Pack:\*\* smart_contract_evm \(hunter-evm-agent\)/);
  });
});

test("normalizeFindingRecord forbids sc_evidence on legacy null-surface rows (back-compat smuggling)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/findings.js");
  // A legacy row may have surface_type=null. The original guard forbade
  // sc_evidence only on surface_type="web", so a malicious or buggy row
  // could carry SC replay data while being routed as web by verifiers.
  // sc_evidence is now allowed only when surface_type === "smart_contract".
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
  // A legacy row may have no chain_family field at all. The normalizer
  // defaults to 'evm' so existing findings.jsonl rows keep validating.
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

test("svm tools register with verifier and evidence role bundles (so balanced/brutalist/final + evidence-agent can re-run SVM PoCs)", () => {
  const tools = ["bounty_svm_fetch_account", "bounty_svm_fetch_program", "bounty_anchor_run"];
  for (const name of tools) {
    const meta = TOOL_MANIFEST[name];
    assert.ok(meta, `${name} is in TOOL_MANIFEST`);
    assert.deepEqual(meta.role_bundles, ["hunter-svm", "verifier", "evidence"], `${name} exposes role_bundles=[hunter-svm, verifier, evidence]`);
    assert.equal(meta.network_access, true, `${name} declares network_access`);
  }
});

// ----------------------------------------------------------------------
// Move (Aptos + Sui) primitives
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

test("hunter-brief summarizeRpcPoolForBrief dispatches to substrate and cosmwasm pool summaries", () => {
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

test("parseCargoTestStdout parses cargo unit test output line-by-line", () => {
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

test("parseCargoTestStdout caps tests[] at 100 and sets truncated", () => {
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

test("parseCargoTestStdout returns ok=false when stdout has no test lines or result line", () => {
  const { parseCargoTestStdout } = require("../mcp/lib/cargo-test-output.js");
  const stdout = "error[E0432]: unresolved import\nCompilation aborted.\n";
  const r = parseCargoTestStdout(stdout);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "no_test_lines");
});

test("substrate runner classifies cargo missing as substrate_dependency_missing", () => {
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

test("cosmwasm runner classifies cargo missing as cosmwasm_dependency_missing", () => {
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

test("substrate runner rejects extra_args not in the cargo allowlist", async () => {
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
    // --workspace is intentionally NOT allowlisted; running tests across
    // every workspace member compounds compile-time blast radius.
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

test("cosmwasm runner rejects extra_args not in the cargo allowlist", async () => {
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

test("substrate runner rejects harness without Cargo.toml at root", async () => {
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

test("cosmwasm runner rejects harness without Cargo.toml at root", async () => {
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

test("bech32 mixed-case rejection happens at findings layer with stable error shape", () => {
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

test("substrate-client rejects malformed SS58", () => {
  const { isSs58Address } = require("../mcp/lib/substrate-client.js");
  assert.equal(isSs58Address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"), true);
  assert.equal(isSs58Address("0x" + "ab".repeat(20)), false);
  assert.equal(isSs58Address("osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5"), false);
  assert.equal(isSs58Address("short"), false);
  assert.equal(isSs58Address(""), false);
});

test("cosmwasm-client rejects malformed bech32", () => {
  const { isBech32Address } = require("../mcp/lib/cosmwasm-client.js");
  assert.equal(isBech32Address("osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4z5ese"), true);
  assert.equal(isBech32Address("0x" + "ab".repeat(20)), false);
  assert.equal(isBech32Address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"), false);
  assert.equal(isBech32Address("noseparator"), false);
});

test("sc_evidence rejects EVM-canonical 40-hex address when chain_family is aptos or sui", () => {
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

test("aptos runner classifies CLI usage errors as aptos_dependency_missing", () => {
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

test("sui runner classifies CLI usage errors as sui_dependency_missing", () => {
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

test("Move tools register with verifier and evidence role bundles (so balanced/brutalist/final + evidence-agent can re-run Aptos/Sui PoCs)", () => {
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
    assert.deepEqual(meta.role_bundles, ["hunter-move", "verifier", "evidence"], `${name} exposes role_bundles=[hunter-move, verifier, evidence]`);
    assert.equal(meta.network_access, true, `${name} declares network_access`);
  }
});

test("bounty_record_finding tolerates legacy findings.jsonl rows with no surface_type or sc_evidence", () => {
  withTempHome(() => {
    const domain = "example.com";
    const findingsPath = findingsJsonlPath(domain);
    fs.mkdirSync(path.dirname(findingsPath), { recursive: true });
    // Hand-write a legacy row representing findings without surface_type.
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
      transition_blockers: [{
        code: "state_unavailable",
        message: "session state could not be read for HUNT -> CHAIN gating",
        error: `Missing session state: ${statePath(domain)}`,
      }],
      http_audit: {
        total: 0,
        shown: 0,
        omitted: 0,
        cap: 0,
        by_status_class: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 },
        errors: 0,
        scope_blocked: 0,
        network_unreachable_target: 0,
        egress: { by_profile: {}, by_region: {} },
        geofence_warning: { threshold: 3, warning: false, code: null, note: null, hosts: [] },
        recent: [],
      },
      traffic: { total: 0, shown: 0, omitted: 0, cap: 0, authenticated_count: 0, by_status_class: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 }, recent: [] },
      circuit_breaker: { threshold: 3, tripped_hosts: [], tripped_count: 0, below_threshold_hosts: [], below_threshold_count: 0, note: null },
      surface_leads: { total: 0, high_confidence_unpromoted: 0, promoted: 0 },
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
      transition_blockers: [{
        code: "state_unavailable",
        message: "session state could not be read for HUNT -> CHAIN gating",
        error: `Missing session state: ${statePath(domain)}`,
      }],
      http_audit: {
        total: 0,
        shown: 0,
        omitted: 0,
        cap: 0,
        by_status_class: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 },
        errors: 0,
        scope_blocked: 0,
        network_unreachable_target: 0,
        egress: { by_profile: {}, by_region: {} },
        geofence_warning: { threshold: 3, warning: false, code: null, note: null, hosts: [] },
        recent: [],
      },
      traffic: { total: 0, shown: 0, omitted: 0, cap: 0, authenticated_count: 0, by_status_class: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 }, recent: [] },
      circuit_breaker: { threshold: 3, tripped_hosts: [], tripped_count: 0, below_threshold_hosts: [], below_threshold_count: 0, note: null },
      surface_leads: { total: 0, high_confidence_unpromoted: 0, promoted: 0 },
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

test("bounty_write_evidence_packs writes JSON and markdown mirror", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);

    const result = JSON.parse(writeEvidencePacks({
      target_domain: domain,
      packs: [evidencePack("F-1")],
    }));
    const paths = evidencePackPaths(domain);

    assert.equal(result.packs_count, 1);
    assert.equal(result.representative_samples_count, 1);
    assert.equal(result.reportable_findings_covered, 1);
    assert.equal(result.written_json, paths.json);
    assert.equal(result.written_md, paths.markdown);
    assert.deepEqual(JSON.parse(fs.readFileSync(paths.json, "utf8")), {
      version: 1,
      target_domain: domain,
      packs: [evidencePack("F-1")],
    });
    assert.match(fs.readFileSync(paths.markdown, "utf8"), /# Evidence Packs/);
    assert.deepEqual(JSON.parse(readEvidencePacks({ target_domain: domain })), {
      version: 1,
      target_domain: domain,
      packs: [evidencePack("F-1")],
    });

    const rows = readJsonl(pipelineEventsJsonlPath(domain));
    const evidenceEvent = rows.find((row) => row.type === "evidence_written");
    assert.ok(evidenceEvent);
    assert.deepEqual(evidenceEvent.counts, {
      packs: 1,
      representative_samples: 1,
      reportable_findings_covered: 1,
    });
  });
});

test("bounty_write_evidence_packs rejects unknown and duplicate finding IDs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);

    assert.throws(() => writeEvidencePacks({
      target_domain: domain,
      packs: [evidencePack("F-99")],
    }), /Unknown finding_id: F-99/);

    assert.throws(() => writeEvidencePacks({
      target_domain: domain,
      packs: [evidencePack("F-1"), evidencePack("F-1")],
    }), /Duplicate finding_id in evidence packs: F-1/);
  });
});

test("bounty_write_evidence_packs requires coverage for all final reportable findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);
    seedFinding(domain, { title: "Second IDOR", endpoint: "/api/second" });
    seedVerificationPipeline(domain, [
      {
        finding_id: "F-1",
        disposition: "confirmed",
        severity: "high",
        reportable: true,
        reasoning: "Confirmed.",
      },
      {
        finding_id: "F-2",
        disposition: "confirmed",
        severity: "medium",
        reportable: true,
        reasoning: "Confirmed.",
      },
    ]);

    assert.throws(() => writeEvidencePacks({
      target_domain: domain,
      packs: [evidencePack("F-1")],
    }), /Evidence packs missing final reportable finding\(s\): F-2/);

    assert.doesNotThrow(() => writeEvidencePacks({
      target_domain: domain,
      packs: [evidencePack("F-1"), evidencePack("F-2")],
    }));
  });
});

test("bounty_read_evidence_packs allows skip only when final verification has no reportable findings", () => {
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

    assert.deepEqual(JSON.parse(readEvidencePacks({ target_domain: domain })), {
      version: 1,
      target_domain: domain,
      packs: [],
      skipped: true,
    });
    assert.doesNotThrow(() => writeEvidencePacks({ target_domain: domain, packs: [] }));

    const reportableDomain = "reportable.example.com";
    seedFinding(reportableDomain);
    seedVerificationPipeline(reportableDomain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);

    assert.throws(() => readEvidencePacks({ target_domain: reportableDomain }), /Missing evidence packs JSON/);
    assert.throws(() => writeEvidencePacks({ target_domain: reportableDomain, packs: [] }), /Evidence packs missing final reportable finding\(s\): F-1/);
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
    JSON.parse(writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] }));

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

test("bounty_write_grade_verdict requires evidence packs for final reportables before writing", () => {
  withTempHome(() => {
    const domain = "grade-evidence-required.example.com";
    seedFinding(domain, { severity: "high" });
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);

    assert.throws(() => writeGradeVerdict({
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
    }), /Evidence packs.*Missing evidence packs JSON/);

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "HOLD",
      total_score: 25,
      findings: [{
        finding_id: "F-1",
        impact: 10,
        proof_quality: 5,
        severity_accuracy: 5,
        chain_potential: 0,
        report_quality: 5,
        total_score: 25,
        feedback: null,
      }],
      feedback: "Evidence collection did not run.",
    }), /Evidence packs.*Missing evidence packs JSON/);
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
      assert.deepEqual(records.map((record) => record.scope_decision), ["allowed", "allowed", "network_unreachable_target", "blocked"]);
      assert.deepEqual(records.map((record) => record.egress_profile), ["default", "default", "default", "default"]);
      assert.equal(records[0].wave, "w1");
      assert.equal(records[0].agent, "a1");
      assert.equal(records[0].surface_id, "surface-a");

      const audit = JSON.parse(readHttpAudit({ target_domain: domain, limit: 2 }));
      assert.equal(audit.summary.total, 4);
      assert.equal(audit.summary.shown, 2);
      assert.equal(audit.summary.by_status_class["4xx"], 1);
      assert.equal(audit.summary.scope_blocked, 1);
      assert.equal(audit.summary.network_unreachable_target, 1);
      assert.equal(audit.summary.egress.by_profile.default, 4);
      assert.ok(fs.existsSync(httpAuditJsonlPath(domain)));
    });
  });
});

test("bounty_http_scan records selected egress profile and passes a proxy agent without storing proxy URLs", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    const rawProxySecret = ["raw", "proxy", "secret"].join("-");
    const proxyAuthority = ["user", rawProxySecret].join(":");
    const document = {
      version: 1,
      profiles: [
        egressProfiles.defaultEgressProfile(),
        {
          name: "gr-residential",
          proxy_url: "${BOB_EGRESS_GR_RESIDENTIAL_PROXY}",
          region: "GR",
          description: "Greece operator profile",
          enabled: true,
        },
      ],
    };

    await withRepoEgressConfig(document, async () => {
      await withEnv({ BOB_EGRESS_GR_RESIDENTIAL_PROXY: ["http://", proxyAuthority, "@127.0.0.1:8080"].join("") }, async () => {
        let sawAgent = false;
        await withMockSafeFetch((url, requestOptions) => {
          sawAgent = !!requestOptions.agent;
          return { status: 200, statusText: "OK", body: "ok" };
        }, async () => {
          const result = await executeTool("bounty_http_scan", {
            target_domain: domain,
            method: "GET",
            url: "https://example.com/ok",
            egress_profile: "gr-residential",
            response_mode: "status_only",
          });

          assert.equal(result.ok, true);
          assert.equal(result.data.egress_profile, "gr-residential");
          assert.equal(result.data.egress_region, "GR");
          assert.equal(sawAgent, true);

          const records = readHttpAuditRecordsFromJsonl(domain);
          assert.equal(records.length, 1);
          assert.equal(records[0].egress_profile, "gr-residential");
          assert.equal(records[0].egress_region, "GR");
          const audit = JSON.parse(readHttpAudit({ target_domain: domain }));
          assert.equal(audit.summary.egress.by_profile["gr-residential"], 1);
          assert.equal(audit.summary.egress.by_region.GR, 1);
          assert.doesNotMatch(JSON.stringify(result), new RegExp(rawProxySecret));
          assert.doesNotMatch(JSON.stringify(records), new RegExp(rawProxySecret));
          assert.doesNotMatch(JSON.stringify(audit), new RegExp(rawProxySecret));
        });
      });
    });
  });
});

test("bounty_http_scan rejects invalid egress profiles before sending network requests and redacts proxy credentials", async () => {
  await withTempHome(async () => {
    const rawProxySecret = ["do", "not", "leak", "proxy", "secret"].join("-");
    const proxyAuthority = ["user", rawProxySecret].join(":");
    const document = {
      version: 1,
      profiles: [
        egressProfiles.defaultEgressProfile(),
        { name: "disabled", proxy_url: "${BOB_EGRESS_DISABLED_PROXY}", region: "EU", description: null, enabled: false },
        { name: "missing-env", proxy_url: "${BOB_EGRESS_MISSING_PROXY}", region: "EU", description: null, enabled: true },
        { name: "unsupported", proxy_url: ["ftp://", proxyAuthority, "@proxy.example:21"].join(""), region: "EU", description: null, enabled: true },
        { name: "malformed", proxy_url: ["http://", proxyAuthority, "@"].join(""), region: "EU", description: null, enabled: true },
      ],
    };

    await withRepoEgressConfig(document, async () => {
      await withMockSafeFetch(() => {
        throw new Error("network should not be reached");
      }, async (requestedUrls) => {
        for (const [profileName, pattern] of [
          ["missing", /not found/],
          ["disabled", /disabled/],
          ["missing-env", /env var BOB_EGRESS_MISSING_PROXY is not set/],
          ["unsupported", /unsupported egress proxy protocol: ftp:/],
          ["malformed", /malformed/],
        ]) {
          const result = await executeTool("bounty_http_scan", {
            target_domain: "example.com",
            method: "GET",
            url: "https://example.com/ok",
            egress_profile: profileName,
          });
          assert.equal(result.ok, false, `${profileName} should fail`);
          assert.equal(result.error.code, "INTERNAL_ERROR");
          assert.match(result.error.message, pattern);
          assert.doesNotMatch(JSON.stringify(result), new RegExp(rawProxySecret));
        }
        assert.deepEqual(requestedUrls, []);
      });
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
  const inputUrl = ["https://", ["alice", "secret"].join(":"), "@example.com/path?token=abc&id=123#frag"].join("");
  const expectedUrl = ["https://", ["REDACTED", "REDACTED"].join(":"), "@example.com/path?token=REDACTED&id=REDACTED"].join("");
  assert.equal(
    redactUrlSensitiveValues(inputUrl),
    expectedUrl,
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

test("buildCircuitBreakerSummary surfaces below-threshold per-host failures in below_threshold_hosts", () => {
  // The veda.tech regression: 2 internal errors + 2 network-unreachable
  // events on the same host produced no tripped breaker (below the
  // ≥3-per-host threshold) and no near-threshold visibility either.
  // Operators looking at a session with errors but no warnings could not
  // tell whether the threshold was reached and suppressed or never crossed.
  // below_threshold_hosts surfaces that data without false escalation.
  const records = [
    {
      version: 1,
      ts: "2026-05-02T00:00:00.000Z",
      target_domain: "example.com",
      method: "GET",
      url: "https://api.example.com/x",
      host: "api.example.com",
      status: 200,
      error: null,
      scope_decision: "allowed",
    },
    {
      version: 1,
      ts: "2026-05-02T00:00:01.000Z",
      target_domain: "example.com",
      method: "GET",
      url: "https://api.example.com/x",
      host: "api.example.com",
      status: 403,
      error: null,
      scope_decision: "allowed",
    },
    {
      version: 1,
      ts: "2026-05-02T00:00:02.000Z",
      target_domain: "example.com",
      method: "GET",
      url: "https://api.example.com/y",
      host: "api.example.com",
      status: null,
      error: "timeout after 5000ms",
      scope_decision: "request_error",
    },
    // A host with 3 failures — crosses the threshold and should appear in
    // tripped_hosts, NOT in below_threshold_hosts.
    {
      version: 1,
      ts: "2026-05-02T00:00:03.000Z",
      target_domain: "example.com",
      method: "GET",
      url: "https://hot.example.com/z",
      host: "hot.example.com",
      status: 429,
      error: null,
      scope_decision: "allowed",
    },
    {
      version: 1,
      ts: "2026-05-02T00:00:04.000Z",
      target_domain: "example.com",
      method: "GET",
      url: "https://hot.example.com/z",
      host: "hot.example.com",
      status: 429,
      error: null,
      scope_decision: "allowed",
    },
    {
      version: 1,
      ts: "2026-05-02T00:00:05.000Z",
      target_domain: "example.com",
      method: "GET",
      url: "https://hot.example.com/z",
      host: "hot.example.com",
      status: 403,
      error: null,
      scope_decision: "allowed",
    },
  ];

  const summary = buildCircuitBreakerSummary(records);
  assert.equal(summary.tripped_count, 1);
  assert.equal(summary.tripped_hosts[0].host, "hot.example.com");
  assert.equal(summary.below_threshold_count, 1);
  assert.equal(summary.below_threshold_hosts[0].host, "api.example.com");
  assert.equal(summary.below_threshold_hosts[0].failures, 2);
  // No host appears in both lists.
  assert.equal(
    summary.below_threshold_hosts.some((item) => item.host === "hot.example.com"),
    false,
  );
});

test("pipeline analytics surfaces egress and geofence warnings from HTTP audit", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: null });

    for (let index = 0; index < 3; index += 1) {
      appendHttpAuditRecord({
        version: 1,
        ts: new Date(Date.now() + index).toISOString(),
        target_domain: domain,
        method: "GET",
        url: `https://api.${domain}/blocked-${index}`,
        host: `api.${domain}`,
        path: `/blocked-${index}`,
        status: null,
        error: "timeout after 1000ms",
        scope_decision: "network_unreachable_target",
        egress_profile: "default",
        egress_region: null,
      });
    }

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain }));
    assert.equal(analytics.sessions[0].egress.by_profile.default, 3);
    assert.equal(analytics.sessions[0].geofence_warnings.warning, true);
    assert.equal(analytics.sessions[0].geofence_warnings.code, "network_unreachable_target");
    assert.ok(analytics.bottlenecks.some((item) => item.code === "network_unreachable_target"));
    assert.doesNotMatch(JSON.stringify(analytics), /proxy/i);
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
      egress_profile: "operator-eu",
      block_internal_hosts: true,
    }));

    assert.deepEqual(brief.run_context, {
      target_domain: domain,
      phase: "HUNT",
      auth_status: "pending",
      egress_profile: "operator-eu",
      block_internal_hosts: true,
      capability_pack: "web",
      capability_pack_version: 1,
      hunter_agent: "hunter-agent",
      brief_profile: "web",
      context_budget: expectedWebContextBudget(),
    });
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
    // Web brief shape: include the HTTP-flavored intel fields, omit SC-only fields.
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "bypass_table"), "web brief must expose bypass_table");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "techniques"), "web brief must expose techniques");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "payload_hints"), "web brief must expose payload_hints");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "knowledge_summary"), "web brief must expose knowledge_summary");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "technique_packs"), "web brief must expose canonical technique_packs");
    assert.equal(brief.technique_packs.selection_budget.attempt_log_required, true);
    assert.deepEqual(brief.technique_packs.registry_warnings, []);
    assert.ok(brief.techniques.length <= 2);
    assert.ok(brief.payload_hints.length <= 2);
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "traffic_summary"), "web brief must expose traffic_summary");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "audit_summary"), "web brief must expose audit_summary");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "circuit_breaker_summary"), "web brief must expose circuit_breaker_summary");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "intel_hints"), "web brief must expose intel_hints");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "static_scan_hints"), "web brief must expose static_scan_hints");
    assert.strictEqual(brief.bob_spec_status, undefined);
    assert.strictEqual(brief.rpc_pool, undefined);
  });
});

test("bounty_read_hunter_brief uses smart_contract_evm shape when the assignment routes to that pack", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      pending_wave: 1,
      dead_ends: [],
      waf_blocked_endpoints: [],
    });
    seedAttackSurfaces(domain, [{
      id: "surface-evm-1",
      surface_type: "smart_contract",
      chain_family: "evm",
      chain_id: "1",
      hosts: [`https://${domain}`],
      foundry_harness_path: "/tmp/harness/evm",
    }]);
    seedAssignments(domain, 1, [{
      agent: "a1",
      surface_id: "surface-evm-1",
      capability_pack: "smart_contract_evm",
      hunter_agent: "hunter-evm-agent",
      brief_profile: "smart_contract_evm",
    }]);

    const brief = JSON.parse(readHunterBrief({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
    }));

    assert.equal(brief.run_context.capability_pack, "smart_contract_evm");
    assert.equal(brief.run_context.brief_profile, "smart_contract_evm");
    assert.equal(brief.run_context.hunter_agent, "hunter-evm-agent");
    assert.deepEqual(brief.run_context.context_budget, expectedSmartContractContextBudget());

    // SC profile must expose typed bob_spec_status and rpc_pool, not just
    // a present-but-undefined slot. hasOwnProperty + null-guard catches
    // the regression where dispatch returns the wrong shape.
    assert.ok(brief.bob_spec_status, "smart-contract brief must expose bob_spec_status");
    assert.equal(typeof brief.bob_spec_status, "object");
    assert.equal(typeof brief.bob_spec_status.present, "boolean");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "rpc_pool"), "smart-contract brief must expose rpc_pool");
    assert.equal(typeof brief.rpc_pool, "object");
    assert.ok(Array.isArray(brief.rpc_pool.endpoints) || brief.rpc_pool.endpoints == null);
    assert.equal(brief.surface.foundry_harness_path, "/tmp/harness/evm",
      "EVM hunter must receive its foundry_harness_path scalar");

    // SC profile: omit the web-flavored fields the SC hunter doesn't have tools for.
    for (const webField of [
      "bypass_table",
      "techniques",
      "payload_hints",
      "knowledge_summary",
      "traffic_summary",
      "audit_summary",
      "circuit_breaker_summary",
      "intel_hints",
      "static_scan_hints",
      "auth_profiles_hint",
    ]) {
      assert.ok(
        !Object.prototype.hasOwnProperty.call(brief, webField),
        `smart-contract brief must omit ${webField} (web-flavored)`,
      );
    }

    // Cross-cutting fields stay in both profiles.
    for (const sharedField of [
      "run_context",
      "target_url",
      "wave",
      "agent",
      "surface",
      "surface_limits",
      "valid_surface_ids",
      "dead_ends",
      "waf_blocked_endpoints",
      "exclusions_summary",
      "coverage_summary",
      "ranking_summary",
    ]) {
      assert.ok(
        Object.prototype.hasOwnProperty.call(brief, sharedField),
        `smart-contract brief must keep cross-cutting ${sharedField}`,
      );
    }
  });
});

test("bounty_read_hunter_brief preserves per-chain harness paths for every smart-contract pack", () => {
  // slimSurfaceForBrief whitelists each chain's harness_path scalar.
  // SVM/Move/Substrate/CosmWasm hunter prompts read anchor_harness_path /
  // move_harness_path / ink_harness_path / cargo_harness_path /
  // cosmwasm_harness_path; if those get stripped, hunters falsely report
  // missing harnesses and write partial handoffs.
  const cases = [
    { pack: "smart_contract_svm",       chain_family: "svm",       agent: "hunter-svm-agent",       field: "anchor_harness_path",   value: "/tmp/harness/svm" },
    { pack: "smart_contract_aptos",     chain_family: "aptos",     agent: "hunter-move-agent",      field: "move_harness_path",     value: "/tmp/harness/aptos" },
    { pack: "smart_contract_sui",       chain_family: "sui",       agent: "hunter-move-agent",      field: "move_harness_path",     value: "/tmp/harness/sui" },
    { pack: "smart_contract_substrate", chain_family: "substrate", agent: "hunter-substrate-agent", field: "ink_harness_path",      value: "/tmp/harness/ink" },
    { pack: "smart_contract_substrate", chain_family: "substrate", agent: "hunter-substrate-agent", field: "cargo_harness_path",    value: "/tmp/harness/cargo" },
    { pack: "smart_contract_cosmwasm",  chain_family: "cosmwasm",  agent: "hunter-cosmwasm-agent",  field: "cosmwasm_harness_path", value: "/tmp/harness/cw" },
  ];
  for (const { pack, chain_family, agent, field, value } of cases) {
    withTempHome(() => {
      const domain = "example.com";
      seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
      seedAttackSurfaces(domain, [{
        id: "sc-1",
        surface_type: "smart_contract",
        chain_family,
        chain_id: "1",
        hosts: [`https://${domain}`],
        [field]: value,
      }]);
      seedAssignments(domain, 1, [{
        agent: "a1",
        surface_id: "sc-1",
        capability_pack: pack,
        hunter_agent: agent,
        brief_profile: pack,
      }]);
      const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
      assert.equal(brief.surface[field], value, `${pack} hunter must receive ${field}`);
    });
  }
});

test("bounty_read_hunter_brief throws on an unsupported brief_profile rather than fail-open to smart-contract", () => {
  // Regression guard for fail-open: the dispatch must reject profiles the
  // capability-pack registry never declared, even if route metadata is
  // forged on disk.
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurface(domain, ["surface-a"]);
    // We can't get an unsupported profile through normalizeAssignmentRouteMetadata
    // because that itself validates against the pack registry. So we forge the
    // assignment file directly to reach the dispatch.
    const dir = sessionDir(domain);
    const assignmentsPath = path.join(dir, "wave-1-assignments.json");
    fs.writeFileSync(assignmentsPath, JSON.stringify({
      wave_number: 1,
      assignments: [{
        agent: "a1",
        surface_id: "surface-a",
        capability_pack: "smart_contract_evm",
        hunter_agent: "hunter-evm-agent",
        brief_profile: "smart_contract_evm",
      }],
    }));
    // Sanity: this assignment is valid and produces an SC brief.
    JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    // Mutate the on-disk assignment to a profile no pack declares. The
    // route-metadata validator rejects it before dispatch, which is the
    // correct fail-loud behavior.
    fs.writeFileSync(assignmentsPath, JSON.stringify({
      wave_number: 1,
      assignments: [{
        agent: "a1",
        surface_id: "surface-a",
        capability_pack: "experimental_mobile",
        hunter_agent: "mobile-hunter-agent",
        brief_profile: "mobile_api",
      }],
    }));
    assert.throws(
      () => readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }),
      /unknown capability_pack|Unsupported brief profile/,
    );
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
    assert.equal(brief.knowledge_summary.max_entries, 2);
    assert.equal(brief.knowledge_summary.legacy_compatibility, true);
    assert.ok(brief.knowledge_summary.char_count <= brief.knowledge_summary.max_chars);
    assert.doesNotMatch(JSON.stringify(brief), /Complete reference library|Advanced Bug Bounty Hunting Techniques|scripts\/|tools\//);
  });
});

test("bounty_read_hunter_brief includes bounded candidate technique packs and context budget", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-graphql",
      hosts: [`https://${domain}`],
      tech_stack: ["GraphQL", "Apollo"],
      endpoints: ["/graphql"],
      interesting_params: ["query", "variables"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-graphql" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.deepEqual(brief.run_context.context_budget, expectedWebContextBudget());
    assert.equal(brief.run_context.capability_pack_version, 1);
    assert.equal(brief.technique_packs.selection_budget.candidate_pack_limit, 5);
    assert.equal(brief.technique_packs.selection_budget.full_pack_read_limit, 2);
    assert.equal(brief.technique_packs.selection_budget.attempt_log_required, true);
    assert.deepEqual(brief.technique_packs.registry_warnings, []);
    assert.ok(brief.technique_packs.selected.length <= 5);
    assert.ok(brief.techniques.length <= 2);
    assert.ok(brief.payload_hints.length <= 2);
    const graphql = brief.technique_packs.selected.find((entry) => entry.id === "graphql");
    assert.ok(graphql);
    assert.equal(graphql.version, 1);
    assert.ok(graphql.score > 0);
    assert.ok(graphql.summary.guidance.length > 0);
    assert.ok(graphql.summary.payload_hints.length > 0);
    assert.equal(graphql.summary_limits.guidance.item_limit, TECHNIQUE_SUMMARY_ITEMS_PER_KIND);
    assert.equal(graphql.summary_limits.guidance.item_max_chars, TECHNIQUE_SUMMARY_ITEM_MAX_CHARS);
    assert.ok(brief.technique_packs.selection_limits);
    assert.equal(graphql.full, undefined);
  });
});

test("technique pack summary and full reads truncate oversized content with limit metadata", () => {
  withTempTechniqueKnowledge(oversizedTechniqueKnowledge(), () => {
    const summary = readTechniquePack("oversized-0", { mode: "summary" });
    assert.equal(summary.technique_pack.id, "oversized-0");
    assert.equal(summary.technique_pack.summary.guidance.length, TECHNIQUE_SUMMARY_ITEMS_PER_KIND);
    assert.equal(summary.technique_pack.summary.payload_hints.length, TECHNIQUE_SUMMARY_ITEMS_PER_KIND);
    assert.equal(summary.technique_pack.summary.guidance.every((entry) => entry.length <= TECHNIQUE_SUMMARY_ITEM_MAX_CHARS), true);
    assert.equal(summary.technique_pack.summary.payload_hints.every((entry) => entry.length <= TECHNIQUE_SUMMARY_ITEM_MAX_CHARS), true);
    assert.equal(summary.technique_pack.summary_limits.guidance.total, 20);
    assert.equal(summary.technique_pack.summary_limits.guidance.omitted, 16);
    assert.equal(summary.technique_pack.summary_limits.guidance.truncated_values, TECHNIQUE_SUMMARY_ITEMS_PER_KIND);
    assert.deepEqual(summary.summary_limits, summary.technique_pack.summary_limits);

    const full = readTechniquePack("oversized-0", { mode: "full" });
    assert.equal(full.technique_pack.full.techniques.length, TECHNIQUE_FULL_ITEMS_PER_KIND);
    assert.equal(full.technique_pack.full.payload_hints.length, TECHNIQUE_FULL_ITEMS_PER_KIND);
    assert.equal(full.technique_pack.full.techniques.every((entry) => entry.length <= TECHNIQUE_FULL_ITEM_MAX_CHARS), true);
    assert.equal(full.technique_pack.full.payload_hints.every((entry) => entry.length <= TECHNIQUE_FULL_ITEM_MAX_CHARS), true);
    assert.equal(full.technique_pack.full_limits.techniques.total, 20);
    assert.equal(full.technique_pack.full_limits.techniques.omitted, 8);
    assert.equal(full.technique_pack.full_limits.techniques.truncated_values, TECHNIQUE_FULL_ITEMS_PER_KIND);
    assert.deepEqual(full.full_limits, full.technique_pack.full_limits);
  });
});

test("bounty_select_technique_packs keeps oversized selected summaries within the selection limit", () => {
  withTempHome(() => {
    withTempTechniqueKnowledge(oversizedTechniqueKnowledge(), () => {
      const domain = "example.com";
      seedAttackSurfaces(domain, [{
        id: "surface-oversized",
        hosts: [`https://${domain}`],
        tech_stack: ["OversizedStack"],
        endpoints: ["/oversized"],
        interesting_params: ["oversized_id"],
        evidence: ["oversized-hint"],
      }]);

      const selected = JSON.parse(selectTechniquePacks({
        target_domain: domain,
        surface_id: "surface-oversized",
        capability_pack: "web",
        max_packs: 50,
      }));

      assert.equal(selected.selection_limits.max_chars, TECHNIQUE_SELECTION_MAX_CHARS);
      assert.equal(JSON.stringify(selected.technique_packs).length, selected.selection_limits.selected_chars);
      assert.ok(JSON.stringify(selected.technique_packs).length <= TECHNIQUE_SELECTION_MAX_CHARS);
      assert.ok(selected.selection_limits.omitted_due_to_char_limit > 0);
      assert.ok(selected.technique_packs.length < selected.max_packs);
      assert.equal(selected.technique_packs.every((pack) => pack.summary.guidance.length <= TECHNIQUE_SUMMARY_ITEMS_PER_KIND), true);
      assert.equal(
        selected.technique_packs.every((pack) => pack.summary.guidance.every((entry) => entry.length <= TECHNIQUE_SUMMARY_ITEM_MAX_CHARS)),
        true,
      );
    });
  });
});

test("bounty_read_hunter_brief returns bounded oversized selected technique packs and selection limits", () => {
  withTempHome(() => {
    withTempTechniqueKnowledge(oversizedTechniqueKnowledge(), () => {
      const domain = "example.com";
      seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
      seedAttackSurfaces(domain, [{
        id: "surface-oversized",
        hosts: [`https://${domain}`],
        tech_stack: ["OversizedStack"],
        endpoints: ["/oversized"],
        interesting_params: ["oversized_id"],
        evidence: ["oversized-hint"],
      }]);
      seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-oversized" }]);

      const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
      assert.ok(Array.isArray(brief.techniques));
      assert.ok(Array.isArray(brief.payload_hints));
      assert.ok(brief.knowledge_summary);
      assert.equal(brief.knowledge_summary.max_entries, 2);
      assert.equal(brief.techniques.length <= 2, true);
      assert.equal(brief.payload_hints.length <= 2, true);
      assert.equal(brief.technique_packs.selection_limits.max_chars, TECHNIQUE_SELECTION_MAX_CHARS);
      assert.equal(JSON.stringify(brief.technique_packs.selected).length, brief.technique_packs.selection_limits.selected_chars);
      assert.ok(JSON.stringify(brief.technique_packs.selected).length <= TECHNIQUE_SELECTION_MAX_CHARS);
      assert.ok(brief.technique_packs.selection_limits.omitted_due_to_char_limit > 0);
      assert.equal(brief.technique_packs.selected.every((pack) => pack.summary_limits), true);
      assert.equal(
        brief.technique_packs.selected.every((pack) => pack.summary.guidance.every((entry) => entry.length <= TECHNIQUE_SUMMARY_ITEM_MAX_CHARS)),
        true,
      );
    });
  });
});

test("technique registry skips malformed entries and surfaces registry warnings", () => {
  withTempHome(() => {
    withTempTechniqueKnowledge({
      version: 4,
      entries: [
        {
          id: "valid-api",
          title: "Valid API pack",
          capability_packs: ["web"],
          match: { tech: ["customapi"], endpoints: ["/custom"] },
          techniques: ["Use the valid registry entry only."],
          payload_hints: ["/custom/export"],
        },
        "bad entry",
        {
          id: "bad-capability",
          title: "Bad capability",
          capability_packs: ["missing_pack"],
          techniques: ["This entry should be skipped."],
        },
        {
          id: "valid-api",
          title: "Duplicate API pack",
          capability_packs: ["web"],
          techniques: ["Duplicate should be skipped."],
        },
      ],
    }, () => {
      const domain = "example.com";
      seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
      seedAttackSurfaces(domain, [{
        id: "surface-custom",
        hosts: [`https://${domain}`],
        tech_stack: ["CustomAPI"],
        endpoints: ["/custom"],
      }]);
      seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-custom" }]);

      const registry = loadTechniqueRegistry();
      assert.deepEqual(registry.packs.map((pack) => pack.id), ["valid-api"]);
      assert.equal(registry.warnings.length, 3);
      assert.match(JSON.stringify(registry.warnings), /technique pack entry must be an object/);
      assert.match(JSON.stringify(registry.warnings), /Unknown capability_pack/);
      assert.match(JSON.stringify(registry.warnings), /Duplicate technique pack id/);

      const selected = JSON.parse(selectTechniquePacks({
        target_domain: domain,
        surface_id: "surface-custom",
        capability_pack: "web",
      }));
      assert.equal(selected.technique_packs[0].id, "valid-api");
      assert.equal(selected.registry_warnings.length, 3);

      const summary = readTechniquePack("valid-api", { mode: "summary" });
      assert.equal(summary.registry_warnings.length, 3);

      const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
      assert.equal(brief.technique_packs.selected[0].id, "valid-api");
      assert.equal(brief.technique_packs.registry_warnings.length, 3);
      assert.equal(brief.knowledge_summary.registry_warnings.length, 3);
    });
  });
});

test("malformed technique registry file warns instead of failing hunter brief generation", () => {
  withTempHome(() => {
    withTempTechniqueKnowledgeText("{bad json", () => {
      const domain = "example.com";
      seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
      seedAttackSurfaces(domain, [{
        id: "surface-api",
        hosts: [`https://${domain}`],
        tech_stack: ["JSON API"],
        endpoints: ["/api"],
      }]);
      seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);

      const registry = loadTechniqueRegistry();
      assert.deepEqual(registry.packs, []);
      assert.equal(registry.warnings.length, 1);
      assert.match(registry.warnings[0].reason, /Malformed hunter-techniques\.json/);

      const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
      assert.deepEqual(brief.technique_packs.selected, []);
      assert.deepEqual(brief.techniques, []);
      assert.deepEqual(brief.payload_hints, []);
      assert.equal(brief.technique_packs.registry_warnings.length, 1);
      assert.equal(brief.knowledge_summary.registry_warnings.length, 1);
    });
  });
});

test("temporary technique knowledge ignores and restores ambient Bob resource env", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-ambient-resources-"));
  try {
    const resources = path.join(root, "resources");
    const project = path.join(root, "project");
    fs.mkdirSync(path.join(resources, "knowledge"), { recursive: true });
    fs.mkdirSync(project, { recursive: true });
    fs.writeFileSync(path.join(resources, "knowledge", "hunter-techniques.json"), `${JSON.stringify({
      version: 1,
      entries: [{
        id: "ambient-only",
        title: "Ambient only",
        capability_packs: ["web"],
        techniques: ["This ambient resource must not leak into scoped tests."],
      }],
    }, null, 2)}\n`, "utf8");

    withEnv({
      BOB_RESOURCE_DIR: resources,
      BOB_PROJECT_DIR: project,
      CLAUDE_PROJECT_DIR: undefined,
    }, () => {
      withTempTechniqueKnowledge({
        version: 1,
        entries: [{
          id: "scoped-only",
          title: "Scoped only",
          capability_packs: ["web"],
          techniques: ["Use only the scoped test registry."],
        }],
      }, () => {
        assert.equal(process.env.BOB_RESOURCE_DIR, undefined);
        assert.equal(process.env.BOB_PROJECT_DIR, undefined);
        assert.deepEqual(loadTechniqueRegistry().packs.map((pack) => pack.id), ["scoped-only"]);
      });
      assert.equal(process.env.BOB_RESOURCE_DIR, resources);
      assert.equal(process.env.BOB_PROJECT_DIR, project);
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("context budget and technique-pack MCP tools are deterministic and bounded", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [
      {
        id: "surface-graphql",
        surface_type: "graphql",
        hosts: [`https://${domain}`],
        tech_stack: ["GraphQL", "Apollo"],
        endpoints: ["/graphql"],
        interesting_params: ["query", "variables"],
      },
      {
        id: "surface-api",
        surface_type: "api",
        hosts: [`https://api.${domain}`],
        tech_stack: ["JSON API"],
        endpoints: ["/api/v1/users/123", "/api/v2/admin/export"],
        interesting_params: ["id", "user_id", "role"],
        bug_class_hints: ["idor"],
      },
      {
        id: "surface-wp",
        surface_type: "cms",
        hosts: [`https://${domain}`],
        tech_stack: ["WordPress"],
        endpoints: ["/wp-json/wp/v2/users", "/wp-admin/admin-ajax.php"],
        interesting_params: ["author", "action"],
      },
    ]);
    JSON.parse(routeSurfaces({ target_domain: domain }));

    const packOnlyBudget = JSON.parse(getContextBudget({ capability_pack: "web" }));
    assert.deepEqual(packOnlyBudget.context_budget, expectedWebContextBudget());

    assert.throws(
      () => getContextBudget({ capability_pack: "web", surface_id: "surface-graphql" }),
      /target_domain is required when surface_id is provided/,
    );
    const missingTargetDomain = await executeTool("bounty_get_context_budget", {
      capability_pack: "web",
      surface_id: "surface-graphql",
    });
    assert.equal(missingTargetDomain.ok, false);
    assert.equal(missingTargetDomain.error.code, "INVALID_ARGUMENTS");

    const budget = JSON.parse(getContextBudget({
      target_domain: domain,
      surface_id: "surface-graphql",
      capability_pack: "web",
      brief_profile: "web",
    }));
    assert.equal(budget.version, 1);
    assert.equal(budget.capability_pack_version, 1);
    assert.deepEqual(budget.context_budget, expectedWebContextBudget());

    const routeSpecificBudget = {
      candidate_pack_limit: 3,
      full_pack_read_limit: 1,
      attempt_log_required: false,
    };
    writeFileAtomic(surfaceRoutesPath(domain), `${JSON.stringify({
      version: 1,
      route_version: 1,
      routes: [{
        surface_id: "surface-graphql",
        surface_type: "graphql",
        capability_pack: "web",
        capability_pack_version: 7,
        hunter_agent: "hunter-agent",
        brief_profile: "web",
        context_budget: routeSpecificBudget,
        confidence: "high",
        reasons: ["test:custom-route-budget"],
      }],
    }, null, 2)}\n`);
    const routeBudget = JSON.parse(getContextBudget({
      target_domain: domain,
      surface_id: "surface-graphql",
      capability_pack: "web",
    }));
    assert.equal(routeBudget.capability_pack_version, 7);
    assert.deepEqual(routeBudget.context_budget, routeSpecificBudget);

    writeFileAtomic(surfaceRoutesPath(domain), `${JSON.stringify({
      version: 1,
      route_version: 1,
      routes: [{
        surface_id: "surface-graphql",
        surface_type: "graphql",
        capability_pack: "web",
        capability_pack_version: 7,
        hunter_agent: "hunter-agent",
        brief_profile: "web",
        context_budget: {
          ...routeSpecificBudget,
          brief_max_tokens: 1234,
        },
        confidence: "high",
        reasons: ["test:unsupported-route-budget"],
      }],
    }, null, 2)}\n`);
    assert.throws(
      () => getContextBudget({
        target_domain: domain,
        surface_id: "surface-graphql",
        capability_pack: "web",
      }),
      /unsupported context_budget\.brief_max_tokens/,
    );
    JSON.parse(routeSurfaces({ target_domain: domain }));

    const graphql = JSON.parse(selectTechniquePacks({
      target_domain: domain,
      surface_id: "surface-graphql",
      capability_pack: "web",
      max_packs: 50,
    }));
    assert.equal(graphql.max_packs, 5);
    assert.ok(graphql.technique_packs.length <= 5);
    assert.equal(graphql.technique_packs[0].id, "graphql");
    assert.equal(graphql.technique_packs[0].full, undefined);
    assert.match(JSON.stringify(graphql.technique_packs[0].matched), /tech:graphql|endpoint:\/graphql/);

    const api = JSON.parse(selectTechniquePacks({ target_domain: domain, surface_id: "surface-api", max_packs: 5 }));
    assert.ok(api.technique_packs.some((entry) => entry.id === "generic-rest-api"));

    const wordpress = JSON.parse(selectTechniquePacks({ target_domain: domain, surface_id: "surface-wp", max_packs: 5 }));
    assert.equal(wordpress.technique_packs[0].id, "wordpress");

    const summary = readTechniquePack("graphql", { mode: "summary" });
    assert.equal(summary.registry_version, 1);
    assert.equal(summary.technique_pack.id, "graphql");
    assert.equal(summary.technique_pack.full, undefined);

    const full = readTechniquePack("graphql", { mode: "full" });
    assert.equal(full.registry_version, 1);
    assert.equal(full.technique_pack.id, "graphql");
    assert.ok(full.technique_pack.full.techniques.length > 0);
    assert.ok(full.technique_pack.full.techniques.length <= TECHNIQUE_FULL_ITEMS_PER_KIND);
    assert.equal(full.technique_pack.full.techniques.every((entry) => entry.length <= TECHNIQUE_FULL_ITEM_MAX_CHARS), true);
    assert.equal(full.technique_pack.full.payload_hints.every((entry) => entry.length <= TECHNIQUE_FULL_ITEM_MAX_CHARS), true);
    assert.ok(full.technique_pack.full_limits);
    assert.doesNotMatch(JSON.stringify(full), /WordPress REST/);

    assert.throws(
      () => readTechniquePack("unknown-pack", { mode: "summary" }),
      /Unknown technique pack id/,
    );

    const envelope = await executeTool("bounty_read_technique_pack", { pack_id: "unknown-pack", mode: "summary" });
    assert.equal(envelope.ok, false);
    assert.equal(envelope.error.code, "NOT_FOUND");
  });
});

test("bounty_read_technique_pack full mode enforces per-assignment read budget", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-graphql",
      surface_type: "graphql",
      hosts: [`https://${domain}`],
      tech_stack: ["GraphQL", "REST API", "WordPress"],
      endpoints: ["/graphql", "/api/v1/users", "/wp-json/wp/v2/users"],
      interesting_params: ["query", "id", "author"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-graphql" }]);

    const summary = await executeTool("bounty_read_technique_pack", { pack_id: "graphql", mode: "summary" });
    assert.equal(summary.ok, true);
    assert.equal(fs.existsSync(techniquePackReadsJsonlPath(domain)), false);

    const missingContext = await executeTool("bounty_read_technique_pack", { pack_id: "graphql", mode: "full" });
    assert.equal(missingContext.ok, false);
    assert.equal(missingContext.error.code, "INVALID_ARGUMENTS");
    assert.match(missingContext.error.message, /full_pack_read_limit/);

    const context = {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-graphql",
      mode: "full",
    };

    const first = await executeTool("bounty_read_technique_pack", { ...context, pack_id: "graphql" });
    assert.equal(first.ok, true);
    assert.equal(first.data.registry_version, 1);
    assert.equal(first.data.full_read_budget.full_pack_read_limit, 2);
    assert.equal(first.data.full_read_budget.full_packs_read, 1);
    assert.equal(first.data.full_read_budget.remaining_full_pack_reads, 1);
    assert.equal(first.data.full_read_budget.already_read, false);
    assert.equal(first.data.full_read_budget.log_path, techniquePackReadsJsonlPath(domain));

    const second = await executeTool("bounty_read_technique_pack", { ...context, pack_id: "generic-rest-api" });
    assert.equal(second.ok, true);
    assert.equal(second.data.full_read_budget.full_packs_read, 2);
    assert.equal(second.data.full_read_budget.remaining_full_pack_reads, 0);

    const reread = await executeTool("bounty_read_technique_pack", { ...context, pack_id: "graphql" });
    assert.equal(reread.ok, true);
    assert.equal(reread.data.full_read_budget.already_read, true);
    assert.equal(reread.data.full_read_budget.full_packs_read, 2);

    const records = readTechniquePackReadRecordsFromJsonl(domain);
    assert.deepEqual(records.map((record) => record.pack_id), ["graphql", "generic-rest-api"]);
    assert.deepEqual(records.map((record) => ({
      pack_id: record.pack_id,
      pack_version: record.pack_version,
      registry_version: record.registry_version,
      capability_pack: record.capability_pack,
      capability_pack_version: record.capability_pack_version,
    })), [
      {
        pack_id: "graphql",
        pack_version: 1,
        registry_version: 1,
        capability_pack: "web",
        capability_pack_version: 1,
      },
      {
        pack_id: "generic-rest-api",
        pack_version: 1,
        registry_version: 1,
        capability_pack: "web",
        capability_pack_version: 1,
      },
    ]);

    const third = await executeTool("bounty_read_technique_pack", { ...context, pack_id: "wordpress" });
    assert.equal(third.ok, false);
    assert.equal(third.error.code, "INVALID_ARGUMENTS");
    assert.match(third.error.message, /full_pack_read_limit/);
    assert.equal(readTechniquePackReadRecordsFromJsonl(domain).length, 2);
  });
});

test("bounty_log_technique_attempt appends valid JSONL and rejects invalid inputs", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-graphql",
      hosts: [`https://${domain}`],
      tech_stack: ["GraphQL"],
      endpoints: ["/graphql"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-graphql" }]);

    const logged = JSON.parse(logTechniqueAttempt({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-graphql",
      pack_id: "graphql",
      status: "attempted",
      outcome: "not_applicable",
      evidence: "GraphQL endpoint returned 404 for this assigned surface.",
    }));
    assert.equal(logged.appended, 1);
    assert.equal(logged.log_path, techniqueAttemptsJsonlPath(domain));
    assert.equal(logged.record.pack_version, 1);
    assert.equal(logged.record.registry_version, 1);
    assert.equal(logged.record.capability_pack, "web");
    assert.equal(logged.record.capability_pack_version, 1);

    const records = readTechniqueAttemptRecordsFromJsonl(domain);
    assert.equal(records.length, 1);
    assert.equal(records[0].pack_id, "graphql");
    assert.equal(records[0].pack_version, 1);
    assert.equal(records[0].registry_version, 1);
    assert.equal(records[0].capability_pack, "web");
    assert.equal(records[0].capability_pack_version, 1);
    assert.equal(records[0].status, "attempted");
    assert.equal(records[0].outcome, "not_applicable");
    assert.match(records[0].ts, /^\d{4}-\d{2}-\d{2}T/);

    const pipelineEvents = readJsonl(pipelineEventsJsonlPath(domain));
    const attemptEvent = pipelineEvents.find((event) => event.type === "technique_attempt_logged");
    assert.ok(attemptEvent);
    assert.equal(attemptEvent.wave_number, 1);
    assert.equal(attemptEvent.agent, "a1");
    assert.equal(attemptEvent.surface_id, "surface-graphql");
    assert.equal(attemptEvent.status, "attempted");
    assert.equal(attemptEvent.source, "bounty_log_technique_attempt");
    assert.deepEqual(attemptEvent.counts, { records: 1 });
    for (const field of ["evidence", "outcome", "pack_id", "technique_pack", "payload_hints"]) {
      assert.equal(Object.prototype.hasOwnProperty.call(attemptEvent, field), false);
    }

    const selectedAfterAttempt = JSON.parse(selectTechniquePacks({
      target_domain: domain,
      surface_id: "surface-graphql",
      capability_pack: "web",
      include_attempted: false,
    }));
    assert.ok(selectedAfterAttempt.attempts_summary.omitted_attempted.some((entry) => entry.pack_id === "graphql"));

    assert.throws(
      () => logTechniqueAttempt({
        target_domain: domain,
        surface_id: "missing-surface",
        pack_id: "graphql",
        status: "selected",
        evidence: "Trying to log an invalid surface.",
      }),
      /Unknown surface_id/,
    );
    const invalidStatus = await executeTool("bounty_log_technique_attempt", {
      target_domain: domain,
      surface_id: "surface-graphql",
      pack_id: "graphql",
      status: "invalid",
      evidence: "Bad status.",
    });
    assert.equal(invalidStatus.ok, false);
    assert.equal(invalidStatus.error.code, "INVALID_ARGUMENTS");
  });
});

test("bounty_log_technique_attempt rejects packs incompatible with assigned capability pack", async () => {
  await withTempHome(async () => {
    await withTempTechniqueKnowledge({
      version: 1,
      entries: [
        {
          id: "web-pack",
          title: "Web pack",
          capability_packs: ["web"],
          match: { tech: ["json api"] },
          techniques: ["Exercise the web API route."],
          payload_hints: ["/api/export"],
        },
        {
          id: "evm-only-pack",
          title: "EVM-only pack",
          capability_packs: ["smart_contract_evm"],
          match: { tech: ["solidity"] },
          techniques: ["Exercise the EVM contract invariant."],
          payload_hints: ["forge test"],
        },
      ],
    }, async () => {
      const domain = "example.com";
      seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
      seedAttackSurfaces(domain, [{
        id: "surface-api",
        hosts: [`https://${domain}`],
        tech_stack: ["JSON API"],
        endpoints: ["/api"],
      }]);
      seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);

      const rejected = await executeTool("bounty_log_technique_attempt", {
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-api",
        pack_id: "evm-only-pack",
        status: "attempted",
        evidence: "Trying to log an EVM-only technique against a web assignment.",
      });
      assert.equal(rejected.ok, false);
      assert.equal(rejected.error.code, "INVALID_ARGUMENTS");
      assert.match(rejected.error.message, /not compatible with capability_pack web/);
      assert.equal(readTechniqueAttemptRecordsFromJsonl(domain).length, 0);

      const accepted = await executeTool("bounty_log_technique_attempt", {
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-api",
        pack_id: "web-pack",
        status: "attempted",
        evidence: "Logged the compatible web technique pack.",
      });
      assert.equal(accepted.ok, true);
      assert.equal(readTechniqueAttemptRecordsFromJsonl(domain).length, 1);
    });
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
    assert.deepEqual(result.coverage.unexplored_high_surface_ids, ["surface-b"]);
    assert.deepEqual(result.coverage.open_requeue_surface_ids, []);
    assert.equal(result.transition_blockers.some((item) => item.code === "unexplored_high_surfaces"), true);
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

test("bounty_wave_status returns open requeue coverage surface ids and transition blockers", () => {
  withTempHome(() => {
    const domain = "example.com";
    // surface-a has unfinished coverage and is NOT in `explored`, so the
    // surface is genuinely still open and the gate must block.
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      pending_wave: null,
      explored: [],
    });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "MEDIUM" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [{
        endpoint: "/api/export",
        method: "GET",
        bug_class: "idor",
        status: "requeue",
        evidence_summary: "late discovered export route",
      }],
    });

    const result = JSON.parse(waveStatus({ target_domain: domain }));
    assert.deepEqual(result.coverage.open_requeue_surface_ids, ["surface-a"]);
    assert.deepEqual(result.coverage.unexplored_high_surface_ids, []);
    assert.equal(result.transition_blockers.some((item) => item.code === "open_requeue_coverage"), true);
  });
});

test("bounty_wave_status excludes explored surfaces from open_requeue_surface_ids", () => {
  // The veda.tech regression: a surface had a `requeue` coverage row from
  // an earlier wave, then was closed by a `surface_status: complete`
  // handoff in a later wave (which populated state.explored). wave_status
  // used to keep the surface in open_requeue_surface_ids forever because
  // no later coverage row was written for the same (endpoint, bug_class)
  // tuple. The complete handoff is the authoritative "surface is closed"
  // signal — coverage rows are endpoint-level history, not surface state.
  withTempHome(() => {
    const domain = "explored-stale-coverage.example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 2,
      pending_wave: null,
      explored: ["surface-a"],
    });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "MEDIUM" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    seedAssignments(domain, 2, [{ agent: "a1", surface_id: "surface-a" }]);
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [{
        endpoint: "/api/legacy",
        method: "GET",
        bug_class: "idor",
        status: "requeue",
        evidence_summary: "endpoint-level requeue from earlier wave",
      }],
    });

    const result = JSON.parse(waveStatus({ target_domain: domain }));
    assert.deepEqual(result.coverage.open_requeue_surface_ids, []);
    assert.equal(
      result.transition_blockers.some((item) => item.code === "open_requeue_coverage"),
      false,
    );
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
