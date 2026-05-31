const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  attackSurfacePath,
  buildRepoInventory,
  finalizeHunterRun,
  initRepoSession,
  logCoverage,
  logTechniqueAttempt,
  prepareRepoEnv,
  readFindings,
  readSessionState,
  recordFinding,
  repoCommandRunsJsonlPath,
  repoCheck,
  repoDockerfilePath,
  repoDockerRun,
  repoEnvPath,
  routeSurfaces,
  startNextWave,
  surfaceRoutesPath,
  transitionPhase,
  writeWaveHandoff,
} = require("../mcp/server.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-oss-test-"));
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

function writeFile(root, relativePath, content) {
  const filePath = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content, "utf8");
}

function createNativeRepoSession(home, targetDomain = "repo-native-proof-test") {
  const repo = path.join(home, targetDomain);
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(native_proof C)\n");
  writeFile(repo, "src/parser.c", "int parse_packet(const char *buf, int len) { return len > 0 ? buf[0] : 0; }\n");

  const init = JSON.parse(initRepoSession({ repo_path: repo, target_domain: targetDomain }));
  JSON.parse(buildRepoInventory({ target_domain: init.target_domain }));
  JSON.parse(routeSurfaces({ target_domain: init.target_domain }));
  JSON.parse(transitionPhase({ target_domain: init.target_domain, to_phase: "AUTH" }));
  JSON.parse(transitionPhase({ target_domain: init.target_domain, to_phase: "HUNT", auth_status: "unauthenticated" }));

  const wave = JSON.parse(startNextWave({ target_domain: init.target_domain }));
  const assignment = wave.assignments.find((item) => item.surface_id === "OSS-NATIVE-CODE");
  assert.ok(assignment, "expected OSS-NATIVE-CODE assignment");
  assert.equal(assignment.capability_pack, "oss_native_code");

  return {
    targetDomain: init.target_domain,
    repo,
    wave: `w${wave.wave_number}`,
    assignment,
  };
}

function appendRepoDockerRun(domain, command, overrides = {}) {
  fs.appendFileSync(repoCommandRunsJsonlPath(domain), `${JSON.stringify({
    version: 1,
    ts: new Date().toISOString(),
    target_domain: domain,
    runner: "docker",
    run_id: "run-test",
    dry_run: false,
    status: "failed",
    command,
    timed_out: false,
    ...overrides,
  })}\n`);
}

function nativeFindingInput(context, overrides = {}) {
  return {
    target_domain: context.targetDomain,
    wave: context.wave,
    agent: context.assignment.agent,
    surface_id: context.assignment.surface_id,
    title: "Out-of-bounds read in packet parser",
    severity: "high",
    cwe: "CWE-125",
    endpoint: "src/parser.c",
    file_path: "src/parser.c",
    symbol: "parse_packet",
    repro_command: "/work/repro.sh",
    description: "The packet parser reads attacker-controlled packet bytes past the available buffer.",
    proof_of_concept: "Compile the ASAN harness and run /work/repro.sh against the crafted packet.",
    response_evidence: "AddressSanitizer: heap-buffer-overflow in parse_packet",
    impact: "Remote input can crash the process and may disclose adjacent memory.",
    validated: true,
    ...overrides,
  };
}

test("repo session inventory emits OSS surfaces and routes to OSS packs", () => withTempHome((home) => {
  const repo = path.join(home, "sample-project");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "package.json", JSON.stringify({
    name: "sample-project",
    scripts: { test: "node --test", release: "npm publish" },
    dependencies: { express: "^4.18.0", jsonwebtoken: "^9.0.0" },
  }, null, 2));
  writeFile(repo, "package-lock.json", "{}\n");
  writeFile(repo, "src/routes/users.ts", "router.get('/api/users/:id', requireAuth, users.show)\n");
  writeFile(repo, "src/auth/middleware.ts", "export function requireAuth(req, res, next) { next() }\n");
  writeFile(repo, ".github/workflows/ci.yml", "on: [pull_request]\npermissions: write-all\n");
  writeFile(repo, ".env.example", "JWT_SECRET=\nDATABASE_URL=\n");
  writeFile(repo, "README.md", "# Sample\n\nSecurity notes.\n");

  const init = JSON.parse(initRepoSession({ repo_path: repo }));
  assert.match(init.target_domain, /^repo-sample-project-[a-f0-9]{12}$/);

  const state = JSON.parse(readSessionState({ target_domain: init.target_domain })).state;
  assert.equal(state.target_kind, "repo");
  assert.equal(state.repo.root_path, fs.realpathSync(repo));

  const inventory = JSON.parse(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.counts.surfaces, 6);
  assert.deepEqual(inventory.surface_ids.sort(), [
    "OSS-API-SCHEMA",
    "OSS-AUTHZ",
    "OSS-CI-CD",
    "OSS-DEPENDENCY",
    "OSS-DOCS-BEHAVIOR",
    "OSS-SECRETS-CONFIG",
  ].sort());

  const attackSurface = JSON.parse(fs.readFileSync(attackSurfacePath(init.target_domain), "utf8"));
  assert.equal(attackSurface.target_kind, "repo");
  assert.ok(attackSurface.surfaces.every((surface) => surface.hosts.includes("repo://local")));

  const routed = JSON.parse(routeSurfaces({ target_domain: init.target_domain }));
  assert.equal(routed.counts.oss_dependency, 1);
  assert.equal(routed.counts.oss_authz, 1);
  assert.equal(routed.counts.oss_ci_cd, 1);

  const routes = JSON.parse(fs.readFileSync(surfaceRoutesPath(init.target_domain), "utf8"));
  assert.ok(routes.routes.some((route) => route.capability_pack === "oss_secrets_config"));

  const check = JSON.parse(repoCheck({
    target_domain: init.target_domain,
    file_path: "package.json",
    pattern: "release",
  }));
  assert.equal(check.check.ok, true);
  assert.equal(check.check.reason, "pattern_found");
}));

test("repo Docker environment plan and dry-run command stay session-scoped", () => withTempHome(async (home) => {
  const repo = path.join(home, "libnfs-like");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(libnfs_like C)\n");
  writeFile(repo, "libnfs.pc.in", "Name: libnfs-like\n");
  writeFile(repo, "src/client.c", "int main(void) { return 0; }\n");

  const init = JSON.parse(initRepoSession({ repo_path: repo, target_domain: "repo-docker-test" }));
  const inventory = JSON.parse(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.counts.native_source_files, 1);
  assert.equal(inventory.counts.native_build_files, 1);
  assert.ok(inventory.surface_ids.includes("OSS-NATIVE-CODE"));
  assert.ok(JSON.parse(fs.readFileSync(attackSurfacePath(init.target_domain), "utf8")).surfaces.some((surface) => (
    surface.id === "OSS-NATIVE-CODE" &&
    surface.surface_type === "oss_native_code" &&
    surface.bug_class_hints.includes("integer_truncation")
  )));
  const routed = JSON.parse(routeSurfaces({ target_domain: init.target_domain }));
  assert.equal(routed.counts.oss_native_code, 1);

  const env = JSON.parse(await prepareRepoEnv({
    target_domain: init.target_domain,
    build_image: true,
    dry_run: true,
  }));
  assert.equal(env.env.docker_build.status, "dry_run");
  assert.equal(env.env.defaults.repo_mount_mode, "read_only");
  assert.ok(fs.existsSync(repoEnvPath(init.target_domain)));
  assert.ok(fs.existsSync(repoDockerfilePath(init.target_domain)));
  const dockerfile = fs.readFileSync(repoDockerfilePath(init.target_domain), "utf8");
  assert.match(dockerfile, /FROM ubuntu:24\.04/);
  assert.match(dockerfile, /cmake/);
  assert.match(dockerfile, /libkrb5-dev/);
  assert.ok(env.env.recommended_commands.some((command) => command.id === "cmake-build-test"));

  const run = JSON.parse(await repoDockerRun({
    target_domain: init.target_domain,
    command: ["sh", "-lc", "cmake --version"],
    dry_run: true,
  }));
  assert.equal(run.run.status, "dry_run");
  assert.deepEqual(run.run.command, ["sh", "-lc", "cmake --version"]);
  assert.ok(run.run.docker_command.includes("--network"));
  assert.ok(run.run.docker_command.includes("none"));
  assert.ok(run.run.docker_command.some((arg) => arg.endsWith(":/src:ro")));
  assert.ok(fs.existsSync(repoCommandRunsJsonlPath(init.target_domain)));
  const log = fs.readFileSync(repoCommandRunsJsonlPath(init.target_domain), "utf8");
  assert.match(log, /"status":"dry_run"/);
}));

test("repo Docker plan ships libpcap-dev when the build links libpcap", () => withTempHome(async (home) => {
  const repo = path.join(home, "pcap-sniffer");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "configure.ac", "AC_INIT([pcap-sniffer],[1.0])\nAC_CHECK_LIB([pcap],[pcap_open_live])\n");
  writeFile(repo, "Makefile.in", "LIBS = -lpcap\nall:\n\t$(CC) -o sniff sniff.c $(LIBS)\n");
  writeFile(repo, "sniff.c", "#include <pcap.h>\nint main(void) { return 0; }\n");

  const init = JSON.parse(initRepoSession({ repo_path: repo, target_domain: "repo-pcap-test" }));
  JSON.parse(buildRepoInventory({ target_domain: init.target_domain }));

  const env = JSON.parse(await prepareRepoEnv({ target_domain: init.target_domain }));
  assert.equal(env.env.detected.source_hints.pcap_like, true);
  assert.ok(env.env.packages.includes("libpcap-dev"), "expected libpcap-dev in the package list");

  const dockerfile = fs.readFileSync(repoDockerfilePath(init.target_domain), "utf8");
  assert.match(dockerfile, /libpcap-dev/);
}));

test("high severity OSS native findings require matching non-dry-run repo replay", () => withTempHome((home) => {
  const context = createNativeRepoSession(home);

  assert.throws(
    () => recordFinding(nativeFindingInput(context, { repro_command: null })),
    /high\/critical oss_native_code findings require repro_command backed by a non-dry-run bounty_repo_docker_run/,
  );
  assert.throws(
    () => recordFinding(nativeFindingInput(context)),
    /matching non-dry-run bounty_repo_docker_run entry before recording/,
  );

  appendRepoDockerRun(context.targetDomain, ["sh", "-lc", "/work/repro.sh"]);
  const recorded = JSON.parse(recordFinding(nativeFindingInput(context)));
  const findings = JSON.parse(readFindings({ target_domain: context.targetDomain })).findings;

  assert.equal(recorded.recorded, true);
  assert.equal(findings[0].severity, "high");
  assert.equal(findings[0].capability_pack, "oss_native_code");
  assert.equal(findings[0].repro_command, "/work/repro.sh");
}));

test("OSS hunters cannot finalize complete surfaces with zero coverage and zero findings", () => withTempHome((home) => {
  const context = createNativeRepoSession(home, "repo-native-coverage-test");

  JSON.parse(logTechniqueAttempt({
    target_domain: context.targetDomain,
    wave: context.wave,
    agent: context.assignment.agent,
    surface_id: context.assignment.surface_id,
    pack_id: "oss-native-code-protocol-memory",
    status: "attempted",
    evidence: "Reviewed parser.c and planned ASAN replay, but no concrete coverage was logged yet.",
    outcome: "No issue recorded",
  }));
  JSON.parse(writeWaveHandoff({
    target_domain: context.targetDomain,
    wave: context.wave,
    agent: context.assignment.agent,
    surface_id: context.assignment.surface_id,
    handoff_token: context.assignment.handoff_token,
    surface_status: "complete",
    summary: "Static pass only.",
    content: "# Static pass only\n",
  }));

  assert.throws(
    () => finalizeHunterRun({
      target_domain: context.targetDomain,
      wave: context.wave,
      agent: context.assignment.agent,
      surface_id: context.assignment.surface_id,
    }),
    /cannot mark OSS surface OSS-NATIVE-CODE complete with zero coverage rows and zero findings/,
  );

  JSON.parse(logCoverage({
    target_domain: context.targetDomain,
    wave: context.wave,
    agent: context.assignment.agent,
    surface_id: context.assignment.surface_id,
    entries: [{
      endpoint: "src/parser.c",
      bug_class: "memory_safety",
      status: "blocked",
      evidence_summary: "ASAN replay command identified, but harness build was blocked by missing Docker runtime in the test fixture.",
      next_step: "Run /work/repro.sh in the prepared repo Docker image.",
    }],
  }));
  const finalized = JSON.parse(finalizeHunterRun({
    target_domain: context.targetDomain,
    wave: context.wave,
    agent: context.assignment.agent,
    surface_id: context.assignment.surface_id,
  }));

  assert.equal(finalized.status, "allowed");
  assert.equal(finalized.handoff.surface_status, "complete");
}));
