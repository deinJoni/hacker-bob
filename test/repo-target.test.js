const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  attackSurfacePath,
  repoCommandRunsJsonlPath,
  repoDockerfilePath,
  repoEnvPath,
  surfaceRoutesPath,
} = require("../mcp/lib/paths.js");
const {
  buildRepoInventory,
  initRepoSession,
  repoCheck,
} = require("../mcp/lib/repo-target.js");
const {
  prepareRepoEnv,
  repoDockerRun,
} = require("../mcp/lib/repo-env.js");
const {
  finalizeHunterRun,
} = require("../mcp/lib/hunter-completion.js");
const {
  logCoverage,
} = require("../mcp/lib/coverage.js");
const {
  logTechniqueAttempt,
} = require("../mcp/lib/technique-packs.js");
const {
  readFindings,
  recordFinding,
} = require("../mcp/lib/finding-store.js");
const {
  routeSurfaces,
} = require("../mcp/lib/surface-router.js");
const {
  readSessionState,
  transitionPhase,
} = require("../mcp/lib/session-state.js");
const {
  startNextWave,
  writeWaveHandoff,
} = require("../mcp/lib/waves.js");

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

test("reachability classifier stamps a MEDIUM ceiling and down-ranks a local-only native parser", () => withTempHome((home) => {
  const repo = path.join(home, "local-parser");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(local_parser C)\n");
  writeFile(repo, "src/decode.c", "int decode(const unsigned char *buf, int len){ return len > 0 ? buf[0] : 0; }\n");

  const init = JSON.parse(initRepoSession({ repo_path: repo, target_domain: "repo-local-parser" }));
  const inventory = JSON.parse(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.reachability.network_reachable, false);
  assert.equal(inventory.reachability.max_credible_severity_ceiling, "medium");

  const surfaces = JSON.parse(fs.readFileSync(attackSurfacePath(init.target_domain), "utf8")).surfaces;
  const native = surfaces.find((surface) => surface.id === "OSS-NATIVE-CODE");
  assert.ok(native, "expected OSS-NATIVE-CODE surface");
  assert.equal(native.network_reachable, false);
  assert.equal(native.attack_vector, "local");
  assert.equal(native.severity_ceiling, "medium");
  assert.equal(native.priority, "MEDIUM");
  assert.equal(native.ranking.score, 55);
}));

test("reachability classifier promotes a network-reachable native daemon to a CRITICAL ceiling", () => withTempHome((home) => {
  const repo = path.join(home, "net-daemon");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(net_daemon C)\n");
  writeFile(repo, "daemon/server.c", [
    "#include <sys/socket.h>",
    "#include <netinet/in.h>",
    "int serve(void){",
    "  int fd = socket(AF_INET, SOCK_STREAM, 0);",
    "  struct sockaddr_in a; a.sin_addr.s_addr = INADDR_ANY;",
    "  listen(fd, 16);",
    "  return fd;",
    "}",
    "",
  ].join("\n"));
  writeFile(repo, "src/proto.c", "int parse(const char *b, int n){ return n > 0 ? b[0] : 0; }\n");

  const init = JSON.parse(initRepoSession({ repo_path: repo, target_domain: "repo-net-daemon" }));
  const inventory = JSON.parse(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.reachability.network_reachable, true);
  assert.equal(inventory.reachability.max_credible_severity_ceiling, "critical");
  assert.ok(inventory.reachability.network_reachable_surface_ids.includes("OSS-NATIVE-CODE"));

  const surfaces = JSON.parse(fs.readFileSync(attackSurfacePath(init.target_domain), "utf8")).surfaces;
  const native = surfaces.find((surface) => surface.id === "OSS-NATIVE-CODE");
  assert.equal(native.network_reachable, true);
  assert.equal(native.attack_vector, "network");
  assert.equal(native.severity_ceiling, "critical");
  assert.equal(native.priority, "HIGH");
}));

test("project metadata files (AUTHORS) do not create a false OSS-AUTHZ surface", () => withTempHome((home) => {
  const repo = path.join(home, "authors-only");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "package.json", JSON.stringify({ name: "authors-only" }, null, 2));
  writeFile(repo, "AUTHORS.md", "# Authors\n- Jane Doe\n");

  const init = JSON.parse(initRepoSession({ repo_path: repo, target_domain: "repo-authors-only" }));
  const inventory = JSON.parse(buildRepoInventory({ target_domain: init.target_domain }));
  assert.ok(!inventory.surface_ids.includes("OSS-AUTHZ"), "AUTHORS must not trigger OSS-AUTHZ");
}));

test("residual hunting seeds recently-patched security fixes onto the native surface", () => withTempHome((home) => {
  const repo = path.join(home, "residual-parser");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(residual C)\n");
  writeFile(repo, "src/decode.c", "int decode(const unsigned char *b, int n){ return n > 0 ? b[0] : 0; }\n");
  writeFile(repo, "CHANGELOG.md", [
    "# Changelog",
    "",
    "## 2.4.4",
    "- Fix heap buffer overflow in decode_chunk() when len is attacker-controlled (CVE-2026-12345)",
    "- Improve documentation wording",
    "",
    "## 2.4.3",
    "- Minor performance refactor",
    "",
  ].join("\n"));

  const init = JSON.parse(initRepoSession({ repo_path: repo, target_domain: "repo-residual-parser" }));
  const inventory = JSON.parse(buildRepoInventory({ target_domain: init.target_domain }));
  assert.ok(inventory.counts.residual_hunt_targets >= 1, "expected at least one residual target");
  assert.ok(
    inventory.residual_hunt_targets.some((target) => /CVE-2026-12345|decode_chunk|overflow/i.test(target)),
    "residual targets must capture the patched security fix",
  );
  // A non-security changelog line must not be picked up as a residual lead.
  assert.ok(
    !inventory.residual_hunt_targets.some((target) => /performance refactor/i.test(target)),
    "non-security changelog lines must be ignored",
  );

  const surfaces = JSON.parse(fs.readFileSync(attackSurfacePath(init.target_domain), "utf8")).surfaces;
  const native = surfaces.find((surface) => surface.id === "OSS-NATIVE-CODE");
  assert.ok(
    Array.isArray(native.residual_hunt_targets) && native.residual_hunt_targets.length >= 1,
    "native surface must carry residual_hunt_targets for the hunter brief",
  );
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
  assert.ok(!dockerfile.includes("libpcap-dev"), "libnfs-like project must not pull libpcap-dev");
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

test("reachability classifier flips network_reachable on XDR/RPC stub calls (no raw socket tokens)", () => withTempHome((home) => {
  // An autogenerated RPC stub whose ONLY network evidence is multi-letter
  // xdr_*() calls — no socket()/listen()/htons/sockaddr_in. The content regex's
  // xdr_/evhttp_/uv_tcp_ prefix families must match real calls or this daemon is
  // mis-stamped AV:L / MEDIUM instead of AV:N / CRITICAL.
  const repo = path.join(home, "rpc-stub");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(rpc_stub C)\n");
  writeFile(repo, "src/nfs_xdr.c", [
    "#include <rpc/xdr.h>",
    "int xdr_nfs_arg(XDR *xdrs, struct nfs_arg *p){",
    "  if (!xdr_u_int(xdrs, &p->count)) return 0;",
    "  if (!xdr_bytes(xdrs, &p->data, &p->len, 65536)) return 0;",
    "  if (!xdr_string(xdrs, &p->name, 256)) return 0;",
    "  return 1;",
    "}",
    "",
  ].join("\n"));

  const init = JSON.parse(initRepoSession({ repo_path: repo, target_domain: "repo-rpc-stub" }));
  const inventory = JSON.parse(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.reachability.network_reachable, true, "xdr_*() calls must flip network_reachable");
  assert.equal(inventory.reachability.max_credible_severity_ceiling, "critical");

  const surfaces = JSON.parse(fs.readFileSync(attackSurfacePath(init.target_domain), "utf8")).surfaces;
  const native = surfaces.find((surface) => surface.id === "OSS-NATIVE-CODE");
  assert.equal(native.attack_vector, "network");
  assert.equal(native.severity_ceiling, "critical");
}));

test("residual git mine derives dir pathspec from the full native set, not the 120-file display cap", () => withTempHome((home) => {
  // Reproduce the alphabetical-sort + 120-cap starvation: pack >120 native files
  // into an alphabetically-early dir so a late dir (where the real security patch
  // lives) falls outside the capped display slice. The git pathspec must still
  // see the late dir, or incomplete-fix residual hunting goes blind on exactly
  // the netatalk-class daemons the feature targets. Skips when git is unusable.
  const { execFileSync } = require("child_process");
  const repo = path.join(home, "residual-cap");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(residual_cap C)\n");
  for (let i = 0; i < 125; i += 1) {
    writeFile(repo, `aaa/f${String(i).padStart(3, "0")}.c`, `int fn_${i}(void){ return ${i}; }\n`);
  }
  writeFile(repo, "zsec/decode.c", "int zsec_decode(const unsigned char *b, int n){ return n > 0 ? b[0] : 0; }\n");

  const gitEnv = {
    ...process.env,
    GIT_AUTHOR_NAME: "bob", GIT_AUTHOR_EMAIL: "bob@example.com",
    GIT_COMMITTER_NAME: "bob", GIT_COMMITTER_EMAIL: "bob@example.com",
    GIT_TERMINAL_PROMPT: "0",
  };
  const git = (...a) => execFileSync("git", ["-C", repo, ...a], { stdio: "ignore", env: gitEnv });
  try {
    git("init", "-q");
    git("add", "-A");
    git("-c", "commit.gpgsign=false", "commit", "-q", "-m", "initial import");
    // The security patch touches ONLY the late dir, so a pathspec that omits
    // zsec/ (the buggy capped behaviour) filters this commit out entirely.
    writeFile(repo, "zsec/decode.c", "int zsec_decode(const unsigned char *b, int n){ return n > 1 ? b[1] : 0; }\n");
    git("add", "-A");
    git("-c", "commit.gpgsign=false", "commit", "-q", "-m", "Fix heap buffer overflow in zsec_decode (CVE-2026-77777)");
  } catch {
    return; // git unavailable / unusable in this environment — skip
  }

  const init = JSON.parse(initRepoSession({ repo_path: repo, target_domain: "repo-residual-cap" }));
  const inventory = JSON.parse(buildRepoInventory({ target_domain: init.target_domain }));
  assert.ok(
    inventory.residual_hunt_targets.some((target) => /CVE-2026-77777|zsec_decode/i.test(target)),
    "residual mine must surface the security commit in the alphabetically-late dir",
  );
}));

test("OSS dynamic-proof gate rejects a repro that claims more than the recorded run executed", () => withTempHome((home) => {
  const context = createNativeRepoSession(home);
  // Only a benign build actually ran...
  appendRepoDockerRun(context.targetDomain, ["sh", "-lc", "cmake --build /work/build"]);
  // ...but the finding claims a superstring repro whose crash step never ran.
  // One-direction matching (run must contain the FULL repro) blocks this.
  assert.throws(
    () => recordFinding(nativeFindingInput(context, {
      repro_command: "cmake --build /work/build && /work/build/fuzzer crash-001.bin",
    })),
    /matching non-dry-run bounty_repo_docker_run entry before recording/,
  );
  // The honest case — the executed run contains the full claimed repro — passes.
  appendRepoDockerRun(context.targetDomain, ["sh", "-lc", "cmake --build /work/build && /work/build/fuzzer crash-001.bin"]);
  const recorded = JSON.parse(recordFinding(nativeFindingInput(context, {
    repro_command: "cmake --build /work/build && /work/build/fuzzer crash-001.bin",
  })));
  assert.equal(recorded.recorded, true);
}));

test("OSS dynamic-proof gate does not block an idempotent duplicate re-record", () => withTempHome((home) => {
  const context = createNativeRepoSession(home);
  appendRepoDockerRun(context.targetDomain, ["sh", "-lc", "/work/repro.sh"]);
  const first = JSON.parse(recordFinding(nativeFindingInput(context)));
  assert.equal(first.recorded, true);

  // Re-recording the same finding (dedupe_key ignores repro_command) with a
  // repro that has NO matching run must return the duplicate, not throw — the
  // proof gate now runs only for records that will be written, after dedup.
  const again = JSON.parse(recordFinding(nativeFindingInput(context, {
    repro_command: "/work/never-invoked.sh",
  })));
  assert.equal(again.duplicate, true);
  assert.equal(again.recorded, false);
}));

test("reachability ignores socket/server code that lives only in non-shipping dirs", () => withTempHome((home) => {
  const repo = path.join(home, "parser-with-demo-server");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(parser C)\n");
  writeFile(repo, "src/decode.c", "int decode(const unsigned char *b, int n){ return n > 0 ? b[0] : 0; }\n");
  // A demo TCP server shipped under examples/ must NOT make the library look
  // network-reachable — it is not part of the shipping parser (AV:L stays MEDIUM).
  writeFile(repo, "examples/echo_server.c", [
    "#include <sys/socket.h>",
    "#include <netinet/in.h>",
    "int main(void){",
    "  int fd = socket(AF_INET, SOCK_STREAM, 0);",
    "  struct sockaddr_in a; a.sin_addr.s_addr = INADDR_ANY;",
    "  listen(fd, 16);",
    "  return fd;",
    "}",
    "",
  ].join("\n"));

  const init = JSON.parse(initRepoSession({ repo_path: repo, target_domain: "repo-parser-demo-server" }));
  const inventory = JSON.parse(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.reachability.network_reachable, false, "demo server in examples/ must not flip reachability");
  assert.equal(inventory.reachability.max_credible_severity_ceiling, "medium");
}));

test("reachability does not treat C++ method calls (bus.listen) as a socket listener", () => withTempHome((home) => {
  const repo = path.join(home, "event-parser");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(events CXX)\n");
  writeFile(repo, "src/decode.cpp", "int decode(const unsigned char *b, int n){ return n > 0 ? b[0] : 0; }\n");
  // Only member-access .listen()/->socket() — never a bare listen(/socket(.
  writeFile(repo, "src/events.cpp", "void wire(Bus &bus, Bus *p){ bus.listen(nullptr); p->socket(0); }\n");

  const init = JSON.parse(initRepoSession({ repo_path: repo, target_domain: "repo-event-parser" }));
  const inventory = JSON.parse(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.reachability.network_reachable, false, "method-call .listen()/->socket() must not flip reachability");
  assert.equal(inventory.reachability.max_credible_severity_ceiling, "medium");
}));

test("reachability detects digit-typed XDR primitives (xdr_uint32_t / xdr_int64_t)", () => withTempHome((home) => {
  const repo = path.join(home, "rpc-fixedwidth");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(rpc C)\n");
  writeFile(repo, "src/proto_xdr.c", [
    "#include <rpc/xdr.h>",
    "int xdr_msg(XDR *xdrs, struct msg *m){",
    "  if (!xdr_uint32_t(xdrs, &m->id)) return 0;",
    "  if (!xdr_int64_t(xdrs, &m->ts)) return 0;",
    "  return 1;",
    "}",
    "",
  ].join("\n"));

  const init = JSON.parse(initRepoSession({ repo_path: repo, target_domain: "repo-rpc-fixedwidth" }));
  const inventory = JSON.parse(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.reachability.network_reachable, true, "xdr_uint32_t/xdr_int64_t must flip reachability");
  assert.equal(inventory.reachability.max_credible_severity_ceiling, "critical");
}));

test("reachability attributes per-path anchors (AV:N) and local-only dirs (AV:L) within one native surface", () => withTempHome((home) => {
  // A repo that is BOTH a daemon AND a local-file parser: the surface ceiling
  // stays best-case (CRITICAL), but the per-path map tells the hunter the daemon
  // dir is the AV:N target and the parser dir is an AV:L candidate (#7).
  const repo = path.join(home, "daemon-plus-parser");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(mixed C)\n");
  writeFile(repo, "daemon/server.c", [
    "#include <sys/socket.h>",
    "#include <netinet/in.h>",
    "int serve(void){",
    "  int fd = socket(AF_INET, SOCK_STREAM, 0);",
    "  struct sockaddr_in a; a.sin_addr.s_addr = INADDR_ANY;",
    "  listen(fd, 16);",
    "  return fd;",
    "}",
    "",
  ].join("\n"));
  writeFile(repo, "parsers/conf.c", "int parse_conf(const char *b, int n){ return n > 0 ? b[0] : 0; }\n");

  const init = JSON.parse(initRepoSession({ repo_path: repo, target_domain: "repo-daemon-plus-parser" }));
  const inventory = JSON.parse(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.reachability.network_reachable, true);
  assert.equal(inventory.reachability.max_credible_severity_ceiling, "critical");
  assert.ok(inventory.reachability.native_attack_vector_map, "inventory exposes the per-path map");

  const surfaces = JSON.parse(fs.readFileSync(attackSurfacePath(init.target_domain), "utf8")).surfaces;
  const native = surfaces.find((surface) => surface.id === "OSS-NATIVE-CODE");
  assert.equal(native.severity_ceiling, "critical", "surface ceiling stays best-case");
  assert.ok(native.network_reachable_anchors.includes("daemon/server.c"), "daemon file is a network anchor");
  assert.ok(native.network_reachable_dirs.includes("daemon"), "daemon dir flagged AV:N");
  assert.ok(native.local_only_candidate_dirs.includes("parsers"), "parser dir flagged AV:L candidate");
  assert.ok(!native.local_only_candidate_dirs.includes("daemon"), "daemon dir is not a local-only candidate");
}));
