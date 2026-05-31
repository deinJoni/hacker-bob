"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const {
  assertNonEmptyString,
  assertBoolean,
  normalizeOptionalText,
} = require("./validation.js");
const {
  attackSurfacePath,
  repoChecksJsonlPath,
  repoInventoryPath,
  sessionsRoot,
} = require("./paths.js");
const {
  appendJsonlLine,
  withSessionLock,
  writeFileAtomic,
} = require("./storage.js");
const {
  initSession,
  readSessionStateStrict,
} = require("./session-state.js");

const REPO_INVENTORY_VERSION = 1;
const REPO_CHECK_LOG_MAX_RECORDS = 1000;
const MAX_WALK_FILES = 5000;
const MAX_FILE_BYTES = 250000;
const MAX_MATCHES = 20;

const IGNORED_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  "vendor",
  "dist",
  "build",
  ".next",
  ".nuxt",
  "coverage",
  ".cache",
  ".turbo",
  ".venv",
  "venv",
  "__pycache__",
  "target",
]);

const MANIFEST_NAMES = new Set([
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lockb",
  "requirements.txt",
  "pyproject.toml",
  "Pipfile",
  "poetry.lock",
  "go.mod",
  "go.sum",
  "Cargo.toml",
  "Cargo.lock",
  "Gemfile",
  "Gemfile.lock",
  "composer.json",
  "composer.lock",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
]);

const DOC_NAMES = new Set([
  "README.md",
  "SECURITY.md",
  "CONTRIBUTING.md",
  "CHANGELOG.md",
  "docs/README.md",
]);

const NATIVE_CODE_EXTENSIONS = new Set([
  ".c",
  ".cc",
  ".cpp",
  ".cxx",
  ".h",
  ".hh",
  ".hpp",
  ".ipp",
  ".inl",
]);

const NATIVE_BUILD_FILE_RE = /(^|\/)(CMakeLists\.txt|Makefile|Makefile\.am|configure|configure\.ac|configure\.in|meson\.build|meson_options\.txt|SConstruct|SConscript)$/;

// --- Reachability + severity-ceiling classification ----------------------
// A memory-safety bug's realistic severity ceiling is set by HOW attacker
// input reaches it. A network-reachable listener (daemon/server/RPC) feeding a
// parser is AV:N (CRITICAL-capable); a pure local-file parser library is AV:L
// (MEDIUM-realistic). Bob historically stamped every native surface a flat
// HIGH, so a .dwg reader looked identical to an NFS daemon and the planner
// burned its top slot proving an OOB-read that could only ever grade MEDIUM.
// These helpers stamp each surface with network_reachable / attack_vector /
// severity_ceiling so routing and the operator can triage the ceiling up front.
// Socket/RPC/TLS call signals. Bare `bind`/`accept`/`recv` are intentionally
// excluded — they collide with std::bind, visitor.accept, etc. The tokens in
// NETWORK_TOKEN_RE carry the socket-setup confidence instead.
// Prefix families (xdr_*, evhttp_*, uv_tcp_*) must consume the rest of the
// identifier — including digits, e.g. xdr_uint32_t / xdr_int64_t — before
// `\s*\(`; a bare prefix only matches nonexistent literals like `xdr_x(`.
const NETWORK_CONTENT_RE = /\b(accept4|recvfrom|recvmsg|WSAStartup|getaddrinfo|svc_run|svc_register|svc_create|xdr_[a-z0-9_]+|clnt_create|rpcb_set|MHD_start_daemon|evhttp_[a-z0-9_]+|uv_tcp_[a-z0-9_]+|SSL_accept|gnutls_handshake|bindresvport)\s*\(/;
// socket()/listen() are the only libc tokens common enough to double as C++
// method names (emitter.listen(), acceptor.socket()); require they not be
// member-/pointer-/identifier-prefixed so event helpers don't read as daemons.
const NETWORK_SOCKET_RE = /(?<![\w.>])(socket|listen)\s*\(/;
const NETWORK_TOKEN_RE = /\b(INADDR_ANY|SOCK_STREAM|SOCK_DGRAM|AF_INET6?|sockaddr_in6?|htons|in_port_t)\b/;
// Bundled test/example/fuzz/benchmark code routinely contains socket/server
// code that is NOT part of the shipping daemon or library; excluding these dirs
// from the reachability scan stops a local-file parser that ships a demo server
// from being mis-stamped network-reachable (AV:N/CRITICAL).
const NON_SHIPPING_DIR_RE = /(^|\/)(tests?|examples?|samples?|demos?|fuzz|fuzzing|benchmarks?|contrib|third[_-]?party|3rdparty|fixtures?|testdata)\//i;
const SERVICE_UNIT_RE = /(^|\/)[^/]+\.(service|socket)$/;
const SERVER_PATH_RE = /(^|\/)(daemon|daemons|server|servers|httpd|net|rpc|proto|protocol|listener|ipc)\//i;
const SERVER_FILE_RE = /(^|\/)[^/]*(server|daemon|listener|socket|httpd|rpcsvc)[^/]*\.(c|cc|cpp|cxx|h|hpp)$/i;
const ENTRYPOINT_FILE_RE = /(^|\/)(main|app|service|net|socket|server|daemon|rpc|http|listen)\w*\.(c|cc|cpp|cxx)$/i;
const DOCKERFILE_RE = /(^|\/)Dockerfile([.-][\w.-]+)?$/;
const NETWORK_SCAN_LIMIT = 50;
const NETWORK_FALLBACK_LIMIT = 80;

const CEILING_RANK = Object.freeze({ critical: 4, high: 3, medium: 2, low: 1, none: 0 });

function maxCeiling(a, b) {
  return (CEILING_RANK[b] || 0) > (CEILING_RANK[a] || 0) ? b : a;
}

// Stamp the realistic severity ceiling for a surface given its reachability.
// Ceiling is the best credible case for that surface class; the verifier/grader
// still set the actual severity from proven impact.
function severityCeilingForSurface(surfaceType, networkReachable) {
  switch (surfaceType) {
    case "oss_native_code":
      return networkReachable ? "critical" : "medium";
    case "oss_api_schema":
    case "oss_authz":
      return networkReachable ? "high" : "medium";
    case "oss_dependency":
    case "oss_ci_cd":
      // Supply-chain (release-pipeline MITM / workflow injection) is real but
      // realistically grades MEDIUM in the corpus (libarchive, exiv2) and is
      // gated on a maintainer/release action — keep it medium so it does not
      // mask a memory-safety target's true (capped) ceiling in the warning.
      return "medium";
    case "oss_secrets_config":
      return "medium";
    case "oss_docs_behavior":
      return "low";
    default:
      return "medium";
  }
}

function attackVectorForSurface(surfaceType, networkReachable) {
  if (surfaceType === "oss_dependency" || surfaceType === "oss_ci_cd") return "supply_chain";
  if (surfaceType === "oss_native_code" || surfaceType === "oss_api_schema" || surfaceType === "oss_authz") {
    return networkReachable ? "network" : "local";
  }
  return "local";
}

// Per-path reachability attribution. The repo-wide severity_ceiling stays the
// best-case (max-credible) ceiling; this map tells the hunter WHICH files/dirs
// carry the listener (pursue the CRITICAL primitive there) and which native dirs
// look local-only (record an honest MEDIUM), so a repo that is both a daemon and
// a pile of local parsers is not blanket-steered with one verdict. Flat string
// arrays only — the brief copies scalars/arrays by default but skips objects.
const REACH_ANCHOR_PREFIXES = ["net_call:", "server_path:", "systemd_unit:", "expose:"];

function dirPrefixesAtDepth(files, maxDepth, cap) {
  const dirs = new Set();
  for (const file of files) {
    if (!file.includes("/")) continue;
    const parts = file.split("/");
    dirs.add(parts.slice(0, Math.min(maxDepth, parts.length - 1)).join("/"));
  }
  return Array.from(dirs).slice(0, cap);
}

function reachabilityAttribution(signals, nativeFiles) {
  const anchors = [];
  for (const signal of signals) {
    const prefix = REACH_ANCHOR_PREFIXES.find((p) => signal.startsWith(p));
    if (prefix) anchors.push(signal.slice(prefix.length));
  }
  const anchorFiles = Array.from(new Set(anchors));
  const reachableDirs = dirPrefixesAtDepth(anchorFiles, 2, 20);
  const localDirs = dirPrefixesAtDepth(nativeFiles, 2, 200).filter(
    (dir) => !reachableDirs.some((rd) => dir === rd || dir.startsWith(`${rd}/`) || rd.startsWith(`${dir}/`)),
  ).slice(0, 20);
  return {
    network_reachable_anchors: anchorFiles.slice(0, 20),
    network_reachable_dirs: reachableDirs,
    local_only_candidate_dirs: localDirs,
  };
}

// Scan a repo for evidence of an in-process network listener that could feed
// attacker-controlled input into a parser. Bounded I/O: priority files first
// (path/name suggests a server), then a capped fallback sweep of native files.
function detectNetworkReachability(repoPath, files) {
  const signals = [];
  // Reachability must reflect the SHIPPING daemon/library, not bundled test
  // harnesses, examples, or fuzzers (which routinely contain socket/server code).
  const shippingFiles = files.filter((file) => !NON_SHIPPING_DIR_RE.test(file));
  const nativeFiles = shippingFiles.filter((file) => NATIVE_CODE_EXTENSIONS.has(path.extname(file).toLowerCase()));
  for (const file of shippingFiles) {
    if (SERVICE_UNIT_RE.test(file)) signals.push(`systemd_unit:${file}`);
  }
  const priority = nativeFiles.filter((file) => SERVER_PATH_RE.test(file) || SERVER_FILE_RE.test(file));
  for (const file of priority) signals.push(`server_path:${file}`);
  const dockerfiles = shippingFiles.filter((file) => DOCKERFILE_RE.test(file));
  const scanList = Array.from(new Set([
    ...priority,
    ...nativeFiles.filter((file) => ENTRYPOINT_FILE_RE.test(file)),
    ...dockerfiles,
  ])).slice(0, NETWORK_SCAN_LIMIT);
  let netHit = false;
  for (const file of scanList) {
    const text = safeReadText(repoPath, file, 150000);
    if (!text) continue;
    if (DOCKERFILE_RE.test(file)) {
      if (/\bEXPOSE\s+\d/.test(text)) { signals.push(`expose:${file}`); netHit = true; }
      continue;
    }
    if (NETWORK_CONTENT_RE.test(text) || NETWORK_SOCKET_RE.test(text) || NETWORK_TOKEN_RE.test(text)) {
      signals.push(`net_call:${file}`);
      netHit = true;
      if (signals.length >= 14) break;
    }
  }
  if (!netHit) {
    for (const file of nativeFiles.slice(0, NETWORK_FALLBACK_LIMIT)) {
      const text = safeReadText(repoPath, file, 150000);
      if (!text) continue;
      if (NETWORK_CONTENT_RE.test(text) || NETWORK_SOCKET_RE.test(text)) { signals.push(`net_call:${file}`); netHit = true; break; }
    }
  }
  const signalsOut = Array.from(new Set(signals)).slice(0, 14);
  const reachable = netHit || signals.some((s) => s.startsWith("systemd_unit:"));
  return {
    network_reachable: reachable,
    signals: signalsOut,
    attribution: reachable ? reachabilityAttribution(signalsOut, nativeFiles) : null,
  };
}

// --- Incomplete-fix residual hunting seed ---------------------------------
// The highest-yield HIGH method in Bob's corpus (netatalk's 2 HIGH) is finding
// the sibling/adjacent code paths a recent security patch did NOT cover. Mine
// the repo's own recent history + changelog for security fixes and hand the
// hunter concrete recently-patched anchors to sibling-hunt. Output is an array
// of concise STRINGS (the brief caps array items via String()).
const SECURITY_KEYWORD_RE = /\b(CVE-\d{4}-\d+|GHSA-[\w-]+|overflow|out[- ]of[- ]bounds|\bOOB\b|use[- ]after[- ]free|\bUAF\b|double[- ]free|buffer overrun|heap corruption|integer (?:overflow|underflow)|bounds[- ]check|sanitiz(?:e|er)|memory safety|security (?:fix|issue)|vulnerabilit|null (?:deref|pointer)|segfault|infinite loop|denial of service|\bDoS\b|malformed|crafted)/i;
const RESIDUAL_DOC_NAMES = new Set([
  "CHANGELOG.md", "CHANGELOG", "ChangeLog", "CHANGES", "CHANGES.md",
  "NEWS", "NEWS.md", "SECURITY.md", "RELEASE_NOTES.md", "HISTORY.md",
]);
const RESIDUAL_GIT_TIMEOUT_MS = 15000;
const RESIDUAL_MAX_TARGETS = 18;
const RESIDUAL_GIT_PATHSPEC_MAX = 40;

function extractResidualFromDocs(repoPath, files) {
  const leads = [];
  const docCandidates = files.filter((file) => RESIDUAL_DOC_NAMES.has(path.basename(file)));
  for (const file of docCandidates.slice(0, 6)) {
    const text = safeReadText(repoPath, file, 200000);
    if (!text) continue;
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length && leads.length < 12; i += 1) {
      const line = lines[i].trim().replace(/^[-*#\s]+/, "");
      if (line.length < 8) continue;
      if (SECURITY_KEYWORD_RE.test(line)) {
        leads.push(`changelog:${path.basename(file)}: ${line.slice(0, 200)}`);
      }
    }
  }
  return leads;
}

// Build a git pathspec that targets where native source actually lives. Prefer
// depth-2 dirs (e.g. src/parsers) for precision; collapse to top-level dirs if a
// wide flat layout would blow the pathspec budget. Root-level native files are
// passed as explicit paths. Never fall back to "." (whole repo) — that drags
// doc/vendor churn in as false residual seeds.
function residualGitPathspec(nativeSourceFiles) {
  const depth1 = new Set();
  const depth2 = new Set();
  const rootFiles = [];
  for (const file of nativeSourceFiles) {
    if (!file.includes("/")) { rootFiles.push(file); continue; }
    const parts = file.split("/");
    depth1.add(parts[0]);
    depth2.add(parts.slice(0, Math.min(2, parts.length - 1)).join("/"));
  }
  const dirs = depth2.size <= RESIDUAL_GIT_PATHSPEC_MAX ? depth2 : depth1;
  return [
    ...Array.from(dirs).slice(0, RESIDUAL_GIT_PATHSPEC_MAX),
    ...rootFiles.slice(0, RESIDUAL_GIT_PATHSPEC_MAX),
  ];
}

function extractResidualFromGit(repoPath, nativeSourceFiles) {
  if (!fs.existsSync(path.join(repoPath, ".git"))) return [];
  const pathspec = residualGitPathspec(nativeSourceFiles);
  if (pathspec.length === 0) return [];
  let out = "";
  try {
    out = execFileSync("git", [
      "-C", repoPath, "log", "--no-merges",
      "--since=9 months ago", "--max-count=600",
      "--pretty=format:%h%x1f%s",
      "--", ...pathspec,
    ], {
      encoding: "utf8",
      timeout: RESIDUAL_GIT_TIMEOUT_MS,
      maxBuffer: 8 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    return [];
  }
  const leads = [];
  for (const line of out.split(/\r?\n/)) {
    if (!line) continue;
    const sep = line.indexOf("\x1f");
    if (sep < 0) continue;
    const hash = line.slice(0, sep);
    const subject = line.slice(sep + 1);
    if (subject && SECURITY_KEYWORD_RE.test(subject)) {
      leads.push(`git:${hash}: ${subject.slice(0, 200)}`);
      if (leads.length >= 15) break;
    }
  }
  return leads;
}

// Recently-patched security anchors (git commits first — most precise — then
// changelog lines). The hunter sibling-hunts these: same struct, adjacent
// count/length field, parallel branch the patch did not bound.
function extractResidualHuntTargets(repoPath, files, nativeSourceFiles) {
  // nativeSourceFiles is the UNCAPPED native set (computed once by the caller).
  // The 120-cap display slice must NOT be used here — on a large daemon
  // (netatalk-class) the alphabetically-first 120 files starve recently-patched
  // dirs like libatalk/ or sys/, and incomplete-fix residual hunting is the
  // highest-yield HIGH method in the corpus, so that bias matters most here.
  const gitLeads = extractResidualFromGit(repoPath, nativeSourceFiles);
  const docLeads = extractResidualFromDocs(repoPath, files);
  return Array.from(new Set([...gitLeads, ...docLeads])).slice(0, RESIDUAL_MAX_TARGETS);
}

function shortHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex").slice(0, 12);
}

function slugify(value) {
  const slug = String(value || "repo")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
  return slug || "repo";
}

function normalizeRepoPath(repoPath) {
  const raw = assertNonEmptyString(repoPath, "repo_path");
  const resolved = path.resolve(raw);
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
    throw new Error(`repo_path must be an existing directory: ${resolved}`);
  }
  const real = fs.realpathSync(resolved);
  const sessionsBase = path.resolve(sessionsRoot());
  if (fs.existsSync(sessionsBase)) {
    const sessions = fs.realpathSync(sessionsBase);
    if (real === sessions || real.startsWith(`${sessions}${path.sep}`)) {
      throw new Error("repo_path must not point inside Bob session storage");
    }
  }
  return real;
}

function makeRepoTargetId(repoPath, explicitTargetId = null) {
  const explicit = normalizeOptionalText(explicitTargetId, "target_domain");
  if (explicit) {
    if (/[\/\\]/.test(explicit) || /(?:^|\.)\.\.(?:\.|$)/.test(explicit)) {
      throw new Error(`target_domain contains invalid path characters: ${explicit}`);
    }
    return explicit;
  }
  const basename = slugify(path.basename(repoPath));
  return `repo-${basename}-${shortHash(repoPath)}`;
}

function readGitMetadata(repoPath) {
  const gitDir = path.join(repoPath, ".git");
  if (!fs.existsSync(gitDir)) return {};
  try {
    const head = fs.readFileSync(path.join(gitDir, "HEAD"), "utf8").trim();
    if (head.startsWith("ref: ")) {
      const ref = head.slice("ref: ".length);
      const branch = ref.split("/").pop() || null;
      const refPath = path.join(gitDir, ref);
      const commit = fs.existsSync(refPath) ? fs.readFileSync(refPath, "utf8").trim() : null;
      return { branch, commit };
    }
    return { commit: head };
  } catch {
    return {};
  }
}

function initRepoSession(args) {
  const repoPath = normalizeRepoPath(args.repo_path);
  const targetDomain = makeRepoTargetId(repoPath, args.target_domain || args.target_id);
  const sourceUrl = normalizeOptionalText(args.source_url, "source_url");
  const git = readGitMetadata(repoPath);
  const result = JSON.parse(initSession({
    target_domain: targetDomain,
    target_url: `repo://${targetDomain}`,
    target_kind: "repo",
    deep_mode: args.deep_mode === true,
    repo: {
      root_path: repoPath,
      source_url: sourceUrl,
      branch: normalizeOptionalText(args.branch, "branch") || git.branch,
      commit: normalizeOptionalText(args.commit, "commit") || git.commit,
    },
  }));
  return JSON.stringify({
    ...result,
    target_domain: targetDomain,
    repo_path: repoPath,
  }, null, 2);
}

function walkRepoFiles(repoPath) {
  const files = [];
  const visit = (dir) => {
    if (files.length >= MAX_WALK_FILES) return;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (files.length >= MAX_WALK_FILES) break;
      const full = path.join(dir, entry.name);
      const relative = path.relative(repoPath, full).split(path.sep).join("/");
      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name)) visit(full);
      } else if (entry.isFile()) {
        files.push(relative);
      }
    }
  };
  visit(repoPath);
  return files.sort();
}

function safeReadText(repoPath, relativePath, maxBytes = MAX_FILE_BYTES) {
  const full = resolveRepoFile(repoPath, relativePath);
  const stat = fs.statSync(full);
  if (!stat.isFile() || stat.size > maxBytes) return null;
  const buffer = fs.readFileSync(full);
  if (buffer.includes(0)) return null;
  return buffer.toString("utf8");
}

function parsePackageJson(repoPath, relativePath) {
  try {
    const parsed = JSON.parse(safeReadText(repoPath, relativePath) || "{}");
    const deps = [
      ...Object.keys(parsed.dependencies || {}),
      ...Object.keys(parsed.devDependencies || {}),
      ...Object.keys(parsed.peerDependencies || {}),
      ...Object.keys(parsed.optionalDependencies || {}),
    ].sort();
    return {
      file: relativePath,
      name: typeof parsed.name === "string" ? parsed.name : null,
      scripts: Object.keys(parsed.scripts || {}).sort(),
      dependencies: Array.from(new Set(deps)).slice(0, 200),
    };
  } catch {
    return { file: relativePath, parse_error: true };
  }
}

function detectTechStack(files, packageManifests) {
  const stack = new Set();
  if (files.some((f) => f.endsWith("package.json"))) stack.add("JavaScript/Node.js");
  if (files.some((f) => f.endsWith("tsconfig.json"))) stack.add("TypeScript");
  if (files.some((f) => f.endsWith("pyproject.toml") || f.endsWith("requirements.txt"))) stack.add("Python");
  if (files.some((f) => f.endsWith("go.mod"))) stack.add("Go");
  if (files.some((f) => f.endsWith("Cargo.toml"))) stack.add("Rust");
  if (files.some((f) => f.endsWith("Gemfile"))) stack.add("Ruby");
  if (files.some((f) => f.endsWith("composer.json"))) stack.add("PHP");
  if (files.some((f) => NATIVE_CODE_EXTENSIONS.has(path.extname(f).toLowerCase()))) stack.add("C/C++");
  if (files.some((f) => /(^|\/)CMakeLists\.txt$/.test(f))) stack.add("CMake");
  if (files.some((f) => /(^|\/)(configure|configure\.ac|Makefile\.am)$/.test(f))) stack.add("Autotools");
  const deps = packageManifests.flatMap((m) => m.dependencies || []);
  if (deps.some((d) => d === "next")) stack.add("Next.js");
  if (deps.some((d) => d === "react" || d === "react-dom")) stack.add("React");
  if (deps.some((d) => d === "express" || d === "fastify" || d === "koa")) stack.add("Node web API");
  if (deps.some((d) => d.includes("graphql"))) stack.add("GraphQL");
  return Array.from(stack).sort();
}

function collectEnvKeyHints(repoPath, files) {
  const candidates = files.filter((file) => /\.(env|env\.example|env\.sample)$/.test(file) || /\.env\.(example|sample|template)$/.test(file));
  const keys = new Set();
  for (const file of candidates.slice(0, 20)) {
    const text = safeReadText(repoPath, file, 50000);
    if (!text) continue;
    for (const line of text.split(/\r?\n/)) {
      const match = line.match(/^\s*([A-Z0-9_]{3,80})\s*=/);
      if (match) keys.add(match[1]);
    }
  }
  return Array.from(keys).sort().slice(0, 80);
}

function hasAny(files, predicate) {
  return files.filter(predicate).slice(0, 120);
}

function makeSurface({
  id, title, surfaceType, priority, files, techStack, bugHints, flows, evidence,
  params = [], networkReachable = false, attackVector = null, severityCeiling = null,
  residualHuntTargets = null, attribution = null,
}) {
  const ceiling = severityCeiling || severityCeilingForSurface(surfaceType, networkReachable);
  const vector = attackVector || attackVectorForSurface(surfaceType, networkReachable);
  const surface = {
    id,
    name: title,
    hosts: ["repo://local"],
    tech_stack: techStack,
    endpoints: files,
    interesting_params: params,
    nuclei_hits: [],
    priority,
    surface_type: surfaceType,
    network_reachable: networkReachable,
    attack_vector: vector,
    severity_ceiling: ceiling,
    bug_class_hints: bugHints,
    high_value_flows: flows,
    evidence,
    ranking: {
      version: 1,
      score: priority === "HIGH" ? 80 : priority === "MEDIUM" ? 55 : 30,
      priority,
      reasons: [`repo_surface:${surfaceType}`, `files:${files.length}`, `ceiling:${ceiling}`, `vector:${vector}`],
    },
  };
  if (Array.isArray(residualHuntTargets) && residualHuntTargets.length > 0) {
    surface.residual_hunt_targets = residualHuntTargets.slice(0, 20);
  }
  // Per-path attack-vector hints (flat string arrays so they ride the brief's
  // copy-by-default path). The best-case severity_ceiling above is unchanged;
  // these only tell the hunter which paths justify AV:N vs which look AV:L.
  if (attribution && typeof attribution === "object") {
    for (const field of ["network_reachable_anchors", "network_reachable_dirs", "local_only_candidate_dirs"]) {
      if (Array.isArray(attribution[field]) && attribution[field].length > 0) {
        surface[field] = attribution[field].slice(0, 20);
      }
    }
  }
  return surface;
}

function buildRepoInventory(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const { state } = readSessionStateStrict(domain);
  if (state.target_kind !== "repo" || !state.repo || !state.repo.root_path) {
    throw new Error("bounty_repo_inventory requires a repo session initialized by bounty_init_repo_session");
  }
  const repoPath = normalizeRepoPath(args.repo_path || state.repo.root_path);
  const files = walkRepoFiles(repoPath);
  const manifests = files.filter((file) => MANIFEST_NAMES.has(path.basename(file)));
  const packageManifests = manifests
    .filter((file) => path.basename(file) === "package.json")
    .map((file) => parsePackageJson(repoPath, file));
  const techStack = detectTechStack(files, packageManifests);
  const lockfiles = manifests.filter((file) => /lock|sum$/.test(path.basename(file)) || file.endsWith("pnpm-lock.yaml"));
  // Compute the native-source set once: the uncapped set feeds residual git
  // mining (which must see every dir), the 120-slice is the surface display cap.
  const allNativeSourceFiles = files.filter((file) => NATIVE_CODE_EXTENSIONS.has(path.extname(file).toLowerCase()));
  const nativeSourceFiles = allNativeSourceFiles.slice(0, 120);
  const nativeBuildFiles = hasAny(files, (file) => NATIVE_BUILD_FILE_RE.test(file));
  const nativeFiles = Array.from(new Set([
    ...nativeBuildFiles,
    ...nativeSourceFiles,
  ])).slice(0, 160);
  const apiFiles = hasAny(files, (file) => (
    /(^|\/)(routes?|api|controllers?|handlers?|server)\b/i.test(file) ||
    /openapi|swagger|schema\.graphql|graphql/i.test(file) ||
    /(^|\/)(pages|app)\/api\//.test(file)
  ));
  const authFiles = hasAny(files, (file) => (
    /auth|jwt|oauth|session|middleware|permission|policy|guard|rbac|acl/i.test(file) &&
    // Project-metadata files match /auth/ ("AUTHORS") but are not auth code.
    !/(^|\/)(AUTHORS|CONTRIBUTORS|MAINTAINERS|CODEOWNERS)(\.[\w-]+)?$/i.test(file)
  ));
  const ciFiles = hasAny(files, (file) => (
    file.startsWith(".github/workflows/") ||
    file === ".gitlab-ci.yml" ||
    file === "Dockerfile" ||
    file.endsWith("Dockerfile") ||
    file.includes("docker-compose") ||
    /\.(tf|tfvars|yml|yaml)$/.test(file) && /deploy|ci|workflow|pipeline|infra|terraform/i.test(file)
  ));
  const configFiles = hasAny(files, (file) => (
    /(^|\/)\.env(\.|$)/.test(file) ||
    /config|secret|credential|settings/i.test(file)
  ));
  const docFiles = hasAny(files, (file) => DOC_NAMES.has(file) || file.startsWith("docs/") && /\.md$/i.test(file));
  const envKeyHints = collectEnvKeyHints(repoPath, files);
  const reach = detectNetworkReachability(repoPath, files);
  // Auth/authz guarding a network API is itself network-reachable even when the
  // listener is in a sibling component the content scan did not sample.
  const authNetworkReachable = reach.network_reachable || apiFiles.length > 0;
  const residualHuntTargets = allNativeSourceFiles.length > 0
    ? extractResidualHuntTargets(repoPath, files, allNativeSourceFiles)
    : [];

  const surfaces = [];
  if (manifests.length > 0) {
    surfaces.push(makeSurface({
      id: "OSS-DEPENDENCY",
      title: "Dependency and package metadata",
      surfaceType: "oss_dependency",
      priority: lockfiles.length > 0 ? "HIGH" : "MEDIUM",
      files: manifests.slice(0, 120),
      techStack,
      bugHints: ["dependency_confusion", "vulnerable_dependency", "supply_chain"],
      flows: ["install", "build", "release"],
      evidence: [`${manifests.length} package/dependency manifest files`, `${lockfiles.length} lockfiles`],
      params: packageManifests.flatMap((m) => m.scripts || []).slice(0, 40),
    }));
  }
  if (nativeFiles.length > 0) {
    surfaces.push(makeSurface({
      id: "OSS-NATIVE-CODE",
      title: "Native code parser, protocol, and memory-safety review",
      surfaceType: "oss_native_code",
      // Reachability sets the ceiling: a network-fed parser (AV:N) is
      // CRITICAL-capable and stays top priority; a pure local-file parser
      // library (AV:L) is MEDIUM-realistic and is down-ranked so it does not
      // crowd out a genuine daemon/server surface.
      priority: reach.network_reachable ? "HIGH" : "MEDIUM",
      networkReachable: reach.network_reachable,
      attribution: reach.attribution,
      residualHuntTargets,
      files: nativeFiles,
      techStack,
      bugHints: [
        "bounds_check",
        "integer_truncation",
        "signed_unsigned_mismatch",
        "parser_state_machine",
        "memory_lifetime",
        "path_handling",
      ],
      flows: ["protocol parsing", "network input", "filesystem paths", "fuzz/sanitizer replay"],
      evidence: [
        `${nativeSourceFiles.length} C/C++ source/header files`,
        `${nativeBuildFiles.length} native build files`,
      ],
    }));
  }
  if (apiFiles.length > 0) {
    surfaces.push(makeSurface({
      id: "OSS-API-SCHEMA",
      title: "API routes and schemas",
      surfaceType: "oss_api_schema",
      priority: "HIGH",
      networkReachable: true,
      files: apiFiles,
      techStack,
      bugHints: ["idor", "authz", "ssrf", "injection", "graphql"],
      flows: ["api", "routing", "request handling"],
      evidence: [`${apiFiles.length} route/schema candidates`],
    }));
  }
  if (authFiles.length > 0) {
    surfaces.push(makeSurface({
      id: "OSS-AUTHZ",
      title: "Authentication and authorization code",
      surfaceType: "oss_authz",
      priority: "HIGH",
      networkReachable: authNetworkReachable,
      files: authFiles,
      techStack,
      bugHints: ["authz", "jwt_oauth", "session_fixation", "privilege_escalation"],
      flows: ["login", "session", "permission checks"],
      evidence: [`${authFiles.length} auth-sensitive files`],
    }));
  }
  if (ciFiles.length > 0) {
    surfaces.push(makeSurface({
      id: "OSS-CI-CD",
      title: "CI/CD, container, and deployment config",
      surfaceType: "oss_ci_cd",
      priority: "MEDIUM",
      files: ciFiles,
      techStack,
      bugHints: ["workflow_injection", "secret_exposure", "supply_chain"],
      flows: ["ci", "release", "deployment"],
      evidence: [`${ciFiles.length} CI/deployment files`],
    }));
  }
  if (configFiles.length > 0) {
    surfaces.push(makeSurface({
      id: "OSS-SECRETS-CONFIG",
      title: "Configuration and secret handling",
      surfaceType: "oss_secrets_config",
      priority: envKeyHints.length > 0 ? "HIGH" : "MEDIUM",
      files: configFiles,
      techStack,
      bugHints: ["secret_exposure", "misconfiguration", "insecure_defaults"],
      flows: ["configuration", "environment", "secrets"],
      evidence: [`${configFiles.length} config/secret-related files`, `${envKeyHints.length} env key names in examples/templates`],
      params: envKeyHints,
    }));
  }
  surfaces.push(makeSurface({
    id: "OSS-DOCS-BEHAVIOR",
    title: "Security docs and documented behavior",
    surfaceType: "oss_docs_behavior",
    priority: docFiles.length > 0 ? "MEDIUM" : "LOW",
    files: docFiles.slice(0, 120),
    techStack,
    bugHints: ["docs_vs_behavior", "unsafe_defaults", "missing_security_policy"],
    flows: ["installation", "configuration", "security policy"],
    evidence: docFiles.length > 0 ? [`${docFiles.length} docs files`] : ["No common security/README docs found"],
  }));

  const reachabilitySummary = {
    max_credible_severity_ceiling: surfaces.reduce(
      (acc, surface) => maxCeiling(acc, surface.severity_ceiling || "none"),
      "none",
    ),
    network_reachable: surfaces.some((surface) => surface.network_reachable),
    network_reachable_surface_ids: surfaces
      .filter((surface) => surface.network_reachable)
      .map((surface) => surface.id),
    surface_ceilings: surfaces.map((surface) => ({
      id: surface.id,
      severity_ceiling: surface.severity_ceiling,
      attack_vector: surface.attack_vector,
      network_reachable: surface.network_reachable,
    })),
    signals: reach.signals,
    native_attack_vector_map: reach.attribution,
  };

  const inventory = {
    version: REPO_INVENTORY_VERSION,
    target_domain: domain,
    repo_path: repoPath,
    generated_at: new Date().toISOString(),
    reachability: reachabilitySummary,
    counts: {
      files: files.length,
      manifests: manifests.length,
      lockfiles: lockfiles.length,
      package_manifests: packageManifests.length,
      native_source_files: nativeSourceFiles.length,
      native_build_files: nativeBuildFiles.length,
      residual_hunt_targets: residualHuntTargets.length,
      surfaces: surfaces.length,
    },
    tech_stack: techStack,
    manifests,
    package_manifests: packageManifests,
    lockfiles,
    native_source_files: nativeSourceFiles,
    native_build_files: nativeBuildFiles,
    api_files: apiFiles,
    auth_files: authFiles,
    ci_files: ciFiles,
    config_files: configFiles,
    doc_files: docFiles,
    env_key_hints: envKeyHints,
    residual_hunt_targets: residualHuntTargets,
  };
  const attackSurface = {
    domain,
    target_kind: "repo",
    repo_path: repoPath,
    reachability: reachabilitySummary,
    surfaces,
  };

  return withSessionLock(domain, () => {
    writeFileAtomic(repoInventoryPath(domain), `${JSON.stringify(inventory, null, 2)}\n`);
    writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify(attackSurface, null, 2)}\n`);
    return JSON.stringify({
      version: 1,
      target_domain: domain,
      repo_inventory_path: repoInventoryPath(domain),
      attack_surface_path: attackSurfacePath(domain),
      counts: inventory.counts,
      surface_ids: surfaces.map((surface) => surface.id),
      reachability: reachabilitySummary,
      residual_hunt_targets: residualHuntTargets,
    }, null, 2);
  });
}

function resolveRepoFile(repoPath, relativePath) {
  const normalized = assertNonEmptyString(relativePath, "file_path");
  if (path.isAbsolute(normalized)) {
    throw new Error("file_path must be repo-relative");
  }
  const full = path.resolve(repoPath, normalized);
  const realRoot = fs.realpathSync(repoPath);
  const parent = fs.existsSync(full) ? fs.realpathSync(full) : path.resolve(path.dirname(full));
  if (parent !== realRoot && !parent.startsWith(`${realRoot}${path.sep}`)) {
    throw new Error("file_path escapes repo root");
  }
  return full;
}

function repoCheck(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const { state } = readSessionStateStrict(domain);
  if (state.target_kind !== "repo" || !state.repo || !state.repo.root_path) {
    throw new Error("bounty_repo_check requires a repo session");
  }
  const repoPath = normalizeRepoPath(state.repo.root_path);
  const filePath = normalizeOptionalText(args.file_path, "file_path");
  const pattern = normalizeOptionalText(args.pattern, "pattern");
  const regex = args.regex == null ? false : assertBoolean(args.regex, "regex");
  const checkType = normalizeOptionalText(args.check_type, "check_type") || "file_contains";
  const record = {
    version: 1,
    target_domain: domain,
    ts: new Date().toISOString(),
    check_type: checkType,
    file_path: filePath,
    pattern: pattern ? "[provided]" : null,
    regex,
    ok: false,
    matches: [],
  };

  if (!filePath) {
    record.ok = true;
    record.reason = "repo session exists";
  } else {
    const full = resolveRepoFile(repoPath, filePath);
    record.exists = fs.existsSync(full) && fs.statSync(full).isFile();
    if (!record.exists) {
      record.reason = "file_missing";
    } else if (!pattern) {
      record.ok = true;
      record.reason = "file_exists";
    } else {
      const text = safeReadText(repoPath, filePath);
      if (text == null) {
        record.reason = "file_unreadable_or_too_large";
      } else {
        const matcher = regex
          ? new RegExp(pattern, "g")
          : new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g");
        const lines = text.split(/\r?\n/);
        for (let index = 0; index < lines.length && record.matches.length < MAX_MATCHES; index += 1) {
          matcher.lastIndex = 0;
          if (matcher.test(lines[index])) {
            record.matches.push({
              line: index + 1,
              excerpt: lines[index].trim().slice(0, 240),
            });
          }
        }
        record.ok = record.matches.length > 0;
        record.reason = record.ok ? "pattern_found" : "pattern_not_found";
      }
    }
  }

  return withSessionLock(domain, () => {
    appendJsonlLine(repoChecksJsonlPath(domain), record, { maxRecords: REPO_CHECK_LOG_MAX_RECORDS });
    return JSON.stringify({
      version: 1,
      target_domain: domain,
      repo_checks_path: repoChecksJsonlPath(domain),
      check: record,
    }, null, 2);
  });
}

module.exports = {
  NATIVE_CODE_EXTENSIONS,
  REPO_INVENTORY_VERSION,
  buildRepoInventory,
  initRepoSession,
  makeRepoTargetId,
  normalizeRepoPath,
  repoCheck,
  walkRepoFiles,
};
