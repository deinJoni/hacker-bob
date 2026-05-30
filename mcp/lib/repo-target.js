"use strict";

// Cycle O.1 of Plane O: repo-bound target axis. This module owns the
// SessionNucleus and state.json initialization path for OSS sessions.
// A repo session derives its `target_domain` from the absolute repo
// path so reopening the same checkout from any working directory
// always lands on the same session.
//
// Plane O invariant O-P1 (local-repo first) is enforced via
// governance-contracts.assertRepoRootPath: the path must exist as a
// local directory before binding. No clone-from-remote happens here.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const {
  assertBoolean,
  assertNonEmptyString,
  normalizeOptionalText,
} = require("./validation.js");
const {
  assertSafeDomain,
  repoInventoryPath,
  sessionDir,
  sessionNucleusPath,
  statePath,
} = require("./paths.js");
const {
  buildSessionNucleus,
  normalizeTargetRepo,
} = require("./governance-contracts.js");
const {
  resolveEgressProfile,
} = require("./egress-profiles.js");
const {
  buildInitialSessionState,
  egressProfileStateFields,
  deriveBlockInternalHostsPolicy,
} = require("./session-state-contracts.js");
const {
  isSessionDirEffectivelyEmpty,
  withSessionLock,
} = require("./storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  hashDocumentExcluding,
  writeJsonDocument,
} = require("./fabric-common.js");
const {
  writeSessionStateDocument,
} = require("./session-state-store.js");
const {
  readSessionNucleus,
} = require("./governance-store.js");
const {
  appendSessionEvent,
} = require("./session-events.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  safeAppendPipelineEventDirect,
} = require("./pipeline-events.js");
const {
  buildGovernanceContextFromNucleus,
} = require("./governance-context.js");
const {
  appendFrontierEvent,
} = require("./frontier-events.js");
const {
  scheduleMaterialization,
} = require("./frontier-materialize-debounce.js");
const {
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");

// Cycle O.1: SAFE_NAME_PATTERN keeps the basename safe for the
// target_domain slug. Any character outside `[A-Za-z0-9._-]` is folded
// to a single dash; leading/trailing dashes are trimmed. Empty
// basenames (e.g. trailing slash on root) fall back to "repo".
function safeBasename(value) {
  const base = path.basename(value || "").trim();
  if (!base) return "repo";
  const folded = base.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return folded || "repo";
}

function sha8(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex").slice(0, 8);
}

function sha64(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function deriveRepoTargetDomain(realpathValue) {
  const name = safeBasename(realpathValue);
  return `repo-${name}-${sha8(realpathValue)}`;
}

function deriveRepoHashFromPath(realpathValue) {
  // Stable 64-hex digest of the canonical path. Trimmed to 64 chars so
  // it shares the validation envelope with explicit git commit hashes
  // (which can be 40 hex chars).
  return sha64(realpathValue);
}

// Translate a friendly error code from assertRepoRootPath into a
// structured ToolError so callers (bob_init_repo_session) surface the
// repo_path_not_found / repo_path_not_directory contract explicitly.
function repoPathError(error) {
  if (error && error.code === "repo_path_not_found") {
    return new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || "repo path not found", {
      repo_error_code: "repo_path_not_found",
    });
  }
  if (error && error.code === "repo_path_not_directory") {
    return new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || "repo path is not a directory", {
      repo_error_code: "repo_path_not_directory",
    });
  }
  return null;
}

function initRepoSession({
  repo_path: repoPath,
  target_domain: requestedTargetDomain = null,
  source_url: sourceUrl = null,
  branch = null,
  commit = null,
  deep_mode: deepMode = false,
  egress_profile: requestedEgressProfile = null,
} = {}) {
  let targetRepo;
  try {
    targetRepo = normalizeTargetRepo({
      root_path: repoPath,
      source_url: sourceUrl,
      branch,
      commit,
    }, "target_repo");
  } catch (error) {
    const mapped = repoPathError(error);
    if (mapped) throw mapped;
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || String(error));
  }

  const canonicalRoot = targetRepo.root_path;
  const derivedDomain = deriveRepoTargetDomain(canonicalRoot);

  let domain;
  if (requestedTargetDomain != null) {
    const trimmed = assertNonEmptyString(requestedTargetDomain, "target_domain");
    assertSafeDomain(trimmed);
    if (trimmed !== derivedDomain) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `target_domain does not match derived repo slug; got ${trimmed}, expected ${derivedDomain}`,
        { expected_target_domain: derivedDomain, provided_target_domain: trimmed },
      );
    }
    domain = trimmed;
  } else {
    domain = derivedDomain;
  }

  const repoHash = (targetRepo.commit && /^[0-9a-f]{8,64}$/i.test(targetRepo.commit))
    ? targetRepo.commit.toLowerCase()
    : deriveRepoHashFromPath(canonicalRoot);

  const normalizedDeepMode = deepMode == null ? false : assertBoolean(deepMode, "deep_mode");
  const profileName = requestedEgressProfile == null
    ? "default"
    : assertNonEmptyString(requestedEgressProfile, "egress_profile");

  return withSessionLock(domain, () => {
    const dir = sessionDir(domain);
    const filePath = statePath(domain);

    if (fs.existsSync(filePath)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session already initialized: ${filePath}`);
    }
    if (!isSessionDirEffectivelyEmpty(dir)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session directory is not empty: ${dir}`);
    }

    const egressProfile = resolveEgressProfile(profileName);
    const egressFields = egressProfileStateFields(egressProfile);
    const internalHostPolicy = deriveBlockInternalHostsPolicy({
      checkpointMode: "normal",
      legacyDefault: false,
    });

    const sessionNucleus = buildSessionNucleus({
      target_domain: domain,
      target_repo: targetRepo,
      repo_hash: repoHash,
      scope_policy: {
        target_domain: domain,
        target_repo: targetRepo,
        ...internalHostPolicy,
      },
      egress_identity: egressFields,
      auth_context: {
        auth_status: "pending",
      },
      operator_constraint: {
        handoff_provenance_required: true,
      },
    });
    writeJsonDocument(sessionNucleusPath(domain), sessionNucleus);
    appendSessionEvent({
      target_domain: domain,
      kind: "governance.session.initialized",
      nucleus_hash: sessionNucleus.nucleus_hash,
      payload: {
        nucleus_hash: sessionNucleus.nucleus_hash,
        scope_policy_hash: hashCanonicalJson(sessionNucleus.scope_policy),
        egress_identity_hash: hashCanonicalJson(sessionNucleus.egress_identity),
        auth_context_hash: hashCanonicalJson(sessionNucleus.auth_context),
        operator_constraint_hash: hashCanonicalJson(sessionNucleus.operator_constraint),
        repo_hash: sessionNucleus.repo_hash,
      },
    });

    const state = buildInitialSessionState(domain, null, {
      deepMode: normalizedDeepMode,
      egressProfile,
      blockInternalHostsPolicy: sessionNucleus.scope_policy,
      targetRepo,
      repoHash,
    });
    writeSessionStateDocument(domain, {}, state);
    safeAppendPipelineEventDirect(domain, "session_started", {
      lifecycle_state: state.lifecycle_state,
      source: "bob_init_repo_session",
      deep_mode: state.deep_mode,
      checkpoint_mode: state.checkpoint_mode,
      block_internal_hosts: state.block_internal_hosts,
      block_internal_hosts_source: state.block_internal_hosts_source,
      repo_hash: repoHash,
      ...egressFields,
    }, buildGovernanceContextFromNucleus(sessionNucleus));

    return {
      created: true,
      session_dir: dir,
      target_domain: domain,
      target_repo: targetRepo,
      repo_hash: repoHash,
      nucleus_hash: sessionNucleus.nucleus_hash,
      lifecycle_state: state.lifecycle_state,
      deep_mode: state.deep_mode,
      egress_profile: state.egress_profile,
    };
  });
}

function readRepoSession(targetDomain) {
  const domain = assertNonEmptyString(targetDomain, "target_domain");
  const nucleus = readSessionNucleus(domain);
  if (!nucleus || nucleus.scope_policy == null || nucleus.scope_policy.target_repo == null) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `target_domain ${domain} is not a repo session`,
    );
  }
  return {
    target_domain: nucleus.target_domain,
    target_repo: nucleus.scope_policy.target_repo,
    repo_hash: nucleus.repo_hash || null,
    nucleus_hash: nucleus.nucleus_hash,
    lifecycle_state: nucleus.lifecycle_state,
  };
}

// Cycle O.2: repo-inventory walks the bound repo and emits frontier
// `surface.observed` events for each enumerated artefact. The walker
// honours `.gitignore`, default-excludes heavy build/vendor trees,
// halts on symlink loops, and caps the walk at 50k files so that
// `init_repo_session(node_modules-monorepo/)` does not exhaust memory.

const REPO_INVENTORY_VERSION = 1;
const REPO_WALK_MAX_FILES = 50000;
const REPO_WALK_PROBE_MAX_BYTES = 64 * 1024; // cap text probes (NFS detection)

// Default-excluded directory names (per O.2 spec). These are layered ON TOP
// of .gitignore patterns; .gitignore is the authoritative source for a
// per-repo override, the default list captures heavy directories that are
// almost always ignored even when no .gitignore exists.
const DEFAULT_EXCLUDED_DIRS = Object.freeze(new Set([
  ".git",
  "node_modules",
  "target",
  "build",
  "dist",
  "vendor",
  ".venv",
  "__pycache__",
  "coverage",
]));

// Manifest filenames that flag a package/module surface.
const MANIFEST_NAMES = Object.freeze(new Set([
  "package.json",
  "Cargo.toml",
  "go.mod",
  "requirements.txt",
  "setup.py",
  "pyproject.toml",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "Gemfile",
  "composer.json",
]));

// Lockfiles paired with the manifest for "has_lockfile" signalling.
const LOCKFILE_NAMES = Object.freeze(new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "Cargo.lock",
  "go.sum",
  "Pipfile.lock",
  "poetry.lock",
  "Gemfile.lock",
  "composer.lock",
]));

// Native build files — presence promotes the repo to NATIVE-CODE surface.
const NATIVE_BUILD_NAMES = Object.freeze(new Set([
  "CMakeLists.txt",
  "configure.ac",
  "Makefile.am",
  "Makefile",
  "meson.build",
]));

const NATIVE_SOURCE_EXTENSIONS = Object.freeze(new Set([
  ".c",
  ".cc",
  ".cpp",
  ".cxx",
  ".h",
  ".hh",
  ".hpp",
]));

// CI/CD config paths. The first match wins; we want the file relative path
// to land on the materialized surface so downstream readers can locate it.
const CI_CONFIG_MATCHERS = Object.freeze([
  (rel) => rel.startsWith(".github/workflows/") && /\.ya?ml$/i.test(rel),
  (rel) => rel === ".gitlab-ci.yml",
  (rel) => rel === "Jenkinsfile",
  (rel) => rel === ".circleci/config.yml",
]);

// Entry-point detectors. Each returns true when the file/path indicates an
// executable / main entry. Directory-shaped patterns are also recognised so
// e.g. `bin/foo` and `cmd/server/main.go` both surface.
const ENTRY_POINT_MATCHERS = Object.freeze([
  (rel) => rel.startsWith("bin/"),
  (rel) => rel.startsWith("cmd/"),
  (rel) => /(^|\/)src\/main\.[a-z0-9]+$/i.test(rel),
  (rel) => /(^|\/)index\.[a-z0-9]+$/i.test(rel),
  (rel) => /(^|\/)__main__\.py$/.test(rel),
]);

// Special config names that should surface as their own "config" event.
const CONFIG_MATCHERS = Object.freeze([
  (rel) => /(^|\/)\.env(\..+)?$/.test(rel),
  (rel) => rel === "Dockerfile",
  (rel) => /(^|\/)Dockerfile(\..+)?$/.test(rel),
  (rel) => rel === "docker-compose.yml" || rel === "docker-compose.yaml",
  (rel) => rel.startsWith(".devcontainer/"),
]);

// File-extension → language hint map. Lightweight and intentionally bounded;
// the hypergraph only needs a per-module language signal, not full LOC.
const LANGUAGE_BY_EXT = Object.freeze({
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".py": "python",
  ".go": "go",
  ".rs": "rust",
  ".rb": "ruby",
  ".php": "php",
  ".java": "java",
  ".kt": "kotlin",
  ".kts": "kotlin",
  ".scala": "scala",
  ".cs": "csharp",
  ".c": "c",
  ".h": "c",
  ".cc": "cpp",
  ".cpp": "cpp",
  ".cxx": "cpp",
  ".hh": "cpp",
  ".hpp": "cpp",
  ".swift": "swift",
  ".m": "objc",
  ".mm": "objc",
});

// Ecosystem mapping for dependency observations.
const ECOSYSTEM_BY_MANIFEST = Object.freeze({
  "package.json": "npm",
  "Cargo.toml": "cargo",
  "go.mod": "go",
  "requirements.txt": "pypi",
  "setup.py": "pypi",
  "pyproject.toml": "pypi",
  "pom.xml": "maven",
  "build.gradle": "gradle",
  "build.gradle.kts": "gradle",
  "Gemfile": "rubygems",
  "composer.json": "composer",
});

// NFS/XDR shape detection — when present, prepare_env can preload extra
// libtirpc/krb5/ssl/nfs packages. We deliberately read a small probe of the
// build file rather than scanning every .c file.
const NFS_XDR_SIGNALS = Object.freeze([
  /libtirpc/i,
  /libnfs\.h/i,
  /rpc\/xdr\.h/i,
  /\bxdr_/i,
]);

// Minimal .gitignore parser. Supports negation (`!pattern`), trailing slashes
// (directory-only), and glob characters via a converted RegExp. We do not
// implement the full git wildmatch semantics — the tradeoff is intentional:
// the bounded surface enumeration here is a hint to the orchestrator, not
// the authoritative file ACL. The session-read-guard remains the trust root
// for sensitive paths.
function compileGitignorePatterns(text) {
  const lines = text.split(/\r?\n/);
  const patterns = [];
  for (const raw of lines) {
    const trimmed = raw.replace(/\s+$/, "");
    if (!trimmed || trimmed.startsWith("#")) continue;
    let pattern = trimmed;
    let negated = false;
    if (pattern.startsWith("!")) {
      negated = true;
      pattern = pattern.slice(1);
    }
    let directoryOnly = false;
    if (pattern.endsWith("/")) {
      directoryOnly = true;
      pattern = pattern.slice(0, -1);
    }
    if (!pattern) continue;
    const anchoredAtRoot = pattern.startsWith("/");
    if (anchoredAtRoot) pattern = pattern.slice(1);
    // Convert glob → regex. * matches anything but `/`; ** matches across
    // path separators; ? matches single non-`/` char. Other regex metas
    // are escaped.
    let regex = "";
    for (let i = 0; i < pattern.length; i++) {
      const ch = pattern[i];
      if (ch === "*" && pattern[i + 1] === "*") {
        regex += ".*";
        i += 1;
      } else if (ch === "*") {
        regex += "[^/]*";
      } else if (ch === "?") {
        regex += "[^/]";
      } else if (/[.+^${}()|[\]\\]/.test(ch)) {
        regex += "\\" + ch;
      } else {
        regex += ch;
      }
    }
    const prefix = anchoredAtRoot ? "^" : "(?:^|.*/)";
    const compiled = new RegExp(`${prefix}${regex}${directoryOnly ? "(?:/|$)" : "$"}`);
    patterns.push({ regex: compiled, negated, directoryOnly });
  }
  return patterns;
}

function matchesGitignore(patterns, relativePath, isDirectory) {
  let ignored = false;
  for (const { regex, negated, directoryOnly } of patterns) {
    if (directoryOnly && !isDirectory) continue;
    if (regex.test(relativePath)) {
      ignored = !negated;
    }
  }
  return ignored;
}

function loadGitignore(rootPath) {
  const candidate = path.join(rootPath, ".gitignore");
  if (!fs.existsSync(candidate)) return [];
  try {
    const raw = fs.readFileSync(candidate, "utf8");
    return compileGitignorePatterns(raw);
  } catch {
    return [];
  }
}

// Symlink-loop guard. Tracks the device+inode pair for every directory we
// descend into; a repeat visit halts that branch cleanly without throwing.
function statKey(stat) {
  return `${stat.dev}:${stat.ino}`;
}

class RepoTooLargeError extends Error {
  constructor(limit) {
    super(`repo_too_large: walked over ${limit} files; rerun against a narrower repo_path`);
    this.code = "repo_too_large";
    this.limit = limit;
  }
}

function walkRepo(rootPath, gitignorePatterns) {
  const files = [];
  const visited = new Set();
  const queue = [{ absPath: rootPath, relPath: "" }];
  while (queue.length > 0) {
    if (files.length > REPO_WALK_MAX_FILES) {
      throw new RepoTooLargeError(REPO_WALK_MAX_FILES);
    }
    const { absPath, relPath } = queue.shift();
    let stat;
    try {
      stat = fs.statSync(absPath);
    } catch {
      continue;
    }
    if (!stat.isDirectory()) continue;
    const key = statKey(stat);
    if (visited.has(key)) continue;
    visited.add(key);
    let entries;
    try {
      entries = fs.readdirSync(absPath, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const childAbs = path.join(absPath, entry.name);
      const childRel = relPath ? `${relPath}/${entry.name}` : entry.name;
      let isDir = entry.isDirectory();
      let isFile = entry.isFile();
      if (entry.isSymbolicLink()) {
        try {
          const linkStat = fs.statSync(childAbs);
          isDir = linkStat.isDirectory();
          isFile = linkStat.isFile();
        } catch {
          continue;
        }
      }
      if (isDir) {
        if (DEFAULT_EXCLUDED_DIRS.has(entry.name)) continue;
        if (matchesGitignore(gitignorePatterns, childRel, true)) continue;
        queue.push({ absPath: childAbs, relPath: childRel });
      } else if (isFile) {
        if (matchesGitignore(gitignorePatterns, childRel, false)) continue;
        if (files.length >= REPO_WALK_MAX_FILES) {
          throw new RepoTooLargeError(REPO_WALK_MAX_FILES);
        }
        files.push(childRel);
      }
    }
  }
  return files.sort();
}

function safeReadProbe(absPath, maxBytes = REPO_WALK_PROBE_MAX_BYTES) {
  try {
    const fd = fs.openSync(absPath, "r");
    try {
      const buf = Buffer.alloc(maxBytes);
      const bytesRead = fs.readSync(fd, buf, 0, maxBytes, 0);
      const slice = buf.subarray(0, bytesRead);
      if (slice.includes(0)) return null;
      return slice.toString("utf8");
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
}

function detectNfsXdrShape(rootPath, files) {
  // Scan a bounded number of native-build files for NFS/XDR signals. The
  // probe stays under 64KiB per file so a pathological CMakeLists does not
  // dominate the inventory time budget.
  for (const file of files) {
    const base = path.basename(file);
    if (!NATIVE_BUILD_NAMES.has(base)) continue;
    const probe = safeReadProbe(path.join(rootPath, file));
    if (!probe) continue;
    for (const re of NFS_XDR_SIGNALS) {
      if (re.test(probe)) return true;
    }
  }
  // Also check for libnfs.h / rpc/xdr.h in any header file path.
  for (const file of files) {
    if (/libnfs\.h$/i.test(file)) return true;
    if (/(^|\/)rpc\/xdr\.h$/i.test(file)) return true;
  }
  return false;
}

function detectEcosystemForManifest(base) {
  return ECOSYSTEM_BY_MANIFEST[base] || null;
}

function findLockfileForManifest(manifestRel, files) {
  const dir = path.dirname(manifestRel);
  for (const file of files) {
    if (path.dirname(file) !== dir) continue;
    if (LOCKFILE_NAMES.has(path.basename(file))) return file;
  }
  return null;
}

function classifyFile(rel) {
  const base = path.basename(rel);
  const ext = path.extname(rel).toLowerCase();
  const manifest = MANIFEST_NAMES.has(base);
  const ci = CI_CONFIG_MATCHERS.some((fn) => fn(rel));
  const config = CONFIG_MATCHERS.some((fn) => fn(rel));
  const entry = ENTRY_POINT_MATCHERS.some((fn) => fn(rel));
  const language = LANGUAGE_BY_EXT[ext] || null;
  const nativeSource = NATIVE_SOURCE_EXTENSIONS.has(ext);
  const nativeBuild = NATIVE_BUILD_NAMES.has(base);
  return {
    base,
    ext,
    manifest,
    ci,
    config,
    entry,
    language,
    nativeSource,
    nativeBuild,
  };
}

function safeSurfaceId(rel, prefix) {
  // Convert a relative path into a deterministic, path-safe surface id.
  // The surface id flows into materialized indexes so it must avoid path
  // characters that surface-router or downstream consumers may interpret.
  const slug = rel.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return `${prefix}:${slug || "root"}`;
}

function emitSurfaceObserved({
  domain,
  surfaceId,
  kind,
  title,
  payload,
  emittedCount,
}) {
  const safePayload = { ...payload, kind, title };
  // O-P7: every Plane O frontier payload pre-flighted before append. The
  // normalizePlainObject path inside appendFrontierEvent already invokes
  // validateNoSensitiveMaterial; this redundant call gives a stable
  // error path in tests when a producer regression slips through.
  validateNoSensitiveMaterial(safePayload, `repo_inventory.${kind}`);
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    surface_id: surfaceId,
    payload: safePayload,
    source: { artifact: "repo-inventory.json", tool: "bob_repo_inventory" },
  });
  emittedCount.value += 1;
}

function buildInventoryProjection(domain, repoRoot, files) {
  const modules = [];
  const dependencies = [];
  const entryPoints = [];
  const ciPipelines = [];
  const configs = [];
  const manifests = [];
  const languageCounts = {};
  let nativeSourceCount = 0;
  let nativeBuildCount = 0;

  for (const rel of files) {
    const info = classifyFile(rel);
    if (info.language) {
      languageCounts[info.language] = (languageCounts[info.language] || 0) + 1;
      // Emit a code_module surface per source file so the frontier carries
      // every code-shaped signal. To avoid blowing the materialized index
      // for very large repos we only emit code_module for native sources
      // here; non-native languages still aggregate via the language counts
      // and per-language dependency observations.
    }
    if (info.nativeSource) {
      nativeSourceCount += 1;
      modules.push({
        rel,
        language: info.language || "c",
        nativeSource: true,
        nativeBuild: false,
      });
    }
    if (info.nativeBuild) {
      nativeBuildCount += 1;
      modules.push({
        rel,
        language: "c",
        nativeSource: false,
        nativeBuild: true,
      });
    }
    if (info.manifest) {
      manifests.push(rel);
      const ecosystem = detectEcosystemForManifest(info.base) || "unknown";
      const hasLockfile = findLockfileForManifest(rel, files) != null;
      dependencies.push({ rel, ecosystem, hasLockfile });
    }
    if (info.ci) ciPipelines.push(rel);
    if (info.entry) entryPoints.push(rel);
    if (info.config) configs.push(rel);
  }

  const nfsShape = detectNfsXdrShape(repoRoot, files);
  return {
    modules,
    dependencies,
    entryPoints,
    ciPipelines,
    configs,
    manifests,
    languageCounts,
    nativeSourceCount,
    nativeBuildCount,
    nfsShape,
  };
}

function buildRepoInventory({ target_domain: targetDomain, repo_path: repoPathOverride } = {}) {
  const domain = assertSafeDomain(targetDomain);
  const repoSession = readRepoSession(domain);
  const root = repoPathOverride
    ? assertNonEmptyString(repoPathOverride, "repo_path")
    : repoSession.target_repo.root_path;
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `repo_path is not a directory: ${root}`);
  }

  const gitignorePatterns = loadGitignore(root);
  let files;
  try {
    files = walkRepo(root, gitignorePatterns);
  } catch (error) {
    if (error && error.code === "repo_too_large") {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message, {
        repo_error_code: "repo_too_large",
        limit: error.limit,
      });
    }
    throw error;
  }
  const projection = buildInventoryProjection(domain, root, files);

  return withSessionLock(domain, () => {
    const generatedAt = new Date().toISOString();
    const emittedCount = { value: 0 };

    // Per-module frontier events.
    for (const mod of projection.modules) {
      emitSurfaceObserved({
        domain,
        surfaceId: safeSurfaceId(mod.rel, "repo:module"),
        kind: "code_module",
        title: mod.rel,
        payload: {
          file_path: mod.rel,
          language: mod.language,
          native_source: mod.nativeSource,
          native_build: mod.nativeBuild,
        },
        emittedCount,
      });
    }

    // Per-manifest frontier event.
    for (const manifestPath of projection.manifests) {
      const ecosystem = detectEcosystemForManifest(path.basename(manifestPath)) || "unknown";
      emitSurfaceObserved({
        domain,
        surfaceId: safeSurfaceId(manifestPath, "repo:manifest"),
        kind: "manifest",
        title: manifestPath,
        payload: {
          file_path: manifestPath,
          ecosystem,
        },
        emittedCount,
      });
    }

    // Per-dependency frontier event (one per manifest, top-level only).
    for (const dep of projection.dependencies) {
      emitSurfaceObserved({
        domain,
        surfaceId: safeSurfaceId(`${dep.rel}#deps`, "repo:dependency"),
        kind: "dependency",
        title: dep.rel,
        payload: {
          manifest_path: dep.rel,
          ecosystem: dep.ecosystem,
          has_lockfile: dep.hasLockfile,
        },
        emittedCount,
      });
    }

    // Per-CI-pipeline frontier event.
    for (const ci of projection.ciPipelines) {
      emitSurfaceObserved({
        domain,
        surfaceId: safeSurfaceId(ci, "repo:ci"),
        kind: "ci_pipeline",
        title: ci,
        payload: {
          file_path: ci,
        },
        emittedCount,
      });
    }

    // Per-entry-point frontier event.
    for (const entry of projection.entryPoints) {
      emitSurfaceObserved({
        domain,
        surfaceId: safeSurfaceId(entry, "repo:entry"),
        kind: "entry_point",
        title: entry,
        payload: {
          file_path: entry,
        },
        emittedCount,
      });
    }

    // Per-config frontier event (NEVER reads file contents — just the path
    // and basename. Secret values live in the file itself and would land in
    // session-read-guard's protected list, not in the inventory payload).
    for (const cfg of projection.configs) {
      emitSurfaceObserved({
        domain,
        surfaceId: safeSurfaceId(cfg, "repo:config"),
        kind: "config",
        title: cfg,
        payload: {
          file_path: cfg,
        },
        emittedCount,
      });
    }

    try {
      scheduleMaterialization(domain);
    } catch {
      // Best-effort: the next producer event will trigger materialization.
    }

    const inventory = {
      version: REPO_INVENTORY_VERSION,
      target_domain: domain,
      repo_path: root,
      generated_at: generatedAt,
      counts: {
        files: files.length,
        manifests: projection.manifests.length,
        dependencies: projection.dependencies.length,
        entry_points: projection.entryPoints.length,
        ci_pipelines: projection.ciPipelines.length,
        configs: projection.configs.length,
        code_modules: projection.modules.length,
        native_source_files: projection.nativeSourceCount,
        native_build_files: projection.nativeBuildCount,
        surface_events_emitted: emittedCount.value,
      },
      languages: projection.languageCounts,
      nfs_xdr_shape: projection.nfsShape,
      manifests: projection.manifests,
      ci_pipelines: projection.ciPipelines,
      entry_points: projection.entryPoints,
      configs: projection.configs,
    };
    // O-P7: validate the persisted document before it lands on disk. The
    // inventory carries only file paths and structural counts — no file
    // contents — but the scrub is still asserted so future fields don't
    // accidentally leak.
    validateNoSensitiveMaterial(inventory, "repo_inventory");
    inventory.inventory_hash = hashDocumentExcluding(inventory, [
      "generated_at",
      "inventory_hash",
    ]);
    writeJsonDocument(repoInventoryPath(domain), inventory);
    return {
      created: true,
      target_domain: domain,
      repo_path: root,
      repo_inventory_path: repoInventoryPath(domain),
      counts: inventory.counts,
      inventory_hash: inventory.inventory_hash,
      nfs_xdr_shape: projection.nfsShape,
    };
  });
}

module.exports = {
  deriveRepoTargetDomain,
  deriveRepoHashFromPath,
  initRepoSession,
  readRepoSession,
  buildRepoInventory,
  // Exposed for cross-module reuse / tests.
  REPO_WALK_MAX_FILES,
  RepoTooLargeError,
  safeBasename,
  sha8,
};

// Quieter shadow imports kept for parity with other session-init paths.
// eslint-disable-next-line no-unused-vars
const _unusedNormalizeOptionalText = normalizeOptionalText;
