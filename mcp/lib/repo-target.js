"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
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

function makeSurface({ id, title, surfaceType, priority, files, techStack, bugHints, flows, evidence, params = [] }) {
  return {
    id,
    name: title,
    hosts: ["repo://local"],
    tech_stack: techStack,
    endpoints: files,
    interesting_params: params,
    nuclei_hits: [],
    priority,
    surface_type: surfaceType,
    bug_class_hints: bugHints,
    high_value_flows: flows,
    evidence,
    ranking: {
      version: 1,
      score: priority === "HIGH" ? 80 : priority === "MEDIUM" ? 55 : 30,
      priority,
      reasons: [`repo_surface:${surfaceType}`, `files:${files.length}`],
    },
  };
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
  const nativeSourceFiles = hasAny(files, (file) => NATIVE_CODE_EXTENSIONS.has(path.extname(file).toLowerCase()));
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
  const authFiles = hasAny(files, (file) => /auth|jwt|oauth|session|middleware|permission|policy|guard|rbac|acl/i.test(file));
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
      priority: "HIGH",
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

  const inventory = {
    version: REPO_INVENTORY_VERSION,
    target_domain: domain,
    repo_path: repoPath,
    generated_at: new Date().toISOString(),
    counts: {
      files: files.length,
      manifests: manifests.length,
      lockfiles: lockfiles.length,
      package_manifests: packageManifests.length,
      native_source_files: nativeSourceFiles.length,
      native_build_files: nativeBuildFiles.length,
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
  };
  const attackSurface = {
    domain,
    target_kind: "repo",
    repo_path: repoPath,
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
  REPO_INVENTORY_VERSION,
  buildRepoInventory,
  initRepoSession,
  makeRepoTargetId,
  normalizeRepoPath,
  repoCheck,
  walkRepoFiles,
};
