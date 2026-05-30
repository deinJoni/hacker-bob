"use strict";

// Cycle O.3 of Plane O: repo-env preparation + Dockerfile.bob generation.
//
// `prepareRepoEnv` is the OSS-axis companion to `bob_init_repo_session`.
// It owns the per-session `Dockerfile.bob`, `repo-env.json`, and the
// `recommended_commands[]` shape that the orchestrator hands to evaluator
// agents. The default mode is `dry_run: true` — we never invoke docker
// unless the operator opts in via `build_image: true` AND docker is
// actually installed.
//
// Plane O invariants enforced here:
//   O-P3  Sandbox flags are emitted in EVERY generated docker argv. Per-flag
//         positive assertions live in the test suite; this module is the
//         producer of those argvs and never strips a sandbox flag.
//   O-D6  Per-session docker image with cache busting. The generated
//         Dockerfile includes `ARG SESSION_ID=<target_domain>` as the FIRST
//         instruction so cross-session BuildKit layer-cache reuse can't
//         smuggle a poisoned layer.
//   O-D7  `recommended_commands[]` has the shape
//         `{id, description, command: string[], role}` where `role ∈
//         {build, test, fuzz, lint, compose}`.
//   O-P7  Every persisted JSONL/JSON write routes through
//         `validateNoSensitiveMaterial` before append. The generated
//         Dockerfile is the only artefact that can carry a proxy reference,
//         and we explicitly forbid `ENV.*PROXY` lines (proxy creds flow via
//         `--build-arg` + `--env` at run time, never via baked image ENV).
//
// Cycle O.3 does NOT exec `docker run`; that is O.4's `repo_docker_run`.
// Cycle O.3 owns the build-image path only, which exec's `docker build`
// when the operator explicitly sets `build_image: true`.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { execFile } = require("child_process");
const { promisify } = require("util");

const {
  assertBoolean,
  assertEnumValue,
  assertNonEmptyString,
  assertInteger,
  normalizeOptionalText,
} = require("./validation.js");
const {
  assertSafeDomain,
  sessionDir,
} = require("./paths.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  writeJsonDocument,
  hashDocumentExcluding,
} = require("./fabric-common.js");
const {
  withSessionLock,
} = require("./storage.js");
const {
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");
const {
  resolveEgressProfile,
} = require("./egress-profiles.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");
const {
  readRepoSession,
} = require("./repo-target.js");

const execFilePromise = promisify(execFile);

const REPO_ENV_VERSION = 1;

// Default + max timeout for `docker build` invocations. The MVP guidance was
// "5 minutes is enough for almost every base image"; we keep that and let
// operators bump per-invocation if a slow base needs longer.
const DEFAULT_DOCKER_BUILD_TIMEOUT_MS = 300_000;
const MAX_DOCKER_BUILD_TIMEOUT_MS = 600_000;

// Per O.3 §2 — language → base image mapping. Keys are manifest filenames or
// well-known build files; the first match wins. Order matters: we look for
// stronger signals (Cargo.toml, go.mod, etc.) before the catch-all native
// build files because a C-extension Rust crate should still resolve to
// `rust:1.79` rather than the C/C++ base.
const LANGUAGE_DETECTION_ORDER = Object.freeze([
  { name: "node", marker: "package.json", base_image: "node:20" },
  { name: "rust", marker: "Cargo.toml", base_image: "rust:1.79" },
  { name: "go", marker: "go.mod", base_image: "golang:1.22" },
  {
    name: "python",
    markers: ["pyproject.toml", "requirements.txt", "setup.py"],
    base_image: "python:3.12",
  },
  { name: "ruby", marker: "Gemfile", base_image: "ruby:3.3" },
  { name: "php", marker: "composer.json", base_image: "php:8.3-cli" },
  {
    name: "java",
    markers: ["pom.xml", "build.gradle", "build.gradle.kts"],
    base_image: "eclipse-temurin:21-jdk",
  },
]);

const NATIVE_BUILD_MARKERS = Object.freeze([
  "CMakeLists.txt",
  "configure.ac",
  "Makefile.am",
  "Makefile",
  "meson.build",
]);

const DEFAULT_BASE_IMAGE = "ubuntu:24.04";
const C_BASE_IMAGE = "ubuntu:24.04";
const C_DEFAULT_APT_PACKAGES = Object.freeze([
  "build-essential",
  "cmake",
  "ninja-build",
  "clang",
  "gdb",
  "valgrind",
]);
// Extra packages preloaded when O.2 detected NFS/XDR shape. Mirrors the
// MVP carry-back: libtirpc/libnfs/libkrb5/libssl give parsers and DVN
// stubs enough surface to repro from packets in fuzz runs.
const NFS_EXTRA_APT_PACKAGES = Object.freeze([
  "libssl-dev",
  "libkrb5-dev",
  "libtirpc-dev",
]);

const RECOMMENDED_COMMAND_ROLES = Object.freeze([
  "build",
  "test",
  "fuzz",
  "lint",
  "compose",
]);

function dockerfileBobPath(domain) {
  return path.join(sessionDir(domain), "Dockerfile.bob");
}

function repoEnvJsonPath(domain) {
  return path.join(sessionDir(domain), "repo-env.json");
}

function sha8(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex").slice(0, 8);
}

function hasFile(repoRoot, name) {
  try {
    return fs.statSync(path.join(repoRoot, name)).isFile();
  } catch {
    return false;
  }
}

function detectLanguageProfile(repoRoot) {
  for (const entry of LANGUAGE_DETECTION_ORDER) {
    const markers = entry.markers || [entry.marker];
    for (const marker of markers) {
      if (hasFile(repoRoot, marker)) {
        return {
          language: entry.name,
          base_image: entry.base_image,
          marker,
        };
      }
    }
  }
  // Native build files? Promote to C/C++ profile.
  for (const marker of NATIVE_BUILD_MARKERS) {
    if (hasFile(repoRoot, marker)) {
      return {
        language: "c",
        base_image: C_BASE_IMAGE,
        marker,
      };
    }
  }
  return {
    language: "default",
    base_image: DEFAULT_BASE_IMAGE,
    marker: null,
  };
}

// Build the recommended command list for a detected language. Each entry
// follows O-D7's shape: `{id, description, command: string[], role}`.
//
// Node:    `npm ci --ignore-scripts` (security carry-back; lifecycle scripts
//          run arbitrary code with whatever creds happen to be in scope).
// Python:  `pip install --no-build-isolation` (static-friendly install; lets
//          the static-scan lens read the resolved dependency tree without a
//          PEP 517 build invoking arbitrary setup.py code).
// C/C++:   uses the `compose` role to stage `/src` into `/work/repo` before
//          building, because the repo mount stays read-only and CMake wants
//          to write into the source tree's parent.
function recommendedCommandsFor(language, { nfsXdrShape = false } = {}) {
  if (language === "node") {
    return [
      {
        id: "install",
        description: "Install dependencies without running lifecycle scripts.",
        command: ["npm", "ci", "--ignore-scripts"],
        role: "build",
      },
      {
        id: "test",
        description: "Run the package's npm test script.",
        command: ["npm", "test", "--", "--silent"],
        role: "test",
      },
    ];
  }
  if (language === "python") {
    return [
      {
        id: "install",
        description: "Install dependencies without running PEP 517 build hooks.",
        command: ["pip", "install", "--no-build-isolation", "-r", "requirements.txt"],
        role: "build",
      },
      {
        id: "test",
        description: "Run the pytest suite.",
        command: ["pytest", "-q"],
        role: "test",
      },
    ];
  }
  if (language === "go") {
    return [
      {
        id: "build",
        description: "Compile every Go module under ./...",
        command: ["go", "build", "./..."],
        role: "build",
      },
      {
        id: "test",
        description: "Run the Go test suite.",
        command: ["go", "test", "./..."],
        role: "test",
      },
    ];
  }
  if (language === "rust") {
    return [
      {
        id: "build",
        description: "Build the workspace in release mode.",
        command: ["cargo", "build", "--release", "--locked"],
        role: "build",
      },
      {
        id: "test",
        description: "Run the cargo test suite.",
        command: ["cargo", "test", "--locked"],
        role: "test",
      },
    ];
  }
  if (language === "ruby") {
    return [
      {
        id: "install",
        description: "Install Gemfile dependencies.",
        command: ["bundle", "install", "--frozen"],
        role: "build",
      },
      {
        id: "test",
        description: "Run the rake test target.",
        command: ["bundle", "exec", "rake", "test"],
        role: "test",
      },
    ];
  }
  if (language === "php") {
    return [
      {
        id: "install",
        description: "Install composer dependencies without dev plugins.",
        command: ["composer", "install", "--no-scripts", "--no-plugins"],
        role: "build",
      },
      {
        id: "test",
        description: "Run the PHPUnit suite.",
        command: ["vendor/bin/phpunit"],
        role: "test",
      },
    ];
  }
  if (language === "java") {
    return [
      {
        id: "build",
        description: "Build via maven without spawning network downloads where possible.",
        command: ["mvn", "-B", "-DskipTests=false", "verify"],
        role: "build",
      },
    ];
  }
  if (language === "c") {
    // The C/C++ recipe uses the `compose` role: copy `/src` into `/work/repo`
    // (writable), then cmake+ctest from there. This is the MVP carry-back
    // for read-only-mount staging.
    const staging =
      "cp -a /src/. /work/repo/ && cd /work/repo && cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure";
    const sanitizerNote = nfsXdrShape ? " (NFS/XDR shape detected — preload libtirpc/libssl/libkrb5)" : "";
    return [
      {
        id: "build_and_test",
        description: `Stage /src into /work/repo, build with cmake, run ctest.${sanitizerNote}`,
        command: ["sh", "-lc", staging],
        role: "compose",
      },
    ];
  }
  return [];
}

// Compose the generated Dockerfile.bob. Plane O reasons:
//
// - `ARG SESSION_ID=<target_domain>` is the FIRST `ARG` instruction. Per O-D6
//   this busts BuildKit's cross-session layer cache so a poisoned layer
//   from another OSS session can't be smuggled into this one.
// - `USER 1000:1000` lands AFTER any apt-get install layer; otherwise the
//   non-root user can't write into /var/lib/apt during install.
// - No `ENV` carries a proxy or credential. Proxy values flow through
//   `--build-arg` (for build-time) and `--env` (for run-time) so they never
//   land in `docker history`.
// - When `allow_network: false`, the generated Dockerfile MUST NOT contain
//   any `apt-get install` / `cargo install` / `npm install` lines so the
//   subsequent `docker build --network none` actually succeeds.
function buildDockerfileBob({
  language,
  baseImage,
  targetDomain,
  nfsXdrShape,
  allowNetwork,
}) {
  const lines = [];
  lines.push(`# Generated by bob_repo_prepare_env for ${targetDomain}`);
  lines.push("# Plane O invariants: O-D6 (ARG SESSION_ID cache-bust), O-P3 (USER 1000:1000),");
  lines.push("# O-P3 (no ENV credentials — proxy threaded via --build-arg / --env at run time).");
  lines.push("");
  lines.push(`ARG SESSION_ID=${targetDomain}`);
  lines.push(`FROM ${baseImage}`);
  lines.push("ARG SESSION_ID");
  lines.push("LABEL bob.session_id=\"${SESSION_ID}\"");
  if (allowNetwork) {
    // ARG declarations for proxy values — populated via --build-arg at build
    // time. These are intentionally NOT promoted to ENV (which would land in
    // `docker history`). The build-time recipe references them locally where
    // an install layer needs them; at run time, --env supplies them again.
    lines.push("ARG HTTP_PROXY=");
    lines.push("ARG HTTPS_PROXY=");
    lines.push("ARG NO_PROXY=");
  }
  if (language === "c") {
    const packages = nfsXdrShape
      ? [...C_DEFAULT_APT_PACKAGES, ...NFS_EXTRA_APT_PACKAGES]
      : [...C_DEFAULT_APT_PACKAGES];
    if (allowNetwork) {
      lines.push("RUN apt-get update \\");
      lines.push(`    && apt-get install -y --no-install-recommends ${packages.join(" ")} \\`);
      lines.push("    && rm -rf /var/lib/apt/lists/*");
    } else {
      lines.push(`# apt-get install skipped (allow_network=false). Packages would be: ${packages.join(" ")}`);
    }
  }
  // Writable staging dir owned by the non-root user. /src remains read-only
  // (mounted at run time by repo_docker_run); /work is the per-session
  // writable area.
  lines.push("RUN mkdir -p /work/repo /work/out && chown -R 1000:1000 /work");
  lines.push("USER 1000:1000");
  lines.push("WORKDIR /src");
  lines.push("");
  return lines.join("\n") + "\n";
}

// Compose the docker build argv for `build_image: true`. Returns an
// `{command, args, env}` triple that the runtime executor consumes. Tests
// inject a fake `execFile` runtime to assert each flag without invoking
// docker.
function buildDockerBuildArgv({
  dockerfilePath,
  contextPath,
  imageTag,
  allowNetwork,
  targetDomain,
  egressProfile,
  env = {},
}) {
  const args = ["build"];
  args.push("--network", allowNetwork ? "default" : "none");
  args.push("--build-arg", `SESSION_ID=${targetDomain}`);
  if (allowNetwork) {
    // Proxy via --build-arg, never ENV in the image. Operators see this as
    // O-R2's mitigation: when the network is open, the proxy stays scoped
    // to build time and never leaks into the resulting image layer.
    const proxyUrl = egressProfile && egressProfile.proxy_url
      ? egressProfile.proxy_url
      : null;
    if (proxyUrl) {
      args.push("--build-arg", `HTTP_PROXY=${proxyUrl}`);
      args.push("--build-arg", `HTTPS_PROXY=${proxyUrl}`);
    }
  }
  args.push("--tag", imageTag);
  args.push("--file", dockerfilePath);
  args.push(contextPath);
  return {
    command: "docker",
    args,
    env: { ...env },
  };
}

// Reject any generated Dockerfile that bakes a proxy/secret into the image
// via `ENV`. The check is intentionally narrow — `ARG HTTP_PROXY=` is fine
// (it's a build-time-only parameter) but `ENV HTTP_PROXY=` would land in
// `docker history`. Per O-P3 / O-R2.
const ENV_SECRET_LEAK_RE = /^\s*ENV\s+[A-Z0-9_]*(PROXY|SECRET|TOKEN|PASSWORD|API[_-]?KEY)\b/m;

function assertNoEnvSecretLeak(dockerfileContent) {
  if (ENV_SECRET_LEAK_RE.test(dockerfileContent)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "generated Dockerfile.bob would bake a proxy or secret into the image via ENV (forbidden by O-P3)",
      { violated_invariant: "O-P3", env_secret_leak: true },
    );
  }
}

async function dockerIsAvailable(runtime) {
  const runner = runtime && typeof runtime.execFile === "function"
    ? runtime.execFile
    : execFilePromise;
  try {
    await runner("docker", ["--version"], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

function buildImageTag(targetDomain, repoHash) {
  // Per O-D6: image tag binds `target_domain` + the pinned `repo_hash` from
  // SessionNucleus. The hash is intentionally already capped to 8-64 hex
  // chars by `initRepoSession`; we trim to 16 for the tag so we stay under
  // docker's 128-char tag limit while still scoping per repo state.
  const tag = `bob-oss-${targetDomain}:${repoHash.slice(0, 16)}`;
  return tag;
}

// Build the repo-env.json document. The document is the operator-visible
// summary of what would happen on docker build — it captures the detected
// language, the chosen base image, the recommended command list, the
// derived image tag, and (when applicable) the resolved egress profile
// identity so reviewers can confirm proxy routing without re-reading the
// session nucleus.
function buildRepoEnvDocument({
  targetDomain,
  repoSession,
  repoRoot,
  detection,
  recommendedCommands,
  imageTag,
  baseImage,
  buildImage,
  dryRun,
  allowNetwork,
  egressProfileSummary,
  generatedAt,
  nfsXdrShape,
}) {
  const doc = {
    version: REPO_ENV_VERSION,
    target_domain: targetDomain,
    repo_path: repoRoot,
    repo_hash: repoSession.repo_hash,
    generated_at: generatedAt,
    detection: {
      language: detection.language,
      marker: detection.marker,
      nfs_xdr_shape: nfsXdrShape,
    },
    base_image: baseImage,
    image_tag: imageTag,
    dry_run: dryRun,
    build_image: buildImage,
    allow_network: allowNetwork,
    egress_profile: egressProfileSummary,
    dockerfile_path: dockerfileBobPath(targetDomain),
    recommended_commands: recommendedCommands,
  };
  return doc;
}

// Read `nfs_xdr_shape` flag from repo-inventory.json if present. The
// inventory is the authoritative source — prepare_env should reuse the
// O.2 detection rather than re-scanning. When the inventory isn't present
// yet (operator skipped `bob_repo_inventory`), fall back to `false`.
function loadNfsXdrShape(targetDomain) {
  const { repoInventoryPath } = require("./paths.js");
  const invPath = repoInventoryPath(targetDomain);
  if (!fs.existsSync(invPath)) return false;
  try {
    const raw = fs.readFileSync(invPath, "utf8");
    const doc = JSON.parse(raw);
    return Boolean(doc && doc.nfs_xdr_shape);
  } catch {
    return false;
  }
}

async function prepareRepoEnv({
  target_domain: targetDomain,
  base_image: baseImageOverride = null,
  build_image: buildImage = false,
  dry_run: dryRun = true,
  allow_network: allowNetwork = false,
  image_tag: imageTagOverride = null,
  timeout_ms: timeoutMsOverride = null,
  egress_profile: egressProfileNameOverride = null,
  runtime = null,
} = {}) {
  const domain = assertSafeDomain(targetDomain);
  const repoSession = readRepoSession(domain);
  const repoRoot = repoSession.target_repo.root_path;
  if (!fs.existsSync(repoRoot) || !fs.statSync(repoRoot).isDirectory()) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `bound repo path is no longer a directory: ${repoRoot}`,
      { repo_error_code: "repo_path_not_directory" },
    );
  }

  const normalizedDryRun = dryRun == null ? true : assertBoolean(dryRun, "dry_run");
  const normalizedBuildImage = buildImage == null ? false : assertBoolean(buildImage, "build_image");
  const normalizedAllowNetwork = allowNetwork == null ? false : assertBoolean(allowNetwork, "allow_network");
  if (normalizedDryRun && normalizedBuildImage) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "dry_run and build_image are mutually exclusive; set dry_run: false to build",
    );
  }
  const timeoutMs = timeoutMsOverride == null
    ? DEFAULT_DOCKER_BUILD_TIMEOUT_MS
    : assertInteger(timeoutMsOverride, "timeout_ms", { min: 1000, max: MAX_DOCKER_BUILD_TIMEOUT_MS });

  const detection = detectLanguageProfile(repoRoot);
  const baseImage = baseImageOverride
    ? assertNonEmptyString(baseImageOverride, "base_image")
    : detection.base_image;
  const nfsXdrShape = loadNfsXdrShape(domain);
  const recommendedCommands = recommendedCommandsFor(detection.language, { nfsXdrShape });
  for (const command of recommendedCommands) {
    assertEnumValue(command.role, RECOMMENDED_COMMAND_ROLES, `recommended_commands[${command.id}].role`);
  }

  const imageTag = imageTagOverride
    ? assertNonEmptyString(imageTagOverride, "image_tag")
    : buildImageTag(domain, repoSession.repo_hash);

  // Resolve egress profile early so build-time proxy routing is deterministic
  // and visible in repo-env.json. We do NOT short-circuit when the profile
  // name override is null — the session's bound egress profile (from
  // state.json) is the default. When `allow_network: false`, we still
  // record the profile name for provenance, but its proxy_url is not
  // injected into the build args.
  let egressProfileResolved = null;
  try {
    const { state } = readSessionStateStrict(domain);
    const profileName = egressProfileNameOverride || state.egress_profile || "default";
    egressProfileResolved = resolveEgressProfile(profileName);
  } catch (error) {
    if (normalizedAllowNetwork) {
      // We need a usable proxy resolution if the operator opened network
      // access. Surface the error explicitly.
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `failed to resolve egress profile for repo build: ${error.message || error}`,
        { repo_error_code: "egress_profile_unresolved" },
      );
    }
  }

  const egressProfileSummary = egressProfileResolved
    ? {
        name: egressProfileResolved.name,
        region: egressProfileResolved.region,
        proxy_configured: egressProfileResolved.proxy_configured,
        proxy_url_redacted: egressProfileResolved.proxy_url_redacted,
        egress_profile_identity_hash: egressProfileResolved.egress_profile_identity_hash,
      }
    : null;

  const dockerfileContent = buildDockerfileBob({
    language: detection.language,
    baseImage,
    targetDomain: domain,
    nfsXdrShape,
    allowNetwork: normalizedAllowNetwork,
  });
  assertNoEnvSecretLeak(dockerfileContent);

  const generatedAt = new Date().toISOString();
  const document = buildRepoEnvDocument({
    targetDomain: domain,
    repoSession,
    repoRoot,
    detection,
    recommendedCommands,
    imageTag,
    baseImage,
    buildImage: normalizedBuildImage,
    dryRun: normalizedDryRun,
    allowNetwork: normalizedAllowNetwork,
    egressProfileSummary,
    generatedAt,
    nfsXdrShape,
  });
  // O-P7: scrub-validate before persistence. The recommended_commands carry
  // shell strings; the validator already catches inline tokens like
  // "PASSWORD=hunter2" via SENSITIVE_VALUE_RE so a future operator override
  // can't smuggle credentials into the recipe.
  validateNoSensitiveMaterial(document, "repo_env");
  document.repo_env_hash = hashDocumentExcluding(document, ["generated_at", "repo_env_hash"]);

  // Phase 1: synchronous persistence under the session lock. The lock helper
  // refuses async callbacks (storage.js: "withSessionLock callback must be
  // synchronous"), so docker build — which is inherently async — happens in
  // phase 2 below, after the lock is released. That ordering also matches
  // the contract that artefacts are durable on disk before any out-of-process
  // side effect fires.
  const persisted = withSessionLock(domain, () => {
    const dockerfilePath = dockerfileBobPath(domain);
    const repoEnvPath = repoEnvJsonPath(domain);
    fs.writeFileSync(dockerfilePath, dockerfileContent, "utf8");
    writeJsonDocument(repoEnvPath, document);
    return { dockerfilePath, repoEnvPath };
  });
  const dockerfilePath = persisted.dockerfilePath;
  const repoEnvPath = persisted.repoEnvPath;

  if (normalizedBuildImage) {
    const dockerAvailable = await dockerIsAvailable(runtime);
    if (!dockerAvailable) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        "docker is not installed or not in PATH; rerun with dry_run: true",
        { repo_error_code: "docker_unavailable" },
      );
    }
    const argv = buildDockerBuildArgv({
      dockerfilePath,
      contextPath: repoRoot,
      imageTag,
      allowNetwork: normalizedAllowNetwork,
      targetDomain: domain,
      egressProfile: egressProfileResolved,
    });
    const runner = runtime && typeof runtime.execFile === "function"
      ? runtime.execFile
      : execFilePromise;
    try {
      await runner(argv.command, argv.args, { timeout: timeoutMs, env: { ...process.env, ...(argv.env || {}) } });
    } catch (error) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `docker build failed: ${error.message || error}`,
        { repo_error_code: "docker_build_failed" },
      );
    }
  }

  return {
    created: true,
    target_domain: domain,
    repo_path: repoRoot,
    dockerfile_path: dockerfilePath,
    repo_env_path: repoEnvPath,
    image_tag: imageTag,
    base_image: baseImage,
    language: detection.language,
    nfs_xdr_shape: nfsXdrShape,
    dry_run: normalizedDryRun,
    build_image: normalizedBuildImage,
    allow_network: normalizedAllowNetwork,
    recommended_commands: recommendedCommands,
    repo_env_hash: document.repo_env_hash,
    egress_profile: egressProfileSummary,
  };
}

module.exports = {
  // Public API
  prepareRepoEnv,
  // Helpers exposed for cross-module reuse / tests
  buildDockerfileBob,
  buildDockerBuildArgv,
  buildImageTag,
  detectLanguageProfile,
  recommendedCommandsFor,
  assertNoEnvSecretLeak,
  dockerfileBobPath,
  repoEnvJsonPath,
  loadNfsXdrShape,
  // Constants
  DEFAULT_DOCKER_BUILD_TIMEOUT_MS,
  MAX_DOCKER_BUILD_TIMEOUT_MS,
  RECOMMENDED_COMMAND_ROLES,
  REPO_ENV_VERSION,
  C_DEFAULT_APT_PACKAGES,
  NFS_EXTRA_APT_PACKAGES,
  ENV_SECRET_LEAK_RE,
};

// Quiet imports for parity with sibling repo-target.js. These are kept so
// future expansions (e.g., normalizing operator-provided base_image text)
// don't need to re-import.
// eslint-disable-next-line no-unused-vars
const _unusedNormalizeOptionalText = normalizeOptionalText;
