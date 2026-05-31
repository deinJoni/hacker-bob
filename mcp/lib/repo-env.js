"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const {
  assertBoolean,
  assertEnumValue,
  assertNonEmptyString,
  normalizeOptionalInteger,
  normalizeOptionalText,
} = require("./validation.js");
const {
  repoCommandRunsJsonlPath,
  repoDockerfilePath,
  repoEnvPath,
  repoInventoryPath,
  sessionDir,
} = require("./paths.js");
const {
  appendJsonlLine,
  withSessionLock,
  writeFileAtomic,
} = require("./storage.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");
const {
  NATIVE_CODE_EXTENSIONS,
  normalizeRepoPath,
  walkRepoFiles,
} = require("./repo-target.js");

const REPO_ENV_VERSION = 1;
const REPO_COMMAND_LOG_MAX_RECORDS = 500;
const DEFAULT_BASE_IMAGE = "ubuntu:24.04";
const MAX_TIMEOUT_MS = 10 * 60 * 1000;
const DEFAULT_RUN_TIMEOUT_MS = 2 * 60 * 1000;
const DEFAULT_BUILD_TIMEOUT_MS = 10 * 60 * 1000;
const MAX_OUTPUT_CHARS = 12000;

const REPO_MOUNT_MODES = Object.freeze(["read_only", "read_write"]);

function shortHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex").slice(0, 12);
}

function dockerSlug(value) {
  const normalized = String(value || "repo")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^[^a-z0-9]+/, "")
    .replace(/[^a-z0-9]+$/, "")
    .slice(0, 60);
  return normalized || "repo";
}

function normalizeDockerImageRef(value, fieldName) {
  const normalized = normalizeOptionalText(value, fieldName);
  if (!normalized) return null;
  if (!/^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,220}$/.test(normalized)) {
    throw new Error(`${fieldName} must be a Docker image reference`);
  }
  return normalized;
}

function defaultImageTag(domain, repoPath) {
  return `bob-oss-${dockerSlug(domain)}:${shortHash(repoPath)}`;
}

function assertRepoSession(domain) {
  const { state } = readSessionStateStrict(domain);
  if (state.target_kind !== "repo" || !state.repo || !state.repo.root_path) {
    throw new Error("repo Docker tools require a repo session initialized by bounty_init_repo_session");
  }
  return {
    state,
    repoPath: normalizeRepoPath(state.repo.root_path),
  };
}

function readJsonIfExists(filePath) {
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

function basenameIs(files, name) {
  return files.some((file) => path.basename(file) === name);
}

function readRepoText(repoPath, relativePath, maxBytes = 512 * 1024) {
  try {
    const fullPath = path.join(repoPath, relativePath);
    const stat = fs.statSync(fullPath);
    if (!stat.isFile() || stat.size > maxBytes) return "";
    return fs.readFileSync(fullPath, "utf8");
  } catch {
    return "";
  }
}

function detectBuildEnvironment(repoPath, files) {
  const dockerfiles = files.filter((file) => path.basename(file).endsWith("Dockerfile")).slice(0, 40);
  const composeFiles = files.filter((file) => /(^|\/)(docker-)?compose\.ya?ml$/i.test(file)).slice(0, 40);
  const devcontainerFiles = files.filter((file) => file.startsWith(".devcontainer/")).slice(0, 40);
  const cLike = files.some((file) => NATIVE_CODE_EXTENSIONS.has(path.extname(file).toLowerCase()));
  const cmake = basenameIs(files, "CMakeLists.txt");
  const autoconf = basenameIs(files, "configure") || basenameIs(files, "configure.ac") || basenameIs(files, "configure.in") || basenameIs(files, "Makefile.am");
  const make = basenameIs(files, "Makefile");
  const node = basenameIs(files, "package.json");
  const python = basenameIs(files, "pyproject.toml") || basenameIs(files, "requirements.txt") || basenameIs(files, "setup.py");
  const go = basenameIs(files, "go.mod");
  const rust = basenameIs(files, "Cargo.toml");
  const ruby = basenameIs(files, "Gemfile");
  const php = basenameIs(files, "composer.json");
  const java = basenameIs(files, "pom.xml") || basenameIs(files, "build.gradle") || basenameIs(files, "build.gradle.kts");
  const libnfsLike = files.some((file) => /(^|\/)(libnfs|nfs)/i.test(file)) ||
    fs.existsSync(path.join(repoPath, "libnfs.pc.in"));
  // Detect a libpcap build dependency (tcpdump and similar packet tools) so the
  // session image ships libpcap-dev; without it native-code builds cannot link.
  const buildConfigText = [
    "configure.ac",
    "configure.in",
    "CMakeLists.txt",
    "Makefile.am",
    "Makefile.in",
  ].map((name) => readRepoText(repoPath, name)).join("\n");
  const pcapLike = /pcap/i.test(buildConfigText);

  const buildSystems = [];
  if (cmake) buildSystems.push("cmake");
  if (autoconf) buildSystems.push("autoconf");
  if (make) buildSystems.push("make");
  if (node) buildSystems.push("node");
  if (python) buildSystems.push("python");
  if (go) buildSystems.push("go");
  if (rust) buildSystems.push("rust");
  if (ruby) buildSystems.push("ruby");
  if (php) buildSystems.push("php");
  if (java) buildSystems.push("java");

  return {
    dockerfiles,
    compose_files: composeFiles,
    devcontainer_files: devcontainerFiles,
    build_systems: buildSystems,
    source_hints: {
      c_cpp: cLike,
      node,
      python,
      go,
      rust,
      ruby,
      php,
      java,
      libnfs_like: libnfsLike,
      pcap_like: pcapLike,
    },
  };
}

function dockerPackagesForDetection(detected) {
  const packages = new Set(["ca-certificates", "bash", "coreutils", "findutils", "git", "curl", "pkg-config"]);
  if (detected.source_hints.c_cpp || detected.build_systems.some((system) => ["cmake", "autoconf", "make"].includes(system))) {
    [
      "build-essential",
      "clang",
      "cmake",
      "ninja-build",
      "make",
      "autoconf",
      "automake",
      "libtool",
      "gdb",
      "valgrind",
      "python3",
    ].forEach((pkg) => packages.add(pkg));
  }
  if (detected.source_hints.libnfs_like) {
    ["libssl-dev", "libkrb5-dev", "libtirpc-dev"].forEach((pkg) => packages.add(pkg));
  }
  if (detected.source_hints.pcap_like) {
    packages.add("libpcap-dev");
  }
  if (detected.source_hints.node) ["nodejs", "npm"].forEach((pkg) => packages.add(pkg));
  if (detected.source_hints.python) ["python3", "python3-pip", "python3-venv"].forEach((pkg) => packages.add(pkg));
  if (detected.source_hints.go) packages.add("golang-go");
  if (detected.source_hints.rust) ["rustc", "cargo"].forEach((pkg) => packages.add(pkg));
  if (detected.source_hints.ruby) ["ruby", "ruby-dev", "bundler"].forEach((pkg) => packages.add(pkg));
  if (detected.source_hints.php) ["php-cli", "composer"].forEach((pkg) => packages.add(pkg));
  if (detected.source_hints.java) ["default-jdk", "maven", "gradle"].forEach((pkg) => packages.add(pkg));
  return Array.from(packages).sort();
}

function renderDockerfile({ baseImage, packages }) {
  return [
    `FROM ${baseImage}`,
    "ENV DEBIAN_FRONTEND=noninteractive",
    "RUN apt-get update \\",
    `  && apt-get install -y --no-install-recommends ${packages.join(" ")} \\`,
    "  && rm -rf /var/lib/apt/lists/*",
    "RUN mkdir -p /src /work",
    "WORKDIR /work",
    "",
  ].join("\n");
}

function recommendedCommands(detected) {
  const commands = [];
  if (detected.build_systems.includes("cmake")) {
    commands.push({
      id: "cmake-build-test",
      description: "Configure, build, and run CTest from a writable /work build directory.",
      command: ["sh", "-lc", "cmake -S /src -B /work/build -DCMAKE_BUILD_TYPE=Debug && cmake --build /work/build -j2 && ctest --test-dir /work/build --output-on-failure"],
    });
  }
  if (detected.build_systems.includes("autoconf") || detected.build_systems.includes("make")) {
    commands.push({
      id: "autotools-build-test",
      description: "Copy the repo into /work, then run configure/make/check without writing to the host checkout.",
      command: ["sh", "-lc", "cp -a /src /work/repo && cd /work/repo && { [ -x ./bootstrap ] && ./bootstrap || true; } && { [ -x ./configure ] && ./configure || true; } && make -j2 && { make check || true; }"],
    });
  }
  if (detected.build_systems.includes("node")) {
    commands.push({
      id: "node-install-test",
      description: "Copy the repo into /work, install Node dependencies, and run the package test script.",
      command: ["sh", "-lc", "cp -a /src /work/repo && cd /work/repo && npm ci && npm test"],
    });
  }
  if (detected.build_systems.includes("python")) {
    commands.push({
      id: "python-test",
      description: "Copy the repo into /work, install Python test dependencies, and run pytest if present.",
      command: ["sh", "-lc", "cp -a /src /work/repo && cd /work/repo && python3 -m venv /work/venv && . /work/venv/bin/activate && { [ -f requirements.txt ] && pip install -r requirements.txt || true; } && { [ -f pyproject.toml ] && pip install -e . || true; } && python -m pytest"],
    });
  }
  if (detected.build_systems.includes("go")) {
    commands.push({
      id: "go-test",
      description: "Run Go tests from the read-only mounted repo.",
      command: ["sh", "-lc", "cd /src && go test ./..."],
    });
  }
  if (detected.build_systems.includes("rust")) {
    commands.push({
      id: "cargo-test",
      description: "Copy the repo into /work and run cargo test without writing to the host checkout.",
      command: ["sh", "-lc", "cp -a /src /work/repo && cd /work/repo && cargo test"],
    });
  }
  return commands.slice(0, 10);
}

function createOutputCollector(maxChars = MAX_OUTPUT_CHARS) {
  let text = "";
  let truncatedChars = 0;
  return {
    append(chunk) {
      const value = String(chunk);
      const remaining = maxChars - text.length;
      if (remaining > 0) {
        text += value.slice(0, remaining);
      }
      if (value.length > remaining) {
        truncatedChars += value.length - Math.max(remaining, 0);
      }
    },
    value() {
      if (truncatedChars <= 0) return text;
      return `${text}\n[truncated ${truncatedChars} chars]`;
    },
  };
}

function runProcess(command, args, { cwd, timeoutMs }) {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    const stdout = createOutputCollector();
    const stderr = createOutputCollector();
    let resolved = false;
    let timedOut = false;
    let child;

    function finish(result) {
      if (resolved) return;
      resolved = true;
      resolve({
        ...result,
        duration_ms: Date.now() - startedAt,
        stdout: stdout.value(),
        stderr: stderr.value(),
      });
    }

    try {
      child = spawn(command, args, { cwd, stdio: ["ignore", "pipe", "pipe"] });
    } catch (error) {
      finish({
        exit_code: null,
        signal: null,
        timed_out: false,
        spawn_error: error.code || error.message,
      });
      return;
    }

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.stdout.on("data", (chunk) => stdout.append(chunk.toString("utf8")));
    child.stderr.on("data", (chunk) => stderr.append(chunk.toString("utf8")));
    child.on("error", (error) => {
      clearTimeout(timer);
      finish({
        exit_code: null,
        signal: null,
        timed_out: false,
        spawn_error: error.code || error.message,
      });
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      finish({
        exit_code: code,
        signal,
        timed_out: timedOut,
      });
    });
  });
}

function normalizeTimeoutMs(value, fieldName, fallback) {
  return normalizeOptionalInteger(value, fieldName, { min: 1000, max: MAX_TIMEOUT_MS }) || fallback;
}

function normalizeCommand(value) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("command must be a non-empty argv array");
  }
  if (value.length > 30) {
    throw new Error("command must contain at most 30 argv entries");
  }
  return value.map((item, index) => {
    if (typeof item !== "string" || !item.trim()) {
      throw new Error(`command[${index}] must be a non-empty string`);
    }
    if (item.includes("\u0000")) {
      throw new Error(`command[${index}] must not contain NUL bytes`);
    }
    return item;
  });
}

function buildDockerPreview(args) {
  return ["docker", ...args];
}

async function prepareRepoEnv(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const { repoPath } = assertRepoSession(domain);
  const dryRun = args.dry_run == null ? false : assertBoolean(args.dry_run, "dry_run");
  const buildImage = args.build_image == null ? false : assertBoolean(args.build_image, "build_image");
  const allowNetwork = args.allow_network == null ? false : assertBoolean(args.allow_network, "allow_network");
  const baseImage = normalizeDockerImageRef(args.base_image, "base_image") || DEFAULT_BASE_IMAGE;
  const imageTag = normalizeDockerImageRef(args.image_tag, "image_tag") || defaultImageTag(domain, repoPath);
  const timeoutMs = normalizeTimeoutMs(args.timeout_ms, "timeout_ms", DEFAULT_BUILD_TIMEOUT_MS);
  const files = walkRepoFiles(repoPath);
  const inventory = readJsonIfExists(repoInventoryPath(domain));
  const detected = detectBuildEnvironment(repoPath, files);
  const packages = dockerPackagesForDetection(detected);
  const dockerfile = renderDockerfile({ baseImage, packages });
  const dockerfilePath = repoDockerfilePath(domain);
  const buildArgs = [
    "build",
    "--pull=false",
    "--network",
    allowNetwork ? "default" : "none",
    "-f",
    dockerfilePath,
    "-t",
    imageTag,
    sessionDir(domain),
  ];
  const envPlan = {
    version: REPO_ENV_VERSION,
    target_domain: domain,
    repo_path: repoPath,
    generated_at: new Date().toISOString(),
    base_image: baseImage,
    image_tag: imageTag,
    dockerfile_path: dockerfilePath,
    docker_build: {
      requested: buildImage,
      dry_run: dryRun,
      allow_network: allowNetwork,
      timeout_ms: timeoutMs,
      command: buildDockerPreview(buildArgs),
      status: buildImage ? "pending" : "not_requested",
    },
    detected,
    inventory_counts: inventory && inventory.counts ? inventory.counts : null,
    packages,
    recommended_commands: recommendedCommands(detected),
    defaults: {
      repo_mount: "/src",
      workdir: "/work",
      network: "none",
      repo_mount_mode: "read_only",
    },
  };

  withSessionLock(domain, () => {
    writeFileAtomic(dockerfilePath, dockerfile);
    writeFileAtomic(repoEnvPath(domain), `${JSON.stringify(envPlan, null, 2)}\n`);
  });

  if (buildImage) {
    if (dryRun) {
      envPlan.docker_build.status = "dry_run";
    } else {
      const result = await runProcess("docker", buildArgs, { cwd: sessionDir(domain), timeoutMs });
      envPlan.docker_build = {
        ...envPlan.docker_build,
        status: result.spawn_error === "ENOENT" ? "docker_unavailable" : result.exit_code === 0 ? "ok" : "failed",
        exit_code: result.exit_code,
        signal: result.signal,
        timed_out: result.timed_out,
        duration_ms: result.duration_ms,
        spawn_error: result.spawn_error || null,
        stdout: result.stdout,
        stderr: result.stderr,
      };
    }
    withSessionLock(domain, () => {
      writeFileAtomic(repoEnvPath(domain), `${JSON.stringify(envPlan, null, 2)}\n`);
    });
  }

  return JSON.stringify({
    version: 1,
    target_domain: domain,
    repo_env_path: repoEnvPath(domain),
    dockerfile_path: dockerfilePath,
    env: envPlan,
  }, null, 2);
}

async function repoDockerRun(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const { repoPath } = assertRepoSession(domain);
  const command = normalizeCommand(args.command);
  const dryRun = args.dry_run == null ? false : assertBoolean(args.dry_run, "dry_run");
  const allowNetwork = args.allow_network == null ? false : assertBoolean(args.allow_network, "allow_network");
  const repoMountMode = assertEnumValue(args.repo_mount_mode || "read_only", REPO_MOUNT_MODES, "repo_mount_mode");
  const timeoutMs = normalizeTimeoutMs(args.timeout_ms, "timeout_ms", DEFAULT_RUN_TIMEOUT_MS);
  let envPlan = readJsonIfExists(repoEnvPath(domain));
  if (!envPlan) {
    envPlan = JSON.parse(await prepareRepoEnv({ target_domain: domain, dry_run: true })).env;
  }
  const imageTag = normalizeDockerImageRef(args.image_tag, "image_tag") || envPlan.image_tag || defaultImageTag(domain, repoPath);
  const runId = `run-${Date.now()}-${shortHash(command.join("\u0000")).slice(0, 8)}`;
  const runDir = path.join(sessionDir(domain), "repo-runs", runId);
  fs.mkdirSync(runDir, { recursive: true });
  const dockerArgs = [
    "run",
    "--rm",
    "--network",
    allowNetwork ? "bridge" : "none",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--pids-limit",
    "256",
    "--memory",
    "2g",
    "--cpus",
    "2",
    "-v",
    `${repoPath}:/src:${repoMountMode === "read_only" ? "ro" : "rw"}`,
    "-v",
    `${runDir}:/work:rw`,
    "-w",
    "/work",
    imageTag,
    ...command,
  ];
  const record = {
    version: 1,
    target_domain: domain,
    ts: new Date().toISOString(),
    runner: "docker",
    run_id: runId,
    dry_run: dryRun,
    image_tag: imageTag,
    command,
    docker_command: buildDockerPreview(dockerArgs),
    network: allowNetwork ? "bridge" : "none",
    repo_mount_mode: repoMountMode,
    run_dir: runDir,
    timeout_ms: timeoutMs,
    status: dryRun ? "dry_run" : "pending",
  };

  if (!dryRun) {
    const result = await runProcess("docker", dockerArgs, { cwd: runDir, timeoutMs });
    record.status = result.spawn_error === "ENOENT" ? "docker_unavailable" : result.exit_code === 0 ? "ok" : "failed";
    record.exit_code = result.exit_code;
    record.signal = result.signal;
    record.timed_out = result.timed_out;
    record.duration_ms = result.duration_ms;
    record.spawn_error = result.spawn_error || null;
    record.stdout = result.stdout;
    record.stderr = result.stderr;
  }

  return withSessionLock(domain, () => {
    appendJsonlLine(repoCommandRunsJsonlPath(domain), record, { maxRecords: REPO_COMMAND_LOG_MAX_RECORDS });
    return JSON.stringify({
      version: 1,
      target_domain: domain,
      repo_command_runs_path: repoCommandRunsJsonlPath(domain),
      run: record,
    }, null, 2);
  });
}

module.exports = {
  REPO_ENV_VERSION,
  prepareRepoEnv,
  repoDockerRun,
};
