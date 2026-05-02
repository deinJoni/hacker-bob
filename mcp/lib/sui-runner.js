"use strict";

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { resolveSuiRpcEndpoints, isPublicHttpsUrl } = require("./sui-rpc-pool.js");
const { parseMoveTestStdout } = require("./move-test-output.js");

const DEFAULT_TIMEOUT_MS = 90_000;
const MAX_TIMEOUT_MS = 600_000;
const MAX_OUTPUT_BYTES = 512 * 1024;
const RAW_EXCERPT_BYTES = 8 * 1024;

// Allowlisted `sui move test` flags. Forbidden: --client.config (could read
// off-home config), --rpc-url (network override that bypasses our RPC pool),
// --gas-coin (irrelevant for local tests).
const SUI_EXTRA_ARG_ALLOWLIST = new Set([
  "--skip-fetch-latest-git-deps",
  "--coverage",
  "--gas-limit",
  "--lint",
  "--no-lint",
  "--silence-warnings",
]);

function isUnderHome(absPath) {
  let home = os.homedir();
  try { home = fs.realpathSync(home); } catch {}
  return absPath.startsWith(home + path.sep) || absPath === home;
}

function assertHarnessPath(harnessPath) {
  if (typeof harnessPath !== "string" || !harnessPath.trim()) {
    throw new Error("harness_path is required");
  }
  const resolved = path.resolve(harnessPath);
  if (!isUnderHome(resolved)) {
    throw new Error(`harness_path must live under the user home directory; received: ${resolved}`);
  }
  if (!fs.existsSync(resolved)) {
    throw new Error(`harness_path does not exist: ${resolved}`);
  }
  const realResolved = fs.realpathSync(resolved);
  if (!isUnderHome(realResolved)) {
    throw new Error(`harness_path must live under the user home directory after symlink resolution; resolved to: ${realResolved}`);
  }
  const stat = fs.statSync(realResolved);
  if (!stat.isDirectory()) {
    throw new Error(`harness_path must be a directory: ${realResolved}`);
  }
  return realResolved;
}

function spawnSui(args, { workdir, env, timeoutMs }) {
  return new Promise((resolve) => {
    let killed = false;
    const stdoutChunks = [];
    const stderrChunks = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;

    let child;
    try {
      child = spawn("sui", args, {
        cwd: workdir,
        env: { ...process.env, ...env },
        stdio: ["ignore", "pipe", "pipe"],
        detached: true,
      });
    } catch (error) {
      resolve({
        ok: false,
        reason: "sui_spawn_failed",
        error: error.message || String(error),
      });
      return;
    }

    const killGroup = (signal) => {
      try {
        if (child.pid) process.kill(-child.pid, signal);
      } catch {
        try { child.kill(signal); } catch {}
      }
    };

    const timer = setTimeout(() => {
      killed = true;
      killGroup("SIGTERM");
      setTimeout(() => killGroup("SIGKILL"), 5000);
    }, timeoutMs);

    child.stdout.on("data", (chunk) => {
      const remaining = MAX_OUTPUT_BYTES - stdoutBytes;
      if (remaining > 0) {
        stdoutChunks.push(chunk.length > remaining ? chunk.subarray(0, remaining) : chunk);
      }
      stdoutBytes += chunk.length;
    });
    child.stderr.on("data", (chunk) => {
      const remaining = MAX_OUTPUT_BYTES - stderrBytes;
      if (remaining > 0) {
        stderrChunks.push(chunk.length > remaining ? chunk.subarray(0, remaining) : chunk);
      }
      stderrBytes += chunk.length;
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({
        ok: false,
        reason: error.code === "ENOENT" ? "sui_not_in_path" : "sui_spawn_failed",
        error: error.message || String(error),
      });
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      const stdout = Buffer.concat(stdoutChunks).toString("utf8");
      const stderr = Buffer.concat(stderrChunks).toString("utf8");
      resolve({
        ok: !killed && code === 0,
        timed_out: killed,
        exit_code: code,
        signal,
        stdout,
        stderr,
        stdout_bytes: stdoutBytes,
        stderr_bytes: stderrBytes,
        truncated: stdoutBytes > MAX_OUTPUT_BYTES || stderrBytes > MAX_OUTPUT_BYTES,
      });
    });
  });
}

function truncateString(value, maxChars) {
  if (typeof value !== "string") return null;
  if (value.length <= maxChars) return value;
  return value.slice(0, maxChars) + `…[truncated, total ${value.length} chars]`;
}

const DEPENDENCY_MISSING_PATTERNS = [
  /(cargo|rustc):.*command not found/i,
  /(cargo|rustc):.*No such file or directory/i,
  /\bmove\b.*command not found/i,
  /\bmove-cli\b.*(command not found|No such file or directory)/i,
];
const COMPILE_FAIL_PATTERNS = [
  /Compilation error/i,
  /error\[E\d+\]/,
  /unable to find package/i,
  /failed to fetch git dependencies/i,
];
// Sui CLI versions vary in flag accepted; older versions take a positional
// regex argument instead of --filter and reject --path. A flag-rejection
// emits a clap usage error which we classify as a tooling blocker rather
// than letting it pass as a generic non-zero exit.
const CLI_USAGE_ERROR_PATTERNS = [
  /unrecognized argument/i,
  /found argument .* which wasn't expected/i,
  /unexpected argument/i,
  /the following required arguments were not provided/i,
  /^error: .*--filter|--path/im,
];

function classifySuiFailure(result, parseResultOk) {
  if (!result || result.ok || parseResultOk) return null;
  const stderr = String(result.stderr || "");
  const stdout = String(result.stdout || "");
  const combined = stderr + "\n" + stdout;
  for (const pattern of DEPENDENCY_MISSING_PATTERNS) {
    if (pattern.test(combined)) return "sui_dependency_missing";
  }
  for (const pattern of CLI_USAGE_ERROR_PATTERNS) {
    if (pattern.test(combined)) return "sui_dependency_missing";
  }
  if (!parseResultOk) {
    for (const pattern of COMPILE_FAIL_PATTERNS) {
      if (pattern.test(combined)) return "move_compile_failed";
    }
  }
  return null;
}

async function runSuiTest({
  workdir,
  matchTest,
  network,
  forkCheckpoint,
  forkUrls,
  extraArgs = [],
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  const resolvedWorkdir = assertHarnessPath(workdir);
  if (!matchTest) {
    throw new Error("match_test is required (sui move test --filter)");
  }
  if (typeof matchTest !== "string") throw new Error("match_test must be a string");
  if (matchTest.length < 1 || matchTest.length > 200) {
    throw new Error("match_test must be 1..200 chars");
  }
  const cappedTimeout = Math.min(Math.max(Number(timeoutMs) || DEFAULT_TIMEOUT_MS, 5_000), MAX_TIMEOUT_MS);

  const explicitForkUrls = Array.isArray(forkUrls)
    ? forkUrls.filter(isPublicHttpsUrl)
    : null;
  const candidateForkUrls = explicitForkUrls && explicitForkUrls.length > 0
    ? explicitForkUrls
    : (network ? resolveSuiRpcEndpoints(network) : []);

  // sui move test takes a positional filter (no --filter flag is required;
  // instead a regex argument matches test names). To stay deterministic and
  // cross-version we use --filter explicitly; CLI versions that don't
  // recognize the flag will surface a CLI usage error which we'll classify
  // as a runtime issue rather than a test failure.
  const baseArgs = ["move", "test", "--filter", matchTest, "--path", resolvedWorkdir];
  for (const arg of extraArgs) {
    if (typeof arg !== "string" || arg.length === 0 || arg.length > 200) continue;
    if (!SUI_EXTRA_ARG_ALLOWLIST.has(arg)) {
      throw new Error(`extra_args[${arg}] is not in the sui allowlist; accepted: ${[...SUI_EXTRA_ARG_ALLOWLIST].join(", ")}`);
    }
    baseArgs.push(arg);
  }

  const forkAttempts = [];
  if (candidateForkUrls.length === 0) {
    if (network != null && network !== "localnet") {
      // localnet has no public default — accept zero candidate URLs and let
      // the test run locally without a network. For other networks, fail
      // closed.
      return {
        ok: false,
        reason: "no_fork_endpoints_for_network",
        network,
        error: `no public RPC endpoints available for network ${network}; supply fork_urls explicitly or set BOB_SUI_RPCS_${String(network).toUpperCase().replace(/-/g, "_")}=url1,url2 in the MCP server env`,
        command: ["sui", ...baseArgs],
        fork_attempts: [],
      };
    }
    const result = await spawnSui(baseArgs, { workdir: resolvedWorkdir, timeoutMs: cappedTimeout, env: {} });
    return finalizeRun({ result, args: baseArgs, forkAttempts: [], forkCheckpoint, fork_used: null });
  }

  let lastResult = null;
  for (const url of candidateForkUrls) {
    const env = { BOB_SUI_FORK_URL: url, BOB_SUI_NETWORK: network || "" };
    const result = await spawnSui(baseArgs, { workdir: resolvedWorkdir, timeoutMs: cappedTimeout, env });
    lastResult = result;
    forkAttempts.push({
      endpoint: url,
      ok: result.ok,
      exit_code: result.exit_code,
      timed_out: result.timed_out === true,
      reason: result.reason || null,
      stderr_excerpt: truncateString(result.stderr || "", 600),
    });
    if (result.ok) {
      return finalizeRun({ result, args: baseArgs, forkAttempts, forkCheckpoint, fork_used: url });
    }
    if (result.reason === "sui_not_in_path") {
      return finalizeRun({ result, args: baseArgs, forkAttempts, forkCheckpoint, fork_used: null });
    }
    const looksLikeTestRan = typeof result.stdout === "string" && /\[\s*(PASS|FAIL|TIMEOUT|SKIP)\s*\]/.test(result.stdout);
    if (looksLikeTestRan) {
      return finalizeRun({ result, args: baseArgs, forkAttempts, forkCheckpoint, fork_used: url });
    }
  }
  return finalizeRun({ result: lastResult, args: baseArgs, forkAttempts, forkCheckpoint, fork_used: null });
}

function finalizeRun({ result, args, forkAttempts, forkCheckpoint, fork_used }) {
  if (!result || result.reason === "sui_not_in_path" || result.reason === "sui_spawn_failed") {
    return {
      ok: false,
      reason: result && result.reason ? result.reason : "spawn_failed",
      error: result && result.error ? result.error : null,
      command: ["sui", ...args],
      fork_attempts: forkAttempts,
    };
  }

  const parseResult = parseMoveTestStdout(result.stdout || "");
  const summary = parseResult.ok
    ? { tests: parseResult.tests, total: parseResult.total, passed: parseResult.passed, failed: parseResult.failed, timed_out: parseResult.timed_out, truncated: parseResult.truncated }
    : { tests: [], total: 0, passed: 0, failed: 0, timed_out: 0, truncated: false };

  const explicitFailureReason = classifySuiFailure(result, parseResult.ok);

  const allForkAttemptsFailed = forkAttempts.length > 0
    && forkAttempts.every((attempt) => attempt.ok !== true);
  const everyAttemptHasNoTestLines = forkAttempts.every((attempt) => {
    const stderr = String(attempt.stderr_excerpt || "");
    return !/\[\s*(PASS|FAIL|TIMEOUT|SKIP)\s*\]/.test(stderr);
  });
  const looksRpcUnreachable = allForkAttemptsFailed
    && everyAttemptHasNoTestLines
    && !parseResult.ok
    && !fork_used
    && !explicitFailureReason;

  let forkCheckpointUsed = null;
  if (forkCheckpoint != null) {
    forkCheckpointUsed = Number(forkCheckpoint);
  }

  const envelope = {
    ok: result.ok && parseResult.ok && summary.failed === 0 && summary.total > 0,
    timed_out: result.timed_out === true,
    exit_code: result.exit_code,
    signal: result.signal || null,
    fork_used,
    fork_checkpoint: forkCheckpoint || null,
    fork_checkpoint_used: forkCheckpointUsed,
    fork_attempts: forkAttempts,
    command: ["sui", ...args],
    summary: {
      total: summary.total,
      passed: summary.passed,
      failed: summary.failed,
      timed_out: summary.timed_out,
    },
    tests: summary.tests,
    tests_truncated: summary.truncated === true,
    raw_excerpt: {
      stdout: truncateString(result.stdout || "", RAW_EXCERPT_BYTES),
      stderr: truncateString(result.stderr || "", RAW_EXCERPT_BYTES),
      truncated: result.truncated === true,
    },
    parse_warning: parseResult.ok ? null : parseResult.reason,
  };
  if (explicitFailureReason) {
    envelope.reason = explicitFailureReason;
  } else if (looksRpcUnreachable) {
    envelope.reason = "rpc_unreachable";
  }
  return envelope;
}

module.exports = {
  SUI_EXTRA_ARG_ALLOWLIST,
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  classifySuiFailure,
  runSuiTest,
};
