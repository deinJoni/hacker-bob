const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  BUNDLE_FILES,
  exportBobReleaseBundle,
  renderExportResult,
} = require("../mcp/lib/bob-export.js");
const {
  pipelineEventsJsonlPath,
  sessionDir,
  statePath,
} = require("../mcp/lib/paths.js");

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function appendJsonl(filePath, rows) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${rows.map((row) => typeof row === "string" ? row : JSON.stringify(row)).join("\n")}\n`, "utf8");
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function readJsonl(filePath) {
  const text = fs.readFileSync(filePath, "utf8").trim();
  return text ? text.split(/\r?\n/).map((line) => JSON.parse(line)) : [];
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-export-home-"));
  process.env.HOME = tempHome;
  try {
    fn(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

function writeSession(domain, events) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeJson(statePath(domain), {
    target: domain,
    target_url: `https://${domain}`,
    phase: "REPORT",
    hunt_wave: 1,
    pending_wave: null,
    total_findings: 0,
    hold_count: 0,
    auth_status: "pending",
    explored: [],
    terminally_blocked: [],
  });
  if (events.length > 0) {
    appendJsonl(pipelineEventsJsonlPath(domain), events);
  }
}

function pipelineEvent(domain, bobVersion, ts, type = "session_started") {
  return {
    version: 1,
    bob_version: bobVersion,
    ts,
    target_domain: domain,
    type,
    phase: type === "session_started" ? "RECON" : undefined,
    source: "test",
  };
}

test("Bob export creates a version-scoped deterministic improvement bundle", () => {
  withTempHome((tempHome) => {
    const projectDir = path.join(tempHome, "project");
    const telemetryRoot = path.join(tempHome, "bounty-agent-telemetry");
    fs.mkdirSync(path.join(projectDir, ".hacker-bob"), { recursive: true });
    fs.writeFileSync(path.join(projectDir, ".hacker-bob", "VERSION"), "9.9.9\n", "utf8");

    writeSession("current.example", [
      pipelineEvent("current.example", "9.9.9", "2026-05-08T10:00:00.000Z"),
      pipelineEvent("current.example", "9.9.9", "2026-05-08T10:01:00.000Z", "phase_transitioned"),
    ]);
    writeSession("old.example", [
      pipelineEvent("old.example", "9.9.8", "2026-05-08T10:00:00.000Z"),
    ]);
    writeSession("mixed.example", [
      pipelineEvent("mixed.example", "9.9.8", "2026-05-08T10:00:00.000Z"),
      pipelineEvent("mixed.example", "9.9.9", "2026-05-08T10:01:00.000Z"),
    ]);
    writeSession("unknown.example", []);

    appendJsonl(path.join(telemetryRoot, "tool-events.jsonl"), [
      {
        version: 1,
        bob_version: "9.9.9",
        ts: "2026-05-08T10:02:00.000Z",
        tool: "bounty_http_scan",
        ok: false,
        elapsed_ms: 12,
        error_code: "NETWORK_ERROR",
        target_domain: "current.example",
      },
      {
        version: 1,
        bob_version: "9.9.9",
        ts: "2026-05-08T10:03:00.000Z",
        tool: "bounty_read_session_summary",
        ok: true,
        elapsed_ms: 4,
        target_domain: "current.example",
      },
      {
        version: 1,
        bob_version: "9.9.8",
        ts: "2026-05-08T10:04:00.000Z",
        tool: "bounty_http_scan",
        ok: false,
        elapsed_ms: 7,
        error_code: "OLD_ERROR",
        target_domain: "old.example",
      },
      {
        version: 1,
        ts: "2026-05-08T10:05:00.000Z",
        tool: "bounty_http_scan",
        ok: false,
        elapsed_ms: 7,
        error_code: "UNKNOWN_VERSION",
        target_domain: "unknown.example",
      },
      "{bad-json",
    ]);
    appendJsonl(path.join(telemetryRoot, "agent-runs.jsonl"), [
      {
        version: 1,
        bob_version: "9.9.9",
        ts: "2026-05-08T10:06:00.000Z",
        run_id: "run-current",
        run_type: "hunter",
        status: "blocked",
        block_code: "MISSING_HANDOFF",
        target_domain: "current.example",
        wave: "w1",
        agent: "a1",
        surface_id: "s1",
      },
      {
        version: 1,
        bob_version: "9.9.8",
        ts: "2026-05-08T10:07:00.000Z",
        run_id: "run-old",
        run_type: "hunter",
        status: "blocked",
        block_code: "OLD_BLOCK",
        target_domain: "old.example",
      },
    ]);

    const env = {
      ...process.env,
      BOUNTY_TELEMETRY_DIR: telemetryRoot,
    };
    const now = new Date("2026-05-08T12:00:00.123Z");
    const first = exportBobReleaseBundle({ projectDir, env, now });
    const second = exportBobReleaseBundle({ projectDir, env, now });

    assert.equal(first.ok, true);
    assert.equal(first.bob_version, "9.9.9");
    assert.match(first.bundle_dir, /release-bundles\/v9\.9\.9\/2026-05-08T12-00-00-123Z$/);
    assert.match(second.bundle_dir, /release-bundles\/v9\.9\.9\/2026-05-08T12-00-00-123Z-001$/);
    assert.notEqual(first.bundle_dir, second.bundle_dir);

    for (const fileName of BUNDLE_FILES) {
      assert.ok(fs.existsSync(path.join(first.bundle_dir, fileName)), `${fileName} should exist`);
    }

    const manifest = readJson(path.join(first.bundle_dir, "manifest.json"));
    assert.equal(manifest.bob_version, "9.9.9");
    assert.equal(manifest.counts.included_sessions, 1);
    assert.equal(manifest.counts.excluded_sessions, 3);
    assert.equal(manifest.counts.tool_events, 2);
    assert.equal(manifest.counts.agent_runs, 1);
    assert.equal(manifest.counts.malformed_tool_event_lines, 1);
    assert.deepEqual(
      manifest.exclusions.sessions.map((session) => session.reason).sort(),
      ["mixed_version", "unknown_version", "version_mismatch"],
    );
    assert.deepEqual(
      manifest.exclusions.telemetry.tool_events.map((row) => row.bob_version).sort(),
      ["9.9.8", "<unknown>"],
    );

    const sessions = readJson(path.join(first.bundle_dir, "sessions.json"));
    assert.deepEqual(sessions.sessions.map((session) => session.target_domain), ["current.example"]);
    assert.ok(sessions.sessions[0].event_log.events.every((event) => event.bob_version === "9.9.9"));

    const toolEvents = readJsonl(path.join(first.bundle_dir, "tool-events.filtered.jsonl"));
    assert.equal(toolEvents.length, 2);
    assert.ok(toolEvents.every((event) => event.bob_version === "9.9.9"));
    assert.ok(toolEvents.some((event) => event.error_code === "NETWORK_ERROR"));

    const agentRuns = readJsonl(path.join(first.bundle_dir, "agent-runs.filtered.jsonl"));
    assert.deepEqual(agentRuns.map((run) => run.block_code), ["MISSING_HANDOFF"]);

    const clusters = readJson(path.join(first.bundle_dir, "problem-clusters.json"));
    assert.ok(clusters.clusters.mcp_tool_errors.some((cluster) => (
      cluster.tool === "bounty_http_scan" && cluster.error_code === "NETWORK_ERROR"
    )));
    assert.ok(clusters.clusters.hunter_blocks.some((cluster) => cluster.block_code === "MISSING_HANDOFF"));
    assert.ok(clusters.clusters.version_exclusions.length >= 3);

    const prompt = fs.readFileSync(path.join(first.bundle_dir, "AGENT_PROMPT.md"), "utf8");
    assert.match(prompt, /improving Hacker Bob itself/);
    assert.match(prompt, /not for hunting/);
    assert.match(prompt, /summary\.md/);
    assert.match(prompt, /problem-clusters\.json/);
    assert.match(prompt, /manifest\.json/);
    assert.match(prompt, /source-paths\.txt/);
    assert.match(prompt, /preserve user privacy/);
    assert.match(prompt, /npm run test:mcp/);
    assert.match(prompt, /npm run release:check/);

    const sourcePaths = fs.readFileSync(path.join(first.bundle_dir, "source-paths.txt"), "utf8");
    assert.match(sourcePaths, /telemetry_tool_events/);
    assert.match(sourcePaths, /current\.example/);

    const rendered = renderExportResult(first);
    assert.match(rendered, new RegExp(`AGENT_PROMPT\\.md: ${first.files.AGENT_PROMPT.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    assert.match(rendered, /1 session, 2 tool events, 1 agent run, 3 excluded sessions/);
  });
});
