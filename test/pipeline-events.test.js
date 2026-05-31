const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  normalizePipelineEvent,
} = require("../mcp/lib/pipeline-events.js");
const {
  CROSS_SESSION_ANALYTICS_MAX_SESSIONS,
  readPipelineAnalytics,
  readPipelineEvents,
} = require("../mcp/lib/pipeline-analytics.js");
const {
  HANDOFF_ANALYTICS_MAX_FILES,
  WAVE_READINESS_MAX_ASSIGNMENT_FILES,
  readSessionArtifactSummary,
} = require("../mcp/lib/pipeline-session-artifacts.js");
const {
  attackSurfacePath,
  pipelineEventsJsonlPath,
  statePath,
  waveAssignmentsPath,
} = require("../mcp/lib/paths.js");
const {
  appendToolTelemetryEvent,
  readToolTelemetryEvents,
  toolTelemetryPath,
  TOOL_TELEMETRY_MAX_RECORDS,
} = require("../mcp/lib/tool-telemetry.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-pipeline-events-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

test("normalizePipelineEvent rejects secret-shaped operational reasons", () => {
  assert.throws(
    () => normalizePipelineEvent("example.com", "phase_transitioned", {
      override_reason: "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
    }),
    /appears to contain secrets/,
  );
  assert.throws(
    () => normalizePipelineEvent("example.com", "wave_merged", {
      force_merge_reason: "api_key=abcdef1234567890",
    }),
    /appears to contain secrets/,
  );
});

test("readPipelineEvents does not backfill over an existing malformed event log", () => {
  withTempHome(() => {
    const filePath = pipelineEventsJsonlPath("example.com");
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, "{not json}\n", "utf8");

    const result = readPipelineEvents("example.com");
    assert.equal(result.exists, true);
    assert.equal(result.backfilled, false);
    assert.equal(result.events.length, 0);
    assert.equal(result.malformed_lines, 1);
  });
});

test("cross-session pipeline analytics bounds session scans and reuses telemetry reads", () => {
  withTempHome((home) => {
    const total = CROSS_SESSION_ANALYTICS_MAX_SESSIONS + 2;
    for (let i = 0; i < total; i++) {
      const domain = `pipeline-bound-${String(i).padStart(3, "0")}.example.com`;
      fs.mkdirSync(path.dirname(statePath(domain)), { recursive: true });
      fs.writeFileSync(statePath(domain), `${JSON.stringify({
        phase: "RECON",
        auth_status: "unknown",
      }, null, 2)}\n`, "utf8");
      fs.writeFileSync(pipelineEventsJsonlPath(domain), `${JSON.stringify(normalizePipelineEvent(domain, "session_started", {
        phase: "RECON",
        status: "started",
        source: "test",
        ts: new Date().toISOString(),
      }))}\n`, "utf8");
    }

    const analytics = JSON.parse(readPipelineAnalytics({ window_days: 1, limit: 100 }, {
      env: {
        ...process.env,
        BOUNTY_TELEMETRY_DIR: path.join(home, "telemetry"),
      },
    }));

    assert.equal(analytics.analytics_bounds.session_scan_limit, CROSS_SESSION_ANALYTICS_MAX_SESSIONS);
    assert.equal(analytics.analytics_bounds.sessions_available, total);
    assert.equal(analytics.analytics_bounds.sessions_considered, CROSS_SESSION_ANALYTICS_MAX_SESSIONS);
    assert.equal(analytics.analytics_bounds.sessions_truncated, true);
    assert.equal(analytics.analytics_bounds.telemetry_reads_reused, true);
    assert.ok(analytics.sessions.length <= CROSS_SESSION_ANALYTICS_MAX_SESSIONS);
  });
});

test("tool telemetry appends retain a bounded recent event window", () => {
  withTempHome((home) => {
    const env = {
      ...process.env,
      BOUNTY_TELEMETRY_DIR: path.join(home, "telemetry"),
    };
    for (let i = 0; i < TOOL_TELEMETRY_MAX_RECORDS + 2; i++) {
      appendToolTelemetryEvent({
        version: 1,
        bob_version: "test",
        ts: new Date(1700000000000 + i).toISOString(),
        tool: `tool_${i}`,
        ok: true,
        elapsed_ms: 1,
      }, { env });
    }

    const lines = fs.readFileSync(toolTelemetryPath(env), "utf8").trim().split("\n");
    assert.equal(lines.length, TOOL_TELEMETRY_MAX_RECORDS);
    assert.equal(JSON.parse(lines[0]).tool, "tool_2");
    assert.equal(readToolTelemetryEvents({ env }).events.length, TOOL_TELEMETRY_MAX_RECORDS);
  });
});

test("session artifact analytics caps handoff file inspection", () => {
  withTempHome(() => {
    const domain = "handoff-cap.example.com";
    fs.mkdirSync(path.dirname(statePath(domain)), { recursive: true });
    fs.writeFileSync(statePath(domain), `${JSON.stringify({ phase: "HUNT" })}\n`, "utf8");
    for (let i = 1; i <= HANDOFF_ANALYTICS_MAX_FILES + 3; i++) {
      fs.writeFileSync(
        path.join(path.dirname(statePath(domain)), `handoff-w1-a${i}.json`),
        "{not-json}\n",
        "utf8",
      );
    }

    const summary = readSessionArtifactSummary(domain);
    assert.equal(summary.chain_handoffs.handoff_files_total, HANDOFF_ANALYTICS_MAX_FILES + 3);
    assert.equal(summary.chain_handoffs.handoff_files_omitted, 3);
    assert.equal(summary.chain_handoffs.malformed_files, HANDOFF_ANALYTICS_MAX_FILES);
  });
});

test("session artifact analytics caps wave assignment payload inspection", () => {
  withTempHome(() => {
    const domain = "assignment-cap.example.com";
    const dir = path.dirname(statePath(domain));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(statePath(domain), `${JSON.stringify({ phase: "HUNT", pending_wave: 2 })}\n`, "utf8");
    for (let i = 1; i <= WAVE_READINESS_MAX_ASSIGNMENT_FILES + 3; i++) {
      fs.writeFileSync(path.join(dir, `wave-${i}-assignments.json`), "{not-json}\n", "utf8");
    }

    const summary = readSessionArtifactSummary(domain);
    assert.equal(summary.wave_bounds.assignment_file_scan_limit, WAVE_READINESS_MAX_ASSIGNMENT_FILES);
    assert.equal(summary.wave_bounds.assignment_files_total, WAVE_READINESS_MAX_ASSIGNMENT_FILES + 3);
    assert.equal(summary.wave_bounds.waves_considered, WAVE_READINESS_MAX_ASSIGNMENT_FILES);
    assert.equal(summary.wave_bounds.waves_omitted, 3);
    assert.equal(summary.wave_bounds.waves_truncated, true);
    assert.equal(summary.wave_bounds.pending_wave_included, true);
    assert.equal(summary.waves.length, WAVE_READINESS_MAX_ASSIGNMENT_FILES);
    assert.equal(summary.waves[0].wave_number, 2);
    assert.equal(summary.waves.at(-1).wave_number, WAVE_READINESS_MAX_ASSIGNMENT_FILES + 3);
    assert.equal(
      summary.artifact_errors.filter((error) => error.startsWith("Wave ")).length,
      WAVE_READINESS_MAX_ASSIGNMENT_FILES,
    );
  });
});

test("session artifact analytics preserves artifact summary shape and value semantics", () => {
  withTempHome(() => {
    const domain = "artifact-shape.example.com";
    const dir = path.dirname(statePath(domain));
    const stateFile = statePath(domain);
    const surfaceFile = attackSurfacePath(domain);
    const assignmentFile = waveAssignmentsPath(domain, 1);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(stateFile, `${JSON.stringify({
      target: domain,
      target_url: `https://${domain}`,
      phase: "HUNT",
      hunt_wave: 1,
      pending_wave: 1,
      explored: ["surface-a"],
      terminally_blocked: [{ surface_id: "surface-b" }],
    }, null, 2)}\n`, "utf8");
    fs.writeFileSync(surfaceFile, `${JSON.stringify({
      surfaces: [
        { id: "surface-a", priority: "HIGH" },
        { id: "surface-b", priority: "HIGH" },
        { id: "surface-c", priority: "LOW" },
      ],
    }, null, 2)}\n`, "utf8");
    fs.writeFileSync(assignmentFile, `${JSON.stringify({
      wave_number: 1,
      assignments: [
        { agent: "a1", surface_id: "surface-b" },
      ],
    }, null, 2)}\n`, "utf8");
    fs.writeFileSync(path.join(dir, "handoff-w1-a1.json"), `${JSON.stringify({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-b",
      surface_status: "complete",
      chain_notes: ["reuse the state-changing request in verification"],
    }, null, 2)}\n`, "utf8");

    const stateMtime = new Date("2026-05-17T00:00:00.000Z");
    const surfaceMtime = new Date("2026-05-17T00:01:00.000Z");
    fs.utimesSync(stateFile, stateMtime, stateMtime);
    fs.utimesSync(surfaceFile, surfaceMtime, surfaceMtime);

    const summary = readSessionArtifactSummary(domain);
    assert.deepEqual(Object.keys(summary).sort(), [
      "artifact_errors",
      "attack_surface_coverage",
      "chain_attempts",
      "chain_handoffs",
      "coverage",
      "evidence",
      "findings",
      "grade",
      "http_audit",
      "latest_artifact_ts",
      "report",
      "session_dir",
      "state",
      "target_domain",
      "technique_attempts",
      "technique_pack_reads",
      "verification",
      "wave_bounds",
      "waves",
    ].sort());
    assert.equal(summary.target_domain, domain);
    assert.equal(summary.state.phase, "HUNT");
    assert.equal(summary.findings.total, 0);
    assert.equal(summary.coverage.total_records, 0);
    assert.equal(summary.technique_attempts.total_records, 0);
    assert.equal(summary.technique_pack_reads.total_records, 0);
    assert.equal(summary.http_audit.total, 0);
    assert.equal(summary.chain_attempts.total, 0);
    assert.equal(summary.wave_bounds.assignment_files_total, 1);
    assert.equal(summary.waves.length, 1);
    assert.deepEqual(summary.waves[0].received_agents, ["a1"]);
    assert.equal(summary.waves[0].is_complete, true);
    assert.equal(summary.chain_handoffs.handoff_count, 1);
    assert.equal(summary.chain_handoffs.chain_notes_count, 1);
    assert.deepEqual(summary.chain_handoffs.handoff_refs, [{
      wave: "w1",
      agent: "a1",
      surface_id: "surface-b",
      chain_notes_count: 1,
    }]);
    assert.equal(summary.attack_surface_coverage.total_surfaces, 3);
    assert.equal(summary.attack_surface_coverage.non_low_total, 2);
    assert.equal(summary.attack_surface_coverage.non_low_explored, 1);
    assert.equal(summary.attack_surface_coverage.non_low_terminally_blocked, 1);
    assert.equal(summary.attack_surface_coverage.coverage_pct, 50);
    assert.equal(summary.attack_surface_coverage.closed_pct, 100);
    assert.equal(summary.attack_surface_coverage.blocked_high, 1);
    assert.equal(summary.attack_surface_coverage.unexplored_high, 0);
    assert.equal(summary.verification.final_reportable_count, 0);
    assert.equal(summary.evidence.valid, true);
    assert.equal(summary.grade.exists, false);
    assert.equal(summary.report.present, false);
    assert.equal(summary.latest_artifact_ts, surfaceMtime.toISOString());
    assert.deepEqual(summary.artifact_errors, []);
  });
});

test("session artifact analytics strips state fields when authority validation fails", () => {
  withTempHome(() => {
    const domain = "artifact-authority-invalid.example.com";
    const stateFile = statePath(domain);
    fs.mkdirSync(path.dirname(stateFile), { recursive: true });
    fs.writeFileSync(stateFile, `${JSON.stringify({
      target: domain,
      target_url: "https://other.example.com",
      phase: "HUNT",
      auth_status: "ready",
      checkpoint_mode: "paranoid",
      block_internal_hosts: true,
      block_internal_hosts_source: "operator",
      egress_profile: "operator-eu",
      egress_region: "EU",
      proxy_configured: true,
      egress_profile_identity_hash: "a".repeat(64),
      egress_profile_identity_version: 7,
      hunt_wave: 3,
      pending_wave: 2,
      total_findings: 9,
      hold_count: 1,
    }, null, 2)}\n`, "utf8");

    const summary = readSessionArtifactSummary(domain, { validateAuthority: true });
    assert.ok(summary.artifact_errors.some((error) => (
      /^Session authority invalid:/.test(error)
    )));
    assert.equal(summary.state.phase, null);
    assert.equal(summary.state.auth_status, null);
    assert.equal(summary.state.checkpoint_mode, null);
    assert.equal(summary.state.block_internal_hosts, null);
    assert.equal(summary.state.block_internal_hosts_source, null);
    assert.equal(summary.state.egress_profile, null);
    assert.equal(summary.state.egress_region, null);
    assert.equal(summary.state.proxy_configured, null);
    assert.equal(summary.state.egress_profile_identity_hash, null);
    assert.equal(summary.state.egress_profile_identity_version, null);
    assert.equal(summary.state.hunt_wave, 0);
    assert.equal(summary.state.pending_wave, null);
    assert.equal(summary.state.total_findings, 0);
    assert.equal(summary.state.hold_count, 0);
  });
});
