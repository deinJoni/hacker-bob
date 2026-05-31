const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const {
  buildDashboardSnapshot,
  dashboardUsageText,
  parseDashboardArgs,
  startDashboardServer,
} = require("../mcp/lib/dashboard.js");
const {
  repoInventoryPath,
} = require("../mcp/lib/paths.js");
const {
  initSession,
} = require("../mcp/lib/session-state.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-dashboard-test-"));
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

function requestText(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        resolve({ statusCode: res.statusCode, body });
      });
    });
    req.on("error", reject);
  });
}

function seedRepoSession(domain, repoPath) {
  JSON.parse(initSession({
    target_domain: domain,
    target_url: `repo://${domain}`,
    target_kind: "repo",
    repo: {
      root_path: repoPath,
      branch: "main",
      commit: "abc1234",
    },
  }));
  fs.writeFileSync(repoInventoryPath(domain), `${JSON.stringify({
    version: 1,
    target_domain: domain,
    repo_path: repoPath,
    generated_at: "2026-01-01T00:00:00.000Z",
    counts: {
      files: 12,
      surfaces: 2,
      native_source_files: 3,
    },
    tech_stack: ["C/C++", "Autotools"],
    reachability: {
      max_credible_severity_ceiling: "CRITICAL",
      network_reachable_surface_ids: ["OSS-NATIVE-CODE"],
    },
  }, null, 2)}\n`);
}

test("dashboard arg parser handles local server and JSON flags", () => {
  const parsed = parseDashboardArgs([
    "--repo-only",
    "--json",
    "--host",
    "127.0.0.1",
    "--port=0",
    "--window-days",
    "14",
    "--limit",
    "25",
  ]);
  assert.equal(parsed.repo_only, true);
  assert.equal(parsed.json, true);
  assert.equal(parsed.host, "127.0.0.1");
  assert.equal(parsed.port, 0);
  assert.equal(parsed.window_days, 14);
  assert.equal(parsed.limit, 25);
  assert.match(dashboardUsageText(), /hacker-bob dashboard/);
  assert.throws(() => parseDashboardArgs(["--port", "70000"]), /port must be between/);
});

test("dashboard snapshot filters repo sessions and keeps compact repo metadata", () => {
  withTempHome((home) => {
    const repoPath = path.join(home, "repo");
    fs.mkdirSync(repoPath, { recursive: true });
    seedRepoSession("repo-dashboard.example", repoPath);
    JSON.parse(initSession({
      target_domain: "web-dashboard.example",
      target_url: "https://web-dashboard.example",
    }));

    const snapshot = buildDashboardSnapshot({ repo_only: true, window_days: 30, limit: 10 });
    assert.equal(snapshot.version, 1);
    assert.equal(snapshot.filters.repo_only, true);
    assert.equal(snapshot.totals.sessions, 1);
    assert.equal(snapshot.totals.repo_sessions, 1);
    assert.equal(snapshot.sessions[0].target_domain, "repo-dashboard.example");
    assert.equal(snapshot.sessions[0].repo.is_repo, true);
    assert.equal(snapshot.sessions[0].repo.root_path, repoPath);
    assert.equal(snapshot.sessions[0].repo.inventory.counts.files, 12);
    assert.deepEqual(snapshot.sessions[0].repo.inventory.tech_stack, ["C/C++", "Autotools"]);
  });
});

test("dashboard server serves HTML and API JSON", async () => {
  await withTempHome(async () => {
    const started = await startDashboardServer({ host: "127.0.0.1", port: 0, repo_only: true });
    try {
      const html = await requestText(started.url);
      assert.equal(html.statusCode, 200);
      assert.match(html.body, /Hacker Bob Dashboard/);

      const api = await requestText(`${started.url}api/snapshot?repo_only=true&limit=5`);
      assert.equal(api.statusCode, 200);
      const parsed = JSON.parse(api.body);
      assert.equal(parsed.version, 1);
      assert.equal(parsed.filters.repo_only, true);
      assert.equal(parsed.filters.limit, 5);
    } finally {
      await new Promise((resolve, reject) => {
        started.server.close((error) => error ? reject(error) : resolve());
      });
    }
  });
});
