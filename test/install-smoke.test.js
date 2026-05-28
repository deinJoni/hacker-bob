const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { getAdapter } = require("../adapters/index.js");
const update = require("../mcp/lib/update-check.js");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "hacker-bob.js");
const PACKAGE_VERSION = require("../package.json").version;
const CODEX_ADAPTER = getAdapter("codex");
const GENERIC_MCP_ADAPTER = getAdapter("generic-mcp");

test("installer copies a require-able complete MCP runtime", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-install-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    update.writeUpdateCache(workspace, {
      schema_version: 1,
      package_name: "hacker-bob",
      install_target: workspace,
      installed_version: "1.0.0",
      latest_version: "1.3.0",
      update_available: true,
      legacy_install: false,
      checked_at: new Date(1000).toISOString(),
      checked_at_ms: 1000,
      error: null,
    }, { homeDir: tempHome });

    execFileSync(path.join(ROOT, "install.sh"), [workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    assert.equal(update.readUpdateCache(workspace, { homeDir: tempHome }), null);

    const installedServer = path.join(workspace, "mcp", "server.js");
    assert.ok(fs.existsSync(installedServer));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "redaction.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "dispatch.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "tools", "index.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "egress-profiles.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "node_modules", "psl", "dist", "psl.cjs")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "node_modules", "proxy-agent", "dist", "index.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "node_modules", "punycode", "punycode.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-egress.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-export.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-evaluate.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "evaluate.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "status.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "debug.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "update.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bountyagent.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bountyagentdebug.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-status", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-debug", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagent", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentstatus", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentdebug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "agent-run-stop.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-egress.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-export.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-update.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-check-update.js")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-update-lib.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "update-check.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "bob-export.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "knowledge", "evaluator-techniques.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "knowledge")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "bypass-tables")));
    assert.ok(fs.existsSync(path.join(workspace, "testing", "policy-replay", "replay.mjs")));
    assert.ok(fs.existsSync(path.join(workspace, "testing", "policy-replay", "tune.mjs")));
    assert.ok(fs.existsSync(path.join(workspace, "testing", "policy-replay", "cases", "sample-evaluator-refusal.json")));
    assert.ok(!fs.existsSync(path.join(workspace, "testing", "policy-replay", "node_modules")));

    const { createRequire } = require("node:module");
    const installedRequire = createRequire(installedServer);
    assert.ok(
      installedRequire.resolve("@anthropic-ai/claude-agent-sdk"),
      "Claude Agent SDK must resolve from <workspace>/mcp/server.js so policy-replay's fallback can find it",
    );

    const sourceSdkManifestPath = path.join(ROOT, "node_modules", "@anthropic-ai", "claude-agent-sdk", "package.json");
    if (fs.existsSync(sourceSdkManifestPath)) {
      const sdkOptionalDeps = JSON.parse(fs.readFileSync(sourceSdkManifestPath, "utf8")).optionalDependencies || {};
      const platformKey = `${process.platform}-${process.arch}`;
      const currentPlatformPackages = Object.keys(sdkOptionalDeps).filter((name) => name.includes(platformKey));
      for (const platformPackage of currentPlatformPackages) {
        const sourcePackageDir = path.join(ROOT, "node_modules", ...platformPackage.split("/"));
        if (!fs.existsSync(sourcePackageDir)) continue;
        const targetPackageDir = path.join(workspace, "mcp", "node_modules", ...platformPackage.split("/"));
        assert.ok(
          fs.existsSync(targetPackageDir),
          `Source has ${platformPackage}; copyRuntimeNodeDependencies must propagate it into <workspace>/mcp/node_modules so live replay can invoke the SDK`,
        );
      }
    }
    assert.equal(fs.readFileSync(path.join(workspace, ".hacker-bob", "VERSION"), "utf8").trim(), PACKAGE_VERSION);
    const neutralInstallMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.equal(neutralInstallMeta.schema_version, 2);
    assert.equal(neutralInstallMeta.bob_version, PACKAGE_VERSION);
    assert.equal(neutralInstallMeta.package_name, "hacker-bob");
    assert.equal(neutralInstallMeta.install_target, workspace);
    assert.deepEqual(neutralInstallMeta.installed_adapters, ["claude"]);
    assert.equal(fs.readFileSync(path.join(workspace, ".claude", "bob", "VERSION"), "utf8").trim(), PACKAGE_VERSION);
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "bob", "egress-profiles.example.json")));
    const egressConfig = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "bob", "egress-profiles.json"), "utf8"));
    assert.equal(egressConfig.profiles.find((profile) => profile.name === "default").proxy_url, null);
    const settings = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8"));
    const settingsText = JSON.stringify(settings);
    assert.match(settingsText, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);
    assert.doesNotMatch(settingsText, /\$CLAUDE_PROJECT_DIR(?!:-)/);
    const installMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "bob", "install.json"), "utf8"));
    assert.equal(installMeta.schema_version, 1);
    assert.equal(installMeta.bob_version, PACKAGE_VERSION);
    assert.equal(installMeta.package_name, "hacker-bob");
    assert.equal(installMeta.install_target, workspace);

    const statuslinePath = path.join(workspace, ".claude", "hooks", "bob-statusline.js");
    const nestedWorkspaceDir = path.join(workspace, "nested");
    fs.mkdirSync(nestedWorkspaceDir, { recursive: true });
    const runStatusline = () => execFileSync(process.execPath, [statuslinePath], {
      cwd: nestedWorkspaceDir,
      env: { ...process.env, HOME: tempHome, CLAUDE_PROJECT_DIR: workspace },
      input: JSON.stringify({
        model: { display_name: "Claude" },
        workspace: { current_dir: nestedWorkspaceDir },
      }),
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });

    update.writeUpdateCache(workspace, {
      schema_version: 1,
      package_name: "hacker-bob",
      install_target: workspace,
      installed_version: "1.0.0",
      latest_version: "1.3.0",
      update_available: true,
      legacy_install: false,
      checked_at: new Date().toISOString(),
      checked_at_ms: Date.now(),
      error: null,
    }, { homeDir: tempHome });
    assert.doesNotMatch(runStatusline(), /Bob 1\.3\.0|Update Bob|bob-update/);

    update.writeUpdateCache(workspace, {
      schema_version: 1,
      package_name: "hacker-bob",
      install_target: workspace,
      installed_version: PACKAGE_VERSION,
      latest_version: "99.0.0",
      update_available: true,
      legacy_install: false,
      checked_at: new Date().toISOString(),
      checked_at_ms: Date.now(),
      error: null,
    }, { homeDir: tempHome });
    assert.match(runStatusline(), /Update Bob to 99\.0\.0: \/bob-update/);

    execFileSync(process.execPath, [
      "-e",
      [
        "const server = require(process.argv[1]);",
        "const installedRequire = require('module').createRequire(process.argv[1]);",
        "installedRequire('psl');",
        "installedRequire('proxy-agent');",
        "if (!Array.isArray(server.TOOLS) || server.TOOLS.length !== 124) process.exit(2);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_list_auth_profiles')) process.exit(3);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_finalize_report')) process.exit(25);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_tool_telemetry')) process.exit(6);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_pipeline_analytics')) process.exit(7);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_finalize_agent_run')) process.exit(8);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_write_evidence_packs')) process.exit(9);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_evidence_packs')) process.exit(10);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_promote_surface_leads')) process.exit(11);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_session_summary')) process.exit(12);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_set_operator_note')) process.exit(13);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_clear_operator_note')) process.exit(14);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_route_surfaces')) process.exit(15);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_surface_routes')) process.exit(16);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_start_next_wave')) process.exit(17);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_select_technique_packs')) process.exit(18);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_technique_pack')) process.exit(19);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_log_technique_attempt')) process.exit(20);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_get_context_budget')) process.exit(21);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_verification_context')) process.exit(22);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_build_verification_adjudication')) process.exit(23);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_browser_session_start')) process.exit(26);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_browser_evaluate')) process.exit(27);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_browser_session_close')) process.exit(28);",
        "Promise.resolve(server.executeTool('bob_init_session', { target_domain: 'example.com', target_url: 'https://example.com/' }))",
        "  .then((init) => { if (!init.ok) process.exit(24); return server.executeTool('bob_list_auth_profiles', { target_domain: 'example.com' }); })",
        "  .then((result) => { if (!result.ok || result.data.target_domain !== 'example.com') process.exit(4); })",
        "  .catch(() => process.exit(5));",
      ].join(" "),
      installedServer,
    ], { env: { ...process.env, HOME: tempHome }, stdio: "pipe" });
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("doctor accepts legacy-only resources and uninstall removes legacy resource copies", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-legacy-resources-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    fs.mkdirSync(path.join(workspace, ".claude"), { recursive: true });
    fs.renameSync(
      path.join(workspace, ".hacker-bob", "knowledge"),
      path.join(workspace, ".claude", "knowledge"),
    );
    fs.renameSync(
      path.join(workspace, ".hacker-bob", "bypass-tables"),
      path.join(workspace, ".claude", "bypass-tables"),
    );
    fs.rmSync(path.join(workspace, ".hacker-bob"), { recursive: true, force: true });

    const doctorOutput = execFileSync(process.execPath, [CLI, "doctor", workspace, "--json"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const doctor = JSON.parse(doctorOutput);
    assert.equal(doctor.ok, true);
    assert.equal(doctor.checks.find((check) => check.id === "resource_knowledge").status, "warn");
    assert.equal(doctor.checks.find((check) => check.id === "resource_bypass_tables").status, "warn");

    const uninstallOutput = execFileSync(process.execPath, [CLI, "uninstall", workspace, "--yes", "--json"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const uninstall = JSON.parse(uninstallOutput);
    assert.equal(uninstall.dry_run, false);
    assert.ok(uninstall.actions.some((action) => action.path === path.join(".claude", "knowledge", "evaluator-techniques.json")));
    assert.ok(uninstall.actions.some((action) => action.path === path.join(".claude", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "knowledge", "evaluator-techniques.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "bypass-tables", "rest-api.txt")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("installer merges existing MCP/settings config idempotently", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-install-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(path.join(workspace, ".claude", "knowledge"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "bypass-tables"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "hooks"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "commands", "bob"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "skills", "bountyagent"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "skills", "bountyagentstatus"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "skills", "bountyagentdebug"), { recursive: true });

  try {
    fs.writeFileSync(path.join(workspace, ".claude", "knowledge", "evaluator-techniques.json"), "{}\n");
    fs.writeFileSync(path.join(workspace, ".claude", "knowledge", "custom.json"), "{}\n");
    fs.writeFileSync(path.join(workspace, ".claude", "bypass-tables", "rest-api.txt"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "bypass-tables", "custom.txt"), "custom\n");
    fs.writeFileSync(path.join(workspace, ".claude", "hooks", "bob-update-lib.js"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "commands", "bob", "evaluate.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "commands", "bob", "status.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "commands", "bob", "debug.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "commands", "bob", "update.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "skills", "bountyagent", "SKILL.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "skills", "bountyagentstatus", "SKILL.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "skills", "bountyagentdebug", "SKILL.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".mcp.json"), `${JSON.stringify({
      mcpServers: {
        existing: { command: "node", args: ["existing.js"] },
      },
    }, null, 2)}\n`);
    fs.writeFileSync(path.join(workspace, ".claude", "settings.json"), `${JSON.stringify({
      permissions: {
        allow: [
          "Read",
          "custom-tool",
          "mcp__bountyagent__bob_merge_wave_handoffs",
          "mcp__bountyagent__custom_user_tool",
          "mcp__hacker-bob__pre_migration_custom",
        ],
      },
      hooks: {
        SessionStart: [{
          matcher: "startup",
          hooks: [
            { type: "command", command: "echo existing session", timeout: 1 },
            { type: "command", command: "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/bob-check-update.js\" \"$CLAUDE_PROJECT_DIR\"", timeout: 2 },
          ],
        }],
        PreToolUse: [{
          matcher: "Bash",
          hooks: [{ type: "command", command: "echo existing", timeout: 1 }],
        }],
        SubagentStop: [{
          matcher: "evaluator-agent",
          hooks: [{ type: "command", command: "echo existing stop", timeout: 1 }],
        }],
      },
      statusLine: {
        type: "command",
        command: "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/bob-statusline.js\"",
      },
      customSetting: true,
    }, null, 2)}\n`);

    for (let index = 0; index < 2; index += 1) {
      execFileSync(path.join(ROOT, "install.sh"), [workspace], {
        cwd: ROOT,
        env: { ...process.env, HOME: tempHome },
        stdio: "pipe",
      });
      if (index === 0) {
        fs.writeFileSync(path.join(workspace, ".claude", "bob", "egress-profiles.json"), `${JSON.stringify({
          version: 1,
          profiles: [
            { name: "default", proxy_url: null, region: null, description: "Direct", enabled: true },
            { name: "operator", proxy_url: "${BOB_EGRESS_OPERATOR_PROXY}", region: "EU", description: "Operator-owned", enabled: true },
          ],
        }, null, 2)}\n`);
      }
    }

    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(mcp.mcpServers.existing);
    // Migration shim rewrites the legacy `bountyagent` key to `hacker-bob`.
    assert.ok(mcp.mcpServers["hacker-bob"]);
    assert.ok(!mcp.mcpServers.bountyagent, "migration shim must remove legacy bountyagent server key");

    const settings = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8"));
    const settingsText = JSON.stringify(settings);
    assert.match(settingsText, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);
    assert.doesNotMatch(settingsText, /\$CLAUDE_PROJECT_DIR(?!:-)/);
    assert.equal(settings.customSetting, true);
    assert.equal(settings.permissions.allow.length, new Set(settings.permissions.allow).size);
    assert.ok(settings.permissions.allow.includes("custom-tool"));
    // Migration shim rewrites mcp__bountyagent__* permission strings to mcp__hacker-bob__*.
    assert.ok(settings.permissions.allow.includes("mcp__hacker-bob__custom_user_tool"));
    assert.ok(!settings.permissions.allow.includes("mcp__bountyagent__custom_user_tool"));
    assert.ok(settings.permissions.allow.includes("mcp__hacker-bob__bob_http_scan"));
    // The pre-migration custom permission is idempotently preserved.
    assert.ok(settings.permissions.allow.includes("mcp__hacker-bob__pre_migration_custom"));
    // Stale legacy permission strings are dropped (both forms).
    assert.ok(!settings.permissions.allow.includes("mcp__bountyagent__bob_merge_wave_handoffs"));
    assert.ok(!settings.permissions.allow.includes("mcp__hacker-bob__bob_merge_wave_handoffs"));
    assert.match(settings.statusLine.command, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);

    const bashEntry = settings.hooks.PreToolUse.find((entry) => entry.matcher === "Bash");
    assert.ok(bashEntry);
    assert.ok(bashEntry.hooks.some((hook) => hook.command === "echo existing"));
    assert.equal(
      bashEntry.hooks.filter((hook) => /session-write-guard\.sh/.test(hook.command)).length,
      1,
    );
    assert.equal(
      settings.hooks.PreToolUse.filter((entry) => entry.matcher === "mcp__hacker-bob__bob_http_scan").length,
      0,
    );
    const stopEntry = settings.hooks.SubagentStop.find((entry) => entry.matcher === "evaluator-agent");
    assert.ok(stopEntry);
    assert.ok(stopEntry.hooks.some((hook) => hook.command === "echo existing stop"));
    assert.equal(
      stopEntry.hooks.filter((hook) => /agent-run-stop\.js/.test(hook.command)).length,
      1,
    );
    const sessionEntry = settings.hooks.SessionStart.find((entry) => entry.matcher === "startup");
    assert.ok(sessionEntry);
    assert.ok(sessionEntry.hooks.some((hook) => hook.command === "echo existing session"));
    assert.equal(
      sessionEntry.hooks.filter((hook) => /bob-check-update\.js/.test(hook.command)).length,
      1,
    );
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "knowledge", "evaluator-techniques.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "knowledge", "evaluator-techniques.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-update-lib.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-export.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-evaluate.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "evaluate.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "status.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "debug.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "update.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagent", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentstatus", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentdebug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-status", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-debug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "knowledge", "custom.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "bypass-tables", "custom.txt")));
    assert.match(sessionEntry.hooks.find((hook) => /bob-check-update\.js/.test(hook.command)).command, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);
    const egressConfig = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "bob", "egress-profiles.json"), "utf8"));
    assert.ok(egressConfig.profiles.some((profile) => profile.name === "operator"));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("install doctor uninstall dry-run uninstall and reinstall workflow works", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-lifecycle-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    execFileSync(process.execPath, [CLI, "doctor", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    execFileSync(process.execPath, [CLI, "uninstall", workspace, "--dry-run"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));

    execFileSync(process.execPath, [CLI, "uninstall", workspace, "--yes"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate", "SKILL.md")));

    execFileSync(process.execPath, [CLI, "uninstall", workspace, "--yes"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    execFileSync(process.execPath, [CLI, "doctor", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("codex adapter installs direct skills and doctor checks MCP wiring", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-codex-adapter-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  const originalCodexHome = process.env.CODEX_HOME;
  fs.mkdirSync(workspace, { recursive: true });
  process.env.CODEX_HOME = path.join(tempHome, ".codex");

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    const install = CODEX_ADAPTER.install({
      sourceRoot: ROOT,
      targetAbs: workspace,
      serverPath: path.join(workspace, "mcp", "server.js"),
    });
    assert.equal(install.skills, 6);
    assert.equal(install.commands, 6);
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".codex-plugin", "plugin.json")));
    const manifest = JSON.parse(fs.readFileSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".codex-plugin", "plugin.json"), "utf8"));
    assert.equal(Object.prototype.hasOwnProperty.call(manifest, "skills"), false);
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-status", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-debug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-update", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-export", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-egress", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "hacker-bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "hacker-bob-evaluate", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-evaluate.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-export.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-egress.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".agents", "plugins", "marketplace.json")));

    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json"), "utf8"));
    assert.deepEqual(mcp.mcpServers["hacker-bob"], {
      command: "node",
      args: [path.join(workspace, "mcp", "server.js")],
    });
    assert.ok(!mcp.mcpServers.bountyagent);

    const doctor = CODEX_ADAPTER.doctor({ targetAbs: workspace });
    assert.equal(doctor.ok, true);
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_manifest" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_global_skills" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_skills_clean" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_mcp" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_commands" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_marketplace" && check.status === "ok"));

    const dryRun = CODEX_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: workspace, dryRun: true });
    assert.equal(dryRun.dry_run, true);
    assert.ok(dryRun.actions.some((action) => action.path === path.join(tempHome, ".codex", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(dryRun.actions.some((action) => action.path === path.join(".codex", "plugins", "hacker-bob", ".mcp.json")));
    assert.ok(dryRun.actions.some((action) => action.path === path.join(".agents", "plugins", "marketplace.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-evaluate", "SKILL.md")));

    const removed = CODEX_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: workspace, dryRun: false });
    assert.equal(removed.dry_run, false);
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-export", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-egress", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-evaluate.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-export.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-egress.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".agents", "plugins", "marketplace.json")));
  } finally {
    if (originalCodexHome === undefined) {
      delete process.env.CODEX_HOME;
    } else {
      process.env.CODEX_HOME = originalCodexHome;
    }
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("generic MCP adapter installs only MCP config and prompt docs", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-generic-mcp-adapter-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    fs.rmSync(path.join(workspace, ".claude"), { recursive: true, force: true });
    fs.writeFileSync(path.join(workspace, ".mcp.json"), `${JSON.stringify({
      mcpServers: {
        existing: { command: "node", args: ["existing.js"] },
      },
    }, null, 2)}\n`);

    GENERIC_MCP_ADAPTER.install({
      sourceRoot: ROOT,
      targetAbs: workspace,
      serverPath: path.join(workspace, "mcp", "server.js"),
    });

    assert.ok(!fs.existsSync(path.join(workspace, ".claude")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "generic-mcp", "hacker-bob.md")));

    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(mcp.mcpServers.existing);
    assert.deepEqual(mcp.mcpServers["hacker-bob"], {
      command: "node",
      args: [path.join(workspace, "mcp", "server.js")],
    });
    assert.ok(!mcp.mcpServers.bountyagent);

    const doctor = GENERIC_MCP_ADAPTER.doctor({ targetAbs: workspace });
    assert.equal(doctor.ok, true);
    assert.ok(doctor.checks.some((check) => check.id === "generic_mcp_server" && check.status === "ok"));

    const removed = GENERIC_MCP_ADAPTER.uninstall({ targetAbs: workspace, dryRun: false });
    assert.equal(removed.dry_run, false);
    assert.ok(!fs.existsSync(path.join(workspace, ".hacker-bob", "generic-mcp", "hacker-bob.md")));
    const after = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(after.mcpServers.existing);
    assert.ok(!after.mcpServers["hacker-bob"]);
    assert.ok(!after.mcpServers.bountyagent);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("migration shim rewrites v1.x bountyagent server key + permission strings to hacker-bob", () => {
  // The shim in scripts/merge-claude-config.js powers the v2.0.0 rename for
  // existing installs. This test exercises it directly (unit-level), then
  // re-runs it on the rewritten output to prove idempotency.
  const {
    migrateLegacyMcp,
    migrateLegacySettings,
    migrateLegacyServerKey,
    rewriteLegacyPermissionString,
  } = require("../scripts/merge-claude-config.js");

  // Sanity: prefix rewriter handles legacy/canonical/unknown strings.
  assert.equal(
    rewriteLegacyPermissionString("mcp__bountyagent__bob_http_scan"),
    "mcp__hacker-bob__bob_http_scan",
  );
  assert.equal(
    rewriteLegacyPermissionString("mcp__hacker-bob__bob_http_scan"),
    "mcp__hacker-bob__bob_http_scan",
  );
  assert.equal(rewriteLegacyPermissionString("custom-tool"), "custom-tool");
  assert.equal(rewriteLegacyPermissionString(undefined), undefined);

  // Pure .mcp.json migration: legacy key is renamed and operator entries
  // unrelated to the rename are preserved.
  const v1Mcp = {
    mcpServers: {
      bountyagent: {
        command: "node",
        args: ["/legacy/path/mcp/server.js"],
      },
      operator: { command: "node", args: ["op.js"] },
    },
  };
  const mcpResult = migrateLegacyMcp(v1Mcp);
  assert.equal(mcpResult.migrated, true);
  assert.deepEqual(mcpResult.value.mcpServers["hacker-bob"], {
    command: "node",
    args: ["/legacy/path/mcp/server.js"],
  });
  assert.ok(!("bountyagent" in mcpResult.value.mcpServers));
  assert.deepEqual(mcpResult.value.mcpServers.operator, { command: "node", args: ["op.js"] });

  // Idempotency: re-running migration on already-migrated input is a no-op.
  const idempotentMcp = migrateLegacyMcp(mcpResult.value);
  assert.equal(idempotentMcp.migrated, false);
  assert.deepEqual(idempotentMcp.value, mcpResult.value);

  // Both keys present: legacy is dropped, canonical is preserved untouched.
  const dualKeyMcp = {
    mcpServers: {
      bountyagent: { command: "node", args: ["legacy.js"] },
      "hacker-bob": { command: "node", args: ["canonical.js"] },
    },
  };
  const dualResult = migrateLegacyMcp(dualKeyMcp);
  assert.equal(dualResult.migrated, true);
  assert.deepEqual(dualResult.value.mcpServers["hacker-bob"], { command: "node", args: ["canonical.js"] });
  assert.ok(!("bountyagent" in dualResult.value.mcpServers));

  // Pure settings.json migration: legacy permission strings rewritten, others
  // preserved.
  const v1Settings = {
    permissions: {
      allow: [
        "mcp__bountyagent__bob_http_scan",
        "mcp__bountyagent__custom_user_tool",
        "Read",
        "mcp__hacker-bob__pre_migration_custom",
      ],
    },
    customSetting: true,
  };
  const settingsResult = migrateLegacySettings(v1Settings);
  assert.equal(settingsResult.migrated, true);
  assert.ok(settingsResult.value.permissions.allow.includes("mcp__hacker-bob__bob_http_scan"));
  assert.ok(settingsResult.value.permissions.allow.includes("mcp__hacker-bob__custom_user_tool"));
  assert.ok(settingsResult.value.permissions.allow.includes("Read"));
  // Idempotency: pre-existing canonical permission survives without duplication.
  assert.ok(settingsResult.value.permissions.allow.includes("mcp__hacker-bob__pre_migration_custom"));
  assert.equal(
    settingsResult.value.permissions.allow.length,
    new Set(settingsResult.value.permissions.allow).size,
    "migration must dedupe permission strings",
  );
  assert.equal(settingsResult.value.customSetting, true, "unrelated settings preserved");
  assert.ok(!settingsResult.value.permissions.allow.some((p) => p.startsWith("mcp__bountyagent__")));

  // Idempotency: re-migration is a no-op.
  const idempotentSettings = migrateLegacySettings(settingsResult.value);
  assert.equal(idempotentSettings.migrated, false);
  assert.deepEqual(idempotentSettings.value, settingsResult.value);

  // No-op cases.
  assert.equal(migrateLegacyMcp({}).migrated, false);
  assert.equal(migrateLegacyMcp({ mcpServers: { other: {} } }).migrated, false);
  assert.equal(migrateLegacySettings({}).migrated, false);
  assert.equal(migrateLegacySettings({ permissions: { allow: ["Read"] } }).migrated, false);

  // Combined entry point logs and reports overall migration status.
  const captured = [];
  const combined = migrateLegacyServerKey({
    mcp: v1Mcp,
    settings: v1Settings,
    logger: (msg) => captured.push(msg),
  });
  assert.equal(combined.migrated, true);
  assert.equal(captured.length, 1);
  assert.match(captured[0], /bountyagent\s*->\s*hacker-bob/);
  assert.match(captured[0], /\.mcp\.json/);
  assert.match(captured[0], /\.claude\/settings\.json/);
});

test("merge-claude-config CLI auto-migrates a v1.x .mcp.json + settings.json layout", () => {
  // Round-trip the migration shim through the CLI entrypoint. This exercises
  // the same code path install/update uses on existing v1.x workspaces.
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-migration-shim-"));
  const workspace = path.join(tempRoot, "v1-install");
  fs.mkdirSync(path.join(workspace, ".claude"), { recursive: true });

  try {
    const legacyServerPath = path.join(workspace, "mcp", "server.js");
    fs.writeFileSync(path.join(workspace, ".mcp.json"), `${JSON.stringify({
      mcpServers: {
        bountyagent: { command: "node", args: [legacyServerPath] },
        operatorService: { command: "node", args: ["sidecar.js"] },
      },
    }, null, 2)}\n`);
    fs.writeFileSync(path.join(workspace, ".claude", "settings.json"), `${JSON.stringify({
      permissions: {
        allow: [
          "mcp__bountyagent__bob_http_scan",
          "mcp__bountyagent__custom_user_tool",
          "custom-allowlisted",
        ],
      },
      customSetting: true,
    }, null, 2)}\n`);

    const merge = require("../scripts/merge-claude-config.js");
    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    const settings = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8"));
    const migrated = merge.migrateLegacyServerKey({ mcp, settings });
    assert.equal(migrated.migrated, true);

    // The merge step then runs over the migrated config (idempotent for the
    // rename surfaces).
    const finalMcp = merge.mergeMcp(migrated.mcp, legacyServerPath);
    assert.ok(finalMcp.mcpServers["hacker-bob"]);
    assert.ok(!finalMcp.mcpServers.bountyagent);
    assert.deepEqual(finalMcp.mcpServers.operatorService, { command: "node", args: ["sidecar.js"] });
    assert.ok(finalMcp.mcpServers.brutalist);

    const finalSettings = merge.mergeSettings(migrated.settings, {
      permissions: { allow: ["mcp__hacker-bob__bob_record_candidate_claim"] },
      hooks: {},
    });
    assert.ok(finalSettings.permissions.allow.includes("mcp__hacker-bob__bob_http_scan"));
    assert.ok(finalSettings.permissions.allow.includes("mcp__hacker-bob__custom_user_tool"));
    assert.ok(finalSettings.permissions.allow.includes("mcp__hacker-bob__bob_record_candidate_claim"));
    assert.ok(finalSettings.permissions.allow.includes("custom-allowlisted"));
    assert.equal(finalSettings.customSetting, true);
    assert.ok(!finalSettings.permissions.allow.some((p) => p.startsWith("mcp__bountyagent__")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
