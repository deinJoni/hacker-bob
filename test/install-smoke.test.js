const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "hacker-bob.js");
const PACKAGE_VERSION = require("../package.json").version;

test("installer copies a require-able complete MCP runtime", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-install-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(path.join(ROOT, "install.sh"), [workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    const installedServer = path.join(workspace, "mcp", "server.js");
    assert.ok(fs.existsSync(installedServer));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "redaction.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "dispatch.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "tools", "index.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "egress-profiles.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-egress.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "hunt.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "status.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "debug.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "update.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bountyagent.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bountyagentdebug.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-status", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-debug", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagent", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentstatus", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentdebug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "hunter-subagent-stop.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-egress.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-update.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-check-update.js")));
    assert.ok(fs.existsSync(path.join(workspace, "testing", "policy-replay", "replay.mjs")));
    assert.ok(fs.existsSync(path.join(workspace, "testing", "policy-replay", "tune.mjs")));
    assert.ok(fs.existsSync(path.join(workspace, "testing", "policy-replay", "cases", "sample-hunter-refusal.json")));
    assert.ok(!fs.existsSync(path.join(workspace, "testing", "policy-replay", "node_modules")));
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
    assert.equal(installMeta.package_name, "hacker-bob-cc");
    assert.equal(installMeta.install_target, workspace);

    execFileSync(process.execPath, [
      "-e",
      [
        "const server = require(process.argv[1]);",
        "if (!Array.isArray(server.TOOLS) || server.TOOLS.length !== 39) process.exit(2);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_list_auth_profiles')) process.exit(3);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_read_tool_telemetry')) process.exit(6);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_read_pipeline_analytics')) process.exit(7);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_write_evidence_packs')) process.exit(8);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_read_evidence_packs')) process.exit(9);",
        "Promise.resolve(server.executeTool('bounty_list_auth_profiles', { target_domain: 'example.com' }))",
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

test("installer merges existing MCP/settings config idempotently", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-install-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(path.join(workspace, ".claude"), { recursive: true });

  try {
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
          "mcp__bountyagent__bounty_merge_wave_handoffs",
          "mcp__bountyagent__custom_user_tool",
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
          matcher: "hunter-agent",
          hooks: [{ type: "command", command: "echo existing stop", timeout: 1 }],
        }],
      },
      statusLine: {
        type: "command",
        command: "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/bounty-statusline.js\"",
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
    assert.ok(mcp.mcpServers.bountyagent);
    assert.equal(Object.keys(mcp.mcpServers).filter((name) => name === "bountyagent").length, 1);

    const settings = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8"));
    const settingsText = JSON.stringify(settings);
    assert.match(settingsText, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);
    assert.doesNotMatch(settingsText, /\$CLAUDE_PROJECT_DIR(?!:-)/);
    assert.equal(settings.customSetting, true);
    assert.equal(settings.permissions.allow.length, new Set(settings.permissions.allow).size);
    assert.ok(settings.permissions.allow.includes("custom-tool"));
    assert.ok(settings.permissions.allow.includes("mcp__bountyagent__custom_user_tool"));
    assert.ok(settings.permissions.allow.includes("mcp__bountyagent__bounty_http_scan"));
    assert.ok(!settings.permissions.allow.includes("mcp__bountyagent__bounty_merge_wave_handoffs"));
    assert.match(settings.statusLine.command, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);

    const bashEntry = settings.hooks.PreToolUse.find((entry) => entry.matcher === "Bash");
    assert.ok(bashEntry);
    assert.ok(bashEntry.hooks.some((hook) => hook.command === "echo existing"));
    assert.equal(
      bashEntry.hooks.filter((hook) => /session-write-guard\.sh/.test(hook.command)).length,
      1,
    );
    assert.equal(
      settings.hooks.PreToolUse.filter((entry) => entry.matcher === "mcp__bountyagent__bounty_http_scan").length,
      1,
    );
    const stopEntry = settings.hooks.SubagentStop.find((entry) => entry.matcher === "hunter-agent");
    assert.ok(stopEntry);
    assert.ok(stopEntry.hooks.some((hook) => hook.command === "echo existing stop"));
    assert.equal(
      stopEntry.hooks.filter((hook) => /hunter-subagent-stop\.js/.test(hook.command)).length,
      1,
    );
    const sessionEntry = settings.hooks.SessionStart.find((entry) => entry.matcher === "startup");
    assert.ok(sessionEntry);
    assert.ok(sessionEntry.hooks.some((hook) => hook.command === "echo existing session"));
    assert.equal(
      sessionEntry.hooks.filter((hook) => /bob-check-update\.js/.test(hook.command)).length,
      1,
    );
    assert.match(sessionEntry.hooks.find((hook) => /bob-check-update\.js/.test(hook.command)).command, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);
    const egressConfig = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "bob", "egress-profiles.json"), "utf8"));
    assert.ok(egressConfig.profiles.some((profile) => profile.name === "operator"));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("install doctor uninstall dry-run uninstall and reinstall workflow works", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-lifecycle-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-home-"));
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
