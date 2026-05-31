const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const PACKAGE_VERSION = require("../package.json").version;
const WRAPPER_PACKAGES = Object.freeze([
  {
    name: "hacker-bob-cc",
    root: path.join(ROOT, "packages", "hacker-bob-cc"),
    bin: "bin/hacker-bob-cc.js",
    adapter: "claude",
  },
  {
    name: "hacker-bob-codex",
    root: path.join(ROOT, "packages", "hacker-bob-codex"),
    bin: "bin/hacker-bob-codex.js",
    adapter: "codex",
  },
]);
const LOCAL_INSTALL_METADATA_FILES = new Set([
  ".hacker-bob/VERSION",
  ".hacker-bob/install.json",
  ".claude/bob/VERSION",
  ".claude/bob/install.json",
  ".claude/bob/egress-profiles.json",
  // Operator-local Claude Code session overrides; excluded from package.json's
  // files glob (only settings.json ships) so npm pack never includes it. The
  // expectedCanonicalFiles walker should not require it either.
  ".claude/settings.local.json",
  // Cron scheduler runtime lock file. Present only while a Claude Code session
  // owns scheduled jobs; never persisted to disk by the installer.
  ".claude/scheduled_tasks.lock",
]);

function sourceTreeFiles(relativeDir) {
  const root = path.join(ROOT, relativeDir);
  if (!fs.existsSync(root)) return [];
  const files = [];
  const visit = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        visit(full);
      } else if (entry.isFile()) {
        files.push(path.relative(ROOT, full).split(path.sep).join("/"));
      }
    }
  };
  visit(root);
  return files.sort();
}

function expectedCanonicalFiles() {
  return Array.from(new Set([
    "package.json",
    "README.md",
    "LICENSE",
    "NOTICE",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "DISCLAIMER.md",
    "SECURITY.md",
    "install.sh",
    ...sourceTreeFiles(".hacker-bob").filter((file) => !LOCAL_INSTALL_METADATA_FILES.has(file)),
    ...sourceTreeFiles(".claude").filter((file) => !LOCAL_INSTALL_METADATA_FILES.has(file)),
    ...sourceTreeFiles("adapters"),
    ...sourceTreeFiles("bin"),
    ...sourceTreeFiles("docs"),
    ...sourceTreeFiles("mcp"),
    ...sourceTreeFiles("prompts"),
    ...sourceTreeFiles("scripts"),
  ])).sort();
}

test("npm package contains runtime surfaces and excludes test/cache artifacts", () => {
  const npmCache = fs.mkdtempSync(path.join(os.tmpdir(), "bob-npm-cache-"));
  try {
    const output = execFileSync("npm", ["pack", "--dry-run", "--json"], {
      cwd: ROOT,
      env: { ...process.env, npm_config_cache: npmCache },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const [pack] = JSON.parse(output);
    const files = new Set(pack.files.map((file) => file.path));

    assert.equal(pack.name, "hacker-bob");
    assert.equal(pack.version, PACKAGE_VERSION);
    for (const expected of expectedCanonicalFiles()) {
      assert.ok(files.has(expected), `${expected} missing from npm pack output`);
    }

    // Backstop against accidental bloat (a stray node_modules, cache, or test
    // fixture would add megabytes); the real exclusions are asserted per-file
    // below. Raised 2.5 MB -> 3 MB after shipped docs/prompts grew the canonical
    // package past the old ceiling (packed ~2.51 MB at v1.3.4, all intended to
    // ship per the docs/** files glob and expectedCanonicalFiles()).
    assert.ok(pack.size < 3000000, `npm pack size ${pack.size} exceeds 3 MB threshold`);

    for (const file of files) {
      assert.ok(!file.startsWith("test/"), `${file} should not be packed`);
      if (file.startsWith("testing/")) {
        assert.ok(
          file.startsWith("testing/policy-replay/"),
          `${file} should not be packed`,
        );
        assert.ok(!file.includes("node_modules"), `${file} should not include node_modules`);
      }
      assert.ok(!file.startsWith(".github/"), `${file} should not be packed`);
      assert.ok(!file.startsWith("packages/"), `${file} should not be packed in canonical package`);
      assert.notEqual(file, ".claude/hooks/bob-update-lib.js", "hook-local update library should not be packed");
      assert.ok(!LOCAL_INSTALL_METADATA_FILES.has(file), `${file} should not be packed`);
      assert.ok(!file.includes("bounty-agent-sessions"), `${file} should not be packed`);
      assert.ok(!file.includes(".cache/"), `${file} should not be packed`);
    }
  } finally {
    fs.rmSync(npmCache, { recursive: true, force: true });
  }
});

for (const wrapper of WRAPPER_PACKAGES) {
  test(`${wrapper.name} package version matches canonical package`, () => {
    const wrapperVersion = require(path.join(wrapper.root, "package.json")).version;
    assert.equal(wrapperVersion, PACKAGE_VERSION);
  });

  test(`${wrapper.name} package declares bin ${wrapper.name} -> ${wrapper.bin}`, () => {
    const wrapperPackage = require(path.join(wrapper.root, "package.json"));
    assert.deepEqual(wrapperPackage.bin, { [wrapper.name]: wrapper.bin });
    assert.deepEqual(wrapperPackage.files, [wrapper.bin, "README.md"]);
    assert.equal(wrapperPackage.dependencies && wrapperPackage.dependencies["hacker-bob"], PACKAGE_VERSION);
  });

  test(`${wrapper.name} bin script pins --adapter ${wrapper.adapter} when none is supplied`, () => {
    const binSource = fs.readFileSync(path.join(wrapper.root, wrapper.bin), "utf8");
    assert.match(binSource, /process\.argv\.push\(\s*"--adapter"\s*,/);
    assert.match(binSource, new RegExp(`"${wrapper.adapter}"`));
    // Explicit --adapter must be respected: the wrapper only injects when
    // the operator has not already supplied one. Catches a regression that
    // would force every install through the wrapper's pinned adapter.
    assert.match(binSource, /arg === "--adapter" \|\| arg\.startsWith\("--adapter="\)/);
    assert.match(binSource, /require\("hacker-bob\/bin\/hacker-bob\.js"\)/);
  });

  test(`${wrapper.name} package packs only wrapper and manifest`, () => {
    const npmCache = fs.mkdtempSync(path.join(os.tmpdir(), `bob-${wrapper.name}-npm-cache-`));
    try {
      const output = execFileSync("npm", ["pack", "--dry-run", "--json"], {
        cwd: wrapper.root,
        env: { ...process.env, npm_config_cache: npmCache },
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
      const [pack] = JSON.parse(output);
      assert.equal(pack.name, wrapper.name);
      assert.equal(pack.version, PACKAGE_VERSION);
      assert.deepEqual(
        pack.files.map((file) => file.path).sort(),
        [wrapper.bin, "README.md", "package.json"].sort(),
      );
      assert.ok(pack.size < 5000, `${wrapper.name} pack size ${pack.size} exceeds 5 KB threshold`);
    } finally {
      fs.rmSync(npmCache, { recursive: true, force: true });
    }
  });
}
