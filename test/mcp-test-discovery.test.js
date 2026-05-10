const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const MANIFEST_PATH = path.join(ROOT, "test", "mcp-test-manifest.json");

function readManifest() {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  assert.ok(Array.isArray(manifest), "mcp-test-manifest.json must be an array");
  return manifest;
}

function discoveredMcpTests() {
  return fs.readdirSync(path.join(ROOT, "test"))
    .filter((name) => /^mcp-.*\.test\.js$/.test(name))
    .map((name) => `test/${name}`)
    .sort();
}

test("test:mcp manifest keeps mcp-prefixed test discovery in sync", () => {
  const manifest = readManifest();
  const manifestMcpTests = manifest.filter((file) => path.basename(file).startsWith("mcp-")).sort();

  assert.equal(new Set(manifest).size, manifest.length, "mcp-test-manifest.json contains duplicate entries");
  for (const file of manifest) {
    assert.ok(fs.existsSync(path.join(ROOT, file)), `${file} does not exist`);
  }

  assert.deepEqual(manifestMcpTests, discoveredMcpTests());
  assert.ok(manifest.includes("test/mcp-server.test.js"));
  assert.ok(manifest.includes("test/mcp-test-discovery.test.js"));
});
