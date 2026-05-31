const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  normalizeScEvidence,
} = require("../mcp/lib/finding-contracts.js");
const {
  listFindings,
  readFindings,
  readFindingsFromJsonl,
  recordFinding,
} = require("../mcp/lib/finding-store.js");
const {
  DEFAULT_ARTIFACT_READ_MAX_BYTES,
} = require("../mcp/lib/storage.js");
const {
  findingsJsonlPath,
  findingsMarkdownPath,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-finding-contracts-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

test("normalizeScEvidence rejects missing harness paths under symlink parents that escape HOME", () => {
  withTempHome((home) => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-outside-"));
    const link = path.join(home, "escape");
    fs.symlinkSync(outside, link, "dir");
    try {
      assert.throws(
        () => normalizeScEvidence({
          chain_family: "evm",
          chain_id: 1,
          contract_address: "0x1111111111111111111111111111111111111111",
          harness_path: path.join(link, "missing", "PoC.t.sol"),
          match_test: "testExploit",
        }),
        /harness_path must live under the user home directory/,
      );
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
});

function findingInput(domain, overrides = {}) {
  return {
    target_domain: domain,
    title: "IDOR exposes billing profile",
    severity: "high",
    cwe: "CWE-639",
    endpoint: "https://victim.example/api/billing/123",
    description: "Changing the billing profile identifier returns another tenant's billing metadata.",
    proof_of_concept: "GET /api/billing/123 as a different tenant returns private billing fields.",
    response_evidence: "Response included another tenant billing_profile_id and billing email.",
    impact: "Cross-tenant billing metadata disclosure.",
    validated: true,
    auth_profile: "attacker",
    ...overrides,
  };
}

test("finding store writes JSONL and markdown mirrors while preserving ID references and dedupe", () => {
  withTempHome(() => {
    const domain = "finding-store.example.com";

    const first = JSON.parse(recordFinding(findingInput(domain)));
    assert.equal(first.recorded, true);
    assert.equal(first.finding_id, "F-1");

    const duplicate = JSON.parse(recordFinding(findingInput(domain)));
    assert.equal(duplicate.recorded, false);
    assert.equal(duplicate.duplicate, true);
    assert.equal(duplicate.finding_id, "F-1");
    assert.equal(duplicate.total, 1);

    const forced = JSON.parse(recordFinding(findingInput(domain, { force_record: true })));
    assert.equal(forced.recorded, true);
    assert.equal(forced.finding_id, "F-2");

    const rows = readFindingsFromJsonl(domain);
    assert.deepEqual(rows.map((finding) => finding.id), ["F-1", "F-2"]);

    const readResult = JSON.parse(readFindings({ target_domain: domain }));
    assert.deepEqual(readResult.findings.map((finding) => finding.id), ["F-1", "F-2"]);

    const listed = JSON.parse(listFindings({ target_domain: domain }));
    assert.deepEqual(listed.findings.map((finding) => finding.id), ["F-1", "F-2"]);

    const jsonl = fs.readFileSync(findingsJsonlPath(domain), "utf8").trim().split("\n");
    assert.equal(jsonl.length, 2);
    const markdown = fs.readFileSync(findingsMarkdownPath(domain), "utf8");
    assert.match(markdown, /FINDING 1/);
    assert.match(markdown, /FINDING 2/);
    assert.match(markdown, /IDOR exposes billing profile/);
  });
});

test("recordFinding allocates and dedupes from an over-cap canonical findings ledger", () => {
  withTempHome(() => {
    const domain = "finding-overcap.example.com";
    const filePath = findingsJsonlPath(domain);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });

    const fd = fs.openSync(filePath, "w");
    let bytes = 0;
    let count = 0;
    try {
      while (bytes <= DEFAULT_ARTIFACT_READ_MAX_BYTES + 1024) {
        count += 1;
        const row = {
          id: `F-${count}`,
          target_domain: domain,
          title: `Legacy finding ${count}`,
          severity: "medium",
          cwe: "CWE-639",
          endpoint: `https://victim.example/api/${count}`,
          description: "Legacy row used to exercise streaming allocation.",
          proof_of_concept: "GET /api/resource returns another tenant record.",
          response_evidence: `bounded evidence ${"x".repeat(900)}`,
          impact: "Tenant data exposure.",
          validated: true,
          surface_type: "web",
          capability_pack: "web",
          hunter_agent: "hunter-agent",
          brief_profile: "web",
          dedupe_key: `legacy-${count}`,
        };
        const line = `${JSON.stringify(row)}\n`;
        fs.writeSync(fd, line);
        bytes += Buffer.byteLength(line);
      }
    } finally {
      fs.closeSync(fd);
    }
    assert.ok(fs.statSync(filePath).size > DEFAULT_ARTIFACT_READ_MAX_BYTES);

    const recorded = JSON.parse(recordFinding(findingInput(domain, {
      dedupe_key: "new-overcap",
      endpoint: "https://victim.example/api/new-overcap",
    })));
    assert.equal(recorded.recorded, true);
    assert.equal(recorded.finding_id, `F-${count + 1}`);

    const duplicate = JSON.parse(recordFinding(findingInput(domain, {
      dedupe_key: "legacy-10",
      endpoint: "https://victim.example/api/10",
    })));
    assert.equal(duplicate.recorded, false);
    assert.equal(duplicate.duplicate, true);
    assert.equal(duplicate.finding_id, "F-10");
    assert.equal(duplicate.total, count + 1);

    const listed = JSON.parse(listFindings({ target_domain: domain }));
    assert.equal(listed.count, count + 1);
    assert.equal(listed.findings.length, count + 1);
  });
});

test("recordFinding allocates from the max observed finding id when legacy rows contain gaps", () => {
  withTempHome(() => {
    const domain = "finding-gap.example.com";
    const filePath = findingsJsonlPath(domain);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const rows = [1, 3].map((id) => JSON.stringify({
      id: `F-${id}`,
      target_domain: domain,
      title: `Legacy finding ${id}`,
      severity: "medium",
      cwe: "CWE-639",
      endpoint: `https://victim.example/api/${id}`,
      description: "Legacy row with an intentional ID gap.",
      proof_of_concept: "GET /api/resource returns another tenant record.",
      response_evidence: "bounded evidence",
      impact: "Tenant data exposure.",
      validated: true,
      surface_type: "web",
      capability_pack: "web",
      hunter_agent: "hunter-agent",
      brief_profile: "web",
      dedupe_key: `legacy-gap-${id}`,
    }));
    fs.writeFileSync(filePath, `${rows.join("\n")}\n`, "utf8");

    const recorded = JSON.parse(recordFinding(findingInput(domain, {
      dedupe_key: "new-gap",
      endpoint: "https://victim.example/api/new-gap",
    })));

    assert.equal(recorded.recorded, true);
    assert.equal(recorded.finding_id, "F-4");
    assert.equal(recorded.total, 3);
    assert.equal(recorded.finding_sequence, 4);
  });
});

test("recordFinding rejects oversized or secret-shaped canonical text before writing mirrors", () => {
  withTempHome(() => {
    const domain = "finding-sensitive.example.com";

    assert.throws(
      () => recordFinding(findingInput(domain, {
        proof_of_concept: "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz' https://victim.example/private",
      })),
      /appears to contain secrets/,
    );
    for (const secretText of [
      "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
      "AWS key AKIAABCDEFGHIJKLMNOP appeared in copied logs.",
      "Google key AIzaABCDEFGHIJKLMNOPQRSTUVWX appeared in copied logs.",
      "GitHub token ghp_abcdefghijklmnopqrstuvwxyz appeared in copied logs.",
      ["Slack token ", "xoxb-", "1234567890-", "abcdefghijklmnop", " appeared in copied logs."].join(""),
    ]) {
      assert.throws(
        () => recordFinding(findingInput(domain, {
          dedupe_key: `secret-${secretText.slice(0, 12)}`,
          proof_of_concept: secretText,
        })),
        /appears to contain secrets/,
      );
    }
    assert.equal(fs.existsSync(findingsJsonlPath(domain)), false);
    assert.equal(fs.existsSync(findingsMarkdownPath(domain)), false);

    assert.throws(
      () => recordFinding(findingInput(domain, {
        description: "x".repeat(4001),
      })),
      /description is too large/,
    );
    assert.equal(fs.existsSync(findingsJsonlPath(domain)), false);
  });
});
