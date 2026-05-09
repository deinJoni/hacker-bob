"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  indexFinding,
  summarizePriorFindingsForSurface,
} = require("../mcp/lib/findings-index.js");

const FINGERPRINT = `bobpriortest${crypto.randomBytes(6).toString("hex")}`;

function uniqueDomain(prefix = "bob-priors-test") {
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${prefix}-${suffix}.local`;
}

function cleanupDomain(domain) {
  const dir = path.join(os.homedir(), "bounty-agent-sessions", domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

test("summarizePriorFindingsForSurface returns null when surface has no indexable text", () => {
  const domain = uniqueDomain();
  try {
    indexFinding({
      target_domain: domain,
      finding: { finding_id: "F-1", title: "x", description: "x" },
    });
    const result = summarizePriorFindingsForSurface(domain, {});
    assert.equal(result, null);
  } finally {
    cleanupDomain(domain);
  }
});

test("priors_slice ranks same-target priors and exposes calibration_label slot", () => {
  const domain = uniqueDomain();
  try {
    indexFinding({
      target_domain: domain,
      finding: {
        finding_id: "F-1",
        title: `${FINGERPRINT} IDOR on user profile endpoint`,
        description: `${FINGERPRINT} broken object level authorization`,
        severity: "high",
        attack_class: "idor",
        endpoint: `/${FINGERPRINT}/users/{id}`,
        tech_stack: ["express"],
      },
      calibration_label: "real",
    });
    const slice = summarizePriorFindingsForSurface(domain, {
      endpoint: `/${FINGERPRINT}/users/{id}`,
      bug_class: "idor",
      tech_stack: ["express"],
    });
    assert.ok(slice);
    assert.ok(slice.priors.length >= 1);
    assert.equal(slice.priors[0].finding_id, "F-1");
    assert.equal(slice.priors[0].calibration_label, "real");
    assert.ok(slice.same_target_count >= 1);
  } finally {
    cleanupDomain(domain);
  }
});

test("priors_slice aggregates across other targets and reports same vs other counts", () => {
  const domainA = uniqueDomain("bob-priors-A");
  const domainB = uniqueDomain("bob-priors-B");
  try {
    indexFinding({
      target_domain: domainA,
      finding: {
        finding_id: "A-1",
        title: `${FINGERPRINT} IDOR on user data`,
        description: `${FINGERPRINT} broken object level auth`,
        severity: "high",
        attack_class: "idor",
        endpoint: `/${FINGERPRINT}/users`,
      },
    });
    indexFinding({
      target_domain: domainB,
      finding: {
        finding_id: "B-1",
        title: `${FINGERPRINT} IDOR on profile`,
        description: `${FINGERPRINT} broken object level auth`,
        severity: "high",
        attack_class: "idor",
        endpoint: `/${FINGERPRINT}/profile`,
      },
    });
    const slice = summarizePriorFindingsForSurface(domainA, {
      endpoint: `/${FINGERPRINT}/users`,
      bug_class: "idor",
      notes: FINGERPRINT,
    }, { limit: 15 });
    assert.ok(slice);
    const myFindings = slice.priors.filter((p) => p.finding_id === "A-1" || p.finding_id === "B-1");
    assert.ok(myFindings.length >= 2, "both fingerprinted findings present");
    assert.ok(slice.domains_scanned >= 2);
  } finally {
    cleanupDomain(domainA);
    cleanupDomain(domainB);
  }
});

test("priors_slice limit option clamps below the hard ceiling", () => {
  const domain = uniqueDomain();
  try {
    for (let i = 0; i < 8; i++) {
      indexFinding({
        target_domain: domain,
        finding: {
          finding_id: `F-${i}`,
          title: `${FINGERPRINT} idor finding ${i}`,
          description: `${FINGERPRINT} broken object level auth`,
          severity: "high",
          attack_class: "idor",
        },
      });
    }
    const slice = summarizePriorFindingsForSurface(domain, {
      bug_class: "idor",
      notes: FINGERPRINT,
    }, { limit: 3 });
    assert.equal(slice.limit, 3);
    assert.ok(slice.priors.length <= 3);
  } finally {
    cleanupDomain(domain);
  }
});

test("priors_slice limit clamps to PRIORS_SLICE_MAX_LIMIT (15)", () => {
  const domain = uniqueDomain();
  try {
    for (let i = 0; i < 20; i++) {
      indexFinding({
        target_domain: domain,
        finding: {
          finding_id: `F-${i}`,
          title: `${FINGERPRINT} idor finding ${i}`,
          description: "x",
          severity: "high",
          attack_class: "idor",
        },
      });
    }
    const slice = summarizePriorFindingsForSurface(domain, {
      bug_class: "idor",
      notes: FINGERPRINT,
    }, { limit: 9999 });
    assert.equal(slice.limit, 15);
  } finally {
    cleanupDomain(domain);
  }
});

test("priors_slice indexable text covers smart-contract surface fields", () => {
  const domain = uniqueDomain();
  try {
    indexFinding({
      target_domain: domain,
      finding: {
        finding_id: "F-evm-1",
        title: `${FINGERPRINT} Reentrancy in withdraw`,
        description: `${FINGERPRINT} external call before state update`,
        severity: "high",
        attack_class: "reentrancy",
      },
    });
    const slice = summarizePriorFindingsForSurface(domain, {
      surface_type: "smart_contract",
      chain_family: "evm",
      chain_id: 1,
      contract_address: "0xabc",
      bug_classes: ["reentrancy"],
      notes: FINGERPRINT,
    });
    assert.ok(slice);
    const found = slice.priors.find((p) => p.finding_id === "F-evm-1");
    assert.ok(found, "fingerprinted SC finding present in slice");
  } finally {
    cleanupDomain(domain);
  }
});
