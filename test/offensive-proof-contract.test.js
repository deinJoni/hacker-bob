"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  EVIDENCE_REFERENCE_KIND_VALUES,
  OFFENSIVE_OUTCOME_VALUES,
  SAFE_ORACLE_KINDS,
  appendCandidateClaim,
  canonicalizeExploitTarget,
  evidenceReferenceLookupKey,
  normalizeCandidateClaim,
  normalizeEvidenceReferenceShape,
  readCandidateClaims,
} = require("../mcp/lib/claims.js");
const {
  claimsJsonlPath,
  isAuditGradedPath,
  offensiveRunsJsonlPath,
  repoCommandRunsJsonlPath,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-offensive-proof-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function hex(char) {
  return char.repeat(64);
}

// The cited target host must be in scope for the claim domain (Codex P1 binding),
// so the ref/row target is derived from the domain unless a test overrides it.
function exploitRef(domain = "example.com", overrides = {}) {
  return {
    kind: "exploit_run",
    run_id: "run-exploit-1",
    tool_id: "bob_http_confirm_reflected_canary",
    target: `https://${domain}/search?q=BOB_CANARY_1`,
    offensive_outcome: "exploited_safely",
    command_hash: hex("a"),
    exit_code: 0,
    stdout_hash: hex("b"),
    stderr_hash: hex("c"),
    ...overrides,
  };
}

function exploitedClaim(domain, overrides = {}) {
  return {
    target_domain: domain,
    title: "Reflected canary was exploited safely",
    summary: "A benign canary was reflected in the target response.",
    severity: "low",
    exploit_outcome: {
      outcome: "exploited_safely",
      safe_oracle: { kind: "reflected_canary" },
    },
    evidence_refs: [exploitRef(domain)],
    ...overrides,
  };
}

function appendOffensiveRunRow(domain, overrides = {}) {
  const ref = exploitRef(domain);
  const row = {
    version: 1,
    target_domain: domain,
    run_id: ref.run_id,
    tool_id: ref.tool_id,
    target: ref.target,
    offensive_outcome: "exploited_safely",
    dry_run: false,
    timed_out: false,
    command_hash: ref.command_hash,
    exit_code: ref.exit_code,
    stdout_hash: ref.stdout_hash,
    stderr_hash: ref.stderr_hash,
    ...overrides,
  };
  // The runner records the same canonical (redacted) target the claim ref carries
  // so the row and ref stay byte-identical for the proof binding.
  row.target = canonicalizeExploitTarget(row.target);
  fs.mkdirSync(path.dirname(offensiveRunsJsonlPath(domain)), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  return row;
}

function mustThrow(fn) {
  let thrown = null;
  try {
    fn();
  } catch (error) {
    thrown = error;
  }
  assert.ok(thrown, "expected function to throw");
  return thrown;
}

function assertInvalidArgumentsCode(error, code) {
  assert.equal(error.code, "INVALID_ARGUMENTS");
  assert.equal(error.details && error.details.code, code);
}

test("exploit_run extends evidence kind enum without dropping existing kinds", () => {
  assert.ok(EVIDENCE_REFERENCE_KIND_VALUES.includes("exploit_run"));
  for (const existing of [
    "finding",
    "verification_round",
    "chain_attempt",
    "http_audit",
    "smart_contract_evidence",
    "agent_run",
    "repo_file",
    "repo_command_run",
  ]) {
    assert.ok(EVIDENCE_REFERENCE_KIND_VALUES.includes(existing), `regression: ${existing} removed`);
  }
  assert.equal(EVIDENCE_REFERENCE_KIND_VALUES.length, 9);
  assert.deepEqual(OFFENSIVE_OUTCOME_VALUES, [
    "exploited_safely",
    "blocked_by_defense",
    "blocked_by_infra",
  ]);
  assert.ok(SAFE_ORACLE_KINDS.includes("reflected_canary"));
});

test("evidenceReferenceLookupKey keys exploit_run by run_id", () => {
  assert.equal(
    evidenceReferenceLookupKey({ kind: "exploit_run", run_id: "run-abc123" }),
    "exploit_run:run-abc123",
  );
});

test("normalizeEvidenceReferenceShape enforces exploit_run payload shape", () => {
  for (const [field, value, pattern] of [
    ["run_id", "", /run_id must be a non-empty string for kind="exploit_run"/],
    ["tool_id", "", /tool_id must be a non-empty string for kind="exploit_run"/],
    ["target", "", /target must be a non-empty string for kind="exploit_run"/],
    ["offensive_outcome", "blocked_by_wishful_thinking", /offensive_outcome must be one of/],
    ["command_hash", "not-a-hash", /command_hash must be a 64-hex content digest/],
    ["stdout_hash", "not-a-hash", /stdout_hash must be a 64-hex content digest/],
    ["stderr_hash", "not-a-hash", /stderr_hash must be a 64-hex content digest/],
    ["exit_code", "0", /exit_code must be an integer or null/],
  ]) {
    assert.throws(
      () => normalizeEvidenceReferenceShape(exploitRef("example.com", { [field]: value })),
      pattern,
      `${field} should be validated`,
    );
  }

  const ok = normalizeEvidenceReferenceShape(exploitRef("example.com", { exit_code: null }));
  assert.equal(ok.kind, "exploit_run");
  assert.equal(ok.exit_code, null);
});

test("exploit_outcome normalizes as a guarded union and round-trips hash-stably", () => withTempHome(() => {
  const domain = "offensive-union.example";

  assert.throws(
    () => normalizeCandidateClaim(exploitedClaim(domain, {
      exploit_outcome: { outcome: "exploited_safely" },
    })),
    /safe_oracle must be an object when outcome is exploited_safely/,
  );
  assert.throws(
    () => normalizeCandidateClaim(exploitedClaim(domain, {
      exploit_outcome: {
        outcome: "exploited_safely",
        safe_oracle: { kind: "unsafe_shell" },
      },
    })),
    /safe_oracle\.kind must be one of/,
  );
  assert.throws(
    () => normalizeCandidateClaim(exploitedClaim(domain, {
      exploit_outcome: {
        outcome: "blocked_by_defense",
        safe_oracle: { kind: "reflected_canary" },
      },
    })),
    /safe_oracle is only allowed when outcome is exploited_safely/,
  );

  appendOffensiveRunRow(domain);
  const claim = appendCandidateClaim(exploitedClaim(domain));
  const [readBack] = readCandidateClaims(domain);
  assert.equal(readBack.claim_hash, claim.claim_hash);
  assert.deepEqual(readBack.exploit_outcome, {
    outcome: "exploited_safely",
    safe_oracle: { kind: "reflected_canary" },
  });
}));

test("exploited_safely claims reject missing exploit_run refs before touching claims.jsonl", () => withTempHome(() => {
  const domain = "offensive-missing-ref.example";
  const error = mustThrow(() => appendCandidateClaim(exploitedClaim(domain, {
    evidence_refs: [],
  })));
  assertInvalidArgumentsCode(error, "exploit_proof_missing_exploit_run_evidence");
  assert.equal(fs.existsSync(claimsJsonlPath(domain)), false);
}));

test("exploited_safely claims require a real matching offensive-runs ledger row", () => {
  const cases = [
    ["no matching row", null, {}],
    ["dry-run row", { dry_run: true }, {}],
    ["timed-out row", { timed_out: true }, {}],
    ["Docker startup failure exit", { exit_code: 125 }, {}],
    ["command-start failure exit", { exit_code: 126 }, {}],
    ["command-not-found failure exit", { exit_code: 127 }, {}],
    ["null exit code", { exit_code: null }, {}],
    ["blocked outcome row", { offensive_outcome: "blocked_by_defense" }, {}],
    ["pinned exit_code mismatch", { exit_code: 1 }, { exit_code: 0 }],
    ["command hash mismatch", { command_hash: hex("d") }, {}],
  ];

  for (const [label, rowOverride, refOverride] of cases) {
    withTempHome(() => {
      const domain = `offensive-${label.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}.example`;
      if (rowOverride) appendOffensiveRunRow(domain, rowOverride);
      const error = mustThrow(() => appendCandidateClaim(exploitedClaim(domain, {
        evidence_refs: [exploitRef(domain, refOverride)],
      })));
      assertInvalidArgumentsCode(error, "exploit_proof_unbacked_exploit_run_evidence");
      assert.equal(fs.existsSync(claimsJsonlPath(domain)), false, `${label}: claims.jsonl should be untouched`);
    });
  }
});

test("exploited_safely accepts a matching non-dry-run offensive-runs row", () => withTempHome(() => {
  const domain = "offensive-happy-path.example";
  appendOffensiveRunRow(domain);
  const claim = appendCandidateClaim(exploitedClaim(domain));
  assert.equal(claim.exploit_outcome.outcome, "exploited_safely");
  assert.equal(claim.evidence_refs[0].kind, "exploit_run");
  assert.equal(fs.readFileSync(claimsJsonlPath(domain), "utf8").trim().split(/\n/).length, 1);
}));

test("non-exploited and legacy claims do not require exploit_run proof", () => withTempHome(() => {
  const domain = "offensive-non-exploited.example";
  const blockedDefense = appendCandidateClaim({
    target_domain: domain,
    title: "Defense blocked the canary",
    summary: "The attempted benign canary was blocked.",
    severity: "low",
    exploit_outcome: { outcome: "blocked_by_defense" },
  });
  const blockedInfra = appendCandidateClaim({
    target_domain: domain,
    title: "Infrastructure blocked the canary",
    summary: "The probe could not reach the target path.",
    severity: "low",
    exploit_outcome: { outcome: "blocked_by_infra" },
  });
  const legacy = appendCandidateClaim({
    target_domain: domain,
    title: "Legacy non-offensive claim",
    summary: "No exploit outcome is asserted.",
    severity: "low",
  });

  assert.equal(blockedDefense.exploit_outcome.outcome, "blocked_by_defense");
  assert.equal(blockedInfra.exploit_outcome.outcome, "blocked_by_infra");
  assert.equal(legacy.exploit_outcome, undefined);
}));

test("persisted exploited claims remain readable after the proof ledger is gone", () => withTempHome(() => {
  const domain = "offensive-append-only-read.example";
  appendOffensiveRunRow(domain);
  const claim = appendCandidateClaim(exploitedClaim(domain));
  fs.unlinkSync(offensiveRunsJsonlPath(domain));

  const [readBack] = readCandidateClaims(domain);
  assert.equal(readBack.claim_hash, claim.claim_hash);
  assert.equal(readBack.exploit_outcome.outcome, "exploited_safely");
}));

test("exploit proof gate is severity-agnostic", () => {
  withTempHome(() => {
    const domain = "offensive-low-reject.example";
    const error = mustThrow(() => appendCandidateClaim(exploitedClaim(domain, {
      severity: "low",
      evidence_refs: [],
    })));
    assertInvalidArgumentsCode(error, "exploit_proof_missing_exploit_run_evidence");
  });

  withTempHome(() => {
    const domain = "offensive-info-accept.example";
    appendOffensiveRunRow(domain);
    const claim = appendCandidateClaim(exploitedClaim(domain, {
      severity: "informational",
    }));
    assert.equal(claim.severity, "informational");
  });
});

test("exploit_run canonicalizes targets to strip embedded secrets value-blind", () => {
  const cases = [
    ["https://example.com/cb?token=abc123secret", ["abc123secret"]],
    ["https://example.com/x?access_token=t0ksecret", ["t0ksecret"]],
    // compound / prefixed names that an exact-name denylist would miss
    ["https://example.com/login?client_secret=xyzsecret&X-Amz-Signature=sigsecret", ["xyzsecret", "sigsecret"]],
    // OAuth implicit-flow fragment
    ["https://example.com/cb#access_token=tokfragsecret&token_type=bearer", ["tokfragsecret"]],
    // SPA routed fragment (URLSearchParams would never see `token` here)
    ["https://example.com/#/callback?token=routedsecret", ["routedsecret"]],
    // userinfo credentials
    ["https://user:passsecret@example.com/poc", ["passsecret"]],
  ];
  for (const [target, secrets] of cases) {
    const ref = normalizeEvidenceReferenceShape(exploitRef("example.com", { target }));
    for (const secret of secrets) {
      assert.ok(!ref.target.includes(secret), `${target} -> ${ref.target} still leaks "${secret}"`);
    }
    assert.ok(!/\/\/[^/]*@/.test(ref.target), `${ref.target} still embeds userinfo`);
  }
  // Benign param NAMES survive (values redacted) for triage clarity.
  const ref = normalizeEvidenceReferenceShape(
    exploitRef("example.com", { target: "https://example.com/s?q=BOB_CANARY_1&page=2" }),
  );
  assert.ok(ref.target.includes("q=") && ref.target.includes("page="), `param names dropped: ${ref.target}`);
  assert.ok(!ref.target.includes("BOB_CANARY_1"), `query value not redacted: ${ref.target}`);
});

test("exploited_safely rejects a claim carrying an extra out-of-scope exploit_run ref", () => withTempHome(() => {
  const domain = "example.com";
  appendOffensiveRunRow(domain); // backs the valid in-scope ref
  const validRef = exploitRef(domain);
  const offHostRef = exploitRef(domain, {
    run_id: "run-exploit-2",
    target: "https://attacker.example/steal?q=BOB_CANARY_1",
  });
  const error = mustThrow(() => appendCandidateClaim(exploitedClaim(domain, {
    evidence_refs: [validRef, offHostRef],
  })));
  // every() binding: one valid ref cannot carry an unbacked, out-of-scope sibling.
  assertInvalidArgumentsCode(error, "exploit_proof_unbacked_exploit_run_evidence");
  assert.equal(fs.existsSync(claimsJsonlPath(domain)), false);
}));

test("exploited_safely fails closed when the proof ledger has a malformed row", () => withTempHome(() => {
  const domain = "example.com";
  appendOffensiveRunRow(domain); // a valid row that would otherwise back the claim
  fs.appendFileSync(offensiveRunsJsonlPath(domain), "{not valid json\n");
  const error = mustThrow(() => appendCandidateClaim(exploitedClaim(domain)));
  assert.equal(error.code, "STATE_CONFLICT");
  assert.equal(fs.existsSync(claimsJsonlPath(domain)), false);
}));

test("exploited_safely proof is bound to the claim target_domain", () => {
  // (a) A row planted in this session's ledger but recorded for another domain
  // cannot back the claim, even though run_id/hashes match.
  withTempHome(() => {
    const domain = "victim.example";
    appendOffensiveRunRow(domain, { target_domain: "attacker.example" });
    const error = mustThrow(() => appendCandidateClaim(exploitedClaim(domain)));
    assertInvalidArgumentsCode(error, "exploit_proof_unbacked_exploit_run_evidence");
    assert.equal(fs.existsSync(claimsJsonlPath(domain)), false);
  });

  // (b) An out-of-scope target URL (host not under the claim domain) cannot back
  // the claim, even with a row whose target_domain matches the claim.
  withTempHome(() => {
    const domain = "victim.example";
    const offHost = "https://attacker.example/steal?q=BOB_CANARY_1";
    appendOffensiveRunRow(domain, { target: offHost });
    const error = mustThrow(() => appendCandidateClaim(exploitedClaim(domain, {
      evidence_refs: [exploitRef(domain, { target: offHost })],
    })));
    assertInvalidArgumentsCode(error, "exploit_proof_unbacked_exploit_run_evidence");
    assert.equal(fs.existsSync(claimsJsonlPath(domain)), false);
  });
});

test("exploited_safely accepts an in-scope subdomain target", () => withTempHome(() => {
  const domain = "example.com";
  const subTarget = "https://api.example.com/v1/search?q=BOB_CANARY_1";
  appendOffensiveRunRow(domain, { target: subTarget });
  const claim = appendCandidateClaim(exploitedClaim(domain, {
    evidence_refs: [exploitRef(domain, { target: subTarget })],
  }));
  assert.equal(claim.exploit_outcome.outcome, "exploited_safely");
  // The stored ref carries the canonical (value-redacted) target, not the raw URL.
  assert.equal(claim.evidence_refs[0].target, canonicalizeExploitTarget(subTarget));
}));

test("offensive-runs.jsonl is audit-graded while repo-command-runs.jsonl stays non-audit-graded", () => withTempHome(() => {
  const domain = "offensive-audit-graded.example";
  assert.equal(isAuditGradedPath(offensiveRunsJsonlPath(domain), domain), true);
  assert.equal(isAuditGradedPath(repoCommandRunsJsonlPath(domain), domain), false);
}));
