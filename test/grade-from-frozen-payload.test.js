"use strict";

// Cycle C.6 invariant: the GRADE phase sources its work-set from the frozen
// CandidateClaim batch (claim-freeze.json) rather than the live findings.jsonl
// ledger. Mutating findings.jsonl after the freeze must not change the grade
// verdict; the verdict records `claim_freeze_id` so a later consumer can prove
// which frozen claim batch was scored; and the C.5 evidence-completeness gate
// is preserved 1:1 on the new surface (an incomplete evidence pack still
// blocks the grade).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  buildClaimFreeze,
  readCurrentClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  appendJsonlLine,
  writeFileAtomic,
} = require("../mcp/lib/storage.js");
const {
  evidencePackPaths,
  findingsJsonlPath,
  gradeArtifactPaths,
  sessionDir,
  verificationRoundPaths,
} = require("../mcp/lib/paths.js");
const {
  normalizeFindingRecord,
} = require("../mcp/lib/finding-contracts.js");
const recordFindingTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  writeVerificationRound,
} = require("../mcp/lib/verification-round-store.js");
const {
  writeEvidencePacks,
} = require("../mcp/lib/evidence.js");
const {
  readGradeVerdict,
  writeGradeVerdict,
} = require("../mcp/lib/grade-verdict-store.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-grade-from-frozen-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function recordFindingViaTool(domain, overrides = {}) {
  const args = {
    target_domain: domain,
    title: overrides.title || "IDOR on billing profile",
    severity: overrides.severity || "high",
    cwe: overrides.cwe || "CWE-639",
    endpoint: overrides.endpoint || "https://victim.example/api/billing/1",
    description: overrides.description || "Tenant boundary allows cross-account view",
    proof_of_concept: overrides.poc || "GET /api/billing/1 returns another tenant payload",
    response_evidence: overrides.response_evidence || "Cross-tenant billing payload",
    impact: overrides.impact || "Cross-tenant billing disclosure",
    validated: true,
    auth_profile: overrides.auth_profile || "attacker",
    surface_id: overrides.surface_id || "surface:billing-profile",
  };
  return JSON.parse(recordFindingTool.handler(args));
}

function appendFindingJsonlDirect(domain, id, overrides = {}) {
  // Bypass the dual-write shim so the file mutation post-freeze does not
  // recreate the claim plane.
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const record = normalizeFindingRecord({
    id,
    target_domain: domain,
    title: overrides.title || `Post-freeze finding ${id}`,
    severity: overrides.severity || "critical",
    cwe: overrides.cwe || "CWE-639",
    endpoint: overrides.endpoint || `https://victim.example/api/post-freeze/${id}`,
    description: overrides.description || "Mutated after the freeze",
    proof_of_concept: overrides.poc || "POST /api/post-freeze inserted after freeze",
    response_evidence: overrides.response_evidence || "Post-freeze evidence",
    impact: overrides.impact || "Should not change grade verdict",
    validated: true,
    surface_id: overrides.surface_id || "surface:post-freeze",
    auth_profile: overrides.auth_profile || "attacker",
  }, { expectedDomain: domain });
  appendJsonlLine(findingsJsonlPath(domain), record);
  return record;
}

function verificationResult(findingId = "F-1", overrides = {}) {
  return {
    finding_id: findingId,
    disposition: "confirmed",
    severity: "high",
    reportable: true,
    reasoning: "Fresh replay confirmed the finding against the current target state.",
    ...overrides,
  };
}

function evidencePack(findingId = "F-1", overrides = {}) {
  return {
    finding_id: findingId,
    sample_type: "cross-account replay",
    sample_count: 1,
    aggregate_counts: { affected_objects_sampled: 1 },
    representative_samples: [{
      request_ref: "http-audit:1",
      endpoint: "/api/billing/1",
      auth_profile: "attacker",
      status: 200,
      observed_fields: ["billing_profile_id", "email"],
      redacted_object_id: "acct_...002",
    }],
    sensitive_clusters: ["billing metadata"],
    replay_summary: "Fresh replay returned another tenant's private billing metadata.",
    redaction_notes: "Object IDs and personal values redacted; auth material omitted.",
    report_snippet: "An attacker can retrieve another tenant's private billing metadata by changing the billing profile ID.",
    ...overrides,
  };
}

function gradeFinding(findingId = "F-1", overrides = {}) {
  return {
    finding_id: findingId,
    impact: 25,
    proof_quality: 20,
    severity_accuracy: 10,
    chain_potential: 10,
    report_quality: 10,
    total_score: 75,
    feedback: "Clear, reproducible, and reportable.",
    ...overrides,
  };
}

function seedFinalVerificationFromFrozen(domain, { findingId = "F-1" } = {}) {
  // Dual-write seeds a single CandidateClaim alongside the Finding.
  recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/1" });
  // Freeze the claim batch so the verdict is bound to a stable claim_freeze_id.
  buildClaimFreeze(domain, {
    write: true,
    now: new Date("2026-05-27T01:00:00.000Z"),
  });
  // Write the V1 round chain. The C.6 path projects the work-set from the
  // frozen claim batch even though the verification artefacts are V1; the
  // round itself remains bound by content (reportable + severity) rather than
  // by snapshot hash.
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain,
      round,
      notes: null,
      results: [verificationResult(findingId)],
    });
  }
  writeEvidencePacks({ target_domain: domain, packs: [evidencePack(findingId)] });
}

test("grade verdict is bound to the frozen claim batch via claim_freeze_id", () => {
  withTempHome(() => {
    const domain = "grade-frozen-bound.example.com";
    seedFinalVerificationFromFrozen(domain);
    const freeze = readCurrentClaimFreeze(domain);
    assert.ok(freeze, "claim freeze must exist");
    assert.equal(freeze.claim_count, 1);

    const written = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    }));
    assert.equal(written.verdict, "SUBMIT");
    assert.equal(
      written.claim_freeze_id,
      freeze.freeze_id,
      "write response must echo the active claim_freeze_id",
    );

    const onDisk = JSON.parse(fs.readFileSync(gradeArtifactPaths(domain).json, "utf8"));
    assert.equal(
      onDisk.claim_freeze_id,
      freeze.freeze_id,
      "persisted grade verdict must carry claim_freeze_id pointing at the source freeze",
    );

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.equal(read.claim_freeze_id, freeze.freeze_id);
  });
});

test("mutating findings.jsonl after the freeze does NOT change the grade verdict (frozen set authoritative)", () => {
  withTempHome(() => {
    const domain = "grade-frozen-stability.example.com";
    seedFinalVerificationFromFrozen(domain);

    const baseline = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    }));
    const baselineDoc = JSON.parse(fs.readFileSync(gradeArtifactPaths(domain).json, "utf8"));
    const baselineFreezeId = baseline.claim_freeze_id;
    assert.ok(typeof baselineFreezeId === "string" && baselineFreezeId, "baseline must carry claim_freeze_id");

    // Mutate findings.jsonl AFTER the freeze + AFTER the verdict is written.
    // The grade work-set is enumerated from the frozen claims[], so a new
    // critical finding must not change the verdict.
    appendFindingJsonlDirect(domain, "F-99", { severity: "critical" });

    // Rewrite the verdict (so we hit the C.6 write-path with the post-mutation
    // disk state). The verdict must still ignore F-99 because the freeze is
    // the source of the work-set, not findings.jsonl.
    const rewritten = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    }));
    const rewrittenDoc = JSON.parse(fs.readFileSync(gradeArtifactPaths(domain).json, "utf8"));

    assert.equal(rewritten.verdict, baseline.verdict);
    assert.equal(rewritten.findings_count, baseline.findings_count);
    assert.equal(
      rewritten.claim_freeze_id,
      baselineFreezeId,
      "claim_freeze_id must reference the same source freeze; mutations are ignored",
    );
    assert.equal(rewrittenDoc.claim_freeze_id, baselineDoc.claim_freeze_id);
    assert.equal(rewrittenDoc.findings.length, 1);
    assert.equal(rewrittenDoc.findings[0].finding_id, "F-1");

    // Attempting to grade the post-freeze critical finding (F-99) must be
    // rejected by the unknown-finding-id guard — F-99 is not in the frozen
    // claim batch, so it cannot be scored.
    assert.throws(
      () => writeGradeVerdict({
        target_domain: domain,
        verdict: "SUBMIT",
        total_score: 75,
        findings: [gradeFinding("F-99")],
      }),
      /Unknown finding_id: F-99/,
      "frozen work-set must reject grading findings added after the freeze",
    );
  });
});

test("strict gate: incomplete evidence (C.5 completeness contract) blocks the grade verdict", () => {
  withTempHome(() => {
    const domain = "grade-incomplete-evidence.example.com";
    // Dual-write so the freeze captures a CandidateClaim. Freeze, then write
    // the V1 final round. Skip the evidence-pack write so the C.5 evidence
    // completeness gate is unsatisfied at grade time.
    recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/1" });
    buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [verificationResult("F-1")],
      });
    }
    // Confirm no evidence pack exists on disk.
    assert.equal(fs.existsSync(evidencePackPaths(domain).json), false);

    assert.throws(
      () => writeGradeVerdict({
        target_domain: domain,
        verdict: "SUBMIT",
        total_score: 75,
        findings: [gradeFinding("F-1")],
      }),
      /Evidence packs are required/,
      "C.5 evidence-completeness gate must block the grade verdict on the C.6 surface",
    );
  });
});

test("strict gate: final verification must exist before grading (preserved 1:1)", () => {
  withTempHome(() => {
    const domain = "grade-missing-final.example.com";
    recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/1" });
    buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    // No verification rounds at all.
    assert.equal(fs.existsSync(verificationRoundPaths(domain, "final").json), false);
    assert.throws(
      () => writeGradeVerdict({
        target_domain: domain,
        verdict: "SUBMIT",
        total_score: 75,
        findings: [gradeFinding("F-1")],
      }),
      /Final verification must exist and be valid before grading/,
      "final-verification gate must remain on the C.6 surface",
    );
  });
});

test("strict gate: grade total_score must equal max per-finding score (verdict consistency preserved)", () => {
  withTempHome(() => {
    const domain = "grade-score-consistency.example.com";
    seedFinalVerificationFromFrozen(domain);

    // Mismatch: total_score = 75 but per-finding total = 75 is fine; force
    // a mismatch by reporting a total_score that does not match the maximum
    // per-finding score.
    assert.throws(
      () => writeGradeVerdict({
        target_domain: domain,
        verdict: "SUBMIT",
        total_score: 100,
        findings: [gradeFinding("F-1", { total_score: 75 })],
      }),
      /grade total_score must equal the maximum per-finding score/,
      "C.6 must preserve the grade-score consistency gate",
    );

    // Mismatched verdict for the score must also be rejected.
    assert.throws(
      () => writeGradeVerdict({
        target_domain: domain,
        verdict: "SKIP",
        total_score: 75,
        findings: [gradeFinding("F-1", { total_score: 75 })],
      }),
      /grade verdict SKIP does not match total_score/,
      "C.6 must preserve the verdict-score consistency gate",
    );
  });
});

test("legacy adapter: callers passing finding_ids[] are routed through claimIdSetFromFindingIds", () => {
  withTempHome(() => {
    const domain = "grade-legacy-adapter.example.com";
    seedFinalVerificationFromFrozen(domain);
    const freeze = readCurrentClaimFreeze(domain);
    assert.ok(freeze);

    // Pass an explicit finding_ids array (legacy shape). The C.6 resolver
    // routes through verification-finding-id-adapter.claimIdSetFromFindingIds
    // to exercise the legacy contract; the resulting verdict must still
    // succeed and remain bound to the active freeze.
    const written = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
      finding_ids: ["F-1"],
    }));
    assert.equal(written.verdict, "SUBMIT");
    assert.equal(written.claim_freeze_id, freeze.freeze_id);
  });
});
