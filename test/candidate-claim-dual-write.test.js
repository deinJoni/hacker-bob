"use strict";

// C.2 invariant: every Finding recorded through the record-finding tool shim
// produces a parallel CandidateClaim row plus a claim.candidate.linked frontier
// event, all hash-bound and pointing back to the source finding_id. The Finding
// remains authoritative; the claim plane is the parallel (dual) write.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const recordFindingTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  readFindingsFromJsonl,
} = require("../mcp/lib/finding-store.js");
const {
  readCandidateClaims,
} = require("../mcp/lib/claims.js");
const {
  readFrontierEvents,
} = require("../mcp/lib/frontier-events.js");
const {
  claimsForFinding,
  findingForClaim,
} = require("../mcp/lib/claim-projections.js");
const {
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-claim-dual-write-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function findingInput(domain, index) {
  return {
    target_domain: domain,
    title: `IDOR exposes record ${index}`,
    severity: index % 2 === 0 ? "high" : "medium",
    cwe: `CWE-${600 + index}`,
    endpoint: `https://victim.example/api/records/${index}`,
    description: `Changing record ${index} identifier returns another tenant payload.`,
    proof_of_concept: `GET /api/records/${index} as the attacker tenant returns private fields.`,
    response_evidence: `Response leaked tenant identifier and email for record ${index}.`,
    impact: `Cross-tenant record ${index} disclosure.`,
    validated: true,
    auth_profile: `attacker-${index}`,
    surface_id: `surface:record-${index}`,
  };
}

test("recording 5 findings dual-writes 5 CandidateClaims plus 5 claim.candidate.linked events", () => {
  withTempHome(() => {
    const domain = "claim-dual-write.example.com";
    const findingIds = [];
    for (let i = 1; i <= 5; i += 1) {
      const response = JSON.parse(recordFindingTool.handler(findingInput(domain, i)));
      assert.equal(response.recorded, true, `finding ${i} must be recorded`);
      findingIds.push(response.finding_id);
    }
    assert.equal(new Set(findingIds).size, 5, "each finding must receive a distinct id");

    const findings = readFindingsFromJsonl(domain);
    assert.equal(findings.length, 5, "findings.jsonl should carry exactly 5 rows");

    const claims = readCandidateClaims(domain);
    assert.equal(claims.length, 5, "claims.jsonl should carry exactly 5 rows");

    // Every claim must have exactly one finding evidence ref pointing back to a
    // Finding, with the content_hash matching hashCanonicalJson(finding).
    const claimsByFindingId = new Map();
    for (const claim of claims) {
      assert.equal(typeof claim.claim_id, "string");
      assert.equal(typeof claim.claim_hash, "string");
      assert.equal(claim.claim_hash.length, 64);
      assert.ok(Array.isArray(claim.evidence_refs), "claim must carry evidence_refs[]");
      assert.equal(claim.evidence_refs.length, 1, "claim must carry exactly one evidence ref to its Finding");
      const ref = claim.evidence_refs[0];
      assert.equal(ref.kind, "finding");
      assert.equal(ref.artifact_path, "findings.jsonl");
      assert.equal(typeof ref.finding_id, "string");
      assert.equal(typeof ref.content_hash, "string");
      assert.equal(ref.content_hash.length, 64);
      claimsByFindingId.set(ref.finding_id, claim);
    }

    for (const finding of findings) {
      const claim = claimsByFindingId.get(finding.id);
      assert.ok(claim, `every finding must have a parallel CandidateClaim (missing for ${finding.id})`);
      assert.equal(
        claim.evidence_refs[0].content_hash,
        hashCanonicalJson(finding),
        "claim evidence ref content_hash must match hashCanonicalJson(finding)",
      );
      // Mirrored fields: severity (info → informational; the test fixtures use
      // high/medium only) and surface_ids contain the finding's surface_id.
      assert.equal(claim.severity, finding.severity);
      assert.deepEqual(claim.surface_ids, [finding.surface_id]);
      assert.ok(claim.payload && typeof claim.payload === "object", "claim payload must mirror auth_profile/attack_class/subject_id");
      assert.equal(claim.payload.auth_profile_ref, finding.auth_profile);
      assert.equal(claim.payload.subject_id, finding.endpoint);
      assert.equal(claim.payload.surface_ref, finding.surface_id);
      assert.equal(claim.payload.attack_class, finding.cwe);
    }

    // Exactly 5 claim.candidate.linked frontier events, each pointing to its
    // claim_id and finding_id.
    const events = readFrontierEvents(domain).filter((event) => event.kind === "claim.candidate.linked");
    assert.equal(events.length, 5, "frontier-events.jsonl should carry 5 claim.candidate.linked events");
    const eventLinks = new Map();
    for (const event of events) {
      assert.equal(typeof event.event_id, "string");
      assert.equal(typeof event.event_hash, "string");
      assert.equal(event.event_hash.length, 64);
      assert.equal(event.plane, "frontier");
      const payload = event.payload || {};
      assert.equal(typeof payload.claim_id, "string");
      assert.equal(typeof payload.finding_id, "string");
      eventLinks.set(payload.finding_id, payload.claim_id);
    }
    for (const finding of findings) {
      const linkedClaimId = eventLinks.get(finding.id);
      assert.ok(linkedClaimId, `frontier event must reference finding ${finding.id}`);
      assert.equal(linkedClaimId, claimsByFindingId.get(finding.id).claim_id);
    }

    // claimsForFinding projection returns exactly one claim per finding_id and
    // findingForClaim returns the inverse mapping.
    for (const finding of findings) {
      const projected = claimsForFinding(domain, finding.id);
      assert.equal(projected.length, 1, `claimsForFinding(${finding.id}) must return exactly one claim`);
      assert.equal(projected[0].claim_id, claimsByFindingId.get(finding.id).claim_id);
      const inverse = findingForClaim(domain, projected[0].claim_id);
      assert.equal(inverse, finding.id, "findingForClaim should round-trip back to the source finding_id");
    }
  });
});
