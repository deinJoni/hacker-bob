"use strict";

// LEGACY: removed in Plane D — finding-id adapter for the verification-plane.
//
// Cycle C.4 moves verification onto the frozen claim payload. Downstream
// callers (verification rounds, evidence, grade) still address claim
// membership by finding_id; this adapter resolves the finding_id set from the
// best available source:
//
//   1. The fresh verification snapshot (claim_ids/finding_ids projected from
//      the claim freeze). Authoritative when an attempt is active.
//   2. The current claim freeze. Authoritative when no attempt is active yet
//      but a freeze exists on disk.
//   3. Live findings.jsonl. Fallback for legacy/pre-claim sessions only.
//
// A future Plane D cycle will collapse (1)-(2) once `finding_ids[]` is gone
// from the snapshot and (3) is impossible (legacy paths deleted).

const {
  readCurrentClaimFreeze,
} = require("./claim-freeze.js");
const {
  readFindingsFromJsonl,
} = require("./finding-store.js");
const {
  claimsForFinding,
} = require("./claim-projections.js");

function findingIdsFromFreeze(freeze) {
  if (!freeze || !Array.isArray(freeze.claims)) return [];
  const ids = [];
  const seen = new Set();
  for (const claim of freeze.claims) {
    if (!claim || !Array.isArray(claim.evidence_refs)) continue;
    for (const ref of claim.evidence_refs) {
      if (ref && typeof ref === "object" && ref.kind === "finding" && typeof ref.finding_id === "string") {
        if (!seen.has(ref.finding_id)) {
          seen.add(ref.finding_id);
          ids.push(ref.finding_id);
        }
      }
    }
  }
  return ids;
}

// Resolve the set of finding_ids for the active verification context.
//
// Priority:
//   - snapshot.finding_ids[] (when an attempt is active)
//   - claim freeze projection (when no attempt is active but freeze exists)
//   - live findings.jsonl scan (legacy / pre-claim sessions)
//
// The adapter understands two equivalent inputs: `{snapshot}` (preferred,
// pass the snapshot returned by `requireFreshVerificationState`) and the older
// `{ finding_ids }` shape kept for callers that still address claim membership
// by raw id arrays.
function findingIdSetForVerificationContext({ domain, snapshot = null, finding_ids = null }) {
  if (snapshot && Array.isArray(snapshot.finding_ids)) {
    return new Set(snapshot.finding_ids);
  }
  if (Array.isArray(finding_ids)) {
    return new Set(finding_ids);
  }
  if (typeof domain === "string" && domain) {
    const freeze = readCurrentClaimFreeze(domain);
    if (freeze) {
      const projected = findingIdsFromFreeze(freeze);
      if (projected.length > 0) return new Set(projected);
    }
    // LEGACY: removed in Plane D
    return new Set(readFindingsFromJsonl(domain).map((finding) => finding.id));
  }
  return new Set();
}

// LEGACY: removed in Plane D — maps a `finding_ids[]` array supplied by an
// older caller into the matching `claim_ids[]` set via the claim-projections
// reverse lookup. Returns the *union* of claims referenced by the listed
// finding_ids.
function claimIdSetFromFindingIds(domain, findingIds) {
  if (!Array.isArray(findingIds)) return new Set();
  const ids = new Set();
  for (const findingId of findingIds) {
    if (typeof findingId !== "string" || !findingId) continue;
    const claims = claimsForFinding(domain, findingId);
    for (const claim of claims) {
      if (claim && typeof claim.claim_id === "string") ids.add(claim.claim_id);
    }
  }
  return ids;
}

module.exports = {
  claimIdSetFromFindingIds,
  findingIdSetForVerificationContext,
  findingIdsFromFreeze,
};
