"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  HANDOFF_PROVENANCE_MODEL,
  signHandoffProvenance,
  validateHandoffProvenance,
} = require("../mcp/lib/wave-handoff-contracts.js");

function baseHandoff() {
  return {
    target_domain: "example.com",
    wave: "w1",
    agent: "a1",
    surface_id: "surface-a",
    surface_type: null,
    surface_status: "complete",
    provenance: "verified",
    summary: "Tested the assigned surface.",
    chain_notes: [],
    blocked_harness_runs: [],
    blocked_prereqs: [],
    bypass_attempts: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
  };
}

test("signed handoff provenance verifies without storing the raw handoff token", () => {
  const signingKey = Buffer.from("0123456789abcdef0123456789abcdef");
  const assignment = {
    agent: "a1",
    surface_id: "surface-a",
    handoff_token_required: true,
    handoff_token_sha256: "0".repeat(64),
  };

  const signed = signHandoffProvenance(baseHandoff(), signingKey, { assignment });

  assert.equal(signed.provenance, "verified");
  assert.equal(signed.provenance_model, HANDOFF_PROVENANCE_MODEL);
  assert.match(signed.provenance_assignment_hash, /^[0-9a-f]{64}$/);
  assert.equal(signed.provenance_signature.algorithm, "hmac-sha256");
  assert.doesNotMatch(JSON.stringify(signed), /plain-handoff-token/);
  assert.equal(validateHandoffProvenance(signed, assignment, { signingKey }), "verified");
});

test("signed handoff provenance is invalid after payload tampering", () => {
  const signingKey = Buffer.from("0123456789abcdef0123456789abcdef");
  const assignment = {
    agent: "a1",
    surface_id: "surface-a",
    handoff_token_required: true,
    handoff_token_sha256: "0".repeat(64),
  };
  const signed = signHandoffProvenance(baseHandoff(), signingKey, { assignment });

  assert.throws(
    () => validateHandoffProvenance({ ...signed, summary: "Different summary." }, assignment, { signingKey }),
    /signature does not match/,
  );
});

test("signed handoff provenance is bound to the current assignment hash", () => {
  const signingKey = Buffer.from("0123456789abcdef0123456789abcdef");
  const assignment = {
    agent: "a1",
    surface_id: "surface-a",
    handoff_token_required: true,
    handoff_token_sha256: "0".repeat(64),
  };
  const signed = signHandoffProvenance(baseHandoff(), signingKey, { assignment });

  assert.throws(
    () => validateHandoffProvenance(signed, { ...assignment, handoff_token_sha256: "1".repeat(64) }, { signingKey }),
    /assignment hash does not match/,
  );
});

test("tokenized assignments reject unsigned verified provenance claims", () => {
  const signingKey = Buffer.from("0123456789abcdef0123456789abcdef");
  const assignment = {
    agent: "a1",
    surface_id: "surface-a",
    handoff_token_required: true,
    handoff_token_sha256: "0".repeat(64),
  };

  assert.throws(
    () => validateHandoffProvenance(baseHandoff(), assignment, { signingKey }),
    /provenance model is missing or unsupported/,
  );
});

test("legacy assignments remain explicitly unverified", () => {
  assert.equal(validateHandoffProvenance(baseHandoff(), {}), "legacy_unverified");
});

test("legacy assignments are rejected when requireProvenance is set", () => {
  // v1.3.5 sessions opt in to provenance via state.handoff_provenance_required.
  // The validator must refuse to silently downgrade a tampered/legacy assignment
  // when this flag is set, even if no token metadata is present.
  assert.throws(
    () => validateHandoffProvenance(baseHandoff(), {}, { requireProvenance: true }),
    /assignment lacks token metadata.*pre-v1\.3\.5/,
  );
});
