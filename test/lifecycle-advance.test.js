"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  advanceSession,
  initSession,
} = require("../mcp/lib/session-state.js");
const {
  readSessionNucleus,
} = require("../mcp/lib/governance-store.js");
const {
  sessionEventsJsonlPath,
} = require("../mcp/lib/paths.js");
const {
  readSessionEvents,
} = require("../mcp/lib/session-events.js");
const {
  allowedTargetsFor,
} = require("../mcp/lib/lifecycle-gates.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-lifecycle-advance-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function bootstrapDomain(domain) {
  initSession({ target_domain: domain, target_url: `https://${domain}/` });
}

function lifecycleAdvancedEvents(domain) {
  return readSessionEvents(domain).filter((event) => event.kind === "governance.lifecycle.advanced");
}

function lifecycleOverrideEvents(domain) {
  return readSessionEvents(domain).filter((event) => event.kind === "governance.lifecycle.override");
}

test("bob_advance_session rejects an unreachable target with a structured no_transition blocker", () => {
  withTempHome(() => {
    const domain = "block.example.com";
    bootstrapDomain(domain);

    let captured = null;
    try {
      advanceSession({ target_domain: domain, to_state: "VERIFY" });
    } catch (error) {
      captured = error;
    }

    assert.ok(captured, "forced VERIFY from SETUP must throw");
    assert.equal(captured.code, "STATE_CONFLICT", `expected STATE_CONFLICT, got ${captured.code}`);
    assert.ok(captured.details, "structured blocker payload must be attached");
    assert.equal(captured.details.blocked_by, "no_transition");
    assert.equal(captured.details.from, "SETUP");
    assert.equal(captured.details.to, "VERIFY");
    assert.deepEqual(captured.details.allowed, allowedTargetsFor("SETUP"));
    assert.ok(Array.isArray(captured.details.blockers));
    assert.equal(captured.details.blockers[0].blocked_by, "no_transition");

    // No advance event should have been written by the rejected call.
    assert.equal(lifecycleAdvancedEvents(domain).length, 0);
    assert.equal(lifecycleOverrideEvents(domain).length, 0);

    // Nucleus must still be SETUP.
    const nucleus = readSessionNucleus(domain);
    assert.equal(nucleus.lifecycle_state, "SETUP");
  });
});

test("bob_advance_session drives SETUP -> OPEN_FRONTIER -> CLAIM_FREEZE -> VERIFY -> GRADE -> REPORT with distinct hashes", () => {
  withTempHome(() => {
    const domain = "sequence.example.com";
    bootstrapDomain(domain);

    const initialNucleus = readSessionNucleus(domain);
    assert.equal(initialNucleus.lifecycle_state, "SETUP");
    const observedHashes = new Set([initialNucleus.nucleus_hash]);

    // The hypergraph review gate calls for six distinct nucleus_hash values
    // and six governance.lifecycle.advanced events. The canonical SETUP ->
    // OPEN_FRONTIER -> CLAIM_FREEZE -> VERIFY -> GRADE -> REPORT walk is
    // 5 forward edges (5 advances). Combined with the initial SETUP nucleus
    // that lands six distinct lifecycle_state values, six distinct
    // nucleus_hash values, and five lifecycle.advanced events. The sixth
    // event comes from the D3 re-entry REPORT -> OPEN_FRONTIER, which lands
    // a sixth lifecycle.advanced event even though it returns to a previously
    // observed OPEN_FRONTIER lifecycle_state.
    const sequence = [
      "OPEN_FRONTIER",
      "CLAIM_FREEZE",
      "VERIFY",
      "GRADE",
      "REPORT",
      "OPEN_FRONTIER",
    ];

    let priorHash = initialNucleus.nucleus_hash;
    for (const target of sequence) {
      const result = JSON.parse(advanceSession({ target_domain: domain, to_state: target }));
      assert.equal(result.advanced, true);
      assert.equal(result.to_state, target);
      assert.equal(result.prior_nucleus_hash, priorHash);
      assert.match(result.nucleus_hash, /^[0-9a-f]{64}$/);
      observedHashes.add(result.nucleus_hash);
      const persisted = readSessionNucleus(domain);
      assert.equal(persisted.lifecycle_state, target);
      assert.equal(persisted.nucleus_hash, result.nucleus_hash);
      priorHash = result.nucleus_hash;
    }

    // Six distinct nucleus_hash values: SETUP, OPEN_FRONTIER, CLAIM_FREEZE,
    // VERIFY, GRADE, REPORT. The seventh advance (REPORT -> OPEN_FRONTIER)
    // returns to the previously observed OPEN_FRONTIER hash, which is correct
    // because the nucleus is deterministically content-hashed and the
    // post-states are identical.
    assert.equal(observedHashes.size, 6, "six distinct nucleus_hash values must be observed across SETUP..REPORT");

    const events = lifecycleAdvancedEvents(domain);
    assert.equal(events.length, 6, `expected 6 lifecycle.advanced events, got ${events.length}`);
    const orderedTransitions = events.map((event) => [event.payload.from_state, event.payload.to_state]);
    assert.deepEqual(orderedTransitions, [
      ["SETUP", "OPEN_FRONTIER"],
      ["OPEN_FRONTIER", "CLAIM_FREEZE"],
      ["CLAIM_FREEZE", "VERIFY"],
      ["VERIFY", "GRADE"],
      ["GRADE", "REPORT"],
      ["REPORT", "OPEN_FRONTIER"],
    ]);

    // Every advance event must carry the nucleus_hash for the post-state and
    // the prior_nucleus_hash for the pre-state.
    for (const event of events) {
      assert.match(event.payload.nucleus_hash, /^[0-9a-f]{64}$/);
      assert.match(event.payload.prior_nucleus_hash, /^[0-9a-f]{64}$/);
      assert.notEqual(event.payload.nucleus_hash, event.payload.prior_nucleus_hash);
      assert.equal(event.nucleus_hash, event.payload.nucleus_hash);
    }
  });
});

test("bob_advance_session with override: operator_force advances despite a no_transition blocker and writes a lifecycle.override event", () => {
  withTempHome(() => {
    const domain = "override.example.com";
    bootstrapDomain(domain);

    const priorNucleus = readSessionNucleus(domain);
    assert.equal(priorNucleus.lifecycle_state, "SETUP");

    const result = JSON.parse(advanceSession({
      target_domain: domain,
      to_state: "VERIFY",
      override: "operator_force",
      override_reason: "operator forced verify for cycle test",
    }));
    assert.equal(result.advanced, true);
    assert.equal(result.from_state, "SETUP");
    assert.equal(result.to_state, "VERIFY");
    assert.equal(result.override, "operator_force");

    const persisted = readSessionNucleus(domain);
    assert.equal(persisted.lifecycle_state, "VERIFY");
    assert.equal(persisted.nucleus_hash, result.nucleus_hash);

    const overrides = lifecycleOverrideEvents(domain);
    assert.equal(overrides.length, 1, "exactly one governance.lifecycle.override event after forced advance");
    const [overrideEvent] = overrides;
    assert.equal(overrideEvent.payload.from_state, "SETUP");
    assert.equal(overrideEvent.payload.to_state, "VERIFY");
    assert.equal(overrideEvent.payload.override, "operator_force");
    assert.equal(overrideEvent.payload.override_reason, "operator forced verify for cycle test");
    assert.equal(overrideEvent.payload.prior_nucleus_hash, priorNucleus.nucleus_hash);
    assert.ok(Array.isArray(overrideEvent.payload.blockers));
    assert.equal(overrideEvent.payload.blockers[0].blocked_by, "no_transition");

    const advances = lifecycleAdvancedEvents(domain);
    assert.equal(advances.length, 1, "override path still emits the lifecycle.advanced event");
    assert.equal(advances[0].payload.from_state, "SETUP");
    assert.equal(advances[0].payload.to_state, "VERIFY");
  });
});

test("bob_advance_session honors D3 bidirectional edges (CLAIM_FREEZE <-> OPEN_FRONTIER and REPORT -> OPEN_FRONTIER)", () => {
  withTempHome(() => {
    const domain = "bidir.example.com";
    bootstrapDomain(domain);

    // SETUP -> OPEN_FRONTIER -> CLAIM_FREEZE -> OPEN_FRONTIER (D3).
    advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" });
    advanceSession({ target_domain: domain, to_state: "CLAIM_FREEZE" });
    const reopened = JSON.parse(advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }));
    assert.equal(reopened.from_state, "CLAIM_FREEZE");
    assert.equal(reopened.to_state, "OPEN_FRONTIER");
    assert.equal(readSessionNucleus(domain).lifecycle_state, "OPEN_FRONTIER");

    // Walk forward to REPORT and then re-enter OPEN_FRONTIER.
    advanceSession({ target_domain: domain, to_state: "CLAIM_FREEZE" });
    advanceSession({ target_domain: domain, to_state: "VERIFY" });
    advanceSession({ target_domain: domain, to_state: "GRADE" });
    advanceSession({ target_domain: domain, to_state: "REPORT" });
    const reentry = JSON.parse(advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }));
    assert.equal(reentry.from_state, "REPORT");
    assert.equal(reentry.to_state, "OPEN_FRONTIER");
    assert.equal(readSessionNucleus(domain).lifecycle_state, "OPEN_FRONTIER");

    const advances = lifecycleAdvancedEvents(domain);
    const orderedTransitions = advances.map((event) => [event.payload.from_state, event.payload.to_state]);
    assert.deepEqual(orderedTransitions, [
      ["SETUP", "OPEN_FRONTIER"],
      ["OPEN_FRONTIER", "CLAIM_FREEZE"],
      ["CLAIM_FREEZE", "OPEN_FRONTIER"],
      ["OPEN_FRONTIER", "CLAIM_FREEZE"],
      ["CLAIM_FREEZE", "VERIFY"],
      ["VERIFY", "GRADE"],
      ["GRADE", "REPORT"],
      ["REPORT", "OPEN_FRONTIER"],
    ]);
    assert.ok(fs.existsSync(sessionEventsJsonlPath(domain)));
  });
});
