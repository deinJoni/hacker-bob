"use strict";

const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  listAuthProfiles,
} = require("./auth.js");
const {
  readChainAttemptsFromJsonl,
} = require("./chain-attempts.js");
const {
  readFindingsFromJsonl,
} = require("./finding-store.js");
const {
  verificationSnapshotPath,
} = require("./paths.js");
const {
  loadJsonDocumentStrict,
} = require("./storage.js");
const {
  canonicalJson,
  cloneJson,
  hashCanonicalJson,
  isPlainObject,
} = require("./verification-contracts.js");
const {
  readSurfaceRoutesStrict,
} = require("./surface-router.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");

const VERIFICATION_SCHEMA_V2 = 2;
const VERIFICATION_INPUT_CHANGED_MESSAGE = "VERIFY input changed after snapshot; restart VERIFY/adjudication.";

function parseListAuthProfiles(domain) {
  try {
    const parsed = JSON.parse(listAuthProfiles({ target_domain: domain }));
    return Array.isArray(parsed.profiles) ? parsed.profiles : [];
  } catch (error) {
    return [{ error: error.message || String(error) }];
  }
}

function normalizeAuthProfileSnapshot(profile) {
  const normalized = cloneJson(profile);
  if (normalized && typeof normalized.expiry === "object" && !Array.isArray(normalized.expiry)) {
    // These booleans depend on Date.now(), so including them would make an
    // otherwise unchanged VERIFY snapshot turn stale just because time passed.
    delete normalized.expiry.is_expired;
    delete normalized.expiry.is_stale;
  }
  return normalized;
}

function readAuthProfileSnapshot(domain) {
  return parseListAuthProfiles(domain)
    .map((profile) => normalizeAuthProfileSnapshot(profile))
    .sort((a, b) => String(a.profile_name || "").localeCompare(String(b.profile_name || "")));
}

function readSurfaceRoutesSnapshot(domain) {
  try {
    return readSurfaceRoutesStrict(domain).document;
  } catch (error) {
    return { error: error.message || String(error) };
  }
}

function buildSnapshotPayload(domain, { attemptId, createdAt }) {
  const findings = readFindingsFromJsonl(domain).slice()
    .sort((a, b) => a.id.localeCompare(b.id));
  const chainAttempts = readChainAttemptsFromJsonl(domain).slice()
    .sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b)));
  const authProfiles = readAuthProfileSnapshot(domain);
  const surfaceRoutes = readSurfaceRoutesSnapshot(domain);
  const findingIds = findings.map((finding) => finding.id);
  return {
    version: 1,
    schema_version: VERIFICATION_SCHEMA_V2,
    target_domain: domain,
    verification_attempt_id: attemptId,
    created_at: createdAt,
    finding_ids: findingIds,
    input_hashes: {
      findings: hashCanonicalJson(findings),
      chain_attempts: hashCanonicalJson(chainAttempts),
      auth_profile_summaries: hashCanonicalJson(authProfiles),
      surface_routes: hashCanonicalJson(surfaceRoutes),
    },
  };
}

function buildVerificationSnapshot(domain, { attemptId, createdAt }) {
  const payload = buildSnapshotPayload(domain, { attemptId, createdAt });
  return {
    ...payload,
    snapshot_hash: hashCanonicalJson(payload),
  };
}

function recomputeSnapshotHash(domain, snapshot) {
  const payload = buildSnapshotPayload(domain, {
    attemptId: snapshot.verification_attempt_id,
    createdAt: snapshot.created_at,
  });
  return hashCanonicalJson(payload);
}

function snapshotPayloadHash(snapshot) {
  const payload = { ...snapshot };
  delete payload.snapshot_hash;
  return hashCanonicalJson(payload);
}

function assertValidSnapshotArtifact(domain, snapshot) {
  if (!isPlainObject(snapshot)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "Current VERIFY v2 snapshot artifact is invalid; restart VERIFY/adjudication.");
  }
  if (snapshot.version !== 1 || snapshot.schema_version !== VERIFICATION_SCHEMA_V2) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "Current VERIFY v2 snapshot artifact schema mismatch; restart VERIFY/adjudication.");
  }
  if (snapshot.target_domain !== domain) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "Current VERIFY v2 snapshot target mismatch; restart VERIFY/adjudication.");
  }
  if (!snapshot.snapshot_hash || snapshotPayloadHash(snapshot) !== snapshot.snapshot_hash) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "Current VERIFY v2 snapshot artifact hash mismatch; restart VERIFY/adjudication.");
  }
}

function loadCurrentSnapshot(domain, state) {
  const snapshot = loadJsonDocumentStrict(verificationSnapshotPath(domain), "verification input snapshot JSON");
  assertValidSnapshotArtifact(domain, snapshot);
  if (snapshot.verification_attempt_id !== state.verification_attempt_id) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "Current VERIFY v2 snapshot attempt mismatch; restart VERIFY/adjudication.");
  }
  if (snapshot.snapshot_hash !== state.verification_snapshot_hash) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "Current VERIFY v2 snapshot hash mismatch; restart VERIFY/adjudication.");
  }
  return snapshot;
}

function assertFreshVerificationSnapshot(domain, state) {
  if (!state || state.verification_schema_version !== VERIFICATION_SCHEMA_V2) return null;
  const snapshot = loadCurrentSnapshot(domain, state);
  const currentHash = recomputeSnapshotHash(domain, snapshot);
  if (currentHash !== state.verification_snapshot_hash) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, VERIFICATION_INPUT_CHANGED_MESSAGE);
  }
  return snapshot;
}

function readVerificationStateSafe(domain) {
  try {
    return readSessionStateStrict(domain).state;
  } catch {
    return null;
  }
}

function requireFreshVerificationState(domain) {
  const state = readVerificationStateSafe(domain);
  if (!state || state.verification_schema_version !== VERIFICATION_SCHEMA_V2) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "VERIFY v2 attempt is not active for this session.");
  }
  if (!state.verification_attempt_id || !state.verification_snapshot_hash) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "VERIFY v2 attempt metadata is missing; transition into VERIFY again.");
  }
  const snapshot = assertFreshVerificationSnapshot(domain, state);
  return { state, snapshot };
}

module.exports = {
  VERIFICATION_INPUT_CHANGED_MESSAGE,
  VERIFICATION_SCHEMA_V2,
  assertFreshVerificationSnapshot,
  buildVerificationSnapshot,
  recomputeSnapshotHash,
  requireFreshVerificationState,
};
