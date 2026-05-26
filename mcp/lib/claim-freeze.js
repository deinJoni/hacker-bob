"use strict";

const fs = require("fs");
const {
  assertSafeDomain,
  claimFreezePath,
} = require("./paths.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  hashDocumentExcluding,
  normalizeIsoTimestamp,
  normalizeOptionalId,
  writeJsonDocument,
} = require("./fabric-common.js");
const {
  readCandidateClaims,
} = require("./claims.js");
const {
  readClaimClusters,
} = require("./claim-clusters.js");
const {
  readFrontierEvents,
} = require("./frontier-events.js");
const {
  readJsonFile,
  withSessionLock,
} = require("./storage.js");

const CLAIM_FREEZE_VERSION = 1;

function generatedClaimFreezeId(fields) {
  return `CF-${hashCanonicalJson(fields).slice(0, 24)}`;
}

function buildClaimFreezeDocument(domain, { write = false, now = new Date(), freezeId = null } = {}) {
  const frozenAt = normalizeIsoTimestamp(now, "frozen_at", null);
  const claims = readCandidateClaims(domain).slice().sort((a, b) => a.claim_id.localeCompare(b.claim_id));
  const clusters = readClaimClusters(domain).slice().sort((a, b) => a.cluster_id.localeCompare(b.cluster_id));
  const frontierEvents = readFrontierEvents(domain);
  const sourceHashes = {
    claims_hash: hashCanonicalJson(claims),
    claim_clusters_hash: hashCanonicalJson(clusters),
    frontier_events_hash: hashCanonicalJson(frontierEvents.map((event) => event.event_hash)),
  };
  const base = {
    version: CLAIM_FREEZE_VERSION,
    target_domain: domain,
    frozen_at: frozenAt,
    claim_count: claims.length,
    cluster_count: clusters.length,
    source_event_count: frontierEvents.length,
    source_hashes: sourceHashes,
    claims,
    clusters,
  };
  const normalizedFreezeId = normalizeOptionalId(freezeId, "freeze_id")
    || generatedClaimFreezeId({
      target_domain: domain,
      source_hashes: sourceHashes,
    });
  const freeze = {
    freeze_id: normalizedFreezeId,
    ...base,
  };
  freeze.freeze_hash = hashDocumentExcluding(freeze, ["frozen_at", "freeze_hash"]);

  if (write) {
    writeJsonDocument(claimFreezePath(domain), freeze);
  }
  return freeze;
}

function buildClaimFreeze(targetDomain, options = {}) {
  const domain = assertSafeDomain(targetDomain);
  if (options.write) {
    return withSessionLock(domain, () => buildClaimFreezeDocument(domain, options));
  }
  return buildClaimFreezeDocument(domain, options);
}

function verificationSnapshotFromClaimFreeze(input, { now = new Date() } = {}) {
  const freeze = input && input.freeze ? input.freeze : input;
  if (freeze == null || typeof freeze !== "object" || Array.isArray(freeze)) {
    throw new Error("claim freeze must be an object");
  }
  const createdAt = normalizeIsoTimestamp(now, "created_at", null);
  const snapshot = {
    version: 1,
    target_domain: assertSafeDomain(freeze.target_domain),
    created_at: createdAt,
    freeze_id: normalizeOptionalId(freeze.freeze_id, "freeze_id"),
    claim_freeze_hash: normalizeOptionalId(freeze.freeze_hash, "freeze_hash"),
    claim_count: Array.isArray(freeze.claims) ? freeze.claims.length : 0,
    cluster_count: Array.isArray(freeze.clusters) ? freeze.clusters.length : 0,
    claims: Array.isArray(freeze.claims) ? freeze.claims : [],
    clusters: Array.isArray(freeze.clusters) ? freeze.clusters : [],
  };
  snapshot.verification_snapshot_hash = hashDocumentExcluding(snapshot, [
    "created_at",
    "verification_snapshot_hash",
  ]);
  return snapshot;
}

function readCurrentClaimFreeze(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  const filePath = claimFreezePath(domain);
  if (!fs.existsSync(filePath)) return null;
  return readJsonFile(filePath, { label: "claim-freeze.json" });
}

module.exports = {
  CLAIM_FREEZE_VERSION,
  buildClaimFreeze,
  generatedClaimFreezeId,
  readCurrentClaimFreeze,
  verificationSnapshotFromClaimFreeze,
};
