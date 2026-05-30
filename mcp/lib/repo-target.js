"use strict";

// Cycle O.1 of Plane O: repo-bound target axis. This module owns the
// SessionNucleus and state.json initialization path for OSS sessions.
// A repo session derives its `target_domain` from the absolute repo
// path so reopening the same checkout from any working directory
// always lands on the same session.
//
// Plane O invariant O-P1 (local-repo first) is enforced via
// governance-contracts.assertRepoRootPath: the path must exist as a
// local directory before binding. No clone-from-remote happens here.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const {
  assertBoolean,
  assertNonEmptyString,
  normalizeOptionalText,
} = require("./validation.js");
const {
  assertSafeDomain,
  sessionDir,
  sessionNucleusPath,
  statePath,
} = require("./paths.js");
const {
  buildSessionNucleus,
  normalizeTargetRepo,
} = require("./governance-contracts.js");
const {
  resolveEgressProfile,
} = require("./egress-profiles.js");
const {
  buildInitialSessionState,
  egressProfileStateFields,
  deriveBlockInternalHostsPolicy,
} = require("./session-state-contracts.js");
const {
  isSessionDirEffectivelyEmpty,
  withSessionLock,
} = require("./storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  writeJsonDocument,
} = require("./fabric-common.js");
const {
  writeSessionStateDocument,
} = require("./session-state-store.js");
const {
  readSessionNucleus,
} = require("./governance-store.js");
const {
  appendSessionEvent,
} = require("./session-events.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  safeAppendPipelineEventDirect,
} = require("./pipeline-events.js");
const {
  buildGovernanceContextFromNucleus,
} = require("./governance-context.js");

// Cycle O.1: SAFE_NAME_PATTERN keeps the basename safe for the
// target_domain slug. Any character outside `[A-Za-z0-9._-]` is folded
// to a single dash; leading/trailing dashes are trimmed. Empty
// basenames (e.g. trailing slash on root) fall back to "repo".
function safeBasename(value) {
  const base = path.basename(value || "").trim();
  if (!base) return "repo";
  const folded = base.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return folded || "repo";
}

function sha8(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex").slice(0, 8);
}

function sha64(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function deriveRepoTargetDomain(realpathValue) {
  const name = safeBasename(realpathValue);
  return `repo-${name}-${sha8(realpathValue)}`;
}

function deriveRepoHashFromPath(realpathValue) {
  // Stable 64-hex digest of the canonical path. Trimmed to 64 chars so
  // it shares the validation envelope with explicit git commit hashes
  // (which can be 40 hex chars).
  return sha64(realpathValue);
}

// Translate a friendly error code from assertRepoRootPath into a
// structured ToolError so callers (bob_init_repo_session) surface the
// repo_path_not_found / repo_path_not_directory contract explicitly.
function repoPathError(error) {
  if (error && error.code === "repo_path_not_found") {
    return new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || "repo path not found", {
      repo_error_code: "repo_path_not_found",
    });
  }
  if (error && error.code === "repo_path_not_directory") {
    return new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || "repo path is not a directory", {
      repo_error_code: "repo_path_not_directory",
    });
  }
  return null;
}

function initRepoSession({
  repo_path: repoPath,
  target_domain: requestedTargetDomain = null,
  source_url: sourceUrl = null,
  branch = null,
  commit = null,
  deep_mode: deepMode = false,
  egress_profile: requestedEgressProfile = null,
} = {}) {
  let targetRepo;
  try {
    targetRepo = normalizeTargetRepo({
      root_path: repoPath,
      source_url: sourceUrl,
      branch,
      commit,
    }, "target_repo");
  } catch (error) {
    const mapped = repoPathError(error);
    if (mapped) throw mapped;
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || String(error));
  }

  const canonicalRoot = targetRepo.root_path;
  const derivedDomain = deriveRepoTargetDomain(canonicalRoot);

  let domain;
  if (requestedTargetDomain != null) {
    const trimmed = assertNonEmptyString(requestedTargetDomain, "target_domain");
    assertSafeDomain(trimmed);
    if (trimmed !== derivedDomain) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `target_domain does not match derived repo slug; got ${trimmed}, expected ${derivedDomain}`,
        { expected_target_domain: derivedDomain, provided_target_domain: trimmed },
      );
    }
    domain = trimmed;
  } else {
    domain = derivedDomain;
  }

  const repoHash = (targetRepo.commit && /^[0-9a-f]{8,64}$/i.test(targetRepo.commit))
    ? targetRepo.commit.toLowerCase()
    : deriveRepoHashFromPath(canonicalRoot);

  const normalizedDeepMode = deepMode == null ? false : assertBoolean(deepMode, "deep_mode");
  const profileName = requestedEgressProfile == null
    ? "default"
    : assertNonEmptyString(requestedEgressProfile, "egress_profile");

  return withSessionLock(domain, () => {
    const dir = sessionDir(domain);
    const filePath = statePath(domain);

    if (fs.existsSync(filePath)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session already initialized: ${filePath}`);
    }
    if (!isSessionDirEffectivelyEmpty(dir)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session directory is not empty: ${dir}`);
    }

    const egressProfile = resolveEgressProfile(profileName);
    const egressFields = egressProfileStateFields(egressProfile);
    const internalHostPolicy = deriveBlockInternalHostsPolicy({
      checkpointMode: "normal",
      legacyDefault: false,
    });

    const sessionNucleus = buildSessionNucleus({
      target_domain: domain,
      target_repo: targetRepo,
      repo_hash: repoHash,
      scope_policy: {
        target_domain: domain,
        target_repo: targetRepo,
        ...internalHostPolicy,
      },
      egress_identity: egressFields,
      auth_context: {
        auth_status: "pending",
      },
      operator_constraint: {
        handoff_provenance_required: true,
      },
    });
    writeJsonDocument(sessionNucleusPath(domain), sessionNucleus);
    appendSessionEvent({
      target_domain: domain,
      kind: "governance.session.initialized",
      nucleus_hash: sessionNucleus.nucleus_hash,
      payload: {
        nucleus_hash: sessionNucleus.nucleus_hash,
        scope_policy_hash: hashCanonicalJson(sessionNucleus.scope_policy),
        egress_identity_hash: hashCanonicalJson(sessionNucleus.egress_identity),
        auth_context_hash: hashCanonicalJson(sessionNucleus.auth_context),
        operator_constraint_hash: hashCanonicalJson(sessionNucleus.operator_constraint),
        repo_hash: sessionNucleus.repo_hash,
      },
    });

    const state = buildInitialSessionState(domain, null, {
      deepMode: normalizedDeepMode,
      egressProfile,
      blockInternalHostsPolicy: sessionNucleus.scope_policy,
      targetRepo,
      repoHash,
    });
    writeSessionStateDocument(domain, {}, state);
    safeAppendPipelineEventDirect(domain, "session_started", {
      lifecycle_state: state.lifecycle_state,
      source: "bob_init_repo_session",
      deep_mode: state.deep_mode,
      checkpoint_mode: state.checkpoint_mode,
      block_internal_hosts: state.block_internal_hosts,
      block_internal_hosts_source: state.block_internal_hosts_source,
      repo_hash: repoHash,
      ...egressFields,
    }, buildGovernanceContextFromNucleus(sessionNucleus));

    return {
      created: true,
      session_dir: dir,
      target_domain: domain,
      target_repo: targetRepo,
      repo_hash: repoHash,
      nucleus_hash: sessionNucleus.nucleus_hash,
      lifecycle_state: state.lifecycle_state,
      deep_mode: state.deep_mode,
      egress_profile: state.egress_profile,
    };
  });
}

function readRepoSession(targetDomain) {
  const domain = assertNonEmptyString(targetDomain, "target_domain");
  const nucleus = readSessionNucleus(domain);
  if (!nucleus || nucleus.scope_policy == null || nucleus.scope_policy.target_repo == null) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `target_domain ${domain} is not a repo session`,
    );
  }
  return {
    target_domain: nucleus.target_domain,
    target_repo: nucleus.scope_policy.target_repo,
    repo_hash: nucleus.repo_hash || null,
    nucleus_hash: nucleus.nucleus_hash,
    lifecycle_state: nucleus.lifecycle_state,
  };
}

module.exports = {
  deriveRepoTargetDomain,
  deriveRepoHashFromPath,
  initRepoSession,
  readRepoSession,
  // Exposed for cross-module reuse / tests.
  safeBasename,
  sha8,
};

// Quieter shadow imports kept for parity with other session-init paths.
// eslint-disable-next-line no-unused-vars
const _unusedNormalizeOptionalText = normalizeOptionalText;
