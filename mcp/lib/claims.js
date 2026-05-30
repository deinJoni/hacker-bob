"use strict";

const {
  assertEnumValue,
  normalizeOptionalText,
} = require("./validation.js");
const {
  assertSafeDomain,
  claimsJsonlPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("./storage.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  normalizeId,
  normalizeIsoTimestamp,
  normalizeOptionalId,
  normalizeOptionalObject,
  normalizeOptionalTextArray,
  normalizeReferenceArray,
  readJsonlStrict,
  withDocumentHash,
} = require("./fabric-common.js");
const {
  normalizeTaskLens,
} = require("./task-lenses.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  readFrontierEvents,
} = require("./frontier-events.js");

const CLAIM_VERSION = 1;
const CLAIMS_MAX_RECORDS = 20000;
const CLAIM_STATUSES = Object.freeze(["candidate", "clustered", "frozen", "verified", "dismissed", "reported"]);
const CLAIM_SEVERITIES = Object.freeze(["critical", "high", "medium", "low", "informational"]);

// EvidenceReference schema (Cycle C.5).
//
// CandidateClaim carries a first-class evidence_refs[] payload. Each reference
// names an external artifact whose canonical-hash content is the durable
// evidence; once the claim batch is frozen, downstream stages (verification,
// evidence pack, grade, report snapshot) read evidence from these references
// rather than re-scanning live disk artifacts.
//
// Canonical shape:
//   {
//     kind: "<one of EVIDENCE_REFERENCE_KIND_VALUES>",
//     artifact_path?: relative or absolute path under the session dir,
//     content_hash?: sha256 hex of the canonical payload of the referenced
//                    artifact,
//     source_run_id?: AgentRun id that produced the evidence,
//     ref?: optional line/anchor pointer into the artifact,
//     ...kind-specific fields (finding_id, chain_attempt_id, ...)
//   }
const EVIDENCE_REFERENCE_KIND_VALUES = Object.freeze([
  "finding",
  "verification_round",
  "chain_attempt",
  "http_audit",
  "smart_contract_evidence",
  "agent_run",
]);

function isHex64(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function normalizeEvidenceReferenceShape(ref, fieldName = "evidence_refs[]") {
  if (ref == null || typeof ref !== "object" || Array.isArray(ref)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const kind = ref.kind;
  if (typeof kind !== "string" || !kind.trim()) {
    throw new Error(`${fieldName}.kind must be a non-empty string`);
  }
  const artifactPath = ref.artifact_path;
  if (artifactPath != null && (typeof artifactPath !== "string" || !artifactPath.trim())) {
    throw new Error(`${fieldName}.artifact_path must be a non-empty string when present`);
  }
  const contentHash = ref.content_hash;
  if (contentHash != null && !isHex64(contentHash)) {
    throw new Error(`${fieldName}.content_hash must be a 64-hex content digest when present`);
  }
  const sourceRunId = ref.source_run_id;
  if (sourceRunId != null && (typeof sourceRunId !== "string" || !sourceRunId.trim())) {
    throw new Error(`${fieldName}.source_run_id must be a non-empty string when present`);
  }
  return ref;
}

function evidenceReferenceLookupKey(ref) {
  // Stable identity for completeness comparison. Two refs are "the same"
  // reference when their kind + the natural identifier for that kind match.
  // Falls back to a tuple of (kind, artifact_path, content_hash) when no
  // kind-specific id is available so two arbitrary refs over the same artifact
  // compare equal.
  if (!ref || typeof ref !== "object") return null;
  const kind = typeof ref.kind === "string" ? ref.kind : "";
  if (kind === "finding" && typeof ref.finding_id === "string") {
    return `${kind}:${ref.finding_id}`;
  }
  if (kind === "verification_round") {
    const round = typeof ref.verification_round === "string"
      ? ref.verification_round
      : (typeof ref.round === "string" ? ref.round : "");
    if (round) return `${kind}:${round}`;
  }
  if (kind === "chain_attempt" && typeof ref.chain_attempt_id === "string") {
    return `${kind}:${ref.chain_attempt_id}`;
  }
  if (kind === "http_audit") {
    if (typeof ref.http_audit_id === "string") return `${kind}:${ref.http_audit_id}`;
    if (typeof ref.request_id === "string") return `${kind}:${ref.request_id}`;
  }
  if (kind === "smart_contract_evidence" && typeof ref.contract_address === "string") {
    const chain = typeof ref.chain_id === "string" || typeof ref.chain_id === "number"
      ? `:${ref.chain_id}`
      : "";
    return `${kind}:${ref.contract_address}${chain}`;
  }
  if (kind === "agent_run" && typeof ref.agent_run_id === "string") {
    return `${kind}:${ref.agent_run_id}`;
  }
  return `${kind}:${ref.artifact_path || ""}:${ref.content_hash || ""}`;
}

function normalizeConfidence(value) {
  if (value == null) return null;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error("confidence must be a number from 0 to 1");
  }
  return Number(value.toFixed(4));
}

function generatedClaimId(fields) {
  return `CL-${hashCanonicalJson(fields).slice(0, 24)}`;
}

function normalizeLensArray(value) {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error("lenses must be an array");
  }
  return Array.from(new Set(value.map((lens, index) => normalizeTaskLens(lens, `lenses[${index}]`))));
}

function normalizeCandidateClaim(input, { targetDomain = null, now = new Date() } = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("claim must be an object");
  }
  const domain = assertSafeDomain(input.target_domain || targetDomain);
  const title = normalizeId(input.title, "title", { maxLength: 240 });
  const summary = normalizeId(input.summary, "summary", { maxLength: 2000 });
  const createdAt = normalizeIsoTimestamp(input.created_at || input.ts, "created_at", now);
  const status = assertEnumValue(input.status || "candidate", CLAIM_STATUSES, "status");
  const severity = assertEnumValue(input.severity || "medium", CLAIM_SEVERITIES, "severity");
  const surfaceIds = normalizeOptionalTextArray(input.surface_ids, "surface_ids");
  const lenses = normalizeLensArray(input.lenses);
  // C.5: evidence_refs[] are first-class EvidenceReference entries. Each must
  // carry a kind; artifact_path and content_hash are validated when present so
  // a CandidateClaim whose refs cannot be content-hash-matched at GRADE time
  // is rejected up front.
  const evidenceRefs = normalizeReferenceArray(input.evidence_refs, "evidence_refs")
    .map((ref, index) => normalizeEvidenceReferenceShape(ref, `evidence_refs[${index}]`));
  const controlExpectation = normalizeOptionalObject(input.control_expectation, "control_expectation");
  const impact = normalizeOptionalText(input.impact, "impact");
  const confidence = normalizeConfidence(input.confidence);
  const sourceTaskIds = normalizeOptionalTextArray(input.source_task_ids, "source_task_ids");
  const agentRunIds = normalizeOptionalTextArray(input.agent_run_ids, "agent_run_ids");
  const tags = normalizeOptionalTextArray(input.tags, "tags");
  const payload = normalizeOptionalObject(input.payload, "payload");

  const base = {
    version: CLAIM_VERSION,
    target_domain: domain,
    title,
    summary,
    severity,
    status,
    created_at: createdAt,
  };
  if (surfaceIds.length > 0) base.surface_ids = surfaceIds;
  if (lenses.length > 0) base.lenses = lenses;
  if (evidenceRefs.length > 0) base.evidence_refs = evidenceRefs;
  if (controlExpectation) base.control_expectation = controlExpectation;
  if (impact) base.impact = impact;
  if (confidence != null) base.confidence = confidence;
  if (sourceTaskIds.length > 0) base.source_task_ids = sourceTaskIds;
  if (agentRunIds.length > 0) base.agent_run_ids = agentRunIds;
  if (tags.length > 0) base.tags = tags;
  if (payload) base.payload = payload;

  const claimId = normalizeOptionalId(input.claim_id, "claim_id") || generatedClaimId(base);
  return withDocumentHash({
    claim_id: claimId,
    ...base,
  }, "claim_hash");
}

// Plane O O-P4 enforcement (cycle O.7). When a CandidateClaim is high/critical
// AND its implicated code surface(s) are native (C/C++/Rust-unsafe/asm) AND
// no evidence_ref carries `kind: "repo_command_run"`, the claim is a
// static-only native-code finding — which the realization pact forbids,
// because native-code corruption claims demand at least one live execution
// (sanitizer/fuzzer/debugger) to be credible. The validator reads frontier
// events to resolve each surface_id's kind (`code_module`) and language.
// Non-repo sessions and surfaces whose code_module language isn't native short-
// circuit; the rule only fires when all three conditions align.
const O_P4_NATIVE_LANGUAGES = Object.freeze(new Set(["c", "cpp", "rust-unsafe", "asm"]));
const O_P4_TRIGGERING_SEVERITIES = Object.freeze(new Set(["high", "critical"]));

function claimSurfaceLanguageMap(domain, surfaceIds) {
  // Returns surfaceId -> { kind, language } for surfaces that appear as
  // `surface.observed` events. Missing or unreadable frontier ledger collapses
  // to an empty map (non-repo sessions don't have a repo inventory to read).
  const result = new Map();
  if (!Array.isArray(surfaceIds) || surfaceIds.length === 0) return result;
  let events;
  try {
    events = readFrontierEvents(domain);
  } catch {
    return result;
  }
  const wanted = new Set(surfaceIds);
  for (const event of events) {
    if (!event || event.kind !== "surface.observed") continue;
    if (typeof event.surface_id !== "string" || !wanted.has(event.surface_id)) continue;
    const payload = event.payload && typeof event.payload === "object" && !Array.isArray(event.payload)
      ? event.payload
      : {};
    const surfaceKind = typeof payload.kind === "string" ? payload.kind.trim() : "";
    const language = typeof payload.language === "string" ? payload.language.trim().toLowerCase() : "";
    if (!surfaceKind && !language) continue;
    const existing = result.get(event.surface_id) || {};
    // Later observations win — the materializer treats surface.observed as
    // last-writer-wins for scalar fields.
    result.set(event.surface_id, {
      kind: surfaceKind || existing.kind || null,
      language: language || existing.language || null,
    });
  }
  return result;
}

function assertNotStaticOnlyNativeHighSeverity(claim) {
  if (!O_P4_TRIGGERING_SEVERITIES.has(claim.severity)) return;
  const surfaceIds = Array.isArray(claim.surface_ids) ? claim.surface_ids : [];
  if (surfaceIds.length === 0) return;
  const surfaceInfo = claimSurfaceLanguageMap(claim.target_domain, surfaceIds);
  const nativeSurfaces = [];
  for (const surfaceId of surfaceIds) {
    const info = surfaceInfo.get(surfaceId);
    if (!info) continue;
    if (info.kind !== "code_module") continue;
    if (!info.language || !O_P4_NATIVE_LANGUAGES.has(info.language)) continue;
    nativeSurfaces.push({ surface_id: surfaceId, language: info.language });
  }
  if (nativeSurfaces.length === 0) return;
  const evidenceRefs = Array.isArray(claim.evidence_refs) ? claim.evidence_refs : [];
  const hasRepoCommandRun = evidenceRefs.some((ref) => ref && ref.kind === "repo_command_run");
  if (hasRepoCommandRun) return;
  throw new ToolError(
    ERROR_CODES.INVALID_ARGUMENTS,
    "high/critical native-code claims must include at least one evidence_refs[] entry with kind: \"repo_command_run\"; static-only claims (repo_file / source review) cannot stand alone for C/C++/Rust-unsafe/asm at this severity.",
    {
      code: "O_P4_static_only_native_code_high_severity",
      severity: claim.severity,
      native_surfaces: nativeSurfaces,
    },
  );
}

function appendCandidateClaim(input, options = {}) {
  const claim = normalizeCandidateClaim(input, options);
  // O-P4 validator runs before the JSONL append so a rejected claim leaves
  // claims.jsonl untouched. Wave-handoff / blocked-harness consistency is the
  // sibling gate on the handoff path; the claim path owns the native-code
  // severity gate.
  assertNotStaticOnlyNativeHighSeverity(claim);
  return withSessionLock(claim.target_domain, () => {
    appendJsonlLine(claimsJsonlPath(claim.target_domain), claim, {
      maxRecords: options.maxRecords == null ? CLAIMS_MAX_RECORDS : options.maxRecords,
    });
    return claim;
  });
}

function readCandidateClaims(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  return readJsonlStrict(
    claimsJsonlPath(domain),
    "claims.jsonl",
    (record) => normalizeCandidateClaim(record, { targetDomain: domain, now: null }),
  );
}

module.exports = {
  CLAIMS_MAX_RECORDS,
  CLAIM_SEVERITIES,
  CLAIM_STATUSES,
  CLAIM_VERSION,
  EVIDENCE_REFERENCE_KIND_VALUES,
  O_P4_NATIVE_LANGUAGES,
  O_P4_TRIGGERING_SEVERITIES,
  appendCandidateClaim,
  assertNotStaticOnlyNativeHighSeverity,
  claimSurfaceLanguageMap,
  evidenceReferenceLookupKey,
  generatedClaimId,
  normalizeCandidateClaim,
  normalizeEvidenceReferenceShape,
  readCandidateClaims,
};
