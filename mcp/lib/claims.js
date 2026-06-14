"use strict";

const fs = require("fs");
const {
  assertEnumValue,
  normalizeOptionalText,
} = require("./validation.js");
const {
  assertSafeDomain,
  claimsJsonlPath,
  offensiveRunsJsonlPath,
  repoCommandRunsJsonlPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  withSessionLock,
  DEFAULT_ARTIFACT_READ_MAX_BYTES,
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
  OFFENSIVE_OUTCOME_VALUES,
  SAFE_ORACLE_KINDS,
} = require("./constants.js");
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
// Plane O Cycle O.8: code-bound EvidenceReference shapes.
//
//   repo_file        : Carries the file_path, the sha256 of the file's full
//                      bytes (`content_hash`), and an optional `line_range`
//                      pointer into the file. When the EvidenceReference
//                      excerpts a specific region, `snippet_hash` is the
//                      sha256 of that excerpted region's bytes. The raw
//                      snippet stays in `repo-checks.jsonl` (which is
//                      read-guard-protected and redacted per O.5/O-P7);
//                      the EvidenceReference itself never carries excerpted
//                      content.
//
//   repo_command_run : Carries the `run_id` of the bob_repo_docker_run row,
//                      the sha256 of the command tokens (`command_hash`),
//                      the integer exit code, and the sha256 of the
//                      captured stdout/stderr files
//                      (`stdout_hash`/`stderr_hash`). The raw stdout/stderr
//                      live on disk under `repo-runs/<run_id>.{stdout,stderr}`
//                      and are read-guard-protected per O.7.
//
//   exploit_run      : Carries the `run_id` of an offensive-runs.jsonl row
//                      produced by the offensive runner, binding tool id,
//                      target URL, safe offensive outcome, command hash,
//                      exit code, and stdout/stderr capture hashes.
//                      DEFERRED (PR #108 review, Codex P2): once a frozen
//                      claim carries an exploit_run ref, the C.5
//                      freeze-completeness gate
//                      (claim-freeze.js::assertCompletenessAgainstFreeze)
//                      will mark it `missing` unless an observed projection is
//                      supplied — there is no projectOffensiveRunObservedRef
//                      yet. This is unreachable today (no tool surface emits
//                      exploit_outcome), so the projection lands with the
//                      offensive runner / tool-surface PR that defines where
//                      raw exploit output is captured. Until then the
//                      evidence-agent must supply the exploit_run observed ref
//                      explicitly, or freeze-completeness will block GRADE.
const EVIDENCE_REFERENCE_KIND_VALUES = Object.freeze([
  "finding",
  "verification_round",
  "chain_attempt",
  "http_audit",
  "smart_contract_evidence",
  "agent_run",
  "repo_file",
  "repo_command_run",
  "exploit_run",
]);

function isHex64(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function assertRepoFileEvidenceShape(ref, fieldName) {
  // O.8 payload contract — repo_file:
  //   {kind, file_path, content_hash, line_range?, snippet_hash?, source_run_id?}
  // file_path + content_hash are the natural identity; snippet_hash is the
  // sha256 of an excerpted region (raw excerpt itself stays in
  // repo-checks.jsonl). line_range, when present, is {start_line, end_line}
  // with 1-based line numbers in non-decreasing order.
  if (typeof ref.file_path !== "string" || !ref.file_path.trim()) {
    throw new Error(`${fieldName}.file_path must be a non-empty string for kind="repo_file"`);
  }
  if (!isHex64(ref.content_hash)) {
    throw new Error(`${fieldName}.content_hash must be a 64-hex content digest for kind="repo_file"`);
  }
  if (ref.snippet_hash != null && !isHex64(ref.snippet_hash)) {
    throw new Error(`${fieldName}.snippet_hash must be a 64-hex content digest when present`);
  }
  if (ref.line_range != null) {
    const range = ref.line_range;
    if (typeof range !== "object" || Array.isArray(range)) {
      throw new Error(`${fieldName}.line_range must be an object {start_line, end_line} when present`);
    }
    if (!Number.isInteger(range.start_line) || range.start_line < 1) {
      throw new Error(`${fieldName}.line_range.start_line must be a positive integer`);
    }
    if (!Number.isInteger(range.end_line) || range.end_line < range.start_line) {
      throw new Error(`${fieldName}.line_range.end_line must be an integer >= start_line`);
    }
  }
}

function assertRepoCommandRunEvidenceShape(ref, fieldName) {
  // O.8 payload contract — repo_command_run:
  //   {kind, run_id, command_hash, exit_code, stdout_hash, stderr_hash, source_run_id?}
  // run_id is the natural identity (deterministic per repoDockerRun row);
  // command_hash is the sha256 of the canonicalized command tokens;
  // exit_code is the integer reported by the runtime (null is allowed for
  // pre-completion captures, but at append time we require a concrete int
  // or null); stdout_hash/stderr_hash are the sha256 of the capture files.
  if (typeof ref.run_id !== "string" || !ref.run_id.trim()) {
    throw new Error(`${fieldName}.run_id must be a non-empty string for kind="repo_command_run"`);
  }
  if (!isHex64(ref.command_hash)) {
    throw new Error(`${fieldName}.command_hash must be a 64-hex content digest for kind="repo_command_run"`);
  }
  if (!isHex64(ref.stdout_hash)) {
    throw new Error(`${fieldName}.stdout_hash must be a 64-hex content digest for kind="repo_command_run"`);
  }
  if (!isHex64(ref.stderr_hash)) {
    throw new Error(`${fieldName}.stderr_hash must be a 64-hex content digest for kind="repo_command_run"`);
  }
  if (ref.exit_code != null && !Number.isInteger(ref.exit_code)) {
    throw new Error(`${fieldName}.exit_code must be an integer or null for kind="repo_command_run"`);
  }
}

// Secret-shaped parameter names. PR #108 review (Codex P2 ×2): the hash-bound
// `target` is persisted verbatim into claims.jsonl, so a credential embedded in
// the URL would leak a live secret on every claim read. Full value-redaction is
// the offensive runner's job (it must redact the SAME canonical string it writes
// to both the offensive-runs.jsonl row and this ref so the two stay byte-identical
// for the proof binding); this validator is the fail-closed backstop that rejects
// a secret-bearing target — in the query, the fragment (OAuth implicit flow puts
// access_token in the #fragment), or the userinfo — before it is ever stored,
// forcing the runner to redact first.
const EXPLOIT_TARGET_SECRET_QUERY_RE = /^(?:access[_-]?token|id[_-]?token|refresh[_-]?token|token|session(?:[_-]?id)?|sid|auth(?:orization)?|api[_-]?key|apikey|secret|password|passwd|pwd|jwt|bearer|x[_-]?api[_-]?key|signature|sig)$/i;

function assertExploitTargetCarriesNoEmbeddedSecret(targetUrl, fieldName) {
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    // Opaque / relative targets carry no parseable URL secrets; the proof gate
    // additionally requires an in-scope absolute URL before a row can back them.
    return;
  }
  // Credentials embedded in userinfo (https://user:pass@host/...) are always
  // sensitive regardless of name.
  if (parsed.username || parsed.password) {
    throw new Error(
      `${fieldName}.target must not embed userinfo credentials for kind="exploit_run"; the offensive runner must redact them before recording`,
    );
  }
  // Secret-shaped params can appear in the query OR the #fragment (OAuth
  // implicit responses return access_token in the fragment).
  const paramKeys = [
    ...parsed.searchParams.keys(),
    ...new URLSearchParams(parsed.hash.replace(/^#/, "")).keys(),
  ];
  for (const key of paramKeys) {
    if (EXPLOIT_TARGET_SECRET_QUERY_RE.test(key)) {
      throw new Error(
        `${fieldName}.target must not carry a secret-shaped parameter ("${key}") in its query or fragment for kind="exploit_run"; the offensive runner must redact it before recording`,
      );
    }
  }
}

function assertExploitRunEvidenceShape(ref, fieldName) {
  // Offensive proof contract:
  //   {kind, run_id, tool_id, target, offensive_outcome, command_hash,
  //    exit_code, stdout_hash, stderr_hash, source_run_id?}
  // The row cross-check later proves this ref is backed by a real,
  // non-dry-run offensive-runs.jsonl row.
  if (typeof ref.run_id !== "string" || !ref.run_id.trim()) {
    throw new Error(`${fieldName}.run_id must be a non-empty string for kind="exploit_run"`);
  }
  if (typeof ref.tool_id !== "string" || !ref.tool_id.trim()) {
    throw new Error(`${fieldName}.tool_id must be a non-empty string for kind="exploit_run"`);
  }
  if (typeof ref.target !== "string" || !ref.target.trim()) {
    throw new Error(`${fieldName}.target must be a non-empty string for kind="exploit_run"`);
  }
  assertExploitTargetCarriesNoEmbeddedSecret(ref.target, fieldName);
  assertEnumValue(ref.offensive_outcome, OFFENSIVE_OUTCOME_VALUES, `${fieldName}.offensive_outcome`);
  if (!isHex64(ref.command_hash)) {
    throw new Error(`${fieldName}.command_hash must be a 64-hex content digest for kind="exploit_run"`);
  }
  if (!isHex64(ref.stdout_hash)) {
    throw new Error(`${fieldName}.stdout_hash must be a 64-hex content digest for kind="exploit_run"`);
  }
  if (!isHex64(ref.stderr_hash)) {
    throw new Error(`${fieldName}.stderr_hash must be a 64-hex content digest for kind="exploit_run"`);
  }
  if (ref.exit_code != null && !Number.isInteger(ref.exit_code)) {
    throw new Error(`${fieldName}.exit_code must be an integer or null for kind="exploit_run"`);
  }
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
  // O.8: kind-specific payload shapes for code-bound evidence. These run
  // after the common-field checks so the existing kinds keep their
  // permissive shape and only the two new kinds carry mandatory fields.
  if (kind === "repo_file") {
    assertRepoFileEvidenceShape(ref, fieldName);
  } else if (kind === "repo_command_run") {
    assertRepoCommandRunEvidenceShape(ref, fieldName);
  } else if (kind === "exploit_run") {
    assertExploitRunEvidenceShape(ref, fieldName);
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
  // O.8 code-bound kinds. repo_file's identity is the (file_path, content_hash)
  // pair so two refs against the same content at different excerpt windows
  // still collapse to one frozen-set entry; repo_command_run's identity is the
  // run_id, which is unique per repoDockerRun row.
  if (kind === "repo_file" && typeof ref.file_path === "string" && typeof ref.content_hash === "string") {
    return `repo_file:${ref.file_path}:${ref.content_hash}`;
  }
  if (kind === "repo_command_run" && typeof ref.run_id === "string") {
    return `repo_command_run:${ref.run_id}`;
  }
  if (kind === "exploit_run" && typeof ref.run_id === "string") {
    return `exploit_run:${ref.run_id}`;
  }
  return `${kind}:${ref.artifact_path || ""}:${ref.content_hash || ""}`;
}

// The deep value-paths a persisted secret_evidence_bypass row is allowed to
// re-honor. Mirrors record-candidate-claim.js secretEvidenceBypassValuePaths:
// the embedded finding lives at payload.finding.<field>; a description bypass
// also covers the top-level summary; an impact bypass also covers claim.impact.
// Any persisted `path` outside this whitelist (e.g. a hand-edited row pointing
// at an arbitrary node) is ignored, so a fabricated row can only suppress the
// value-scan on the same operator-approvable fields the writer could.
const SECRET_EVIDENCE_BYPASS_FIELDS = Object.freeze(new Set([
  "description",
  "proof_of_concept",
  "response_evidence",
  "impact",
]));

// The metadata key that carries the operator-approved secret-evidence bypass
// rows. Its segment `secret` trips the structural SENSITIVE_KEY_RE, but it is a
// fixed, code-emitted metadata key (not attacker/evaluator-controlled secret
// material), so it is lifted out of the payload before the sensitive-material
// scan and validated separately. The scan still fires on every OTHER key and
// value in the payload; only this one code-owned key is exempt, and the rows'
// rationale is length-capped (matching the write-side normalizer).
const SECRET_EVIDENCE_BYPASS_KEY = "secret_evidence_bypass";
const SECRET_EVIDENCE_BYPASS_MAX_ROWS = SECRET_EVIDENCE_BYPASS_FIELDS.size * 2;
const SECRET_EVIDENCE_BYPASS_RATIONALE_MAX = 512;

function isPlainObjectValue(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

// Honorable value-paths for a single bypass field. A row may only suppress the
// value-scan on a path this field is allowed to cover, so a hand-edited row
// pointing at an arbitrary node is ignored.
function allowedSecretEvidenceBypassPaths(field) {
  const paths = new Set([`payload.finding.${field}`]);
  if (field === "description") paths.add("summary");
  if (field === "impact") paths.add("impact");
  return paths;
}

// Normalize + bound-check the persisted secret_evidence_bypass rows. Only rows
// that name a known field, carry a non-empty length-capped rationale, and point
// at an allowed value-path for that field are kept. Returns null when none
// survive so the metadata key is simply dropped. The rationale is operator audit
// free-text that DESCRIBES the secret-shaped evidence (it routinely mentions
// "bearer"/"cookie"); like the write-side normalizeSecretDetectionBypass it is
// length-capped, NOT value-scanned, so read stays symmetric with write. The
// anti-smuggling property here is audit-visible, not prevented (per the RCA:
// claim_hash is recomputed-not-verified and a local-FS attacker already bypasses
// the scanner).
function normalizeSecretEvidenceBypassRows(rows) {
  if (!Array.isArray(rows) || rows.length === 0) return null;
  if (rows.length > SECRET_EVIDENCE_BYPASS_MAX_ROWS) {
    throw new Error(`payload.${SECRET_EVIDENCE_BYPASS_KEY} carries too many rows`);
  }
  const normalized = [];
  for (const row of rows) {
    if (row == null || typeof row !== "object" || Array.isArray(row)) continue;
    const field = typeof row.field === "string" ? row.field : null;
    const rationale = typeof row.rationale === "string" ? row.rationale : "";
    const path = typeof row.path === "string" ? row.path : null;
    if (!field || !SECRET_EVIDENCE_BYPASS_FIELDS.has(field)) continue;
    // Emptiness is checked on the trimmed value but the stored rationale is kept
    // verbatim so the read-normalized row is byte-identical to the write-persisted
    // row (stable claim_hash recompute).
    if (!rationale.trim() || rationale.length > SECRET_EVIDENCE_BYPASS_RATIONALE_MAX) continue;
    if (!path || !allowedSecretEvidenceBypassPaths(field).has(path)) continue;
    normalized.push({ field, rationale, path });
  }
  return normalized.length > 0 ? normalized : null;
}

// Reconstruct the Set<string> of value-paths whose secret value-scan is skipped,
// from already-normalized secret_evidence_bypass rows. Returns null when nothing
// is honorable so callers fall through to the default full scan.
function reconstructSecretEvidenceBypassPaths(rows) {
  if (!Array.isArray(rows) || rows.length === 0) return null;
  const paths = new Set();
  for (const row of rows) {
    if (row && typeof row.path === "string") paths.add(row.path);
  }
  return paths.size > 0 ? paths : null;
}

function normalizeConfidence(value) {
  if (value == null) return null;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error("confidence must be a number from 0 to 1");
  }
  return Number(value.toFixed(4));
}

function normalizeExploitOutcome(value) {
  if (value == null) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error("exploit_outcome must be an object when present");
  }
  const outcome = assertEnumValue(value.outcome, OFFENSIVE_OUTCOME_VALUES, "exploit_outcome.outcome");
  const safeOracle = value.safe_oracle;
  if (outcome === "exploited_safely") {
    if (safeOracle == null || typeof safeOracle !== "object" || Array.isArray(safeOracle)) {
      throw new Error("exploit_outcome.safe_oracle must be an object when outcome is exploited_safely");
    }
    const kind = assertEnumValue(safeOracle.kind, SAFE_ORACLE_KINDS, "exploit_outcome.safe_oracle.kind");
    return {
      outcome,
      safe_oracle: { kind },
    };
  }
  if (safeOracle != null) {
    throw new Error("exploit_outcome.safe_oracle is only allowed when outcome is exploited_safely");
  }
  return { outcome };
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

function normalizeCandidateClaim(input, { targetDomain = null, now = new Date(), payloadBypassValuePaths = null } = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("claim must be an object");
  }
  const domain = assertSafeDomain(input.target_domain || targetDomain);
  const title = normalizeId(input.title, "title", { maxLength: 240 });
  // Y.0 hotfix 1 (O2): summary cap raised to accommodate field-observed
  // payloads whose description (used as the summary fallback in
  // record-candidate-claim) routinely exceeded 2000 chars. Per-field text
  // caps for the inline finding payload live in
  // mcp/lib/tools/record-candidate-claim.js CLAIM_TEXT_LIMITS.
  const summary = normalizeId(input.summary, "summary", { maxLength: 16000 });
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
  const exploitOutcome = normalizeExploitOutcome(input.exploit_outcome);
  const confidence = normalizeConfidence(input.confidence);
  const sourceTaskIds = normalizeOptionalTextArray(input.source_task_ids, "source_task_ids");
  const agentRunIds = normalizeOptionalTextArray(input.agent_run_ids, "agent_run_ids");
  const tags = normalizeOptionalTextArray(input.tags, "tags");
  // Y.0 hotfix 1 (O2): payload carries the embedded finding-shaped record
  // whose per-field caps were raised in
  // mcp/lib/tools/record-candidate-claim.js. Pass the widened text cap so the
  // generic plain-object validator does not re-tighten what the writer just
  // accepted. payloadBypassValuePaths is the deep-path Set the caller built
  // from secret_detection_bypass; structural sensitive-key detection still
  // fires, only the listed value-paths skip the regex scan.
  //
  // On read (readCandidateClaims passes no payloadBypassValuePaths) we
  // reconstruct the honored paths from the persisted payload.secret_evidence_bypass
  // rows so a legitimately secret-shaped PoC, approved at write, no longer
  // re-throws on every read. The explicit caller-supplied set and the
  // reconstructed set are unioned so the write path stays a strict superset.
  //
  // The metadata key itself (secret_evidence_bypass) is lifted out of the
  // payload before the scan: its `secret` segment would otherwise trip the
  // structural SENSITIVE_KEY_RE, yet it is a fixed, code-emitted key, not secret
  // material. Every other key and value in the payload is still scanned; the
  // lifted rows are independently normalized, field-whitelisted, and capped.
  const normalizedBypassRows = normalizeSecretEvidenceBypassRows(
    isPlainObjectValue(input.payload) ? input.payload[SECRET_EVIDENCE_BYPASS_KEY] : null,
  );
  const reconstructedBypassPaths = reconstructSecretEvidenceBypassPaths(normalizedBypassRows);
  let effectiveBypassPaths = payloadBypassValuePaths instanceof Set
    ? new Set(payloadBypassValuePaths)
    : null;
  if (reconstructedBypassPaths) {
    if (!effectiveBypassPaths) effectiveBypassPaths = new Set();
    for (const path of reconstructedBypassPaths) effectiveBypassPaths.add(path);
  }
  let payloadForScan = input.payload;
  if (isPlainObjectValue(input.payload) && SECRET_EVIDENCE_BYPASS_KEY in input.payload) {
    payloadForScan = { ...input.payload };
    delete payloadForScan[SECRET_EVIDENCE_BYPASS_KEY];
  }
  const payload = normalizeOptionalObject(payloadForScan, "payload", {
    maxTextChars: 16000,
    bypassValuePaths: effectiveBypassPaths,
  });
  // Re-attach the normalized bypass rows after the scan so the claim persists
  // them verbatim for the next read's path reconstruction.
  if (payload && normalizedBypassRows) {
    payload[SECRET_EVIDENCE_BYPASS_KEY] = normalizedBypassRows;
  }

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
  if (exploitOutcome) base.exploit_outcome = exploitOutcome;
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

function readRepoCommandRunRecords(domain) {
  // Read the append-only ledger of bob_repo_docker_run executions. The records
  // are the live-side evidence that a repro command actually ran (rather than
  // being merely cited in an evidence_ref). Missing ledger collapses to an
  // empty list so non-repo sessions short-circuit cleanly; an oversized file
  // raises a hard error rather than silently truncating.
  const filePath = repoCommandRunsJsonlPath(domain);
  if (!fs.existsSync(filePath)) return [];
  const stats = fs.statSync(filePath);
  if (DEFAULT_ARTIFACT_READ_MAX_BYTES != null && stats.size > DEFAULT_ARTIFACT_READ_MAX_BYTES) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `repo-command-runs.jsonl exceeds read cap of ${DEFAULT_ARTIFACT_READ_MAX_BYTES} bytes: ${filePath}`,
    );
  }
  const rows = [];
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      rows.push(JSON.parse(line));
    } catch {
      // Malformed run-log lines never satisfy the cross-check below; they are
      // silently skipped here so a single corrupt row cannot DoS claim
      // recording for the whole session.
    }
  }
  return rows;
}

function readOffensiveRunRecords(domain) {
  const filePath = offensiveRunsJsonlPath(domain);
  if (!fs.existsSync(filePath)) return [];
  const stats = fs.statSync(filePath);
  if (DEFAULT_ARTIFACT_READ_MAX_BYTES != null && stats.size > DEFAULT_ARTIFACT_READ_MAX_BYTES) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `offensive-runs.jsonl exceeds read cap of ${DEFAULT_ARTIFACT_READ_MAX_BYTES} bytes: ${filePath}`,
    );
  }
  const rows = [];
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      rows.push(JSON.parse(line));
    } catch {
      // PR #108 review (Codex P2): unlike repo-command-runs.jsonl (convenience
      // telemetry that tolerates a corrupt line), the offensive ledger is
      // audit-graded proof material. A malformed line means an interrupted
      // append or tampering, so fail closed rather than silently skipping it and
      // letting a later row satisfy the exploit-proof gate against an
      // incomplete/corrupt ledger. Blast radius is limited to exploited_safely
      // claims (the only path that reads this ledger).
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `offensive-runs.jsonl contains a malformed row; refusing to evaluate exploit proof against a corrupt proof ledger: ${filePath}`,
      );
    }
  }
  return rows;
}

const O_P4_DISALLOWED_REPO_COMMAND_EXIT_CODES = Object.freeze([125, 126, 127]);
const OFFENSIVE_RUN_DISALLOWED_EXIT_CODES = Object.freeze([125, 126, 127]);

function repoCommandRunRowSatisfiesEvidence(row, ref) {
  // The cross-check (additive to the evidence_ref shape gate): the row must
  // exist, be a live execution (not a dry-run plan), and bind back to the
  // evidence_ref via run_id + command_hash. exit_code on the ledger row must
  // also agree with the evidence_ref's claimed exit code so a flaky reviewer
  // cannot cite a different run.
  if (!row || typeof row !== "object") return false;
  if (row.dry_run === true) return false;
  if (row.timed_out === true) return false;
  if (typeof row.run_id !== "string" || row.run_id !== ref.run_id) return false;
  if (typeof row.command_hash !== "string" || row.command_hash !== ref.command_hash) return false;
  // exit_code on the row must be a concrete integer (live execution produced
  // a result). If the evidence_ref also pinned a value, it must match.
  if (!Number.isInteger(row.exit_code)) return false;
  if (O_P4_DISALLOWED_REPO_COMMAND_EXIT_CODES.includes(row.exit_code)) return false;
  if (Number.isInteger(ref.exit_code) && row.exit_code !== ref.exit_code) return false;
  return true;
}

// PR #108 review (Codex P1): bind the proof to the claim's own target_domain.
// Returns true only when the cited target URL's host is the claim domain or a
// subdomain of it, so a row planted for another host can never back a claim.
function exploitTargetHostInScope(targetUrl, domain) {
  let host;
  try {
    host = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    return false;
  }
  const scope = String(domain).toLowerCase();
  return host === scope || host.endsWith(`.${scope}`);
}

function offensiveRunRowSatisfiesEvidence(row, ref, domain) {
  if (!row || typeof row !== "object") return false;
  if (row.dry_run === true) return false;
  if (row.timed_out === true) return false;
  // Domain binding (Codex P1): the ledger is read from the claim's session, but
  // the row must also be *recorded for* this domain and the cited URL must be in
  // its scope, so a cross-domain row in the same session cannot stand as proof.
  if (typeof row.target_domain !== "string" || row.target_domain !== domain) return false;
  if (!exploitTargetHostInScope(ref.target, domain)) return false;
  if (typeof row.run_id !== "string" || row.run_id !== ref.run_id) return false;
  if (typeof row.tool_id !== "string" || row.tool_id !== ref.tool_id) return false;
  if (typeof row.target !== "string" || row.target !== ref.target) return false;
  if (typeof row.command_hash !== "string" || row.command_hash !== ref.command_hash) return false;
  if (typeof row.stdout_hash !== "string" || row.stdout_hash !== ref.stdout_hash) return false;
  if (typeof row.stderr_hash !== "string" || row.stderr_hash !== ref.stderr_hash) return false;
  if (row.offensive_outcome !== "exploited_safely") return false;
  if (ref.offensive_outcome != null && row.offensive_outcome !== ref.offensive_outcome) return false;
  if (!Number.isInteger(row.exit_code)) return false;
  if (OFFENSIVE_RUN_DISALLOWED_EXIT_CODES.includes(row.exit_code)) return false;
  if (Number.isInteger(ref.exit_code) && row.exit_code !== ref.exit_code) return false;
  return true;
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
  const repoCommandRunRefs = evidenceRefs.filter((ref) => ref && ref.kind === "repo_command_run");
  if (repoCommandRunRefs.length === 0) {
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
  const runRows = readRepoCommandRunRecords(claim.target_domain);
  // This proof gate is domain-scoped: it proves the cited repo_command_run row
  // exists and was live. File/surface-level linkage remains part of the
  // evaluator-authored evidence narrative and verifier review.
  const backedRef = repoCommandRunRefs.some((ref) => (
    runRows.some((row) => repoCommandRunRowSatisfiesEvidence(row, ref))
  ));
  if (!backedRef) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "high/critical native-code claims require at least one repo_command_run evidence_ref backed by a matching non-dry-run repo-command-runs.jsonl row.",
      {
        code: "O_P4_unbacked_repo_command_run_evidence",
        severity: claim.severity,
        native_surfaces: nativeSurfaces,
        disallowed_repo_command_exit_codes: O_P4_DISALLOWED_REPO_COMMAND_EXIT_CODES,
      },
    );
  }
}

function assertExploitedClaimHasProof(claim) {
  if (claim.exploit_outcome?.outcome !== "exploited_safely") return;
  const evidenceRefs = Array.isArray(claim.evidence_refs) ? claim.evidence_refs : [];
  const exploitRunRefs = evidenceRefs.filter((ref) => ref && ref.kind === "exploit_run");
  if (exploitRunRefs.length === 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "exploited_safely claims must include at least one evidence_refs[] entry with kind: \"exploit_run\".",
      {
        code: "exploit_proof_missing_exploit_run_evidence",
        outcome: claim.exploit_outcome.outcome,
      },
    );
  }
  const runRows = readOffensiveRunRecords(claim.target_domain);
  // PR #108 review (Codex P2): require EVERY exploit_run ref to be backed by an
  // in-scope, non-dry-run ledger row — not just one. `some()` would let an extra
  // unbacked or out-of-scope exploit_run ref ride along into claims.jsonl/the
  // freeze on the coattails of one valid ref, smuggling off-scope offensive
  // evidence. (Stricter than the O-P4 repo_command_run gate by design: offensive
  // target URLs are scope-sensitive in a way native-code run ids are not.)
  const allBacked = exploitRunRefs.every((ref) => (
    runRows.some((row) => offensiveRunRowSatisfiesEvidence(row, ref, claim.target_domain))
  ));
  if (!allBacked) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "exploited_safely claims require every exploit_run evidence_ref to be backed by a matching in-scope, non-dry-run offensive-runs.jsonl row.",
      {
        code: "exploit_proof_unbacked_exploit_run_evidence",
        outcome: claim.exploit_outcome.outcome,
        disallowed_offensive_run_exit_codes: OFFENSIVE_RUN_DISALLOWED_EXIT_CODES,
      },
    );
  }
}

function appendCandidateClaim(input, options = {}) {
  const claim = normalizeCandidateClaim(input, options);
  // O-P4 validator runs before the JSONL append so a rejected claim leaves
  // claims.jsonl untouched. Wave-handoff / blocked-harness consistency is the
  // sibling gate on the handoff path; the claim path owns the native-code
  // severity gate.
  assertNotStaticOnlyNativeHighSeverity(claim);
  assertExploitedClaimHasProof(claim);
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
  OFFENSIVE_OUTCOME_VALUES,
  O_P4_NATIVE_LANGUAGES,
  O_P4_TRIGGERING_SEVERITIES,
  SAFE_ORACLE_KINDS,
  appendCandidateClaim,
  assertExploitedClaimHasProof,
  assertNotStaticOnlyNativeHighSeverity,
  claimSurfaceLanguageMap,
  evidenceReferenceLookupKey,
  generatedClaimId,
  normalizeCandidateClaim,
  normalizeEvidenceReferenceShape,
  readCandidateClaims,
};
