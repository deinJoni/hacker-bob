"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const {
  APTOS_NETWORK_VALUES,
  CHAIN_FAMILY_VALUES,
  COSMWASM_NETWORK_VALUES,
  GRADE_HOLD_MIN_SCORE,
  GRADE_SUBMIT_MIN_SCORE,
  GRADE_VERDICT_VALUES,
  SEVERITY_VALUES,
  SUBSTRATE_NETWORK_VALUES,
  SUI_NETWORK_VALUES,
  SURFACE_TYPE_VALUES,
  SVM_CLUSTER_VALUES,
  VERIFICATION_CONFIDENCE_REASON_VALUES,
  VERIFICATION_CONFIDENCE_VALUES,
  VERIFICATION_DISPOSITION_VALUES,
  VERIFICATION_ROUND_VALUES,
} = require("./constants.js");
const {
  assertBoolean,
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  assertRequiredText,
  normalizeOptionalText,
  parseAgentId,
  parseFindingId,
  parseWaveId,
} = require("./validation.js");
const {
  findingsJsonlPath,
  findingsMarkdownPath,
  gradeArtifactPaths,
  verificationRoundPaths,
} = require("./paths.js");
const {
  appendJsonlLine,
  appendMarkdownMirror,
  loadJsonDocumentStrict,
  withSessionLock,
  writeFileAtomic,
  writeMarkdownMirror,
} = require("./storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  validateAssignedWaveAgentSurface,
} = require("./assignments.js");
const {
  capabilityPackForLegacyFinding,
} = require("./capability-packs.js");
const {
  safeAppendPipelineEventDirect,
} = require("./pipeline-analytics.js");

function verificationLib() {
  return require("./verification.js");
}

function normalizeEndpointForDedupe(endpoint) {
  const raw = String(endpoint || "").trim();
  try {
    const parsed = new URL(raw);
    parsed.hash = "";
    parsed.hostname = parsed.hostname.toLowerCase();
    parsed.pathname = parsed.pathname.replace(/\/+$/, "") || "/";
    const queryKeys = Array.from(parsed.searchParams.keys()).sort();
    parsed.search = queryKeys.map((key) => `${encodeURIComponent(key)}=*`).join("&");
    return parsed.toString().toLowerCase();
  } catch {
    return raw
      .replace(/#.*$/, "")
      .replace(/\?.*$/, (query) => {
        const keys = query.slice(1).split("&").map((part) => part.split("=", 1)[0]).filter(Boolean).sort();
        return keys.length ? `?${keys.map((key) => `${key}=*`).join("&")}` : "";
      })
      .replace(/\/+$/, "")
      .toLowerCase();
  }
}

function normalizeTextForDedupe(value) {
  return String(value || "").trim().toLowerCase().replace(/\s+/g, " ");
}

function shortFingerprint(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex").slice(0, 16);
}

// surface_type is null on legacy findings.jsonl rows recorded before this
// field was introduced. Coerce explicit empty strings to null; otherwise the
// value must be one of the known surface types. Verifiers/reporter treat null
// as "web" downstream so old findings keep flowing through the pipeline.
function normalizeSurfaceType(value) {
  if (value == null) return null;
  if (typeof value !== "string") {
    throw new Error("surface_type must be a string");
  }
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (!SURFACE_TYPE_VALUES.includes(trimmed)) {
    throw new Error(`surface_type must be one of: ${SURFACE_TYPE_VALUES.join(", ")}`);
  }
  return trimmed;
}

const EVM_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
// Solana base58 alphabet excludes 0/O/I/l. Bytes-wise a Solana pubkey is
// always 32 bytes; in base58 that's 32..44 chars (32 chars only when the
// pubkey is the all-zero System Program; canonical IDs are 43-44 chars).
// The alphabet+length regex is a fast first gate — the real check is the
// base58 decode below, which verifies the byte length is exactly 32. Without
// the decode step a malformed 32-char string like "12345..." would pass the
// alphabet test but decode to <32 bytes (NOT a valid pubkey).
const SVM_PUBKEY_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const SVM_PUBKEY_BYTE_LENGTH = 32;
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Decode a base58 string to its byte representation. Returns null on invalid
// input (alphabet violation). Mirrors Bitcoin/Solana base58: leading "1"
// chars are leading 0x00 bytes; the rest is big-endian base-58 digits.
function base58Decode(input) {
  if (typeof input !== "string" || input.length === 0) return null;
  let zeros = 0;
  while (zeros < input.length && input[zeros] === "1") zeros += 1;
  let big = 0n;
  for (let i = zeros; i < input.length; i++) {
    const idx = BASE58_ALPHABET.indexOf(input[i]);
    if (idx < 0) return null;
    big = big * 58n + BigInt(idx);
  }
  const tail = [];
  while (big > 0n) {
    tail.unshift(Number(big & 0xFFn));
    big >>= 8n;
  }
  return Buffer.from([...new Array(zeros).fill(0), ...tail]);
}

// Move (Aptos + Sui) addresses are 32 bytes. Aptos prints them in hex with
// optional leading-zero shorthand: "0x1" is the standard library address,
// canonically "0x000...001" (62 zeros + 01). Sui always prints the full
// 64-char form. The normalizer accepts the shorthand on input, but stores
// them left-padded to the canonical 64-hex form so that two findings against
// "0x1" and "0x000...001" dedupe to the same address.
const MOVE_ADDRESS_RE = /^0x[a-fA-F0-9]{1,64}$/;
const MOVE_ADDRESS_HEX_LENGTH = 64;

function normalizeMoveAddress(input) {
  if (typeof input !== "string" || !MOVE_ADDRESS_RE.test(input)) return null;
  const hexBody = input.slice(2).toLowerCase();
  if (hexBody.length === MOVE_ADDRESS_HEX_LENGTH) return `0x${hexBody}`;
  return `0x${hexBody.padStart(MOVE_ADDRESS_HEX_LENGTH, "0")}`;
}

// Substrate addresses are encoded in SS58 — base58 of [prefix(1..2)][AccountId32(32)][checksum(2)].
// The prefix byte(s) identify the chain (Polkadot=0, Kusama=2, generic substrate=42).
// Decoded byte length is therefore 35 (single-byte prefix) or 36 (multi-byte prefix); we accept
// 33..38 to cover edge cases where checksum length varies. The base58 alphabet excludes 0/O/I/l,
// so EVM 0x... and CosmWasm bech32 inputs that contain 0/l fail the alphabet check; bech32
// inputs that happen to avoid 0/l (rare) still fail the decoded-byte-length gate.
//
// We do NOT verify the BLAKE2b checksum here — node has no built-in BLAKE2b and pulling a
// crypto dep just for hunters' input validation is heavy. The verifier-side RPC fetch via
// state_getStorage is the authoritative existence check; this is shape validation only.
const SS58_BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]+$/;
const SS58_LENGTH_RANGE = { min: 45, max: 52 };
const SS58_BYTE_LENGTH_RANGE = { min: 33, max: 38 };

function normalizeSs58Address(input) {
  if (typeof input !== "string") return null;
  const trimmed = input.trim();
  if (trimmed.length < SS58_LENGTH_RANGE.min || trimmed.length > SS58_LENGTH_RANGE.max) return null;
  if (!SS58_BASE58_RE.test(trimmed)) return null;
  const decoded = base58Decode(trimmed);
  if (!decoded) return null;
  if (decoded.length < SS58_BYTE_LENGTH_RANGE.min || decoded.length > SS58_BYTE_LENGTH_RANGE.max) return null;
  return trimmed; // SS58 is case-sensitive — preserve verbatim.
}

// Bech32 (BIP-0173) decode + checksum verify. CosmWasm contract addresses are
// `<hrp>1<data><checksum>` where hrp is the chain prefix (osmo, juno, neutron, ...).
// We verify the polymod checksum so accidental typos fail-loud at recordFinding rather than
// at verifier-fetch time. Mixed-case inputs are explicitly forbidden by the spec — we accept
// either fully-lowercase or fully-uppercase, then store as lowercase for dedup stability.
//
// CosmWasm uses bech32 (constant 1), not bech32m (constant 0x2bc830a3). If a chain ever ships
// a CosmWasm-on-bech32m variant, switch the polymod constant per chain in the runner; for now
// the validator is bech32-only.
const BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i += 1) {
      if ((top >> i) & 1) chk ^= BECH32_GENERATORS[i];
    }
  }
  return chk >>> 0;
}

function bech32HrpExpand(hrp) {
  const out = [];
  for (let i = 0; i < hrp.length; i += 1) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i += 1) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

function bech32Decode(input) {
  if (typeof input !== "string") return null;
  if (input.length < 8 || input.length > 90) return null;
  let hasUpper = false;
  let hasLower = false;
  for (let i = 0; i < input.length; i += 1) {
    const code = input.charCodeAt(i);
    if (code < 33 || code > 126) return null; // non-printable ASCII
    if (code >= 97 && code <= 122) hasLower = true;
    if (code >= 65 && code <= 90) hasUpper = true;
  }
  if (hasUpper && hasLower) return null;
  const lower = input.toLowerCase();
  const idx = lower.lastIndexOf("1");
  if (idx < 1 || idx + 7 > lower.length) return null;
  const hrp = lower.slice(0, idx);
  for (let i = 0; i < hrp.length; i += 1) {
    const c = hrp.charCodeAt(i);
    if (c < 33 || c > 126) return null;
  }
  const data = [];
  for (let i = idx + 1; i < lower.length; i += 1) {
    const v = BECH32_ALPHABET.indexOf(lower[i]);
    if (v < 0) return null;
    data.push(v);
  }
  if (bech32Polymod([...bech32HrpExpand(hrp), ...data]) !== 1) return null;
  return { hrp, data: data.slice(0, data.length - 6) };
}

function normalizeBech32Address(input) {
  if (typeof input !== "string") return null;
  const trimmed = input.trim();
  const decoded = bech32Decode(trimmed);
  if (!decoded) return null;
  return trimmed.toLowerCase();
}

const SC_EVIDENCE_REQUIRED_FIELDS = ["chain_id", "contract_address", "harness_path", "match_test"];

// sc_evidence carries the structured re-run handle for a smart-contract
// finding. Verifiers replay the bug via bounty_foundry_run / bounty_anchor_run
// with these fields, so each one must be machine-actionable — no free-text PoC
// parsing.
//
// chain_family is the discriminator. EVM uses an integer chain_id and 0x40
// hex contract address; SVM uses a Solana cluster string and base58 program
// pubkey. Legacy rows omit chain_family; we default to "evm" so
// findings.jsonl back-compat is preserved without a migration.
function normalizeScEvidence(value) {
  if (value == null) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error("sc_evidence must be an object");
  }

  let chainFamily = "evm";
  if (value.chain_family != null) {
    if (typeof value.chain_family !== "string") {
      throw new Error("sc_evidence.chain_family must be a string");
    }
    const trimmed = value.chain_family.trim();
    if (trimmed) {
      if (!CHAIN_FAMILY_VALUES.includes(trimmed)) {
        throw new Error(`sc_evidence.chain_family must be one of: ${CHAIN_FAMILY_VALUES.join(", ")}`);
      }
      chainFamily = trimmed;
    }
  }

  for (const field of SC_EVIDENCE_REQUIRED_FIELDS) {
    if (value[field] == null) {
      throw new Error(`sc_evidence.${field} is required`);
    }
  }

  let chainId;
  if (chainFamily === "evm") {
    chainId = value.chain_id;
    if (!Number.isInteger(chainId) || chainId < 1 || chainId > Number.MAX_SAFE_INTEGER) {
      throw new Error("sc_evidence.chain_id must be a positive integer when chain_family='evm'");
    }
  } else if (chainFamily === "svm") {
    chainId = value.chain_id;
    if (typeof chainId !== "string" || !SVM_CLUSTER_VALUES.includes(chainId)) {
      throw new Error(
        `sc_evidence.chain_id must be one of: ${SVM_CLUSTER_VALUES.join(", ")} when chain_family='svm'`,
      );
    }
  } else if (chainFamily === "aptos") {
    chainId = value.chain_id;
    if (typeof chainId !== "string" || !APTOS_NETWORK_VALUES.includes(chainId)) {
      throw new Error(
        `sc_evidence.chain_id must be one of: ${APTOS_NETWORK_VALUES.join(", ")} when chain_family='aptos'`,
      );
    }
  } else if (chainFamily === "sui") {
    chainId = value.chain_id;
    if (typeof chainId !== "string" || !SUI_NETWORK_VALUES.includes(chainId)) {
      throw new Error(
        `sc_evidence.chain_id must be one of: ${SUI_NETWORK_VALUES.join(", ")} when chain_family='sui'`,
      );
    }
  } else if (chainFamily === "substrate") {
    chainId = value.chain_id;
    if (typeof chainId !== "string" || !SUBSTRATE_NETWORK_VALUES.includes(chainId)) {
      throw new Error(
        `sc_evidence.chain_id must be one of: ${SUBSTRATE_NETWORK_VALUES.join(", ")} when chain_family='substrate'`,
      );
    }
  } else {
    // cosmwasm
    chainId = value.chain_id;
    if (typeof chainId !== "string" || !COSMWASM_NETWORK_VALUES.includes(chainId)) {
      throw new Error(
        `sc_evidence.chain_id must be one of: ${COSMWASM_NETWORK_VALUES.join(", ")} when chain_family='cosmwasm'`,
      );
    }
  }

  const contractAddressRaw = String(value.contract_address);
  let contractAddress;
  if (chainFamily === "evm") {
    if (!EVM_ADDRESS_RE.test(contractAddressRaw)) {
      throw new Error("sc_evidence.contract_address must be a 0x-prefixed 40-hex EVM address when chain_family='evm'");
    }
    contractAddress = contractAddressRaw.toLowerCase();
  } else if (chainFamily === "svm") {
    // svm: base58 is case-sensitive — preserve verbatim. Two-step validation:
    // (a) regex rejects 0/O/I/l alphabet violations and bounds length;
    // (b) base58 decode verifies the resulting byte string is exactly 32
    //     bytes (a real Solana pubkey). A malformed 32-char string like
    //     "12345..." passes (a) but fails (b).
    if (!SVM_PUBKEY_RE.test(contractAddressRaw)) {
      throw new Error("sc_evidence.contract_address must be a base58 32-44 char Solana program id when chain_family='svm'");
    }
    const decoded = base58Decode(contractAddressRaw);
    if (!decoded || decoded.length !== SVM_PUBKEY_BYTE_LENGTH) {
      throw new Error(`sc_evidence.contract_address must base58-decode to exactly ${SVM_PUBKEY_BYTE_LENGTH} bytes when chain_family='svm'; received ${decoded ? decoded.length : "null"} bytes`);
    }
    contractAddress = contractAddressRaw;
  } else if (chainFamily === "aptos" || chainFamily === "sui") {
    // aptos / sui: 0x-prefixed hex, 1..64 hex chars on input. Both store as
    // 64-char canonical (left-padded with leading zeros) so "0x1" and
    // "0x000...001" dedupe into the same address. We refuse exactly-40-hex
    // input (canonical EVM address shape) because hunters who paste an EVM
    // address into a Move surface would otherwise have it silently
    // left-padded to a 64-hex form that looks Move-native — rendering
    // wrong-family addresses to triagers and routing the verifier to a
    // non-existent Aptos/Sui resource. Legitimate Move addresses with 12
    // leading zero bytes still encode canonically as 0x000...<40hex>; the
    // 0x-prefix-plus-40-hex shorthand is reserved for EVM.
    const familyLabel = chainFamily; // "aptos" or "sui"
    if (EVM_ADDRESS_RE.test(contractAddressRaw)) {
      throw new Error(`sc_evidence.contract_address looks like a canonical EVM address (0x + 40 hex) but chain_family='${familyLabel}'; if this is genuinely a Move address with 12 leading zero bytes, encode it canonically as 0x000...<40hex> (64 hex chars total)`);
    }
    const normalized = normalizeMoveAddress(contractAddressRaw);
    if (!normalized) {
      throw new Error(`sc_evidence.contract_address must be a 0x-prefixed hex address (1-64 hex chars) when chain_family='${familyLabel}'`);
    }
    contractAddress = normalized;
  } else if (chainFamily === "substrate") {
    // SS58 base58 with prefix byte(s) + 32-byte AccountId32 + 2-byte BLAKE2b
    // checksum. We validate alphabet + length + decoded byte length; the
    // BLAKE2b checksum is verified at runtime by the substrate RPC client
    // when the verifier queries pallet_contracts.ContractInfoOf for the
    // address. Hunters who paste an EVM 0x... or CosmWasm bech32 input fail
    // here because base58 excludes 0/O/I/l and the bech32 separator '1'
    // would otherwise be valid base58, but the decoded length check rejects
    // bech32-shaped inputs (~30 bytes vs SS58's 35-36).
    const normalized = normalizeSs58Address(contractAddressRaw);
    if (!normalized) {
      throw new Error("sc_evidence.contract_address must be a valid SS58-encoded substrate address (base58, 45-52 chars, decoded length 33-38 bytes) when chain_family='substrate'");
    }
    contractAddress = normalized;
  } else {
    // cosmwasm: bech32 with chain-specific HRP (osmo, juno, neutron, ...).
    // We verify the bech32 polymod checksum so typos fail-loud at record
    // time. The HRP is NOT pinned to a specific chain — operators can run a
    // hunter against an osmo1 address while chain_id="osmosis", but a hunter
    // recording an osmo1 address against chain_id="juno" will be caught by
    // the verifier's required read-side disambiguation (cosmwasm_fetch_contract
    // returns 404/not_found if the address doesn't resolve on the claimed
    // network). Mirrors the Aptos↔Sui address-collision guard pattern.
    const normalized = normalizeBech32Address(contractAddressRaw);
    if (!normalized) {
      throw new Error("sc_evidence.contract_address must be a valid bech32-encoded CosmWasm address (e.g., osmo1..., juno1...) with a checksum that verifies when chain_family='cosmwasm'");
    }
    contractAddress = normalized;
  }

  const harnessPath = String(value.harness_path);
  if (!harnessPath.trim()) {
    throw new Error("sc_evidence.harness_path is required");
  }
  // Path containment: harness must live under the user's home so a verifier
  // re-running it can't be tricked into reading /etc/passwd or similar.
  // path.resolve is purely textual — symlinks under $HOME pointing outside
  // would slip past. fs.realpathSync follows the link chain so containment
  // is judged on the actual on-disk location. We also realpath $HOME because
  // macOS exposes /var/folders/... whose canonical form is /private/var/...;
  // comparing realpath-of-input against the lexical $HOME would falsely fail.
  const resolved = path.resolve(harnessPath);
  let realHome = os.homedir();
  try {
    realHome = fs.realpathSync(realHome);
  } catch {
    // If $HOME does not exist (test sandboxes that haven't created it yet),
    // fall back to the lexical form.
  }
  let realResolved;
  try {
    realResolved = fs.realpathSync(resolved);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      // Path may not exist yet at record time (some clients record before the
      // harness is fsync'd). Fall back to lexical resolution but still require
      // the lexical form be under $HOME — verifier-side re-run will repeat
      // realpath check and fail-closed if a symlink escape was attempted.
      realResolved = resolved;
    } else {
      throw new Error(`sc_evidence.harness_path could not be resolved: ${error.message || String(error)}`);
    }
  }
  if (!(realResolved === realHome || realResolved.startsWith(realHome + path.sep))) {
    throw new Error(`sc_evidence.harness_path must live under the user home directory; received: ${realResolved}`);
  }

  const matchTest = String(value.match_test);
  if (matchTest.length < 1 || matchTest.length > 200) {
    throw new Error("sc_evidence.match_test must be 1..200 chars");
  }

  const normalized = {
    chain_family: chainFamily,
    chain_id: chainId,
    contract_address: contractAddress,
    harness_path: resolved,
    match_test: matchTest,
  };

  if (value.match_contract != null) {
    const matchContract = String(value.match_contract);
    if (matchContract.length < 1 || matchContract.length > 200) {
      throw new Error("sc_evidence.match_contract must be 1..200 chars when provided");
    }
    normalized.match_contract = matchContract;
  }

  if (value.fork_block != null) {
    // EVM block number; SVM slot number. Both are non-negative integers.
    const forkBlock = value.fork_block;
    if (!Number.isInteger(forkBlock) || forkBlock < 0 || forkBlock > Number.MAX_SAFE_INTEGER) {
      throw new Error("sc_evidence.fork_block must be a non-negative integer when provided");
    }
    normalized.fork_block = forkBlock;
  }

  if (value.function_signature != null) {
    const sig = String(value.function_signature);
    if (sig.length < 1 || sig.length > 200) {
      throw new Error("sc_evidence.function_signature must be 1..200 chars when provided");
    }
    normalized.function_signature = sig;
  }

  return normalized;
}

function computeFindingDedupeKey(record) {
  const endpoint = normalizeEndpointForDedupe(record.endpoint);
  const classification = normalizeTextForDedupe(record.title || record.cwe || record.severity);
  const authContext = normalizeTextForDedupe(record.auth_profile || "");
  const evidence = shortFingerprint(`${record.response_evidence || ""}\n${record.proof_of_concept || ""}`);
  return crypto.createHash("sha256")
    .update(JSON.stringify([endpoint, classification, authContext, evidence]))
    .digest("hex")
    .slice(0, 24);
}

function summarizeFindings(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
  }

  return {
    total: findings.length,
    by_severity: bySeverity,
    has_high_or_critical: bySeverity.critical + bySeverity.high > 0,
  };
}

function normalizeFindingRecord(record, { expectedDomain = null, lineNumber = null } = {}) {
  if (record == null || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(lineNumber == null
      ? "finding record must be an object"
      : `Malformed findings.jsonl at line ${lineNumber}: expected object`);
  }

  try {
    const finding = {
      id: parseFindingId(record.id, "id"),
      target_domain: assertNonEmptyString(record.target_domain, "target_domain"),
      title: assertRequiredText(record.title, "title"),
      severity: assertEnumValue(record.severity, SEVERITY_VALUES, "severity"),
      cwe: normalizeOptionalText(record.cwe, "cwe"),
      endpoint: assertRequiredText(record.endpoint, "endpoint"),
      description: assertRequiredText(record.description, "description"),
      proof_of_concept: assertRequiredText(record.proof_of_concept, "proof_of_concept"),
      response_evidence: normalizeOptionalText(record.response_evidence, "response_evidence"),
      impact: normalizeOptionalText(record.impact, "impact"),
      validated: assertBoolean(record.validated, "validated"),
      wave: record.wave == null ? null : parseWaveId(record.wave),
      agent: record.agent == null ? null : parseAgentId(record.agent),
      surface_id: normalizeOptionalText(record.surface_id, "surface_id"),
      surface_type: normalizeSurfaceType(record.surface_type),
      // Routing metadata. Optional on disk so legacy rows in findings.jsonl
      // normalize without failure; required on write because recordFinding
      // always derives them from the assignment. We backfill from
      // surface_type + sc_evidence.chain_family below so downstream consumers
      // (verifier/evidence/grader/reporter) never see null and don't have to
      // re-implement the surface_type→pack mapping each.
      capability_pack: normalizeOptionalText(record.capability_pack, "capability_pack"),
      hunter_agent: normalizeOptionalText(record.hunter_agent, "hunter_agent"),
      brief_profile: normalizeOptionalText(record.brief_profile, "brief_profile"),
      sc_evidence: normalizeScEvidence(record.sc_evidence),
      auth_profile: normalizeOptionalText(record.auth_profile, "auth_profile"),
      dedupe_key: normalizeOptionalText(record.dedupe_key, "dedupe_key"),
    };
    // Read-side backfill for legacy rows. If at least one of the three fields
    // is missing, derive the triple from surface_type + sc_evidence.chain_family.
    // Rows written under the current schema always carry the triple; this is a
    // one-way upgrade for old persisted findings.
    const missingRouting = !finding.capability_pack || !finding.hunter_agent || !finding.brief_profile;
    if (missingRouting) {
      const backfill = capabilityPackForLegacyFinding({
        surface_type: finding.surface_type,
        sc_evidence: finding.sc_evidence,
      });
      if (backfill) {
        if (!finding.capability_pack) finding.capability_pack = backfill.capability_pack;
        if (!finding.hunter_agent) finding.hunter_agent = backfill.hunter_agent;
        if (!finding.brief_profile) finding.brief_profile = backfill.brief_profile;
      }
    }
    if (finding.surface_type === "smart_contract" && !finding.sc_evidence) {
      throw new Error("smart-contract findings must include sc_evidence");
    }
    // sc_evidence is rejected on every non-SC surface, including legacy null.
    // The previous check only forbade `web` which let a legacy row carry SC
    // replay data while being routed as web by verifiers — a backdoor to
    // smuggle harness paths through the pipeline without surface_type.
    if (finding.surface_type !== "smart_contract" && finding.sc_evidence) {
      throw new Error("sc_evidence is only allowed on smart_contract findings");
    }
    if (!finding.dedupe_key) {
      finding.dedupe_key = computeFindingDedupeKey(record);
    }
    if (record.force_record === true) {
      finding.force_record = true;
    }

    if (expectedDomain != null && finding.target_domain !== expectedDomain) {
      throw new Error("target_domain mismatch");
    }

    return finding;
  } catch (error) {
    if (lineNumber == null) {
      throw error;
    }
    throw new Error(`Malformed findings.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
}

function readFindingsFromJsonl(domain) {
  const filePath = findingsJsonlPath(domain);
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const content = fs.readFileSync(filePath, "utf8");
  if (!content.trim()) {
    return [];
  }

  const findings = [];
  const lines = content.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;

    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (error) {
      throw new Error(`Malformed findings.jsonl at line ${index + 1}: ${error.message || String(error)}`);
    }

    findings.push(normalizeFindingRecord(parsed, {
      expectedDomain: domain,
      lineNumber: index + 1,
    }));
  }

  return findings;
}

function renderFindingMarkdownEntry(finding) {
  const waveAgent = finding.wave || finding.agent
    ? `\n- **Wave/Agent:** ${finding.wave || "?"}/${finding.agent || "?"}`
    : "";
  const surfaceLabel = finding.surface_id
    ? `${finding.surface_id}${finding.surface_type ? ` (${finding.surface_type})` : ""}`
    : (finding.surface_type ? `(${finding.surface_type})` : "");
  const surface = surfaceLabel ? `\n- **Surface:** ${surfaceLabel}` : "";
  const routing = finding.capability_pack
    ? `\n- **Capability Pack:** ${finding.capability_pack}${finding.hunter_agent ? ` (${finding.hunter_agent})` : ""}`
    : "";
  const authProfile = finding.auth_profile ? `\n- **Auth Profile:** ${finding.auth_profile}` : "";
  let scBlock = "";
  if (finding.sc_evidence) {
    const e = finding.sc_evidence;
    const family = e.chain_family || "evm";
    let idLabel; let addressLabel; let blockLabel;
    if (family === "svm") {
      idLabel = "cluster"; addressLabel = "program_id"; blockLabel = "fork_slot";
    } else if (family === "aptos") {
      // Aptos uses "version" for txn ordering and "ledger version" for state
      // snapshots. The fork_block field stores the ledger version a hunter
      // pinned at recording time.
      idLabel = "network"; addressLabel = "module_address"; blockLabel = "fork_version";
    } else if (family === "sui") {
      // Sui uses checkpoint sequence numbers for chain ordering. The
      // fork_block field stores the checkpoint sequence at recording time.
      idLabel = "network"; addressLabel = "package_id"; blockLabel = "fork_checkpoint";
    } else if (family === "substrate") {
      // Substrate identifies block ordering by block number (state at a
      // specific block hash); the fork_block field stores that height.
      idLabel = "network"; addressLabel = "ss58_address"; blockLabel = "fork_block";
    } else if (family === "cosmwasm") {
      // CosmWasm chains are Cosmos SDK Tendermint chains with sequential
      // block heights; fork_block stores the block height at recording time.
      idLabel = "network"; addressLabel = "contract_address"; blockLabel = "fork_block";
    } else {
      idLabel = "chain_id"; addressLabel = "contract"; blockLabel = "fork_block";
    }
    const lines = [
      `\n- **SC Evidence:**`,
      `  - chain_family: ${family}`,
      `  - ${idLabel}: ${e.chain_id}`,
      `  - ${addressLabel}: ${e.contract_address}`,
      `  - harness: ${e.harness_path}`,
      `  - match_test: ${e.match_test}`,
    ];
    if (e.match_contract) lines.push(`  - match_contract: ${e.match_contract}`);
    if (e.fork_block != null) lines.push(`  - ${blockLabel}: ${e.fork_block}`);
    if (e.function_signature) lines.push(`  - function: ${e.function_signature}`);
    scBlock = lines.join("\n");
  }

  return [
    `## FINDING ${finding.id.slice(2)} (${finding.severity.toUpperCase()}): ${finding.title}`,
    `- **ID:** ${finding.id}`,
    `- **CWE:** ${finding.cwe || "N/A"}`,
    `- **Endpoint:** ${finding.endpoint}`,
    `- **Validated:** ${finding.validated ? "YES" : "NO"}`,
    `- **Description:** ${finding.description}`,
    `- **PoC:**`,
    "```",
    finding.proof_of_concept,
    "```",
    `- **Evidence:** ${finding.response_evidence || "See PoC"}`,
    `- **Impact:** ${finding.impact || "N/A"}`,
    waveAgent,
    surface,
    routing,
    authProfile,
    scBlock,
    "---\n\n",
  ].join("\n");
}

function recordFinding(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const hasWave = args.wave != null;
  const hasAgent = args.agent != null;
  if (hasWave !== hasAgent) {
    throw new Error("wave and agent must either both be provided or both be omitted");
  }

  let wave = null;
  let agent = null;
  let surfaceId = null;
  let surfaceType = null;
  let capabilityPack = null;
  let hunterAgent = null;
  let briefProfile = null;
  if (hasWave) {
    wave = parseWaveId(args.wave);
    agent = parseAgentId(args.agent);
    surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
    const assignment = validateAssignedWaveAgentSurface(domain, wave, agent, surfaceId);
    // surface_type on the assignment may be any value attack_surface.json
    // accepts (api, web, javascript_bundle, smart_contract, ...). For finding
    // routing only the SC vs non-SC split matters, so collapse anything other
    // than smart_contract to "web". The assignment value still drives the
    // surface-completion gate via waves.js — that logic uses the raw value.
    const rawSurfaceType = assignment && assignment.surface_type ? assignment.surface_type : null;
    surfaceType = rawSurfaceType === "smart_contract" ? "smart_contract" : "web";
    // The assignment file (loaded via loadWaveAssignments → normalizeAssignmentRouteMetadata)
    // already validated capability_pack / hunter_agent / brief_profile against
    // the pack registry. Persisting them on the finding lets verifier/grader/
    // reporter dispatch on the routed decision rather than re-deriving from
    // surface_type and chain_family.
    capabilityPack = assignment.capability_pack || null;
    hunterAgent = assignment.hunter_agent || null;
    briefProfile = assignment.brief_profile || null;
  } else {
    surfaceId = args.surface_id == null ? null : assertNonEmptyString(args.surface_id, "surface_id");
    // No wave/agent context (orchestrator-direct or legacy). The web defaults
    // are correct only because smart-contract findings always come from a
    // hunter wave; assert that locally rather than relying on the
    // surface_type/sc_evidence guard further down to keep us honest. If a
    // future caller passes sc_evidence here, the routed pack would silently
    // be web and downstream verifier/evidence dispatch would mis-route.
    if (args.sc_evidence != null) {
      throw new Error("sc_evidence findings must be recorded with wave and agent so the routed capability pack is captured from the assignment");
    }
    surfaceType = "web";
    capabilityPack = "web";
    hunterAgent = "hunter-agent";
    briefProfile = "web";
  }

  return withSessionLock(domain, () => {
    const structuredPath = findingsJsonlPath(domain);
    const existingFindings = readFindingsFromJsonl(domain);
    const counter = existingFindings.length + 1;

    const finding = normalizeFindingRecord({
      id: `F-${counter}`,
      target_domain: domain,
      title: args.title,
      severity: args.severity,
      cwe: args.cwe,
      endpoint: args.endpoint,
      description: args.description,
      proof_of_concept: args.proof_of_concept,
      response_evidence: args.response_evidence,
      impact: args.impact,
      validated: args.validated,
      wave,
      agent,
      surface_id: surfaceId,
      surface_type: surfaceType,
      capability_pack: capabilityPack,
      hunter_agent: hunterAgent,
      brief_profile: briefProfile,
      sc_evidence: args.sc_evidence,
      dedupe_key: args.dedupe_key,
      auth_profile: args.auth_profile,
      force_record: args.force_record === true,
    }, { expectedDomain: domain });

    const duplicate = existingFindings.find((existing) => existing.dedupe_key === finding.dedupe_key);
    if (duplicate && args.force_record !== true) {
      return JSON.stringify({
        recorded: false,
        duplicate: true,
        finding_id: duplicate.id,
        existing_finding_id: duplicate.id,
        dedupe_key: duplicate.dedupe_key,
        total: existingFindings.length,
        written_jsonl: structuredPath,
      });
    }

    appendJsonlLine(structuredPath, finding);

    const response = {
      recorded: true,
      finding_id: finding.id,
      total: counter,
      dedupe_key: finding.dedupe_key,
      written_jsonl: structuredPath,
    };
    if (finding.force_record) {
      response.force_record = true;
    }

    appendMarkdownMirror(findingsMarkdownPath(domain), renderFindingMarkdownEntry(finding), response);
    safeAppendPipelineEventDirect(domain, "finding_recorded", {
      wave,
      agent,
      surface_id: surfaceId,
      status: finding.severity,
      source: "bounty_record_finding",
      counts: {
        findings: counter,
        validated: finding.validated ? 1 : 0,
      },
    });
    try {
      const { indexFinding } = require("./findings-index.js");
      indexFinding({
        target_domain: domain,
        finding: {
          finding_id: finding.id,
          title: finding.title,
          description: finding.description,
          severity: finding.severity,
          attack_class: finding.attack_class,
          cwe: finding.cwe,
          endpoint: finding.endpoint,
          surface_id: finding.surface_id,
          surface_type: finding.surface_type,
          tech_stack: finding.tech_stack,
          evidence_summary: finding.evidence_summary || finding.response_evidence,
          proof_of_concept: finding.proof_of_concept,
        },
      });
    } catch (_err) {
      // Best-effort: indexing failure must not break the recordFinding write.
    }
    return JSON.stringify(response);
  });
}

function readFindings(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    findings: readFindingsFromJsonl(domain),
  });
}

function listFindings(args) {
  const findings = readFindingsFromJsonl(assertNonEmptyString(args.target_domain, "target_domain"));
  return JSON.stringify({
    count: findings.length,
    findings: findings.map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      title: finding.title,
      endpoint: finding.endpoint,
    })),
  });
}

function normalizeStringEnumArray(value, fieldName, allowedValues, { required = false } = {}) {
  if (value == null) {
    if (required) throw new Error(`${fieldName} must be an array`);
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array`);
  }
  const seen = new Set();
  const normalized = [];
  for (const item of value) {
    const text = assertEnumValue(item, allowedValues, fieldName);
    if (!seen.has(text)) {
      seen.add(text);
      normalized.push(text);
    }
  }
  normalized.sort();
  return normalized;
}

const VERIFICATION_ARTIFACT_HASH_KEY_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;
const VERIFICATION_ARTIFACT_HASH_VALUE_RE = /^[a-f0-9]{64}$/;
const VERIFICATION_ARTIFACT_HASH_MAX_ENTRIES = 20;
const VERIFICATION_ARTIFACT_HASH_SECRET_KEY_RE = /(?:authorization|cookie|token|secret|password|passwd|api[_-]?key|credential|session)/i;

function normalizeArtifactHashes(value, fieldName = "artifact_hashes") {
  if (value == null) return {};
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const entries = Object.entries(value);
  if (entries.length > VERIFICATION_ARTIFACT_HASH_MAX_ENTRIES) {
    throw new Error(`${fieldName} must contain at most ${VERIFICATION_ARTIFACT_HASH_MAX_ENTRIES} entries`);
  }
  const normalized = {};
  for (const [key, hash] of entries.sort(([a], [b]) => a.localeCompare(b))) {
    const safeKey = assertNonEmptyString(key, `${fieldName} key`);
    if (!VERIFICATION_ARTIFACT_HASH_KEY_RE.test(safeKey)) {
      throw new Error(`${fieldName} key must use only letters, numbers, dot, underscore, colon, or hyphen and be at most 80 chars`);
    }
    if (VERIFICATION_ARTIFACT_HASH_SECRET_KEY_RE.test(safeKey)) {
      throw new Error(`${fieldName} key must be metadata-only and must not name secrets or credentials`);
    }
    const normalizedHash = assertNonEmptyString(hash, `${fieldName}.${safeKey}`);
    if (!VERIFICATION_ARTIFACT_HASH_VALUE_RE.test(normalizedHash)) {
      throw new Error(`${fieldName}.${safeKey} must be a lower-case SHA-256 hex hash`);
    }
    normalized[safeKey] = normalizedHash;
  }
  return normalized;
}

function normalizeVerificationResult(result, findingIdSet, { schemaVersion = 1 } = {}) {
  if (result == null || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("results entries must be objects");
  }

  const findingId = parseFindingId(result.finding_id);
  if (!findingIdSet.has(findingId)) {
    throw new Error(`Unknown finding_id: ${findingId}`);
  }

  const normalized = {
    finding_id: findingId,
    disposition: assertEnumValue(result.disposition, VERIFICATION_DISPOSITION_VALUES, "disposition"),
    severity: result.severity == null ? null : assertEnumValue(result.severity, SEVERITY_VALUES, "severity"),
    reportable: assertBoolean(result.reportable, "reportable"),
    reasoning: assertRequiredText(result.reasoning, "reasoning"),
  };

  if (schemaVersion === 2) {
    normalized.confidence = assertEnumValue(result.confidence, VERIFICATION_CONFIDENCE_VALUES, "confidence");
    normalized.confidence_reasons = normalizeStringEnumArray(
      result.confidence_reasons,
      "confidence_reasons",
      VERIFICATION_CONFIDENCE_REASON_VALUES,
      { required: true },
    ).sort((a, b) => a.localeCompare(b));
    normalized.state_sensitive = assertBoolean(result.state_sensitive, "state_sensitive");
    normalized.artifact_hashes = normalizeArtifactHashes(result.artifact_hashes);
    normalized.inherited_confidence_reasons = normalizeStringEnumArray(
      result.inherited_confidence_reasons,
      "inherited_confidence_reasons",
      VERIFICATION_CONFIDENCE_REASON_VALUES,
    ).sort((a, b) => a.localeCompare(b));
    normalized.resolved_confidence_reasons = normalizeStringEnumArray(
      result.resolved_confidence_reasons,
      "resolved_confidence_reasons",
      VERIFICATION_CONFIDENCE_REASON_VALUES,
    ).sort((a, b) => a.localeCompare(b));
  }

  return normalized;
}

function sortVerificationResultsByFindingIds(results, findingIds) {
  const order = new Map(findingIds.map((id, index) => [id, index]));
  return results.slice().sort((a, b) => (
    (order.get(a.finding_id) ?? Number.MAX_SAFE_INTEGER)
    - (order.get(b.finding_id) ?? Number.MAX_SAFE_INTEGER)
    || a.finding_id.localeCompare(b.finding_id)
  ));
}

function normalizeVerificationRoundDocument(document, { expectedDomain, expectedRound, findingIdSet = null } = {}) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("verification round document must be an object");
  }

  const round = assertEnumValue(document.round, VERIFICATION_ROUND_VALUES, "round");
  const version = assertInteger(document.version, "version", { min: 1, max: 2 });
  const normalized = {
    version,
    target_domain: assertNonEmptyString(document.target_domain, "target_domain"),
    round,
    notes: normalizeOptionalText(document.notes, "notes"),
    results: [],
  };

  if (version === 2) {
    if (document.plan_hash != null) {
      throw new Error("plan_hash is not supported; use adjudication_plan_hash");
    }
    normalized.verification_attempt_id = assertNonEmptyString(document.verification_attempt_id, "verification_attempt_id");
    normalized.verification_snapshot_hash = assertNonEmptyString(document.verification_snapshot_hash, "verification_snapshot_hash");
    normalized.round_profile = assertRequiredText(document.round_profile, "round_profile");
    if (round === "final") {
      normalized.adjudication_plan_hash = assertNonEmptyString(document.adjudication_plan_hash, "adjudication_plan_hash");
      normalized.final_verification_hash = normalizeOptionalText(document.final_verification_hash, "final_verification_hash");
    }
  }

  if (!Array.isArray(document.results)) {
    throw new Error("results must be an array");
  }

  const seenIds = new Set();
  for (const result of document.results) {
    const normalizedResult = normalizeVerificationResult(
      result,
      findingIdSet ?? new Set([parseFindingId(result.finding_id)]),
      { schemaVersion: version },
    );
    if (seenIds.has(normalizedResult.finding_id)) {
      throw new Error(`Duplicate finding_id in results: ${normalizedResult.finding_id}`);
    }
    seenIds.add(normalizedResult.finding_id);
    normalized.results.push(normalizedResult);
  }
  if (version === 2) {
    normalized.results.sort((a, b) => a.finding_id.localeCompare(b.finding_id));
  }

  if (expectedDomain != null && normalized.target_domain !== expectedDomain) {
    throw new Error(`verification round target_domain mismatch: expected ${expectedDomain}`);
  }
  if (expectedRound != null && normalized.round !== expectedRound) {
    throw new Error(`verification round mismatch: expected ${expectedRound}`);
  }

  return normalized;
}

function requirePriorVerificationRound(domain, round, findingIdSet) {
  const priorRoundByRound = { balanced: "brutalist", final: "balanced" };
  const priorRound = priorRoundByRound[round];
  if (!priorRound) return null;

  const priorPaths = verificationRoundPaths(domain, priorRound);
  const priorDocument = loadJsonDocumentStrict(priorPaths.json, `${priorRound} verification round JSON`);
  return normalizeVerificationRoundDocument(priorDocument, {
    expectedDomain: domain,
    expectedRound: priorRound,
    findingIdSet,
  });
}

function renderVerificationRoundMarkdown(document) {
  const lines = [
    `# Verification Round: ${document.round}`,
    `- Target: ${document.target_domain}`,
    ...(document.version === 2
      ? [
        `- Schema: v2`,
        `- Attempt: ${document.verification_attempt_id}`,
        `- Snapshot: ${document.verification_snapshot_hash}`,
        ...(document.adjudication_plan_hash ? [`- Adjudication Plan: ${document.adjudication_plan_hash}`] : []),
        ...(document.final_verification_hash ? [`- Final Verification Hash: ${document.final_verification_hash}`] : []),
      ]
      : []),
    `- Notes: ${document.notes || "N/A"}`,
    `- Results: ${document.results.length}`,
    "",
  ];

  if (document.results.length === 0) {
    lines.push("No verification results recorded.");
    lines.push("");
    return `${lines.join("\n")}\n`;
  }

  for (const result of document.results) {
    lines.push(`## ${result.finding_id}`);
    lines.push(`- Disposition: ${result.disposition}`);
    lines.push(`- Severity: ${result.severity || "none"}`);
    lines.push(`- Reportable: ${result.reportable ? "YES" : "NO"}`);
    if (document.version === 2) {
      lines.push(`- Confidence: ${result.confidence}`);
      lines.push(`- Confidence Reasons: ${result.confidence_reasons.length ? result.confidence_reasons.join(", ") : "N/A"}`);
      lines.push(`- State Sensitive: ${result.state_sensitive ? "YES" : "NO"}`);
    }
    lines.push(`- Reasoning: ${result.reasoning}`);
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

function writeVerificationRound(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const round = assertEnumValue(args.round, VERIFICATION_ROUND_VALUES, "round");
  const notes = normalizeOptionalText(args.notes, "notes");
  if (!Array.isArray(args.results)) {
    throw new Error("results must be an array");
  }

  const schemaVersion = verificationLib().selectVerificationWriteSchemaVersion(domain);
  let v2State = null;
  let v2Snapshot = null;
  let v2Adjudication = null;
  if (schemaVersion === 2) {
    const current = verificationLib().currentV2RoundInput(domain, args);
    v2State = current.state;
    v2Snapshot = current.snapshot;
  }

  const findingIdSet = schemaVersion === 2
    ? new Set(v2Snapshot.finding_ids)
    : new Set(readFindingsFromJsonl(domain).map((finding) => finding.id));
  const seenIds = new Set();
  let results = args.results.map((result) => {
    const normalizedResult = normalizeVerificationResult(result, findingIdSet, { schemaVersion });
    if (seenIds.has(normalizedResult.finding_id)) {
      throw new Error(`Duplicate finding_id in results: ${normalizedResult.finding_id}`);
    }
    seenIds.add(normalizedResult.finding_id);
    return normalizedResult;
  });
  if (schemaVersion === 2) {
    results.sort((a, b) => a.finding_id.localeCompare(b.finding_id));
  }

  if (schemaVersion === 1) {
    const priorDocument = requirePriorVerificationRound(domain, round, findingIdSet);
    if (priorDocument) {
      const priorIds = new Set(priorDocument.results.map((result) => result.finding_id));
      const currentIds = new Set(results.map((result) => result.finding_id));
      const missing = [...priorIds].filter((id) => !currentIds.has(id));
      if (missing.length > 0) {
        throw new Error(
          `${round} round is missing ${missing.length} finding(s) from ${priorDocument.round} round: ${missing.join(", ")}. ` +
          "Include ALL findings from the prior round — pass through unchanged findings you did not re-test."
        );
      }
    }
  } else {
    if (args.plan_hash != null) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "plan_hash is not supported; use adjudication_plan_hash");
    }
    verificationLib().assertExactFindingCoverage(results, v2Snapshot.finding_ids, round);
    results = sortVerificationResultsByFindingIds(results, v2Snapshot.finding_ids);
    if (round === "final") {
      const adjudicationPlanHash = assertNonEmptyString(args.adjudication_plan_hash, "adjudication_plan_hash");
      v2Adjudication = verificationLib().requireCurrentAdjudication(domain, {
        adjudicationPlanHash,
        state: v2State,
        snapshot: v2Snapshot,
      });
    } else if (args.adjudication_plan_hash != null) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "adjudication_plan_hash is only allowed for final v2 verification");
    }
  }

  const document = {
    version: schemaVersion,
    target_domain: domain,
    round,
    notes,
    results,
  };
  if (schemaVersion === 2) {
    document.verification_attempt_id = v2State.verification_attempt_id;
    document.verification_snapshot_hash = v2State.verification_snapshot_hash;
    document.round_profile = args.round_profile == null
      ? round
      : assertRequiredText(args.round_profile, "round_profile");
    if (round === "final") {
      document.adjudication_plan_hash = v2Adjudication.adjudication_plan_hash;
      document.final_verification_hash = verificationLib().finalVerificationHash(document);
      verificationLib().validateFinalAgainstAdjudication(domain, document, v2Adjudication);
    }
  }

  const paths = verificationRoundPaths(domain, round);
  writeFileAtomic(paths.json, JSON.stringify(document, null, 2) + "\n");

  const response = {
    round,
    schema_version: schemaVersion,
    results_count: results.length,
    written_json: paths.json,
  };
  if (schemaVersion === 2) {
    response.verification_attempt_id = v2State.verification_attempt_id;
    response.verification_snapshot_hash = v2State.verification_snapshot_hash;
    if (document.adjudication_plan_hash) response.adjudication_plan_hash = document.adjudication_plan_hash;
    if (document.final_verification_hash) response.final_verification_hash = document.final_verification_hash;
  }
  writeMarkdownMirror(paths.markdown, renderVerificationRoundMarkdown(document), response);
  safeAppendPipelineEventDirect(domain, "verification_written", {
    phase: "VERIFY",
    status: round,
    source: "bounty_write_verification_round",
    verification_attempt_id: schemaVersion === 2 ? v2State.verification_attempt_id : undefined,
    verification_snapshot_hash: schemaVersion === 2 ? v2State.verification_snapshot_hash : undefined,
    adjudication_plan_hash: schemaVersion === 2 && round === "final" ? document.adjudication_plan_hash : undefined,
    final_verification_hash: schemaVersion === 2 && round === "final" ? document.final_verification_hash : undefined,
    counts: {
      results: results.length,
      reportable: results.filter((result) => result.reportable).length,
      confirmed: results.filter((result) => result.disposition === "confirmed").length,
    },
  });
  if (schemaVersion === 2) verificationLib().refreshVerificationManifest(domain);
  return JSON.stringify(response);
}

function readVerificationRound(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const paths = verificationRoundPaths(domain, args.round);
  const document = loadJsonDocumentStrict(paths.json, `${paths.round} verification round JSON`);
  const findingIdSet = document && document.version === 2
    ? null
    : new Set(readFindingsFromJsonl(domain).map((finding) => finding.id));
  const normalized = normalizeVerificationRoundDocument(document, {
    expectedDomain: domain,
    expectedRound: paths.round,
    findingIdSet,
  });
  return JSON.stringify(verificationLib().decorateVerificationRoundRead(domain, normalized));
}

function normalizeGradeFinding(result, findingIdSet) {
  if (result == null || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("findings entries must be objects");
  }

  const findingId = parseFindingId(result.finding_id);
  if (!findingIdSet.has(findingId)) {
    throw new Error(`Unknown finding_id: ${findingId}`);
  }

  const normalized = {
    finding_id: findingId,
    impact: assertInteger(result.impact, "impact", { min: 0, max: 30 }),
    proof_quality: assertInteger(result.proof_quality, "proof_quality", { min: 0, max: 25 }),
    severity_accuracy: assertInteger(result.severity_accuracy, "severity_accuracy", { min: 0, max: 15 }),
    chain_potential: assertInteger(result.chain_potential, "chain_potential", { min: 0, max: 15 }),
    report_quality: assertInteger(result.report_quality, "report_quality", { min: 0, max: 15 }),
    total_score: assertInteger(result.total_score, "total_score", { min: 0 }),
    feedback: normalizeOptionalText(result.feedback, "feedback"),
  };

  const expectedTotal = normalized.impact
    + normalized.proof_quality
    + normalized.severity_accuracy
    + normalized.chain_potential
    + normalized.report_quality;
  if (normalized.total_score !== expectedTotal) {
    throw new Error(`finding ${findingId} total_score must equal the sum of rubric scores`);
  }

  return normalized;
}

function normalizeGradeVerdictDocument(document, { expectedDomain = null, findingIdSet = null } = {}) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("grade verdict document must be an object");
  }

  const normalized = {
    version: assertInteger(document.version, "version", { min: 1, max: 1 }),
    target_domain: assertNonEmptyString(document.target_domain, "target_domain"),
    verdict: assertEnumValue(document.verdict, GRADE_VERDICT_VALUES, "verdict"),
    total_score: assertInteger(document.total_score, "total_score", { min: 0 }),
    findings: [],
    feedback: normalizeOptionalText(document.feedback, "feedback"),
  };

  if (!Array.isArray(document.findings)) {
    throw new Error("findings must be an array");
  }

  const seenIds = new Set();
  for (const finding of document.findings) {
    const normalizedFinding = normalizeGradeFinding(
      finding,
      findingIdSet ?? new Set([parseFindingId(finding.finding_id)]),
    );
    if (seenIds.has(normalizedFinding.finding_id)) {
      throw new Error(`Duplicate finding_id in findings: ${normalizedFinding.finding_id}`);
    }
    seenIds.add(normalizedFinding.finding_id);
    normalized.findings.push(normalizedFinding);
  }

  if (expectedDomain != null && normalized.target_domain !== expectedDomain) {
    throw new Error(`grade verdict target_domain mismatch: expected ${expectedDomain}`);
  }

  enforceGradeVerdictConsistency(normalized, {
    finalReportableSeveritySet: expectedDomain == null ? null : requireFinalReportableSeveritySet(expectedDomain, findingIdSet),
  });

  return normalized;
}

function isMediumOrHigher(severity) {
  return ["medium", "high", "critical"].includes(severity);
}

function requireFinalReportableSeveritySet(domain, findingIdSet) {
  const paths = verificationRoundPaths(domain, "final");
  let normalized;
  try {
    const document = loadJsonDocumentStrict(paths.json, "final verification round JSON");
    let effectiveFindingIdSet = findingIdSet;
    let v2Current = null;
    if (document && document.version === 2) {
      v2Current = verificationLib().requireV2State(domain);
      effectiveFindingIdSet = new Set(v2Current.snapshot.finding_ids);
    }
    normalized = normalizeVerificationRoundDocument(document, {
      expectedDomain: domain,
      expectedRound: "final",
      findingIdSet: effectiveFindingIdSet,
    });
    if (normalized.version === 2) {
      verificationLib().assertCurrentV2RoundDocument(domain, normalized, {
        expectedRound: "final",
        state: v2Current.state,
        snapshot: v2Current.snapshot,
      });
    }
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Final verification must exist and be valid before grading: ${error.message || String(error)}`,
    );
  }
  return new Set(
    normalized.results
      .filter((result) => result.reportable && isMediumOrHigher(result.severity))
      .map((result) => result.finding_id),
  );
}

function requireEvidencePacksForGrading(domain, findingIdSet) {
  const {
    requireValidEvidencePacksForFinalReportableFindings,
  } = require("./evidence.js");
  return requireValidEvidencePacksForFinalReportableFindings(domain, { findingIdSet });
}

function enforceGradeVerdictConsistency(document, { finalReportableSeveritySet: reportableSet = null } = {}) {
  const maxFindingScore = document.findings.reduce(
    (maxScore, finding) => Math.max(maxScore, finding.total_score),
    0,
  );
  if (document.total_score !== maxFindingScore) {
    throw new Error(`grade total_score must equal the maximum per-finding score (${maxFindingScore})`);
  }

  const hasReportableMedium = reportableSet == null
    ? document.findings.length > 0
    : document.findings.some((finding) => reportableSet.has(finding.finding_id));

  let expectedVerdict;
  if (!hasReportableMedium || document.total_score < GRADE_HOLD_MIN_SCORE) {
    expectedVerdict = "SKIP";
  } else if (document.total_score < GRADE_SUBMIT_MIN_SCORE) {
    expectedVerdict = "HOLD";
  } else {
    expectedVerdict = "SUBMIT";
  }

  if (document.verdict !== expectedVerdict) {
    throw new Error(
      `grade verdict ${document.verdict} does not match total_score ${document.total_score} and reportable findings; expected ${expectedVerdict}`,
    );
  }
}

function renderGradeVerdictMarkdown(document) {
  const lines = [
    "# Grade Verdict",
    `- Target: ${document.target_domain}`,
    `- Verdict: ${document.verdict}`,
    `- Total Score: ${document.total_score}`,
    `- Feedback: ${document.feedback || "N/A"}`,
    "",
  ];

  if (document.findings.length === 0) {
    lines.push("No graded findings.");
    lines.push("");
    return `${lines.join("\n")}\n`;
  }

  for (const finding of document.findings) {
    lines.push(`## ${finding.finding_id}`);
    lines.push(`- Impact: ${finding.impact}`);
    lines.push(`- Proof Quality: ${finding.proof_quality}`);
    lines.push(`- Severity Accuracy: ${finding.severity_accuracy}`);
    lines.push(`- Chain Potential: ${finding.chain_potential}`);
    lines.push(`- Report Quality: ${finding.report_quality}`);
    lines.push(`- Total Score: ${finding.total_score}`);
    lines.push(`- Feedback: ${finding.feedback || "N/A"}`);
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

function writeGradeVerdict(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const verdict = assertEnumValue(args.verdict, GRADE_VERDICT_VALUES, "verdict");
  const totalScore = assertInteger(args.total_score, "total_score", { min: 0 });
  const feedback = normalizeOptionalText(args.feedback, "feedback");
  if (!Array.isArray(args.findings)) {
    throw new Error("findings must be an array");
  }

  const findingIdSet = new Set(readFindingsFromJsonl(domain).map((finding) => finding.id));
  const seenIds = new Set();
  const findings = args.findings.map((finding) => {
    const normalizedFinding = normalizeGradeFinding(finding, findingIdSet);
    if (seenIds.has(normalizedFinding.finding_id)) {
      throw new Error(`Duplicate finding_id in findings: ${normalizedFinding.finding_id}`);
    }
    seenIds.add(normalizedFinding.finding_id);
    return normalizedFinding;
  });

  const document = {
    version: 1,
    target_domain: domain,
    verdict,
    total_score: totalScore,
    findings,
    feedback,
  };
  enforceGradeVerdictConsistency(document, {
    finalReportableSeveritySet: requireFinalReportableSeveritySet(domain, findingIdSet),
  });
  verificationLib().requireVerificationCompleteForGrade(domain, { findingIdSet });

  const paths = gradeArtifactPaths(domain);
  writeFileAtomic(paths.json, JSON.stringify(document, null, 2) + "\n");

  const response = {
    verdict,
    findings_count: findings.length,
    written_json: paths.json,
  };
  writeMarkdownMirror(paths.markdown, renderGradeVerdictMarkdown(document), response);
  safeAppendPipelineEventDirect(domain, "grade_written", {
    phase: "GRADE",
    status: verdict,
    source: "bounty_write_grade_verdict",
    counts: {
      findings: findings.length,
      total_score: totalScore,
    },
  });
  return JSON.stringify(response);
}

function readGradeVerdict(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const paths = gradeArtifactPaths(domain);
  const document = loadJsonDocumentStrict(paths.json, "grade verdict JSON");
  const findingIdSet = new Set(readFindingsFromJsonl(domain).map((finding) => finding.id));
  const normalized = normalizeGradeVerdictDocument(document, {
    expectedDomain: domain,
    findingIdSet,
  });
  requireEvidencePacksForGrading(domain, findingIdSet);
  return JSON.stringify(normalized);
}

module.exports = {
  listFindings,
  computeFindingDedupeKey,
  normalizeFindingRecord,
  enforceGradeVerdictConsistency,
  normalizeBech32Address,
  normalizeGradeVerdictDocument,
  normalizeSs58Address,
  normalizeVerificationRoundDocument,
  normalizeVerificationResult,
  readFindings,
  readFindingsFromJsonl,
  readGradeVerdict,
  readVerificationRound,
  recordFinding,
  renderFindingMarkdownEntry,
  renderGradeVerdictMarkdown,
  renderVerificationRoundMarkdown,
  summarizeFindings,
  writeGradeVerdict,
  writeVerificationRound,
};
