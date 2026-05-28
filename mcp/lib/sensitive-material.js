"use strict";

const DEFAULT_MAX_TEXT_CHARS = 4000;

// A small set of safe meta-suffixes that describe a secret without carrying
// its value. Keys like `token_fingerprint` (a sha256), `token_snippet` (a
// truncated excerpt with literal "..."), `cookie_name` (just the cookie's
// label, never the value), and `set_cookie_name` (same) are deliberately
// allowed. Adding a new suffix here is a deliberate widening — keep the list
// tight and audit the producer to confirm the field never carries the actual
// secret bytes (see Plane T-R3, jwt_observed payload).
const SAFE_META_SUFFIXES = [
  "fingerprint",
  "snippet",
  "location",
  "name",
  "label",
  "kind",
  "type",
  "hash",
  "sha256",
  "path",
];
const SAFE_META_SUFFIX_GROUP = SAFE_META_SUFFIXES.join("|");

// `key_lookbehind` rejects e.g. `id_token` but allows `token_fingerprint`.
// The pattern fires when a forbidden token (`token`, `cookie`, ...) appears as
// a `_`/`-` separated segment NOT immediately followed by one of the safe
// meta-suffix terminators above.
const SENSITIVE_KEY_RE = new RegExp(
  "(?:^|[_-])"
    + "(authorization|cookie|set-cookie|password|passwd|secret|token|jwt"
    + "|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token)"
    + `(?:$|[_-](?!(?:${SAFE_META_SUFFIX_GROUP})(?:$|[_-])))`,
  "i",
);
const SENSITIVE_VALUE_RE = Object.freeze([
  /\b(?:authorization|cookie|set-cookie)\s*[:=]/i,
  /\b(?:bearer|basic)\s+[a-z0-9._~+/=-]{8,}/i,
  /\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|jwt|sessionid)\s*[:=]\s*["']?[a-z0-9._~+/=-]{6,}/i,
  /\beyJ[a-z0-9_-]{10,}\.[a-z0-9_-]{10,}\.[a-z0-9_-]{10,}\b/i,
  /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bAIza[0-9A-Za-z_-]{20,}\b/,
  /\bgh[pousr]_[0-9A-Za-z_]{20,}\b/,
  /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/,
]);

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function validateNoSensitiveMaterial(value, fieldName, { maxTextChars = DEFAULT_MAX_TEXT_CHARS } = {}) {
  const visit = (item, path) => {
    if (typeof item === "string") {
      if (item.length > maxTextChars) {
        throw new Error(`${path} is too large; do not persist raw large response bodies`);
      }
      if (SENSITIVE_VALUE_RE.some((pattern) => pattern.test(item))) {
        throw new Error(`${path} appears to contain secrets, auth headers, cookies, or tokens`);
      }
      return;
    }
    if (Array.isArray(item)) {
      item.forEach((entry, index) => visit(entry, `${path}[${index}]`));
      return;
    }
    if (!isPlainObject(item)) return;
    for (const [key, child] of Object.entries(item)) {
      if (SENSITIVE_KEY_RE.test(key)) {
        throw new Error(`${path}.${key} appears to contain secrets, auth headers, cookies, or tokens`);
      }
      visit(child, `${path}.${key}`);
    }
  };
  visit(value, fieldName);
}

module.exports = {
  DEFAULT_MAX_TEXT_CHARS,
  SENSITIVE_KEY_RE,
  SENSITIVE_VALUE_RE,
  validateNoSensitiveMaterial,
};
