"use strict";

const SENSITIVE_QUERY_KEY_RE = /(?:^|[_-])(token|code|session|sid|password|passwd|secret|jwt|auth|authorization|key|api[_-]?key|credential|csrf|xsrf|access[_-]?token|refresh[_-]?token|id[_-]?token)(?:$|[_-])/i;
const REDACTED_VALUE = "REDACTED";
const LOOSE_SECRET_KEY_PATTERN = "api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|token|secret|password|passwd|credential|session|sid|jwt|csrf|xsrf|auth|key";
const LOOSE_SECRET_ASSIGNMENT_RE = new RegExp(`(^|[^A-Za-z0-9])((?:["'])?(?:${LOOSE_SECRET_KEY_PATTERN})(?:["'])?\\s*[:=]\\s*(?:["'])?)[^"',&#\\s}]+(?:#[^\\s]*)?((?:["'])?)`, "gi");
const LOOSE_AUTHORIZATION_RE = /(^|[^A-Za-z0-9])((?:["'])?authorization(?:["'])?\s*[:=]\s*(?:["'])?)(?:Bearer\s+)?[^"',&#\s}]+(?:#[^\s]*)?((?:["'])?)/gi;

function isSensitiveQueryKey(key) {
  return SENSITIVE_QUERY_KEY_RE.test(String(key || ""));
}

function redactUrlSensitiveValues(urlValue) {
  if (urlValue == null) return urlValue;
  const original = String(urlValue);
  let parsed;
  try {
    parsed = new URL(original);
  } catch {
    return redactLooseUrlSensitiveValues(original);
  }

  let changed = false;
  if (parsed.username) {
    parsed.username = REDACTED_VALUE;
    changed = true;
  }
  if (parsed.password) {
    parsed.password = REDACTED_VALUE;
    changed = true;
  }
  if (parsed.hash) {
    parsed.hash = "";
    changed = true;
  }

  for (const key of Array.from(parsed.searchParams.keys())) {
    // Query values are frequently tokens, emails, object IDs, signed URL
    // fragments, or one-time auth codes even when the key looks harmless.
    parsed.searchParams.set(key, REDACTED_VALUE);
    changed = true;
  }

  const redactedPath = redactSensitivePathSegments(parsed.pathname);
  if (redactedPath !== parsed.pathname) {
    parsed.pathname = redactedPath;
    changed = true;
  }

  return changed ? parsed.toString() : original;
}

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function isLikelySecretPathSegment(segment, index, segments) {
  const decoded = safeDecodeURIComponent(segment || "").trim();
  if (!decoded || decoded === REDACTED_VALUE) return false;
  const previous = safeDecodeURIComponent(segments[index - 1] || "").toLowerCase();
  const secretPredecessor = /^(?:api|api[_-]?key|key|keys|project|projects|rpc|token|tokens|v[0-9]+)$/.test(previous);
  const mixedAlphaNumeric = /[A-Za-z]/.test(decoded) && /[0-9]/.test(decoded);
  if (secretPredecessor && (decoded.length >= 8 || (decoded.length >= 6 && mixedAlphaNumeric))) return true;
  if (decoded.length >= 6 && /(?:token|key|secret|auth|credential)/i.test(decoded)) return true;
  if (/^0x[0-9a-f]+$/i.test(decoded)) return false;
  return decoded.length >= 24
    && mixedAlphaNumeric
    && /^[A-Za-z0-9._~%-]+$/.test(segment);
}

function redactSensitivePathSegments(pathname) {
  const segments = String(pathname || "").split("/");
  let changed = false;
  const redacted = segments.map((segment, index) => {
    if (isLikelySecretPathSegment(segment, index, segments)) {
      changed = true;
      return REDACTED_VALUE;
    }
    return segment;
  });
  return changed ? redacted.join("/") : pathname;
}

function redactTextSensitiveValues(value) {
  if (typeof value !== "string") return value;
  const urlRedacted = value.replace(/https?:\/\/[^\s)"'<>]+/g, (url) => redactUrlSensitiveValues(url));
  return redactLooseUrlSensitiveValues(urlRedacted);
}

function redactLooseUrlSensitiveValues(value) {
  return String(value)
    .replace(/\/\/([^/\s:@]+):([^@\s/]+)@/g, `//${REDACTED_VALUE}:${REDACTED_VALUE}@`)
    .replace(LOOSE_AUTHORIZATION_RE, `$1$2${REDACTED_VALUE}$3`)
    .replace(LOOSE_SECRET_ASSIGNMENT_RE, `$1$2${REDACTED_VALUE}$3`);
}

module.exports = {
  REDACTED_VALUE,
  isSensitiveQueryKey,
  redactTextSensitiveValues,
  redactUrlSensitiveValues,
};
