"use strict";

const crypto = require("crypto");
const fs = require("fs");
const {
  handoffSigningKeyPath,
} = require("./paths.js");
const {
  writeFileExclusiveAtomic,
} = require("./storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");

const HANDOFF_SIGNING_KEY_VERSION = 1;
const HANDOFF_SIGNING_KEY_BYTES = 32;

function decodeSigningKeyDocument(document, filePath) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Malformed handoff signing key: ${filePath}`);
  }
  const keys = Object.keys(document).sort();
  if (keys.length !== 2 || keys[0] !== "key" || keys[1] !== "version") {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Malformed handoff signing key schema in ${filePath}`);
  }
  if (document.version !== HANDOFF_SIGNING_KEY_VERSION) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Unsupported handoff signing key version in ${filePath}`);
  }
  if (typeof document.key !== "string" || !/^[A-Za-z0-9_-]+$/.test(document.key)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Malformed handoff signing key material in ${filePath}`);
  }
  const key = Buffer.from(document.key, "base64url");
  if (key.length !== HANDOFF_SIGNING_KEY_BYTES) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Malformed handoff signing key length in ${filePath}`);
  }
  return key;
}

function readSigningKeyDocumentSecure(filePath) {
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let fd;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
    const stats = fs.fstatSync(fd);
    if (!stats.isFile()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Handoff signing key is not a regular file: ${filePath}`);
    }
    if ((stats.mode & 0o077) !== 0) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Handoff signing key must be owner-only 0600: ${filePath}`);
    }
    if (stats.nlink !== 1) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Handoff signing key must not have hard links: ${filePath}`);
    }
    return JSON.parse(fs.readFileSync(fd, "utf8"));
  } catch (error) {
    if (error instanceof ToolError) throw error;
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Could not read handoff signing key: ${filePath} (${error.message || String(error)})`,
    );
  } finally {
    if (fd != null) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

function readHandoffSigningKey(domain) {
  const filePath = handoffSigningKeyPath(domain);
  if (!fs.existsSync(filePath)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Missing handoff signing key: ${filePath}`);
  }
  return decodeSigningKeyDocument(readSigningKeyDocumentSecure(filePath), filePath);
}

function ensureHandoffSigningKey(domain) {
  const filePath = handoffSigningKeyPath(domain);
  const document = {
    version: HANDOFF_SIGNING_KEY_VERSION,
    key: crypto.randomBytes(HANDOFF_SIGNING_KEY_BYTES).toString("base64url"),
  };
  const wrote = writeFileExclusiveAtomic(filePath, `${JSON.stringify(document, null, 2)}\n`, { mode: 0o600 });
  if (!wrote) {
    return readHandoffSigningKey(domain);
  }
  return decodeSigningKeyDocument(document, filePath);
}

module.exports = {
  HANDOFF_SIGNING_KEY_BYTES,
  HANDOFF_SIGNING_KEY_VERSION,
  ensureHandoffSigningKey,
  readHandoffSigningKey,
};
