"use strict";

const crypto = require("crypto");

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }
  if (isPlainObject(value)) {
    const result = Object.create(null);
    for (const key of Object.keys(value).sort()) {
      if (value[key] === undefined) continue;
      Object.defineProperty(result, key, {
        value: canonicalize(value[key]),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return result;
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function hashCanonicalJson(value) {
  return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function documentHashExcluding(document, fields) {
  const copy = cloneJson(document);
  for (const field of fields) delete copy[field];
  return hashCanonicalJson(copy);
}

function finalVerificationHash(document) {
  return documentHashExcluding(document, ["final_verification_hash"]);
}

function adjudicationHashPayload(document) {
  const payload = cloneJson(document);
  delete payload.adjudication_plan_hash;
  delete payload.built_at;
  return payload;
}

function computeAdjudicationPlanHash(document) {
  return hashCanonicalJson(adjudicationHashPayload(document));
}

module.exports = {
  adjudicationHashPayload,
  canonicalJson,
  canonicalize,
  cloneJson,
  computeAdjudicationPlanHash,
  documentHashExcluding,
  finalVerificationHash,
  hashCanonicalJson,
  isPlainObject,
};
