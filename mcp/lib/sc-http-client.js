"use strict";

const https = require("https");
const net = require("net");
const {
  assertResolvedPublicRpcEndpoint,
  redactRpcEndpoint,
  redactRpcEndpointText,
} = require("./sc-egress-policy.js");

const DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; hacker-bob)";
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024;

let testRequestOverride = null;

function setSmartContractHttpRequestForTesting(requestFn) {
  testRequestOverride = typeof requestFn === "function" ? requestFn : null;
}

function normalizePinnedAddresses(addresses) {
  return (Array.isArray(addresses) ? addresses : [])
    .map((item) => {
      if (typeof item === "string") return { address: item, family: net.isIP(item) || 0 };
      if (!item || typeof item.address !== "string") return null;
      return { address: item.address, family: Number(item.family) || net.isIP(item.address) || 0 };
    })
    .filter((item) => item && item.address && item.family);
}

function stripIpv6Brackets(hostname) {
  return String(hostname || "").replace(/^\[|\]$/g, "");
}

function hostMatchesPinnedHost(requestedHost, pinnedHost) {
  return stripIpv6Brackets(requestedHost).toLowerCase() === stripIpv6Brackets(pinnedHost).toLowerCase();
}

function createPinnedLookup(pinnedHost, addresses) {
  const pinnedAddresses = normalizePinnedAddresses(addresses);
  return function pinnedLookup(hostname, options, callback) {
    const cb = typeof options === "function" ? options : callback;
    const opts = typeof options === "object" && options ? options : {};
    if (typeof cb !== "function") {
      throw new Error("lookup callback is required");
    }
    if (!hostMatchesPinnedHost(hostname, pinnedHost)) {
      const error = new Error(`SC HTTP pinned lookup refused unexpected host ${hostname}`);
      error.code = "ENOTFOUND";
      cb(error);
      return;
    }
    const requestedFamily = Number(opts.family) || 0;
    const candidates = requestedFamily
      ? pinnedAddresses.filter((item) => Number(item.family) === requestedFamily)
      : pinnedAddresses;
    if (candidates.length === 0) {
      const error = new Error(`SC HTTP pinned lookup has no address for family ${requestedFamily || "any"}`);
      error.code = "ENOTFOUND";
      cb(error);
      return;
    }
    if (opts.all === true) {
      cb(null, candidates.map((item) => ({ address: item.address, family: item.family })));
      return;
    }
    const selected = candidates[0];
    cb(null, selected.address, selected.family);
  };
}

function headerGetter(headers) {
  const raw = headers && typeof headers === "object" ? headers : {};
  return {
    raw,
    get(name) {
      const key = String(name || "").toLowerCase();
      const value = raw[key] !== undefined ? raw[key] : raw[name];
      if (Array.isArray(value)) return value.join(", ");
      if (value == null) return null;
      return String(value);
    },
  };
}

function normalizeHeaderObject(headers) {
  return {
    "User-Agent": DEFAULT_USER_AGENT,
    ...(headers && typeof headers === "object" ? headers : {}),
  };
}

function normalizeTestResponse(response) {
  if (!response || typeof response !== "object") {
    return { ok: false, status: 599, headers: headerGetter({}), text: "" };
  }
  const status = Number(response.status || response.statusCode || 0);
  const text = typeof response.text === "function"
    ? response.text()
    : (response.text != null ? response.text : "");
  return Promise.resolve(text).then((resolvedText) => ({
    ok: response.ok === true || (status >= 200 && status < 300),
    status,
    headers: response.headers && typeof response.headers.get === "function"
      ? response.headers
      : headerGetter(response.headers || {}),
    text: String(resolvedText || ""),
    pinned_addresses: response.pinned_addresses || null,
  }));
}

function requestViaHttps(options, body, { timeoutMs, maxBytes, displayUrl, requestImpl = https.request } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const byteLimit = Math.max(1, Number(maxBytes) || DEFAULT_MAX_RESPONSE_BYTES);
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };

    let req;
    try {
      req = requestImpl(options, (resp) => {
        const chunks = [];
        let received = 0;
        const finishResponse = () => {
          const status = Number(resp.statusCode || 0);
          finish(null, {
            ok: status >= 200 && status < 300,
            status,
            headers: headerGetter(resp.headers || {}),
            text: Buffer.concat(chunks).toString("utf8"),
          });
        };
        resp.on("data", (chunk) => {
          if (settled) return;
          const buffer = Buffer.from(chunk);
          const nextReceived = received + buffer.length;
          if (nextReceived > byteLimit) {
            const remaining = byteLimit - received;
            if (remaining > 0) {
              chunks.push(buffer.subarray(0, remaining));
            }
            const error = new Error(`SC HTTP response exceeded ${byteLimit} bytes for ${displayUrl}`);
            error.code = "ERESPONSETOOLARGE";
            error.response_truncated = true;
            finish(error);
            try { if (typeof resp.destroy === "function") resp.destroy(); } catch {}
            try { if (req && typeof req.destroy === "function") req.destroy(); } catch {}
            return;
          }
          const remaining = byteLimit - received;
          if (remaining > 0) {
            chunks.push(buffer);
          }
          received = nextReceived;
        });
        resp.on("end", finishResponse);
        resp.on("error", finish);
      });
    } catch (error) {
      finish(error);
      return;
    }

    req.on("error", (error) => {
      if (settled && error && error.code === "ECONNRESET") return;
      finish(error);
    });
    if (typeof req.setTimeout === "function") {
      req.setTimeout(timeoutMs, () => {
        const error = new Error(`SC HTTP request timed out for ${displayUrl}`);
        error.code = "ETIMEDOUT";
        try { req.destroy(error); } catch {}
        finish(error);
      });
    }
    if (body != null) {
      req.write(body);
    }
    req.end();
  });
}

async function requestPublicHttpsText(url, {
  method = "GET",
  headers = {},
  body = null,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxBytes = DEFAULT_MAX_RESPONSE_BYTES,
  lookup,
  dnsTimeoutMs,
  requestImpl,
} = {}) {
  const resolved = await assertResolvedPublicRpcEndpoint(url, { lookup, dnsTimeoutMs });
  const parsed = new URL(resolved.endpoint);
  const hostname = stripIpv6Brackets(parsed.hostname);
  const pinnedLookup = createPinnedLookup(resolved.host, resolved.addresses);
  const displayUrl = redactRpcEndpoint(resolved.endpoint);
  const headerObject = normalizeHeaderObject(headers);
  const requestOptions = {
    protocol: "https:",
    hostname,
    port: parsed.port || 443,
    method,
    path: `${parsed.pathname || "/"}${parsed.search || ""}`,
    headers: headerObject,
    lookup: pinnedLookup,
    agent: false,
  };
  if (!net.isIP(hostname)) {
    requestOptions.servername = hostname;
  }
  if (parsed.username || parsed.password) {
    requestOptions.auth = `${decodeURIComponent(parsed.username)}:${decodeURIComponent(parsed.password)}`;
  }

  if (testRequestOverride) {
    return normalizeTestResponse(await testRequestOverride(resolved.endpoint, {
      ...requestOptions,
      body,
      timeoutMs,
      maxBytes,
      displayUrl,
      pinned_addresses: resolved.addresses,
      pinned_lookup: pinnedLookup,
    }));
  }

  try {
    return await requestViaHttps(requestOptions, body, {
      timeoutMs: Math.max(1, Number(timeoutMs) || DEFAULT_TIMEOUT_MS),
      maxBytes: Math.max(1, Number(maxBytes) || DEFAULT_MAX_RESPONSE_BYTES),
      displayUrl,
      requestImpl,
    });
  } catch (error) {
    const message = redactRpcEndpointText(error && error.message ? error.message : String(error));
    const wrapped = new Error(`SC HTTP request failed for ${displayUrl}: ${message}`);
    wrapped.cause = error;
    throw wrapped;
  }
}

module.exports = {
  DEFAULT_MAX_RESPONSE_BYTES,
  DEFAULT_TIMEOUT_MS,
  createPinnedLookup,
  requestPublicHttpsText,
  setSmartContractHttpRequestForTesting,
};
