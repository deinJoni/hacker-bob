"use strict";

const {
  assertSafeResolvedRequestUrl,
} = require("../safe-fetch.js");
const {
  browserSessions,
  envelopeFromError,
  envelopeSuccess,
  patchrightUnavailableEnvelope,
  safeTargetDomain,
} = require("../browser-tools-shared.js");
const {
  assertNonEmptyString,
} = require("../validation.js");

const BROWSER_BUNDLES = ["evaluator-shared", "surface-discovery", "deep-surface-discovery"];

async function handler(args = {}) {
  if (!browserSessions.isPatchrightAvailable()) {
    return JSON.stringify(patchrightUnavailableEnvelope());
  }
  try {
    const targetDomain = safeTargetDomain(args.target_domain);
    const targetUrl = assertNonEmptyString(args.target_url, "target_url");
    try {
      await assertSafeResolvedRequestUrl(targetUrl, targetDomain, {
        blockInternalHosts: false,
      });
    } catch (err) {
      const wrapped = new Error(`scope_blocked: ${err && err.message ? err.message : err}`);
      wrapped.code = "scope_blocked";
      throw wrapped;
    }
    const result = await browserSessions.startSession({
      targetDomain,
      targetUrl,
      headless: args.headless === true,
    });
    return envelopeSuccess(result);
  } catch (err) {
    return envelopeFromError(err);
  }
}

module.exports = Object.freeze({
  name: "bob_browser_session_start",
  description:
    "Start a long-running Patchright (stealth Playwright fork) browser session for the given in-scope target_url. Returns a session_id used by the other bob_browser_* tools. Sessions persist across MCP calls until explicit close or idle/hard timeout. Anti-detection stack: channel=chrome, no --enable-automation flag, ignoreDefaultArgs=['--enable-automation'], headed by default, human-like delays between interactions. Returns patchright_unavailable when the optional browser dependency is missing.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string", description: "Session domain anchor; the URL host must equal this or be a subdomain." },
      target_url: { type: "string", description: "Initial in-scope URL the browser will eventually navigate to. Scope-checked via the same validator that gates bob_http_scan." },
      headless: { type: "boolean", description: "Run headless. Default false (headed) to preserve anti-detection fingerprint." },
    },
    required: ["target_domain", "target_url"],
  },
  handler,
  role_bundles: BROWSER_BUNDLES,
  mutating: true,
  global_preapproval: false,
  network_access: true,
  browser_access: true,
  scope_required: true,
  scope_url_fields: ["target_url"],
  sensitive_output: false,
  session_artifacts_written: [],
});
