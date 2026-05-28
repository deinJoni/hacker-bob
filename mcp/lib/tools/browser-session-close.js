"use strict";

const {
  browserSessions,
  envelopeFromError,
  envelopeSuccess,
  patchrightUnavailableEnvelope,
  safeSessionId,
  safeTargetDomain,
} = require("../browser-tools-shared.js");

const BROWSER_BUNDLES = ["evaluator-shared", "surface-discovery", "deep-surface-discovery"];

async function handler(args = {}) {
  if (!browserSessions.isPatchrightAvailable()) {
    return JSON.stringify(patchrightUnavailableEnvelope());
  }
  try {
    const targetDomain = safeTargetDomain(args.target_domain);
    const sessionId = safeSessionId(args.session_id);
    const entry = browserSessions.getSession(sessionId);
    if (entry && !entry.closed && entry.targetDomain !== targetDomain) {
      const err = new Error(
        `browser_session_domain_mismatch: session ${sessionId} is bound to ${entry.targetDomain}, not ${targetDomain}`,
      );
      err.code = "browser_session_domain_mismatch";
      throw err;
    }
    const result = await browserSessions.closeSession(sessionId, "explicit_close");
    return envelopeSuccess(result);
  } catch (err) {
    return envelopeFromError(err);
  }
}

module.exports = Object.freeze({
  name: "bob_browser_session_close",
  description:
    "Close a browser session, terminating the subprocess. Always call this when finished with a session — idle and hard timeouts will reap stragglers but the explicit close releases the per-domain concurrency slot immediately.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      session_id: { type: "string" },
    },
    required: ["target_domain", "session_id"],
  },
  handler,
  role_bundles: BROWSER_BUNDLES,
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: true,
  scope_required: true,
  sensitive_output: false,
  session_artifacts_written: [],
});
