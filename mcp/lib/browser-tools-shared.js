"use strict";

// Shared envelope + scope-check helpers for the bob_browser_* MCP tool family.
// Each tool wrapper validates its target_domain, optionally validates a URL
// against scope (defense-in-depth on top of the driver's own check), then
// routes through browser-sessions.js. Failures convert to a structured JSON
// envelope rather than throwing into the registry — keeps the agent's view
// stable when patchright is absent or a session has been reaped.

const {
  assertNonEmptyString,
} = require("./validation.js");
const browserSessions = require("./browser-sessions.js");

// Defense-in-depth: the wrapper rejects the same forbidden patterns the driver
// rejects, so we never even spawn the subprocess for an obviously bad expr.
//
// Two classes of agent-controlled bypass are blocked:
//   (1) Direct network IO from page context: XMLHttpRequest, fetch(),
//       navigator.sendBeacon(), EventSource, WebSocket. Agents should use
//       bob_http_scan or bob_browser_navigate for HTTP traffic.
//   (2) Top-level navigation writes: location.href=, location.assign,
//       location.replace, window.location=, document.location=, window.open,
//       top.location / parent.location. The agent-controlled navigation gate
//       is bob_browser_navigate (scope-checked); without these patterns the
//       evaluate sandbox would let the agent point the browser anywhere.
//
// Page-initiated subresource loads (CDN bundles, anti-bot fingerprint scripts,
// OAuth callbacks the server redirects to, analytics, etc.) are NOT the
// agent's choice — the page itself wired them in HTML/JS. They run unblocked.
const FORBIDDEN_EVAL_PATTERN =
  /XMLHttpRequest|fetch\(|navigator\.sendBeacon|new\s+EventSource|new\s+WebSocket|window\.open\(|(?:window|document|top|parent)\.location\s*=|location\.(?:href|assign|replace)/i;

function errorEnvelope(code, message, extra = {}) {
  return {
    ok: false,
    error: { code, message, ...extra },
  };
}

function patchrightUnavailableEnvelope() {
  return errorEnvelope(
    "patchright_unavailable",
    "Optional dependency patchright is not installed; the bob_browser_* tools cannot start a session. Run `npm install` and `npx patchright install chromium` to enable browser-shaped surface coverage.",
  );
}

function safeSessionId(value) {
  return assertNonEmptyString(value, "session_id");
}

function safeTargetDomain(value) {
  return assertNonEmptyString(value, "target_domain");
}

function assertExpressionSandbox(expression) {
  if (typeof expression !== "string" || !expression.trim()) {
    const err = new Error("expression must be a non-empty string");
    err.code = "invalid_arguments";
    throw err;
  }
  if (FORBIDDEN_EVAL_PATTERN.test(expression)) {
    const err = new Error(
      "evaluate_sandbox_violation: expression contains forbidden network-IO pattern (XMLHttpRequest, fetch(, sendBeacon, EventSource, WebSocket). Use bob_http_scan or bob_browser_navigate for HTTP traffic; the expression sandbox blocks page-context network calls.",
    );
    err.code = "evaluate_sandbox_violation";
    throw err;
  }
  return expression;
}

async function callBrowser(command, sessionId, args = {}) {
  return browserSessions.sendCommand(sessionId, command, args);
}

function ensureSessionMatchesDomain(sessionId, targetDomain) {
  const entry = browserSessions.getSession(sessionId);
  if (!entry) {
    const err = new Error(`browser_session_not_found: ${sessionId}`);
    err.code = "browser_session_not_found";
    throw err;
  }
  if (entry.closed) {
    const err = new Error(`browser_session_closed: ${sessionId}`);
    err.code = "browser_session_closed";
    throw err;
  }
  if (entry.targetDomain !== targetDomain) {
    const err = new Error(
      `browser_session_domain_mismatch: session ${sessionId} is bound to ${entry.targetDomain}, not ${targetDomain}`,
    );
    err.code = "browser_session_domain_mismatch";
    throw err;
  }
  return entry;
}

function envelopeSuccess(fields) {
  return JSON.stringify({ ok: true, ...fields });
}

function envelopeFromError(err) {
  return JSON.stringify(
    errorEnvelope(
      err && err.code ? err.code : "browser_tool_error",
      err && err.message ? err.message : String(err),
    ),
  );
}

module.exports = {
  FORBIDDEN_EVAL_PATTERN,
  assertExpressionSandbox,
  browserSessions,
  callBrowser,
  ensureSessionMatchesDomain,
  envelopeFromError,
  envelopeSuccess,
  errorEnvelope,
  patchrightUnavailableEnvelope,
  safeSessionId,
  safeTargetDomain,
};
