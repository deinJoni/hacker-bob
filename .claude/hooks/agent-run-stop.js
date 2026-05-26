#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const MARKER = "BOB_AGENT_RUN_DONE";

function readStdin() {
  return fs.readFileSync(0, "utf8");
}

function textFromValue(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(textFromValue).filter(Boolean).join("\n");
  if (!value || typeof value !== "object") return "";
  if (typeof value.text === "string") return value.text;
  if (typeof value.content === "string") return value.content;
  if (Array.isArray(value.content)) return textFromValue(value.content);
  if (typeof value.message === "string") return value.message;
  return "";
}

function readTranscriptLastAssistant(transcriptPath) {
  if (!transcriptPath || !fs.existsSync(transcriptPath)) return "";
  const lines = fs.readFileSync(transcriptPath, "utf8").trim().split(/\r?\n/).filter(Boolean);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    try {
      const event = JSON.parse(lines[index]);
      const role = event.role || event.message?.role;
      if (role !== "assistant") continue;
      return textFromValue(event.message || event);
    } catch {}
  }
  return "";
}

function lastAssistantMessage(payload) {
  return textFromValue(
    payload.last_assistant_message ||
    payload.lastAssistantMessage ||
    payload.assistant_message ||
    payload.message,
  ) || readTranscriptLastAssistant(payload.transcript_path);
}

function parseMarker(message) {
  return parseMarkerWithStatus(message).marker;
}

function parseMarkerWithStatus(message) {
  const markerPattern = new RegExp(`${MARKER}\\s+(\\{[^\\n]+\\})`, "g");
  let match;
  let malformed = typeof message === "string" && message.includes(MARKER);
  while ((match = markerPattern.exec(message)) !== null) {
    try {
      const parsed = JSON.parse(match[1]);
      if (parsed && typeof parsed === "object") {
        return { marker: parsed, malformed: false };
      }
      malformed = true;
    } catch {
      malformed = true;
    }
  }
  return { marker: null, malformed };
}

function block(reason, telemetryInput = null) {
  recordAgentCompletionTelemetry(telemetryInput);
  console.error(reason);
  process.exit(2);
}

function projectRoot() {
  return process.env.BOB_PROJECT_DIR || process.env.CLAUDE_PROJECT_DIR || path.resolve(__dirname, "..", "..");
}

function loadAgentCompletion() {
  return require(path.join(projectRoot(), "mcp", "lib", "agent-run-completion.js"));
}

function recordAgentCompletionTelemetry(input) {
  if (!input) return;
  try {
    const completion = loadAgentCompletion();
    if (completion && typeof completion.recordAgentCompletionTelemetry === "function") {
      completion.recordAgentCompletionTelemetry(input, {
        transcript_path: input.transcript_path,
        telemetry_source: input.telemetry_source || "agent-run-stop",
        now: input.now,
      });
    }
  } catch {}
}

function markerValidationError(marker) {
  const completion = loadAgentCompletion();
  if (completion && typeof completion.isEvidenceMarker === "function" && completion.isEvidenceMarker(marker)) {
    return completion.evidenceMarkerValidationError(marker);
  }
  const missing = ["target_domain", "wave", "agent", "surface_id"].filter((field) => {
    return typeof marker[field] !== "string" || marker[field].trim() === "";
  });
  if (missing.length) {
    return {
      block_code: "malformed_marker",
      reason: `Evaluator final marker is missing required field(s): ${missing.join(", ")}`,
    };
  }
  if (!/^w[1-9][0-9]*$/.test(marker.wave)) {
    return {
      block_code: "malformed_marker",
      reason: "Evaluator final marker wave must look like positive wN",
    };
  }
  if (!/^a[1-9][0-9]*$/.test(marker.agent)) {
    return {
      block_code: "malformed_marker",
      reason: "Evaluator final marker agent must look like positive aN",
    };
  }
  return null;
}

function inspectEvidenceRun(marker) {
  const completion = loadAgentCompletion();
  return completion.evaluateEvidenceCompletion(marker);
}

function evidenceTelemetryInput({ payload, marker, now, status, block_code = null, handoff = null }) {
  const completion = loadAgentCompletion();
  return completion.evidenceTelemetryInput({
    marker,
    status,
    block_code,
    handoff,
    transcript_path: transcriptPathFromPayload(payload),
    now,
  });
}

function isEvidenceMarker(marker) {
  const completion = loadAgentCompletion();
  return completion && typeof completion.isEvidenceMarker === "function" && completion.isEvidenceMarker(marker);
}

function transcriptPathFromPayload(payload) {
  if (typeof payload.transcript_path === "string") return payload.transcript_path;
  if (typeof payload.transcriptPath === "string") return payload.transcriptPath;
  return null;
}

function finalizeMarker(marker, payload, now) {
  const completion = loadAgentCompletion();
  return completion.finalizeAgentCompletion(marker, {
    transcript_path: transcriptPathFromPayload(payload),
    telemetry_source: "agent-run-stop",
    now,
  });
}

function markerTelemetryInput({
  payload,
  marker = null,
  now,
  status,
  block_code = null,
  handoff = null,
}) {
  return {
    ok: status === "allowed",
    status,
    block_code,
    reason: null,
    marker,
    handoff,
    target_domain: marker?.target_domain,
    wave: marker?.wave,
    agent: marker?.agent,
    surface_id: marker?.surface_id,
    transcript_path: transcriptPathFromPayload(payload),
    telemetry_source: "agent-run-stop",
    now,
  };
}

function main() {
  const now = new Date();
  let payload = {};
  let marker = null;
  try {
    payload = JSON.parse(readStdin() || "{}");
  } catch {
    payload = {};
  }

  const message = lastAssistantMessage(payload);
  const markerResult = parseMarkerWithStatus(message);
  marker = markerResult.marker;
  if (!marker) {
    block(
      `Evaluator stop blocked: write the wave handoff with bounty_write_wave_handoff, then emit ${MARKER} {"target_domain":"...","wave":"wN","agent":"aN","surface_id":"..."}.`,
      markerTelemetryInput({
        payload,
        now,
        status: "blocked",
        block_code: markerResult.malformed ? "malformed_marker" : "missing_marker",
      }),
    );
  }

  const markerError = markerValidationError(marker);
  if (markerError) {
    if (isEvidenceMarker(marker)) {
      block(markerError.reason, evidenceTelemetryInput({
        payload, marker, now, status: "blocked", block_code: markerError.block_code,
      }));
    } else {
      block(markerError.reason, markerTelemetryInput({
        payload, marker, now, status: "blocked", block_code: markerError.block_code,
      }));
    }
  }

  if (isEvidenceMarker(marker)) {
    const evidenceResult = inspectEvidenceRun(marker);
    if (!evidenceResult.ok) {
      block(evidenceResult.reason, evidenceTelemetryInput({
        payload, marker, now, status: "blocked",
        block_code: evidenceResult.block_code,
      }));
    }
    recordAgentCompletionTelemetry(evidenceTelemetryInput({
      payload, marker, now, status: "allowed",
      handoff: evidenceResult.handoff,
    }));
    console.log(JSON.stringify({ ok: true, message: "post-report evidence run accepted" }));
    process.exit(0);
  }

  const finalization = finalizeMarker(marker, payload, now);
  if (!finalization.ok) {
    console.error(finalization.reason);
    process.exit(2);
  }
  console.log(JSON.stringify({ ok: true, message: finalization.reason }));
  process.exit(0);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    block(error.message || String(error));
  }
}

module.exports = {
  MARKER,
  lastAssistantMessage,
  parseMarker,
  parseMarkerWithStatus,
};
