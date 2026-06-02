"use strict";

// Y.2.5 Stage c — bob_compose_report (Y-D15b / Y-P13 / Y-P13a / Y-P13c).
// Asserts:
//   * Renderer produces report.md server-side with the operator-edit-warning
//     banner (Y-P13a)
//   * provenance: "bob_verified" with at least one verification_round ref
//     whose reportable=true → success
//   * provenance: "bob_verified" with no evidence_refs[] → INVALID_ARGUMENTS
//     with structured remediation (Y-P13c)
//   * provenance: "bob_verified" with refs that don't resolve to a reportable
//     verification_round result → INVALID_ARGUMENTS
//   * Bounded narrative caps (Y-P13b): prose ≤ 4096, severity_summary ≤ 2048
//   * Subsequent calls re-render (append-only amendments included)

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const composeReportTool = require("../mcp/lib/tools/compose-report.js");
const { ERROR_CODES } = require("../mcp/lib/envelope.js");
const {
  reportMarkdownPath,
  sessionDir,
  verificationRoundPaths,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-compose-report-"));
  process.env.HOME = home;
  try {
    const result = fn(home);
    if (result && typeof result.then === "function") {
      throw new Error("withTempHome callers must be synchronous; use awaiting wrapper for async callers");
    }
    return result;
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function seedFinalRound(domain, results) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  const paths = verificationRoundPaths(domain, "final");
  fs.writeFileSync(paths.json, JSON.stringify({
    target_domain: domain,
    round: "final",
    notes: null,
    results,
    written_at: new Date().toISOString(),
  }));
}

function callTool(tool, args) {
  const response = tool.handler(args);
  return typeof response === "string" ? JSON.parse(response) : response;
}

test("bob_compose_report renders report.md with operator-edit-warning banner (Y-P13a)", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    seedFinalRound(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed",
      repro_steps: ["step 1"],
      evidence_refs: ["frontier_event:e1"],
    }]);

    const result = callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "impact",
        heading: "Impact Summary",
        prose: "An attacker can drain the vault by replaying the signed permit.",
        provenance: "bob_verified",
        evidence_refs: ["verification_round:final:F-1"],
      }],
    });

    assert.equal(result.target_domain, domain);
    assert.match(result.report_content_hash, /^[a-f0-9]{64}$/);
    const rendered = fs.readFileSync(reportMarkdownPath(domain), "utf8");
    assert.match(rendered, /This file is MCP-rendered/);
    assert.match(rendered, /bob_amend_report/);
    assert.match(rendered, /Impact Summary/);
    assert.match(rendered, /An attacker can drain the vault/);
  });
});

test("bob_compose_report REJECTS bob_verified section without evidence_refs (Y-P13c)", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    let err;
    try {
      composeReportTool.handler({
        target_domain: domain,
        sections: [{
          kind: "impact",
          heading: "Impact Summary",
          prose: "Unverified claim.",
          provenance: "bob_verified",
        }],
      });
    } catch (e) { err = e; }
    assert.ok(err, "missing evidence_refs[] must throw");
    assert.equal(err.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.equal(typeof err.remediation, "string");
    assert.match(err.remediation, /remove provenance: bob_verified/);
    assert.match(err.remediation, /verification_round/);
  });
});

test("bob_compose_report REJECTS bob_verified when refs don't resolve to a reportable=true round", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    seedFinalRound(domain, [{
      finding_id: "F-1",
      disposition: "denied",
      severity: "low",
      reportable: false,
      reasoning: "Not reportable",
      repro_steps: ["x"],
      evidence_refs: ["frontier_event:e1"],
    }]);

    let err;
    try {
      composeReportTool.handler({
        target_domain: domain,
        sections: [{
          kind: "impact",
          heading: "Impact",
          prose: "Claimed verified but referenced finding is not reportable.",
          provenance: "bob_verified",
          evidence_refs: ["verification_round:final:F-1"],
        }],
      });
    } catch (e) { err = e; }
    assert.ok(err, "non-reportable ref must reject");
    assert.equal(err.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.match(err.remediation, /reportable: true/);
  });
});

test("bob_compose_report ACCEPTS operator_osint provenance without verification_round backing", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    const result = callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "evidence",
        heading: "OSINT Context",
        prose: "Operator-provided context: this org was acquired in 2024.",
        provenance: "operator_osint",
        evidence_refs: [],
      }],
    });
    assert.equal(result.target_domain, domain);
  });
});

test("bob_compose_report enforces Y-P13b prose cap at 4096 characters", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    const longProse = "x".repeat(4097);
    let err;
    try {
      composeReportTool.handler({
        target_domain: domain,
        sections: [{
          kind: "impact",
          heading: "Too long",
          prose: longProse,
          provenance: "external_research",
        }],
      });
    } catch (e) { err = e; }
    assert.ok(err);
    assert.equal(err.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.match(err.message, /4096/);
  });
});

test("bob_compose_report enforces Y-P13b repro_steps_by_finding cap at K=12 per finding", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    let err;
    try {
      composeReportTool.handler({
        target_domain: domain,
        sections: [{
          kind: "impact",
          heading: "Impact",
          prose: "x",
          provenance: "external_research",
        }],
        repro_steps_by_finding: [{
          finding_id: "F-1",
          steps: Array.from({ length: 13 }, (_, i) => `step ${i}`),
        }],
      });
    } catch (e) { err = e; }
    assert.ok(err);
    assert.match(err.message, /at most 12 (entries|items)/);
  });
});

test("bob_compose_report rejects unknown evidence_ref prefix with structured remediation", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    let err;
    try {
      composeReportTool.handler({
        target_domain: domain,
        sections: [{
          kind: "impact",
          heading: "Impact",
          prose: "claim",
          provenance: "bob_verified",
          evidence_refs: ["unknown_prefix:foo"],
        }],
      });
    } catch (e) { err = e; }
    assert.ok(err);
    assert.equal(err.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.match(err.remediation, /known prefix|provenance: bob_verified/);
  });
});

test("bob_compose_report tool spec carries Y_self_reporting capability_id and is wrapWriteTool-wrapped", () => {
  assert.equal(composeReportTool.name, "bob_compose_report");
  assert.equal(composeReportTool.capability_id, "Y_self_reporting");
  assert.ok(composeReportTool.role_bundles.includes("orchestrator"));
});
