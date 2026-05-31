"use strict";

const { recordSurfaceLeads } = require("../surface-leads.js");

const LEAD_SCHEMA = {
  type: "object",
  properties: {
    id: { type: "string" },
    title: { type: "string" },
    source: { type: "string" },
    source_wave: { type: "string" },
    source_agent: { type: "string" },
    source_surface_id: { type: "string" },
    hosts: { type: "array", items: { type: "string" } },
    endpoints: { type: "array", items: { type: "string" } },
    interesting_params: { type: "array", items: { type: "string" } },
    tech_stack: { type: "array", items: { type: "string" } },
    nuclei_hits: { type: "array", items: { type: "string" } },
    priority: { type: "string", enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"] },
    surface_type: { type: "string" },
    bug_class_hints: { type: "array", items: { type: "string" } },
    high_value_flows: { type: "array", items: { type: "string" } },
    evidence: { type: "array", items: { type: "string" } },
    confidence: { type: "string", enum: ["high", "medium", "low"] },
    score: { type: "number", minimum: 0, maximum: 100 },
    promote: { type: "boolean" },
  },
};

module.exports = Object.freeze({
  name: "bounty_record_surface_leads",
  description:
    "Append compact discovered attack-surface leads to session-owned surface-leads.json for later promotion into wave-assignable surfaces.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      source: { type: "string" },
      source_wave: { type: "string" },
      source_agent: { type: "string" },
      source_surface_id: { type: "string" },
      leads: {
        type: "array",
        minItems: 1,
        maxItems: 25,
        items: LEAD_SCHEMA,
      },
    },
    required: ["target_domain", "leads"],
  },
  handler: recordSurfaceLeads,
  role_bundles: ["hunter-web", "orchestrator"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["surface-leads.json"],
});
