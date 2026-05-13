"use strict";

const fs = require("fs");
const path = require("path");
const {
  mcpPermissionForTool,
} = require("../../adapters/claude/config.js");
const {
  mcpToolNamesForRole,
  roleDefinition,
} = require("../../mcp/lib/role-model.js");
const {
  substituteCapabilityPackVerifierTable,
  substituteClaudeHunterPackCatalogue,
  substituteHandoffFieldLimits,
} = require("../../mcp/lib/capability-packs-rendering.js");
const {
  renderCapabilityPlaybookAppendix,
} = require("../../mcp/lib/capability-playbooks.js");
const { hunterRoleSpecs } = require("../../mcp/lib/capability-packs.js");

const DEFAULT_ROOT = path.join(__dirname, "..", "..");

const SUPPORTED_CLAUDE_AGENT_COLORS = Object.freeze([
  "blue",
  "green",
  "yellow",
  "magenta",
  "cyan",
  "purple",
  "orange",
  "pink",
  "red",
]);

const CLAUDE_LAUNCH_TEMPLATES = Object.freeze({
  "{{SPAWN_RECON_AGENT}}": [
    "```text",
    "deep_mode false: Agent(subagent_type: \"recon-agent\", name: \"recon\", prompt: \"DOMAIN=[domain] SESSION=~/bounty-agent-sessions/[domain]\")",
    "```",
  ].join("\n"),
  "{{SPAWN_DEEP_RECON_AGENT}}": [
    "```text",
    "deep_mode true: Agent(subagent_type: \"deep-recon-agent\", name: \"deep-recon\", prompt: \"DOMAIN=[domain] SESSION=~/bounty-agent-sessions/[domain]\")",
    "```",
  ].join("\n"),
  "{{SPAWN_SURFACE_ROUTER_AGENT}}": [
    "```text",
    "Agent(subagent_type: \"surface-router-agent\", name: \"surface-router\", prompt: \"Domain: [domain]. Session: ~/bounty-agent-sessions/[domain]. Confirm attack_surface.json exists and has surfaces, then call bounty_route_surfaces({ target_domain: '[domain]' }) and use .data. If routing fails or returns zero surfaces, report the error and stop. Otherwise return route count, capability-pack counts, and surface_routes_path.\")",
    "```",
  ].join("\n"),
  "{{SPAWN_HUNTER_AGENT}}": [
    "```text",
    "Agent(subagent_type: \"[assignment.hunter_agent]\", name: \"hunter-w[wave]-a[agent]\", run_in_background: true, prompt: \"",
    "Domain: [domain]",
    "Wave: w[wave]",
    "Agent: a[agent]",
    "Handoff token: [only this agent's handoff_token from wave-start result.data.assignments]",
    "Capability pack: [assignment.capability_pack]. Brief profile: [assignment.brief_profile]. Hunter agent: [assignment.hunter_agent]. Context budget: [assignment.context_budget].",
    "First action: call bounty_read_hunter_brief({ target_domain: '[domain]', wave: 'w[wave]', agent: 'a[agent]', egress_profile: '[egress_profile]', block_internal_hosts: [block_internal_hosts] }) and use .data, including run_context.context_budget and technique_packs.selected.",
    "Use surface_type, bug_class_hints, high_value_flows, evidence, surface_limits, coverage_summary, traffic_summary, audit_summary, circuit_breaker_summary, ranking_summary, intel_hints, static_scan_hints, and technique_packs.selected as prioritization inputs for this one assigned surface.",
    "Call bounty_read_technique_pack(mode=\"full\") only with target_domain/wave/agent/surface_id for relevant selected summaries, and bounty_log_technique_attempt for selections, skips, attempts, and outcomes. Before finalizing, ensure one completion-status technique attempt is logged for this surface.",
    "Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. Pass these exact values as egress_profile and block_internal_hosts on every bounty_http_scan call.",
    "Prefer traffic_summary endpoints, replay through bounty_http_scan with target_domain and egress_profile, log bounty_log_coverage after meaningful tests, and log before switching away from promising traffic-derived endpoints.",
    "New token-contract scans must use bounty_import_static_artifact then bounty_static_scan; never scan arbitrary paths.",
    "Checkpoint mode: [normal|paranoid|yolo].",
    "Auth: call bounty_list_auth_profiles, use attacker profile for primary testing, victim profile for IDOR/access-control confirmation, legacy auth as a single profile, or unauthenticated testing if auth is absent.",
    "Geofence rule: after 3+ consecutive INTERNAL_ERROR, timeout, connection reset, or network_unreachable_target results on target-owned hosts, log blocked/unreachable coverage and dead-end context, write or prepare the handoff, and request orchestrator egress rotation instead of retrying.",
    "Final: if no completion-status technique attempt has been logged, call bounty_log_technique_attempt first. Then call bounty_write_wave_handoff exactly once with target_domain, wave, agent, surface_id, surface_status, handoff_token, summary, optional chain_notes, content, and any dead_ends / waf_blocked_endpoints / lead_surface_ids. Then call bounty_finalize_hunter_run with target_domain, wave, agent, and surface_id. If finalization fails, fix the structured handoff or missing technique-attempt log and retry finalization. After finalization succeeds, emit `BOB_HUNTER_DONE {\"target_domain\":\"[domain]\",\"wave\":\"w[wave]\",\"agent\":\"a[agent]\",\"surface_id\":\"[surface_id]\"}` for Claude compatibility.",
    "\")",
    "```",
  ].join("\n"),
  // Smart-contract spawn bodies are rendered from the capability pack
  // manifest's `spawn` block — see `mcp/lib/capability-packs-rendering.js`.
  // Adding a new chain pack auto-extends the orchestrator catalogue at next
  // prompt regeneration; no per-pack template lives inline here anymore.
  "{{SPAWN_CHAIN_AGENT}}": [
    "```",
    "Agent(subagent_type: \"chain-builder\", name: \"chain\", prompt: \"Domain: [domain]. Egress profile: [egress_profile]. Session: ~/bounty-agent-sessions/[domain]. Read findings, wave handoffs, auth profiles, HTTP audit, and prior chain attempts through MCP. Test plausible chains with bounty_http_scan as needed, passing egress_profile on every scan, and write every outcome through bounty_write_chain_attempt with the required steps array. Do not read findings.md, chains.md, or markdown handoffs.\")",
    "```",
  ].join("\n"),
  "{{SPAWN_BRUTALIST_VERIFIER}}": [
    "```",
    "Agent(subagent_type: \"brutalist-verifier\", name: \"brutalist\", prompt: \"Session: ~/bounty-agent-sessions/[domain]. Egress profile: [egress_profile]. First call bounty_read_verification_context({ target_domain }); for v2 use current_attempt_id and snapshot_hash on writes and verification_replay context, cover exactly the snapshot findings, then write only through bounty_write_verification_round(round='brutalist').\")",
    "```",
  ].join("\n"),
  "{{SPAWN_BALANCED_VERIFIER}}": [
    "```",
    "Agent(subagent_type: \"balanced-verifier\", name: \"balanced\", prompt: \"Session: ~/bounty-agent-sessions/[domain]. Egress profile: [egress_profile]. First call bounty_read_verification_context({ target_domain }). If v1, read brutalist and preserve the legacy cascade. If v2, do not read brutalist or adjudication; use current_attempt_id and snapshot_hash, pass verification_replay context on replay tools, cover exactly snapshot findings, then write only through bounty_write_verification_round(round='balanced').\")",
    "```",
  ].join("\n"),
  "{{SPAWN_FINAL_VERIFIER}}": [
    "```",
    "Agent(subagent_type: \"final-verifier\", name: \"final-verify\", prompt: \"Session: ~/bounty-agent-sessions/[domain]. Egress profile: [egress_profile]. First call bounty_read_verification_context({ target_domain }). If v2, consume adjudication_context.adjudication_plan_hash from bounty_read_verification_context, do not compute diffs, pass verification_replay context on replay tools, and write round='final' with verification_attempt_id, verification_snapshot_hash, and adjudication_plan_hash. If v1, read balanced and use the legacy final cascade.\")",
    "```",
  ].join("\n"),
  "{{SPAWN_EVIDENCE_AGENT}}": [
    "```",
    "Agent(subagent_type: \"evidence-agent\", name: \"evidence\", prompt: \"Domain: [domain]. Egress profile: [egress_profile]. Session: ~/bounty-agent-sessions/[domain]. Call bounty_read_verification_context, bounty_read_findings, bounty_read_verification_round({ target_domain: '[domain]', round: 'final' }), bounty_read_http_audit, and bounty_list_auth_profiles; for v2 pass evidence_replay context on replay tools and rely on MCP to bind evidence to final_verification_hash; write only through bounty_write_evidence_packs.\")",
    "```",
  ].join("\n"),
  "{{SPAWN_GRADER_AGENT}}": [
    "```",
    "Agent(subagent_type: \"grader\", name: \"grader\", prompt: \"Domain: [domain]. Session: ~/bounty-agent-sessions/[domain]. Call bounty_read_findings, bounty_read_chain_attempts, bounty_read_verification_round({ target_domain: '[domain]', round: 'final' }), and bounty_read_evidence_packs, score survivors, then write only through bounty_write_grade_verdict.\")",
    "```",
  ].join("\n"),
  "{{SPAWN_REPORTER_AGENT}}": [
    "```",
    "Agent(subagent_type: \"report-writer\", name: \"reporter\", prompt: \"Domain: [domain]. Session: ~/bounty-agent-sessions/[domain]. Call bounty_read_findings, bounty_read_chain_attempts, bounty_read_verification_round({ target_domain: '[domain]', round: 'final' }), bounty_read_evidence_packs, and bounty_read_grade_verdict, then write the canonical ~/bounty-agent-sessions/[domain]/report.md. For SUBMIT, include only confirmed chain evidence. For SKIP/no reportables, write a concise no-findings closeout with verification, chain-attempt, and blocker summary.\")",
    "```",
  ].join("\n"),
});

const CLAUDE_ROLE_SPECS = Object.freeze({
  orchestrator: Object.freeze({
    role_id: "orchestrator",
    kind: "skill",
    output_path: path.join(".claude", "skills", "bob-hunt", "SKILL.md"),
    name: "bob-hunt",
    disable_model_invocation: true,
    argument_hint: "[target-url | resume <domain> [force-merge]] [--deep] [--egress <profile>]",
    local_tools: Object.freeze(["Task", "Read"]),
  }),
  status: Object.freeze({
    role_id: "status",
    kind: "skill",
    output_path: path.join(".claude", "skills", "bob-status", "SKILL.md"),
    name: "bob-status",
    disable_model_invocation: true,
    argument_hint: "[--last | <target_domain>]",
    local_tools: Object.freeze([
      "Read",
      "Glob",
      "Bash(find *)",
      "Bash(ls *)",
      "Bash(node *)",
      "Bash(stat *)",
      "Bash(test *)",
    ]),
  }),
  debug: Object.freeze({
    role_id: "debug",
    kind: "skill",
    output_path: path.join(".claude", "skills", "bob-debug", "SKILL.md"),
    name: "bob-debug",
    disable_model_invocation: true,
    argument_hint: "[--last | <target_domain>] [--deep]",
    local_tools: Object.freeze([
      "Read",
      "Glob",
      "Grep",
      "Bash(find *)",
      "Bash(ls *)",
      "Bash(stat *)",
      "Bash(test *)",
    ]),
  }),
  recon: Object.freeze({
    role_id: "recon",
    kind: "agent",
    output_path: path.join(".claude", "agents", "recon-agent.md"),
    name: "recon-agent",
    description: "Runs bounded normal recon \u2014 subdomain enum, live hosts, archived/crawled URLs, nuclei, JS/JWT extraction \u2014 and produces attack_surface.json",
    model: "opus",
    color: "cyan",
    local_tools: Object.freeze(["Bash", "Read", "Write", "Glob", "Grep"]),
  }),
  "deep-recon": Object.freeze({
    role_id: "deep-recon",
    kind: "agent",
    output_path: path.join(".claude", "agents", "deep-recon-agent.md"),
    name: "deep-recon-agent",
    description: "Runs bounded deep recon and produces compact attack_surface, deep-summary, and surface lead artifacts",
    model: "opus",
    color: "cyan",
    local_tools: Object.freeze(["Bash", "Read", "Write", "Glob", "Grep"]),
  }),
  "surface-router": Object.freeze({
    role_id: "surface-router",
    kind: "agent",
    output_path: path.join(".claude", "agents", "surface-router-agent.md"),
    name: "surface-router-agent",
    description: "Calls the MCP surface router after recon and reports the capability-pack summary",
    model: "sonnet",
    color: "blue",
    mcp_server: true,
    local_tools: Object.freeze(["Read"]),
  }),
  hunter: Object.freeze({
    role_id: "hunter",
    kind: "agent",
    output_path: path.join(".claude", "agents", "hunter-agent.md"),
    name: "hunter-agent",
    description: "Tests one attack surface for vulnerabilities \u2014 spawned per-surface with injected context from the orchestrator",
    model: "opus",
    color: "yellow",
    max_turns: 200,
    background: true,
    mcp_server: true,
    local_tools: Object.freeze(["Bash", "Read", "Grep", "Glob"]),
  }),
  // Per-chain hunter Claude role specs derived from HUNTER_ROLES. Multiple
  // capability packs that share a role_id (e.g. Aptos and Sui both route to
  // the Move hunter) collapse to a single Claude agent \u2014 matching
  // role-model.js + codex/role-specs.js. Adding a new hunter role
  // auto-extends this object without editing this file.
  ...Object.fromEntries(
    hunterRoleSpecs().map((role) => [
      role.role_id,
      Object.freeze({
        role_id: role.role_id,
        kind: "agent",
        output_path: path.join(".claude", "agents", `${role.name}.md`),
        name: role.name,
        description: role.description,
        model: "opus",
        color: role.color,
        max_turns: 200,
        background: true,
        mcp_server: true,
        local_tools: Object.freeze(["Bash", "Read", "Write", "Grep", "Glob"]),
      }),
    ]),
  ),
  chain: Object.freeze({
    role_id: "chain",
    kind: "agent",
    output_path: path.join(".claude", "agents", "chain-builder.md"),
    name: "chain-builder",
    description: "Analyzes proven findings for credible exploit chains that elevate severity",
    model: "opus",
    color: "purple",
    mcp_server: true,
    local_tools: Object.freeze(["Write"]),
  }),
  "brutalist-verifier": Object.freeze({
    role_id: "brutalist-verifier",
    kind: "agent",
    output_path: path.join(".claude", "agents", "brutalist-verifier.md"),
    name: "brutalist-verifier",
    description: "Round 1 verification \u2014 re-runs PoCs with maximum skepticism, checks severity inflation, filters non-bugs",
    model: "sonnet",
    color: "red",
    mcp_server: true,
    local_tools: Object.freeze(["Bash", "Read"]),
    // External @brutalist/mcp tools for the adversarial roast layer.
    // roast_cli_debate is intentionally excluded: the debate orchestrator
    // spawns multiple CLI agents and is too time-expensive for a per-finding
    // loop. Single-shot roast is the correct primitive here.
    extra_mcp_tools: Object.freeze([
      "mcp__brutalist__roast",
      "mcp__brutalist__brutalist_discover",
      "mcp__brutalist__cli_agent_roster",
    ]),
    // Brutalist MCP is optional \u2014 registered for availability but not gated.
    // Graceful fallback when missing is the brutalist-verifier prompt's job.
    extra_mcp_servers: Object.freeze(["brutalist"]),
  }),
  "balanced-verifier": Object.freeze({
    role_id: "balanced-verifier",
    kind: "agent",
    output_path: path.join(".claude", "agents", "balanced-verifier.md"),
    name: "balanced-verifier",
    description: "Round 2 verification \u2014 reviews brutalist decisions for false negatives and severity over-corrections",
    model: "opus",
    color: "blue",
    mcp_server: true,
    local_tools: Object.freeze(["Bash", "Read"]),
  }),
  "final-verifier": Object.freeze({
    role_id: "final-verifier",
    kind: "agent",
    output_path: path.join(".claude", "agents", "final-verifier.md"),
    name: "final-verifier",
    description: "Round 3 verification \u2014 re-runs only REPORTABLE findings with fresh requests as final confirmation",
    model: "sonnet",
    color: "green",
    mcp_server: true,
    local_tools: Object.freeze(["Bash"]),
  }),
  evidence: Object.freeze({
    role_id: "evidence",
    kind: "agent",
    output_path: path.join(".claude", "agents", "evidence-agent.md"),
    name: "evidence-agent",
    description: "Collects bounded pre-grade evidence packs for final reportable findings (HTTP via bounty_http_scan; SC via family runners)",
    model: "sonnet",
    color: "cyan",
    mcp_server: true,
    local_tools: Object.freeze([]),
  }),
  grader: Object.freeze({
    role_id: "grader",
    kind: "agent",
    output_path: path.join(".claude", "agents", "grader.md"),
    name: "grader",
    description: "Scores verified findings on 5 axes and issues SUBMIT/HOLD/SKIP verdict",
    model: "sonnet",
    color: "orange",
    mcp_server: true,
    local_tools: Object.freeze([]),
  }),
  reporter: Object.freeze({
    role_id: "reporter",
    kind: "agent",
    output_path: path.join(".claude", "agents", "report-writer.md"),
    name: "report-writer",
    description: "Generates submission-ready bug bounty report from verified and graded findings",
    model: "sonnet",
    color: "green",
    mcp_server: true,
    // Read is needed so the reporter can pick up validated chain narratives
    // from chains.md (chain-builder writes prose; no MCP tool exposes it).
    local_tools: Object.freeze(["Write", "Read"]),
  }),
});

function uniqueStrings(values) {
  return Array.from(new Set(values.filter((value) => typeof value === "string" && value.trim())));
}

function claudeMcpToolsForRole(roleId) {
  return mcpToolNamesForRole(roleId).map(mcpPermissionForTool);
}

function claudeAllowedToolsForRole(roleId) {
  const spec = CLAUDE_ROLE_SPECS[roleId];
  if (!spec) throw new Error(`Missing Claude role spec for ${roleId}`);
  return uniqueStrings([
    ...(spec.local_tools || []),
    ...claudeMcpToolsForRole(roleId),
    ...(spec.extra_mcp_tools || []),
  ]);
}

function renderSkillFrontmatter(spec) {
  const allowedTools = claudeAllowedToolsForRole(spec.role_id);
  return [
    "---",
    `name: ${spec.name}`,
    `disable-model-invocation: ${spec.disable_model_invocation ? "true" : "false"}`,
    `argument-hint: ${JSON.stringify(spec.argument_hint)}`,
    "allowed-tools:",
    ...allowedTools.map((tool) => `  - ${tool}`),
    "---",
  ].join("\n");
}

function renderAgentFrontmatter(spec) {
  const lines = [
    "---",
    `name: ${spec.name}`,
    `description: ${spec.description}`,
    `tools: ${claudeAllowedToolsForRole(spec.role_id).join(", ")}`,
    `model: ${spec.model}`,
    `color: ${spec.color}`,
  ];
  if (spec.max_turns) lines.push(`maxTurns: ${spec.max_turns}`);
  if (spec.background) lines.push("background: true");
  if (spec.mcp_server) {
    const mcpServers = uniqueStrings(["bountyagent", ...(spec.extra_mcp_servers || [])]);
    lines.push("mcpServers:");
    for (const server of mcpServers) lines.push(`  - ${server}`);
    // requiredMcpServers stays at bountyagent only — extra servers are optional
    // (graceful fallback). Bumping a server here makes the agent fail to spawn
    // when the server is missing, which we explicitly do not want for brutalist.
    lines.push("requiredMcpServers:", "  - bountyagent");
  }
  lines.push("---");
  return lines.join("\n");
}

function roleBody(roleId, { root = DEFAULT_ROOT } = {}) {
  const role = roleDefinition(roleId);
  const body = fs.readFileSync(path.join(root, role.prompt_body), "utf8").replace(/^\n+/, "");
  return renderClaudePromptBody(roleId, body, { root });
}

function renderClaudePromptBody(roleId, body, { root = DEFAULT_ROOT } = {}) {
  let document = body;
  if (roleId === "status") {
    document = document.replace(
      "{{STATUS_UPDATE_CACHE_COMMAND}}",
      'node "$CLAUDE_PROJECT_DIR/.claude/hooks/bob-update.js" status "$CLAUDE_PROJECT_DIR" --json',
    );
  }
  document = document
    .replace(/Use host-normal agent permissions by default/g, "Use normal Agent permissions by default")
    .replace(/Hunter waves MUST use the host's asynchronous\/background worker mechanism when available\./g, "Hunter waves MUST use `run_in_background: true`.")
    .replace(/host stop hooks are only adapter guardrails/g, "Claude `SubagentStop` is only an adapter guardrail")
    .replace(/Paste in the current agent session\./g, "Paste in Claude Code.");
  for (const [placeholder, template] of Object.entries(CLAUDE_LAUNCH_TEMPLATES)) {
    document = document.split(placeholder).join(template);
  }
  // Lazily-rendered, registry-driven placeholders. Substitution lives in
  // mcp/lib/capability-packs-rendering.js so the Codex renderer consumes
  // the same logic. Adding a pack to capability-packs.js updates every
  // consumer prompt at next regeneration.
  document = substituteCapabilityPackVerifierTable(document);
  document = substituteClaudeHunterPackCatalogue(document);
  document = substituteHandoffFieldLimits(document);
  if (roleId === "orchestrator") {
    document += renderCapabilityPlaybookAppendix({ root });
  }
  return document
    .replace(/\/bob:hunt/g, "/bob-hunt")
    .replace(/\/bob:status/g, "/bob-status")
    .replace(/\/bob:debug/g, "/bob-debug")
    .replace(/\/bob:update/g, "/bob-update");
}

function renderClaudeRole(roleId, options = {}) {
  const spec = CLAUDE_ROLE_SPECS[roleId];
  if (!spec) throw new Error(`Missing Claude role spec for ${roleId}`);
  const frontmatter = spec.kind === "skill"
    ? renderSkillFrontmatter(spec)
    : renderAgentFrontmatter(spec);
  const separator = spec.kind === "agent" ? "\n\n" : "\n";
  return `${frontmatter}${separator}${roleBody(roleId, options)}`;
}

function claudeRoleOutputPath(roleId, { root = DEFAULT_ROOT } = {}) {
  const spec = CLAUDE_ROLE_SPECS[roleId];
  if (!spec) throw new Error(`Missing Claude role spec for ${roleId}`);
  return path.join(root, spec.output_path);
}

function updateClaudeRoleFile(roleId, { check = false, root = DEFAULT_ROOT } = {}) {
  const filePath = claudeRoleOutputPath(roleId, { root });
  const document = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : null;
  const nextDocument = renderClaudeRole(roleId, { root });
  if (document === nextDocument) return false;
  if (check) {
    throw new Error(`${path.relative(root, filePath)} is stale; run node scripts/generate-claude-roles.js`);
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, nextDocument, "utf8");
  return true;
}

function updateClaudeRoleFiles({ check = false, root = DEFAULT_ROOT, roleIds = Object.keys(CLAUDE_ROLE_SPECS) } = {}) {
  let changed = false;
  for (const roleId of roleIds) {
    changed = updateClaudeRoleFile(roleId, { check, root }) || changed;
  }
  return changed;
}

module.exports = {
  CLAUDE_ROLE_SPECS,
  SUPPORTED_CLAUDE_AGENT_COLORS,
  claudeAllowedToolsForRole,
  claudeMcpToolsForRole,
  claudeRoleOutputPath,
  renderClaudePromptBody,
  renderClaudeRole,
  updateClaudeRoleFile,
  updateClaudeRoleFiles,
};
