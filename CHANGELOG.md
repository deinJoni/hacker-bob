# Changelog

## [Unreleased]

### Capability-pack routing for hunter dispatch

- New `mcp/lib/capability-packs.js` defines a registry of capability packs (web + smart_contract_evm/svm/aptos/sui/substrate/cosmwasm) plus a `HUNTER_ROLES` map keyed by role_id. Each pack pins `hunter_agent`, `brief_profile`, `role_bundles`, and pack-keyed verifier/evidence/spawn dispatch metadata. `HUNTER_ROLES` is the single source of truth for hunter role display (name, description, color, role_bundles, prompt body filename).
- `bounty_route_surfaces` and the new `surface-router-agent` classify `attack_surface.json` entries into capability packs and write `surface-routes.json`. The orchestrator transitions RECON → AUTH only after routing succeeds. New `bounty_read_surface_routes` tool exposes the routes to verifier/chain/evidence/reporter.
- Hunter waves carry the route triple end-to-end: `bounty_start_wave` writes `capability_pack` + `hunter_agent` + `brief_profile` into each persisted assignment; `bounty_record_finding` persists them on every finding; `bounty_read_hunter_brief` dispatches by `brief_profile` to either the web builder (HTTP context, traffic/audit summaries, auth-profile hints) or the smart-contract builder (`bob_spec_status` filtered to the assigned surface plus `rpc_pool` for the surface's chain). Cross-cutting fields stay in both profiles.
- Verifier, evidence, and reporter prompts dispatch on `finding.capability_pack` and embed `{{CAPABILITY_PACK_VERIFIER_TABLE}}` rendered from the registry. The orchestrator skill embeds one canonical SC spawn template plus a `{{HUNTER_PACK_CATALOGUE}}` keyed by `capability_pack`. Per-chain dispatch lives in the pack manifest's `verifier`/`evidence`/`spawn` blocks; prompt sources do not branch on `chain_family`.
- Read-side backfill in `normalizeFindingRecord` reconstructs the pack triple from `surface_type` + `sc_evidence.chain_family` for legacy rows that lack the metadata, so downstream consumers never see null. The all-null assignment shortcut now throws on smart-contract surfaces; the surface classifier throws on missing/unsupported `chain_family`; `recordFinding` rejects `sc_evidence` when wave/agent are absent.
- MCP tool bundles are per-chain: legacy `hunter` bundle removed; new bundles `hunter-shared`, `hunter-web`, `hunter-evm`, `hunter-svm`, `hunter-move`, `hunter-substrate`, `hunter-cosmwasm`. SC hunter agents went from 38 tools to 10–13. `tool-registry.js` derives the chain-specific bundles from `HUNTER_ROLES` at module load. `SubagentStop` matchers now cover every registered hunter family.
- `mcp/lib/role-model.js`, `scripts/lib/claude-role-renderer.js`, `adapters/codex/role-specs.js`, and `scripts/lib/codex-role-renderer.js` derive their per-chain hunter entries from `HUNTER_ROLES`; adding a chain pack auto-extends every consumer. The Codex renderer's cross-cutting role list (`CODEX_CROSS_CUTTING_ROLE_IDS`) is explicit; per-chain ids are appended from the registry.
- Schema and runtime parity: `bounty_write_wave_handoff` `blocked_harness_runs[].kind` enum, the renderer's `BLOCKED_HARNESS_RUN_KINDS` constant, and `mcp/lib/waves.js BLOCKED_HARNESS_KIND_VALUES` mirror each other; tests assert the three-way mirror so a future schema or normalizer edit cannot diverge silently.
- `mcp/lib/capability-packs-rendering.js` exposes `renderCapabilityPackVerifierTable`, `substituteClaudeHunterPackCatalogue`, and `substituteCodexHunterPackCatalogue` so both renderers go through the same substitution helpers. Both Claude agents and Codex worker contracts ship complete tables; no rendered prompt artifact leaks an unsubstituted `{{...}}` placeholder.
- New tests: pack ↔ role-bundle consistency, hunter MCP-tool budget ≤16, every SC pack ships a complete spawn block, rendered orchestrator catalogue lists every SC pack exactly once, no chain-specific identifier appears outside the registry, `HUNTER_ROLES` drives every consumer, no renderer leaks a raw placeholder, verifier/evidence registry resolution per pack, chain_family branching budget per verifier source.

### Adapter wrapper packages — `hacker-bob-cc` (Claude Code) and `hacker-bob-codex`

- `hacker-bob-cc` is now an explicit Claude Code adapter wrapper: its bin is `hacker-bob-cc`, and it injects `--adapter claude` as the default before delegating to the canonical `hacker-bob` CLI. Explicit `--adapter <id>` is preserved so the wrapper does not block multi-adapter installs.
- New parallel package `hacker-bob-codex`: `npx hacker-bob-codex install <project-dir>` installs the Codex adapter without needing `--adapter codex`.
- The canonical `hacker-bob` package and its `hacker-bob` binary are unchanged. Both wrappers depend on the canonical `hacker-bob@<version>`; framework updates ship from the canonical package and the wrapper deps bump in lock-step.
- Bin rename: the previous `hacker-bob-cc` package exposed a `hacker-bob` binary (collided with canonical when globally installed). It now exposes `hacker-bob-cc`. Use `npx hacker-bob-cc install <dir>` or `npx hacker-bob-codex install <dir>`.
- `scripts/release-check.js` now drives both wrappers from a `WRAPPER_PACKAGES` registry — adding a third wrapper means appending one entry. Each wrapper's bin source is grepped for the adapter literal so a future maintainer who renames the wrapper without updating its adapter pin gets a release-check failure.
- Tests added: per-wrapper version sync, package shape (bin name matches package name, files list contains only the bin, `dependencies.hacker-bob` pinned), bin script content (pushes `--adapter <id>`, respects explicit `--adapter`, delegates via `require`), and npm-pack output stays under 3 KB.

### Capability-pack routing (merged from main)

- Added `mcp/lib/capability-packs.js` with a `web` pack and five smart-contract packs (`smart_contract_evm`, `smart_contract_svm`, `smart_contract_move`, `smart_contract_substrate`, `smart_contract_cosmwasm`). Each pack pins a `hunter_agent`, `brief_profile`, and role bundle; SC packs route by `surface.chain_family` (Aptos and Sui both go to `hunter-move-agent`).
- Added `bounty_route_surfaces` MCP tool plus `mcp/lib/surface-router.js` and a new `surface-router-agent` (rendered for both Claude and Codex). The orchestrator now spawns the router after recon and only transitions RECON → AUTH after `surface-routes.json` is written.
- `bounty_start_wave` now writes `capability_pack`, `hunter_agent`, and `brief_profile` into each persisted assignment and returns them in `result.data.assignments[]`. Hunters are spawned with `subagent_type: assignment.hunter_agent`; the orchestrator no longer branches by `chain_family` itself.
- Web tools moved to a new `hunter-web` role bundle so the `hunter-agent` agent receives a web-only allowlist; SC tools stay in `hunter` and SC hunter agents (`hunter-evm-agent`, etc.) keep their full chain tooling.
- `SubagentStop` hooks are now derived from `hunterAgentNamesForCapabilityPacks()` so each registered hunter family gets its own stop hook automatically; adding a pack adds a hook.
- `bounty_read_hunter_brief` now omits `bob_spec_status` and `rpc_pool` for web profiles and includes `run_context.capability_pack` / `hunter_agent` / `brief_profile` so hunters can confirm their routing.

## [1.2.0] - 2026-05-02

### Deep recon mode (merged from main)

- Added a `--deep` flag to `/bob-hunt` and `$bob-hunt` that swaps the normal recon agent for a new `deep-recon-agent` running broader passive discovery (subfinder, amass, assetfinder, chaos, crt.sh, archived URL collection, JS endpoint extraction, takeover candidates).
- Added compact `surface-leads.json` with three new MCP tools — `bounty_record_surface_leads`, `bounty_read_surface_leads`, `bounty_promote_surface_leads` — so hunters can log durable leads in deep mode and the orchestrator can promote ranked leads back into `attack_surface.json` for new waves.
- `state.deep_mode` persists on resume, so `/bob-hunt resume` keeps deep behavior even when `--deep` is omitted.

### Session summary, read guard, operator notes (merged from main)

- Added `bounty_read_session_summary` MCP tool returning a compact, structured summary (phase, blockers, evidence status, next action) so orchestrator/status/debug avoid bulky raw `state.json` reads.
- Added `.claude/hooks/session-read-guard.sh` PreToolUse hook that blocks Bash/Read against denylisted session artifacts (`state.json`, `findings.jsonl`, `report.md`, etc.) under `~/bounty-agent-sessions/`. Only `attack_surface.json` is allowed for direct reads.
- Added `mcp/lib/sensitive-material.js` validation that rejects auth headers, cookies, JWTs, and other secrets at the input boundary of any mutating MCP tool.
- Added `bounty_set_operator_note` and `bounty_clear_operator_note` for bounded non-secret operator instructions stored in session state.
- Verifier/grader/reporter/evidence prompts now require compact summary-only final responses with `BOB_VERIFY_DONE` / `BOB_CHAIN_DONE` / `BOB_GRADE_DONE` / `BOB_REPORT_DONE` / `BOB_EVIDENCE_DONE` markers and explicit forbids on raw requests, responses, cookies, tokens, or authorization headers in the final message.

### Offline guide and architecture site (merged from main)

- Added `docs/hacker-bob-offline-guide.md` (operator manual) and `docs/hacker-bob-offline-guide.pdf` (printable form).
- Added `docs/bob-architecture-event.html` (single-page architecture overview) and `docs/hacker-bob-github-qr.png`.
- Added `site/` (React + Vite marketing site source).

### Smart-contract testing pipeline

- Added six chain-family runners with allowlisted, sandboxed test execution: `bounty_foundry_run` and `bounty_halmos_run` (EVM), `bounty_anchor_run` (SVM), `bounty_aptos_run` and `bounty_sui_run` (Move), `bounty_substrate_run` (ink! / `cargo test`), and `bounty_cosmwasm_run` (cw-multi-test / `cargo test`). Each runner accepts a manifest path and a single test selector, parses framework output into structured pass/fail records, and caps captured stdout to bounded excerpts.
- Added 14 read-only chain-data fetch tools across the same six families for live state lookups during HUNT/CHAIN/VERIFY.
- Added new `hunter-substrate` and `hunter-cosmwasm` agent roles with bug-class catalogs (e.g., `set_code_hash_unauthorized`, `caller_spoof`, `lazy_storage_layout_drift`, `chain_extension_unauthenticated`, `migrate_msg_open`, `submessage_reply_misuse`, `indexed_map_key_collision`).
- Extended findings normalization to validate SS58 (substrate) and bech32 (cosmwasm) addresses with their actual checksum/length rules; rejected EVM-shape addresses on Move families.
- Added a dedicated `evidence-agent` role that dispatches by `surface_type`: HTTP findings go through `bounty_http_scan`; SC findings go through the appropriate family runner with a `sample_type` mapping (`evm_foundry_run`, `svm_anchor_run`, `aptos_move_test`, `sui_move_test`, `substrate_ink_test`, `cosmwasm_cw_multi_test`).
- Phase gates now treat SC surfaces consistently: HUNT→CHAIN respects `partial` + `bypass_attempts`; CHAIN→VERIFY clears via `bounty_write_chain_attempt` per pivot; VERIFY→GRADE clears via SC-aware evidence packs.

### Adapter auto-detection on install / update / doctor / uninstall

- `hacker-bob install <project-dir>` no longer requires `--adapter`. When the flag is omitted, Bob picks an adapter using a layered detector: (1) prior install metadata in `.hacker-bob/install.json`, (2) host environment markers (`$CLAUDE_PROJECT_DIR`, `$CODEX_HOME`), (3) project files (`.claude/`, `.codex/plugins/`, `.agents/plugins/`, `.mcp.json`), or (4) host CLI on `PATH`. Claude remains the final fallback. The chosen adapter and reason are logged to stderr.
- **Behavior change (no-flag `install` and `update`):** previously, missing `--adapter` always defaulted to `claude`. Reinstalling a Codex-only project would silently install Claude *alongside* it; updating that project would refresh only Claude. With auto-detection, reinstalls and updates preserve the existing adapter mix from `.hacker-bob/install.json`.
- **Behavior change (no-flag `doctor`):** previously, missing `--adapter` ran only Claude checks. Now `doctor` runs the checks for every adapter recorded in install metadata.
- **Behavior change (no-flag `uninstall`):** previously, missing `--adapter` removed only Claude. Now `uninstall` removes every adapter recorded in install metadata. The default `--dry-run` behavior is unchanged: explicit `--yes` is still required to remove files.
- Added `detectAdapterId(projectDir, options)` to `adapters/index.js` as a pure, host-injectable function with a fixed precedence order; added `resolveInstallAdapters` and `resolveLifecycleAdapters` helpers in `scripts/install.js` and `scripts/lifecycle.js` so install/update/doctor/uninstall share the same adapter resolution path.

### Brutalist verifier wired to `@brutalist/mcp`

- Added the external `@brutalist/mcp` server (npm) to the install configuration of every adapter as an optional MCP server alongside `bountyagent`. Claude registers it via `.mcp.json` merge; Codex ships it in the bundled plugin `.mcp.json`; generic-mcp merges it into the operator's root `.mcp.json`.
- Updated `prompts/roles/brutalist-verifier.md` so the brutalist verifier calls `mcp__brutalist__roast` per finding for an additional adversarial pass after the PoC re-run, with explicit graceful fallback when the MCP is unavailable. The roast verdict folds into `reasoning`; the PoC re-run still drives `disposition` and `severity`.
- The brutalist tools allowlist excludes `mcp__brutalist__roast_cli_debate` — the debate orchestrator is too time-expensive for a per-finding loop. Only `roast`, `brutalist_discover`, and `cli_agent_roster` are exposed.
- `requiredMcpServers` for brutalist-verifier remains `bountyagent`-only so the agent can spawn even when `@brutalist/mcp` is absent.
- Added an info-level doctor check (`claude_mcp_brutalist_optional`, `generic_mcp_brutalist_optional`) reporting brutalist-server presence; never errors on absence.

### AI-agent install reframing (mirrors main v1.1.8 / v1.1.9 intents, adapted for the multi-adapter architecture)

- Added a new `### For AI Coding Agents` subsection at the top of the README Quickstart that treats a pasted repository URL as an install request, defaults the install target to `$PWD`, and tells AI agents not to ask "what do you want to do?" when the current directory is a normal project.
- Documented the auto-detection precedence and the per-adapter verification commands (claude: `claude mcp list` shows `bountyagent`; codex: `~/.codex/skills/bob-hunt/SKILL.md` exists; generic-mcp: `.mcp.json` contains `mcpServers.bountyagent`).
- Added a "do not install into the Hacker Bob source tree" guard for AI agents.
- Added a `## MCP Troubleshooting` section covering the `Cannot find module './tools/index.js'` failure mode and three adapter-specific reload failures, plus a callout that `bountyagent` is the expected MCP server namespace and not a stale skill name.
- Tagline edit: "point him at a domain" → "point him at an authorized target".
- Ignored `.claude/bob/{VERSION,install.json,egress-profiles.json}` so installing Bob into a hacker-bob source checkout does not leak machine-specific install metadata into commits.

### Tests

- Added `test/adapter-detection.test.js` with 14 unit tests covering all four detection layers and precedence.
- Added 7 new CLI integration tests covering: fresh-install default fallback, project-artifact-driven codex selection, reinstall preservation, multi-adapter no-flag uninstall, multi-adapter no-flag doctor, no-flag update preserving prior adapters, and generic-mcp `.mcp.json` presence after install.

## [1.1.9] - 2026-04-29

- Simplified README onboarding for AI coding agents: a pasted repository URL is now explicitly treated as an install request.
- Changed the AI-agent default path to install into the current working directory with `npx -y hacker-bob-cc@latest install "$PWD"`, then run the MCP load check and `claude mcp list`.
- Added guidance that agents should not ask "what do you want to do?" when the current directory is a normal project/workspace.
- Kept source-clone installation as a fallback for npm outages or explicit source-install requests.

## [1.1.8] - 2026-04-29

- Reordered the README quickstart so AI coding agents see the repository-link install flow before the human install path.
- Clarified that the cloned Hacker Bob repository is normally the install source and that Bob must be installed into the Claude Code project where `/bob-hunt` will run.
- Documented that `bountyagent` is the expected internal MCP server namespace behind Bob's `bounty_*` tools, while `/bob-*` commands remain the user-facing surface.
- Added MCP troubleshooting for stale or incomplete installs that fail with `Cannot find module './tools/index.js'`.
- Ignored local `.claude/bob/` install metadata so source checkouts used for packaging do not accidentally include machine-specific install state.

## [1.1.7] - 2026-04-28

- Added operator-controlled egress profiles under `.claude/bob/`, including a safe example config, installer-preserved operator config, and `/bob-egress` management commands for listing, adding, testing, enabling, disabling, and removing profiles.
- Extended `bounty_http_scan` with optional `egress_profile` support, proxy-backed `http`, `https`, `socks5`, and `socks5h` scanning through `proxy-agent`, early profile validation, credential redaction, and audit fields for `egress_profile` and `egress_region`.
- Added geofence/reachability visibility for repeated first-party network failures through HTTP audit summaries, circuit-breaker summaries, pipeline analytics, `/bob-status`, `/bob-debug --deep`, and hunter briefs.
- Updated `/bob-hunt` so `--egress <profile>` is passed through AUTH, hunter, chain, verifier, and evidence prompts while keeping profile switching explicit and operator-controlled.
- Updated install, doctor, uninstall, packaging, and release checks so the egress command, helper, config example, runtime dependency, and package metadata are shipped and validated.
- Changed `/bob-hunt` so zero-reportable VERIFY results still close through SKIP grading and a no-findings report instead of stopping at VERIFY.
- Added hunter guardrails for repeated `INTERNAL_ERROR` host failures and explicit `chain_notes` length truncation before wave handoff writes.
- Added required force-merge reasons to wave reconciliation and pipeline analytics so debug attribution survives without transcript context.

## [1.1.6] - 2026-04-27

- Added bounded evidence pack visibility to `/bob-status` so operators can see whether final reportable findings have valid, missing/invalid, skipped, or unknown evidence readiness.
- Documented the `VERIFY -> GRADE` evidence-pack gate without adding a new FSM phase: final reportable findings need valid evidence packs after final verification and before grading or reporting.
- Tightened prompt-contract coverage so `/bob-status` may read evidence packs for confirmation while remaining read-only and non-networked.

## [1.1.5] - 2026-04-26

- Fixed `/bob-update` and the `bob-status` skill body so the `node .../.claude/hooks/bob-update.js` invocations resolve when Claude Code does not propagate `CLAUDE_PROJECT_DIR` into the assistant's Bash tool subprocess (observed on Claude Code 2.1.119). Both surfaces now use `${CLAUDE_PROJECT_DIR:-$PWD}` so the path falls back to the Bash tool's working directory, which is the project root, while still preferring the env var when the harness exports it.
- Added prompt-contract regression assertions pinning the `${CLAUDE_PROJECT_DIR:-$PWD}` form in `bob-update.md` and `bob-status/SKILL.md` so a future edit cannot silently reintroduce the bare `$CLAUDE_PROJECT_DIR` that produced `MODULE_NOT_FOUND /.claude/hooks/bob-update.js`.

## [1.1.4] - 2026-04-27

- Fixed the installer to copy the shipped `testing/policy-replay/` harness into target projects so `/bob-debug` replay escalation can run from installed workspaces.
- Added doctor and install-smoke coverage for the policy replay harness files.

## [1.1.3] - 2026-04-27

- Added a shipped `testing/policy-replay/` harness for diagnosing Bob policy/refusal regressions with the Claude Agent SDK and local Claude OAuth.
- Updated `/bob-debug` so post-session QA can detect policy/refusal stuck signals, run bounded local replay/tune diagnostics, and suggest a reviewed prompt change without editing prompts or mutating session state.
- Added structured chain-attempt artifacts and read/write MCP tools so CHAIN, VERIFY, GRADE, REPORT, analytics, and hooks consume machine-readable chain evidence instead of markdown.
- Added CI-safe policy replay tests, package coverage for the replay harness, and release packaging of the harness scripts and sample fixture.
- Deprecated the older raw Anthropic API refusal replay helpers in favor of the maintained policy replay case format.

## [1.1.2] - 2026-04-26

- Renamed the three skill directories and frontmatter `name:` fields to hyphen form (`bob-hunt`, `bob-status`, `bob-debug`). v1.1.1 used colon-form `name:` (`bob:hunt`), which Claude Code v2.1.119 rejects as invalid (`name:` only accepts lowercase letters, numbers, and hyphens), so it silently fell back to the directory name and registered the slashes as `/bountyagent`, `/bountyagentstatus`, `/bountyagentdebug` — meaning typing `/bob:hunt` got rewritten to `/bountyagent` on enter.
- Renamed `/bob:update` to `/bob-update` and moved the command from `.claude/commands/bob/update.md` to `.claude/commands/bob-update.md` so all four slash commands share the same hyphen scheme.
- Installer and `dev-sync.sh` now proactively delete the legacy `bountyagent`, `bountyagentstatus`, `bountyagentdebug` skill directories and the entire `commands/bob/` subdirectory on upgrade, so users coming from `<=1.1.1` do not keep orphan slash entries.
- Uninstall manifest sweeps the new layout, the v1.1.1 layout, and the v1.1.0 layout so old installs still clean up entirely.
- Updated README, CLAUDE.md, FIRST_RUN, ROADMAP, TROUBLESHOOTING, and media docs to use the new `/bob-hunt`, `/bob-status`, `/bob-debug`, `/bob-update` slashes.

## [1.1.1] - 2026-04-25

- Fixed duplicate slash entries (`/bob-hunt` + `/bob:hunt`, etc.) in the Claude Code menu by giving the three skills colon-form `name:` frontmatter (`bob:hunt`, `bob:status`, `bob:debug`) so each skill IS its own slash command.
- Removed redundant command shims `commands/bob/{hunt,status,debug}.md`; only `commands/bob/update.md` remains because no skill backs `/bob:update`.
- Installer and `dev-sync.sh` now proactively delete the legacy hunt/status/debug shims on upgrade so users coming from <=1.1.0 do not retain orphan files that would re-introduce the duplicates.
- Uninstall manifest sweeps both the current shim layout and the legacy three-shim layout so old installs still clean up entirely.

## [1.1.0] - 2026-04-26

- Added `hacker-bob doctor <project-dir> [--json]` for read-only install diagnostics.
- Added `hacker-bob uninstall <project-dir> [--dry-run] [--yes] [--json]` for conservative removal of Bob-managed files and config entries.
- Added the `hacker-bob` npm alias package while keeping `hacker-bob-cc` canonical.
- Updated release publishing to publish both npm packages with provenance.
- Added Quickstart, troubleshooting docs, release notes, and bug report diagnostics guidance.
- Optimized the README image to reduce npm package size.

## [1.0.1] - 2026-04-26

- Clarified install docs and CLI help: Bob installs into one project directory per command, while global npm install only installs the `hacker-bob` CLI.

## [1.0.0] - 2026-04-26

- Initial public `hacker-bob-cc` npm package with `hacker-bob` CLI install and update commands.
- Added `/bob:update`, passive update cache checks, installed version metadata, and status update hints.
- Preserved the source `install.sh` path as a compatibility wrapper.
