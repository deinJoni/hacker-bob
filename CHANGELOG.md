# Changelog

## [Unreleased]

## [1.2.0] - 2026-05-01

### Smart-contract testing pipeline (Phase 0–6)

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
