<p align="center">
  <img src="docs/hacker-bob.png" alt="Hacker Bob" width="320" />
</p>

<h1 align="center">Meet Hacker Bob</h1>

<p align="center"><i>Portable autonomous bug bounty MCP framework with host adapters.</i></p>

<p align="center">
  <a href="https://github.com/vmihalis/hacker-bob/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/vmihalis/hacker-bob/actions/workflows/ci.yml/badge.svg" /></a>
  <a href="https://www.npmjs.com/package/hacker-bob"><img alt="hacker-bob on npm" src="https://img.shields.io/npm/v/hacker-bob?label=hacker-bob" /></a>
  <a href="https://www.npmjs.com/package/hacker-bob-cc"><img alt="hacker-bob-cc compatibility package on npm" src="https://img.shields.io/npm/v/hacker-bob-cc?label=hacker-bob-cc" /></a>
  <a href="https://www.npmjs.com/package/hacker-bob-codex"><img alt="hacker-bob-codex compatibility package on npm" src="https://img.shields.io/npm/v/hacker-bob-codex?label=hacker-bob-codex" /></a>
  <a href="LICENSE"><img alt="Apache-2.0 license" src="https://img.shields.io/github/license/vmihalis/hacker-bob" /></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/vmihalis/hacker-bob"><img alt="OpenSSF Scorecard" src="https://api.securityscorecards.dev/projects/github.com/vmihalis/hacker-bob/badge" /></a>
</p>

Bob is an autonomous bug bounty hunting framework built around a local MCP runtime. You point him at an authorized target, and the runtime coordinates recon, hunting, verification, grading, reporting, telemetry, and local evidence.

You go to bed. Bob does not.

## Quickstart

### For AI Coding Agents

If a user pastes this repository URL into an AI coding agent, treat it as an install request. Install Bob into the current working directory by default — that is the project the user is already in. Do not ask "what do you want to do?" when the current directory is a normal project. Ask only if the current directory is the Hacker Bob source tree itself, a home directory, or a root directory.

```bash
npx -y hacker-bob@latest install "$PWD"
node -e "require('./mcp/server.js'); console.log('MCP ok')"
```

Verify the host integration based on the adapter Bob picked. The install command logs the chosen adapter and reason to stderr (e.g., `hacker-bob: auto-selected adapter claude (reason: project_dot_claude)`). Pass `--adapter claude|codex|generic-mcp` to override.

| Adapter | Verification |
|---|---|
| `claude` | `claude mcp list` should show `bountyagent` connected. Then fully restart Claude Code in this directory and run `/bob-hunt target.com`. |
| `codex` | `~/.codex/skills/bob-hunt/SKILL.md` should exist. Then fully restart Codex and run `$bob-hunt target.com`. |
| `generic-mcp` | `.mcp.json` should contain `mcpServers.bountyagent` pointing at this project's `mcp/server.js`. Then reload your MCP host. |

**Adapter auto-selection.** When `--adapter` is omitted, Bob picks one based on (1) prior install metadata in `.hacker-bob/install.json`, (2) host environment markers (`$CLAUDE_PROJECT_DIR`, `$CODEX_HOME`), (3) project files (`.claude/`, `.codex/plugins/`, `.agents/plugins/`, `.mcp.json`), or (4) host CLI on `PATH`. Claude is the final fallback.

**MCP namespace.** Bob's MCP server is registered as `bountyagent`, so its tools appear as `mcp__bountyagent__bounty_*` in Claude Code. That name is expected. The user-facing commands renamed to `/bob-*` (Claude) and `$bob-*` (Codex), but the MCP server name stayed `bountyagent` for backward-compatible tool wiring. Do not "fix" the namespace.

**Do not install into the Hacker Bob source tree.** If the install target contains `adapters/`, `mcp/server.js`, and `prompts/roles/` at its root, the user has handed you the source checkout. Ask for the actual target project before continuing.

### Before You Run

Bob is autonomous and can send real requests, use local tools, attempt signup and authentication flows, and interact with third-party, internal, or private hosts when instructed by Bob's agents. Only run Bob when you have explicit authorization for the target, accounts, testing methods, automation, and any third-party systems involved.

The `claude --dangerously-skip-permissions` examples below disable Claude Code permission prompts. Use that mode only in a dedicated workspace for authorized security testing.

Create or choose one project directory, then install Bob into that directory. Claude is the default host adapter:

```bash
npx -y hacker-bob@latest install /path/to/your/project
cd /path/to/your/project
claude --dangerously-skip-permissions --effort max
```

Then run:

```
/bob-hunt target.com
```

## Install

Bob installs into **one project directory per command**. The install target is the project you will later open from your host CLI. The installer always writes the shared MCP runtime into `mcp/` and neutral Bob resources into `.hacker-bob/`; host adapters add their own integration files.

Recommended one-off Claude install:

```bash
npx -y hacker-bob@latest install /path/to/your/project
```

`hacker-bob` is the canonical npm package. `hacker-bob-cc` and `hacker-bob-codex` are small compatibility wrappers that delegate to the matching `hacker-bob` version while pinning the Claude or Codex adapter by default.

Adapter-specific installs:

```bash
npx -y hacker-bob@latest install /path/to/your/project --adapter claude
npx -y hacker-bob@latest install /path/to/your/project --adapter codex
npx -y hacker-bob@latest install /path/to/your/project --adapter generic-mcp
npx -y hacker-bob@latest install /path/to/your/project --adapter all
```

The Claude adapter writes `.claude/` commands, skills, agents, hooks, statusline, and settings. The Codex adapter installs direct `$bob-*` skills into `~/.codex/skills`, writes a local `.codex/plugins/hacker-bob` plugin for MCP wiring and command wrappers, writes a repo-local `.agents/plugins/marketplace.json` entry, and activates the plugin in Codex's cache/config for MCP discovery. The generic MCP adapter writes root `.mcp.json` plus prompt docs under `.hacker-bob/generic-mcp/`.

Run installs as many times as you like. They are idempotent and preserve unrelated host config. Bob is polite about other people's settings.

If you prefer a global command, install the CLI once:

```bash
npm install -g hacker-bob
hacker-bob install /path/to/your/project
```

Global npm install only puts the `hacker-bob` command on your `PATH`; it does **not** install Bob into every directory. To use Bob in another project, run `hacker-bob install /path/to/that/project --adapter <adapter>` for that project too.

The adapter wrapper packages provide pinned entrypoints when you want the host choice encoded in the package name:

```bash
npm install -g hacker-bob-cc
hacker-bob-cc install /path/to/your/project

npm install -g hacker-bob-codex
hacker-bob-codex install /path/to/your/project
```

Source installs still work for contributors:

```bash
git clone https://github.com/vmihalis/hacker-bob.git
cd hacker-bob
./install.sh /path/to/your/project
```

## Usage

```bash
cd /path/to/your/project
claude --dangerously-skip-permissions --effort max
```

Then in Claude Code, use the Claude slash commands:

```
/bob-hunt target.com         # full autonomous run
/bob-hunt target.com --deep  # broader script-heavy recon and lead promotion
/bob-hunt resume target.com  # pick up where you left off
/bob-status                 # quick latest-session status
/bob-debug                   # review the latest local session
/bob-update                  # preview and install the latest Bob release
/bob-export                  # create a post-release improvement bundle
```

That's it. Now go make coffee.

In Codex, restart in the target project and use `$bob-hunt`, `$bob-status`, `$bob-debug`, `$bob-update`, and `$bob-export`. In generic MCP hosts, connect to `mcp/server.js` through the generated `.mcp.json` entry and follow `.hacker-bob/generic-mcp/hacker-bob.md`.

For install diagnostics, run:

```bash
hacker-bob doctor /path/to/your/project
hacker-bob doctor /path/to/your/project --adapter codex
```

For common setup issues, see [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).
For a copy-paste first-run flow, see [`docs/FIRST_RUN.md`](docs/FIRST_RUN.md).

## Updates

Run `/bob-update` inside Claude Code from the project where Bob is installed. The command checks the installed version, previews relevant `CHANGELOG.md` entries, asks before changing files, installs with:

```bash
npx -y hacker-bob@latest install "$CLAUDE_PROJECT_DIR"
```

After an update, fully restart Claude Code in that project. Bob also checks for available updates once per day on `SessionStart` and stores the result in `~/.cache/hacker-bob/update-checks/`; the statusline and `/bob-status` only read that local cache.

In Codex, use `$bob-update`. In generic MCP hosts, run `hacker-bob update /path/to/your/project --adapter generic-mcp` from a shell and reload the host's MCP config.

## Post-Release Export

After running Bob on one or more sessions with the installed release, run `/bob-export` in Claude or `$bob-export` in Codex. Bob writes a timestamped bundle under `~/bounty-agent-telemetry/release-bundles/v<version>/` with a fresh-agent prompt, manifest, summaries, filtered telemetry, and source paths for improving the next release. The export is read-only and release-scoped; it does not start hunts or touch targets.

## How Bob hunts

```
RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT
```

1. **RECON** — Bob sniffs around. Normal mode collects subdomains, live hosts, archived and Katana-crawled URLs, nuclei hits, JWT-shaped candidates, and JS hints. Add `--deep` for broader discovery, DNS/TLS enrichment, bounded Subzy takeover checks, JS endpoint clustering, takeover/CVE-style lead hints, and promoted follow-up surfaces.
2. **AUTH** — Bob tries to sign up. If he can, he keeps a victim and an attacker account in his pocket. If he can't, he shrugs and hunts unauthenticated.
3. **HUNT** — Parallel hunter agents fan out, one per attack surface. They are not gentle.
4. **CHAIN** — Bob squints at the findings and asks "wait, can I combine these into something worse?"
5. **VERIFY** — Three rounds of arguing with himself: skeptical Bob, balanced Bob, and final-PoC Bob. Most "bugs" do not survive. After final verification, Bob collects bounded evidence packs for every final reportable finding.
6. **GRADE** — 5-axis scoring. Bob decides: SUBMIT, HOLD, or "this is not a bug, please stop." Valid evidence packs are required before grading or reporting when final reportable findings exist.
7. **REPORT** — A clean, submission-ready writeup with PoCs and evidence. No "could potentially". No "an attacker may". Just receipts.

MCP ranking computes runtime priority for status views and hunter briefs. `/bob-status` also shows evidence readiness so missing or invalid evidence packs are visible before grade/report work. Imports and public-intel fetches do not rewrite `attack_surface.json`.

## Requirements

- One supported host: Claude Code, Codex, or another MCP-capable host
- Node.js 20 or newer
- For Claude: [Claude Code](https://docs.anthropic.com/en/docs/claude-code) with a model suitable for long autonomous workflows
- `curl` and `python3` (already on your machine, probably)
- Optional sidekicks for deeper recon:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/owasp-amass/amass/v4/...@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/PentestPad/subzy@latest
git clone https://github.com/ticarpi/jwt_tool ~/jwt_tool
python3 -m pip install -r ~/jwt_tool/requirements.txt
```

If those aren't installed, Bob just works with what he's got and doesn't complain.

## MCP Troubleshooting

If the MCP runtime isn't loading or Bob's tools don't appear in your host CLI, work through these failure modes before reinstalling.

### `Cannot find module './tools/index.js'`

The MCP runtime is partially copied: `mcp/lib/tool-registry.js` exists but `mcp/lib/tools/` is missing or empty. This affects upgrades from older Bob versions where the install copied a stale subset. Reinstall to refresh:

```bash
npx -y hacker-bob@latest install /path/to/your/project
cd /path/to/your/project
node -e "require('./mcp/server.js'); console.log('MCP ok')"
```

### `bountyagent` does not appear in `claude mcp list` (Claude adapter)

The MCP wiring lives in `.mcp.json`. After install, fully restart Claude Code in the project directory; the `claude` CLI must reload `.mcp.json` to pick up the new server. If `bountyagent` still does not appear, run `hacker-bob doctor /path/to/your/project` and check for `claude_mcp_server_config` errors.

### `$bob-hunt` does not resolve in Codex (Codex adapter)

The Codex plugin manifest lives in `.codex/plugins/hacker-bob/.codex-plugin/plugin.json`, and Codex skills install into `~/.codex/skills/bob-{hunt,status,debug,update}/`. If `$bob-hunt` is not recognized:

```bash
ls ~/.codex/skills/bob-hunt/SKILL.md
ls .codex/plugins/hacker-bob/.codex-plugin/plugin.json
```

If either is missing, reinstall with `--adapter codex`. Then fully restart Codex.

### MCP server entry missing or stale (generic-mcp adapter)

Open `.mcp.json` and confirm it contains an `mcpServers.bountyagent` entry pointing at this project's `mcp/server.js`. If it does, the host has not reloaded its MCP config — follow your host's reload procedure. If it does not, reinstall with `--adapter generic-mcp`.

### `bountyagent` looks like a stale skill name

It is not a skill name. The MCP server namespace stayed `bountyagent` so existing tool wiring (`mcp__bountyagent__bounty_*`) continues to work after the user-facing slash and skill commands renamed to `/bob-*` and `$bob-*`. Seeing `bountyagent` in `claude mcp list` or `.mcp.json` is correct.

### `brutalist` server missing from `claude mcp list`

The brutalist verifier uses the external [`@brutalist/mcp`](https://www.npmjs.com/package/@brutalist/mcp) server for an adversarial roast pass per finding. The installer registers it as an optional MCP server alongside `bountyagent`, but it is **not required** — the brutalist verifier falls back to PoC-only verification with `brutalist roast unavailable` noted in the verification reasoning. If you want the roast layer back, ensure your `.mcp.json` contains `mcpServers.brutalist` (`npx -y @brutalist/mcp@latest`) and reload your host CLI.

## Security Model

Bob installs into a local project directory. The installer writes Bob-managed shared files under `mcp/` and `.hacker-bob/`, then writes adapter-specific host files such as `.claude/`, `.codex/plugins/hacker-bob`, `.agents/plugins/marketplace.json`, and `.mcp.json`. The Codex adapter also writes Bob-managed activation entries under `$CODEX_HOME` or `~/.codex` so Codex can load the local plugin. These files should be reviewed like any other automation that can run commands from your host CLI.

Bob stores local run state and evidence under `~/bounty-agent-sessions`. Treat that directory as sensitive: it can contain target names, request metadata, notes, and report evidence from authorized testing.

During a hunt, Bob may make outbound HTTP requests, run local recon tools you have installed, import local HTTP/static artifacts, and ask host agents to reason over the results. Optional third-party services, such as browser automation dependencies, CAPTCHA solving, public-intel sources, or external recon tools, are only used when you configure the relevant dependencies or credentials.

Bob logs and audits some activity, including local session artifacts and MCP HTTP scan records, but those records are for operator review. Bob does not verify authorization, enforce bug bounty scope, or guarantee containment.

By default, Bob does not block localhost, private networks, internal hostnames, or cloud metadata-style hostnames. This keeps exploration flexible for local labs, VPN/internal scopes, SSRF chains, and user-authorized pivots. Supported MCP HTTP calls can reject those destinations when you pass `block_internal_hosts: true`.

The npm packages are published through the GitHub release workflow with npm provenance. `hacker-bob` is the canonical package; `hacker-bob-cc` and `hacker-bob-codex` are small adapter wrapper packages that depend on the matching canonical version.

Bob will scan the targets you provide and may touch other hosts during authorized chaining or proof-of-concept work. You are responsible for running it only against domains, applications, accounts, and infrastructure that you own or are explicitly authorized to test, and for following each program's scope and rules of engagement.

## Development

If you're hacking on Bob himself and want to push the current repo into a test workspace:

```bash
./dev-sync.sh /absolute/path/to/test-workspace
./dev-sync.sh /absolute/path/to/test-workspace --adapter codex
```

It backs up host config, runs the local installer with the selected adapter, recopies the MCP runtime and neutral resources, and runs adapter-appropriate smoke checks. You can find the maintainer workflow in [`CLAUDE.md`](CLAUDE.md).

## A note on scope

Bob will scan whatever you tell him to scan. **You are responsible for making sure the target is in scope and that you have permission.** Bob is enthusiastic, not licensed.

Hunt responsibly. Read the program's policy. Read [`DISCLAIMER.md`](DISCLAIMER.md) before you point him at anything.

## Contributing

Community pull requests are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening an issue or PR, and report vulnerabilities in Hacker Bob itself through [`SECURITY.md`](SECURITY.md).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
