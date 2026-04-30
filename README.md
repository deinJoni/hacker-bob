<p align="center">
  <img src="docs/hacker-bob.png" alt="Hacker Bob" width="320" />
</p>

<h1 align="center">Meet Hacker Bob</h1>

<p align="center"><i>Autonomous bug bounty agent for Claude Code.</i></p>

<p align="center">
  <a href="https://github.com/vmihalis/hacker-bob/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/vmihalis/hacker-bob/actions/workflows/ci.yml/badge.svg" /></a>
  <a href="https://www.npmjs.com/package/hacker-bob-cc"><img alt="hacker-bob-cc on npm" src="https://img.shields.io/npm/v/hacker-bob-cc?label=hacker-bob-cc" /></a>
  <a href="https://www.npmjs.com/package/hacker-bob"><img alt="hacker-bob on npm" src="https://img.shields.io/npm/v/hacker-bob?label=hacker-bob" /></a>
  <a href="LICENSE"><img alt="Apache-2.0 license" src="https://img.shields.io/github/license/vmihalis/hacker-bob" /></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/vmihalis/hacker-bob"><img alt="OpenSSF Scorecard" src="https://api.securityscorecards.dev/projects/github.com/vmihalis/hacker-bob/badge" /></a>
</p>

Bob is an autonomous bug bounty hunting framework for Claude Code. You install it into a Claude Code project, point it at an authorized target, and it coordinates recon, auth capture, hunting, verification, grading, and report writing through local agents and a project-local MCP server.

## Quickstart

### For AI Coding Agents

If a user pastes this repository URL into an AI coding agent, treat that as an install request. Install Bob into the current working directory by default; that is the Claude Code project the user is already in.

Run this first:

```bash
npx -y hacker-bob-cc@latest install "$PWD"
node -e "require('./mcp/server.js'); console.log('MCP ok')"
claude mcp list
```

Do not ask "what do you want to do?" when the current directory is a normal project/workspace. Ask only if the current directory is clearly the Hacker Bob source checkout itself, a home/root directory, or the user gave an explicit different target path.

`claude mcp list` should show `bountyagent` connected. That name is expected: it is Bob's internal MCP server namespace, not a legacy user command. The user-facing commands are `/bob-hunt`, `/bob-status`, `/bob-debug`, `/bob-update`, and `/bob-egress`.

After install, tell the user to fully restart Claude Code from this directory, then run:

```
/bob-hunt target.com
```

Use the source checkout only as a fallback when npm is unavailable or the user explicitly asks to install from source:

```bash
git clone https://github.com/vmihalis/hacker-bob.git /tmp/hacker-bob
cd /tmp/hacker-bob
./install.sh /absolute/path/to/target-project
```

### For Humans

#### Before You Run

Bob is autonomous and can send real requests, use local tools, attempt signup and authentication flows, and interact with third-party, internal, or private hosts when instructed by Bob's agents. Only run Bob when you have explicit authorization for the target, accounts, testing methods, automation, and any third-party systems involved.

The `claude --dangerously-skip-permissions` examples below disable Claude Code permission prompts. Use that mode only in a dedicated workspace for authorized security testing.

Create or choose one Claude Code project directory, then install Bob into that directory:

```bash
npx -y hacker-bob-cc@latest install /path/to/your/project
cd /path/to/your/project
claude --dangerously-skip-permissions --effort max
```

Then run:

```
/bob-hunt target.com
```

## Install

Bob installs into **one Claude Code project directory per command**. The install target is the project you will later run `claude` from; the installer writes that project's `.claude/`, `mcp/`, `.mcp.json`, and related config.

Recommended one-off install:

```bash
npx -y hacker-bob-cc@latest install /path/to/your/project
```

`hacker-bob-cc` is the canonical npm package. The `hacker-bob` package is a small convenience alias that delegates to `hacker-bob-cc`; keep using `hacker-bob-cc` for pinned installs and release provenance.

The installer copies Bob's agents, `/bob-*` commands, skills, rules, hooks, MCP server, and supporting runtime files into your project. Run it as many times as you like; it is idempotent and merges Bob-managed config without overwriting unrelated Claude Code settings.

If you prefer a global command, install the CLI once:

```bash
npm install -g hacker-bob-cc
hacker-bob install /path/to/your/project
```

Global npm install only puts the `hacker-bob` command on your `PATH`; it does **not** install Bob into every directory. To use Bob in another Claude Code project, run `hacker-bob install /path/to/that/project` for that project too.

The alias package also provides the same command:

```bash
npm install -g hacker-bob
hacker-bob install /path/to/your/project
```

Source installs still work for contributors:

```bash
git clone https://github.com/vmihalis/hacker-bob.git
cd hacker-bob
./install.sh /path/to/your/project
```

Do not run `/bob-hunt` from the cloned Hacker Bob source tree unless you intentionally installed Bob into that same directory. The source checkout is normally the installer, while `/path/to/your/project` is the active Claude Code workspace.

## Usage

```bash
cd /path/to/your/project
claude --dangerously-skip-permissions --effort max
```

Then in Claude Code, summon Bob:

```
/bob-hunt target.com         # full autonomous run
/bob-hunt resume target.com  # pick up where you left off
/bob-status                 # quick latest-session status
/bob-debug                   # review the latest local session
/bob-update                  # preview and install the latest Bob release
```

For install diagnostics, run:

```bash
hacker-bob doctor /path/to/your/project
```

For common setup issues, see [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).
For a copy-paste first-run flow, see [`docs/FIRST_RUN.md`](docs/FIRST_RUN.md).

## Updates

Run `/bob-update` inside Claude Code from the project where Bob is installed. The command checks the installed version, previews relevant `CHANGELOG.md` entries, asks before changing files, installs with:

```bash
npx -y hacker-bob-cc@latest install "$CLAUDE_PROJECT_DIR"
```

After an update, fully restart Claude Code in that project. Bob also checks for available updates once per day on `SessionStart` and stores the result in `~/.cache/hacker-bob/update-checks/`; the statusline and `/bob-status` only read that local cache.

## How Bob hunts

```
RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT
```

1. **RECON** — Bob sniffs around. Subdomains, live hosts, archived URLs, nuclei, JS secrets people forgot about.
2. **AUTH** — Bob tries to sign up. If he can, he keeps a victim and an attacker account in his pocket. If he can't, he shrugs and hunts unauthenticated.
3. **HUNT** — Parallel hunter agents fan out, one per attack surface. They are not gentle.
4. **CHAIN** — Bob squints at the findings and asks "wait, can I combine these into something worse?"
5. **VERIFY** — Three rounds of arguing with himself: skeptical Bob, balanced Bob, and final-PoC Bob. Most "bugs" do not survive. After final verification, Bob collects bounded evidence packs for every final reportable finding.
6. **GRADE** — 5-axis scoring. Bob decides: SUBMIT, HOLD, or "this is not a bug, please stop." Valid evidence packs are required before grading or reporting when final reportable findings exist.
7. **REPORT** — A clean, submission-ready writeup with PoCs and evidence. No "could potentially". No "an attacker may". Just receipts.

MCP ranking computes runtime priority for status views and hunter briefs. `/bob-status` also shows evidence readiness so missing or invalid evidence packs are visible before grade/report work. Imports and public-intel fetches do not rewrite `attack_surface.json`.

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) with Claude Opus (Bob has expensive taste)
- Node.js 20 or newer
- `curl` and `python3` (already on your machine, probably)
- Optional sidekicks for deeper recon:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

If those aren't installed, Bob just works with what he's got and doesn't complain.

## MCP Troubleshooting

Bob depends on the project-local MCP server copied into `mcp/server.js`. If Claude Code reports `Cannot find module './tools/index.js'`, the installed MCP runtime is stale or incomplete: `mcp/lib/tool-registry.js` is present, but `mcp/lib/tools/index.js` was not copied into the same target project.

Fix it by reinstalling Bob into the project you run Claude Code from:

```bash
npx -y hacker-bob-cc@latest install /path/to/your/project
cd /path/to/your/project
node -e "require('./mcp/server.js'); console.log('MCP ok')"
claude mcp list
```

Then fully restart Claude Code in that project. `claude mcp list` should show `bountyagent` connected. Seeing `bountyagent` is not an old slash command; it is the stable MCP server namespace behind Bob's `bounty_*` tools.

## Security Model

Bob installs into a local Claude Code project directory. The installer writes Bob-managed files under `.claude/`, copies the MCP runtime into `mcp/`, merges a local `.mcp.json`, and merges Claude settings/hooks into `.claude/settings.json`. These files are project-local and should be reviewed like any other automation that can run commands from Claude Code.

Bob stores local run state and evidence under `~/bounty-agent-sessions`. Treat that directory as sensitive: it can contain target names, request metadata, notes, and report evidence from authorized testing.

During a hunt, Bob may make outbound HTTP requests, run local recon tools you have installed, import local HTTP/static artifacts, and ask Claude Code agents to reason over the results. Optional third-party services, such as browser automation dependencies, CAPTCHA solving, public-intel sources, or external recon tools, are only used when you configure the relevant dependencies or credentials.

Bob logs and audits some activity, including local session artifacts and MCP HTTP scan records, but those records are for operator review. Bob does not verify authorization, enforce bug bounty scope, or guarantee containment.

By default, Bob does not block localhost, private networks, internal hostnames, or cloud metadata-style hostnames. This keeps exploration flexible for local labs, VPN/internal scopes, SSRF chains, and user-authorized pivots. Supported MCP HTTP calls can reject those destinations when you pass `block_internal_hosts: true`.

The npm packages are published through the GitHub release workflow with npm provenance. `hacker-bob-cc` is the canonical package; `hacker-bob` is a small alias package that depends on the matching canonical version.

Bob will scan the targets you provide and may touch other hosts during authorized chaining or proof-of-concept work. You are responsible for running it only against domains, applications, accounts, and infrastructure that you own or are explicitly authorized to test, and for following each program's scope and rules of engagement.

## Development

If you're hacking on Bob himself and want to push the current repo into a test workspace:

```bash
./dev-sync.sh /absolute/path/to/test-workspace
```

It backs up the target's `.mcp.json` and `.claude/settings.json`, runs the installer, recopies the MCP runtime, and smoke-checks with `claude mcp list`. You can find the maintainer workflow in [`CLAUDE.md`](CLAUDE.md).

## A note on scope

Bob will scan whatever you tell him to scan. **You are responsible for making sure the target is in scope and that you have permission.** Bob is enthusiastic, not licensed.

Hunt responsibly. Read the program's policy. Read [`DISCLAIMER.md`](DISCLAIMER.md) before you point him at anything.

## Contributing

Community pull requests are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening an issue or PR, and report vulnerabilities in Hacker Bob itself through [`SECURITY.md`](SECURITY.md).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
