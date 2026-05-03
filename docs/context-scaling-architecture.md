# Context Scaling Architecture

Hacker Bob scales attack-surface coverage through MCP-owned routing and bounded context retrieval, not by loading every technique into every hunter prompt.

## Architecture

The core flow is:

```text
surface -> capability pack -> surface-family hunter -> on-demand technique packs -> structured finalization
```

Capability packs own surface-family routing. Each routed assignment carries the selected `capability_pack`, `hunter_agent`, `brief_profile`, `capability_pack_version`, and enforced `context_budget`. The orchestrator must spawn the returned `assignment.hunter_agent` instead of hard-coding hunter names.

Technique packs are Bob registry records, not host-native skills by default. Hunters receive bounded summaries through `bounty_read_hunter_brief` and request full technique bodies only through `bounty_read_technique_pack`. This keeps context selection, read budgets, attempt history, and warning metadata in the MCP runtime, which preserves adapter portability across Claude, Codex, and generic MCP hosts.

## Context Budget

The current enforced assignment budget is:

```json
{
  "candidate_pack_limit": 5,
  "full_pack_read_limit": 2,
  "attempt_log_required": true
}
```

`candidate_pack_limit` caps selected technique summaries returned to a web hunter. `full_pack_read_limit` caps distinct full technique-pack reads per wave assignment. `attempt_log_required` makes hunter finalization require at least one matching `bounty_log_technique_attempt` record for that assignment.

Smart-contract hunters currently set `attempt_log_required: false` because their workflows are driven by chain-specific tools, `bob-spec.json`, and harness evidence rather than web technique packs. When smart-contract technique packs are added, the capability packs should opt into the same attempt-log contract.

## Technique Registry

The registry file is `knowledge/hunter-techniques.json` under Bob resource roots. Registry entries should contain compact metadata, match hints, summary guidance, payload hints, capability-pack compatibility, and estimated token costs.

Registry reads are resilient. A malformed optional file or entry must not block hunter brief generation. The runtime skips invalid entries and returns bounded `registry_warnings` metadata without exposing raw technique bodies in warnings.

`technique_packs.selected` is the canonical web-hunter context. Top-level `techniques` and `payload_hints` are retained only as small legacy compatibility summaries derived from selected packs.

## Host Adapters

Host adapters install and render Bob contracts, but they should not own routing, technique selection, budget enforcement, or session artifact mutation. Claude Code agent teams or additional workers may be useful for explicit escalation, but the default execution model remains one routed surface-family hunter per assignment.

Session artifacts for state, routes, handoffs, findings, coverage, technique reads, and technique attempts remain MCP-owned. Host hooks and guards should preserve that boundary instead of introducing adapter-specific artifact writers.

## Evaluation Gates

Before adding a large technique registry, keep tests around:

- capability routing accuracy across mixed surfaces
- selected technique count and full-read limits
- duplicate or incompatible technique-attempt prevention
- finalization blocking when required attempt logs are missing
- prompt/rendered adapter parity
- registry warning behavior for malformed entries

The scaling goal is not more context. It is better ownership over which context each hunter is allowed to see and when.
