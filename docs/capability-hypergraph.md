# Bob Capability Hypergraph — Post-v2 Roadmap

## Audience and scope

This is an internal engineering roadmap for what Bob ships after the v2 verification work (PR #20) merges. It is not the public `docs/ROADMAP.md` — that doc lists community-contribution areas and intentionally hides depth. This doc is the depth.

The animating claim: Bob's structural advantage is **not context width**. It is **graph-shaped state with tool-mediated dereferencing**. The slab (v2 substrate) and the existing pillars (capability-pack routing, technique-pack on-demand reads, hunter brief) make that possible. The work ahead is building the **indexes** that turn each new hunting capability into a bounded query problem, then shipping the capabilities on top.

## How to read this doc

The codebase has three layers and a set of cross-cutting concerns:

- **Slab (S)** — substrate already shipped. Provides invariants the rest depends on.
- **Pillars (I, IP)** — pre-computed indexes (`I*`) and ingestion paths (`IP*`) that turn each capability into a bounded query. Some scaffolded, most new.
- **Roof (C)** — eight hunting capabilities that produce findings a triager recognizes.
- **Cross-cutting (X)** — concerns that span multiple items (context budgets, observability, evaluation, parishioner-facing surfaces).

A **hyperedge (H)** in this graph links N predecessors to M unlocked items. Real engineering dependencies are rarely pairwise — the hypergraph captures that fan-in / fan-out directly.

Each work item has a **do→review cycle**:

- **DO** — spec → build → wire → ship.
- **REVIEW (engineering)** — tests, context-budget compliance, determinism, failure-mode coverage.
- **REVIEW (parishioner)** — run on a real authorized target. Count actionable findings. Count false positives. Triager-recognition test: would a triager close this as duplicate / informational / valid?

Tiers gate on parishioner review. **No proceeding to tier N+1 without findings tier N actually produces.** Substrate work is not a tier-advancing activity unless a capability ship demands it.

## Disambiguation

These terms collide if not separated:

- **Capability pack** (existing, see `docs/context-scaling-architecture.md`) — a surface-family router selected per assignment. Governs `candidate_pack_limit`, `full_pack_read_limit`, `attempt_log_required`. Lives in MCP runtime.
- **Capability** (this doc, `C1`–`C8`) — a hunting *mode* that produces findings. May be implemented as one or more new capability packs plus indexes plus orchestrator routines. Strictly a higher-level abstraction than capability pack.
- **Technique pack** (existing) — a tactic body, registry-driven, fetched on demand by `bounty_read_technique_pack`. Indexes in this doc do not replace technique packs; they feed brief construction so technique selection has more signal.

## Slab — substrate already shipped

| ID  | Substrate                                                                                 | Provides                                                                |
| --- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| S1  | Content-addressed evidence (canonical hashing, `final_verification_hash`)                 | Same artifact → same hash, anywhere, anyone                             |
| S2  | Manifest-coupled state (atomic transitions, rollback on failure)                          | No half-states; state and evidence advance together or not at all       |
| S3  | Per-pack replay leases (`serialized` vs `parallel_safe`, lease scope `attempt_pack`/etc.) | Operational safety as typed property of each capability pack            |
| S4  | Orphan-attempt recovery (`inferOrphanedAttemptId`, attempt archive)                       | Every attempt reconstructible from artifacts; no silent state loss      |
| S5  | MCP tool registry + role bundles + generators                                             | Centralized capability boundary; tool privilege stays current with code |
| S6  | Static artifact import (foundry, anchor, OpenAPI partial)                                 | Evidence anchored to source, not just runtime                           |
| S7  | HTTP scan with auth profile injection                                                     | Credentials never enter LLM context                                     |
| S8  | Phase FSM + capability-pack routing + technique-pack on-demand reads                      | Bounded hunter brief; evaluated context selection                       |
| S9  | Coverage and dead-end logging                                                             | No duplicate testing within hunt                                        |
| S10 | Hunter brief + structured handoff + finalization marker                                   | Bounded subagent contract, validated by SubagentStop                    |

**Invariant:** any capability that violates a slab property — embedding credentials in a brief, advancing state without manifest refresh, holding artifacts without content-addressing, bypassing replay-lease typing — is a regression even if it works in demo. Reject at PR review.

## Pillars — indexes (`I1`–`I8`)

Each index is a pre-computed structure that turns one or more capabilities into a bounded graph or schema query. Without indexes, capabilities collapse to "stuff every artifact in context" and lose sharpness — attention dilution, hallucinated correlations, blown context budgets.

### I1 — Surface graph

**What it holds.** Edges between (subdomain, endpoint, JS file, OpenAPI spec, archived URL, parameter, hostname, secret marker). Nodes are content-addressed. Edges carry source and confidence.

**Failure mode it prevents.** The LLM hallucinating correlations across artifacts because it has all of them in one prompt and no structure.

**Predecessors.** Substrate: `S5, S7, S8, S9`. Ingestion: `IP1, IP6`.

**Unlocks.** `C1` (cross-surface correlation), partial `C3` (file→surface lookup), partial `C4` (endpoint inventory), prerequisite for `I3`.

**DO.** Define edge schema and version it. Build extractor that runs at recon completion. Persist as `surface-graph.json` per target with content-addressed nodes. Wire into hunter brief construction so a surface-family hunter receives a graph slice scoped to its surface, not the full graph.

**REVIEW (engineering).**
- Schema versioned and canonical-hashable.
- Edges deterministic across re-runs (same inputs → same edges → same hash).
- Per-surface graph slice fits ≤5k tokens for orchestrator queries; per-edge dereferenced detail ≤2k.
- Stale-artifact cleanup integrates with v2 manifest refresh.
- Fixture target with known JS bundle + OpenAPI spec → expected edge set.

**REVIEW (parishioner).**
- Run on a real authorized target.
- Did surface-family hunters use graph queries instead of holding raw artifacts?
- Did at least one finding emerge from a multi-source correlation no single artifact would surface?
- Was orchestrator context-window usage measurably lower than pre-graph baseline?

**Context budget.** Orchestrator query ≤5k. Per-edge dereference ≤2k. Full slice for one surface ≤15k hard cap.

### I2 — Schema-contract corpus

**Status.** Complete. Source coverage (OpenAPI 3, GraphQL SDL, Postman v2.1), persistence with content-hash dedup, orchestrator-only MCP tools (`bounty_ingest_schema_doc`, `bounty_query_schema_contracts`), and hunter-brief `schema_slice` integration all shipped. Web hunters now receive an endpoint-filtered, budgeted slice of the corpus alongside techniques, traffic, audit, intel, and static-scan hints.

**What it holds.** Parsed contracts from OpenAPI / GraphQL / Postman collections. Each contract is `(endpoint, method, claimed_auth, claimed_params, claimed_response_shape, source_doc_hash)`.

**Failure mode it prevents.** Treating prose docs as opaque text. Forces the doc into a deterministic, diffable shape so differential testing can run without LLM in the inner loop.

**Predecessors.** Substrate: `S5, S6`. Ingestion: `IP2`.

**Unlocks.** `C2` (doc-vs-behavior delta), partial `C4` (response shape comparison), feeds `I4`.

**DO.** Build OpenAPI / GraphQL / Postman parsers. Normalize into the contract tuple. Hash each contract. Store as `schema-contracts.jsonl` per target. Provide `bounty_query_schema_contracts` tool for orchestrator queries.

**REVIEW (engineering).**
- Parsers cover OpenAPI 2/3, GraphQL SDL, Postman v2.1.
- Contract tuples canonical-hashable; same input doc → same hash.
- Tool returns ≤5k token slice per query (paginated).
- Malformed input doesn't block ingestion (warning + skip, like technique registry).

**REVIEW (parishioner).**
- Did the corpus produce ≥1 doc-vs-behavior divergence on a real authorized target?
- Were divergences classifiable into (security bug, doc bug, test infra quirk)?
- Did the LLM-on-divergence subagent stay within budget?

**Context budget.** Per-contract tuple ≤500 tokens. Per-divergence triage subagent ≤5k.

### I3 — Symbol-to-surface index

**What it holds.** `(file:line → endpoint → surface)` mapping built from static analysis of authorized public repos. Edges back to `I1`.

**Failure mode it prevents.** Diffs that touch impactful surfaces being missed because there's no edge from changed code to the live surface bob hunts.

**Predecessors.** Substrate: `S6`. Ingestion: `IP6`. Pillars: `I1`.

**Unlocks.** `C3` (diff-aware regression hunting).

**DO.** Static analysis pass extracting handler→route→surface mappings (Express, Flask, Django, Spring, Rails, Go HTTP, etc.). Index by `file:line`. Refresh on commit hash change.

**REVIEW (engineering).**
- Coverage report per language framework: % of routes resolved.
- Index canonical-hashable per repo commit.
- Stale on commit drift; refresh deterministic.

**REVIEW (parishioner).**
- Given a real diff on a real repo, did the index correctly identify ≥80% of impacted surfaces?
- Did diff-driven hunts produce findings shorter wall-clock than equivalent baseline hunts?

**Context budget.** Per-diff dispatch ≤2k tokens for the surface-list. Surface-detail dereference ≤2k each.

### I4 — Auth-differential matrix

**What it holds.** Per-target, per-endpoint, per-auth-profile response signatures: status, header set, body shape hash, sensitive-field presence, latency band. Sparse — only populated for endpoints exercised.

**Failure mode it prevents.** Authz bug-class regressions slipping past because the comparison is ad-hoc per finding.

**Predecessors.** Substrate: `S5, S7`. Pillars: `I1` (endpoint enumeration).

**Unlocks.** `C4` (multi-account differential by default).

**DO.** During HUNT, every payload runs across all available auth profiles by default. Responses programmatically diffed and recorded into `auth-differential.jsonl` per target. Suspicious-row threshold (configurable: status delta, body-hash delta, sensitive-field delta) triggers LLM triage subagent.

**REVIEW (engineering).**
- Differential runs deterministic given fixed inputs.
- Sensitive-field detection covers common patterns (PII, internal IDs, role markers).
- Runner respects replay-lease typing — no double-fire of destructive endpoints across profiles.
- Triage subagent budget enforced.

**REVIEW (parishioner).**
- Did the matrix surface ≥1 authz finding on a real target?
- False-positive rate (triaged divergences that weren't bugs) reasonable?

**Context budget.** Per-row ≤300 tokens. Per-suspicious-row triage subagent ≤5k.

### I5 — Audit-to-invariant template corpus

**What it holds.** Templates of (vulnerability prose pattern → Foundry invariant code pattern). Built incrementally from past audit reports. Each template has examples, applicability rules, parameterization.

**Failure mode it prevents.** Re-deriving invariants from scratch per audit. Templates compound: corpus grows, per-audit subagent gets cheaper.

**Predecessors.** Substrate: `S3, S6`. Ingestion: `IP4`. Pillars: `I6` (used as memory layer over time).

**Unlocks.** `C5` (LLM-authored invariant fuzzing).

**DO.** Pipeline: audit report → chunked findings → per-finding subagent generates invariant + applicability rule → human reviews first batches to seed corpus → corpus queryable by audit class / contract pattern.

**REVIEW (engineering).**
- Templates parameterized cleanly (no hard-coded contract addresses).
- Invariants compile under Foundry as-is.
- Per-finding subagent stays within budget; full audit doesn't enter context.
- Replay-lease typing on the harness pack ensures concurrent hunts don't corrupt local Foundry workspace.

**REVIEW (parishioner).**
- Run on a real audited target. Does ≥1 generated invariant produce a counterexample on the deployed bytecode?
- For programs with public bug bounty (Immunefi etc.): is the counterexample submission-grade?

**Context budget.** Per-audit-finding subagent ≤8k. Per-counterexample triage subagent ≤5k.

### I6 — Findings vector index

**Status.** Engineering-complete pending parishioner gate. Library, MCP tool wrappers (`bounty_index_finding`, `bounty_query_findings_index`), auto-indexing in `bounty_record_finding`, and brief-time prior injection (`priors_slice` in both web and smart-contract hunter briefs) all shipped. Hunters automatically receive the top-K cross-target priors that match their surface (endpoint, bug class, tech stack, chain family, contract address) without any orchestrator action.

**What it holds.** Vector embeddings of past findings: `(description, target stack, attack class, severity, evidence summary, calibration label)`. Calibration label comes from grade verdicts and adjudication archive — ground truth signal for what was real.

**Failure mode it prevents.** Each hunt starting from zero. Bob's accumulated experience invisible to itself.

**Predecessors.** Substrate: `S1, S2` (manifest provides calibration ground truth). Existing: grade verdicts, adjudication archive.

**Unlocks.** `C6` (cross-target pattern memory). Augments `C1, C2, C3, C5, C7, C8` by injecting top-K similar prior findings into hunter briefs.

**DO.** Embedding pipeline runs on every shipped finding. Vector store (sqlite-vss or similar lightweight choice). Query API: `bounty_query_findings_index(recon_summary, top_k)` returns compact summaries. Wire into brief construction so new hunts open with relevant priors.

**REVIEW (engineering).**
- Pipeline idempotent — same finding hashes to same embedding key.
- Calibration labels (`real`, `rejected_duplicate`, `rejected_intended`, `rejected_oos`) wired from adjudication archive.
- Query returns ≤5k token summary regardless of corpus size.
- Index handles incremental growth without full rebuild.

**REVIEW (parishioner).**
- Does a hunt with the index reach a finding faster than a baseline hunt without?
- Does the index reduce duplicate findings (bob re-finding the same class on same target)?

**Context budget.** Per-query injection at hunt start ≤2k. Per-similar-finding summary ≤200 tokens.

### I7 — Chain state tree

**What it holds.** Per-engagement, content-addressed branch nodes. Each node = `(parent_state_hash, action, observed_outcome, verdict)`. Tree shape; orchestrator holds frontier.

**Failure mode it prevents.** Linear CHAIN that can't backtrack from a failed branch. Real chains are 5–10 steps with dead ends; current CHAIN is ~2 steps shallow.

**Predecessors.** Substrate: `S1, S3, S8`. Pillars: `I1` (for action proposals).

**Unlocks.** `C7` (branching chain search).

**DO.** Extend CHAIN phase. Each chain attempt becomes a tree node, hashed by parent + action. Heuristic pruner (deterministic, above LLM): "this branch failed for reason X on target Y — skip." Frontier exploration with budget cap. Replay leases govern which branches can run in parallel.

**REVIEW (engineering).**
- Tree serialization canonical-hashable.
- Backtracking re-pins to known state hash without replay-unsafe side effects.
- Pruner rules deterministic; same tree state → same prune set.
- Per-node subagent budget enforced.

**REVIEW (parishioner).**
- Did a real chain require backtracking, and did the tree handle it?
- Did the resulting chain reach a verified outcome that flat CHAIN couldn't?

**Context budget.** Frontier in orchestrator ≤5k. Per-node subagent ≤8k.

### I8 — CVE-to-corpus matcher

**What it holds.** Index over authorized scope by `(stack, version_range, surface_kind)`. Plus a normalized form of incoming CVE/disclosure data: `(vulnerable_software, version_range, vector, indicator_of_vulnerability)`.

**Failure mode it prevents.** Per-CVE manual triage of which authorized targets are affected.

**Predecessors.** Substrate: `S5`. Ingestion: `IP5`. Pillars: `I1` (for surface match), `I3` (for stack inference).

**Unlocks.** `C8` (live disclosure speedrun).

**DO.** Periodic pull of NVD / GitHub Security Advisories / vendor disclosures. Normalize. Match against scope corpus. Match → emit `disclosure-match.jsonl` event. Orchestrator consumes events and dispatches per-match hunt subagents.

**REVIEW (engineering).**
- Matcher false-positive rate measured (matched targets that aren't actually vulnerable).
- Match operations canonical-hashable for replay.
- Dispatch respects per-target rate limits and program AI-hunting policy.

**REVIEW (parishioner).**
- For a real CVE matching a real authorized target: did the speedrun produce a verified finding within the same day as disclosure?
- Was the finding submission-acceptable under program policy?

**Context budget.** Match-frontier in orchestrator ≤5k. Per-match hunt subagent ≤10k.

## Pillars — ingestion paths (`IP1`–`IP6`)

| ID  | Path                                          | Status            | Feeds            |
| --- | --------------------------------------------- | ----------------- | ---------------- |
| IP1 | JS extraction (current recon pipeline)        | Existing, partial | `I1`             |
| IP2 | OpenAPI / GraphQL / Postman ingestion         | Complete (OpenAPI 3, GraphQL SDL, Postman v2.1)               | `I2` |
| IP3 | Public-repo watcher with diff dispatch        | New               | `I3` (via `I1`)  |
| IP4 | Audit report ingestion (PDF, markdown, HTML)  | New               | `I5`             |
| IP5 | CVE / advisory feed ingestion                 | New               | `I8`             |
| IP6 | Static analysis pass (file:line → handler)    | New               | `I1`, `I3`       |

Each ingestion path has its own do→review cycle. Engineering review checks idempotence, hash determinism, and bounded output size. Parishioner review for ingestion is "does the index it feeds become useful?" — ingestion alone is not parishioner-visible.

## Roof — capabilities (`C1`–`C8`)

Each capability is a hunting mode that produces findings a triager recognizes. Implementation may be one or more new capability packs, plus index queries, plus orchestrator routines.

### C1 — Cross-surface correlation

**Pedagogical note.** A skilled hunter chains "JS bundle leaks internal API → docs hide an admin endpoint → another subdomain's OpenAPI dump reveals param shape" maybe once a week. Bob with `I1` does this across dozens of targets concurrently. The leverage is not in finding *one* correlation — it's in finding the long tail of correlations no individual hunter has time to chase.

**Predecessors.** Substrate: full slab. Pillars: `I1` (primary), `I6` (pattern memory).

**DO.** Add correlation-query routine to orchestrator: form hypothesis (e.g., "internal admin endpoint reachable from JS"), query `I1` for matching paths, dereference matched artifacts, dispatch verification. New capability pack `web-cross-surface` for follow-up.

**REVIEW.** Engineering: correlation queries deterministic; hypothesis-formation subagent budget enforced; dereferencing respects per-edge cap. Parishioner: ≥1 finding from a multi-source correlation no single artifact would have surfaced.

### C2 — Doc-vs-behavior delta hunting (Tier 1, first ship)

**Status.** Engineering-complete pending parishioner gate. Divergence-detection kernel, DI-style differential runner, `bounty_http_scan` adapter, MCP tool wrapper `bounty_run_doc_delta`, hunter-brief `schema_slice` integration, and orchestrator playbook section (`prompts/roles/orchestrator.md` "Optional: Doc-vs-Behavior Differential") all shipped. The "capability pack" planned in the original hyperedge resolved to an orchestrator-driven workflow rather than a hunter-routed pack, because C2 produces findings via differential testing the orchestrator drives, not via a per-surface hunter sub-agent. Triage of prose-only contracts (LLM subagent) remains a quality-of-life refinement; the existing severity_class taxonomy (`security`, `info_leak_potential`, `doc_or_infra`) already drives a useful triage default. Parishioner gate stays open until C2 produces ≥1 finding accepted by a real triager.

**Pedagogical note.** Every public-facing API is two systems — the documented contract and the deployed behavior. The delta is bug surface. Skilled hunters find these one endpoint at a time. Bob with `I2` finds them across full scope mechanically. The LLM is needed only on prose-only docs (no formal spec) and on triage of divergences.

**Why first ship.** Highest yield. No NDA risk. No AI-ban risk. Plays directly to bob's context-window advantage. Requires only `IP2` + `I2` (cheapest pillar to build). Produces findings a triager recognizes on day one.

**Predecessors.** Substrate: `S5, S7, S8`. Pillars: `I2` (primary), partial `I1` (endpoint enumeration).

**DO.** Ship `IP2` → `I2` → new capability pack `web-doc-delta` → orchestrator wiring → first hunt on a real authorized target with public OpenAPI.

**REVIEW.** Engineering: differentials deterministic; per-divergence subagent ≤5k; findings flow through v2 verification with hash-stable evidence. Parishioner: ≥1 actionable finding. ≥3 high-quality candidates ready for submission. Ideally: ≥1 accepted by a triager.

**GATE for advancing to Tier 2.** This.

### C3 — Diff-aware regression hunting

**Pedagogical note.** "What changed → what broke" is one of the highest-yield human hunting modes and one of the least-automated. Bob with `I3` + `IP3` watches public repos for authorized targets and dispatches surface-scoped re-hunts on every diff.

**Predecessors.** Substrate: `S6, S8`. Pillars: `I3` (primary), `I1` (surface lookup), `IP3`, `IP6`.

**DO.** Repo watcher (webhook or polling) → diff parser → `I3` query → spawn one subagent per impacted surface with diff slice + prior findings + tools. New capability pack `web-diff-regression` (and a smart-contract analog later).

**REVIEW.** Engineering: subagent context ≤20k per surface; diff-to-surface mapping accuracy ≥80% on fixture repos; replay-safe re-runs. Parishioner: ≥1 regression finding on a real target's recent PR.

### C4 — Multi-account differential by default

**Status.** Engineering-complete pending parishioner gate. Kernel, DI-style runner, per-call `bounty_http_scan` adapter (`makePerCallHttpScanFetcher`), and MCP tool wrapper (`bounty_run_auth_differential`) all shipped. The orchestrator can now run multi-account differentials end-to-end: pass a target's endpoint list and ≥2 auth profiles, the tool fans across profiles, classifies divergences, and persists results. Profile metadata defaults auto-flag common unauth profile names (`guest`, `anon`, `noauth`, `public`, `unauthenticated`) so the `unauth_succeeds_where_auth_blocked` security heuristic fires without explicit metadata in the common case. Parishioner gate stays open until `C4` produces ≥1 authz finding accepted by a real triager.


**Pedagogical note.** Authz bugs are mostly "do same thing as user A vs user B, see what differs." Doing this at depth across all endpoints, all role pairs, all tenant boundaries is mechanical but exhausting for humans. Bob with `I4` makes it default.

**Predecessors.** Substrate: `S5, S7`. Pillars: `I1` (endpoints), `I4` (matrix). Existing: `bounty_list_auth_profiles`.

**DO.** Modify HUNT to run every web payload across all configured auth profiles by default, recording into `I4`. Suspicious-row threshold triggers triage subagent. Web capability packs gain `multi_account_differential: true` knob.

**REVIEW.** Engineering: differential deterministic; replay-lease typing prevents destructive double-fire across profiles; matrix canonical-hashable. Parishioner: ≥1 authz finding on a real target. False-positive rate stays under threshold (configurable).

### C5 — LLM-authored invariant fuzzing (smart-contract)

**Pedagogical note.** Audit reports are prose. Foundry invariants are code. The bridge — generating invariants from prose — is the human bottleneck in invariant fuzzing. Bob with `IP4` + `I5` automates the bridge and runs the resulting invariants on imported bytecode. Counterexamples are real findings.

**Predecessors.** Substrate: `S3, S6`. Pillars: `IP4`, `I5`. Optional: `I6` (template memory).

**DO.** Audit ingestion → per-finding subagent → invariant code → Foundry harness run → counterexample → triage subagent → finding. Smart-contract capability pack gains `audit_driven_invariant: true` mode.

**REVIEW.** Engineering: invariants compile cleanly; harness reuse content-addressed; replay leases prevent concurrent corruption of local workspace. Parishioner: ≥1 counterexample on a real audited target. Submission-grade for a public bounty (Immunefi, Cantina, Code4rena).

**Smart-contract economic gravity.** This is the capability where v2 substrate has direct payout-relevant value. Six-figure bounties exist; reproducibility is contested; harness reuse compounds.

### C6 — Cross-target pattern memory

**Status.** Engineering-complete pending parishioner gate. Closes once I6's brief-time prior injection ships, which it has: web hunters get a `priors_slice` next to their `schema_slice` and other context summaries; smart-contract hunters get the same alongside `bob_spec_status` and `rpc_pool`. Calibration label slot is reserved on every record so a future grade-verdict feedback path (which would index findings with `calibration_label: "real" | "rejected_*"`) provides ground-truth signal for similarity ranking.


**Pedagogical note.** Bob has access to its own past hunts in principle but not in practice — there's no retrieval layer. `I6` is the retrieval layer. Each new hunt opens with top-K similar prior findings, calibrated by which were real. This is the capability that compounds over time.

**Predecessors.** Substrate: `S1, S2`. Pillars: `I6`.

**DO.** Embedding pipeline on every shipped finding. Vector store. Query API. Wire into hunter brief construction across all capability packs.

**REVIEW.** Engineering: idempotent ingestion; calibration labels wired; query returns bounded summaries. Parishioner: hunts using the index reach findings faster than baseline; duplicate-finding rate decreases.

**Augmentation.** This capability also makes every other capability sharper. After it ships, `C1`/`C2`/`C3`/`C5`/`C7`/`C8` all benefit from priors-injection.

### C7 — Branching chain search

**Pedagogical note.** Real exploit chains are 5–10 steps with dead ends. Current CHAIN handles ~2-step linear. `I7` makes CHAIN a tree search with safe backtracking. Replay leases (S3) make backtracking *safe* — without them you can't unwind a destructive step.

**Predecessors.** Substrate: `S1, S3, S8`. Pillars: `I7`.

**DO.** Extend CHAIN phase with tree state. Heuristic pruner. Frontier exploration. Per-node subagent dispatch with replay-safe state pinning.

**REVIEW.** Engineering: tree serialization canonical-hashable; backtracking respects replay leases; pruner deterministic. Parishioner: a chain that flat CHAIN couldn't reach. Verified end-to-end.

### C8 — Live disclosure speedrun

**Pedagogical note.** When a CVE drops, hunters race to apply it across known programs. Bob with `IP5` + `I8` is the fastest possible matcher, running the moment disclosure lands.

**Predecessors.** Substrate: `S5`. Pillars: `IP5`, `I8`, `I1`, `I3`.

**Caveat.** Highest leverage, highest ban risk. Many programs ban AI hunting and would treat speedrun bots adversarially. **Requires program-level negotiation up front.** Do not ship until at least one program has explicit policy permitting it.

**DO.** Disclosure feed → normalization → match against scope corpus → per-match hunt subagent. Rate limiting per target. Policy gate per program.

**REVIEW.** Engineering: matcher false-positive rate measured; dispatch respects rate limits and program policy. Parishioner: a finding shipped on the day of disclosure, accepted by program.

## Cross-cutting concerns (`X1`–`X5`)

### X1 — Context budgets formalized per subagent

Make context budgets a typed property of capability packs and orchestrator routines, like replay leases. Every subagent invocation declares its budget; dispatch refuses to spawn over-budget. Observability (X3) records actual usage vs budget.

**Why.** Without enforcement, budgets are aspirational. Substrate becomes load-bearing only when violations are caught at dispatch time.

### X2 — Parishioner-facing surfaces

Substrate work that nobody can see is invisible. Parishioner-facing surfaces translate substrate gains into operator-readable signal:

- `bob-status` v2 panel — **shipped** (`prompts/roles/status.md` "V2 Verification Panel" section, mirrored to `.claude/skills/bob-status/SKILL.md` and `adapters/codex/skills/bob-status/SKILL.md` via the role renderers). Surfaces current attempt + snapshot freshness, adjudication / evidence match status, replay execution policy, and an archive trail showing the up-to-three most recent superseded attempts.
- `/bob-debug --diff-attempts <prev> <curr>` — **shipped** (`mcp/lib/verification-attempt-diff.js` + `mcp/lib/tools/diff-verification-attempts.js` + bob-debug skill update). Cross-attempt diff surfaces snapshot / adjudication / final hash matches plus per-file divergence (only-in-a, only-in-b, and content-changed entries with truncated 16-char hashes). Either side can be `current` for live-vs-archive comparison.
- `bob-export` replay-budget summary — per-pack lease usage and remaining budget. Pending.

These ship **alongside** capability ships, not after. After C2's first ship, X2's bob-status panel ships next.

### X3 — Observability

Per-capability metrics: index queries fired, hit rates, dereferences, context usage vs budget, hallucination flags (when a subagent claimed a correlation the index doesn't support). Surfaced in `bob-status`.

**Why.** Without observability, capability regressions are silent. Hallucination flags are the early warning for "the LLM stopped using the index and started making things up."

### X4 — Determinism CI

Per-PR CI invariant: same input artifacts → same canonical hashes across runs. Built on G regression test from PR #20.

**When.** After Tier 2. Substrate maintenance is not a tier-advancing activity; this ships when capabilities depend on it.

### X5 — Capability evaluation harness

Per-capability fixture: a known authorized target with seeded findings. Hunts run against the fixture must produce expected findings deterministically. Regressions caught before parishioner review.

**Why.** Parishioner review is expensive (real targets, real triagers). Evaluation harness catches regressions cheaply.

## Hyperedges — full dependency map

| Edge ID | Predecessors                                  | Unlocks                          |
| ------- | --------------------------------------------- | -------------------------------- |
| H-IP1   | (existing recon)                              | partial `I1`                     |
| H-IP2   | `S5, S6`                                      | `I2`                             |
| H-IP3   | `S5`                                          | `I3` (via `I1`)                  |
| H-IP4   | `S6`                                          | `I5`                             |
| H-IP5   | `S5`                                          | `I8`                             |
| H-IP6   | `S6`                                          | `I1` (full), `I3`                |
| H-I1    | `S5, S7, S8, S9, IP1, IP6`                    | `C1`, partial `C3`, partial `C4`, `I3` |
| H-I2    | `S5, S6, IP2`                                 | `C2`, partial `C4`               |
| H-I3    | `S6, IP6, I1`                                 | `C3`                             |
| H-I4    | `S5, S7, I1`                                  | `C4`                             |
| H-I5    | `S3, S6, IP4`                                 | `C5`                             |
| H-I6    | `S1, S2`                                      | `C6`, augments `C1`–`C8`         |
| H-I7    | `S1, S3, S8`                                  | `C7`                             |
| H-I8    | `S5, IP5, I1, I3`                             | `C8`                             |
| H-C1    | full slab, `I1`, `I6`                         | findings                         |
| H-C2    | `S5, S7, S8, I2`, partial `I1`                | findings                         |
| H-C3    | `S6, S8, I3, I1, IP3, IP6`                    | findings                         |
| H-C4    | `S5, S7, I1, I4`                              | findings                         |
| H-C5    | `S3, S6, IP4, I5`, optional `I6`              | findings                         |
| H-C6    | `S1, S2, I6`                                  | findings, augments others        |
| H-C7    | `S1, S3, S8, I7`                              | findings                         |
| H-C8    | `S5, IP5, I8, I1, I3`                         | findings                         |
| H-X2    | substrate per-capability                      | parishioner visibility           |

## Tiered sequencing

The order is engineered so each tier produces parishioner-visible findings before the next tier starts. Substrate maintenance items are pulled in only when a capability ship demands them.

### Tier 1 — first ship (high leverage, short path)

1. `IP2` → `I2` → `C2` (doc-vs-behavior delta hunting)
2. `X2` ship: `bob-status` v2 panel (parishioner visibility into v2 substrate)
3. Partial `IP6` → partial `I1` → partial `C4` (multi-account differential, web-only mode)

**Gate.** `C2` produces ≥1 actionable finding on a real authorized target. Ideally accepted by a triager.

### Tier 2 — surface graph and pattern memory

4. Full `IP6` → full `I1` → `C1` (cross-surface correlation)
5. `IP3` → `I3` → `C3` (diff-aware regression hunting)
6. `I6` → `C6` (cross-target pattern memory) — augments all later capabilities
7. `X2` ship: cross-attempt diff in `/bob-debug`

**Gate.** `C1` + `C3` each produce findings on at least one shared target. `C6` measurably reduces hunt-to-finding wall-clock.

### Tier 3 — depth and smart-contract economic gravity

8. `IP4` → `I5` → `C5` (LLM-authored invariant fuzzing) — smart-contract focus
9. `I7` → `C7` (branching chain search)
10. `X2` ship: replay-budget summary in `bob-export`

**Gate.** `C5` produces ≥1 invariant counterexample on a real audited target. Submission-grade. `C7` produces a chain that flat CHAIN couldn't.

### Tier 4 — disclosure speedrun and substrate maintenance

11. Program-level conversation about AI hunting policy. **Do not ship `C8` without it.**
12. `IP5` → `I8` → `C8` (live disclosure speedrun)
13. `X4` (determinism CI), `X3` (observability), `X5` (capability evaluation harness) — substrate maintenance for the system at scale

**Gate.** `C8` produces a finding on day-of-disclosure, accepted by program.

## Do→Review cycle template

For every work item in this hypergraph:

**DO.**
1. Spec — write a one-page contract covering inputs, outputs, predecessors, context budget.
2. Build — implement with tests alongside.
3. Wire — integrate into existing brief / pack / orchestrator surfaces.
4. Ship — one commit per coherent slice; PR per work item or tight bundle.

**REVIEW (engineering).**
- Unit + integration tests passing.
- Context budget compliance (hard caps, observability records actual usage).
- Determinism (same inputs → same hashes across runs).
- Failure-mode coverage (orphan, partial, replay-unsafe, malformed input).
- Slab invariants preserved (no credential leakage, no unreffed state, etc.).

**REVIEW (parishioner).**
- Run on a real authorized target.
- Count actionable findings.
- Count false positives.
- Triager-recognition test (at least informal — would a HackerOne / Immunefi triager close this as duplicate / informational / valid?).
- Compare against pre-ship baseline (capability previously not present → was the gain real?).

**GATE.** Do not advance to the next item without passing both reviews. Do not proceed to the next tier without the tier gate passing on a real target.

## Anti-patterns (reject at PR review)

1. **Substrate-as-trajectory.** Shipping more substrate without a capability ship pulling on it. Substrate is a ratchet, not a destination.
2. **Context-as-strategy.** Solving any capability problem by widening the context window. Reach for an index instead.
3. **Capability without parishioner review.** Shipping a capability that passes engineering review but never runs against a real target. The findings count is the proof.
4. **Index without consumer.** Building an index speculatively because it might be useful. An index ships when its first consumer ships.
5. **Cathedral cadence.** Two substrate items in a row with no parishioner-facing ship between them.
6. **Hallucinated correlation, surfaced as feature.** A capability that produces findings the underlying index can't support. Observability (X3) catches this; PR review enforces it.

## Open questions

1. **Embedding model for `I6`.** Local (e.g., bge-small) vs API (Voyage, Cohere, Anthropic). Tradeoff: privacy/cost vs quality. Resolve before Tier 2.
2. **Repo watcher mechanism for `IP3`.** GitHub webhooks vs polling. Webhooks need a callback service; polling is simpler but less timely. Likely polling first.
3. **Audit ingestion format coverage for `IP4`.** PDF parsing is hard. Start with markdown + HTML; add PDF when a target requires it.
4. **CVE feed source for `IP5`.** NVD lags; vendor advisories are heterogeneous. Likely composite ingestion.
5. **Program negotiation strategy for `C8`.** Out of scope for this doc; but the negotiation must precede the engineering.

## Progress log

Append-only, newest first. Each entry: date, item, slice, commit ref, parishioner-review status.

- **2026-05-10** · I6 + C6 · Brief-time prior injection (`priors_slice`) in web and smart-contract hunter briefs · `mcp/lib/findings-index.js` adds `summarizePriorFindingsForSurface(domain, surface, opts?)` which builds a query string from surface fields (endpoint, endpoint_pattern, endpoints, surface_type, bug_class, bug_classes, tech_stack, notes, title, description, chain_family, chain_id, contract_address) and runs a cross-target similarity query, capping at 5 by default with a 15 hard ceiling. `mcp/lib/hunter-brief.js`'s `buildWebBriefExtras` and `buildSmartContractBriefExtras` both inject the slice; web hunters now see priors next to schema_slice + technique packs + traffic + audit + intel + static-scan hints, smart-contract hunters next to bob_spec_status + rpc_pool. Same/other-target counts and `domains_scanned` keep the brief honest about whether the priors come from the live target or the cross-target corpus. Function returns `null` when no matches surface, so empty results never noise the brief. Closes I6 + C6 from the original Tier 2 layer. Full `npm test` green (544→550 mcp tests).
- **2026-05-10** · I6 · MCP tool wrappers + auto-indexing in `bounty_record_finding` · `mcp/lib/tools/index-finding.js` (orchestrator-only mutator with optional `calibration_label`), `mcp/lib/tools/query-findings-index.js` (target or `cross_target` scope, top-K ≤50, severity / attack_class filters). Auto-indexing patched into `recordFinding`'s success path under a try/catch so an index-write failure never blocks the finding write. The handler hands the persisted finding's full shape (title, description, severity, attack_class, cwe, endpoint, surface_id, surface_type, tech_stack, evidence_summary or response_evidence, proof_of_concept) to `indexFinding`, so every hunt's findings populate the index automatically without operator action. Tool count 84→86; install-smoke length bumped; settings unchanged because both new tools are `global_preapproval: false`. Closes I6 substrate work; brief-time prior injection (orchestrator calls `bounty_query_findings_index` and threads top-K into hunter briefs) lands next.
- **2026-05-10** · I6 · Findings vector index library (lexical similarity, dep-free) · `mcp/lib/findings-index.js` + `test/findings-index.test.js` (14 tests passing). 256-slot hashed feature vectors over tokens + 2-grams of finding fields, with SHA-256-derived slot mapping for determinism. `tokenize` strips stop-words and emits unigrams + bigrams; `cosineSimilarity` ranks priors against a query string. `indexFinding` upserts per-target into `findings-index.jsonl` with calibration_label slot for future grade-verdict feed; `queryFindingsForTarget` and `queryFindingsCrossTarget` return top-K with optional severity / attack_class filters. Cross-target query iterates `~/bounty-agent-sessions/*` and skips dot-prefixed dirs so it never reads scratch state. No ML dependency, no embedding model — keeps the project's two-deps constraint intact while still letting later capabilities query priors at hunt start. MCP tools and auto-indexing in `bounty_record_finding` land in subsequent slices. Full `npm test` green (530→544 mcp tests).
- **2026-05-10** · X2 · `/bob-debug --diff-attempts <prev> <curr>` cross-attempt diff · `mcp/lib/verification-attempt-diff.js` + `mcp/lib/tools/diff-verification-attempts.js` + `test/verification-attempt-diff.test.js` (9 tests passing). Compares two verification attempts (each is either an archive id or `current`) by reading the per-attempt manifest hashes and the per-file hashes. Output: snapshot / adjudication-plan / final-verification hash match flags + file divergence (only-in-a, only-in-b, content-changed with truncated 16-char hashes). Wired into bob-debug skill's allowed-tools through the shared `READ_ONLY_DEBUG_TOOLS` list. Tool count 83→84; install-smoke length bumped; bob-debug source role gains the `--diff-attempts` argument-handling section, regenerated to Claude + Codex skills. Closes the second X2 deliverable from the original Tier 1 layer (cathedral pivot deferred parishioner-facing surface that turns the v2 archive trail into operator-readable signal). Full `npm test` green (523→530 mcp tests).
- **2026-05-10** · C2 + C4 · Read tools + consolidated orchestrator differential workflow · `mcp/lib/tools/read-doc-delta-results.js`, `mcp/lib/tools/read-auth-differential-results.js` (both orchestrator-only, read-only, with optional `summary_only` to skip the heavy per-contract / per-endpoint arrays). The orchestrator playbook collapses the prior two separate "Optional: Doc-vs-Behavior Differential" and "Optional: Multi-Account Differential" sections into a single "Optional: Differential Workflows" header with two named subsections, keeping the bob-hunt skill under its 340-line cap (now 330 lines). Tool count 81→83; settings, agent-tools, skill, codex skill regenerated; install-smoke and EXPECTED_TOOL_NAMES bumped. Test asserts both differential workflows reference their full tool chain (ingest/query/run/read for C2; list_auth_profiles/run/read for C4) and that rendered Claude + Codex skills carry the same workflow text. Closes Tier 1 small-wires backlog.
- **2026-05-10** · C4 · Per-call `bounty_http_scan` adapter + `bounty_run_auth_differential` MCP tool · `mcp/lib/http-scan-adapter.js` adds `makePerCallHttpScanFetcher` (uses `auth_profile` from per-call args instead of closure, so one fetcher serves the whole differential run); `mcp/lib/tools/run-auth-differential.js` registers the MCP tool. Auto-derives `profile_metadata.sent_with_auth: false` for profile names matching `guest`/`anon`/`noauth`/`public`/`unauthenticated` etc., so the `unauth_succeeds_where_auth_blocked` security heuristic fires without explicit metadata in the common case. Tool is orchestrator-only, scope-required, hook-required, writes `auth-differential-results.json`. Tool count 80→81; settings, agent-tools, skill regenerated. 3 new adapter tests cover per-call profile injection, blank profile sent_with_auth handling, and configuration validation. Full `npm test` green (518→521 mcp tests).
- **2026-05-10** · C4 · Multi-account differential runner with DI-style fetch + persistence · `mcp/lib/auth-differential-runner.js` + `test/auth-differential-runner.test.js` (13 tests passing). `runAuthDifferential({ target_domain, base_url, endpoints, auth_profiles, fetch_fn, profile_metadata?, run_id?, limit? })` normalizes endpoint shapes (strings or `{endpoint, method?}`), dedups + caps profile list to ≥2 distinct entries, fans `fetch_fn` across endpoint × profile, runs the kernel's cross-profile differ, and persists to `auth-differential-results.json`. Per-endpoint entries sort deterministically by `(endpoint, method)`; `results_hash` zeroes timestamps so identical inputs hash identically across runs. Fetch errors record per-(endpoint, profile) without aborting the broader run. Path added to `mcp/lib/paths.js`. Full `npm test` green (505→518 mcp tests).
- **2026-05-10** · C4 · Response-signature kernel + cross-profile differ · `mcp/lib/auth-differential.js` + `test/auth-differential.test.js` (17 tests passing). `computeResponseSignature` lowers an HTTP response into a stable signature: status / status_class / response_class, body_shape with structural keys only (so re-encoded same-shape bodies hash identically while admin-only fields surface), body_length_bucket (`empty`/`small`/`medium`/`large`/`huge`), sensitive_field_count over a curated regex list (password, token, ssn, internal_id, admin, etc.) walked to depth 3, and sent_with_auth flag. `diffResponseSignatures` emits six divergence types: `status_class_differs`, `response_class_differs`, `body_hash_differs`, `body_length_bucket_differs`, `sensitive_field_count_differs` (`info_leak_potential`), and `unauth_succeeds_where_auth_blocked` (`security`, requires optional `profile_metadata`). Output sorted deterministically by type. Pure-function design: no HTTP, no FS — runner integration lands in the next slice. Full `npm test` green (488→505 mcp tests).
- **2026-05-10** · C2 · Orchestrator playbook section for doc-vs-behavior differential · `prompts/roles/orchestrator.md` adds an "Optional: Doc-vs-Behavior Differential" section above PHASE 3 documenting the four-step workflow (ingest schema doc → confirm corpus → run per-auth-profile differential → record security-class divergences). Mirrored to `.claude/skills/bob-hunt/SKILL.md` and `adapters/codex/skills/bob-hunt/SKILL.md` via the bountyagent-skill and codex skill renderers. Test asserts the workflow content + tool names + rendered-surface parity. Closes the "C2 capability pack" deliverable as an orchestrator workflow rather than a hunter pack — C2's runner is orchestrator-driven, so hunter routing was the wrong shape for this capability. Triage of prose-only contracts via LLM subagent remains queued as quality-of-life refinement, not a blocker.
- **2026-05-10** · I2 · Hunter-brief `schema_slice` integration · `mcp/lib/schema-contracts-store.js` adds `summarizeSchemaSliceForSurface(domain, surfaceObj, opts?)`; `mcp/lib/hunter-brief.js` `buildWebBriefExtras` includes the slice. The slice tries `surface.endpoint_pattern` first, then walks `surface.endpoints[]` until a substring hit lands; if no hint matches it falls back to the full corpus. Default limit 5, hard ceiling 25. Each contract compresses to `(endpoint, method, claimed_auth_schemes, none_allowed, param_count, documented_status_codes, contract_hash:0..16, schema_format)` so a five-contract slice fits well inside the existing brief budget. Web hunters now see the documented contracts for their surface alongside techniques, traffic, audit, intel, and static-scan hints. 8 new tests cover empty corpus, default cap, endpoint_pattern hint match, fallthrough across endpoints array, compact-contract field shape, custom limit clamping below and above the ceiling, and no-match fallback. Closes I2 hunter-brief integration. Full `npm test` green (480→488 mcp tests).
- **2026-05-10** · X2 · `bob-status` v2 verification panel · `prompts/roles/status.md` adds an explicit "V2 Verification Panel" section that surfaces current attempt + first-eight-chars snapshot hash + freshness flag, adjudication / evidence match status, replay execution policy, and an archive trail (`archived_attempts.length` plus the up-to-three most recent superseded attempts as `<attempt_id> @ <archived_at> snapshot <hash:8> files <count>`). Mirrored to `.claude/skills/bob-status/SKILL.md` and `adapters/codex/skills/bob-status/SKILL.md` via the role renderers; prompt-contracts test extended with six panel-content assertions. Package size threshold bumped 2.0→2.5 MB to absorb the recent slice growth (~100 KB across parsers, runners, and the hypergraph doc itself).
- **2026-05-10** · IP2 / I2 · Postman v2.1 collection parser · `mcp/lib/postman-parser.js` + `test/postman-parser.test.js` (15 tests passing). Flattens nested folders into leaf requests, normalizes Postman path variables (`:name`) to OpenAPI shape (`{name}`), extracts query / path / header / body params (skipping Authorization and Content-Type request headers, those are runtime concerns), infers JSON body shape from raw bodies, derives `claimed_auth` schemes as `postman_auth:<type>` with collection-level cascade and item-level override, and reads response examples for `claimed_response_shape`. Closes IP2 source coverage (OpenAPI 3, GraphQL SDL, Postman v2.1). Full `npm test` green (465→480 mcp tests).
- **2026-05-10** · IP2 / I2 · GraphQL SDL parser + dispatcher routing · `mcp/lib/graphql-sdl-parser.js` + `test/graphql-sdl-parser.test.js` (17 tests passing). Hand-rolled tokenizer + recursive-descent parser handles type / input / schema / extend defs, descriptions, comments, list / non-null type modifiers, args with defaults, and directives. Auth directives (`@auth`, `@authenticated`, `@requireAuth`, `@hasRole`, `@guard`, etc.) populate `claimed_auth.schemes` as `graphql_directive:<name>`. Each Query / Mutation field becomes one contract with `endpoint = /graphql:<kind>.<name>` and `method = POST`. Return-type shape resolves nested types with `$ref_cycle` markers for self-recursion and `$ref_unresolved` for missing types. `parseSchemaDoc` now dispatches to GraphQL when JSON parsing fails and the source matches SDL heuristics. Full `npm test` green (448→465 mcp tests).
- **2026-05-10** · C2 · `bounty_http_scan` adapter + `bounty_run_doc_delta` MCP tool · `mcp/lib/http-scan-adapter.js`, `mcp/lib/tools/run-doc-delta.js`, `test/http-scan-adapter.test.js` (13 adapter tests passing). Adapter parses http-scan's JSON-stringified result, extracts content-type via case-insensitive header lookup, JSON-parses the body when content-type indicates JSON, and surfaces fetch errors with their `scope_decision`. The MCP tool is orchestrator-only, scope-required, hook-required (for the scope guard around the underlying http-scan call), and writes `doc-delta-results.json`. Tool count 79→80; settings, agent-tools, skill regenerated. Full `npm test` green (435→448 mcp tests).
- **2026-05-10** · C2 · Differential runner with DI-style fetch + deterministic persistence · `mcp/lib/doc-delta-runner.js` + `test/doc-delta-runner.test.js` (12 tests passing). Runner queries the I2 corpus, joins each contract endpoint to a base URL, calls a caller-supplied `fetch_fn` (so production wires `bounty_http_scan` while tests stub synthetic responses), runs the divergence classifier, and persists a content-addressed `doc-delta-results.json` per target. Per-contract entries sort by contract_hash; results_hash is computed over the canonicalized payload with timestamps zeroed so identical inputs hash identically across runs. Fetch errors per-contract are recorded but do not abort the run. Full `npm test` green (423→435 mcp tests).
- **2026-05-10** · C2 · Divergence-detection kernel · `mcp/lib/contract-divergence.js` + `test/contract-divergence.test.js` (15 tests passing). Pure-function classifier emits seven divergence types (auth-bypass, auth-misconfig, unreachable, status mismatch, undocumented field, missing required field, content-type mismatch) tagged with one of three severity classes (security, info_leak_potential, doc_or_infra) for the triage subagent. Output sorted deterministically by type. Full `npm test` green (408→423 mcp tests).
- **2026-05-10** · I2 · JSONL persistence + orchestrator-only ingest/query tools · `mcp/lib/schema-contracts-store.js`, `mcp/lib/tools/{ingest-schema-doc,query-schema-contracts}.js`, `test/schema-contracts-store.test.js` (10 store tests passing); full `npm test` green (407→408 mcp tests, 129 prompt-contracts, 9 package). Tools land as orchestrator-only mutators with `global_preapproval: false` so the budgeted hunter-web brief stays under cap. Settings, agent tools, and skill regenerated; install-smoke and package canonical-files walker updated for the new tool count and the cron lock file.
- **2026-05-10** · IP2 / I2 · OpenAPI 3 parser + contract canonicalization · `mcp/lib/schema-contracts.js` + `test/schema-contracts.test.js` (13 tests passing) · *engineering review complete; persistence + tool wrappers pending; parishioner gate not yet reachable.*

## Glossary

- **Slab** — substrate already shipped (v2 invariants and existing pack/brief architecture).
- **Pillar** — pre-computed index or ingestion path.
- **Roof** — hunting capability producing findings.
- **Cross-cutting** — concerns that span multiple items.
- **Hyperedge** — dependency relation linking N predecessors to M unlocked items.
- **Capability** (this doc) — hunting mode (`C1`–`C8`); not the same as capability pack.
- **Capability pack** (existing system) — surface-family router selected per assignment.
- **Technique pack** (existing system) — tactic body fetched on demand.
- **Hunter brief** (existing system) — bounded subagent contract with context-selection metadata.
- **Parishioner** — operator or hunter who consumes bob's output. Used in this doc as shorthand for "the human who has to look at what bob produced."
- **Triager** — bug-bounty platform or program triage analyst who decides finding disposition.
- **Slab invariant** — a property the substrate guarantees; violations are regressions even if they look like features.

---

*Doc version 0. Update as work lands; mark items complete inline; promote findings to capabilities; demote items that fail parishioner review back to spec.*
