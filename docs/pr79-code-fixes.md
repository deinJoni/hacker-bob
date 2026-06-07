# PR #79 — verified code-review fixes for Codex

These are the **verified** code-level findings from the PR #79 bot reviews (Codex + CodeRabbit), each confirmed against the actual code with an exact fix. Apply them on branch `integrate/delta1-to-main`, add the tests noted, run `npm test` (`test:mcp` + `test:prompts` + `test:install` must stay green), then push to the PR branch. **Do NOT touch the docs** (already fixed in `e97fa91`). **SKIP** the invalid finding at the end.

---

## FIX 1 — CX1 (P1): reachability gate fails open
**Files:** `mcp/lib/reachability-ceiling.js` + `mcp/lib/lifecycle-gates.js` + `mcp/lib/grade-verdict-store.js`

For repo (`target_repo`) sessions with **no** `repo-inventory.json` reachability (absent, or an old inventory predating the reachability cycle), `missingReachabilityStampsForReportableFindings()` returns `{reachability_present:false, missing:[]}`. So the VERIFY→GRADE gate (`lifecycle-gates.js:90`) returns an empty blocker list (allows), and `writeGradeVerdict()` (`grade-verdict-store.js:~354`) does not throw → **medium/high/critical repo-module findings get graded with NO I9 ceiling**, silently skipping the local-vs-network severity cap.

Make it **fail closed, surgically** (only block when findings would actually be graded uncapped — not a blanket block):

1. In `missingReachabilityStampsForReportableFindings` (`reachability-ceiling.js` ~:317): when `!hasReachabilityInventory(domain)`, return
   `{ reachability_present: false, inventory_absent: true, missing: [<reportable medium+ finding ids from finalReportableFindingSeverities(domain) that pass findingHasReachabilityStampedSurface(domain, id)>] }`.
   (`surfaceIdsForFinding` reads the claim-freeze, not the inventory, so this is computable without inventory.) If none qualify, `missing: []` (allow — nothing to cap).
2. In `lifecycle-gates.js` `gateVerifyToGrade` (:90): change to `if (reachability.missing.length === 0) return blockers;` (drop the `!reachability.reachability_present ||`), and make the blocker `message`/`remediation` inventory_absent-aware (e.g. "repo session has no reachability inventory; N reportable repo-module finding(s) would be graded without an I9 ceiling — run bob_repo_inventory").
3. In `grade-verdict-store.js` (:~354): change the throw condition to `if (missingReachability.missing.length > 0)` and make the message inventory_absent-aware.

**TEST:** a repo session with a reportable medium finding on a `repo:module:` surface and **no** reachability inventory is **blocked** at VERIFY→GRADE (and `writeGradeVerdict` throws). A repo session with no medium+ repo-module findings is unaffected. The normal flow (inventory always run in SETUP) is unaffected.

---

## FIX 2 — CX2 (P2): meaningless reachability metadata on web/SC findings
**File:** `mcp/lib/grade-verdict-store.js` (~:361-372)

`writeGradeVerdict` attaches `reachability:{disposition:"unknown", attack_vector:"unknown", graded_severity:<final>}` to **every** finding that has a final severity — including ordinary web/SC findings with no stamped surface. `report-writer` treats the presence of `reachability.graded_severity` as authoritative → public reports carry meaningless `attack_vector: unknown` / `disposition: unknown` lines.

Only attach the block when a stamp actually resolved. After computing
`const reachability = reachabilityDispositionForFinding({ domain, findingId: finding.finding_id, recordedSeverity });`
add `if (reachability.disposition === "unknown") return finding;` before `return { ...finding, reachability };`.

Safe: the markdown render already guards `if (finding.reachability)`; report-writer instructions are all "when present"; the repo-stamp grade tests resolve to non-unknown dispositions.

---

## FIX 3 — CX3 (P2): scoped-inventory paths are not session-root-relative
**File:** `mcp/lib/repo-target.js` (`buildRepoInventory`)

`bob_repo_inventory` with a `repo_path` subdirectory override emits/persists paths **relative to the subdir**, but `bob_repo_check` resolves `file_path` against the session root → wrong evidence and surface IDs (e.g. inventorying `packages/service` emits `package.json`, which checks the root package).

Derive a session-root-relative prefix from the already-computed `relativeToSessionRoot` (~:924):
`const subdirPrefix = relativeToSessionRoot ? relativeToSessionRoot.split(path.sep).join("/") : "";`
`const rootRel = (rel) => subdirPrefix ? `${subdirPrefix}/${rel}` : rel;`
Apply `rootRel()` to every path written into **frontier events** (`surfaceId` input, `title`, `payload.file_path` / `payload.manifest_path`, ~:960-1062) and into the **inventory-document path arrays** (`projection.manifests` / `ciPipelines` / `entryPoints` / `configs`, and any `residual_hunt_targets` / `seed_corpus` rels, ~:1096-1099).
**Do NOT** prefix `mod.rel` before the `reachability.perSurface.get(mod.rel)` lookup (~:959) — reachability was classified with `repoRoot = root`, so keep the projection rels and reachability map keys subdir-relative. The default (no override) path keeps `subdirPrefix = ""`, so behavior is unchanged.

**TEST:** inventory a subdir and assert the emitted `file_path` equals `"<subdir>/package.json"`.

---

## FIX 4 — CX4 (P2): unbounded CHANGELOG excerpt aborts inventory
**File:** `mcp/lib/repo-target.js` (`detectResidualLinesFromFiles`, ~:677-683)

For a `SECURITY`/`CHANGELOG`/similar file with a long matching line (e.g. a generated markdown table row mentioning a CVE), the whole trimmed line is stored. `buildRepoInventory` then runs `validateNoSensitiveMaterial` with a 4000-char cap, which **hard-throws**, aborting `bob_repo_inventory` instead of truncating the hint.

Cap the excerpt before pushing, mirroring `buildMatchedLines`:
`const ex = redactTextSensitiveValues(trimmed); const capped = ex.length > REPO_CHECK_MAX_EXCERPT_CHARS ? ex.slice(0, REPO_CHECK_MAX_EXCERPT_CHARS) + "…" : ex; targets.push(`${file}: ${capped}`);`
Reuse the existing `REPO_CHECK_MAX_EXCERPT_CHARS` (1024).

---

## FIX 5 — CR-RT (security): symlink escape during inventory walk
**File:** `mcp/lib/repo-target.js` (`walkRepo`)

`walkRepo` follows symlinked directories with no realpath containment (the inode `visited` set only prevents loops, not off-repo escape). An untrusted repo's symlink can enumerate off-repo trees.

Near the top of `walkRepo` (after `const files = [];`, ~:541): `const rootReal = fs.realpathSync(rootPath);`.
In the symlink branch (~:570-578), before `statSync`, resolve + contain:
`const childReal = fs.realpathSync(childAbs); if (!pathWithinRoot(rootReal, childReal)) continue;`
`pathWithinRoot` is already defined (~:595) and in scope.

**TEST:** a symlink pointing outside the repo root is not traversed.

---

## FIX 6 — CR-AB2: `valid_surface_ids` dropped in OSS/projection briefs
**File:** `mcp/lib/assignment-brief.js` (~:995)

The `currentSurfaces()` projection path has no `surface_ids`, so `valid_surface_ids` is omitted from the brief on the projection-backed path (OSS always; web/SC on fallback) — a profile-dependent contract inconsistency (currently no consumer, but fix for uniformity).

One-line fix:
`valid_surface_ids: attackSurface.surface_ids || attackSurface.document.surfaces.map((s) => s.id),`
(`document.surfaces` exists on both paths, already used at :885; the `||` preserves existing `attack_surface.json` behavior.)

---

## SKIP — CR-AB1 (redact command args): INVALID
`slimRepoEnvCommand` forwards `recommended_commands[].command[]` with only length caps, but its only input is hardcoded language templates + `repo-env.json`, which is **already gated by `validateNoSensitiveMaterial` at write time** (`repo-env.js:714`) — that rejects exactly the token/key/cookie/auth-header patterns the finding claims could leak. There is no attacker-controllable path placing a credential into the brief. Do not change. (Optional defense-in-depth only.)

---

## Process
- `npm test` green (`test:mcp` + `test:prompts` + `test:install`).
- Push to `integrate/delta1-to-main`.
- After pushing, address CodeRabbit/Codex/brutalist comments: fix valid ones, reply to invalid ones with rationale and resolve the thread. Done when CI is green and threads are resolved.
- Remove this file (`docs/pr79-code-fixes.md`) in the final commit once the fixes land.
