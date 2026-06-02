#!/usr/bin/env node
"use strict";

// Cycle Y.8 — `check:skill-protocol-coherence` (Y-D7 / Y-P7 first
// coherence dimension family).
//
// Three coherence dimensions, all consuming the Y-D16 shared parser IR
// at `scripts/lib/skill-parser.js`:
//
//   D1. Structural containment (Y-D7c). For every STATE block in every
//       rendered skill / role markdown file, every write-tool token
//       (matching the `bob_write_*` / `bob_compose_*` / `bob_amend_*`
//       prefixes) that appears OUTSIDE a fenced code block MUST have a
//       matching `@schema_ref: <tool>` HTML-comment directive inside
//       the SAME state block. The generator
//       (`scripts/lib/claude-role-renderer.js` →
//       `injectSchemaRefDirectives`) auto-emits the markers from
//       TOOL_REGISTRY, so a violation here means either (a) the
//       generator was bypassed (hand-edited SKILL.md) or (b) the
//       source markdown references a write tool the registry doesn't
//       know about.
//
//   D2. Registry coherence. Every value cited in an `@schema_ref:`
//       directive MUST name a primary tool currently registered in
//       `mcp/lib/tool-registry.js` TOOL_REGISTRY. Stale directives
//       pointing at retired/renamed tools fail here.
//
//   D3. Token registry coherence. Every write-tool token that appears
//       outside a fenced code block MUST resolve to a primary tool in
//       TOOL_REGISTRY. Catches `bob_write_typo_handoff` and similar
//       drift between source markdown and the live registry.
//
// FP-rate budget: ≤2% on the curated corpus under
// `test/fixtures/skill-parser/`. The corpus is small and curated; the
// budget is enforced by `test/skill-protocol-coherence.test.js`.

const fs = require("fs");
const path = require("path");
const {
  parseSkillText,
  readSkillFile,
  discoverRoleMarkdownFiles,
} = require("./lib/skill-parser.js");
const { TOOL_REGISTRY } = require("../mcp/lib/tool-registry.js");

const ROOT = path.join(__dirname, "..");
const REGISTERED_TOOL_NAMES = new Set(
  TOOL_REGISTRY.filter((tool) => !tool.alias_of).map((tool) => tool.name),
);

function checkDocument(document) {
  const violations = [];
  for (const block of document.blocks) {
    if (block.kind !== "state") continue;
    const schemaRefTokens = new Set(block.tokens.schema_refs.map((r) => r.token));
    const seenWriteTokens = new Map(); // token -> { line, column }
    for (const writeRef of block.tokens.write_tools) {
      if (writeRef.in_code_block) continue;
      if (!REGISTERED_TOOL_NAMES.has(writeRef.token)) {
        violations.push({
          dimension: "D3_token_registry",
          file: block.file,
          block: block.name,
          line: writeRef.line,
          column: writeRef.column,
          token: writeRef.token,
          message: `write-tool token "${writeRef.token}" in STATE block "${block.name}" is not registered in TOOL_REGISTRY`,
        });
        continue;
      }
      if (!seenWriteTokens.has(writeRef.token)) {
        seenWriteTokens.set(writeRef.token, writeRef);
      }
    }
    for (const [token, ref] of seenWriteTokens) {
      if (!schemaRefTokens.has(token)) {
        violations.push({
          dimension: "D1_structural_containment",
          file: block.file,
          block: block.name,
          line: ref.line,
          column: ref.column,
          token,
          message: `write-tool token "${token}" appears in STATE block "${block.name}" without a matching @schema_ref directive in the same block (Y-D7c structural containment)`,
        });
      }
    }
    for (const schemaRef of block.tokens.schema_refs) {
      if (!REGISTERED_TOOL_NAMES.has(schemaRef.token)) {
        violations.push({
          dimension: "D2_registry_coherence",
          file: block.file,
          block: block.name,
          line: schemaRef.line,
          column: schemaRef.column,
          token: schemaRef.token,
          message: `@schema_ref directive cites "${schemaRef.token}" which is not registered in TOOL_REGISTRY`,
        });
      }
    }
  }
  return violations;
}

function runCheck({ root = ROOT, additionalFiles = [] } = {}) {
  const files = discoverRoleMarkdownFiles(root).concat(additionalFiles);
  const violations = [];
  const inspected = [];
  for (const filePath of files) {
    const document = readSkillFile(filePath);
    inspected.push({ file: filePath, blocks: document.blocks.length });
    for (const violation of checkDocument(document)) {
      violations.push(violation);
    }
  }
  return { files_inspected: inspected, violations };
}

function formatViolation(violation) {
  const relativePath = path.relative(ROOT, violation.file);
  return `[${violation.dimension}] ${relativePath}:${violation.line}:${violation.column}  block="${violation.block}"  token=${violation.token}\n    ${violation.message}`;
}

function main() {
  const result = runCheck();
  if (result.violations.length === 0) {
    console.log(`check:skill-protocol-coherence — ${result.files_inspected.length} files OK`);
    return;
  }
  for (const violation of result.violations) {
    console.error(formatViolation(violation));
  }
  console.error(`\ncheck:skill-protocol-coherence — ${result.violations.length} violation(s) across ${result.files_inspected.length} files`);
  process.exit(1);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.stack || error.message || String(error));
    process.exit(1);
  }
}

module.exports = {
  runCheck,
  checkDocument,
  REGISTERED_TOOL_NAMES,
};
