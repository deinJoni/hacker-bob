"use strict";

const fs = require("fs");
const { attackSurfacePath } = require("./paths.js");
const { readJsonFile } = require("./storage.js");
const { appendEdges } = require("./surface-graph.js");
const { querySchemaContracts } = require("./schema-contracts-store.js");
const { hashCanonicalJson } = require("./verification-contracts.js");

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function safeReadAttackSurface(domain) {
  const filePath = attackSurfacePath(domain);
  if (!fs.existsSync(filePath)) return null;
  try {
    const parsed = readJsonFile(filePath, { label: "attack_surface.json" });
    if (!isPlainObject(parsed) || !Array.isArray(parsed.surfaces)) return null;
    return parsed;
  } catch (_err) {
    return null;
  }
}

function pushEdge(edges, edge) {
  edges.push(edge);
}

function edgesFromAttackSurface(parsedSurface) {
  if (parsedSurface == null) return [];
  const edges = [];
  for (const surface of parsedSurface.surfaces) {
    if (!isPlainObject(surface)) continue;
    const surfaceId = typeof surface.id === "string" ? surface.id : null;
    if (!surfaceId) continue;
    const hosts = Array.isArray(surface.hosts)
      ? surface.hosts.filter((h) => typeof h === "string" && h.length > 0)
      : [];
    const endpoints = Array.isArray(surface.endpoints)
      ? surface.endpoints.filter((e) => typeof e === "string" && e.length > 0)
      : [];
    const techStack = Array.isArray(surface.tech_stack)
      ? surface.tech_stack.filter((t) => typeof t === "string" && t.length > 0)
      : [];
    const jsHints = Array.isArray(surface.js_hints)
      ? surface.js_hints.filter((j) => typeof j === "string" && j.length > 0)
      : [];
    const leakedSecrets = Array.isArray(surface.leaked_secrets)
      ? surface.leaked_secrets.filter((s) => typeof s === "string" && s.length > 0)
      : [];
    for (const endpoint of endpoints) {
      pushEdge(edges, {
        source: { type: "surface", id: surfaceId },
        target: { type: "endpoint", id: endpoint },
        edge_type: "contains",
        source_artifact: "attack_surface.json",
        confidence: 1,
      });
      for (const host of hosts) {
        pushEdge(edges, {
          source: { type: "subdomain", id: host },
          target: { type: "endpoint", id: endpoint },
          edge_type: "hosts",
          source_artifact: "attack_surface.json",
          confidence: 0.9,
        });
      }
    }
    for (const host of hosts) {
      pushEdge(edges, {
        source: { type: "surface", id: surfaceId },
        target: { type: "subdomain", id: host },
        edge_type: "contains",
        source_artifact: "attack_surface.json",
        confidence: 1,
      });
    }
    for (const tech of techStack) {
      pushEdge(edges, {
        source: { type: "surface", id: surfaceId },
        target: { type: "tech", id: tech.toLowerCase() },
        edge_type: "references",
        source_artifact: "attack_surface.json",
        confidence: 0.8,
      });
    }
    for (const jsHint of jsHints) {
      pushEdge(edges, {
        source: { type: "surface", id: surfaceId },
        target: { type: "js_file", id: jsHint },
        edge_type: "references",
        source_artifact: "attack_surface.json",
        confidence: 0.7,
      });
    }
    for (const secret of leakedSecrets) {
      const markerId = `secret-${hashCanonicalJson({ secret }).slice(0, 16)}`;
      pushEdge(edges, {
        source: { type: "surface", id: surfaceId },
        target: { type: "secret_marker", id: markerId },
        edge_type: "leaks",
        source_artifact: "attack_surface.json",
        confidence: 0.6,
      });
    }
  }
  return edges;
}

function edgesFromSchemaCorpus(domain) {
  let queryResult;
  try {
    queryResult = querySchemaContracts({ target_domain: domain });
  } catch (_err) {
    return [];
  }
  if (!queryResult || !Array.isArray(queryResult.contracts)) return [];
  const edges = [];
  for (const contract of queryResult.contracts) {
    if (!isPlainObject(contract)) continue;
    const endpoint = typeof contract.endpoint === "string" ? contract.endpoint : null;
    if (!endpoint) continue;
    const sourceDocHash = typeof contract.source_doc_hash === "string"
      ? contract.source_doc_hash
      : null;
    const sourceUri = typeof contract.source_uri === "string" ? contract.source_uri : null;
    const specId = sourceUri || (sourceDocHash ? `spec-${sourceDocHash.slice(0, 16)}` : null);
    if (specId) {
      pushEdge(edges, {
        source: { type: "openapi_spec", id: specId },
        target: { type: "endpoint", id: endpoint },
        edge_type: "documents",
        source_artifact: "schema-contracts.jsonl",
        confidence: 1,
      });
    }
    const claimedAuth = isPlainObject(contract.claimed_auth) ? contract.claimed_auth : null;
    if (claimedAuth && Array.isArray(claimedAuth.schemes)) {
      for (const scheme of claimedAuth.schemes) {
        if (typeof scheme !== "string" || scheme.length === 0) continue;
        pushEdge(edges, {
          source: { type: "endpoint", id: endpoint },
          target: { type: "auth_scheme", id: scheme },
          edge_type: "claims_auth",
          source_artifact: "schema-contracts.jsonl",
          confidence: 1,
        });
      }
    }
  }
  return edges;
}

function buildSurfaceGraph({ target_domain, sources }) {
  const enabledSources = Array.isArray(sources) && sources.length > 0
    ? new Set(sources)
    : new Set(["attack_surface", "schema_corpus"]);
  const allEdges = [];
  const sourcesUsed = [];
  if (enabledSources.has("attack_surface")) {
    const parsed = safeReadAttackSurface(target_domain);
    if (parsed) {
      const edges = edgesFromAttackSurface(parsed);
      allEdges.push(...edges);
      sourcesUsed.push({ source: "attack_surface", edge_count: edges.length });
    } else {
      sourcesUsed.push({ source: "attack_surface", edge_count: 0, missing: true });
    }
  }
  if (enabledSources.has("schema_corpus")) {
    const edges = edgesFromSchemaCorpus(target_domain);
    allEdges.push(...edges);
    sourcesUsed.push({ source: "schema_corpus", edge_count: edges.length });
  }
  const result = appendEdges({ target_domain, edges: allEdges });
  return {
    target_domain: result.target_domain,
    sources_used: sourcesUsed,
    new_count: result.new_count,
    replaced_count: result.replaced_count,
    total_in_graph: result.total_in_graph,
  };
}

module.exports = {
  buildSurfaceGraph,
  edgesFromAttackSurface,
  edgesFromSchemaCorpus,
};
