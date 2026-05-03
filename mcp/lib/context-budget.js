"use strict";

const fs = require("fs");
const {
  assertNonEmptyString,
  normalizeOptionalText,
} = require("./validation.js");
const {
  readAttackSurfaceStrict,
} = require("./attack-surface.js");
const {
  surfaceRoutesPath,
} = require("./paths.js");
const {
  readJsonFile,
} = require("./storage.js");
const {
  getCapabilityPack,
  getCapabilityPackContextBudget,
  normalizeContextBudget,
} = require("./capability-packs.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");

function getContextBudget(args) {
  const capabilityPack = assertNonEmptyString(args.capability_pack, "capability_pack");
  const pack = getCapabilityPack(capabilityPack);
  if (!pack) {
    throw new Error(`Unknown capability_pack: ${capabilityPack}`);
  }

  const targetDomain = normalizeOptionalText(args.target_domain, "target_domain");
  const surfaceId = normalizeOptionalText(args.surface_id, "surface_id");
  let briefProfile = normalizeOptionalText(args.brief_profile, "brief_profile") || pack.brief_profile;
  let capabilityPackVersion = pack.capability_pack_version;
  let contextBudget = getCapabilityPackContextBudget(capabilityPack);

  if (surfaceId && !targetDomain) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "target_domain is required when surface_id is provided",
    );
  }

  if (briefProfile !== pack.brief_profile) {
    throw new Error(`brief_profile ${briefProfile} does not match capability_pack ${capabilityPack}`);
  }

  if (targetDomain && surfaceId) {
    const attackSurface = readAttackSurfaceStrict(targetDomain);
    if (!attackSurface.surface_id_set.has(surfaceId)) {
      throw new Error(`Unknown surface_id: ${surfaceId}`);
    }

    const routesPath = surfaceRoutesPath(targetDomain);
    if (fs.existsSync(routesPath)) {
      const routes = readJsonFile(routesPath);
      const route = routes && Array.isArray(routes.routes)
        ? routes.routes.find((entry) => entry.surface_id === surfaceId)
        : null;
      if (route) {
        if (route.capability_pack !== capabilityPack) {
          throw new Error(`surface_id ${surfaceId} is routed to capability_pack ${route.capability_pack}`);
        }
        if (route.brief_profile) briefProfile = route.brief_profile;
        if (route.capability_pack_version) capabilityPackVersion = route.capability_pack_version;
        if (route.context_budget && typeof route.context_budget === "object" && !Array.isArray(route.context_budget)) {
          contextBudget = normalizeContextBudget(route.context_budget, pack);
        }
      }
    }
  }

  return JSON.stringify({
    version: 1,
    capability_pack: capabilityPack,
    capability_pack_version: capabilityPackVersion,
    brief_profile: briefProfile,
    context_budget: contextBudget,
  });
}

module.exports = {
  getContextBudget,
};
