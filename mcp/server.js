#!/usr/bin/env node
"use strict";

// Public MCP server facade: runtime tool registry, dispatch, and CLI startup.

const {
  executeTool,
} = require("./lib/dispatch.js");
const {
  TOOL_MANIFEST,
  TOOLS,
} = require("./lib/tool-registry.js");
const {
  startStdioServer,
} = require("./lib/transport.js");

function startServer() {
  startStdioServer({ tools: TOOLS, executeTool });
}

module.exports = {
  TOOLS,
  TOOL_MANIFEST,
  executeTool,
  startServer,
};

if (require.main === module) {
  startServer();
}
