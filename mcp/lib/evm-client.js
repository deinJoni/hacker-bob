"use strict";

const { resolveEvmRpcEndpoints } = require("./evm-rpc-pool.js");
const {
  filterResolvedPublicRpcEndpoints,
  redactRpcEndpoint,
  redactRpcEndpointText,
  summarizeRpcPolicyRejections,
} = require("./sc-egress-policy.js");
const { requestPublicHttpsText } = require("./sc-http-client.js");

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024; // 256 KiB
const DEFAULT_MAX_RESULT_BYTES = 64 * 1024;     // 64 KiB returned to caller

const HEX_BYTES_RE = /^0x([0-9a-fA-F]*)$/;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const STORAGE_SLOT_RE = /^0x[0-9a-fA-F]{1,64}$/;

function isAddress(value) {
  return typeof value === "string" && ADDRESS_RE.test(value);
}

function isHexBytes(value) {
  return typeof value === "string" && HEX_BYTES_RE.test(value);
}

function isStorageSlot(value) {
  return typeof value === "string" && STORAGE_SLOT_RE.test(value);
}

function normalizeBlockTag(value) {
  if (value == null || value === "" || value === "latest" || value === "earliest" || value === "pending" || value === "safe" || value === "finalized") {
    return value || "latest";
  }
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) {
    return `0x${value.toString(16)}`;
  }
  if (typeof value === "string" && /^0x[0-9a-fA-F]+$/.test(value)) {
    return value.toLowerCase();
  }
  if (typeof value === "string" && /^[0-9]+$/.test(value)) {
    return `0x${BigInt(value).toString(16)}`;
  }
  throw new Error(`block must be 'latest|earliest|pending|safe|finalized', a non-negative integer, or a hex string; received: ${value}`);
}

async function rpcRequestOnce(url, method, params, { timeoutMs = DEFAULT_TIMEOUT_MS, maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES, lookup } = {}) {
  const displayUrl = redactRpcEndpoint(url);
  const resp = await requestPublicHttpsText(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", method, params, id: 1 }),
    timeoutMs,
    maxBytes: maxResponseBytes,
    lookup,
  });
  const text = resp.text;
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status} from ${displayUrl}: ${redactRpcEndpointText(text).slice(0, 200)}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`malformed JSON-RPC response from ${displayUrl}: ${error.message || String(error)}`);
  }
  if (parsed && parsed.error) {
    const message = typeof parsed.error.message === "string" ? parsed.error.message : JSON.stringify(parsed.error);
    const err = new Error(`JSON-RPC error from ${displayUrl}: ${redactRpcEndpointText(message)}`);
    err.rpcError = parsed.error;
    throw err;
  }
  return parsed && parsed.result;
}

async function rpcRequest({
  chainId,
  method,
  params,
  endpoints,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  lookup,
} = {}) {
  const rawEndpointList = Array.isArray(endpoints) && endpoints.length > 0
    ? endpoints
    : resolveEvmRpcEndpoints(chainId);
  const { endpoints: endpointList, rejected } = await filterResolvedPublicRpcEndpoints(rawEndpointList, { lookup });
  if (endpointList.length === 0) {
    const err = new Error(`no public HTTPS RPC endpoints available for chain_id ${chainId}; set BOB_EVM_RPCS_${chainId}=url1,url2 to override`);
    err.rpc_policy_rejections = summarizeRpcPolicyRejections(rejected);
    err.details = { rpc_policy_rejections: err.rpc_policy_rejections };
    throw err;
  }

  const errors = [];
  for (const endpoint of endpointList) {
    try {
      const result = await rpcRequestOnce(endpoint, method, params, { timeoutMs, maxResponseBytes, lookup });
      return { result, endpoint: redactRpcEndpoint(endpoint) };
    } catch (error) {
      errors.push({
        endpoint: redactRpcEndpoint(endpoint),
        message: redactRpcEndpointText(error.message || String(error)),
      });
    }
  }
  const summary = errors.map((e) => `${e.endpoint}: ${e.message}`).join("; ");
  const err = new Error(`all RPC endpoints failed for ${method} on chain ${chainId}: ${summary}`);
  err.attempts = errors;
  throw err;
}

async function ethCall({ chainId, to, data, block = "latest", from = null, endpoints }) {
  if (!isAddress(to)) throw new Error(`to must be a 20-byte hex address, received: ${to}`);
  if (!isHexBytes(data)) throw new Error(`data must be a hex string, received: ${data}`);
  if (from != null && !isAddress(from)) throw new Error(`from must be a 20-byte hex address, received: ${from}`);
  const txObject = { to, data };
  if (from) txObject.from = from;
  return rpcRequest({
    chainId,
    method: "eth_call",
    params: [txObject, normalizeBlockTag(block)],
    endpoints,
    maxResponseBytes: DEFAULT_MAX_RESULT_BYTES * 4,
  });
}

async function ethGetStorageAt({ chainId, address, slot, block = "latest", endpoints }) {
  if (!isAddress(address)) throw new Error(`address must be a 20-byte hex address, received: ${address}`);
  if (!isStorageSlot(slot)) throw new Error(`slot must be a hex string with up to 32 bytes, received: ${slot}`);
  return rpcRequest({
    chainId,
    method: "eth_getStorageAt",
    params: [address, slot, normalizeBlockTag(block)],
    endpoints,
    maxResponseBytes: 4096,
  });
}

async function ethGetCode({ chainId, address, block = "latest", endpoints }) {
  if (!isAddress(address)) throw new Error(`address must be a 20-byte hex address, received: ${address}`);
  return rpcRequest({
    chainId,
    method: "eth_getCode",
    params: [address, normalizeBlockTag(block)],
    endpoints,
    maxResponseBytes: 1024 * 1024, // up to 1 MiB for runtime bytecode
  });
}

async function ethBlockNumber({ chainId, endpoints }) {
  const { result } = await rpcRequest({
    chainId,
    method: "eth_blockNumber",
    params: [],
    endpoints,
    maxResponseBytes: 1024,
  });
  return result;
}

module.exports = {
  ADDRESS_RE,
  HEX_BYTES_RE,
  STORAGE_SLOT_RE,
  DEFAULT_MAX_RESULT_BYTES,
  ethBlockNumber,
  ethCall,
  ethGetCode,
  ethGetStorageAt,
  isAddress,
  isHexBytes,
  isStorageSlot,
  normalizeBlockTag,
  rpcRequest,
};
