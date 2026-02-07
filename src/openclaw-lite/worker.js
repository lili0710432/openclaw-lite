/* eslint-disable no-console */

import { agentLoop } from "@mariozechner/pi-agent-core/dist/agent-loop.js";
import { zipSync } from "fflate";

import {
  repairToolCallInputs,
  repairToolUseResultPairing,
} from "../../vendor/openclaw-main/src/agents/session-transcript-repair.ts";

import { base58Encode } from "./shared/base58.js";
import { b64ToBytes, bytesToB64, utf8ToBytes } from "./shared/encoding.js";
import {
  aesGcmDecryptRaw,
  aesGcmEncryptRaw,
  hkdfSha256,
  importHmacSha256Key,
  randomBytes,
  sha256,
  sha256B64FromUtf8,
  hmacSha256B64,
} from "./shared/crypto.js";
import { deleteByKeys, getAllFromIndex, getRecord, putRecord } from "./shared/idb.js";
import { vfsGetUtf8, vfsPutBytes, vfsPutUtf8, vfsReadAllBytes } from "./shared/vfs.js";

const OPENCLAW_VERSION = __OPENCLAW_VERSION__;
const PI_VERSIONS = __PI_VERSIONS__;

const MAIN_AGENT_ID = "main";
const MAIN_SESSION_KEY = "agent:main:main";

const MAX_CHECKPOINTS_PER_HOUSE = 50;

function post(msg) {
  self.postMessage(msg);
}

function log(line) {
  post({ type: "worker.log.append", line: String(line || "") });
}

function updateGatewayState() {
  post({
    type: "worker.state.update",
    state: {
      houseId: state.houseId,
      vault: { latestBackupId: state.vaultLatestBackupId || null },
    },
  });
}

function nowMs() {
  return Date.now();
}

function randomId(prefix) {
  const r = Math.random().toString(16).slice(2);
  return `${prefix}_${Date.now()}_${r}`;
}

async function metaGet(key) {
  const rec = await getRecord("meta", key);
  return rec ? rec.value : null;
}

async function metaSet(key, value) {
  await putRecord("meta", { key, value });
}

function safeOrigin() {
  try {
    return self.location?.origin || "";
  } catch {
    return "";
  }
}

function assertAllowlistedUrl(url) {
  const u = new URL(url, safeOrigin() || "http://localhost");
  const origin = safeOrigin();
  if (origin && u.origin !== origin) {
    throw new Error("NETWORK_ORIGIN_NOT_ALLOWLISTED");
  }
}

async function apiJson(url, opts = {}) {
  assertAllowlistedUrl(url);
  const res = await fetch(url, {
    ...opts,
    credentials: "include",
    headers: {
      "content-type": "application/json",
      ...(opts.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = data?.error || `HTTP_${res.status}`;
    throw new Error(err);
  }
  return data;
}

// --- PI-AI model configuration (NO MOCKS) ---
//
// Lite runs PI's agent loop in-browser and uses PI-AI providers for real LLM calls.
// In this repo, calls go to a same-origin OpenAI-compatible proxy:
// - /api/llm/openai/v1/chat/completions
//
// Tests use the same endpoint but the server responds deterministically.
function defaultLlmBaseUrl() {
  // Must be same-origin to satisfy the runtime allowlist.
  const u = new URL("/api/llm/openai/v1", safeOrigin() || "http://localhost");
  return u.toString();
}

function getConfiguredModel() {
  const api = state.llmApi || "openai-completions";
  const provider = state.llmProvider || "openai";
  const id = state.llmModelId || "gpt-4o-mini";
  const baseUrl = state.llmBaseUrl || defaultLlmBaseUrl();
  assertAllowlistedUrl(baseUrl);

  /** @type {import("@mariozechner/pi-ai").Model<any>} */
  return {
    id,
    name: id,
    api,
    provider,
    baseUrl,
    headers: {},
    reasoning: false,
    input: ["text"],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 128_000,
    maxTokens: 4096,
  };
}

function makeAssistant(text, { stopReason = "stop", errorMessage = null } = {}) {
  const model = getConfiguredModel();
  const msg = {
    role: "assistant",
    content: [{ type: "text", text: String(text || "") }],
    api: model.api,
    provider: model.provider,
    model: model.id,
    usage: {
      input: 0,
      output: 0,
      cacheRead: 0,
      cacheWrite: 0,
      totalTokens: 0,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
    },
    stopReason,
    timestamp: nowMs(),
  };
  if (errorMessage) msg.errorMessage = String(errorMessage || "");
  return msg;
}

async function runAgentTurn(userText) {
  const prompt = {
    role: "user",
    content: String(userText || ""),
    timestamp: nowMs(),
  };

  if (!state.llmApiKey) {
    const m = makeAssistant("LLM not configured. Set your API key in the Gateway panel.", { stopReason: "error" });
    state.transcript.push(prompt);
    state.transcript.push(m);
    post({ type: "worker.chat.append", role: "user", text: String(userText || "") });
    post({ type: "worker.chat.append", role: "assistant", text: "LLM not configured. Set your API key in the Gateway panel." });
    await persistTranscript();
    return;
  }

  const context = {
    systemPrompt: "",
    messages: state.transcript.slice(),
    tools: [],
  };

  const config = {
    model: getConfiguredModel(),
    apiKey: state.llmApiKey,
    reasoning: undefined,
    convertToLlm: (messages) => messages.filter((m) => m && (m.role === "user" || m.role === "assistant" || m.role === "toolResult")),
  };

  const abortController = new AbortController();
  const stream = agentLoop([prompt], context, config, abortController.signal);

  for await (const event of stream) {
    if (event.type === "message_end") {
      const m = event.message;
      if (!m || typeof m !== "object" || typeof m.role !== "string") continue;
      state.transcript.push(m);
      if (m.role === "user") post({ type: "worker.chat.append", role: "user", text: userText });
      if (m.role === "assistant") {
        const t = Array.isArray(m.content)
          ? m.content.map((c) => (c && c.type === "text" ? c.text : "")).join("")
          : "";
        post({ type: "worker.chat.append", role: "assistant", text: t });
      }
      await persistTranscript();
    }
  }
}

// --- Approvals ---
const approvals = new Map();

function requestApproval({ title, body }) {
  const id = randomId("ap");
  post({ type: "worker.approval.request", approval: { id, title, body } });
  return new Promise((resolve) => {
    approvals.set(id, resolve);
  });
}

function resolveApproval(id, decision) {
  const fn = approvals.get(id);
  if (!fn) return;
  approvals.delete(id);
  post({ type: "worker.approval.clear", id });
  fn(decision === "approve" ? "approve" : "reject");
}

// --- Wallet bridge ---
const walletRequests = new Map();

function walletRequest(method, payload) {
  const id = randomId("w");
  post({ type: "worker.wallet.request", id, method, ...(payload || {}) });
  return new Promise((resolve, reject) => {
    walletRequests.set(id, { resolve, reject });
  });
}

function resolveWalletResponse(msg) {
  const id = String(msg.id || "");
  const rec = walletRequests.get(id);
  if (!rec) return;
  walletRequests.delete(id);
  if (msg.ok) rec.resolve(msg);
  else rec.reject(new Error(msg.error || "WALLET_ERROR"));
}

async function walletConnect() {
  const res = await walletRequest("connect", {});
  const addr = typeof res.address === "string" ? res.address.trim() : "";
  if (!addr) throw new Error("WALLET_NOT_CONNECTED");
  return addr;
}

async function walletSignMessage(message) {
  const res = await walletRequest("signMessage", { message });
  const sig = typeof res.signatureB64 === "string" ? res.signatureB64.trim() : "";
  if (!sig) throw new Error("MISSING_SIGNATURE");
  return { address: typeof res.address === "string" ? res.address.trim() : "", signatureBytes: b64ToBytes(sig) };
}

// --- Checkpoints ---
async function writeCheckpoint(reason) {
  const houseId = state.houseId || null;
  const checkpoint = {
    v: 1,
    checkpointId: randomId("cp"),
    createdAtMs: nowMs(),
    houseId,
    reason,
    state: {
      runtime: { houseId: state.houseId || null, sessionId: state.sessionId || null },
      vaultPointer: { latestBackupId: state.vaultLatestBackupId || null },
    },
  };

  await putRecord("checkpoints", checkpoint);

  if (!houseId) return;
  const all = await getAllFromIndex(
    "checkpoints",
    "by_house_createdAtMs",
    IDBKeyRange.bound([houseId, 0], [houseId, 9e15]),
    "asc",
  );
  if (all.length <= MAX_CHECKPOINTS_PER_HOUSE) return;
  const toDelete = all
    .slice(0, all.length - MAX_CHECKPOINTS_PER_HOUSE)
    .map((x) => x.checkpointId)
    .filter(Boolean);
  await deleteByKeys("checkpoints", toDelete);
}

// --- OpenClaw VFS persistence ---
async function ensureWorkspaceFiles() {
  const required = [
    ["workspace/AGENTS.md", "# Agents\n\nOpenClaw Lite exports OpenClaw-compatible artifacts.\n"],
    ["workspace/SOUL.md", "# Soul\n\nThis is a minimal OpenClaw Lite soul.\n"],
    ["workspace/USER.md", "# User\n\nUser profile is stored locally.\n"],
    ["workspace/IDENTITY.md", `# Identity\n\nhouseId: ${state.houseId || "unknown"}\n`],
    ["workspace/TOOLS.md", "# Tools\n\nBrowser runtime. Networking is allowlisted.\n"],
  ];

  for (const [p, content] of required) {
    const existing = await vfsGetUtf8(p);
    if (existing === null) {
      await vfsPutUtf8(p, content);
    }
  }
}

async function ensureSessionFiles() {
  if (!state.sessionId) {
    state.sessionId = randomId("sess");
    await metaSet("sessionId", state.sessionId);
  }
  const sessionsPath = `.openclaw/agents/${MAIN_AGENT_ID}/sessions/sessions.json`;
  const existing = await vfsGetUtf8(sessionsPath);
  let store = {};
  if (existing) {
    try {
      store = JSON.parse(existing);
    } catch {
      store = {};
    }
  }
  store[MAIN_SESSION_KEY] = { sessionId: state.sessionId, updatedAt: nowMs() };
  await vfsPutUtf8(sessionsPath, JSON.stringify(store, null, 2));

  const transcriptPath = `.openclaw/agents/${MAIN_AGENT_ID}/sessions/${state.sessionId}.jsonl`;
  const tExisting = await vfsGetUtf8(transcriptPath);
  if (tExisting === null) {
    await vfsPutUtf8(transcriptPath, "");
  }
}

async function persistTranscript() {
  await ensureSessionFiles();
  const sessionsPath = `.openclaw/agents/${MAIN_AGENT_ID}/sessions/sessions.json`;
  const transcriptPath = `.openclaw/agents/${MAIN_AGENT_ID}/sessions/${state.sessionId}.jsonl`;

  // Repair using OpenClaw source of truth before writing.
  const repairedInputs = repairToolCallInputs(state.transcript);
  const repairedTools = repairToolUseResultPairing(repairedInputs.messages);
  const repaired = repairedTools.messages;
  state.transcript = repaired;

  const jsonl = repaired.map((m) => JSON.stringify(m)).join("\n") + "\n";
  await vfsPutUtf8(transcriptPath, jsonl);

  let store = {};
  try {
    store = JSON.parse((await vfsGetUtf8(sessionsPath)) || "{}");
  } catch {
    store = {};
  }
  store[MAIN_SESSION_KEY] = { sessionId: state.sessionId, updatedAt: nowMs() };
  await vfsPutUtf8(sessionsPath, JSON.stringify(store, null, 2));
}

// --- House crypto helpers (mirrors public/create.js + public/house.js) ---
function buildHouseKeyWrapMessage({ houseId, origin }) {
  const parts = ["ElizaTown House Key Wrap", `houseId: ${houseId}`];
  if (origin) parts.push(`origin: ${origin}`);
  return parts.join("\n");
}

function buildVaultKeyWrapMessage({ houseId, origin }) {
  return ["ElizaTown Vault Backup Key Wrap", `houseId: ${houseId}`, `origin: ${origin}`].join("\n");
}

async function deriveHouseKeysFromKroot(krootBytes) {
  const kencBytes = await hkdfSha256(krootBytes, "elizatown-house-enc-v1", 32);
  const kauthBytes = await hkdfSha256(krootBytes, "elizatown-house-auth-v1", 32);
  const kauthKey = await importHmacSha256Key(kauthBytes, ["sign"]);
  return { kencBytes, kauthBytes, kauthKey };
}

async function houseAuthHeaders({ houseId, method, urlPath, body }) {
  if (!state.kauthKey) throw new Error("HOUSE_AUTH_NOT_READY");
  const ts = String(nowMs());
  const bodyHash = await sha256B64FromUtf8(body || "");
  const msg = `${houseId}.${ts}.${method}.${urlPath}.${bodyHash}`;
  const auth = await hmacSha256B64(state.kauthKey, msg);
  return { "x-house-ts": ts, "x-house-auth": auth };
}

// --- Vault backup ---
async function ensureDeterministicSigner(message) {
  const a = await walletSignMessage(message);
  const b = await walletSignMessage(message);
  const aa = a.signatureBytes;
  const bb = b.signatureBytes;
  if (aa.length !== bb.length) throw new Error("NON_DETERMINISTIC_SIGNATURES");
  for (let i = 0; i < aa.length; i += 1) {
    if (aa[i] !== bb[i]) throw new Error("NON_DETERMINISTIC_SIGNATURES");
  }
  return a;
}

async function deriveVaultKeyBytes({ houseId }) {
  const origin = safeOrigin();
  const message = buildVaultKeyWrapMessage({ houseId, origin });
  const { signatureBytes } = await ensureDeterministicSigner(message);
  const wrapKeyBytes = await sha256(signatureBytes);
  return await hkdfSha256(wrapKeyBytes, "elizatown-vault-backup-v1", 32);
}

async function buildVaultPlaintext() {
  const allFiles = await vfsReadAllBytes("");
  const vfs = {};
  for (const [p, bytes] of Object.entries(allFiles)) {
    vfs[p] = bytesToB64(bytes);
  }
  return {
    v: 1,
    schema: "openclaw-lite-vault@1",
    createdAtMs: nowMs(),
    houseId: state.houseId,
    krootB64: state.krootBytes ? bytesToB64(state.krootBytes) : null,
    marker: state.secretMarker || null,
    vfs,
  };
}

async function lockAndBackupVault() {
  if (!state.houseId || !state.krootBytes) throw new Error("HOUSE_NOT_READY");
  const decision = await requestApproval({ title: "Approval", body: "Lock + backup vault" });
  if (decision !== "approve") {
    log("backup rejected");
    return;
  }

  const vaultKeyBytes = await deriveVaultKeyBytes({ houseId: state.houseId });
  const plaintext = await buildVaultPlaintext();
  const ptBytes = utf8ToBytes(JSON.stringify(plaintext));
  const enc = await aesGcmEncryptRaw(vaultKeyBytes, ptBytes);
  const sha = await sha256(enc.ct);

  const envelope = {
    v: 1,
    alg: "AES-GCM",
    kdf: {
      kind: "wallet-signature",
      wallet: "solana",
      message: buildVaultKeyWrapMessage({ houseId: state.houseId, origin: safeOrigin() }),
      origin: safeOrigin(),
      houseId: state.houseId,
    },
    iv: bytesToB64(enc.iv),
    ct: bytesToB64(enc.ct),
    meta: {
      schema: "openclaw-lite-vault@1",
      createdAtMs: nowMs(),
      byteLength: ptBytes.length,
      sha256: bytesToB64(sha),
    },
  };

  const urlPath = `/api/house/${encodeURIComponent(state.houseId)}/vault/backup`;
  const body = JSON.stringify({ vault: envelope });
  const headers = await houseAuthHeaders({ houseId: state.houseId, method: "POST", urlPath, body });
  const resp = await apiJson(urlPath, { method: "POST", body, headers });
  state.vaultLatestBackupId = resp?.backupId || null;
  await metaSet("vaultLatestBackupId", state.vaultLatestBackupId);
  updateGatewayState();
  log(`backup ok ${state.vaultLatestBackupId || ""}`);

  // Lock: wipe K_root from memory, but keep persisted VFS.
  state.krootBytes = null;
  state.kencBytes = null;
  state.kauthBytes = null;
  state.kauthKey = null;
  await metaSet("krootB64", null);
}

async function restoreFromLatestVault() {
  if (!state.houseId) throw new Error("HOUSE_NOT_READY");

  // If K_root is missing, recover via wallet keyWrap.
  if (!state.krootBytes) {
    await recoverHouse();
  }
  if (!state.krootBytes) throw new Error("HOUSE_KEY_NOT_RECOVERED");

  const urlPath = `/api/house/${encodeURIComponent(state.houseId)}/vault/latest`;
  const headers = await houseAuthHeaders({ houseId: state.houseId, method: "GET", urlPath, body: "" });
  const resp = await apiJson(urlPath, { method: "GET", headers });
  const vault = resp?.vault || null;
  if (!vault || typeof vault.ct !== "string" || typeof vault.iv !== "string") throw new Error("NO_VAULT");

  const vaultKeyBytes = await deriveVaultKeyBytes({ houseId: state.houseId });
  const ptBytes = await aesGcmDecryptRaw(vaultKeyBytes, b64ToBytes(vault.iv), b64ToBytes(vault.ct));

  const parsed = JSON.parse(new TextDecoder().decode(ptBytes));
  if (!parsed || parsed.v !== 1 || parsed.schema !== "openclaw-lite-vault@1") throw new Error("INVALID_VAULT");

  // Restore VFS (overwrite).
  const vfs = parsed.vfs && typeof parsed.vfs === "object" ? parsed.vfs : {};
  for (const [p, dataB64] of Object.entries(vfs)) {
    if (typeof p !== "string" || typeof dataB64 !== "string") continue;
    await vfsPutBytes(p, b64ToBytes(dataB64));
  }

  // Restore marker and transcript/session ids.
  state.secretMarker = parsed.marker || null;

  // If vault includes K_root, use it (still validate houseId).
  if (typeof parsed.krootB64 === "string" && parsed.krootB64) {
    const kroot = b64ToBytes(parsed.krootB64);
    const derivedHouseId = base58Encode(await sha256(kroot));
    if (derivedHouseId !== state.houseId) throw new Error("HOUSE_ID_MISMATCH");
    const keys = await deriveHouseKeysFromKroot(kroot);
    state.krootBytes = kroot;
    state.kencBytes = keys.kencBytes;
    state.kauthBytes = keys.kauthBytes;
    state.kauthKey = keys.kauthKey;
  }

  await ensureWorkspaceFiles();
  await ensureSessionFiles();
  await persistTranscript();
  log(`restore ok marker=${state.secretMarker || ""}`);
  updateGatewayState();
}

// --- Public profile ---
async function publishProfile({ housePublicJson, promptMd }) {
  if (!state.houseId || !state.kauthKey) throw new Error("HOUSE_NOT_READY");
  const decision = await requestApproval({ title: "Approval", body: "Publish public profile" });
  if (decision !== "approve") {
    log("publish rejected");
    return;
  }

  const urlPath = `/api/house/${encodeURIComponent(state.houseId)}/public-profile`;
  const body = JSON.stringify({ housePublicJson, promptMd: promptMd || "", previewImage: null, clear: false });
  const headers = await houseAuthHeaders({ houseId: state.houseId, method: "POST", urlPath, body });
  await apiJson(urlPath, { method: "POST", body, headers });
  log("publish ok");
}

// --- Export ---
async function exportZip() {
  await ensureWorkspaceFiles();
  await ensureSessionFiles();
  await persistTranscript();

  const files = await vfsReadAllBytes("");
  const manifest = {
    v: 1,
    kind: "openclaw-lite-export",
    createdAtMs: nowMs(),
    openclaw: {
      agentId: MAIN_AGENT_ID,
      mainSessionKey: MAIN_SESSION_KEY,
      compat: { openclawVersion: OPENCLAW_VERSION, piVersions: PI_VERSIONS },
    },
  };
  files["manifest.json"] = utf8ToBytes(JSON.stringify(manifest, null, 2));

  const zipped = zipSync(files, { level: 0 });
  post({ type: "worker.export.zip", filename: "openclaw-lite-export.zip", bytes: zipped.buffer }, [zipped.buffer]);
}

// --- House creation + recovery ---
async function createHouse({ rhB64 }) {
  if (state.houseId) return;

  const rh = b64ToBytes(rhB64);
  const ra = randomBytes(32);
  const combo = new Uint8Array(rh.length + ra.length);
  combo.set(rh, 0);
  combo.set(ra, rh.length);

  const kroot = await sha256(combo);
  const houseId = base58Encode(await sha256(kroot));
  const keys = await deriveHouseKeysFromKroot(kroot);

  const address = await walletConnect();
  const wrapMsg = buildHouseKeyWrapMessage({ houseId, origin: safeOrigin() });
  const { signatureBytes } = await walletSignMessage(wrapMsg);
  const wrapKeyBytes = await sha256(signatureBytes);
  const wrapped = await aesGcmEncryptRaw(wrapKeyBytes, kroot);
  const keyWrap = { alg: "AES-GCM", iv: bytesToB64(wrapped.iv), ct: bytesToB64(wrapped.ct) };

  const nonce = (await apiJson("/api/house/nonce"))?.nonce;
  await apiJson("/api/house/init", {
    method: "POST",
    body: JSON.stringify({
      houseId,
      housePubKey: houseId,
      nonce,
      keyMode: "ceremony",
      unlock: { kind: "solana-wallet-signature", address },
      keyWrap,
      houseAuthKey: bytesToB64(keys.kauthBytes),
    }),
  });

  state.houseId = houseId;
  state.krootBytes = kroot;
  state.kencBytes = keys.kencBytes;
  state.kauthBytes = keys.kauthBytes;
  state.kauthKey = keys.kauthKey;
  state.secretMarker = "secret.marker=1";

  await metaSet("houseId", houseId);
  await metaSet("krootB64", bytesToB64(kroot));
  await metaSet("secretMarker", state.secretMarker);

  await ensureWorkspaceFiles();
  await ensureSessionFiles();
  await persistTranscript();

  updateGatewayState();
  log(`house created ${houseId}`);
}

async function recoverHouse() {
  const address = await walletConnect();
  const nonceResp = await apiJson("/api/wallet/nonce");
  const nonce = nonceResp?.nonce;
  if (!nonce) throw new Error("NONCE_FAILED");
  const lookupMsg = ["ElizaTown House Lookup", `address: ${address}`, `nonce: ${nonce}`].join("\n");
  const lookupSig = await walletSignMessage(lookupMsg);
  const lookup = await apiJson("/api/wallet/lookup", {
    method: "POST",
    body: JSON.stringify({
      address,
      nonce,
      signature: bytesToB64(lookupSig.signatureBytes),
    }),
  });

  const houseId = typeof lookup?.houseId === "string" ? lookup.houseId.trim() : "";
  if (!houseId) throw new Error("HOUSE_NOT_FOUND");

  const keyWrap = lookup?.keyWrap || null;
  if (!keyWrap || keyWrap.alg !== "AES-GCM" || typeof keyWrap.iv !== "string" || typeof keyWrap.ct !== "string") {
    throw new Error("MISSING_KEY_WRAP");
  }

  async function decryptWithMessage(msg) {
    const sig = await walletSignMessage(msg);
    const wrapKeyBytes = await sha256(sig.signatureBytes);
    return await aesGcmDecryptRaw(wrapKeyBytes, b64ToBytes(keyWrap.iv), b64ToBytes(keyWrap.ct));
  }

  const attempts = [];
  attempts.push(buildHouseKeyWrapMessage({ houseId })); // legacy (no origin)
  const origin = safeOrigin();
  if (origin) {
    attempts.push(buildHouseKeyWrapMessage({ houseId, origin }));
    const u = new URL(origin);
    const portSuffix = u.port ? `:${u.port}` : "";
    if (u.hostname === "localhost") {
      attempts.push(buildHouseKeyWrapMessage({ houseId, origin: `${u.protocol}//127.0.0.1${portSuffix}` }));
    } else if (u.hostname === "127.0.0.1") {
      attempts.push(buildHouseKeyWrapMessage({ houseId, origin: `${u.protocol}//localhost${portSuffix}` }));
    }
  }

  let kroot = null;
  let lastErr = null;
  for (const msg of attempts) {
    try {
      kroot = await decryptWithMessage(msg);
      break;
    } catch (e) {
      lastErr = e;
    }
  }
  if (!kroot) throw new Error(lastErr?.message || "KEY_WRAP_DECRYPT_FAILED");

  const derivedHouseId = base58Encode(await sha256(kroot));
  if (derivedHouseId !== houseId) throw new Error("HOUSE_ID_MISMATCH");

  const keys = await deriveHouseKeysFromKroot(kroot);
  state.houseId = houseId;
  state.krootBytes = kroot;
  state.kencBytes = keys.kencBytes;
  state.kauthBytes = keys.kauthBytes;
  state.kauthKey = keys.kauthKey;

  await metaSet("houseId", houseId);
  await metaSet("krootB64", bytesToB64(kroot));

  updateGatewayState();
  log(`house recovered ${houseId}`);
}

async function appendE2eeEntry(text) {
  if (!state.houseId || !state.krootBytes || !state.kencBytes) throw new Error("HOUSE_NOT_READY");
  const decision = await requestApproval({ title: "Approval", body: "Append entry" });
  if (decision !== "approve") {
    log("append rejected");
    return;
  }

  const payload = {
    v: 1,
    id: randomId("e"),
    ts: nowMs(),
    author: "lite",
    type: "note",
    body: { text: String(text || "") },
  };
  const pt = utf8ToBytes(JSON.stringify(payload));
  const aad = utf8ToBytes(`house=${state.houseId}`);
  const enc = await aesGcmEncryptRaw(state.kencBytes, pt, aad);
  const ciphertext = { alg: "AES-GCM", iv: bytesToB64(enc.iv), ct: bytesToB64(enc.ct) };

  const urlPath = `/api/house/${encodeURIComponent(state.houseId)}/append`;
  const body = JSON.stringify({ ciphertext, author: "lite" });
  const headers = await houseAuthHeaders({ houseId: state.houseId, method: "POST", urlPath, body });
  await apiJson(urlPath, { method: "POST", body, headers });
  log("append ok");
}

// --- State ---
const state = {
  houseId: null,
  krootBytes: null,
  kencBytes: null,
  kauthBytes: null,
  kauthKey: null,
  vaultLatestBackupId: null,
  secretMarker: null,
  sessionId: null,
  transcript: [],
  llmApi: null,
  llmProvider: null,
  llmModelId: null,
  llmBaseUrl: null,
  llmApiKey: null,
};

async function loadStateFromIdb() {
  state.houseId = (await metaGet("houseId")) || null;
  state.vaultLatestBackupId = (await metaGet("vaultLatestBackupId")) || null;
  state.secretMarker = (await metaGet("secretMarker")) || null;
  state.sessionId = (await metaGet("sessionId")) || null;

  state.llmApi = (await metaGet("llmApi")) || null;
  state.llmProvider = (await metaGet("llmProvider")) || null;
  state.llmModelId = (await metaGet("llmModelId")) || null;
  state.llmBaseUrl = (await metaGet("llmBaseUrl")) || null;
  state.llmApiKey = (await metaGet("llmApiKey")) || null;

  const krootB64 = (await metaGet("krootB64")) || null;
  if (typeof krootB64 === "string" && krootB64) {
    const kroot = b64ToBytes(krootB64);
    const keys = await deriveHouseKeysFromKroot(kroot);
    state.krootBytes = kroot;
    state.kencBytes = keys.kencBytes;
    state.kauthBytes = keys.kauthBytes;
    state.kauthKey = keys.kauthKey;
  }

  await ensureWorkspaceFiles();
  await ensureSessionFiles();

  // Hydrate transcript from VFS.
  if (state.sessionId) {
    const transcriptPath = `.openclaw/agents/${MAIN_AGENT_ID}/sessions/${state.sessionId}.jsonl`;
    const raw = await vfsGetUtf8(transcriptPath);
    if (raw) {
      const lines = raw.split(/\r?\n/).filter((l) => l.trim().length > 0);
      const parsed = [];
      for (const line of lines) {
        try {
          parsed.push(JSON.parse(line));
        } catch {
          // ignore malformed
        }
      }
      state.transcript = parsed;
    }
  }
}

async function boot() {
  await loadStateFromIdb();
  updateGatewayState();
  post({ type: "worker.runtime.ready" });
  post({ type: "worker.runtime.status", status: "ready" });

  if (!state.transcript.length) {
    const m = makeAssistant("openclaw-lite boot");
    state.transcript.push(m);
    post({ type: "worker.chat.append", role: "assistant", text: "openclaw-lite boot" });
    await persistTranscript();
  }

  // Demo approval request (M1): deterministic and immediate.
  const decision = await requestApproval({ title: "Approval", body: "Demo approval request" });
  log(`demo approval: ${decision === "approve" ? "approved" : "rejected"}`);
}

self.addEventListener("message", async (ev) => {
  const msg = ev.data;
  if (!msg || typeof msg.type !== "string") return;

  try {
    if (msg.type === "gateway.boot") {
      // no-op; boot is implicit
      return;
    }

    if (msg.type === "gateway.wallet.response") {
      resolveWalletResponse(msg);
      return;
    }

    if (msg.type === "gateway.approval.respond") {
      resolveApproval(String(msg.id || ""), String(msg.decision || ""));
      return;
    }

    if (msg.type === "gateway.chat.send") {
      const text = String(msg.text || "");
      await runAgentTurn(text);
      await writeCheckpoint("observation");

      if (text.startsWith("append:")) {
        const body = text.slice("append:".length).trim();
        if (body) await appendE2eeEntry(body);
      }
      return;
    }

    if (msg.type === "gateway.event.pagehide") {
      await writeCheckpoint("pagehide");
      return;
    }

    if (msg.type === "gateway.event.visibilitychange") {
      const st = String(msg.state || "");
      if (st === "hidden") {
        // Mirror pagehide behavior for browsers that don't reliably fire pagehide.
        await writeCheckpoint("pagehide");
      }
      return;
    }

    if (msg.type === "gateway.command.createHouse") {
      await createHouse({ rhB64: String(msg.rhB64 || "") });
      return;
    }

    if (msg.type === "gateway.command.recoverHouse") {
      await recoverHouse();
      return;
    }

    if (msg.type === "gateway.command.backupVault") {
      await lockAndBackupVault();
      return;
    }

    if (msg.type === "gateway.command.restoreVault") {
      await restoreFromLatestVault();
      return;
    }

    if (msg.type === "gateway.command.publishProfile") {
      await publishProfile({ housePublicJson: msg.housePublicJson || null, promptMd: msg.promptMd || "" });
      return;
    }

    if (msg.type === "gateway.command.freezeNow") {
      await writeCheckpoint("manual");
      log("freeze ok");
      return;
    }

    if (msg.type === "gateway.command.setLlmConfig") {
      const apiKey = typeof msg.apiKey === "string" ? msg.apiKey.trim() : "";
      const api = typeof msg.api === "string" ? msg.api.trim() : "";
      const provider = typeof msg.provider === "string" ? msg.provider.trim() : "";
      const modelId = typeof msg.modelId === "string" ? msg.modelId.trim() : "";
      const baseUrl = typeof msg.baseUrl === "string" ? msg.baseUrl.trim() : "";

      state.llmApiKey = apiKey || null;
      state.llmApi = api || null;
      state.llmProvider = provider || null;
      state.llmModelId = modelId || null;
      state.llmBaseUrl = baseUrl || null;

      await metaSet("llmApiKey", state.llmApiKey);
      await metaSet("llmApi", state.llmApi);
      await metaSet("llmProvider", state.llmProvider);
      await metaSet("llmModelId", state.llmModelId);
      await metaSet("llmBaseUrl", state.llmBaseUrl);

      log(`llm configured api=${state.llmApi || "default"} provider=${state.llmProvider || "default"} model=${state.llmModelId || "default"}`);
      return;
    }

    if (msg.type === "gateway.command.exportZip") {
      await exportZip();
      return;
    }
  } catch (e) {
    log(`error: ${e.message || String(e)}`);
  }
});

boot().catch((e) => {
  log(`boot failed: ${e.message || String(e)}`);
});
