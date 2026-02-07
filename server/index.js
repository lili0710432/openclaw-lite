const path = require("path");
const crypto = require("crypto");
const { Readable } = require("stream");
const express = require("express");

const { nowIso, parseCookies, randomHex } = require("./util");
const { readStore, writeStore } = require("./store");

function b64ToBytes(str) {
  const bin = Buffer.from(String(str || ""), "base64");
  return new Uint8Array(bin);
}

function bytesToB64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

function sha256Base64(input) {
  return crypto.createHash("sha256").update(input).digest("base64");
}

// --- base58 (for Solana public keys) ---
function base58Encode(bytes) {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let x = BigInt("0x" + Buffer.from(bytes).toString("hex"));
  let out = "";
  while (x > 0n) {
    const mod = x % 58n;
    out = alphabet[Number(mod)] + out;
    x = x / 58n;
  }
  // leading zeros
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out = "1" + out;
  return out || "1";
}

function base58Decode(str) {
  if (!str || typeof str !== "string") return null;
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = 0n;
  for (const ch of str) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) return null;
    num = num * 58n + BigInt(idx);
  }
  const bytes = [];
  while (num > 0n) {
    bytes.push(Number(num & 0xffn));
    num >>= 8n;
  }
  bytes.reverse();
  let leadingZeros = 0;
  for (let i = 0; i < str.length && str[i] === "1"; i++) leadingZeros++;
  if (leadingZeros) {
    return new Uint8Array(Array(leadingZeros).fill(0).concat(bytes));
  }
  return new Uint8Array(bytes);
}

function buildWalletLookupMessage({ address, nonce, houseId }) {
  const parts = ["ElizaTown House Lookup", `address: ${address}`, `nonce: ${nonce}`];
  if (houseId) parts.push(`houseId: ${houseId}`);
  return parts.join("\n");
}

function buildHouseKeyWrapMessage({ houseId, origin = null } = {}) {
  const parts = ["ElizaTown House Key Wrap", `houseId: ${houseId}`];
  if (origin) parts.push(`origin: ${origin}`);
  return parts.join("\n");
}

function verifySolanaSignature(address, message, signatureB64) {
  try {
    const pubKey = base58Decode(address);
    if (!pubKey || pubKey.length !== 32) return false;
    const sig = Buffer.from(signatureB64 || "", "base64");
    if (sig.length !== 64) return false;
    const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(pubKey)]);
    const key = crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
    return crypto.verify(null, Buffer.from(message, "utf8"), key, sig);
  } catch (e) {
    console.warn("wallet signature verify failed", e);
    return false;
  }
}

// --- sessions ---
const sessionsById = new Map();
function ensureSession(req, res) {
  const cookies = parseCookies(req.header("cookie") || "");
  let sid = cookies.et_session;
  let session = sid ? sessionsById.get(sid) : null;
  if (!session) {
    sid = randomHex(16);
    session = {
      sessionId: sid,
      createdAt: nowIso(),
      walletLookupNonce: null,
      houseId: null,
    };
    sessionsById.set(sid, session);

    // Cookie is the only "identity". No external auth required.
    const isProd = process.env.NODE_ENV === "production";
    const secureFlag = isProd || req.secure ? "; Secure" : "";
    res.setHeader(
      "Set-Cookie",
      `et_session=${encodeURIComponent(sid)}; Path=/; SameSite=Lax; HttpOnly${secureFlag}`,
    );
  }
  return session;
}

function resetAllSessions() {
  sessionsById.clear();
}

// --- Test wallet helpers (no mocks) ---
//
// E2E runs in isolated browser contexts that can't share extension wallets.
// Instead of injecting "mock wallets", we provision a deterministic Ed25519
// keypair from a test seed so that signatures are real and verifiable.
let testWalletSeedHex = null;
let testWalletAddress = null;

function deriveEd25519PublicKeyBytesFromSeed(seedBytes) {
  // PKCS8: 302e020100300506032b657004220420 || seed(32)
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedBytes)]);
  const priv = crypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const pub = crypto.createPublicKey(priv);
  const spki = pub.export({ format: "der", type: "spki" });
  // SPKI: 302a300506032b6570032100 || pubKey(32)
  return new Uint8Array(Buffer.from(spki).slice(-32));
}

function getTestWalletSeedHex() {
  if (process.env.NODE_ENV !== "test") return null;
  if (testWalletSeedHex) return testWalletSeedHex;
  const envHex = typeof process.env.TEST_WALLET_SEED_HEX === "string" ? process.env.TEST_WALLET_SEED_HEX.trim() : "";
  if (envHex && /^[0-9a-fA-F]{64}$/.test(envHex)) {
    testWalletSeedHex = envHex.toLowerCase();
    return testWalletSeedHex;
  }
  // Fallback: random but stable for the lifetime of the test server process.
  testWalletSeedHex = crypto.randomBytes(32).toString("hex");
  return testWalletSeedHex;
}

function getTestWalletAddress() {
  if (process.env.NODE_ENV !== "test") return null;
  if (testWalletAddress) return testWalletAddress;
  const seedHex = getTestWalletSeedHex();
  const seedBytes = Buffer.from(seedHex, "hex");
  const pubKeyBytes = deriveEd25519PublicKeyBytesFromSeed(seedBytes);
  testWalletAddress = base58Encode(pubKeyBytes);
  return testWalletAddress;
}

// --- server ---
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(
  express.json({
    limit: "3mb",
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString("utf8");
    },
  }),
);

app.use((err, req, res, next) => {
  if (err && err.type === "entity.parse.failed") {
    const size = req.rawBody ? req.rawBody.length : 0;
    console.warn(`[bad-json] ${req.method} ${req.originalUrl} (${size} bytes)`);
    return res.status(400).json({ ok: false, error: "INVALID_JSON" });
  }
  return next(err);
});

const PUBLIC_DIR = path.join(process.cwd(), "public");
const isProd = process.env.NODE_ENV === "production";
const HOUSE_AUTH_SKEW_MS = 2 * 60 * 1000;

function setSecurityHeaders(req, res, next) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("X-Frame-Options", "DENY");

  const connectSrc = ["'self'"];
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    `connect-src ${connectSrc.join(" ")}`,
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
  res.setHeader("Content-Security-Policy", csp);

  if (isProd) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }

  if (isProd && !req.secure) {
    const host = req.get("host");
    if (host) return res.redirect(301, `https://${host}${req.originalUrl}`);
  }

  return next();
}

app.use(setSecurityHeaders);

// --- API ---
app.get("/api/health", (_req, res) => {
  res.json({ ok: true, time: nowIso() });
});

// --- LLM proxy (OpenAI-compatible) ---
//
// OpenClaw Lite (browser) uses PI-AI providers which expect to call an OpenAI-style API.
// Browsers can't reliably call vendor APIs directly (CORS) and we must keep a strict
// networking allowlist, so we provide a same-origin proxy.
//
// Security:
// - The server MUST NOT persist any user API keys.
// - The proxy forwards bytes and streams responses.
const llmTestStats = {
  chatCompletions: 0,
  responses: 0,
  lastPath: null,
};
let llmTestSeq = 0;

function getReqHeader(req, name) {
  const v = req.header(name);
  return typeof v === "string" ? v : "";
}

function respondSse(res, lines) {
  res.status(200);
  res.setHeader("content-type", "text/event-stream; charset=utf-8");
  res.setHeader("cache-control", "no-cache");
  res.setHeader("connection", "keep-alive");
  res.flushHeaders?.();
  for (const line of lines) res.write(line);
  res.end();
}

function handleTestOpenAiChatCompletions(req, res) {
  llmTestStats.chatCompletions += 1;
  llmTestStats.lastPath = "/api/llm/openai/v1/chat/completions";
  llmTestSeq += 1;
  const id = `chatcmpl_test_${llmTestSeq}`;
  const model = typeof req.body?.model === "string" && req.body.model.trim() ? req.body.model.trim() : "test-model";
  const created = Math.floor(Date.now() / 1000);
  const content = "pi-ai ok";

  const chunk1 = {
    id,
    object: "chat.completion.chunk",
    created,
    model,
    choices: [{ index: 0, delta: { role: "assistant", content }, finish_reason: null }],
  };
  const chunk2 = {
    id,
    object: "chat.completion.chunk",
    created,
    model,
    choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
  };

  respondSse(res, [`data: ${JSON.stringify(chunk1)}\n\n`, `data: ${JSON.stringify(chunk2)}\n\n`, "data: [DONE]\n\n"]);
}

function handleTestOpenAiResponses(req, res) {
  llmTestStats.responses += 1;
  llmTestStats.lastPath = "/api/llm/openai/v1/responses";
  // For now we only need chat.completions for deterministic e2e.
  return res.status(501).json({ ok: false, error: "TEST_RESPONSES_NOT_IMPLEMENTED" });
}

async function proxyToOpenAI(req, res, upstreamPath) {
  const auth = getReqHeader(req, "authorization");
  if (!auth || !auth.toLowerCase().startsWith("bearer ")) {
    return res.status(400).json({ ok: false, error: "MISSING_OPENAI_API_KEY" });
  }

  const upstreamUrl = `https://api.openai.com/v1/${upstreamPath}`;
  const headers = {
    authorization: auth,
    "content-type": getReqHeader(req, "content-type") || "application/json",
    accept: getReqHeader(req, "accept") || "application/json",
  };
  for (const h of ["openai-beta", "x-initiator", "openai-intent", "copilot-vision-request"]) {
    const v = getReqHeader(req, h);
    if (v) headers[h] = v;
  }

  const body = typeof req.rawBody === "string" ? req.rawBody : JSON.stringify(req.body || {});
  let upstream;
  try {
    upstream = await fetch(upstreamUrl, { method: "POST", headers, body, redirect: "manual" });
  } catch {
    return res.status(502).json({ ok: false, error: "UPSTREAM_UNAVAILABLE" });
  }

  res.status(upstream.status);
  const ct = upstream.headers.get("content-type");
  if (ct) res.setHeader("content-type", ct);
  const cc = upstream.headers.get("cache-control");
  if (cc) res.setHeader("cache-control", cc);

  if (!upstream.body) {
    const text = await upstream.text().catch(() => "");
    res.send(text);
    return;
  }

  Readable.fromWeb(upstream.body).pipe(res);
}

app.post("/api/llm/openai/v1/chat/completions", async (req, res) => {
  if (process.env.NODE_ENV === "test") return handleTestOpenAiChatCompletions(req, res);
  return await proxyToOpenAI(req, res, "chat/completions");
});

app.post("/api/llm/openai/v1/responses", async (req, res) => {
  if (process.env.NODE_ENV === "test") return handleTestOpenAiResponses(req, res);
  return await proxyToOpenAI(req, res, "responses");
});

// --- House auth ---
function decodeB64(input) {
  try {
    return Buffer.from(input, "base64");
  } catch {
    return null;
  }
}

function verifyHouseAuth(req, house) {
  if (!house || !house.authKey) return { ok: false, error: "HOUSE_AUTH_REQUIRED" };
  const ts = req.header("x-house-ts");
  const auth = req.header("x-house-auth");
  if (!ts || !auth) return { ok: false, error: "HOUSE_AUTH_REQUIRED" };
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum)) return { ok: false, error: "HOUSE_AUTH_INVALID" };
  const skew = Math.abs(Date.now() - tsNum);
  if (skew > HOUSE_AUTH_SKEW_MS) return { ok: false, error: "HOUSE_AUTH_EXPIRED" };
  const key = decodeB64(house.authKey);
  if (!key || key.length < 16) return { ok: false, error: "HOUSE_AUTH_INVALID" };
  const bodyHash = sha256Base64(req.rawBody || "");
  const msg = `${house.id}.${ts}.${req.method.toUpperCase()}.${req.path}.${bodyHash}`;
  const expected = crypto.createHmac("sha256", key).update(msg).digest("base64");
  const a = Buffer.from(expected, "base64");
  const b = Buffer.from(auth, "base64");
  if (a.length !== b.length) return { ok: false, error: "HOUSE_AUTH_INVALID" };
  if (!crypto.timingSafeEqual(a, b)) return { ok: false, error: "HOUSE_AUTH_INVALID" };
  return { ok: true };
}

// --- Houses ---
function makeNonce(prefix) {
  const p = prefix || "n";
  return `${p}_${Date.now()}_${Math.random().toString(16).slice(2)}`;
}

app.get("/api/house/nonce", (_req, res) => {
  res.json({ ok: true, nonce: makeNonce("n") });
});

app.post("/api/house/init", (req, res) => {
  const s = ensureSession(req, res);
  const houseId = typeof req.body?.houseId === "string" ? req.body.houseId.trim() : "";
  const housePubKey = typeof req.body?.housePubKey === "string" ? req.body.housePubKey.trim() : "";
  const nonce = typeof req.body?.nonce === "string" ? req.body.nonce.trim() : "";
  const keyMode = typeof req.body?.keyMode === "string" ? req.body.keyMode.trim() : "ceremony";
  const unlock = req.body?.unlock || null;
  const keyWrap = req.body?.keyWrap || null;
  const houseAuthKey = typeof req.body?.houseAuthKey === "string" ? req.body.houseAuthKey.trim() : "";

  if (!houseId || !housePubKey) return res.status(400).json({ ok: false, error: "MISSING_HOUSE_ID" });
  if (houseId !== housePubKey) return res.status(400).json({ ok: false, error: "HOUSE_ID_MISMATCH" });
  if (!nonce) return res.status(400).json({ ok: false, error: "MISSING_NONCE" });
  if (!houseAuthKey) return res.status(400).json({ ok: false, error: "MISSING_HOUSE_AUTH" });
  const authKeyBytes = decodeB64(houseAuthKey);
  if (!authKeyBytes || authKeyBytes.length < 16) return res.status(400).json({ ok: false, error: "INVALID_HOUSE_AUTH" });

  // v1.2: ceremony-only houses.
  if (keyMode !== "ceremony") return res.status(400).json({ ok: false, error: "CEREMONY_ONLY" });

  let normalizedKeyWrap = null;
  if (keyWrap && typeof keyWrap === "object") {
    const alg = typeof keyWrap.alg === "string" ? keyWrap.alg.trim() : "";
    const iv = typeof keyWrap.iv === "string" ? keyWrap.iv.trim() : "";
    const ct = typeof keyWrap.ct === "string" ? keyWrap.ct.trim() : "";
    if (alg && iv && ct) {
      if (alg !== "AES-GCM") return res.status(400).json({ ok: false, error: "INVALID_KEY_WRAP" });
      normalizedKeyWrap = { alg, iv, ct };
    }
  }

  const store = readStore();
  const exists = store.houses.find((r) => r && r.id === houseId);
  if (exists) return res.status(409).json({ ok: false, error: "HOUSE_EXISTS" });

  store.houses.push({
    id: houseId,
    housePubKey,
    createdAt: nowIso(),
    nonce,
    keyMode: "ceremony",
    unlock,
    keyWrap: normalizedKeyWrap,
    authKey: houseAuthKey,
    entries: [],
  });
  writeStore(store);

  s.houseId = houseId;
  res.json({ ok: true, houseId });
});

app.get("/api/house/:id/meta", (req, res) => {
  const houseId = typeof req.params?.id === "string" ? req.params.id.trim() : "";
  if (!houseId) return res.status(400).json({ ok: false, error: "MISSING_HOUSE_ID" });
  const store = readStore();
  const house = store.houses.find((r) => r && r.id === houseId) || null;
  if (!house) return res.status(404).json({ ok: false, error: "NOT_FOUND" });
  const auth = verifyHouseAuth(req, house);
  if (!auth.ok) return res.status(401).json({ ok: false, error: auth.error });
  res.json({ ok: true, houseId: house.id, housePubKey: house.housePubKey, nonce: house.nonce, keyMode: "ceremony" });
});

app.get("/api/house/:id/log", (req, res) => {
  const houseId = typeof req.params?.id === "string" ? req.params.id.trim() : "";
  if (!houseId) return res.status(400).json({ ok: false, error: "MISSING_HOUSE_ID" });
  const store = readStore();
  const house = store.houses.find((r) => r && r.id === houseId) || null;
  if (!house) return res.status(404).json({ ok: false, error: "NOT_FOUND" });
  const auth = verifyHouseAuth(req, house);
  if (!auth.ok) return res.status(401).json({ ok: false, error: auth.error });
  res.json({ ok: true, entries: Array.isArray(house.entries) ? house.entries : [] });
});

const MAX_HOUSE_ENTRIES = 200;
app.post("/api/house/:id/append", (req, res) => {
  const houseId = typeof req.params?.id === "string" ? req.params.id.trim() : "";
  if (!houseId) return res.status(400).json({ ok: false, error: "MISSING_HOUSE_ID" });
  const ciphertext = req.body?.ciphertext;
  const author = typeof req.body?.author === "string" ? req.body.author.trim() : "unknown";
  if (!ciphertext || typeof ciphertext.iv !== "string" || typeof ciphertext.ct !== "string") {
    return res.status(400).json({ ok: false, error: "INVALID_CIPHERTEXT" });
  }

  const store = readStore();
  const house = store.houses.find((r) => r && r.id === houseId) || null;
  if (!house) return res.status(404).json({ ok: false, error: "NOT_FOUND" });
  const auth = verifyHouseAuth(req, house);
  if (!auth.ok) return res.status(401).json({ ok: false, error: auth.error });

  house.entries = Array.isArray(house.entries) ? house.entries : [];
  if (house.entries.length >= MAX_HOUSE_ENTRIES) return res.status(403).json({ ok: false, error: "HOUSE_FULL" });

  house.entries.push({ id: makeNonce("re"), createdAt: nowIso(), author, ciphertext });
  writeStore(store);
  res.json({ ok: true });
});

// --- Wallet lookup ---
app.get("/api/wallet/nonce", (req, res) => {
  const s = ensureSession(req, res);
  const nonce = `wn_${randomHex(16)}`;
  s.walletLookupNonce = nonce;
  res.json({ ok: true, nonce });
});

app.post("/api/wallet/lookup", (req, res) => {
  const s = ensureSession(req, res);
  const address = typeof req.body?.address === "string" ? req.body.address.trim() : "";
  const signature = typeof req.body?.signature === "string" ? req.body.signature.trim() : "";
  const nonce = typeof req.body?.nonce === "string" ? req.body.nonce.trim() : "";
  const houseId = typeof req.body?.houseId === "string" ? req.body.houseId.trim() : "";

  if (!address) return res.status(400).json({ ok: false, error: "MISSING_ADDRESS" });
  if (!signature) return res.status(400).json({ ok: false, error: "MISSING_SIGNATURE" });

  const usingNonce = !!nonce;
  if (usingNonce) {
    if (nonce !== s.walletLookupNonce) return res.status(400).json({ ok: false, error: "NONCE_MISMATCH" });
    const msg = buildWalletLookupMessage({ address, nonce, houseId: houseId || null });
    if (!verifySolanaSignature(address, msg, signature)) {
      return res.status(401).json({ ok: false, error: "BAD_SIGNATURE" });
    }
    s.walletLookupNonce = null;
  } else {
    if (!houseId) return res.status(400).json({ ok: false, error: "MISSING_HOUSE_ID" });
    const msg = buildHouseKeyWrapMessage({ houseId });
    if (!verifySolanaSignature(address, msg, signature)) {
      return res.status(401).json({ ok: false, error: "BAD_SIGNATURE" });
    }
  }

  const store = readStore();
  let matches = store.houses.filter(
    (r) => r && r.unlock && r.unlock.kind === "solana-wallet-signature" && r.unlock.address === address,
  );
  if (houseId) {
    matches = matches.filter((r) => r.id === houseId);
    if (!matches.length) return res.status(404).json({ ok: false, error: "HOUSE_NOT_FOUND" });
  }

  if (!matches.length) return res.json({ ok: true, houseId: null, keyWrap: null });

  matches.sort((a, b) => String(a.createdAt || "").localeCompare(String(b.createdAt || "")));
  const house = matches[matches.length - 1];

  if (house?.id) s.houseId = house.id;
  res.json({ ok: true, houseId: house.id, keyWrap: house.keyWrap || null });
});

// Minimal ceremony surface for interop with legacy house pages.
app.get("/api/human/house/material", (req, res) => {
  const s = ensureSession(req, res);
  res.json({ ok: true, houseId: s.houseId || null, humanReveal: null, agentReveal: null });
});

// --- OpenClaw Lite server storage ---
const MAX_VAULT_CT_B64 = 1_600_000; // ~1.2MB binary + overhead
const MAX_PROMPT_MD = 16 * 1024;

function sanitizeProfileText(input, maxLen) {
  const raw = typeof input === "string" ? input : "";
  // Minimal, deterministic sanitizer: strip HTML tags + control chars.
  let cleaned = raw.replace(/[\u0000-\u001f\u007f]/g, "");
  cleaned = cleaned.replace(/<[^>]*>/g, "");
  cleaned = cleaned.replace(/\s+/g, " ").trim();
  if (!maxLen || maxLen <= 0) return cleaned;
  return cleaned.length > maxLen ? cleaned.slice(0, maxLen) : cleaned;
}

function normalizeHousePublicJson(input) {
  if (!input || typeof input !== "object") return null;
  const v = input.v === 1 ? 1 : null;
  if (!v) return null;
  const displayName = sanitizeProfileText(input.displayName, 64) || "House";
  const tagline = sanitizeProfileText(input.tagline, 280) || "";
  return { v, displayName, tagline };
}

function parsePublicImageDataUrl(dataUrl) {
  if (dataUrl == null || dataUrl === "") return { dataUrl: null };
  if (typeof dataUrl !== "string") return { error: "INVALID_PUBLIC_IMAGE" };
  const match = dataUrl.match(/^data:(image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$/);
  if (!match) return { error: "INVALID_PUBLIC_IMAGE" };
  const mime = match[1];
  const payload = match[2];
  let bytes;
  try {
    bytes = Buffer.from(payload, "base64");
  } catch {
    return { error: "INVALID_PUBLIC_IMAGE" };
  }
  if (!bytes || bytes.length === 0) return { error: "INVALID_PUBLIC_IMAGE" };
  if (bytes.length > 1024 * 1024) return { error: "PUBLIC_IMAGE_TOO_LARGE" };
  return { dataUrl, mime, bytes };
}

app.post("/api/house/:id/vault/backup", (req, res) => {
  const houseId = typeof req.params?.id === "string" ? req.params.id.trim() : "";
  if (!houseId) return res.status(400).json({ ok: false, error: "MISSING_HOUSE_ID" });
  const vault = req.body?.vault;
  if (!vault || typeof vault !== "object") return res.status(400).json({ ok: false, error: "INVALID_VAULT" });
  if (vault.v !== 1 || vault.alg !== "AES-GCM") return res.status(400).json({ ok: false, error: "INVALID_VAULT" });
  if (!vault.kdf || typeof vault.kdf !== "object") return res.status(400).json({ ok: false, error: "INVALID_VAULT" });
  if (vault.kdf.houseId !== houseId) return res.status(400).json({ ok: false, error: "HOUSE_ID_MISMATCH" });
  if (typeof vault.iv !== "string" || typeof vault.ct !== "string") return res.status(400).json({ ok: false, error: "INVALID_VAULT" });
  if (vault.ct.length > MAX_VAULT_CT_B64) return res.status(413).json({ ok: false, error: "VAULT_TOO_LARGE" });

  const store = readStore();
  const house = store.houses.find((r) => r && r.id === houseId) || null;
  if (!house) return res.status(404).json({ ok: false, error: "NOT_FOUND" });
  const auth = verifyHouseAuth(req, house);
  if (!auth.ok) return res.status(401).json({ ok: false, error: auth.error });

  store.vaultBackups = Array.isArray(store.vaultBackups) ? store.vaultBackups : [];
  store.vaultPointers = Array.isArray(store.vaultPointers) ? store.vaultPointers : [];

  const backupId = makeNonce("vb");
  store.vaultBackups.push({ id: backupId, houseId, createdAt: nowIso(), vault });

  store.vaultPointers = store.vaultPointers.filter((p) => p && p.houseId !== houseId);
  const pointer = { houseId, latestBackupId: backupId, updatedAt: nowIso() };
  store.vaultPointers.push(pointer);

  writeStore(store);
  res.json({ ok: true, backupId, pointer });
});

app.get("/api/house/:id/vault/latest", (req, res) => {
  const houseId = typeof req.params?.id === "string" ? req.params.id.trim() : "";
  if (!houseId) return res.status(400).json({ ok: false, error: "MISSING_HOUSE_ID" });
  const store = readStore();
  const house = store.houses.find((r) => r && r.id === houseId) || null;
  if (!house) return res.status(404).json({ ok: false, error: "NOT_FOUND" });
  const auth = verifyHouseAuth(req, house);
  if (!auth.ok) return res.status(401).json({ ok: false, error: auth.error });

  const ptr = (store.vaultPointers || []).find((p) => p && p.houseId === houseId) || null;
  if (!ptr || !ptr.latestBackupId) return res.json({ ok: true, backupId: null, vault: null });
  const rec = (store.vaultBackups || []).find((b) => b && b.id === ptr.latestBackupId) || null;
  if (!rec) return res.json({ ok: true, backupId: null, vault: null });

  res.json({ ok: true, backupId: rec.id, vault: rec.vault });
});

app.post("/api/house/:id/public-profile", (req, res) => {
  const houseId = typeof req.params?.id === "string" ? req.params.id.trim() : "";
  if (!houseId) return res.status(400).json({ ok: false, error: "MISSING_HOUSE_ID" });

  const store = readStore();
  const house = store.houses.find((r) => r && r.id === houseId) || null;
  if (!house) return res.status(404).json({ ok: false, error: "NOT_FOUND" });
  const auth = verifyHouseAuth(req, house);
  if (!auth.ok) return res.status(401).json({ ok: false, error: auth.error });

  store.publicProfiles = Array.isArray(store.publicProfiles) ? store.publicProfiles : [];

  const clear = req.body?.clear === true;
  if (clear) {
    store.publicProfiles = store.publicProfiles.filter((p) => p && p.houseId !== houseId);
    writeStore(store);
    return res.json({ ok: true, profile: null });
  }

  const normalized = normalizeHousePublicJson(req.body?.housePublicJson);
  if (!normalized) return res.status(400).json({ ok: false, error: "INVALID_PUBLIC_PROFILE" });

  const promptMd = req.body?.promptMd == null ? "" : String(req.body.promptMd);
  const safePromptMd = sanitizeProfileText(promptMd, MAX_PROMPT_MD);

  const preview = req.body?.previewImage;
  let previewImage = null;
  if (typeof preview === "string" && preview.trim()) {
    const parsed = parsePublicImageDataUrl(preview);
    if (parsed.error) return res.status(400).json({ ok: false, error: parsed.error });
    previewImage = parsed.dataUrl;
  }

  const rec = {
    houseId,
    updatedAt: nowIso(),
    housePublicJson: normalized,
    promptMd: safePromptMd,
    previewImage,
  };

  store.publicProfiles = store.publicProfiles.filter((p) => p && p.houseId !== houseId);
  store.publicProfiles.unshift(rec);
  writeStore(store);

  res.json({
    ok: true,
    profile: {
      houseId,
      updatedAt: rec.updatedAt,
      housePublicJson: rec.housePublicJson,
      promptMd: rec.promptMd,
      previewImageUrl: previewImage ? `/api/house/${encodeURIComponent(houseId)}/public-profile/preview` : null,
    },
  });
});

app.get("/api/house/:id/public-profile", (req, res) => {
  const houseId = typeof req.params?.id === "string" ? req.params.id.trim() : "";
  if (!houseId) return res.status(400).json({ ok: false, error: "MISSING_HOUSE_ID" });
  const store = readStore();
  const rec = (store.publicProfiles || []).find((p) => p && p.houseId === houseId) || null;
  if (!rec) return res.json({ ok: true, profile: null });
  res.json({
    ok: true,
    profile: {
      houseId,
      updatedAt: rec.updatedAt || null,
      housePublicJson: rec.housePublicJson || null,
      promptMd: rec.promptMd || "",
      previewImageUrl: rec.previewImage ? `/api/house/${encodeURIComponent(houseId)}/public-profile/preview` : null,
    },
  });
});

app.get("/api/house/:id/public-profile/preview", (req, res) => {
  const houseId = typeof req.params?.id === "string" ? req.params.id.trim() : "";
  if (!houseId) return res.status(400).json({ ok: false, error: "MISSING_HOUSE_ID" });
  const store = readStore();
  const rec = (store.publicProfiles || []).find((p) => p && p.houseId === houseId) || null;
  if (!rec || !rec.previewImage) return res.status(404).json({ ok: false, error: "NOT_FOUND" });
  const parsed = parsePublicImageDataUrl(rec.previewImage);
  if (parsed.error || !parsed.bytes) return res.status(500).json({ ok: false, error: "INVALID_PUBLIC_IMAGE" });
  res.setHeader("Content-Type", parsed.mime || "application/octet-stream");
  res.setHeader("Cache-Control", "public, max-age=300");
  res.end(parsed.bytes);
});

app.get("/api/town/grid", (_req, res) => {
  const store = readStore();
  const out = [];
  for (const rec of store.publicProfiles || []) {
    if (!rec || typeof rec.houseId !== "string") continue;
    out.push({
      houseId: rec.houseId,
      updatedAt: rec.updatedAt || null,
      housePublicJson: rec.housePublicJson || null,
      previewImageUrl: rec.previewImage ? `/api/house/${encodeURIComponent(rec.houseId)}/public-profile/preview` : null,
    });
  }
  res.json({ ok: true, houses: out });
});

// Unknown API routes should not redirect.
app.use("/api", (_req, res) => {
  res.status(404).json({ ok: false, error: "NOT_FOUND" });
});

// --- Test-only endpoints ---
if (process.env.NODE_ENV === "test") {
  app.get("/__test__/env", (_req, res) => {
    res.json({ ok: true, env: "test" });
  });

  app.get("/__test__/wallet/seed", (_req, res) => {
    const seedHex = getTestWalletSeedHex();
    const address = getTestWalletAddress();
    if (!seedHex || !address) return res.status(500).json({ ok: false, error: "TEST_WALLET_NOT_AVAILABLE" });
    res.json({ ok: true, seedHex, address });
  });

  app.get("/__test__/llm/stats", (_req, res) => {
    res.json({ ok: true, ...llmTestStats });
  });

  app.post("/__test__/reset", (_req, res) => {
    const token = process.env.TEST_RESET_TOKEN;
    if (!token) return res.status(404).json({ ok: false, error: "NOT_FOUND" });
    const header = _req.header("x-test-reset");
    if (header !== token) return res.status(403).json({ ok: false, error: "FORBIDDEN" });

    writeStore({
      signups: [],
      shares: [],
      publicTeams: [],
      houses: [],
      anchors: [],
      inbox: [],
      vaultBackups: [],
      vaultPointers: [],
      publicProfiles: [],
    });
    resetAllSessions();
    llmTestStats.chatCompletions = 0;
    llmTestStats.responses = 0;
    llmTestStats.lastPath = null;
    res.json({ ok: true });
  });
}

// --- Static + routes ---
app.use(
  express.static(PUBLIC_DIR, {
    etag: true,
    maxAge: isProd ? "1h" : 0,
    setHeaders: (res) => {
      if (!isProd) res.setHeader("Cache-Control", "no-store");
    },
  }),
);

app.get("/", (_req, res) => res.redirect(302, "/lite"));
app.get("/lite", (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "lite.html")));
app.get("/town", (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "town.html")));
app.get("/house", (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "house.html")));

// Default route: keep it single-purpose.
app.get("*", (_req, res) => res.redirect(302, "/lite"));

const port = Number(process.env.PORT || 4173);
app.listen(port, () => {
  console.log(`[openclaw-lite] http://localhost:${port}`);
});
