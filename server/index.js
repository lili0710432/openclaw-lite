const path = require("path");
const crypto = require("crypto");
const net = require("net");
const { Readable } = require("stream");
const express = require("express");
const { WebSocketServer } = require("ws");
const { ethers } = require("ethers");

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

function normalizeToolMaxBytes(value, fallback, hardMax) {
  const n = Math.floor(Number(value));
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(n, hardMax);
}

function isPrivateIpv4(host) {
  const parts = String(host || "")
    .split(".")
    .map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function isLocalOrPrivateIpv6(host) {
  const h = String(host || "").toLowerCase();
  if (!h) return false;
  if (h === "::1") return true;
  if (h.startsWith("fc") || h.startsWith("fd")) return true; // unique local
  if (h.startsWith("fe8") || h.startsWith("fe9") || h.startsWith("fea") || h.startsWith("feb")) return true; // link-local
  return false;
}

function isBlockedProxyHost(hostname) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/, "");
  if (!host) return true;
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (host === "0.0.0.0") return true;
  if (host.endsWith(".local")) return true;

  const ipVersion = net.isIP(host);
  if (ipVersion === 4 && isPrivateIpv4(host)) return true;
  if (ipVersion === 6 && isLocalOrPrivateIpv6(host)) return true;
  return false;
}

function truncateUtf8Buffer(buf, maxBytes) {
  if (!Buffer.isBuffer(buf)) return { text: "", truncated: false };
  if (buf.length <= maxBytes) return { text: buf.toString("utf8"), truncated: false };
  return { text: buf.subarray(0, maxBytes).toString("utf8"), truncated: true };
}

function webFetchSuccess({ url, finalUrl, status, contentType, etag, lastModified, text, truncated, fromCache, startedAtMs }) {
  return {
    ok: true,
    data: {
      url,
      finalUrl,
      status,
      contentType: contentType || "",
      etag: etag || null,
      lastModified: lastModified || null,
      sha256B64: sha256Base64(String(text || "")),
      text: String(text || ""),
      truncated: !!truncated,
      fromCache: !!fromCache,
    },
    meta: {
      tool: "web_fetch",
      durationMs: Math.max(0, Date.now() - Number(startedAtMs || 0)),
    },
  };
}

function webFetchFailure({ code, message, details, retryable, startedAtMs }) {
  return {
    ok: false,
    error: {
      code: String(code || "UNSUPPORTED"),
      message: String(message || code || "web_fetch failed"),
      retryable: !!retryable,
      details: details && typeof details === "object" ? details : {},
    },
    meta: {
      tool: "web_fetch",
      durationMs: Math.max(0, Date.now() - Number(startedAtMs || 0)),
    },
  };
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

function buildEvmHouseInitMessage({ address, houseId, nonce }) {
  return ["ElizaTown EVM House Init", `address: ${address}`, `houseId: ${houseId}`, `nonce: ${nonce}`].join("\n");
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

function normalizeEvmAddress(address) {
  try {
    return ethers.getAddress(String(address || "").trim());
  } catch {
    return null;
  }
}

function verifyEvmSignature(address, message, signatureHex) {
  try {
    const normalized = normalizeEvmAddress(address);
    if (!normalized) return false;
    const recovered = ethers.verifyMessage(String(message || ""), String(signatureHex || ""));
    const recNorm = normalizeEvmAddress(recovered);
    if (!recNorm) return false;
    return recNorm === normalized;
  } catch (e) {
    console.warn("evm signature verify failed", e);
    return false;
  }
}

// --- sessions ---
const sessionsById = new Map();
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h
const SESSION_MAX = 5_000;
const SESSION_CLEANUP_INTERVAL_MS = 60 * 1000; // 1m
let lastSessionCleanupMs = 0;

function cleanupSessions() {
  const now = Date.now();
  if (now - lastSessionCleanupMs < SESSION_CLEANUP_INTERVAL_MS) return;
  lastSessionCleanupMs = now;

  // TTL eviction.
  for (const [sid, s] of sessionsById.entries()) {
    const createdAtMs = typeof s?.createdAtMs === "number" ? s.createdAtMs : null;
    if (typeof createdAtMs === "number" && now - createdAtMs > SESSION_TTL_MS) {
      sessionsById.delete(sid);
    }
  }

  // Hard cap eviction (oldest first) as a backstop.
  if (sessionsById.size <= SESSION_MAX) return;
  const ordered = Array.from(sessionsById.entries())
    .map(([sid, s]) => ({ sid, createdAtMs: typeof s?.createdAtMs === "number" ? s.createdAtMs : 0 }))
    .sort((a, b) => a.createdAtMs - b.createdAtMs);
  const toDrop = ordered.slice(0, Math.max(0, sessionsById.size - SESSION_MAX));
  for (const rec of toDrop) sessionsById.delete(rec.sid);
}

function ensureSession(req, res) {
  cleanupSessions();
  const cookies = parseCookies(req.header("cookie") || "");
  let sid = cookies.et_session;
  let session = sid ? sessionsById.get(sid) : null;
  if (!session) {
    sid = randomHex(16);
    session = {
      sessionId: sid,
      createdAt: nowIso(),
      createdAtMs: Date.now(),
      walletLookupNonce: null,
      houseInitNonce: null,
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

let testEvmWallet = null;
function getTestEvmWallet() {
  if (process.env.NODE_ENV !== "test") return null;
  if (testEvmWallet) return testEvmWallet;
  const envPk = typeof process.env.TEST_EVM_PRIVATE_KEY === "string" ? process.env.TEST_EVM_PRIVATE_KEY.trim() : "";
  let pk = envPk;
  if (!pk || !/^(0x)?[0-9a-fA-F]{64}$/.test(pk)) {
    pk = "0x59c6995e998f97a5a0044966f0945381d1d0e6f94f7f8f6fe1d9a8f8a9f2f9d3";
  }
  if (!pk.startsWith("0x")) pk = `0x${pk}`;
  testEvmWallet = new ethers.Wallet(pk);
  return testEvmWallet;
}

function getTestEvmAddress() {
  const wallet = getTestEvmWallet();
  return wallet ? wallet.address : null;
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

const WEB_FETCH_DEFAULT_MAX_BYTES = 262_144;
const WEB_FETCH_MAX_BYTES = 1_048_576;
const WEB_FETCH_REDIRECT_LIMIT = 5;
const WEB_FETCH_TIMEOUT_MS = 20_000;

function normalizeExpectedMime(raw) {
  const value = String(raw || "any").trim().toLowerCase();
  if (value === "text/markdown") return "text/markdown";
  if (value === "text/plain") return "text/plain";
  if (value === "application/json") return "application/json";
  return "any";
}

function expectedMimeMatches(expectedMime, contentType) {
  if (expectedMime === "any") return true;
  const ct = String(contentType || "").toLowerCase();
  return ct.startsWith(expectedMime);
}

function normalizeWebFetchRequest(body) {
  const rawUrl = typeof body?.url === "string" ? body.url.trim() : "";
  if (!rawUrl) throw new Error("INVALID_ARGUMENTS");
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error("INVALID_ARGUMENTS");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("INVALID_ARGUMENTS");
  }
  return {
    url: parsed.toString(),
    followRedirects: body?.followRedirects !== false,
    maxBytes: normalizeToolMaxBytes(body?.maxBytes, WEB_FETCH_DEFAULT_MAX_BYTES, WEB_FETCH_MAX_BYTES),
    cacheMode: String(body?.cacheMode || "allow-cache"),
    expectedMime: normalizeExpectedMime(body?.expectedMime),
  };
}

function fixtureDocumentForPath(pathname) {
  if (pathname === "/docs/agenttown") {
    return {
      contentType: "text/markdown; charset=utf-8",
      text: "# Agent Town\n\nYou are an Agent Town worker. Use structured API calls.",
    };
  }
  if (pathname === "/docs/long-skill") {
    return {
      contentType: "text/markdown; charset=utf-8",
      text: [
        "# Long Skill",
        "",
        "This fixture intentionally exceeds truncation thresholds for deterministic tests.",
        "Agent Town long skill content.",
      ].join("\n"),
    };
  }
  return null;
}

async function executeWebFetchProxy(input, startedAtMs) {
  let current = new URL(input.url);
  let redirects = 0;

  for (;;) {
    if (isBlockedProxyHost(current.hostname)) {
      return webFetchFailure({
        code: "NETWORK_BLOCKED",
        message: "Blocked local/private host",
        details: { hostname: current.hostname },
        startedAtMs,
      });
    }

    // Deterministic cross-origin fixture host for e2e (no external internet dependency).
    if (current.hostname === "fixture.openclaw.test") {
      if (current.pathname === "/redirect/long-skill") {
        if (!input.followRedirects) {
          return webFetchSuccess({
            url: input.url,
            finalUrl: current.toString(),
            status: 302,
            contentType: "text/plain; charset=utf-8",
            etag: null,
            lastModified: null,
            text: "",
            truncated: false,
            fromCache: false,
            startedAtMs,
          });
        }
        if (redirects >= WEB_FETCH_REDIRECT_LIMIT) {
          return webFetchFailure({
            code: "UNSUPPORTED",
            message: "Redirect limit exceeded",
            details: { limit: WEB_FETCH_REDIRECT_LIMIT },
            startedAtMs,
          });
        }
        redirects += 1;
        current = new URL("https://fixture.openclaw.test/docs/long-skill");
        continue;
      }

      const doc = fixtureDocumentForPath(current.pathname);
      if (!doc) {
        return webFetchFailure({
          code: "NOT_FOUND",
          message: "Fixture document not found",
          details: { path: current.pathname },
          startedAtMs,
        });
      }

      if (!expectedMimeMatches(input.expectedMime, doc.contentType)) {
        return webFetchFailure({
          code: "UNSUPPORTED",
          message: "MIME type mismatch",
          details: { expectedMime: input.expectedMime, contentType: doc.contentType },
          startedAtMs,
        });
      }

      const truncatedDoc = truncateUtf8Buffer(Buffer.from(doc.text, "utf8"), input.maxBytes);
      return webFetchSuccess({
        url: input.url,
        finalUrl: current.toString(),
        status: 200,
        contentType: doc.contentType,
        etag: '"fixture-etag"',
        lastModified: "Mon, 01 Jan 2024 00:00:00 GMT",
        text: truncatedDoc.text,
        truncated: truncatedDoc.truncated,
        fromCache: false,
        startedAtMs,
      });
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), WEB_FETCH_TIMEOUT_MS);
    let upstream;
    try {
      upstream = await fetch(current.toString(), {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
      });
    } catch (e) {
      clearTimeout(timeoutId);
      if (e?.name === "AbortError") {
        return webFetchFailure({
          code: "TIMEOUT",
          message: "Upstream fetch timed out",
          retryable: true,
          details: { timeoutMs: WEB_FETCH_TIMEOUT_MS },
          startedAtMs,
        });
      }
      return webFetchFailure({
        code: "UNSUPPORTED",
        message: "Upstream fetch failed",
        retryable: true,
        details: { url: current.toString() },
        startedAtMs,
      });
    } finally {
      clearTimeout(timeoutId);
    }

    const location = upstream.headers.get("location");
    if (location && upstream.status >= 300 && upstream.status < 400) {
      if (!input.followRedirects) {
        return webFetchSuccess({
          url: input.url,
          finalUrl: current.toString(),
          status: upstream.status,
          contentType: upstream.headers.get("content-type") || "",
          etag: upstream.headers.get("etag"),
          lastModified: upstream.headers.get("last-modified"),
          text: "",
          truncated: false,
          fromCache: false,
          startedAtMs,
        });
      }
      if (redirects >= WEB_FETCH_REDIRECT_LIMIT) {
        return webFetchFailure({
          code: "UNSUPPORTED",
          message: "Redirect limit exceeded",
          details: { limit: WEB_FETCH_REDIRECT_LIMIT },
          startedAtMs,
        });
      }
      let next;
      try {
        next = new URL(location, current.toString());
      } catch {
        return webFetchFailure({
          code: "UNSUPPORTED",
          message: "Invalid redirect URL",
          details: { location },
          startedAtMs,
        });
      }
      if (next.protocol !== "http:" && next.protocol !== "https:") {
        return webFetchFailure({
          code: "NETWORK_BLOCKED",
          message: "Blocked redirect protocol",
          details: { protocol: next.protocol },
          startedAtMs,
        });
      }
      redirects += 1;
      current = next;
      continue;
    }

    const contentType = upstream.headers.get("content-type") || "";
    if (!expectedMimeMatches(input.expectedMime, contentType)) {
      return webFetchFailure({
        code: "UNSUPPORTED",
        message: "MIME type mismatch",
        details: { expectedMime: input.expectedMime, contentType },
        startedAtMs,
      });
    }

    const bytes = Buffer.from(await upstream.arrayBuffer());
    const truncated = truncateUtf8Buffer(bytes, input.maxBytes);
    return webFetchSuccess({
      url: input.url,
      finalUrl: current.toString(),
      status: upstream.status,
      contentType,
      etag: upstream.headers.get("etag"),
      lastModified: upstream.headers.get("last-modified"),
      text: truncated.text,
      truncated: truncated.truncated,
      fromCache: false,
      startedAtMs,
    });
  }
}

const HTTP_REQUEST_DEFAULT_MAX_BYTES = 262_144;
const HTTP_REQUEST_MAX_BYTES = 1_048_576;
const HTTP_REQUEST_MAX_REDIRECTS = 5;
const HTTP_REQUEST_DEFAULT_TIMEOUT_MS = 30_000;
const HTTP_REQUEST_MIN_TIMEOUT_MS = 100;
const HTTP_REQUEST_MAX_TIMEOUT_MS = 60_000;

function normalizeHttpRequestMethod(value) {
  const method = String(value || "GET").trim().toUpperCase();
  const allowed = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]);
  if (!allowed.has(method)) throw new Error("INVALID_ARGUMENTS");
  return method;
}

function normalizeHttpRequestResponseMode(value) {
  const mode = String(value || "auto").trim().toLowerCase();
  if (mode === "json" || mode === "text" || mode === "base64") return mode;
  return "auto";
}

function normalizeHttpRequestTimeout(value) {
  const n = Math.floor(Number(value));
  if (!Number.isFinite(n)) return HTTP_REQUEST_DEFAULT_TIMEOUT_MS;
  if (n < HTTP_REQUEST_MIN_TIMEOUT_MS) return HTTP_REQUEST_MIN_TIMEOUT_MS;
  if (n > HTTP_REQUEST_MAX_TIMEOUT_MS) return HTTP_REQUEST_MAX_TIMEOUT_MS;
  return n;
}

function normalizeHttpRequestHeaders(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return {};
  const out = {};
  for (const [k, v] of Object.entries(input)) {
    const key = String(k || "").trim().toLowerCase();
    if (!key || v == null) continue;
    out[key] = String(v);
  }
  return out;
}

function normalizeHttpRequestQuery(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return {};
  const out = {};
  for (const [k, v] of Object.entries(input)) {
    const key = String(k || "").trim();
    if (!key) continue;
    if (Array.isArray(v)) out[key] = v.map((x) => String(x));
    else out[key] = String(v);
  }
  return out;
}

function applyQueryToUrl(urlStr, query) {
  const url = new URL(urlStr);
  for (const [k, v] of Object.entries(query || {})) {
    url.searchParams.delete(k);
    if (Array.isArray(v)) {
      for (const entry of v) url.searchParams.append(k, String(entry));
    } else {
      url.searchParams.set(k, String(v));
    }
  }
  return url.toString();
}

function normalizeHttpRequestBody(body, headers) {
  if (!body || typeof body !== "object") return { wire: null, buffer: null };
  const kind = String(body.kind || "text").trim().toLowerCase();
  if (kind === "json") {
    const jsonValue = body.json !== undefined ? body.json : {};
    const text = JSON.stringify(jsonValue);
    if (!headers["content-type"]) headers["content-type"] = "application/json";
    return { wire: { kind: "json", json: jsonValue }, buffer: Buffer.from(text, "utf8") };
  }
  if (kind === "text") {
    const text = typeof body.text === "string" ? body.text : String(body.text ?? "");
    return { wire: { kind: "text", text }, buffer: Buffer.from(text, "utf8") };
  }
  if (kind === "base64") {
    const base64 = typeof body.base64 === "string" ? body.base64 : "";
    if (!/^[A-Za-z0-9+/=]*$/.test(base64)) throw new Error("INVALID_ARGUMENTS");
    return { wire: { kind: "base64", base64 }, buffer: Buffer.from(base64, "base64") };
  }
  throw new Error("INVALID_ARGUMENTS");
}

function normalizeHttpRequestProxyInput(body) {
  const rawUrl = typeof body?.url === "string" ? body.url.trim() : "";
  if (!rawUrl) throw new Error("INVALID_ARGUMENTS");
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error("INVALID_ARGUMENTS");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("INVALID_ARGUMENTS");
  }

  const method = normalizeHttpRequestMethod(body?.method);
  const headers = normalizeHttpRequestHeaders(body?.headers);
  const query = normalizeHttpRequestQuery(body?.query);
  const bodyInfo = normalizeHttpRequestBody(body?.body, headers);
  return {
    method,
    headers,
    query,
    body: bodyInfo.wire,
    bodyBuffer: bodyInfo.buffer,
    followRedirects: body?.followRedirects !== false,
    timeoutMs: normalizeHttpRequestTimeout(body?.timeoutMs),
    maxBytes: normalizeToolMaxBytes(body?.maxBytes, HTTP_REQUEST_DEFAULT_MAX_BYTES, HTTP_REQUEST_MAX_BYTES),
    responseMode: normalizeHttpRequestResponseMode(body?.responseMode),
    url: applyQueryToUrl(parsed.toString(), query),
  };
}

function isSensitiveHeaderName(name) {
  const key = String(name || "").toLowerCase();
  return key === "authorization" || key === "cookie" || key === "proxy-authorization" || key === "x-api-key";
}

function stripSensitiveHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (isSensitiveHeaderName(k)) continue;
    out[k] = v;
  }
  return out;
}

function responseHeadersToObject(headers) {
  const out = {};
  if (!headers || typeof headers.entries !== "function") return out;
  for (const [k, v] of headers.entries()) out[String(k || "").toLowerCase()] = String(v || "");
  return out;
}

function decodeHttpRequestResponseBody(buffer, responseMode, contentType) {
  const bytes = Buffer.isBuffer(buffer) ? buffer : Buffer.from("");
  const bodyText = bytes.toString("utf8");
  let bodyJson = null;
  let bodyBase64 = "";
  const mode = normalizeHttpRequestResponseMode(responseMode);
  const isJsonLike = String(contentType || "").toLowerCase().includes("application/json");
  if (mode === "json" || (mode === "auto" && isJsonLike)) {
    try {
      bodyJson = JSON.parse(bodyText);
    } catch {
      bodyJson = null;
    }
  }
  if (mode === "base64") bodyBase64 = bytes.toString("base64");
  return { bodyText, bodyJson, bodyBase64 };
}

function httpRequestSuccess({ status, finalUrl, headers, bodyBuffer, responseMode, startedAtMs, maxBytes }) {
  const allBytes = Buffer.isBuffer(bodyBuffer) ? bodyBuffer : Buffer.from("");
  const truncated = allBytes.length > maxBytes;
  const limited = truncated ? allBytes.subarray(0, maxBytes) : allBytes;
  const ct = headers["content-type"] || "";
  const decoded = decodeHttpRequestResponseBody(limited, responseMode, ct);
  return {
    ok: true,
    data: {
      status,
      finalUrl,
      headers,
      bodyText: decoded.bodyText,
      bodyJson: decoded.bodyJson,
      bodyBase64: decoded.bodyBase64,
      truncated,
      timing: {
        startedAtMs,
        durationMs: Math.max(0, Date.now() - Number(startedAtMs || 0)),
      },
    },
    meta: {
      tool: "http_request",
      durationMs: Math.max(0, Date.now() - Number(startedAtMs || 0)),
    },
  };
}

function httpRequestFailure({ code, message, details, retryable, startedAtMs }) {
  return {
    ok: false,
    error: {
      code: String(code || "UNSUPPORTED"),
      message: String(message || code || "http_request failed"),
      retryable: !!retryable,
      details: details && typeof details === "object" ? details : {},
    },
    meta: {
      tool: "http_request",
      durationMs: Math.max(0, Date.now() - Number(startedAtMs || 0)),
    },
  };
}

function tryFixtureHttpResponse(urlObj, method, headers, followRedirects) {
  if (urlObj.hostname === "fixture.openclaw.test" && urlObj.pathname === "/redirect/auth-header") {
    if (!followRedirects) {
      return {
        done: true,
        status: 302,
        headers: { location: "https://fixture-two.openclaw.test/echo/auth-header", "content-type": "text/plain" },
        bodyBuffer: Buffer.from("", "utf8"),
        finalUrl: urlObj.toString(),
      };
    }
    return {
      redirectTo: "https://fixture-two.openclaw.test/echo/auth-header",
    };
  }

  if (urlObj.hostname === "fixture-two.openclaw.test" && urlObj.pathname === "/echo/auth-header") {
    return {
      done: true,
      status: 200,
      headers: { "content-type": "application/json; charset=utf-8" },
      bodyBuffer: Buffer.from(
        JSON.stringify({
          ok: true,
          method,
          receivedAuthorization: headers.authorization || null,
        }),
        "utf8",
      ),
      finalUrl: urlObj.toString(),
    };
  }

  if (urlObj.hostname === "fixture-rate.openclaw.test" && urlObj.pathname === "/ping") {
    return {
      done: true,
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
      bodyBuffer: Buffer.from("pong", "utf8"),
      finalUrl: urlObj.toString(),
    };
  }

  return null;
}

async function executeHttpRequestProxy(input, startedAtMs) {
  let currentUrl = new URL(input.url);
  let currentMethod = input.method;
  let currentHeaders = { ...input.headers };
  let currentBody = input.bodyBuffer;
  let redirects = 0;

  for (;;) {
    if (isBlockedProxyHost(currentUrl.hostname)) {
      return httpRequestFailure({
        code: "NETWORK_BLOCKED",
        message: "Blocked local/private host",
        details: { hostname: currentUrl.hostname },
        startedAtMs,
      });
    }

    const fixture = tryFixtureHttpResponse(currentUrl, currentMethod, currentHeaders, input.followRedirects);
    if (fixture) {
      if (fixture.redirectTo) {
        if (redirects >= HTTP_REQUEST_MAX_REDIRECTS) {
          return httpRequestFailure({
            code: "UNSUPPORTED",
            message: "Redirect limit exceeded",
            details: { limit: HTTP_REQUEST_MAX_REDIRECTS },
            startedAtMs,
          });
        }
        const next = new URL(fixture.redirectTo, currentUrl.toString());
        if (next.origin !== currentUrl.origin) {
          currentHeaders = stripSensitiveHeaders(currentHeaders);
        }
        redirects += 1;
        currentUrl = next;
        currentBody = null;
        currentMethod = "GET";
        continue;
      }
      return httpRequestSuccess({
        status: fixture.status,
        finalUrl: fixture.finalUrl,
        headers: fixture.headers,
        bodyBuffer: fixture.bodyBuffer,
        responseMode: input.responseMode,
        startedAtMs,
        maxBytes: input.maxBytes,
      });
    }

    const abort = new AbortController();
    const timeoutId = setTimeout(() => abort.abort(), input.timeoutMs);
    let upstream;
    try {
      upstream = await fetch(currentUrl.toString(), {
        method: currentMethod,
        headers: currentHeaders,
        body: currentBody == null ? undefined : currentBody,
        redirect: "manual",
        signal: abort.signal,
      });
    } catch (e) {
      clearTimeout(timeoutId);
      if (e?.name === "AbortError") {
        return httpRequestFailure({
          code: "TIMEOUT",
          message: "Upstream request timed out",
          retryable: true,
          details: { timeoutMs: input.timeoutMs },
          startedAtMs,
        });
      }
      return httpRequestFailure({
        code: "UNSUPPORTED",
        message: "Upstream request failed",
        retryable: true,
        details: { url: currentUrl.toString() },
        startedAtMs,
      });
    } finally {
      clearTimeout(timeoutId);
    }

    const location = upstream.headers.get("location");
    if (location && upstream.status >= 300 && upstream.status < 400) {
      if (!input.followRedirects) {
        const bodyBuffer = Buffer.from(await upstream.arrayBuffer());
        return httpRequestSuccess({
          status: upstream.status,
          finalUrl: currentUrl.toString(),
          headers: responseHeadersToObject(upstream.headers),
          bodyBuffer,
          responseMode: input.responseMode,
          startedAtMs,
          maxBytes: input.maxBytes,
        });
      }
      if (redirects >= HTTP_REQUEST_MAX_REDIRECTS) {
        return httpRequestFailure({
          code: "UNSUPPORTED",
          message: "Redirect limit exceeded",
          details: { limit: HTTP_REQUEST_MAX_REDIRECTS },
          startedAtMs,
        });
      }
      let next;
      try {
        next = new URL(location, currentUrl.toString());
      } catch {
        return httpRequestFailure({
          code: "UNSUPPORTED",
          message: "Invalid redirect URL",
          details: { location },
          startedAtMs,
        });
      }
      if (next.protocol !== "http:" && next.protocol !== "https:") {
        return httpRequestFailure({
          code: "NETWORK_BLOCKED",
          message: "Blocked redirect protocol",
          details: { protocol: next.protocol },
          startedAtMs,
        });
      }
      if (next.origin !== currentUrl.origin) {
        currentHeaders = stripSensitiveHeaders(currentHeaders);
      }

      // Follow browser-like semantics for 303 or legacy 301/302 non-GET/HEAD.
      if (
        upstream.status === 303 ||
        ((upstream.status === 301 || upstream.status === 302) && currentMethod !== "GET" && currentMethod !== "HEAD")
      ) {
        currentMethod = "GET";
        currentBody = null;
      }

      redirects += 1;
      currentUrl = next;
      continue;
    }

    const bodyBuffer = Buffer.from(await upstream.arrayBuffer());
    return httpRequestSuccess({
      status: upstream.status,
      finalUrl: currentUrl.toString(),
      headers: responseHeadersToObject(upstream.headers),
      bodyBuffer,
      responseMode: input.responseMode,
      startedAtMs,
      maxBytes: input.maxBytes,
    });
  }
}

// --- API ---
app.get("/api/health", (_req, res) => {
  res.json({ ok: true, time: nowIso() });
});

// Runtime feature flags/capabilities (minimal; used by the Gateway UI).
app.get("/api/runtime/capabilities", (_req, res) => {
  res.json({
    ok: true,
    llm: {
      codexCli: process.env.OPENCLAW_LITE_CODEX_CLI === "1",
    },
  });
});

app.post("/api/tools/web_fetch", async (req, res) => {
  const startedAtMs = Date.now();
  let input;
  try {
    input = normalizeWebFetchRequest(req.body || {});
  } catch {
    return res.status(400).json(
      webFetchFailure({
        code: "INVALID_ARGUMENTS",
        message: "Invalid web_fetch request",
        startedAtMs,
      }),
    );
  }

  const out = await executeWebFetchProxy(input, startedAtMs);
  if (out.ok) return res.status(200).json(out);
  if (out.error?.code === "NETWORK_BLOCKED") return res.status(403).json(out);
  if (out.error?.code === "TIMEOUT") return res.status(504).json(out);
  if (out.error?.code === "INVALID_ARGUMENTS") return res.status(400).json(out);
  if (out.error?.code === "NOT_FOUND") return res.status(404).json(out);
  return res.status(502).json(out);
});

app.post("/api/tools/http_request", async (req, res) => {
  const startedAtMs = Date.now();
  let input;
  try {
    input = normalizeHttpRequestProxyInput(req.body || {});
  } catch {
    return res.status(400).json(
      httpRequestFailure({
        code: "INVALID_ARGUMENTS",
        message: "Invalid http_request request",
        startedAtMs,
      }),
    );
  }

  const out = await executeHttpRequestProxy(input, startedAtMs);
  if (out.ok) return res.status(200).json(out);
  if (out.error?.code === "NETWORK_BLOCKED") return res.status(403).json(out);
  if (out.error?.code === "TIMEOUT") return res.status(504).json(out);
  if (out.error?.code === "INVALID_ARGUMENTS") return res.status(400).json(out);
  if (out.error?.code === "NOT_FOUND") return res.status(404).json(out);
  if (out.error?.code === "SIZE_LIMIT") return res.status(413).json(out);
  return res.status(502).json(out);
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
let agentTownTrace = [];
let moltbookTrace = [];
let moltbookApiKey = null;
let soloTrace = [];

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

const { proxyViaCodexCli } = require("./codex_bridge");

app.post("/api/llm/openai/v1/chat/completions", async (req, res) => {
  if (process.env.NODE_ENV === "test") return handleTestOpenAiChatCompletions(req, res);
  if (process.env.OPENCLAW_LITE_CODEX_CLI === "1") return proxyViaCodexCli(req, res);
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

app.get("/api/house/nonce", (req, res) => {
  const s = ensureSession(req, res);
  const nonce = makeNonce("n");
  s.houseInitNonce = nonce;
  res.json({ ok: true, nonce });
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
  if (!s.houseInitNonce || nonce !== s.houseInitNonce) {
    return res.status(400).json({ ok: false, error: "NONCE_MISMATCH" });
  }
  if (!houseAuthKey) return res.status(400).json({ ok: false, error: "MISSING_HOUSE_AUTH" });
  const authKeyBytes = decodeB64(houseAuthKey);
  if (!authKeyBytes || authKeyBytes.length < 16) return res.status(400).json({ ok: false, error: "INVALID_HOUSE_AUTH" });

  // v1.2: ceremony-only houses.
  if (keyMode !== "ceremony") return res.status(400).json({ ok: false, error: "CEREMONY_ONLY" });

  let normalizedUnlock = unlock;
  if (unlock && typeof unlock === "object" && unlock.kind === "evm-wallet-signature") {
    const address = normalizeEvmAddress(unlock.address);
    const signature = typeof unlock.signature === "string" ? unlock.signature.trim() : "";
    const unlockNonce = typeof unlock.nonce === "string" ? unlock.nonce.trim() : "";
    if (!address || !signature || !unlockNonce) {
      return res.status(400).json({ ok: false, error: "INVALID_UNLOCK" });
    }
    if (unlockNonce !== nonce) {
      return res.status(400).json({ ok: false, error: "NONCE_MISMATCH" });
    }
    const msg = buildEvmHouseInitMessage({ address, houseId, nonce });
    if (!verifyEvmSignature(address, msg, signature)) {
      return res.status(401).json({ ok: false, error: "BAD_SIGNATURE" });
    }
    normalizedUnlock = {
      kind: "evm-wallet-signature",
      address,
      nonce: unlockNonce,
      signature,
    };
  }

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
    unlock: normalizedUnlock,
    keyWrap: normalizedKeyWrap,
    authKey: houseAuthKey,
    entries: [],
  });
  writeStore(store, { tables: ["houses"] });

  s.houseId = houseId;
  s.houseInitNonce = null;
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
  writeStore(store, { tables: ["houses"] });
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
  const chainRaw = typeof req.body?.chain === "string" ? req.body.chain.trim().toLowerCase() : "";
  const signature = typeof req.body?.signature === "string" ? req.body.signature.trim() : "";
  const nonce = typeof req.body?.nonce === "string" ? req.body.nonce.trim() : "";
  const houseId = typeof req.body?.houseId === "string" ? req.body.houseId.trim() : "";

  if (!address) return res.status(400).json({ ok: false, error: "MISSING_ADDRESS" });
  if (!signature) return res.status(400).json({ ok: false, error: "MISSING_SIGNATURE" });

  const inferredChain = address.startsWith("0x") ? "evm" : "solana";
  const chain = chainRaw || inferredChain;
  if (chain !== "solana" && chain !== "evm") return res.status(400).json({ ok: false, error: "UNSUPPORTED_CHAIN" });

  const normalizedAddress = chain === "evm" ? normalizeEvmAddress(address) : address;
  if (!normalizedAddress) return res.status(400).json({ ok: false, error: "INVALID_ADDRESS" });

  const usingNonce = !!nonce;
  if (usingNonce) {
    if (nonce !== s.walletLookupNonce) return res.status(400).json({ ok: false, error: "NONCE_MISMATCH" });
    const msg = buildWalletLookupMessage({ address: normalizedAddress, nonce, houseId: houseId || null });
    const verified =
      chain === "evm"
        ? verifyEvmSignature(normalizedAddress, msg, signature)
        : verifySolanaSignature(normalizedAddress, msg, signature);
    if (!verified) {
      return res.status(401).json({ ok: false, error: "BAD_SIGNATURE" });
    }
    s.walletLookupNonce = null;
  } else {
    if (!houseId) return res.status(400).json({ ok: false, error: "MISSING_HOUSE_ID" });
    const msg = buildHouseKeyWrapMessage({ houseId });
    const verified =
      chain === "evm"
        ? verifyEvmSignature(normalizedAddress, msg, signature)
        : verifySolanaSignature(normalizedAddress, msg, signature);
    if (!verified) {
      return res.status(401).json({ ok: false, error: "BAD_SIGNATURE" });
    }
  }

  const store = readStore();
  let matches = [];
  if (chain === "evm") {
    matches = store.houses.filter((r) => {
      if (!r || !r.unlock || r.unlock.kind !== "evm-wallet-signature") return false;
      const addr = normalizeEvmAddress(r.unlock.address);
      return !!addr && addr === normalizedAddress;
    });
  } else {
    matches = store.houses.filter(
      (r) => r && r.unlock && r.unlock.kind === "solana-wallet-signature" && r.unlock.address === normalizedAddress,
    );
  }
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

function sanitizePromptMd(input, maxLen) {
  const raw = typeof input === "string" ? input : "";
  // Preserve newlines for Markdown, but strip control chars + HTML tags deterministically.
  let cleaned = raw.replace(/\r\n?/g, "\n");
  cleaned = cleaned.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "");
  cleaned = cleaned.replace(/<[^>]*>/g, "");

  if (maxLen && maxLen > 0 && cleaned.length > maxLen) {
    cleaned = cleaned.slice(0, maxLen);
  }

  // Trim trailing whitespace per-line and outer whitespace.
  cleaned = cleaned
    .split("\n")
    .map((l) => l.replace(/[ \t]+$/g, ""))
    .join("\n")
    .trim();
  return cleaned;
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

  writeStore(store, { tables: ["vaultBackups", "vaultPointers"] });
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
    writeStore(store, { tables: ["publicProfiles"] });
    return res.json({ ok: true, profile: null });
  }

  const normalized = normalizeHousePublicJson(req.body?.housePublicJson);
  if (!normalized) return res.status(400).json({ ok: false, error: "INVALID_PUBLIC_PROFILE" });

  const promptMd = req.body?.promptMd == null ? "" : String(req.body.promptMd);
  const safePromptMd = sanitizePromptMd(promptMd, MAX_PROMPT_MD);

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
  writeStore(store, { tables: ["publicProfiles"] });

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

  app.get("/__test__/web-fetch/doc/:name", (req, res) => {
    const name = typeof req.params?.name === "string" ? req.params.name.trim().toLowerCase() : "";
    if (!name) return res.status(400).type("text/plain").send("missing name");
    if (name === "same") {
      return res
        .status(200)
        .set("content-type", "text/plain; charset=utf-8")
        .set("etag", '"same-doc-v1"')
        .set("last-modified", "Mon, 01 Jan 2024 00:00:00 GMT")
        .send("Same Origin Fixture: OpenClaw Lite web_fetch deterministic doc.");
    }
    if (name === "blocked") {
      return res
        .status(200)
        .set("content-type", "text/plain; charset=utf-8")
        .send("Localhost fixture document (should be blocked when fetched via proxy).");
    }
    return res.status(404).type("text/plain").send("not found");
  });

  app.post("/__test__/http/echo-json", (req, res) => {
    res.status(200).json({
      ok: true,
      method: "POST",
      echo: req.body || {},
      contentType: req.header("content-type") || "",
    });
  });

  app.get("/__test__/http/large-text", (_req, res) => {
    const text = [
      "OpenClaw Lite http_request large fixture.",
      "This response is intentionally long for truncation checks.",
      "abcdefghijklmnopqrstuvwxyz0123456789",
    ].join(" ");
    res.status(200).type("text/plain; charset=utf-8").send(text);
  });

  app.get("/__test__/http/auth-echo", (req, res) => {
    const auth = req.header("authorization") || null;
    res.status(200).json({
      ok: true,
      receivedAuthorization: auth,
    });
  });

  app.get("/__test__/agenttown/connect", (_req, res) => {
    agentTownTrace.push("connect");
    res.json({ ok: true, sessionId: "at_session_1" });
  });

  app.get("/__test__/agenttown/poll", (_req, res) => {
    agentTownTrace.push("poll");
    res.json({ ok: true, lobbies: [{ id: "lobby-1", name: "Main Lobby" }] });
  });

  app.post("/__test__/agenttown/select", (req, res) => {
    agentTownTrace.push("select");
    const target = typeof req.body?.target === "string" ? req.body.target : "lobby-1";
    res.json({ ok: true, selected: target });
  });

  app.post("/__test__/agenttown/open", (req, res) => {
    agentTownTrace.push("open");
    const target = typeof req.body?.target === "string" ? req.body.target : "lobby-1";
    res.json({ ok: true, opened: target });
  });

  app.get("/__test__/agenttown/trace", (_req, res) => {
    res.json({ ok: true, trace: agentTownTrace.slice() });
  });

  app.post("/__test__/moltbook/register", (_req, res) => {
    const token = `mb_tok_${randomHex(8)}`;
    moltbookApiKey = token;
    moltbookTrace.push("register");
    res.json({ ok: true, apiKey: token, userId: "mb_user_1" });
  });

  app.get("/__test__/moltbook/feed", (req, res) => {
    const auth = req.header("authorization") || "";
    if (!moltbookApiKey || auth !== `Bearer ${moltbookApiKey}`) {
      return res.status(401).json({ ok: false, error: "UNAUTHORIZED" });
    }
    moltbookTrace.push("feed");
    res.json({ ok: true, items: [{ id: "post_1", text: "Welcome to Moltbook" }] });
  });

  app.post("/__test__/moltbook/post", (req, res) => {
    const auth = req.header("authorization") || "";
    if (!moltbookApiKey || auth !== `Bearer ${moltbookApiKey}`) {
      return res.status(401).json({ ok: false, error: "UNAUTHORIZED" });
    }
    const text = typeof req.body?.text === "string" ? req.body.text : "";
    moltbookTrace.push("post");
    res.json({ ok: true, postId: `post_${randomHex(4)}`, text });
  });

  app.get("/__test__/moltbook/trace", (_req, res) => {
    res.json({ ok: true, trace: moltbookTrace.slice() });
  });

  app.post("/__test__/solo/session/create", (_req, res) => {
    soloTrace.push("session.create");
    res.json({ ok: true, sessionId: `solo_${randomHex(6)}` });
  });

  app.post("/__test__/solo/paint", (req, res) => {
    soloTrace.push("paint");
    const confidence = typeof req.body?.confidence === "number" ? req.body.confidence : 0;
    res.json({ ok: true, accepted: confidence >= 0.8 });
  });

  app.post("/__test__/solo/commit", (req, res) => {
    soloTrace.push("commit");
    const commit = typeof req.body?.commit === "string" ? req.body.commit : "";
    res.json({ ok: true, commit });
  });

  app.post("/__test__/solo/reveal", (req, res) => {
    soloTrace.push("reveal");
    const reveal = typeof req.body?.reveal === "string" ? req.body.reveal : "";
    res.json({ ok: true, reveal });
  });

  app.get("/__test__/solo/trace", (_req, res) => {
    res.json({ ok: true, trace: soloTrace.slice() });
  });

  app.get("/__test__/webmcp/discover", (_req, res) => {
    res.json({
      ok: true,
      tools: [
        {
          name: "fixture.echo",
          description: "Echoes text input.",
          inputSchema: {
            type: "object",
            properties: { text: { type: "string" } },
            required: ["text"],
          },
        },
      ],
    });
  });

  app.post("/__test__/webmcp/call", (req, res) => {
    const tool = typeof req.body?.tool === "string" ? req.body.tool.trim() : "";
    const args = req.body?.args && typeof req.body.args === "object" ? req.body.args : {};
    if (tool !== "fixture.echo") return res.status(404).json({ ok: false, error: "NOT_FOUND" });
    const text = typeof args.text === "string" ? args.text : "";
    res.json({ ok: true, result: { text } });
  });

  app.get("/__test__/wallet/seed", (_req, res) => {
    const seedHex = getTestWalletSeedHex();
    const address = getTestWalletAddress();
    if (!seedHex || !address) return res.status(500).json({ ok: false, error: "TEST_WALLET_NOT_AVAILABLE" });
    res.json({ ok: true, seedHex, address });
  });

  app.get("/__test__/evm/wallet", (_req, res) => {
    const address = getTestEvmAddress();
    if (!address) return res.status(500).json({ ok: false, error: "TEST_EVM_WALLET_NOT_AVAILABLE" });
    res.json({ ok: true, address });
  });

  app.post("/__test__/evm/sign", async (req, res) => {
    const wallet = getTestEvmWallet();
    if (!wallet) return res.status(500).json({ ok: false, error: "TEST_EVM_WALLET_NOT_AVAILABLE" });
    const message = typeof req.body?.message === "string" ? req.body.message : "";
    if (!message) return res.status(400).json({ ok: false, error: "MISSING_MESSAGE" });
    try {
      const signatureHex = await wallet.signMessage(message);
      res.json({ ok: true, address: wallet.address, signatureHex });
    } catch {
      res.status(500).json({ ok: false, error: "EVM_SIGN_FAILED" });
    }
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
    agentTownTrace = [];
    moltbookTrace = [];
    moltbookApiKey = null;
    soloTrace = [];
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
const server = app.listen(port, () => {
  console.log(`[openclaw-lite] http://localhost:${port}`);
});

if (process.env.NODE_ENV === "test") {
  const wsEchoServer = new WebSocketServer({ noServer: true });

  wsEchoServer.on("connection", (ws, req) => {
    let pathname = "";
    try {
      const base = `http://${req?.headers?.host || "localhost"}`;
      pathname = new URL(req?.url || "/", base).pathname;
    } catch {
      pathname = "";
    }

    ws.on("message", (data, isBinary) => {
      if (isBinary) {
        ws.send(data, { binary: true });
        return;
      }
      const text = Buffer.isBuffer(data) ? data.toString("utf8") : String(data || "");
      let parsed = null;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = null;
      }

      if (pathname === "/__test__/experience/ws") {
        const files = parsed && parsed.files && typeof parsed.files === "object" ? parsed.files : {};
        const required = ["skill", "heartbeat", "goals", "tools", "penalty"];
        const receivedFiles = required.filter((k) => typeof files[k] === "string" && files[k].length > 0);
        const ok = parsed && parsed.type === "experience.run" && receivedFiles.length === required.length;
        ws.send(JSON.stringify({ ok, receivedFiles }));
        return;
      }

      if (parsed && parsed.jsonrpc === "2.0" && parsed.method === "ping") {
        ws.send(
          JSON.stringify({
            jsonrpc: "2.0",
            id: parsed.id ?? null,
            result: "pong",
          }),
        );
        return;
      }
      ws.send(text);
    });
  });

  server.on("upgrade", (req, socket, head) => {
    let pathname = "";
    try {
      const base = `http://${req.headers.host || "localhost"}`;
      pathname = new URL(req.url || "/", base).pathname;
    } catch {
      pathname = "";
    }
    if (pathname !== "/__test__/ws/echo" && pathname !== "/__test__/experience/ws") {
      socket.destroy();
      return;
    }
    wsEchoServer.handleUpgrade(req, socket, head, (ws) => {
      wsEchoServer.emit("connection", ws, req);
    });
  });
}
