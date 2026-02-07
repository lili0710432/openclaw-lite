/* eslint-disable no-console */

import { bytesToB64, utf8ToBytes } from "./shared/encoding.js";

function byId(id) {
  return document.getElementById(id);
}

function appendLine(node, line) {
  if (!node) return;
  const next = `${node.textContent || ""}${node.textContent ? "\n" : ""}${line}`;
  node.textContent = next.slice(-20_000);
}

function normalizeSignatureBytes(sig) {
  if (sig instanceof Uint8Array) return sig;
  if (sig instanceof ArrayBuffer) return new Uint8Array(sig);
  if (ArrayBuffer.isView(sig)) return new Uint8Array(sig.buffer);
  if (Array.isArray(sig)) return new Uint8Array(sig);
  return null;
}

async function solanaConnect() {
  const provider = window.solana;
  if (!provider || typeof provider.connect !== "function") throw new Error("NO_SOLANA_WALLET");
  const resp = await provider.connect();
  const address = resp?.publicKey?.toString?.();
  if (!address) throw new Error("WALLET_CONNECT_FAILED");
  return { provider, address };
}

async function solanaSignMessageBytes(messageStr) {
  const provider = window.solana;
  if (!provider || typeof provider.signMessage !== "function") throw new Error("NO_SOLANA_SIGN");

  const msgBytes = utf8ToBytes(messageStr);
  const resp = await provider.signMessage(msgBytes);
  const sig = normalizeSignatureBytes(resp?.signature ?? resp);
  if (!sig || sig.length !== 64) throw new Error("SIGNATURE_FORMAT");
  return sig;
}

async function init() {
  const runtimeStatus = byId("runtimeStatus");
  const walletLine = byId("walletLine");
  const houseId = byId("houseId");
  const vaultStatus = byId("vaultStatus");
  const approvals = byId("approvals");
  const runtimeLogs = byId("runtimeLogs");
  const chatTranscript = byId("chatTranscript");
  const chatInput = byId("chatInput");
  const llmKeyInput = byId("llmKeyInput");
  const llmLine = byId("llmLine");

  const connectWalletBtn = byId("connectWalletBtn");
  const createHouseBtn = byId("createHouseBtn");
  const recoverHouseBtn = byId("recoverHouseBtn");
  const backupBtn = byId("backupBtn");
  const restoreBtn = byId("restoreBtn");
  const publishBtn = byId("publishBtn");
  const freezeBtn = byId("freezeBtn");
  const exportBtn = byId("exportBtn");
  const chatSend = byId("chatSend");
  const llmSaveBtn = byId("llmSaveBtn");

  /** @type {Map<string, HTMLElement>} */
  const approvalNodes = new Map();

  function updateWalletLine(addr) {
    if (!walletLine) return;
    walletLine.textContent = addr ? `Wallet: ${addr}` : "";
  }

  let walletAddr = null;

  async function connectWallet({ silent = false } = {}) {
    try {
      const { address } = await solanaConnect();
      walletAddr = address;
      updateWalletLine(walletAddr);
      return address;
    } catch (e) {
      if (!silent) {
        updateWalletLine(`Wallet error: ${e.message || String(e)}`);
      }
      throw e;
    }
  }

  connectWalletBtn?.addEventListener("click", async () => {
    try {
      await connectWallet();
    } catch {
      // handled
    }
  });

  const worker = new Worker("/openclaw-lite/worker.js", { type: "module" });

  function sendToWorker(msg) {
    worker.postMessage(msg);
  }

  function configureLlm({ apiKey }) {
    const key = String(apiKey || "").trim();
    const baseUrl = new URL("/api/llm/openai/v1", window.location.origin).toString();
    sendToWorker({
      type: "gateway.command.setLlmConfig",
      apiKey: key,
      api: "openai-completions",
      provider: "openai",
      modelId: "gpt-4o-mini",
      baseUrl,
    });
    if (llmLine) llmLine.textContent = key ? "LLM: key saved (local)" : "LLM: missing key";
  }

  llmSaveBtn?.addEventListener("click", () => {
    configureLlm({ apiKey: llmKeyInput?.value || "" });
  });

  createHouseBtn?.addEventListener("click", () => {
    const rh = new Uint8Array(32);
    crypto.getRandomValues(rh);
    sendToWorker({ type: "gateway.command.createHouse", rhB64: bytesToB64(rh) });
  });

  recoverHouseBtn?.addEventListener("click", () => {
    sendToWorker({ type: "gateway.command.recoverHouse" });
  });

  backupBtn?.addEventListener("click", () => {
    sendToWorker({ type: "gateway.command.backupVault" });
  });

  restoreBtn?.addEventListener("click", () => {
    sendToWorker({ type: "gateway.command.restoreVault" });
  });

  publishBtn?.addEventListener("click", () => {
    sendToWorker({
      type: "gateway.command.publishProfile",
      housePublicJson: { v: 1, displayName: "Lite House", tagline: "<b>hello</b> from <script>lite</script>" },
      promptMd: "Hello from OpenClaw Lite.",
    });
  });

  freezeBtn?.addEventListener("click", () => {
    sendToWorker({ type: "gateway.command.freezeNow" });
  });

  exportBtn?.addEventListener("click", () => {
    sendToWorker({ type: "gateway.command.exportZip" });
  });

  chatSend?.addEventListener("click", () => {
    const text = (chatInput?.value || "").trim();
    if (!text) return;
    chatInput.value = "";
    sendToWorker({ type: "gateway.chat.send", text });
  });

  chatInput?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") chatSend?.click();
  });

  window.addEventListener("pagehide", () => {
    sendToWorker({ type: "gateway.event.pagehide" });
  });
  document.addEventListener("visibilitychange", () => {
    sendToWorker({ type: "gateway.event.visibilitychange", state: document.visibilityState });
  });

  worker.addEventListener("message", async (ev) => {
    const msg = ev.data;
    if (!msg || typeof msg.type !== "string") return;

    if (msg.type === "worker.runtime.status") {
      if (runtimeStatus) runtimeStatus.textContent = String(msg.status || "");
      return;
    }

    if (msg.type === "worker.runtime.ready") {
      if (runtimeStatus) runtimeStatus.textContent = "ready";
      return;
    }

    if (msg.type === "worker.state.update") {
      if (houseId) houseId.textContent = msg.state?.houseId || "—";
      const latest = msg.state?.vault?.latestBackupId || null;
      if (vaultStatus) vaultStatus.textContent = latest ? `latest ${latest}` : "—";
      return;
    }

    if (msg.type === "worker.log.append") {
      appendLine(runtimeLogs, String(msg.line || ""));
      return;
    }

    if (msg.type === "worker.chat.append") {
      const role = String(msg.role || "unknown");
      const text = String(msg.text || "");
      appendLine(chatTranscript, `${role}: ${text}`);
      return;
    }

    if (msg.type === "worker.approval.request") {
      const approval = msg.approval || {};
      const id = String(approval.id || "");
      if (!id || !approvals) return;
      if (approvalNodes.has(id)) return;

      const wrap = document.createElement("div");
      wrap.className = "kv";
      wrap.style.marginBottom = "8px";
      wrap.textContent = "";

      const label = document.createElement("span");
      label.textContent = `${approval.title || "Approval"}: ${approval.body || ""}`;
      label.style.flex = "1";

      const okBtn = document.createElement("button");
      okBtn.className = "btn primary";
      okBtn.textContent = "Approve";
      okBtn.addEventListener("click", () => {
        sendToWorker({ type: "gateway.approval.respond", id, decision: "approve" });
      });

      const noBtn = document.createElement("button");
      noBtn.className = "btn";
      noBtn.textContent = "Reject";
      noBtn.addEventListener("click", () => {
        sendToWorker({ type: "gateway.approval.respond", id, decision: "reject" });
      });

      wrap.appendChild(label);
      wrap.appendChild(okBtn);
      wrap.appendChild(noBtn);

      approvals.appendChild(wrap);
      approvalNodes.set(id, wrap);
      return;
    }

    if (msg.type === "worker.approval.clear") {
      const id = String(msg.id || "");
      const node = approvalNodes.get(id);
      if (node) node.remove();
      approvalNodes.delete(id);
      return;
    }

    if (msg.type === "worker.wallet.request") {
      const id = String(msg.id || "");
      const method = String(msg.method || "");
      try {
        if (method === "connect") {
          const addr = await connectWallet();
          sendToWorker({ type: "gateway.wallet.response", id, ok: true, address: addr });
          return;
        }
        if (method === "signMessage") {
          if (!walletAddr) {
            await connectWallet({ silent: true });
          }
          const message = String(msg.message || "");
          const sigBytes = await solanaSignMessageBytes(message);
          sendToWorker({
            type: "gateway.wallet.response",
            id,
            ok: true,
            address: walletAddr,
            signatureB64: bytesToB64(sigBytes),
          });
          return;
        }
        throw new Error("UNSUPPORTED_WALLET_METHOD");
      } catch (e) {
        sendToWorker({ type: "gateway.wallet.response", id, ok: false, error: e.message || String(e) });
      }
      return;
    }

    if (msg.type === "worker.export.zip") {
      const filename = String(msg.filename || "openclaw-lite-export.zip");
      const bytes = msg.bytes instanceof ArrayBuffer ? new Uint8Array(msg.bytes) : null;
      if (!bytes) return;

      const blob = new Blob([bytes], { type: "application/zip" });
      const url = URL.createObjectURL(blob);
      try {
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
      } finally {
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      }
      return;
    }
  });

  // Allow Playwright to await readiness deterministically.
  sendToWorker({ type: "gateway.boot" });

  // Test-only helpers (stable surface for Playwright).
  window.__openclawLiteTest = {
    async countCheckpoints() {
      const req = indexedDB.open("openclaw-lite", 1);
      const db = await new Promise((resolve, reject) => {
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error || new Error("IDB_OPEN_FAILED"));
      });
      const tx = db.transaction(["checkpoints"], "readonly");
      const countReq = tx.objectStore("checkpoints").count();
      const count = await new Promise((resolve, reject) => {
        countReq.onsuccess = () => resolve(countReq.result || 0);
        countReq.onerror = () => reject(countReq.error || new Error("IDB_COUNT_FAILED"));
      });
      await new Promise((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error || new Error("IDB_TX_FAILED"));
      });
      db.close();
      return Number(count) || 0;
    },
  };
}

init().catch((e) => {
  console.error(e);
});
