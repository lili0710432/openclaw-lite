const { Readable } = require("stream");

const { proxyViaCodexCli } = require("../codex_bridge");

function registerLlmRoutes(app) {
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
    if (process.env.OPENCLAW_LITE_CODEX_CLI === "1") return proxyViaCodexCli(req, res);
    return await proxyToOpenAI(req, res, "chat/completions");
  });

  app.post("/api/llm/openai/v1/responses", async (req, res) => {
    if (process.env.NODE_ENV === "test") return handleTestOpenAiResponses(req, res);
    return await proxyToOpenAI(req, res, "responses");
  });

  function getLlmStats() {
    return { ...llmTestStats };
  }

  function resetLlmStats() {
    llmTestStats.chatCompletions = 0;
    llmTestStats.responses = 0;
    llmTestStats.lastPath = null;
  }

  return { getLlmStats, resetLlmStats };
}

module.exports = { registerLlmRoutes };
