const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

function readCodexAccessToken() {
  const p = path.join(os.homedir(), ".codex", "auth.json");
  const raw = fs.readFileSync(p, "utf8");
  const json = JSON.parse(raw);
  const tok = json?.tokens?.access_token;
  return typeof tok === "string" && tok.trim() ? tok.trim() : null;
}

function isLocalRequest(req) {
  const ip = req.ip || req.connection?.remoteAddress || "";
  // Express may report ::ffff:127.0.0.1
  return ip === "127.0.0.1" || ip === "::1" || ip.endsWith("::1") || ip.endsWith("127.0.0.1");
}

function clampBody(rawBody, maxBytes = 200_000) {
  const body = typeof rawBody === "string" ? rawBody : JSON.stringify(rawBody || {});
  if (Buffer.byteLength(body, "utf8") > maxBytes) {
    throw new Error("BODY_TOO_LARGE");
  }
  return body;
}

function proxyViaCodexCli(req, res) {
  if (!isLocalRequest(req)) {
    return res.status(403).json({ ok: false, error: "LOCALHOST_ONLY" });
  }

  const accessToken = readCodexAccessToken();
  if (!accessToken) {
    return res.status(400).json({ ok: false, error: "MISSING_CODEX_CLI_SESSION" });
  }

  const rawBody = clampBody(req.rawBody || req.body);

  const child = spawn(
    "codex",
    [
      "exec",
      "--json",
      // Run a minimal session that only emits JSONL on stdout.
      // We ask Codex to call the OpenAI-style endpoint, but use the Codex CLI session.
      // The actual provider plumbing happens inside the Codex CLI.
      //
      // IMPORTANT: We do not implement full OpenAI request translation here yet.
      // For v0, we only support chat.completions with a single user message.
      "-",
    ],
    {
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        ...process.env,
        // Ensure codex uses its normal auth/session.
        // Don't pass OPENAI_API_KEY.
        OPENAI_API_KEY: "",
      },
    },
  );

  let stderr = "";
  child.stderr.on("data", (d) => {
    stderr += d.toString("utf8");
  });

  // Parse the incoming OpenAI-style body to extract the user prompt.
  let prompt = "";
  try {
    const body = JSON.parse(rawBody);
    const messages = Array.isArray(body?.messages) ? body.messages : [];
    const firstUser = messages.find((m) => m && m.role === "user");
    const content = firstUser?.content;
    prompt = typeof content === "string" ? content : "";
  } catch {
    // ignore
  }

  // Feed prompt to codex via stdin.
  child.stdin.write(prompt || "");
  child.stdin.end();

  // Collect JSONL events.
  let out = "";
  child.stdout.on("data", (d) => {
    out += d.toString("utf8");
  });

  child.on("close", (code) => {
    if (code !== 0) {
      return res.status(502).json({ ok: false, error: "CODEX_CLI_FAILED", code, stderr: stderr.slice(-4000) });
    }

    // Find the final agent_message text.
    const lines = out.split(/\r?\n/).filter(Boolean);
    let text = "";
    for (const line of lines) {
      if (!line.startsWith("{")) continue;
      try {
        const evt = JSON.parse(line);
        if (evt?.type === "item.completed" && evt?.item?.type === "agent_message") {
          text = String(evt.item.text || "");
        }
      } catch {
        // ignore
      }
    }

    // Return an OpenAI-compatible non-streaming chat.completions response.
    return res.json({
      id: `chatcmpl_codexcli_${Date.now()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: "codex-cli",
      choices: [
        {
          index: 0,
          message: { role: "assistant", content: text },
          finish_reason: "stop",
        },
      ],
    });
  });
}

module.exports = { proxyViaCodexCli };
