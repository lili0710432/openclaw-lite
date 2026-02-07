// OpenClaw Lite: PI-AI browser port
//
// Why this file exists:
// - `@mariozechner/pi-agent-core` imports `streamSimple`, `EventStream`, and
//   `validateToolArguments` from `@mariozechner/pi-ai`.
// - The PI-AI package entrypoint registers *all* built-in providers, including
//   Node-only ones (AWS Bedrock, etc). That breaks browser bundling.
//
// This port module:
// - registers only browser-safe providers we need for Lite (Phase 1: OpenAI),
// - exports a compatible `streamSimple` that routes via PI-AI's api registry,
// - keeps tool argument validation as a no-op to avoid CSP `unsafe-eval`.

export { EventStream } from "@mariozechner/pi-ai/dist/utils/event-stream.js";

import { getApiProvider, registerApiProvider } from "@mariozechner/pi-ai/dist/api-registry.js";

import { streamOpenAICompletions, streamSimpleOpenAICompletions } from "@mariozechner/pi-ai/dist/providers/openai-completions.js";
import { streamOpenAIResponses, streamSimpleOpenAIResponses } from "@mariozechner/pi-ai/dist/providers/openai-responses.js";

const SOURCE_ID = "openclaw-lite-browser-port@1";

// Register the subset of providers Lite supports today.
registerApiProvider(
  {
    api: "openai-completions",
    stream: streamOpenAICompletions,
    streamSimple: streamSimpleOpenAICompletions,
  },
  SOURCE_ID,
);

registerApiProvider(
  {
    api: "openai-responses",
    stream: streamOpenAIResponses,
    streamSimple: streamSimpleOpenAIResponses,
  },
  SOURCE_ID,
);

function resolveApiProvider(api) {
  const provider = getApiProvider(api);
  if (!provider) {
    throw new Error(`No API provider registered for api: ${api}`);
  }
  return provider;
}

export function streamSimple(model, context, options) {
  const provider = resolveApiProvider(model.api);
  return provider.streamSimple(model, context, options);
}

// Avoid AJV and schema compilation under strict CSP. Lite MVP does not execute
// tool calls in-browser (tools: []).
export function validateToolArguments(_tool, toolCall) {
  return toolCall?.arguments ?? {};
}

