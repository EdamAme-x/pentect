import assert from "node:assert/strict";
import test from "node:test";
import {
  parseReady,
  providerArguments,
  providerDefinition,
  restoreProviderCredentials,
} from "../extensions/pentect.js";

const baseUrl = `http://127.0.0.1:43123/${"a".repeat(64)}`;

test("uses environment settings without putting credentials in arguments", () => {
  assert.deepEqual(
    providerArguments({
      PENTECT_PI_MODEL: "openai/custom-model",
      PENTECT_PI_API: "responses",
      OPENAI_API_KEY: "must-not-appear",
    }),
    [
      "provider",
      "pi",
      "--model",
      "openai/custom-model",
      "--api",
      "responses",
    ],
  );
});

test("accepts only authenticated IPv4 loopback readiness", () => {
  const ready = parseReady(
    JSON.stringify({
      protocol: 1,
      integration: "pi",
      baseUrl,
      model: "gpt-5",
      api: "openai-responses",
    }),
  );
  assert.equal(ready.baseUrl, baseUrl);

  assert.throws(() =>
    parseReady(
      JSON.stringify({
        protocol: 1,
        integration: "pi",
        baseUrl: "https://gateway.example/v1",
        model: "gpt-5",
        api: "openai-responses",
      }),
    ),
  );
});

test("registers one Pentect provider and one selected model", () => {
  const provider = providerDefinition({
    baseUrl,
    model: "gpt-5",
    api: "openai-completions",
  });
  assert.equal(provider.baseUrl, baseUrl);
  assert.equal(provider.apiKey, "pentect-local");
  assert.equal(provider.models.length, 1);
  assert.equal(provider.models[0].id, "gpt-5");
});

test("allows truthful model limits and capabilities for custom upstreams", () => {
  const provider = providerDefinition(
    { baseUrl, model: "local-model", api: "openai-completions" },
    {
      PENTECT_PI_CONTEXT_WINDOW: "65536",
      PENTECT_PI_MAX_TOKENS: "8192",
      PENTECT_PI_INPUTS: "text",
      PENTECT_PI_REASONING: "true",
    },
  );
  assert.equal(provider.models[0].contextWindow, 65536);
  assert.equal(provider.models[0].maxTokens, 8192);
  assert.deepEqual(provider.models[0].input, ["text"]);
  assert.equal(provider.models[0].reasoning, true);

  assert.throws(() =>
    providerDefinition(
      { baseUrl, model: "bad", api: "openai-completions" },
      { PENTECT_PI_CONTEXT_WINDOW: "unknown" },
    ),
  );
});

test("restores credentials when provider startup fails", () => {
  const env = {
    OPENAI_API_KEY: "pentect-local",
  };
  restoreProviderCredentials(
    {
      openaiApiKey: "original-key",
      upstreamAuthorization: "Bearer original",
    },
    env,
  );
  assert.equal(env.OPENAI_API_KEY, "original-key");
  assert.equal(env.PENTECT_UPSTREAM_AUTHORIZATION, "Bearer original");

  restoreProviderCredentials(
    { openaiApiKey: undefined, upstreamAuthorization: undefined },
    env,
  );
  assert.equal(env.OPENAI_API_KEY, undefined);
  assert.equal(env.PENTECT_UPSTREAM_AUTHORIZATION, undefined);
});
