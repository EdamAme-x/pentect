import assert from "node:assert/strict";
import test from "node:test";
import {
  parseReady,
  providerArguments,
  providerDefinition,
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
