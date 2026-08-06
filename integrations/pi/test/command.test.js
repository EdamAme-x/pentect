import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { invocation, piBinaryFromEntry } from "../lib/command.js";

test("launches the bundled Pi CLI through Pentect without a shell", () => {
  const result = invocation(
    "/packages/pentect/cli.js",
    "/packages/pi/cli.js",
    ["--model", "openai/gpt-5", "hello"],
    "/usr/bin/node",
  );

  assert.deepEqual(result, {
    command: "/usr/bin/node",
    args: [
      "/packages/pentect/cli.js",
      "pi",
      "--pi",
      "/usr/bin/node",
      "--",
      "/packages/pi/cli.js",
      "--model",
      "openai/gpt-5",
      "hello",
    ],
  });
});

test("finds Pi's CLI beside its public package entry", () => {
  assert.equal(
    piBinaryFromEntry("/packages/pi/dist/index.js"),
    resolve("/packages/pi/dist/cli.js"),
  );
});
