import { createInterface } from "node:readline";

export const schema = "pentect.plugin.v1" as const;
export const configPath = () => process.env.PENTECT_PLUGIN_CONFIG;
export const cachePath = () => process.env.PENTECT_PLUGIN_CACHE_DIR;

export type PluginRequest = {
  schema: typeof schema;
  id: number;
  type: "initialize" | "event";
  stage?: string;
  payload?: unknown;
  context?: unknown;
};

export function next(request: PluginRequest, payload?: unknown, spans?: unknown[]) {
  return {
    schema,
    id: request.id,
    type: "result",
    action: "next",
    ...(payload === undefined ? {} : { payload }),
    ...(spans === undefined ? {} : { spans }),
  };
}

export function stop(
  request: PluginRequest,
  outcome: "block" | "respond" | "handled" = "block",
  payload?: unknown,
  message?: string,
) {
  return {
    schema,
    id: request.id,
    type: "result",
    action: "stop",
    outcome,
    ...(payload === undefined ? {} : { payload }),
    ...(message === undefined ? {} : { message }),
  };
}

export function serve(handler: (request: PluginRequest) => unknown | Promise<unknown>) {
  const lines = createInterface({ input: process.stdin });
  lines.on("line", async (line) => {
    const request = JSON.parse(line) as PluginRequest;
    if (request.schema !== schema) throw new Error("unsupported Pentect plugin schema");
    const response =
      request.type === "initialize"
        ? { schema, id: request.id, type: "initialized" }
        : await handler(request);
    process.stdout.write(`${JSON.stringify(response)}\n`);
  });
}
