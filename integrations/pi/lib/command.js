import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function invocation(pentectCli, piCli, userArgs, node = process.execPath) {
  return {
    command: node,
    args: [
      pentectCli,
      "pi",
      "--pi",
      node,
      "--",
      piCli,
      ...userArgs,
    ],
  };
}

export function piBinaryFromEntry(entry) {
  return resolve(dirname(entry), "cli.js");
}

export function packageEntryPath(specifier, resolver = import.meta.resolve) {
  return fileURLToPath(resolver(specifier));
}
