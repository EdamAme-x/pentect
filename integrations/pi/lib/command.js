import { dirname, resolve } from "node:path";

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
