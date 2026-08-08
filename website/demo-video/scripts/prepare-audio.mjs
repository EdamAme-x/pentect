import {access, mkdir, writeFile} from "node:fs/promises";
import {fileURLToPath} from "node:url";

const source = "https://assets.mixkit.co/music/1167/1167.mp3";
const outputUrl = new URL("../public/audio/close-up-bed.mp3", import.meta.url);
const output = fileURLToPath(outputUrl);
const force = process.argv.includes("--force");

if (!force) {
  try {
    await access(output);
    console.log(`Using ${output}`);
    process.exit(0);
  } catch {
    // Download the track below.
  }
}

const response = await fetch(source);
if (!response.ok) {
  throw new Error(`Unable to download demo music: ${response.status} ${response.statusText}`);
}

const bytes = Buffer.from(await response.arrayBuffer());
if (bytes.length < 100_000) {
  throw new Error(`Downloaded demo music is unexpectedly small (${bytes.length} bytes)`);
}

await mkdir(fileURLToPath(new URL("../public/audio/", import.meta.url)), {recursive: true});
await writeFile(outputUrl, bytes);
console.log(`Downloaded Close Up to ${output}`);
