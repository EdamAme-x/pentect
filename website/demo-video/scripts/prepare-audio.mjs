import {createHash} from "node:crypto";
import {mkdir, readFile, writeFile} from "node:fs/promises";
import {fileURLToPath} from "node:url";

const source = "https://assets.mixkit.co/music/1167/1167.mp3";
const expectedSha256 = "a7f05a29d07a84d38072ccd2b35204bca812db86e75b2a837e71cc144d3e739b";
const outputUrl = new URL("../public/audio/close-up-bed.mp3", import.meta.url);
const output = fileURLToPath(outputUrl);
const force = process.argv.includes("--force");

function verifyAudio(bytes) {
  if (bytes.length < 100_000) {
    throw new Error(`Downloaded demo music is unexpectedly small (${bytes.length} bytes)`);
  }

  const sha256 = createHash("sha256").update(bytes).digest("hex");
  if (sha256 !== expectedSha256) {
    throw new Error(`Demo music SHA-256 mismatch: expected ${expectedSha256}, received ${sha256}`);
  }
}

if (!force) {
  try {
    const cachedBytes = await readFile(output);
    verifyAudio(cachedBytes);
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
verifyAudio(bytes);

await mkdir(fileURLToPath(new URL("../public/audio/", import.meta.url)), {recursive: true});
await writeFile(outputUrl, bytes);
console.log(`Downloaded Close Up to ${output}`);
