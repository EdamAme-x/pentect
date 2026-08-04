import { createHash } from 'node:crypto';
import { chmod, mkdir, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const repository = 'EdamAme-x/pentect';
const packageRoot = fileURLToPath(new URL('../..', import.meta.url));
const destination = join(packageRoot, 'packaging', 'npm', 'vendor', process.platform === 'win32' ? 'pentect.exe' : 'pentect');

export function releaseAsset(platform = process.platform, architecture = process.arch) {
  const assets = {
    'win32-x64': 'pentect-windows-x86_64.exe',
    'linux-x64': 'pentect-linux-x86_64',
    'linux-arm64': 'pentect-linux-aarch64',
    'darwin-x64': 'pentect-macos-x86_64',
    'darwin-arm64': 'pentect-macos-aarch64',
  };
  const asset = assets[`${platform}-${architecture}`];
  if (!asset) throw new Error(`Pentect does not provide a binary for ${platform}/${architecture}`);
  return asset;
}

export function expectedChecksum(text) {
  const match = text.trim().match(/^([a-fA-F0-9]{64})(?:\s+\*?[^\s]+)?$/);
  if (!match) throw new Error('The release checksum is invalid');
  return match[1].toLowerCase();
}

async function download(url, signal) {
  const response = await fetch(url, {
    redirect: 'follow',
    headers: { 'user-agent': 'pentect-npm-installer' },
    signal,
  });
  if (!response.ok) throw new Error(`Download failed (${response.status} ${response.statusText})`);
  return Buffer.from(await response.arrayBuffer());
}

async function downloadBinary(base, asset, signal) {
  const compressed = await fetch(`${base}/${asset}.gz`, {
    redirect: 'follow',
    headers: { 'user-agent': 'pentect-npm-installer' },
    signal,
  });
  if (compressed.ok) return gunzipSync(Buffer.from(await compressed.arrayBuffer()));
  if (compressed.status !== 404) {
    throw new Error(`Download failed (${compressed.status} ${compressed.statusText})`);
  }
  return download(`${base}/${asset}`, signal);
}

export async function install() {
  const asset = releaseAsset();
  const version = process.env.PENTECT_VERSION?.replace(/^v/, '');
  const tag = version ? `v${version}` : 'latest';
  const base = tag === 'latest'
    ? `https://github.com/${repository}/releases/latest/download`
    : `https://github.com/${repository}/releases/download/${tag}`;
  const signal = AbortSignal.timeout(90_000);
  const [binary, checksumFile] = await Promise.all([
    downloadBinary(base, asset, signal),
    download(`${base}/${asset}.sha256`, signal),
  ]);
  const expected = expectedChecksum(checksumFile.toString('utf8'));
  const actual = createHash('sha256').update(binary).digest('hex');
  if (actual !== expected) throw new Error('The release checksum does not match the downloaded binary');

  await mkdir(dirname(destination), { recursive: true });
  const temporary = `${destination}.${process.pid}.tmp`;
  try {
    await writeFile(temporary, binary, { mode: 0o755, flag: 'wx' });
    await rm(destination, { force: true });
    await rename(temporary, destination);
    if (process.platform !== 'win32') await chmod(destination, 0o755);
  } finally {
    await rm(temporary, { force: true });
  }
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (invokedDirectly) {
  install().catch((error) => {
    console.error(`pentect: ${error.message}`);
    process.exitCode = 1;
  });
}
