import { createHash } from 'node:crypto';
import { access, chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const repository = 'EdamAme-x/pentect';
const packageRoot = fileURLToPath(new URL('../..', import.meta.url));

function cacheBase(environment = process.env, platform = process.platform, home = homedir()) {
  if (environment.PENTECT_NPM_CACHE) return resolve(environment.PENTECT_NPM_CACHE);
  if (platform === 'win32') {
    return resolve(environment.LOCALAPPDATA || join(home, 'AppData', 'Local'), 'Pentect', 'npm');
  }
  if (platform === 'darwin') return resolve(home, 'Library', 'Caches', 'Pentect', 'npm');
  return resolve(environment.XDG_CACHE_HOME || join(home, '.cache'), 'pentect', 'npm');
}

export function installationPath(version, options = {}) {
  if (!/^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$/.test(version) || version === '..') {
    throw new Error('The Pentect package version is invalid');
  }
  const platform = options.platform || process.platform;
  const base = cacheBase(options.environment, platform, options.home);
  return join(base, version, platform === 'win32' ? 'pentect.exe' : 'pentect');
}

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

async function packageVersion() {
  const metadata = JSON.parse(await readFile(join(packageRoot, 'package.json'), 'utf8'));
  return metadata.version?.replace(/^v/, '');
}

export function retryableStatus(status) {
  return status === 408 || status === 429 || status >= 500;
}

export async function downloadWithRetry(url, options = {}) {
  const request = options.request || globalThis.fetch;
  const wait = options.wait || ((milliseconds) => new Promise(
    (resolveDelay) => setTimeout(resolveDelay, milliseconds),
  ));
  const timeout = options.timeout || (() => AbortSignal.timeout(90_000));
  let lastError;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const response = await request(url, {
        redirect: 'follow',
        headers: { 'user-agent': 'pentect-npm-installer' },
        signal: timeout(),
      });
      if (!response.ok) {
        await response.body?.cancel();
        if (!retryableStatus(response.status) || attempt === 3) {
          return {
            ok: false,
            status: response.status,
            statusText: response.statusText,
          };
        }
        lastError = new Error(`Download failed (${response.status} ${response.statusText})`);
      } else {
        return {
          ok: true,
          status: response.status,
          statusText: response.statusText,
          bytes: Buffer.from(await response.arrayBuffer()),
        };
      }
    } catch (error) {
      lastError = error;
      if (attempt === 3) throw error;
    }
    await wait(attempt * 250);
  }
  throw lastError;
}

async function download(url) {
  const response = await downloadWithRetry(url);
  if (!response.ok) throw new Error(`Download failed (${response.status} ${response.statusText})`);
  return response.bytes;
}

async function downloadBinary(base, asset) {
  const compressed = await downloadWithRetry(`${base}/${asset}.gz`);
  if (compressed.ok) return gunzipSync(compressed.bytes);
  if (compressed.status !== 404) {
    throw new Error(`Download failed (${compressed.status} ${compressed.statusText})`);
  }
  return download(`${base}/${asset}`);
}

export async function install(version) {
  version ||= await packageVersion();
  const asset = releaseAsset();
  const destination = installationPath(version);
  const tag = version ? `v${version}` : 'latest';
  const base = tag === 'latest'
    ? `https://github.com/${repository}/releases/latest/download`
    : `https://github.com/${repository}/releases/download/${tag}`;
  const [binary, checksumFile] = await Promise.all([
    downloadBinary(base, asset),
    download(`${base}/${asset}.sha256`),
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
    await writeFile(join(dirname(destination), '.pentect-managed-install.json'), JSON.stringify({
      version: 1,
      manager: 'npm',
      update: 'npm update -g pentect',
      uninstall: 'npm uninstall -g pentect',
    }), { mode: 0o600 });
  } finally {
    await rm(temporary, { force: true });
  }
  return destination;
}

export async function ensureInstalled() {
  const version = await packageVersion();
  const destination = installationPath(version);
  try {
    await access(destination);
    return destination;
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  return install(version);
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (invokedDirectly) {
  install().catch((error) => {
    console.error(`pentect: ${error.message}`);
    process.exitCode = 1;
  });
}
