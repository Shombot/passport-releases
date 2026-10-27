// Install in the PUBLIC binary repository. It never receives source or signing secrets.
import { mkdir, writeFile, rename } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  BETA_ENDPOINT,
  RELEASE_REPOSITORY,
  parsePublicKey,
  releaseVersion,
  selectPublishedBeta,
  validateReleaseAssets,
  validateDownloadedRelease,
  monotonicManifest,
} from './release-core.mjs';

export async function readResponse(response, maximum = 2 * 1024 * 1024) {
  const claimed = response.headers.get('content-length');
  if (claimed && (!/^\d+$/.test(claimed) || Number(claimed) > maximum))
    throw new Error('Release response exceeds its size limit');
  const reader = response.body?.getReader();
  if (!reader) throw new Error('Empty release response');
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > maximum) throw new Error('Release response exceeds its size limit');
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return Buffer.concat(chunks, size);
}
export async function githubJson(
  path,
  { token, method = 'GET', body, allowMissing = false, fetcher = fetch } = {},
) {
  if (!path.startsWith(`/repos/${RELEASE_REPOSITORY}/`))
    throw new Error('Unexpected public repository API path');
  const response = await fetcher(`https://api.github.com${path}`, {
    method,
    redirect: 'error',
    signal: AbortSignal.timeout(30_000),
    headers: {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  if (response.status === 404 && allowMissing) return null;
  if (!response.ok) throw new Error(`GitHub release request failed (${response.status})`);
  try {
    return JSON.parse((await readResponse(response)).toString('utf8'));
  } catch {
    throw new Error('Invalid GitHub release response');
  }
}
export async function listReleases(options = {}) {
  const releases = [];
  for (let page = 1; page <= 100; page++) {
    const items = await githubJson(
      `/repos/${RELEASE_REPOSITORY}/releases?per_page=100&page=${page}`,
      options,
    );
    if (!Array.isArray(items)) throw new Error('Invalid GitHub release list');
    releases.push(...items);
    if (items.length < 100) return releases;
  }
  throw new Error('Release list exceeds validation limit');
}
export async function downloadRelease(release, { fetcher = fetch } = {}) {
  const files = new Map();
  for (const asset of validateReleaseAssets(release)) {
    // These are public files. Never forward the API credential to a download/CDN host.
    const response = await fetcher(asset.browser_download_url, {
      signal: AbortSignal.timeout(180_000),
    });
    if (!response.ok) throw new Error(`Release artifact download failed (${response.status})`);
    const maximum = asset.name.endsWith('.sig')
      ? 16_384
      : asset.name.endsWith('.json')
        ? 128 * 1024
        : asset.name.endsWith('.txt')
          ? 16_384
          : 512 * 1024 * 1024;
    files.set(asset.name, await readResponse(response, maximum));
  }
  return files;
}
export async function readCurrentManifest({ fetcher = fetch, now = Date.now } = {}) {
  const url = new URL(BETA_ENDPOINT);
  url.searchParams.set('publication-check', String(now()));
  const response = await fetcher(url, {
    redirect: 'error',
    signal: AbortSignal.timeout(30_000),
    cache: 'no-store',
    headers: { 'Cache-Control': 'no-cache, no-store', Pragma: 'no-cache' },
  });
  if (response.status === 404) return null; // First deployment only.
  if (!response.ok)
    throw new Error('Current beta manifest unavailable; refusing an unguarded publication');
  try {
    return JSON.parse((await readResponse(response, 128 * 1024)).toString('utf8'));
  } catch {
    throw new Error('Current beta manifest is invalid');
  }
}
export async function prepareBetaManifest({
  eventName,
  event,
  token,
  publicKey,
  outputDirectory,
  fetcher = fetch,
  now = Date.now,
}) {
  if (!publicKey) throw new Error('PASSPORT_UPDATER_PUBLIC_KEY is required');
  parsePublicKey(publicKey);
  const options = { token, fetcher };
  let triggerTag;
  if (eventName === 'release') {
    if (event.action !== 'published') throw new Error('Only release: published can advance beta');
    releaseVersion(event.release); // Drafts and stable releases are never eligible.
    triggerTag = event.release.tag_name;
  } else if (eventName === 'workflow_dispatch') {
    triggerTag = event.inputs?.release_tag;
  } else throw new Error('Unexpected manifest publication event');
  const trigger = await githubJson(
    `/repos/${RELEASE_REPOSITORY}/releases/tags/${encodeURIComponent(triggerTag)}`,
    options,
  );
  releaseVersion(trigger); // Re-read authoritative publication state, not just the webhook.
  const newest = selectPublishedBeta(await listReleases(options));
  const files = await downloadRelease(newest, { fetcher });
  const candidate = validateDownloadedRelease(newest, files, publicKey);
  const current = await readCurrentManifest({ fetcher, now });
  const manifest = monotonicManifest(candidate, current);
  const destination = resolve(outputDirectory, 'beta');
  await mkdir(destination, { recursive: true });
  const temporary = resolve(destination, 'latest.json.tmp');
  await writeFile(temporary, JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
  await rename(temporary, resolve(destination, 'latest.json'));
  await writeFile(resolve(outputDirectory, '.nojekyll'), '');
  return manifest;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const { readFile } = await import('node:fs/promises');
    const event = JSON.parse(await readFile(process.env.GITHUB_EVENT_PATH, 'utf8'));
    const manifest = await prepareBetaManifest({
      eventName: process.env.GITHUB_EVENT_NAME,
      event,
      token: process.env.GH_TOKEN,
      publicKey: process.env.PASSPORT_UPDATER_PUBLIC_KEY,
      outputDirectory: process.argv[2] || '.pages',
    });
    console.log(`Verified published beta ${manifest.version}; Pages artifact prepared.`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'Beta manifest validation failed');
    process.exitCode = 1;
  }
}
