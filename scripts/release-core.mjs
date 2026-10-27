// Pure validation shared by the private build pipeline and public Pages publisher.
// Minisign layout follows minisign-verify 0.3.0, used by tauri-plugin-updater 2.14.0.
import { createHash, createPublicKey, timingSafeEqual, verify } from 'node:crypto';

export const RELEASE_REPOSITORY = 'Shombot/passport-releases';
export const SOURCE_REPOSITORY = 'Shombot/passport';
export const APPLICATION_IDENTIFIER = 'app.passport.companion';
export const BETA_ENDPOINT = 'https://shombot.github.io/passport-releases/beta/latest.json';
export const BASELINE_VERSION = '0.1.1-beta.1';
export const TARGETS = ['darwin-aarch64', 'windows-x86_64'];
const betaPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)-beta\.(0|[1-9]\d*)$/;
const keyPrefix = Buffer.from('302a300506032b6570032100', 'hex');
const maximumVersionPart = 18_446_744_073_709_551_615n;

export function parseBetaVersion(value) {
  if (typeof value !== 'string' || value.length > 100) throw new Error('Invalid beta version');
  const match = betaPattern.exec(value);
  if (!match) throw new Error('Expected X.Y.Z-beta.N without leading zeros');
  const parts = match.slice(1).map((part) => BigInt(part));
  if (parts.some((part) => part > maximumVersionPart) || parts[3] === 0n)
    throw new Error('Beta version exceeds the supported client range');
  return parts;
}
export function compareBetaVersions(left, right) {
  const a = parseBetaVersion(left),
    b = parseBetaVersion(right);
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return a[i] > b[i] ? 1 : -1;
  }
  return 0;
}
export function versionFromTag(tag) {
  if (typeof tag !== 'string' || !tag.startsWith('v'))
    throw new Error('Expected a v-prefixed beta tag');
  const version = tag.slice(1);
  parseBetaVersion(version);
  if (compareBetaVersions(version, BASELINE_VERSION) < 0)
    throw new Error('Legacy beta has no updater contract');
  return version;
}
function strictBase64(value, maximum) {
  if (
    typeof value !== 'string' ||
    !value ||
    value.length > maximum ||
    value.trim() !== value ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  )
    throw new Error('Invalid signature or public-key encoding');
  const buffer = Buffer.from(value, 'base64');
  if (buffer.toString('base64') !== value)
    throw new Error('Noncanonical signature or public-key encoding');
  return buffer;
}
export function parsePublicKey(value) {
  // The owner's existing .pub file may have a final newline when loaded via stdin.
  const encoded = typeof value === 'string' ? value.trim() : value;
  const decoded = strictBase64(encoded, 2048).toString('utf8');
  const lines = decoded.replace(/\r\n/g, '\n').trimEnd().split('\n');
  if (lines.length !== 2 || !lines[0].startsWith('untrusted comment: '))
    throw new Error('Invalid updater public key');
  const packet = strictBase64(lines[1], 100);
  if (packet.length !== 42 || packet.subarray(0, 2).toString() !== 'Ed')
    throw new Error('Invalid updater public key');
  return {
    encoded,
    packet,
    key: createPublicKey({
      key: Buffer.concat([keyPrefix, packet.subarray(10)]),
      format: 'der',
      type: 'spki',
    }),
  };
}
export function parseSignature(value) {
  const decoded = strictBase64(value, 4096).toString('utf8');
  const lines = decoded.replace(/\r\n/g, '\n').trimEnd().split('\n');
  if (
    lines.length !== 4 ||
    !lines[0].startsWith('untrusted comment: ') ||
    !lines[2].startsWith('trusted comment: ')
  )
    throw new Error('Invalid updater signature format');
  const packet = strictBase64(lines[1], 150);
  const global = strictBase64(lines[3], 100);
  if (
    packet.length !== 74 ||
    global.length !== 64 ||
    !['Ed', 'ED'].includes(packet.subarray(0, 2).toString())
  )
    throw new Error('Invalid updater signature format');
  return { packet, global, trusted: lines[2].slice(17) };
}
export function verifyUpdaterSignature(payload, encodedSignature, encodedPublicKey, version) {
  parseBetaVersion(version);
  const { packet: publicPacket, key } = parsePublicKey(encodedPublicKey);
  const signature = parseSignature(encodedSignature);
  if (!timingSafeEqual(publicPacket.subarray(2, 10), signature.packet.subarray(2, 10)))
    throw new Error('Updater signing key does not match');
  const bytes = Buffer.from(payload);
  const signed =
    signature.packet.subarray(0, 2).toString() === 'ED'
      ? createHash('blake2b512').update(bytes).digest()
      : bytes;
  const rawSignature = signature.packet.subarray(10);
  if (
    !verify(null, signed, key, rawSignature) ||
    !verify(
      null,
      Buffer.concat([rawSignature, Buffer.from(signature.trusted)]),
      key,
      signature.global,
    )
  )
    throw new Error('Updater signature verification failed');
  // Trust this field only after verifying both the payload and global signature.
  const versions = signature.trusted.split('\t').filter((field) => field.startsWith('version:'));
  if (versions.length !== 1 || versions[0].slice(8) !== version)
    throw new Error('Signed updater version does not match release');
  return true;
}
export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}
export function payloadNames(version) {
  parseBetaVersion(version);
  return {
    dmg: `Passport_${version}_aarch64.dmg`,
    mac: 'Passport.app.tar.gz',
    windows: `Passport_${version}_x64-setup.exe`,
  };
}
export function signedAssetNames(version) {
  return Object.values(payloadNames(version)).flatMap((name) => [name, `${name}.sig`]);
}
export function expectedAssetNames(version) {
  return [...signedAssetNames(version), 'SHA256SUMS.txt', 'release-metadata.json'];
}
export function assetUrl(tag, name) {
  const version = versionFromTag(tag);
  if (!expectedAssetNames(version).includes(name)) throw new Error('Unexpected release asset');
  return `https://github.com/${RELEASE_REPOSITORY}/releases/download/${tag}/${name}`;
}
export function releaseVersion(release) {
  if (
    !release ||
    release.draft !== false ||
    release.prerelease !== true ||
    !release.published_at ||
    !Number.isFinite(Date.parse(release.published_at))
  )
    throw new Error('Only published beta releases are eligible');
  return versionFromTag(release.tag_name);
}
export function selectPublishedBeta(releases) {
  const eligible = releases.flatMap((release) => {
    if (release.draft || !release.prerelease) return [];
    try {
      return [{ release, version: releaseVersion(release) }];
    } catch {
      return [];
    }
  });
  eligible.sort((a, b) => compareBetaVersions(b.version, a.version));
  if (!eligible.length) throw new Error('No published updater-enabled beta exists');
  return eligible[0].release;
}
export function validateReleaseAssets(release) {
  const version = releaseVersion(release);
  const names = expectedAssetNames(version);
  if (!Array.isArray(release.assets)) throw new Error('Missing release assets');
  const map = new Map();
  for (const asset of release.assets) {
    if (map.has(asset.name)) throw new Error('Duplicate release asset');
    map.set(asset.name, asset);
  }
  for (const name of names) {
    const asset = map.get(name);
    if (
      !asset ||
      !Number.isSafeInteger(asset.size) ||
      asset.size <= 0 ||
      asset.size > 512 * 1024 * 1024 ||
      asset.browser_download_url !== assetUrl(release.tag_name, name)
    )
      throw new Error('Missing, invalid or wrong-platform release asset');
  }
  return names.map((name) => map.get(name));
}
export function makeMetadata(version, sourceCommit, files, publicKey) {
  const { encoded } = parsePublicKey(publicKey);
  if (!/^[a-f0-9]{40}$/.test(sourceCommit)) throw new Error('Expected immutable source commit');
  return {
    schemaVersion: 1,
    version,
    tag: `v${version}`,
    applicationIdentifier: APPLICATION_IDENTIFIER,
    sourceRepository: SOURCE_REPOSITORY,
    sourceCommit,
    updaterPublicKeySha256: sha256(Buffer.from(encoded)),
    targets: {
      'darwin-aarch64': 'aarch64-apple-darwin',
      'windows-x86_64': 'x86_64-pc-windows-msvc',
    },
    assets: signedAssetNames(version).map((name) => {
      const bytes = files.get(name);
      if (!bytes?.length) throw new Error('Missing signed asset');
      return { name, bytes: bytes.length, sha256: sha256(bytes) };
    }),
  };
}
export function checksumText(version, files) {
  return signedAssetNames(version)
    .map((name) => `${sha256(files.get(name))}  ${name}\n`)
    .join('');
}
export function validatePayloadSet(version, sourceCommit, files, publicKey) {
  const names = payloadNames(version);
  for (const name of Object.values(names)) {
    const bytes = files.get(name),
      signature = files.get(`${name}.sig`);
    if (!bytes?.length || !signature?.length)
      throw new Error('Missing updater artifact or signature');
    verifyUpdaterSignature(bytes, signature.toString('utf8').trim(), publicKey, version);
  }
  const dmg = files.get(names.dmg),
    windows = files.get(names.windows),
    mac = files.get(names.mac);
  if (dmg.length < 512 || dmg.subarray(-512, -508).toString() !== 'koly')
    throw new Error('Invalid macOS DMG');
  if (mac[0] !== 0x1f || mac[1] !== 0x8b)
    throw new Error('macOS updater must be a gzip app archive, never a DMG');
  const peOffset = windows.length >= 64 ? windows.readUInt32LE(0x3c) : -1;
  if (
    windows.subarray(0, 2).toString() !== 'MZ' ||
    peOffset < 0 ||
    peOffset + 4 > windows.length ||
    !windows.subarray(peOffset, peOffset + 4).equals(Buffer.from([0x50, 0x45, 0, 0]))
  )
    throw new Error('Invalid Windows NSIS executable');
  return makeMetadata(version, sourceCommit, files, publicKey);
}
export function validateDownloadedRelease(release, files, publicKey) {
  const version = releaseVersion(release);
  validateReleaseAssets(release);
  let metadata;
  try {
    metadata = JSON.parse(files.get('release-metadata.json').toString('utf8'));
  } catch {
    throw new Error('Invalid release metadata');
  }
  const expected = validatePayloadSet(version, metadata.sourceCommit, files, publicKey);
  if (JSON.stringify(metadata) !== JSON.stringify(expected))
    throw new Error('Release metadata, platform, version or checksums mismatch');
  if (files.get('SHA256SUMS.txt')?.toString('utf8') !== checksumText(version, files))
    throw new Error('Release checksums mismatch');
  for (const asset of validateReleaseAssets(release))
    if (files.get(asset.name)?.length !== asset.size)
      throw new Error('Incomplete release asset download');
  const names = payloadNames(version);
  const notes = typeof release.body === 'string' ? release.body : '';
  if (Buffer.byteLength(notes, 'utf8') > 64 * 1024)
    throw new Error('Release notes exceed the supported client limit');
  return {
    version,
    notes,
    pub_date: new Date(release.published_at).toISOString(),
    platforms: {
      'darwin-aarch64': {
        url: assetUrl(release.tag_name, names.mac),
        signature: files.get(`${names.mac}.sig`).toString('utf8').trim(),
      },
      'windows-x86_64': {
        url: assetUrl(release.tag_name, names.windows),
        signature: files.get(`${names.windows}.sig`).toString('utf8').trim(),
      },
    },
  };
}
export function monotonicManifest(candidate, current) {
  validateManifest(candidate);
  if (!current) return candidate;
  validateManifest(current);
  const comparison = compareBetaVersions(candidate.version, current.version);
  if (comparison < 0) throw new Error('Refusing beta manifest downgrade');
  if (comparison === 0) {
    if (JSON.stringify(candidate.platforms) !== JSON.stringify(current.platforms))
      throw new Error('An existing beta version cannot change its signed artifacts');
    return current;
  }
  return candidate;
}

export function validateManifest(manifest) {
  versionFromTag(`v${manifest?.version}`);
  if (
    typeof manifest.notes !== 'string' ||
    Buffer.byteLength(manifest.notes, 'utf8') > 64 * 1024 ||
    typeof manifest.pub_date !== 'string' ||
    !Number.isFinite(Date.parse(manifest.pub_date)) ||
    JSON.stringify(Object.keys(manifest.platforms ?? {}).sort()) !==
      JSON.stringify([...TARGETS].sort())
  )
    throw new Error('Invalid beta manifest shape');
  const names = payloadNames(manifest.version);
  for (const [target, name] of [
    ['darwin-aarch64', names.mac],
    ['windows-x86_64', names.windows],
  ]) {
    const platform = manifest.platforms[target];
    if (platform?.url !== assetUrl(`v${manifest.version}`, name))
      throw new Error('Invalid beta manifest platform URL');
    parseSignature(platform.signature);
  }
  return manifest;
}
