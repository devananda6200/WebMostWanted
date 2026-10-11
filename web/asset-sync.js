// Runs in a dedicated worker. Memory use is bounded by the manifest chunk size.
const HEX = /^[a-f0-9]{64}$/;
const PIN = '80774c2e5d619b4f120b48d4462896fd504c263399d203a238769cffde1d253c';

export function validateManifest(m) {
  if (m.schema !== 1 || !HEX.test(m.version) || m.executable_sha256 !== PIN ||
      m.chunk_bytes !== 4 * 1024 * 1024 || !Array.isArray(m.files)) throw Error('Unsupported manifest');
  const names = new Set();
  let total = 0;
  for (const f of m.files) {
    if (typeof f.path !== 'string' || /[\\:\x00]/.test(f.path) ||
        f.path.split('/').some(p => !p || p === '.' || p === '..')) throw Error('Unsafe asset path');
    const key = f.path.toLowerCase();
    if (names.has(key)) throw Error('Case-insensitive path collision');
    names.add(key);
    if (!Number.isSafeInteger(f.size) || f.size < 0 || !HEX.test(f.sha256) ||
        !Array.isArray(f.chunks) || f.chunks.length !== Math.ceil(f.size / m.chunk_bytes) ||
        f.chunks.some(c => !HEX.test(c))) throw Error('Invalid asset checksums');
    total += f.size;
  }
  if (!Number.isSafeInteger(total) || total !== m.total_bytes ||
      !m.files.some(f => f.path === 'speed.exe' && f.sha256 === PIN)) throw Error('Invalid game identity');
  return m;
}

async function digest(bytes) {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(hash, n => n.toString(16).padStart(2, '0')).join('');
}

async function directory(root, parts) {
  for (const part of parts) root = await root.getDirectoryHandle(part, {create: true});
  return root;
}

async function fetchChunk(url, start, length, file) {
  const response = await fetch(url, {headers: {
    Range: `bytes=${start}-${start + length - 1}`, 'If-Range': `"${file.sha256}"`
  }, cache: 'no-store'});
  const expectedRange = `bytes ${start}-${start + length - 1}/${file.size}`;
  if (response.status !== 206 || response.headers.get('Content-Range') !== expectedRange) {
    await response.body?.cancel();
    throw Error(`Range delivery failed for ${file.path}: HTTP ${response.status}`);
  }
  const bytes = new Uint8Array(length);
  const reader = response.body.getReader();
  let used = 0;
  try {
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      if (used + value.length > length) throw Error('Oversized asset response');
      bytes.set(value, used);
      used += value.length;
    }
  } finally {
    await reader.cancel();
  }
  if (used !== length) throw Error(`Truncated asset response: ${file.path}`);
  return bytes;
}

export async function syncAssets({manifestUrl = '/asset-manifest.json', gamePath = ['nfsmw', 'game'], report = () => {}} = {}) {
  const url = new URL(manifestUrl, self.location.href);
  if (url.origin !== self.location.origin) throw Error('Asset delivery must use this private origin');
  if (!Array.isArray(gamePath) || !gamePath.length || gamePath.some(p => !/^[a-zA-Z0-9_-]+$/.test(p))) throw Error('Invalid storage path');
  return navigator.locks.request('nfsmw-private-asset-sync', async () => {
    const response = await fetch(url, {cache: 'no-store'});
    if (!response.ok) throw Error(`Manifest: HTTP ${response.status}`);
    const manifest = validateManifest(await response.json());
    const game = await directory(await navigator.storage.getDirectory(), gamePath);
    let verified = 0, downloaded = 0, cached = 0;
    const progress = path => report({type: 'progress', path, verified, downloaded, cached, total: manifest.total_bytes});
    for (const file of manifest.files) {
      const parts = file.path.split('/');
      const name = parts.pop();
      const parent = await directory(game, parts);
      const handle = await (await parent.getFileHandle(name, {create: true})).createSyncAccessHandle();
      try {
        for (let index = 0; index < file.chunks.length; index++) {
          const start = index * manifest.chunk_bytes;
          const length = Math.min(manifest.chunk_bytes, file.size - start);
          let valid = false;
          if (handle.getSize() >= start + length) {
            const bytes = new Uint8Array(length);
            valid = handle.read(bytes, {at: start}) === length && await digest(bytes) === file.chunks[index];
          }
          if (valid) cached += length;
          else {
            // Retain only the verified prefix; a failed fetch resumes here.
            handle.truncate(start);
            const assetUrl = new URL(`/assets/${manifest.version}/${file.path.split('/').map(encodeURIComponent).join('/')}`, url);
            const bytes = await fetchChunk(assetUrl, start, length, file);
            if (await digest(bytes) !== file.chunks[index]) throw Error(`Checksum mismatch: ${file.path}, chunk ${index}`);
            let written = 0;
            while (written < bytes.length) {
              const count = handle.write(bytes.subarray(written), {at: start + written});
              if (!count) throw Error(`Storage write failed: ${file.path}`);
              written += count;
            }
            handle.flush();
            downloaded += length;
          }
          verified += length;
          progress(file.path);
        }
        handle.truncate(file.size);
        handle.flush();
      } finally {
        handle.close();
      }
    }
    const result = {type: 'complete', version: manifest.version, files: manifest.files.length, verified, downloaded, cached};
    report(result);
    return result;
  });
}
