// Async, read-only Windows-style file access. A translated guest syscall bridge
// must explicitly suspend/resume around these promises; none is fabricated here.
export function normalizeAssetPath(name) {
  if (typeof name !== "string" || !name || /[:\0]/.test(name) || /^[\\/]/.test(name)) throw new Error("Asset path must be relative to the configured installation");
  const parts = [];
  for (const part of name.replaceAll("\\", "/").split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") {
      if (!parts.length) throw new Error("Asset path escapes the configured installation");
      parts.pop();
    } else {
      if (/[. ]$/.test(part) || /[\x00-\x1f]/.test(part)) throw new Error("Ambiguous Windows asset path");
      parts.push(part);
    }
  }
  if (!parts.length) throw new Error("An asset filename is required");
  return parts.join("/").toLowerCase();
}

export class ReadOnlyAssets {
  constructor(baseURL = "/assets/", {blockBytes = 256 * 1024, cacheBytes = 16 * 1024 * 1024} = {}) {
    if (!Number.isInteger(blockBytes) || blockBytes < 1 || blockBytes > 8 * 1024 * 1024 || !Number.isInteger(cacheBytes) || cacheBytes < blockBytes) throw new Error("Invalid bounded asset-cache dimensions");
    this.baseURL = baseURL.replace(/\/?$/, "/");
    this.blockBytes = blockBytes;
    this.cacheLimitBytes = cacheBytes;
    this.cache = new Map();
    this.cachedBytes = 0;
    this.peakCachedBytes = 0;
    this.bytesFetched = 0;
    this.nextHandle = 1;
    this.handles = new Map();
  }

  url(path) {return this.baseURL + path.split("/").map(encodeURIComponent).join("/");}

  async open(name) {
    const path = normalizeAssetPath(name);
    const response = await fetch(this.url(path), {method: "HEAD", cache: "no-store"});
    if (!response.ok) throw new Error(`Cannot open ${path}: HTTP ${response.status}`);
    const length = response.headers.get("Content-Length");
    const size = Number(length);
    if (length === null || !Number.isSafeInteger(size) || size < 0 || response.headers.get("Accept-Ranges") !== "bytes") throw new Error(`Invalid read-only asset metadata: ${path}`);
    const handle = this.nextHandle++;
    this.handles.set(handle, {path, size, position: 0});
    return {handle, size};
  }

  file(handle) {
    const file = this.handles.get(handle);
    if (!file) throw new Error(`Invalid asset handle ${handle}`);
    return file;
  }

  close(handle) {const file = this.file(handle); if (file.reading) throw new Error("Asset handle has a pending read"); this.handles.delete(handle);}

  seek(handle, offset, whence = 0) {
    const file = this.file(handle);
    if (file.reading) throw new Error("Asset handle has a pending read");
    if (![0, 1, 2].includes(whence) || !Number.isSafeInteger(offset)) throw new Error("Invalid asset seek");
    const position = (whence === 0 ? 0 : whence === 1 ? file.position : file.size) + offset;
    if (!Number.isSafeInteger(position) || position < 0) throw new Error("Asset seek is outside the supported range");
    file.position = position;
    return position;
  }

  async block(file, start) {
    const key = `${file.path}:${start}`;
    if (this.cache.has(key)) {
      const bytes = this.cache.get(key);
      this.cache.delete(key); this.cache.set(key, bytes);
      return bytes;
    }
    const end = Math.min(start + this.blockBytes, file.size);
    const response = await fetch(this.url(file.path), {headers: {Range: `bytes=${start}-${end - 1}`}, cache: "no-store"});
    if (response.status !== 206 || response.headers.get("Content-Range") !== `bytes ${start}-${end - 1}/${file.size}`) throw new Error(`Invalid or changed asset range: ${file.path} at ${start}`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length !== end - start) throw new Error(`Truncated asset range: ${file.path} at ${start}`);
    this.bytesFetched += bytes.length;
    while (this.cachedBytes + bytes.length > this.cacheLimitBytes && this.cache.size) {
      const oldest = this.cache.keys().next().value;
      this.cachedBytes -= this.cache.get(oldest).length;
      this.cache.delete(oldest);
    }
    // Concurrent duplicate fetches replace the same key without double-counting.
    if (this.cache.has(key)) this.cachedBytes -= this.cache.get(key).length;
    this.cache.set(key, bytes); this.cachedBytes += bytes.length;
    this.peakCachedBytes = Math.max(this.peakCachedBytes, this.cachedBytes);
    return bytes;
  }

  async read(handle, count) {
    const file = this.file(handle);
    if (file.reading) throw new Error("Asset handle has a pending read");
    if (!Number.isSafeInteger(count) || count < 0 || count > this.cacheLimitBytes) throw new Error("A single asset read must fit the bounded working set");
    const output = new Uint8Array(Math.max(0, Math.min(count, file.size - file.position)));
    file.reading = true;
    try {
      let written = 0;
      while (written < output.length) {
        const start = Math.floor(file.position / this.blockBytes) * this.blockBytes;
        const block = await this.block(file, start);
        const local = file.position - start;
        const take = Math.min(block.length - local, output.length - written);
        output.set(block.subarray(local, local + take), written);
        written += take; file.position += take;
      }
      return output;
    } finally {
      file.reading = false;
    }
  }

  measurements() {
    return {openHandles: this.handles.size, cachedBytes: this.cachedBytes, peakCachedBytes: this.peakCachedBytes, cacheLimitBytes: this.cacheLimitBytes, bytesFetched: this.bytesFetched};
  }
}
