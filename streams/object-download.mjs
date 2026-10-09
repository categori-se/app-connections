export async function downloadPrivateObject({manifest, request, assertCurrent, writable, maximumBytes = 64 * 1024 * 1024, cryptoImpl = globalThis.crypto}) {
  const pinned = structuredClone(manifest);
  const sameManifest = value => value && Object.keys(value).sort().join() === 'contentType,etag,schemaVersion,size,versionId' && Object.keys(pinned).every(key => value[key] === pinned[key]);
  if (!sameManifest(pinned) || pinned.schemaVersion !== 1 || !Number.isSafeInteger(pinned.size) || pinned.size < 0 || typeof pinned.etag !== 'string' || !pinned.etag ||
      pinned.versionId !== null && (typeof pinned.versionId !== 'string' || !pinned.versionId || pinned.versionId === 'null') || typeof pinned.contentType !== 'string' ||
      !Number.isSafeInteger(maximumBytes) || pinned.size > maximumBytes || typeof request !== 'function' || typeof assertCurrent !== 'function') throw Error('Invalid private object manifest or output capacity');
  const parts = [];
  try {
    assertCurrent();
    for (let offset = 0; offset < pinned.size;) {
      const length = Math.min(4 * 1024 * 1024, pinned.size - offset);
      const result = await request({manifest: pinned, offset, length}); assertCurrent();
      if (!sameManifest(result.manifest) || result.offset !== offset || result.length !== length || typeof result.base64 !== 'string' ||
          result.base64.length !== 4 * Math.ceil(length / 3) || typeof result.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(result.sha256)) throw Error('The private download manifest changed');
      const raw = atob(result.base64); if (raw.length !== length || btoa(raw) !== result.base64) throw Error('Invalid private download range');
      const bytes = Uint8Array.from(raw, char => char.charCodeAt(0));
      const actual = Array.from(new Uint8Array(await cryptoImpl.subtle.digest('SHA-256', bytes)), byte => byte.toString(16).padStart(2, '0')).join(''); assertCurrent();
      if (actual !== result.sha256) throw Error('Private download range integrity failed');
      if (writable) {await writable.write(bytes); bytes.fill(0); assertCurrent();} else parts.push(bytes);
      offset += length;
    }
    assertCurrent();
    if (writable) {await writable.close(); return null;}
    return new Blob(parts, {type: pinned.contentType});
  } catch (error) {
    for (const part of parts) part.fill(0);
    try {await writable?.abort?.(error);} catch {}
    throw error;
  }
}
