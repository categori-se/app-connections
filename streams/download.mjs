export const privateDownloadChunkBytes = 512 * 1024;

// Transport and access checks belong to the app. This reusable client never
// follows a provider URL or puts an authentication token into a download URL.
export async function readPrivateDownload({manifest, selector, request, assertCurrent = () => {}, maximumBytes,
  cryptoImpl = globalThis.crypto}) {
  const pinned = structuredClone(manifest), selected = structuredClone(selector);
  if (pinned.mediated !== true || !Number.isSafeInteger(pinned.size_bytes) || pinned.size_bytes < 1 || !Number.isSafeInteger(maximumBytes) ||
      pinned.size_bytes > maximumBytes || typeof pinned.version_id !== 'string' || !pinned.version_id || pinned.version_id === 'null' ||
      typeof pinned.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(pinned.sha256) || typeof request !== 'function') throw Error('Invalid private download manifest');
  const bytes = new Uint8Array(pinned.size_bytes);
  try {
    for (let offset = 0; offset < bytes.length;) {
      assertCurrent();
      const length = Math.min(privateDownloadChunkBytes, bytes.length - offset);
      const result = await request({...selected, version_id: pinned.version_id, sha256: pinned.sha256, size_bytes: bytes.length, offset, length});
      assertCurrent();
      if (result.version_id !== pinned.version_id || result.sha256 !== pinned.sha256 || result.size_bytes !== bytes.length || result.offset !== offset ||
          result.length !== length || typeof result.bytes_base64 !== 'string' || result.bytes_base64.length !== 4 * Math.ceil(length / 3) ||
          !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(result.bytes_base64)) throw Error('Private download range manifest changed');
      const raw = atob(result.bytes_base64);
      if (raw.length !== length || btoa(raw) !== result.bytes_base64) throw Error('Invalid private download bytes');
      for (let index = 0; index < length; index++) bytes[offset + index] = raw.charCodeAt(index);
      offset += length;
    }
    const digest = Array.from(new Uint8Array(await cryptoImpl.subtle.digest('SHA-256', bytes)), byte => byte.toString(16).padStart(2, '0')).join('');
    assertCurrent();
    if (digest !== pinned.sha256) throw Error('Private download bytes do not match their original SHA-256');
    return bytes;
  } catch (error) {bytes.fill(0); throw error;}
}
