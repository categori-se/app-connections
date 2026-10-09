import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {readResponse} from './index.mjs';

export const privateObjectChunkBytes = 4 * 1024 * 1024;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
// The owning app resolves and authorizes its own resource on every invocation.
// Provider addresses never come from a browser-selected manifest.
export function createPrivateObjectReader({resolve, head, read, fail, maximumBytes = 64 * 1024 ** 3}) {
  const descriptor = result => {
    if (!Number.isSafeInteger(result.ContentLength) || result.ContentLength < 0 || result.ContentLength > maximumBytes || typeof result.ETag !== 'string' ||
        !result.ETag || result.ETag.length > 500 || /[\x00-\x1f\x7f]/.test(result.ETag) || result.VersionId !== undefined && (typeof result.VersionId !== 'string' || !result.VersionId || result.VersionId.length > 2048 || /[\x00-\x1f\x7f]/.test(result.VersionId))) fail(409, 'A bounded private object manifest could not be verified.');
    return {schemaVersion: 1, size: result.ContentLength, etag: result.ETag, versionId: result.VersionId && result.VersionId !== 'null' ? result.VersionId : null,
      contentType: result.ContentType || 'application/octet-stream'};
  };
  const binding = target => [target.bucket, target.key, target.binding ?? null];
  return {
    async describe(context) {
      const target = await resolve(context);
      try {
        const manifest = descriptor(await head(target));
        const current = await resolve(context);
        try {if (!isDeepStrictEqual(binding(current), binding(target))) fail(409, 'The private download scope changed.');} finally {current.destroy?.();}
        return {mediated: true, manifest};
      } finally {target.destroy?.();}
    },
    async chunk(context, input) {
      if (!input || Object.keys(input).sort().join() !== 'length,manifest,offset' || !Number.isSafeInteger(input.offset) || input.offset < 0 ||
          !Number.isSafeInteger(input.length) || input.length < 1 || input.length > privateObjectChunkBytes) fail(400, 'Supply an exact bounded private download range.');
      const target = await resolve(context); let object;
      try {
        const manifest = descriptor(await head(target));
        if (!isDeepStrictEqual(manifest, input.manifest) || input.offset + input.length > manifest.size) fail(409, 'The private object manifest changed.');
        object = await read(target, {manifest, offset: input.offset, length: input.length});
        if (object.ETag !== manifest.etag || manifest.versionId !== null && object.VersionId !== manifest.versionId || object.ContentLength !== input.length ||
            object.ContentRange !== `bytes ${input.offset}-${input.offset + input.length - 1}/${manifest.size}`) fail(409, 'The provider returned a different private object range.');
        const bytes = await readResponse(object.Body, {maximum: input.length});
        if (bytes.length !== input.length) fail(409, 'The private object range is incomplete.');
        const current = await resolve(context);
        try {
          if (!isDeepStrictEqual(binding(current), binding(target)) || !isDeepStrictEqual(descriptor(await head(current)), manifest)) fail(409, 'The private object or access scope changed during reading.');
        } finally {current.destroy?.();}
        return {manifest, offset: input.offset, length: input.length, sha256: hash(bytes), base64: bytes.toString('base64')};
      } finally {object?.Body?.destroy?.(); target.destroy?.();}
    }
  };
}
