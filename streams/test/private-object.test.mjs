import test from 'node:test';
import assert from 'node:assert/strict';
import {Readable} from 'node:stream';
import {webcrypto, createHash} from 'node:crypto';
import {createPrivateObjectReader} from '../private-object.mjs';
import {downloadPrivateObject} from '../object-download.mjs';

const bytes = Buffer.from('private original bytes');
function fixture() {
  let enabled = true, duringRead, calls = 0;
  const header = {ContentLength: bytes.length, ETag: '"original"', VersionId: 'pinned-version', ContentType: 'text/plain'};
  const reader = createPrivateObjectReader({resolve: async () => {if (!enabled) throw Object.assign(Error('Revoked'), {statusCode: 403}); return {bucket: 'private', key: 'owned/object', binding: ['account-a', 'workspace-a']};},
    fail(statusCode, message) {throw Object.assign(Error(message), {statusCode});}, head: async () => ({...header}),
    read: async (_, input) => {calls++; await duringRead?.(); return {...header, ContentLength: input.length,
      ContentRange: `bytes ${input.offset}-${input.offset + input.length - 1}/${bytes.length}`, Body: Readable.from([bytes.subarray(input.offset, input.offset + input.length)])};}});
  return {reader, header, revoke() {enabled = false;}, duringRead(fn) {duringRead = fn;}, calls: () => calls};
}
test('private selectors require current authority, pin provider versions and carry no GET URL', async () => {
  const f = fixture(), result = await f.reader.describe({}); assert.equal(result.url, undefined);
  const input = {manifest: result.manifest, offset: 0, length: bytes.length};
  assert.equal((await f.reader.chunk({}, input)).base64, bytes.toString('base64'));
  f.revoke(); await assert.rejects(f.reader.chunk({}, input), {statusCode: 403}); assert.equal(f.calls(), 1);
});
test('revocation, provider replacement and manifest target injection discard a buffered download', async t => {
  for (const mode of ['revoked', 'replaced', 'tampered']) await t.test(mode, async () => {
    const f = fixture(), {manifest} = await f.reader.describe({});
    if (mode === 'tampered') manifest.bucket = 'other';
    else f.duringRead(mode === 'revoked' ? f.revoke : () => {f.header.ETag = '"later"';});
    await assert.rejects(f.reader.chunk({}, {manifest, offset: 0, length: bytes.length}));
    assert.equal(f.calls(), mode === 'tampered' ? 0 : 1);
  });
});
test('large output stays bounded per request, verifies each range and closes its destination only on completion', async () => {
  const data = Buffer.alloc(4 * 1024 * 1024 + 1, 42), manifest = {schemaVersion: 1, size: data.length, etag: '"pinned"', versionId: null, contentType: 'application/octet-stream'};
  const writes = [], calls = []; let closed = false;
  await downloadPrivateObject({manifest, maximumBytes: 64 * 1024 ** 3, assertCurrent() {}, cryptoImpl: webcrypto,
    writable: {async write(bytes) {writes.push(Buffer.from(bytes));}, async close() {closed = true;}}, request: async input => {
      calls.push(input); const bytes = data.subarray(input.offset, input.offset + input.length);
      return {...input, sha256: createHash('sha256').update(bytes).digest('hex'), base64: bytes.toString('base64')};
    }});
  assert.equal(closed, true); assert.deepEqual(Buffer.concat(writes), data); assert.deepEqual(calls.map(input => input.length), [4194304, 1]);
});
test('a corrupt range or a changed session aborts an incomplete destination without committing it', async t => {
  for (const mode of ['corrupt', 'session']) await t.test(mode, async () => {
    let current = true, aborted = false, closed = false;
    const manifest = {schemaVersion: 1, size: bytes.length, etag: 'original', versionId: 'v', contentType: 'text/plain'};
    await assert.rejects(downloadPrivateObject({manifest, assertCurrent() {if (!current) throw Error('Sign-in changed');}, cryptoImpl: webcrypto,
      writable: {async write() {}, async close() {closed = true;}, async abort() {aborted = true;}}, request: async input => {
        if (mode === 'session') current = false;
        return {...input, sha256: 'a'.repeat(64), base64: bytes.toString('base64')};
      }}));
    assert.equal(aborted, true); assert.equal(closed, false);
  });
});
