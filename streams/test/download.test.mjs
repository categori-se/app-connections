import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, webcrypto} from 'node:crypto';
import {readPrivateDownload} from '../download.mjs';

const source = Buffer.alloc(512 * 1024 + 7, 42);
const manifest = {mediated: true, version_id: 'original-version', sha256: createHash('sha256').update(source).digest('hex'), size_bytes: source.length};
const result = body => ({...body, bytes_base64: source.subarray(body.offset, body.offset + body.length).toString('base64')});
const options = {manifest, selector: {kind: 'document', artifact_id: 'd'}, maximumBytes: source.length, cryptoImpl: webcrypto};
test('a large private download uses bounded authenticated requests and verifies its complete hash', async () => {
  const calls = [];
  const bytes = await readPrivateDownload({...options, request: async body => {calls.push(body); return result(body);}});
  assert.deepEqual(Buffer.from(bytes), source); assert.deepEqual(calls.map(row => row.length), [524288, 7]);
});
test('a revoked continuation, changed session, altered version or corrupt range never returns partial bytes', async t => {
  for (const mode of ['revoke', 'session', 'version', 'corrupt']) await t.test(mode, async () => {
    let calls = 0, current = true;
    await assert.rejects(readPrivateDownload({...options, assertCurrent() {if (!current) throw Error('Session changed');}, request: async body => {
      calls++;
      if (mode === 'session') current = false;
      if (mode === 'revoke' && calls === 2) throw Object.assign(Error('Revoked'), {status: 403});
      const response = result(body);
      if (mode === 'version') response.version_id = 'other';
      if (mode === 'corrupt') response.bytes_base64 = Buffer.alloc(body.length, 0).toString('base64');
      return response;
    }}));
  });
});
