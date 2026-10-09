# App Connections bounded reads and private downloads

Apache-2.0 shared mechanisms; version `0.1.0-alpha.3`. GitHub source releases do not publish npm packages. Application policy, provider credentials, billing and hosted operators retain their own boundaries.

## Already-authorized Node streams

`readResponse(body, {maximum, limitError})` copies binary chunks, rejects nonbinary chunks and stops at the first overflow. It always calls the body's optional synchronous `destroy()`. The final buffer temporarily duplicates the retained chunks; the provider controls its own allocation. Metadata is not proof of bytes.

## Application-mediated objects

`createPrivateObjectReader` from `./private-object` accepts owning-app callbacks `resolve`, `head`, `read` and a throwing `fail(status, message)`. `resolve` must authenticate the current actor, authorize the resource and return a server-selected bucket/key and an authority binding. Browser input must never select provider addresses. Provider callbacks must enforce deadlines and select the manifest's version, ETag and exact Range.

`describe(context)` returns a bounded object manifest. `chunk(context, {manifest, offset, length})` re-resolves current permission, verifies provider metadata, reads at most 4 MiB, and rechecks current scope and object metadata before returning bytes. Each range carries SHA-256. Versioned objects are pinned to their version; unversioned objects use their ETag and final metadata check. The API supplies no transferable provider GET URL. App adapters must set private/no-store response headers.

`downloadPrivateObject` from `./object-download` fetches sequential ranges, checks the pinned manifest, exact lengths and chunk digests, and invokes `assertCurrent` around asynchronous work. It returns a Blob within its configured memory bound, or writes to a caller-owned abortable writable destination. Output is closed only after success and aborted on failure. The caller must provide its original-session lifecycle checks and authenticated requests. A per-range hash and object pin do not establish an independently recorded whole-file digest.

`readPrivateDownload` from `./download` supports the retained-object protocol with version ID, original size and recorded whole-file SHA-256. It uses at most 512 KiB per range, verifies the complete digest and clears partial bytes on failure.

Revocation denies later application reads, including a buffered range when the adapter observes revoked authority after reading it. There is a final-check/response race; delivered bytes cannot be recalled. Earlier provider URLs remain usable until their provider expiry or explicit provider policy invalidation. The owning app must convert every private delivery path before claiming complete coverage.

Run `node --test test/*.test.mjs` in this directory. Tests use synthetic providers and bytes.
