# app-connections-streams

Alpha 0.1.0-alpha.1; Apache-2.0. Not for production use.

Node 20+ reader for already-authorized binary response streams.

```js
import {readResponse} from "@categori/app-connections-streams";
const bytes = await readResponse(body, {maximum: 512 * 1024});
```

Buffer/Uint8Array chunks are copied and retained only within the caller's finite byte bound; nonbinary or overflowing chunks are rejected. The final Buffer temporarily duplicates retained bytes. Provider chunk allocation is outside this module's control. An optional synchronous `destroy()` runs on success or failure and retains ordinary-finally exception precedence. Response metadata is not integrity proof. SDKs, credentials, authorization, retries, Web ReadableStream handling and publication are outside this module.

Registry packages are not published by this source release. Node manifests retain `private: true` to guard against accidental npm publication. See the repository CI for offline test commands.
