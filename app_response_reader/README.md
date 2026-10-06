# app-connections-response

Alpha 0.1.0a2; Apache-2.0. Not for production use.

Python 3.11+ standard-library reader for an already-authorized binary response body.

```python
from app_response_reader import read_response
payload = read_response(body, maximum=64 * 1024)
```

The caller supplies a finite byte limit and optional authoritative exact length/SHA-256 pins. The reader handles short reads, requests at most 64 KiB per read, rejects nonbinary or oversized bodies and always closes the body. Accumulation is bounded by the limit plus one byte; producing immutable bytes may temporarily duplicate the buffer. Transport and close exceptions retain their normal precedence. This reader performs no object selection, authentication, provider interpretation, retries or publication.

Registry packages are not published by this source release. Node manifests retain `private: true` to guard against accidental npm publication. See the repository CI for offline test commands.
