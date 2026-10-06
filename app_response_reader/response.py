"""Read an already-authorized binary body with a caller-owned finite policy."""

import hashlib
import re
import sys

_CHUNK_BYTES = 64 * 1024
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")


class ResponseError(ValueError):
    """The response does not satisfy the caller's explicit read policy."""


class ResponsePolicyError(ResponseError):
    """The caller did not provide a valid finite read or verification policy."""


class ResponseLimitError(ResponseError):
    """The complete response exceeds the caller's byte limit."""


class ResponseLengthError(ResponseError):
    """The complete response differs from the supplied exact length."""


class ResponseDigestError(ResponseError):
    """The complete response differs from the supplied exact SHA-256."""


def read_response(body, *, maximum, expected_length=None, expected_sha256=None):
    """Return complete bytes, closing ``body`` on success and every failure.

    ``read(size)`` must return bytes and may return fewer than requested. Only an
    empty result means EOF. Read at most ``maximum + 1`` bytes, in requests of at
    most 64 KiB; the extra byte distinguishes exact-capacity data from overflow.
    The accumulated buffer never exceeds that bound. The final bytes conversion
    can temporarily retain both the buffer and the returned complete value.

    Length and digest checks apply only when explicitly supplied by the caller.
    This function does not select objects, interpret permissions, trust response
    metadata, parse JSON, retry requests or manufacture provenance evidence.
    Read and close exceptions propagate; as with a normal finally-close, a close
    exception takes precedence if closing also fails during another exception.
    """
    try:
        if type(maximum) is not int or not 0 <= maximum < sys.maxsize:
            raise ResponsePolicyError("A finite nonnegative byte limit is required")
        if (expected_length is not None
            and (type(expected_length) is not int or not 0 <= expected_length <= maximum)):
            raise ResponsePolicyError("Expected length must fit the explicit byte limit")
        if (expected_sha256 is not None
            and (not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256))):
            raise ResponsePolicyError("Expected SHA-256 must be 64 lowercase hexadecimal characters")
        contents = bytearray()
        digest = hashlib.sha256() if expected_sha256 is not None else None
        while True:
            requested = min(_CHUNK_BYTES, maximum + 1 - len(contents))
            chunk = body.read(requested)
            if not isinstance(chunk, bytes):
                raise ResponseError("Binary response read must return bytes")
            if len(chunk) > requested:
                raise ResponseError("Binary response returned more bytes than requested")
            if not chunk:
                break
            contents.extend(chunk)
            if len(contents) > maximum:
                raise ResponseLimitError("Response exceeds its explicit byte limit")
            if digest is not None:
                digest.update(chunk)
        if expected_length is not None and len(contents) != expected_length:
            raise ResponseLengthError("Response differs from its expected exact length")
        if digest is not None and digest.hexdigest() != expected_sha256:
            raise ResponseDigestError("Response differs from its expected exact SHA-256")
        return bytes(contents)
    finally:
        body.close()
