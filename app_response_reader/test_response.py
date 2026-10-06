"""Provider-free read policy and resource lifetime regressions."""
import hashlib
import io
import sys
import unittest

try:
    from .response import (
        ResponseDigestError, ResponseError, ResponseLengthError,
        ResponseLimitError, ResponsePolicyError, read_response,
    )
except ImportError:
    from response import (
        ResponseDigestError, ResponseError, ResponseLengthError,
        ResponseLimitError, ResponsePolicyError, read_response,
    )


class Body(io.BytesIO):
    def __init__(self, data, short=3):
        super().__init__(data)
        self.short = short
        self.requests = []
        self.close_count = 0

    def read(self, size):
        self.requests.append(size)
        return super().read(min(size, self.short))

    def close(self):
        self.close_count += 1
        super().close()


class ResponseTests(unittest.TestCase):
    def test_short_reads_are_complete_with_exact_supplied_pins(self):
        payload = b"{\"complete\":true}\n"
        body = Body(payload)
        self.assertEqual(read_response(body, maximum=len(payload), expected_length=len(payload),
            expected_sha256=hashlib.sha256(payload).hexdigest()), payload)
        self.assertGreater(len(body.requests), 2)
        self.assertTrue(all(0 < n <= 64 * 1024 for n in body.requests))
        self.assertEqual(body.close_count, 1)

    def test_no_pin_is_inferred_from_body_metadata(self):
        body = Body(b"unverified", short=100)
        body.content_length = 0
        body.checksum_sha256 = "a" * 64
        self.assertEqual(read_response(body, maximum=20), b"unverified")
        self.assertTrue(body.closed)

    def test_zero_capacity_and_empty_response(self):
        body = Body(b"")
        self.assertEqual(read_response(body, maximum=0, expected_length=0), b"")
        self.assertEqual(body.requests, [1])
        self.assertTrue(body.closed)

    def test_overflow_reads_only_first_extra_byte_and_closes(self):
        body = Body(b"x" * 100_000, short=100_000)
        with self.assertRaises(ResponseLimitError):
            read_response(body, maximum=70_000)
        self.assertEqual(body.requests, [65_536, 4_465])
        self.assertEqual(body.close_count, 1)

    def test_exact_limit_requires_a_final_eof_probe(self):
        body = Body(b"abcd", short=100)
        self.assertEqual(read_response(body, maximum=4), b"abcd")
        self.assertEqual(body.requests, [5, 1])

    def test_invalid_policies_close_without_read(self):
        for fields in ({"maximum": True}, {"maximum": -1}, {"maximum": None},
            {"maximum": float("inf")}, {"maximum": sys.maxsize},
            {"maximum": 3, "expected_length": True}, {"maximum": 3, "expected_length": 4},
            {"maximum": 3, "expected_sha256": "A" * 64},
            {"maximum": 3, "expected_sha256": 1}):
            with self.subTest(fields=fields):
                body = Body(b"abc")
                with self.assertRaises(ResponsePolicyError):
                    read_response(body, **fields)
                self.assertEqual(body.requests, [])
                self.assertEqual(body.close_count, 1)

    def test_supplied_exact_length_mismatch_closes(self):
        for length in (1, 3):
            with self.subTest(length=length):
                body = Body(b"ab")
                with self.assertRaises(ResponseLengthError):
                    read_response(body, maximum=3, expected_length=length)
                self.assertTrue(body.closed)

    def test_supplied_exact_digest_mismatch_closes(self):
        body = Body(b"ab")
        with self.assertRaises(ResponseDigestError):
            read_response(body, maximum=3, expected_sha256="0" * 64)
        self.assertTrue(body.closed)

    def test_read_failure_propagates_and_closes(self):
        body = Body(b"ab")
        def fail(_size):
            raise OSError("transport interrupted")
        body.read = fail
        with self.assertRaisesRegex(OSError, "transport interrupted"):
            read_response(body, maximum=3)
        self.assertEqual(body.close_count, 1)

    def test_invalid_binary_contract_closes(self):
        for returned in (None, "abc", b"toolong"):
            with self.subTest(returned=returned):
                body = Body(b"")
                body.read = lambda _size: returned
                with self.assertRaises(ResponseError):
                    read_response(body, maximum=3)
                self.assertEqual(body.close_count, 1)

    def test_close_failure_keeps_normal_finally_precedence(self):
        body = Body(b"abc")
        def fail_close():
            raise OSError("close failed")
        body.close = fail_close
        with self.assertRaisesRegex(OSError, "close failed"):
            read_response(body, maximum=2)
        io.BytesIO.close(body)


if __name__ == "__main__":
    unittest.main()
