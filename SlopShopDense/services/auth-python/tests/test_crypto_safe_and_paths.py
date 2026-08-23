import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import crypto_safe  # noqa: E402


class TestCryptoSafe(unittest.TestCase):
    def test_hash_roundtrip(self):
        stored = crypto_safe.hash_password("correct horse")
        self.assertTrue(crypto_safe.verify_password("correct horse", stored))
        self.assertFalse(crypto_safe.verify_password("wrong", stored))

    def test_hashes_are_salted_uniquely(self):
        a = crypto_safe.hash_password("same")
        b = crypto_safe.hash_password("same")
        self.assertNotEqual(a, b)

    def test_token_length(self):
        self.assertTrue(len(crypto_safe.new_token(16)) >= 16)

    def test_signature_roundtrip(self):
        key = b"k" * 32
        sig = crypto_safe.sign(b"payload", key)
        self.assertTrue(crypto_safe.verify_signature(b"payload", sig, key))
        self.assertFalse(crypto_safe.verify_signature(b"tampered", sig, key))

    def test_verify_rejects_malformed(self):
        self.assertFalse(crypto_safe.verify_password("x", "not-a-valid-record"))


class TestReorder(unittest.TestCase):
    def test_reorder_quantity(self):
        from inventory import reorder_quantity
        self.assertEqual(reorder_quantity(3, 3), 0)
        self.assertEqual(reorder_quantity(0, 25, minimum_batch=10), 30)


if __name__ == "__main__":
    unittest.main()
