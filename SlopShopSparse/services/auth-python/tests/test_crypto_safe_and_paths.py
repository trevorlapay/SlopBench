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
class TestRehash(unittest.TestCase):
    def test_needs_rehash_for_weaker_record(self):
        weak = "aa$bb$1000"
        self.assertTrue(crypto_safe.needs_rehash(weak))

    def test_current_record_does_not_need_rehash(self):
        stored = crypto_safe.hash_password("passphrase")
        self.assertFalse(crypto_safe.needs_rehash(stored))

    def test_malformed_record_needs_rehash(self):
        self.assertTrue(crypto_safe.needs_rehash("garbage"))

    def test_rotate_requires_a_matching_password(self):
        stored = crypto_safe.hash_password("passphrase")
        with self.assertRaises(ValueError):
            crypto_safe.rotate_hash("wrong", stored)


class TestSubkeys(unittest.TestCase):
    def test_purposes_produce_distinct_subkeys(self):
        master = b"m" * 32
        a = crypto_safe.derive_subkey(master, b"sessions")
        b = crypto_safe.derive_subkey(master, b"receipts")
        self.assertNotEqual(a, b)

    def test_subkey_is_deterministic(self):
        master = b"m" * 32
        self.assertEqual(
            crypto_safe.derive_subkey(master, b"sessions"),
            crypto_safe.derive_subkey(master, b"sessions"),
        )

    def test_salts_differ_between_calls(self):
        self.assertNotEqual(crypto_safe.random_salt(), crypto_safe.random_salt())


class TestStockStatus(unittest.TestCase):
    def test_labels(self):
        from inventory import stock_status
        self.assertEqual(stock_status(0), "out_of_stock")
        self.assertEqual(stock_status(3), "low_stock")
        self.assertEqual(stock_status(50), "in_stock")


if __name__ == "__main__":
    unittest.main()
