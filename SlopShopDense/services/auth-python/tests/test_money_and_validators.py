import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from money import Money, format_money, split_evenly, apply_percentage  # noqa: E402
import validators  # noqa: E402
from pagination import paginate, normalize_page_args  # noqa: E402


class TestMoney(unittest.TestCase):
    def test_from_dollars(self):
        self.assertEqual(Money.from_dollars("19.99").cents, 1999)

    def test_add_sub(self):
        self.assertEqual((Money(100) + Money(50)).cents, 150)
        self.assertEqual((Money(100) - Money(30)).cents, 70)

    def test_format(self):
        self.assertEqual(format_money(123456), "$1,234.56")
        self.assertEqual(format_money(-99), "-$0.99")

    def test_split_evenly_sums(self):
        parts = split_evenly(1000, 3)
        self.assertEqual(sum(parts), 1000)
        self.assertEqual(parts, [334, 333, 333])

    def test_apply_percentage(self):
        self.assertEqual(apply_percentage(10000, 8.875), 888)


class TestValidators(unittest.TestCase):
    def test_email(self):
        self.assertTrue(validators.is_email("a.b+c@example.co.uk"))
        self.assertFalse(validators.is_email("not-an-email"))

    def test_slug(self):
        self.assertTrue(validators.is_slug("great-product-1"))
        self.assertFalse(validators.is_slug("Bad Slug"))

    def test_sku(self):
        self.assertTrue(validators.is_sku("AB-1234"))
        self.assertFalse(validators.is_sku("abc"))

    def test_clamp_quantity(self):
        self.assertEqual(validators.clamp_quantity(0), 1)
        self.assertEqual(validators.clamp_quantity(500), 99)
        self.assertEqual(validators.clamp_quantity("junk"), 1)

    def test_normalize_username_rejects_bad(self):
        self.assertEqual(validators.normalize_username("  JDoe_1 "), "jdoe_1")
        with self.assertRaises(ValueError):
            validators.normalize_username("a")

    def test_require_fields(self):
        with self.assertRaises(ValueError):
            validators.require_fields({"a": 1}, ["a", "b"])


class TestPagination(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_page_args("junk", "junk"), (1, 20))
        self.assertEqual(normalize_page_args(3, 5000), (3, 100))

    def test_paginate(self):
        page = paginate(list(range(0, 55)), 2, 20)
        self.assertEqual(page.items, list(range(20, 40)))
        self.assertEqual(page.pages, 3)
        self.assertTrue(page.has_next and page.has_prev)


if __name__ == "__main__":
    unittest.main()
