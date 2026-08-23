import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import Product, LineItem  # noqa: E402
import pricing  # noqa: E402


class Coupon:
    def __init__(self, kind, value):
        self.kind = kind
        self.value = value


def widget(price_cents, qty):
    p = Product(id=1, sku="AB-1234", name="Widget", price_cents=price_cents,
                category_id=1, stock=100)
    return LineItem(product=p, quantity=qty)


class TestPricing(unittest.TestCase):
    def test_subtotal(self):
        items = [widget(1000, 2), widget(250, 4)]
        self.assertEqual(pricing.subtotal(items), 3000)

    def test_free_shipping_over_threshold(self):
        self.assertEqual(pricing.shipping_cost(6000), 0)

    def test_flat_shipping_under_threshold(self):
        self.assertEqual(pricing.shipping_cost(4000), pricing.FLAT_SHIPPING_CENTS)

    def test_expedited_never_free(self):
        self.assertEqual(pricing.shipping_cost(9999, expedited=True),
                         pricing.FLAT_SHIPPING_CENTS * 2)

    def test_percent_discount(self):
        self.assertEqual(pricing.discount_amount(10000, Coupon("percent", 10)), 1000)

    def test_fixed_discount_capped_at_subtotal(self):
        self.assertEqual(pricing.discount_amount(500, Coupon("fixed", 800)), 500)

    def test_tax_by_state(self):
        self.assertEqual(pricing.tax_amount(10000, "OR"), 0)
        self.assertTrue(pricing.tax_amount(10000, "CA") > 0)

    def test_total_breakdown_sums(self):
        items = [widget(2000, 1)]
        result = pricing.total(items, state="CA")
        self.assertEqual(
            result["total"],
            result["subtotal"] - result["discount"] + result["tax"] + result["shipping"],
        )
class TestPricingExtras(unittest.TestCase):
    def test_free_shipping_predicate(self):
        self.assertTrue(pricing.is_free_shipping(6000))
        self.assertFalse(pricing.is_free_shipping(100))

    def test_cents_to_free_shipping(self):
        remaining = pricing.cents_to_free_shipping(4000)
        self.assertEqual(remaining, pricing.FREE_SHIPPING_THRESHOLD_CENTS - 4000)

    def test_cents_to_free_shipping_never_negative(self):
        self.assertEqual(pricing.cents_to_free_shipping(999999), 0)

    def test_effective_rate_defaults_to_zero(self):
        self.assertEqual(pricing.effective_rate("ZZ"), 0.0)

    def test_taxable_states_excludes_zero_rate(self):
        self.assertNotIn("OR", pricing.taxable_states())

    def test_summarize_includes_total(self):
        breakdown = pricing.total([widget(2000, 1)], state="CA")
        self.assertIn(str(breakdown["total"]), pricing.summarize(breakdown))


if __name__ == "__main__":
    unittest.main()
