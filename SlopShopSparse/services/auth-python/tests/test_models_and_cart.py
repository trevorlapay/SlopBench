import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import Product, User, Order, OrderStatus, Address, Review  # noqa: E402
from cart import Cart  # noqa: E402


def make_product(pid=1, price=1000, stock=10, active=True):
    return Product(id=pid, sku="AB-1234", name="Thing", price_cents=price,
                   category_id=1, stock=stock, active=active)


class TestModels(unittest.TestCase):
    def test_product_in_stock(self):
        self.assertTrue(make_product().in_stock())
        self.assertFalse(make_product(stock=0).in_stock())
        self.assertFalse(make_product(active=False).in_stock())

    def test_can_fulfill(self):
        p = make_product(stock=3)
        self.assertTrue(p.can_fulfill(3))
        self.assertFalse(p.can_fulfill(4))

    def test_price_dollars(self):
        self.assertEqual(make_product(price=1599).price_dollars(), 15.99)

    def test_user_label_falls_back_to_username(self):
        self.assertEqual(User(1, "jdoe", "j@x.com").label(), "jdoe")
        self.assertEqual(User(1, "jdoe", "j@x.com", display_name="Jane").label(), "Jane")

    def test_order_totals(self):
        order = Order(id=1, user_id=1)
        self.assertEqual(order.item_count(), 0)
        self.assertTrue(order.is_editable())

    def test_address_single_line(self):
        addr = Address(line1="1 Main St", city="Springfield", postal_code="00001",
                       country="US")
        self.assertIn("Springfield", addr.single_line())

    def test_review_rating_bounds(self):
        self.assertTrue(Review(1, 1, "a", 5, "great").is_valid_rating())
        self.assertFalse(Review(1, 1, "a", 6, "too high").is_valid_rating())


class TestCart(unittest.TestCase):
    def test_add_and_count(self):
        cart = Cart()
        cart.add(make_product(pid=1), 2)
        cart.add(make_product(pid=2), 1)
        self.assertEqual(cart.count(), 3)

    def test_add_same_product_accumulates(self):
        cart = Cart()
        cart.add(make_product(pid=1), 1)
        cart.add(make_product(pid=1), 2)
        self.assertEqual(cart.count(), 3)

    def test_set_quantity_zero_removes(self):
        cart = Cart()
        cart.add(make_product(pid=1), 2)
        cart.set_quantity(1, 0)
        self.assertTrue(cart.is_empty())

    def test_subtotal(self):
        cart = Cart()
        cart.add(make_product(pid=1, price=500), 2)
        self.assertEqual(cart.subtotal_cents(), 1000)

    def test_validate_stock_flags_shortfalls(self):
        cart = Cart()
        cart.add(make_product(pid=1, stock=1), 1)
        cart.set_quantity(1, 5)
        self.assertEqual(len(cart.validate_stock()), 1)
class TestCartExtras(unittest.TestCase):
    def test_quantity_of_missing_product_is_zero(self):
        cart = Cart()
        self.assertEqual(cart.quantity_of(99), 0)

    def test_has_reports_membership(self):
        cart = Cart()
        cart.add(make_product(pid=7), 1)
        self.assertTrue(cart.has(7))
        self.assertFalse(cart.has(8))

    def test_merge_accumulates_quantities(self):
        first, second = Cart(), Cart()
        first.add(make_product(pid=1), 1)
        second.add(make_product(pid=1), 2)
        first.merge(second)
        self.assertEqual(first.quantity_of(1), 3)

    def test_heaviest_line_picks_largest_subtotal(self):
        cart = Cart()
        cart.add(make_product(pid=1, price=100), 1)
        cart.add(make_product(pid=2, price=900), 1)
        self.assertEqual(cart.heaviest_line().product.id, 2)

    def test_snapshot_reports_subtotal(self):
        cart = Cart()
        cart.add(make_product(pid=1, price=250), 2)
        self.assertEqual(cart.snapshot()["subtotal_cents"], 500)


class TestOrderStatusHelpers(unittest.TestCase):
    def test_labels_exist_for_every_state(self):
        from models import order_status_label

        for status in OrderStatus:
            self.assertTrue(order_status_label(status))

    def test_terminal_states(self):
        from models import is_terminal

        self.assertTrue(is_terminal(OrderStatus.DELIVERED))
        self.assertFalse(is_terminal(OrderStatus.PENDING))


if __name__ == "__main__":
    unittest.main()
