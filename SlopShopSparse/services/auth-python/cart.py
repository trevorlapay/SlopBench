"""Shopping-cart operations (pure business logic)."""
from typing import Dict

from models import LineItem, Product
from validators import clamp_quantity


class Cart:
    def __init__(self):
        self._items: Dict[int, LineItem] = {}

    def add(self, product: Product, quantity: int = 1) -> None:
        quantity = clamp_quantity(quantity)
        if product.id in self._items:
            existing = self._items[product.id]
            existing.quantity = clamp_quantity(existing.quantity + quantity)
        else:
            self._items[product.id] = LineItem(product=product, quantity=quantity)

    def remove(self, product_id: int) -> None:
        self._items.pop(product_id, None)

    def set_quantity(self, product_id: int, quantity: int) -> None:
        if product_id not in self._items:
            return
        if quantity <= 0:
            self.remove(product_id)
        else:
            self._items[product_id].quantity = clamp_quantity(quantity)

    def items(self):
        return list(self._items.values())

    def count(self) -> int:
        return sum(item.quantity for item in self._items.values())

    def subtotal_cents(self) -> int:
        return sum(item.subtotal_cents() for item in self._items.values())

    def is_empty(self) -> bool:
        return not self._items

    def clear(self) -> None:
        self._items.clear()

    def validate_stock(self) -> list:
        """Return line items that cannot currently be fulfilled."""
        return [item for item in self._items.values()
                if not item.product.can_fulfill(item.quantity)]
    def has(self, product_id: int) -> bool:
        """True when the cart already holds a line for this product."""
        return product_id in self._items

    def quantity_of(self, product_id: int) -> int:
        """Quantity currently held for a product, or zero when absent."""
        item = self._items.get(product_id)
        return item.quantity if item else 0

    def merge(self, other: "Cart") -> None:
        """Fold another cart into this one, respecting the quantity clamp."""
        for item in other.items():
            self.add(item.product, item.quantity)

    def heaviest_line(self):
        """Line with the largest subtotal, used by the free-shipping banner."""
        if not self._items:
            return None
        return max(self._items.values(), key=lambda item: item.subtotal_cents())

    def snapshot(self) -> dict:
        """Serialisable view of the cart for the session store."""
        return {
            "items": [
                {"product_id": pid, "quantity": item.quantity}
                for pid, item in sorted(self._items.items())
            ],
            "subtotal_cents": self.subtotal_cents(),
        }
