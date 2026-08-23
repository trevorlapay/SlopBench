"""Inventory and restock logic."""
from collections import defaultdict


class InventoryService:
    def __init__(self, repository):
        self._repo = repository
        self._reservations = defaultdict(int)

    def available(self, product) -> int:
        return max(0, product.stock - self._reservations[product.id])

    def reserve(self, product, quantity: int) -> bool:
        if quantity <= 0:
            return False
        if self.available(product) < quantity:
            return False
        self._reservations[product.id] += quantity
        return True

    def release(self, product, quantity: int) -> None:
        self._reservations[product.id] = max(0, self._reservations[product.id] - quantity)

    def commit(self, product, quantity: int) -> bool:
        if not self._repo.decrement_stock(product.id, quantity):
            return False
        self.release(product, quantity)
        return True

    def low_stock(self, products, threshold: int = 5):
        return [p for p in products if self.available(p) <= threshold]


def reorder_quantity(current: int, target: int, minimum_batch: int = 10) -> int:
    if current >= target:
        return 0
    deficit = target - current
    batches = (deficit + minimum_batch - 1) // minimum_batch
    return batches * minimum_batch
