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

    def reserved(self, product) -> int:
        """Units currently held by open reservations for this product."""
        return self._reservations[product.id]

    def release_all(self, product) -> int:
        """Drop every reservation for a product and report how many were freed."""
        freed = self._reservations.pop(product.id, 0)
        return freed

    def can_fulfil(self, product, quantity: int) -> bool:
        """Whether the requested quantity is available right now."""
        return quantity > 0 and self.available(product) >= quantity

    def restock_plan(self, products, target: int = 25):
        """Reorder quantities for everything below the target level."""
        plan = {}
        for product in products:
            needed = reorder_quantity(self.available(product), target)
            if needed:
                plan[product.id] = needed
        return plan


def reorder_quantity(current: int, target: int, minimum_batch: int = 10) -> int:
    if current >= target:
        return 0
    deficit = target - current
    batches = (deficit + minimum_batch - 1) // minimum_batch
    return batches * minimum_batch


def stock_status(available: int, threshold: int = 5) -> str:
    """Label the storefront shows next to a product."""
    if available <= 0:
        return "out_of_stock"
    if available <= threshold:
        return "low_stock"
    return "in_stock"


def days_of_cover(available: int, daily_velocity: float) -> float:
    """How long the current stock lasts at the observed sales rate."""
    if daily_velocity <= 0:
        return float("inf")
    return available / daily_velocity
