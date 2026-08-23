"""Domain models for the SlopShop marketplace."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class OrderStatus(Enum):
    PENDING = "pending"
    PAID = "paid"
    SHIPPED = "shipped"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"


@dataclass
class Address:
    line1: str
    city: str
    postal_code: str
    country: str
    line2: str = ""

    def single_line(self) -> str:
        parts = [self.line1, self.line2, self.city, self.postal_code, self.country]
        return ", ".join(p for p in parts if p)


@dataclass
class Category:
    id: int
    name: str
    slug: str
    parent_id: Optional[int] = None

    def is_root(self) -> bool:
        return self.parent_id is None


@dataclass
class Product:
    id: int
    sku: str
    name: str
    price_cents: int
    category_id: int
    stock: int = 0
    active: bool = True
    tags: List[str] = field(default_factory=list)

    def in_stock(self) -> bool:
        return self.active and self.stock > 0

    def can_fulfill(self, quantity: int) -> bool:
        return self.in_stock() and quantity <= self.stock

    def price_dollars(self) -> float:
        return round(self.price_cents / 100.0, 2)


@dataclass
class LineItem:
    product: Product
    quantity: int

    def subtotal_cents(self) -> int:
        return self.product.price_cents * self.quantity


@dataclass
class User:
    id: int
    username: str
    email: str
    display_name: str = ""
    role: str = "customer"
    created_at: Optional[datetime] = None

    def is_admin(self) -> bool:
        return self.role == "admin"

    def label(self) -> str:
        return self.display_name or self.username


@dataclass
class Order:
    id: int
    user_id: int
    items: List[LineItem] = field(default_factory=list)
    status: OrderStatus = OrderStatus.PENDING
    shipping_address: Optional[Address] = None

    def item_count(self) -> int:
        return sum(item.quantity for item in self.items)

    def subtotal_cents(self) -> int:
        return sum(item.subtotal_cents() for item in self.items)

    def is_editable(self) -> bool:
        return self.status in (OrderStatus.PENDING,)


@dataclass
class Review:
    id: int
    product_id: int
    author: str
    rating: int
    body: str

    def is_valid_rating(self) -> bool:
        return 1 <= self.rating <= 5
@dataclass
class Coupon:
    code: str
    kind: str
    value: int
    active: bool = True

    def is_percentage(self) -> bool:
        return self.kind == "percent"

    def describe(self) -> str:
        if self.is_percentage():
            return "%d%% off" % self.value
        return "%d cents off" % self.value


@dataclass
class Shipment:
    id: int
    order_id: int
    carrier: str
    tracking: str = ""
    delivered_at: Optional[datetime] = None

    def is_delivered(self) -> bool:
        return self.delivered_at is not None

    def has_tracking(self) -> bool:
        return bool(self.tracking.strip())


@dataclass
class Refund:
    id: int
    order_id: int
    amount_cents: int
    reason: str = ""

    def is_partial(self, order: "Order") -> bool:
        return self.amount_cents < order.subtotal_cents()


def order_status_label(status: OrderStatus) -> str:
    """Human-readable label the storefront shows for an order state."""
    labels = {
        OrderStatus.PENDING: "Awaiting payment",
        OrderStatus.PAID: "Paid",
        OrderStatus.SHIPPED: "On its way",
        OrderStatus.DELIVERED: "Delivered",
        OrderStatus.CANCELLED: "Cancelled",
        OrderStatus.REFUNDED: "Refunded",
    }
    return labels.get(status, "Unknown")


def is_terminal(status: OrderStatus) -> bool:
    """True for states an order can never leave."""
    return status in (OrderStatus.DELIVERED, OrderStatus.CANCELLED, OrderStatus.REFUNDED)
