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
