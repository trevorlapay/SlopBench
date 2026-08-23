"use strict";
// Domain models for the storefront.

class Product {
  constructor({ id, sku, name, priceCents, categoryId, stock = 0, active = true }) {
    this.id = id;
    this.sku = sku;
    this.name = name;
    this.priceCents = priceCents;
    this.categoryId = categoryId;
    this.stock = stock;
    this.active = active;
  }

  inStock() {
    return this.active && this.stock > 0;
  }

  canFulfill(quantity) {
    return this.inStock() && quantity <= this.stock;
  }

  priceDollars() {
    return Math.round(this.priceCents) / 100;
  }
}

const ORDER_STATUSES = ["pending", "paid", "shipped", "delivered", "cancelled"];

class Order {
  constructor({ id, userId, items = [], status = "pending" }) {
    this.id = id;
    this.userId = userId;
    this.items = items;
    this.status = status;
  }

  itemCount() {
    return this.items.reduce((n, it) => n + it.quantity, 0);
  }

  subtotalCents() {
    return this.items.reduce((n, it) => n + it.product.priceCents * it.quantity, 0);
  }

  isEditable() {
    return this.status === "pending";
  }
}

function paginate(items, page, size) {
  const p = Math.max(1, Number.parseInt(page, 10) || 1);
  const s = Math.max(1, Math.min(100, Number.parseInt(size, 10) || 20));
  const start = (p - 1) * s;
  return {
    items: items.slice(start, start + s),
    page: p,
    size: s,
    total: items.length,
    pages: Math.ceil(items.length / s),
  };
}

module.exports = { Product, Order, ORDER_STATUSES, paginate };
