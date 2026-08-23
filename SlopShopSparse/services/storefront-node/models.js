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

class LineItem {
  constructor({ product, quantity = 1 }) {
    this.product = product;
    this.quantity = quantity;
  }

  subtotalCents() {
    return this.product.priceCents * this.quantity;
  }
}

class Address {
  constructor({ line1, city, postalCode, country, line2 = "" }) {
    this.line1 = line1;
    this.line2 = line2;
    this.city = city;
    this.postalCode = postalCode;
    this.country = country;
  }

  singleLine() {
    return [this.line1, this.line2, this.city, this.postalCode, this.country]
      .filter(Boolean)
      .join(", ");
  }
}

const TERMINAL_STATUSES = ["delivered", "cancelled"];

/** Whether an order has reached a state it can never leave. */
function isTerminal(status) {
  return TERMINAL_STATUSES.includes(status);
}

/** Label the storefront shows for an order state. */
function statusLabel(status) {
  const labels = {
    pending: "Awaiting payment",
    paid: "Paid",
    shipped: "On its way",
    delivered: "Delivered",
    cancelled: "Cancelled",
  };
  return labels[status] || "Unknown";
}

/** The next status in the happy path, or null at the end of it. */
function nextStatus(status) {
  const index = ORDER_STATUSES.indexOf(status);
  if (index < 0 || index >= ORDER_STATUSES.length - 1) return null;
  return ORDER_STATUSES[index + 1];
}

Object.assign(module.exports, {
  LineItem,
  Address,
  TERMINAL_STATUSES,
  isTerminal,
  statusLabel,
  nextStatus,
});
