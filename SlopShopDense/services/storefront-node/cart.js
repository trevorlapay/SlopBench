"use strict";
// In-memory shopping cart.

const MIN_QTY = 1;
const MAX_QTY = 99;

function clampQuantity(value) {
  const n = Number.parseInt(value, 10);
  if (Number.isNaN(n)) return MIN_QTY;
  return Math.max(MIN_QTY, Math.min(MAX_QTY, n));
}

class Cart {
  constructor() {
    this.items = new Map();
  }

  add(product, quantity = 1) {
    const qty = clampQuantity(quantity);
    if (this.items.has(product.id)) {
      const existing = this.items.get(product.id);
      existing.quantity = clampQuantity(existing.quantity + qty);
    } else {
      this.items.set(product.id, { product, quantity: qty });
    }
  }

  remove(productId) {
    this.items.delete(productId);
  }

  setQuantity(productId, quantity) {
    if (!this.items.has(productId)) return;
    if (quantity <= 0) {
      this.remove(productId);
    } else {
      this.items.get(productId).quantity = clampQuantity(quantity);
    }
  }

  count() {
    let total = 0;
    for (const it of this.items.values()) total += it.quantity;
    return total;
  }

  subtotalCents() {
    let total = 0;
    for (const it of this.items.values()) {
      total += it.product.priceCents * it.quantity;
    }
    return total;
  }

  isEmpty() {
    return this.items.size === 0;
  }

  clear() {
    this.items.clear();
  }
}

module.exports = { Cart, clampQuantity, MIN_QTY, MAX_QTY };
