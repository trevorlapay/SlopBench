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

/** True when the cart already holds a line for this product. */
function has(cart, productId) {
  return cart.items.has(productId);
}

/** Quantity held for a product, or zero when the cart has no line for it. */
function quantityOf(cart, productId) {
  const line = cart.items.get(productId);
  return line ? line.quantity : 0;
}

/** Total for one line, in cents. */
function lineTotalCents(cart, productId) {
  const line = cart.items.get(productId);
  return line ? line.product.priceCents * line.quantity : 0;
}

/** Fold one cart into another, respecting the quantity clamp on every add. */
function merge(target, source) {
  for (const line of source.items.values()) {
    target.add(line.product, line.quantity);
  }
  return target;
}

/** The line with the largest subtotal, used by the free-shipping banner. */
function heaviestLine(cart) {
  let best = null;
  for (const line of cart.items.values()) {
    const total = line.product.priceCents * line.quantity;
    if (!best || total > best.total) best = { productId: line.product.id, total };
  }
  return best;
}

/** Lines that can no longer be fulfilled at their current quantity. */
function unfulfillable(cart) {
  const out = [];
  for (const line of cart.items.values()) {
    if (!line.product.canFulfill(line.quantity)) out.push(line);
  }
  return out;
}

/** Serialisable view of the cart for the session store. */
function snapshot(cart) {
  return {
    items: [...cart.items.values()].map((line) => ({
      productId: line.product.id,
      quantity: line.quantity,
    })),
    subtotalCents: cart.subtotalCents(),
  };
}

Object.assign(module.exports, {
  has,
  quantityOf,
  lineTotalCents,
  merge,
  heaviestLine,
  unfulfillable,
  snapshot,
});
