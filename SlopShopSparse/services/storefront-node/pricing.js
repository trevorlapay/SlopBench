"use strict";
// Cart pricing helpers (pure functions, no I/O).

const FREE_SHIPPING_THRESHOLD_CENTS = 5000;
const FLAT_SHIPPING_CENTS = 599;

const TAX_RATES = { CA: 7.25, NY: 8.875, TX: 6.25, WA: 6.5, OR: 0.0 };

function subtotal(lineItems) {
  return lineItems.reduce((sum, it) => sum + it.priceCents * it.quantity, 0);
}

function shippingCost(subtotalCents, expedited = false) {
  if (subtotalCents >= FREE_SHIPPING_THRESHOLD_CENTS && !expedited) {
    return 0;
  }
  return expedited ? FLAT_SHIPPING_CENTS * 2 : FLAT_SHIPPING_CENTS;
}

function discountAmount(subtotalCents, coupon) {
  if (!coupon) return 0;
  let raw = 0;
  if (coupon.kind === "percent") {
    raw = Math.round(subtotalCents * (coupon.value / 100));
  } else if (coupon.kind === "fixed") {
    raw = coupon.value;
  }
  return Math.min(raw, subtotalCents);
}

function taxAmount(taxableCents, state) {
  const rate = TAX_RATES[(state || "").toUpperCase()] || 0;
  return Math.round(taxableCents * (rate / 100));
}

function orderTotal(lineItems, { state = "CA", coupon = null, expedited = false } = {}) {
  const sub = subtotal(lineItems);
  const discount = discountAmount(sub, coupon);
  const taxable = sub - discount;
  const tax = taxAmount(taxable, state);
  const shipping = shippingCost(taxable, expedited);
  return { subtotal: sub, discount, tax, shipping, total: taxable + tax + shipping };
}

function formatCents(cents) {
  const sign = cents < 0 ? "-" : "";
  const abs = Math.abs(cents);
  const whole = Math.floor(abs / 100).toLocaleString("en-US");
  const frac = String(abs % 100).padStart(2, "0");
  return `${sign}$${whole}.${frac}`;
}

module.exports = {
  subtotal, shippingCost, discountAmount, taxAmount, orderTotal, formatCents,
  FREE_SHIPPING_THRESHOLD_CENTS, FLAT_SHIPPING_CENTS,
};

/** Whether this basket qualifies for free standard shipping. */
function isFreeShipping(subtotalCents, expedited = false) {
  return shippingCost(subtotalCents, expedited) === 0;
}

/** How much more the basket needs before shipping is free. */
function centsToFreeShipping(subtotalCents) {
  return Math.max(0, FREE_SHIPPING_THRESHOLD_CENTS - subtotalCents);
}

/** Tax rate for a state, defaulting to zero for anywhere unlisted. */
function effectiveRate(state) {
  return TAX_RATES[(state || "").toUpperCase()] || 0;
}

/** States with a non-zero rate, sorted for a stable settings display. */
function taxableStates() {
  return Object.keys(TAX_RATES)
    .filter((code) => TAX_RATES[code] > 0)
    .sort();
}

/** Split an amount into whole-cent shares that sum exactly to the input. */
function splitEvenly(cents, parts) {
  if (parts <= 0) throw new Error("parts must be positive");
  const base = Math.floor(cents / parts);
  const remainder = cents - base * parts;
  return Array.from({ length: parts }, (_v, i) => base + (i < remainder ? 1 : 0));
}

/** One-line rendering of an orderTotal breakdown for the confirmation email. */
function summarize(breakdown) {
  const parts = [`subtotal ${formatCents(breakdown.subtotal)}`];
  if (breakdown.discount) parts.push(`less ${formatCents(breakdown.discount)}`);
  parts.push(`tax ${formatCents(breakdown.tax)}`);
  parts.push(`shipping ${formatCents(breakdown.shipping)}`);
  return `${parts.join(", ")} = ${formatCents(breakdown.total)}`;
}

Object.assign(module.exports, {
  isFreeShipping,
  centsToFreeShipping,
  effectiveRate,
  taxableStates,
  splitEvenly,
  summarize,
});
