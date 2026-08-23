"use strict";
// Display formatting helpers for the storefront UI layer.

function titleCase(s) {
  return String(s)
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join(" ");
}

function pluralize(count, singular, plural) {
  const word = count === 1 ? singular : plural || `${singular}s`;
  return `${count} ${word}`;
}

function truncate(text, length = 80) {
  const s = String(text);
  return s.length <= length ? s : `${s.slice(0, length - 1).trimEnd()}…`;
}

function slugify(text) {
  return String(text)
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function humanizeStatus(status) {
  return titleCase(String(status).replace(/_/g, " "));
}

function starRating(rating) {
  const n = Math.max(0, Math.min(5, Math.round(rating)));
  return "★".repeat(n) + "☆".repeat(5 - n);
}

module.exports = { titleCase, pluralize, truncate, slugify, humanizeStatus, starRating };

function formatCents(cents) {
  const n = Number(cents) || 0;
  const sign = n < 0 ? "-" : "";
  const abs = Math.abs(n);
  const whole = Math.floor(abs / 100).toLocaleString("en-US");
  return `${sign}$${whole}.${String(abs % 100).padStart(2, "0")}`;
}

function parseCents(text) {
  const cleaned = String(text == null ? "" : text).replace(/[$,\s]/g, "");
  if (cleaned === "" || Number.isNaN(Number(cleaned))) {
    throw new Error(`not an amount: ${text}`);
  }
  return Math.round(Number(cleaned) * 100);
}

function humanSize(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KiB`;
  return `${Math.round(n / (1024 * 1024))} MiB`;
}

function relativeTime(secondsAgo) {
  const s = Math.max(0, Number(secondsAgo) || 0);
  if (s < 60) return "just now";
  if (s < 3600) return `${pluralize(Math.floor(s / 60), "minute")} ago`;
  if (s < 86400) return `${pluralize(Math.floor(s / 3600), "hour")} ago`;
  return `${pluralize(Math.floor(s / 86400), "day")} ago`;
}

function ordinal(n) {
  const value = Math.abs(Math.trunc(Number(n) || 0));
  const tens = value % 100;
  if (tens >= 11 && tens <= 13) return `${n}th`;
  const suffixes = { 1: "st", 2: "nd", 3: "rd" };
  return `${n}${suffixes[value % 10] || "th"}`;
}

function addressLine(address) {
  const parts = [address.line1, address.line2, address.city, address.postalCode];
  return parts.filter((part) => part && String(part).trim()).join(", ");
}

Object.assign(module.exports, {
  formatCents,
  parseCents,
  humanSize,
  relativeTime,
  ordinal,
  addressLine,
});
