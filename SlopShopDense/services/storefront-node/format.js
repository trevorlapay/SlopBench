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
