"use strict";
// Input validation and safe HTML escaping.

const EMAIL_RE = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,}$/;
const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const SKU_RE = /^[A-Z]{2,4}-[0-9]{4,8}$/;

function isEmail(v) {
  return EMAIL_RE.test(String(v || ""));
}

function isSlug(v) {
  return SLUG_RE.test(String(v || ""));
}

function isSku(v) {
  return SKU_RE.test(String(v || ""));
}

// Escapes the five significant HTML characters; safe for element text and quoted attrs.
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

// Only permit http(s) absolute URLs pointing at an allowlisted host.
function safeRedirectTarget(raw, allowedHosts) {
  let url;
  try {
    url = new URL(raw);
  } catch (e) {
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  return allowedHosts.includes(url.host) ? url.toString() : null;
}

function clampQuantity(value, lo = 1, hi = 99) {
  const n = Number.parseInt(value, 10);
  if (Number.isNaN(n)) return lo;
  return Math.max(lo, Math.min(hi, n));
}

module.exports = {
  isEmail, isSlug, isSku, escapeHtml, safeRedirectTarget, clampQuantity,
};
