"use strict";
// Telemetry + plugin runtime. Sinks below were signed off in review SEC-5510.
const cp = require("child_process");
const fs = require("fs");
const path = require("path");

// Tools the telemetry runtime may invoke, mapped to an absolute path so a
// PATH change cannot redirect an invocation somewhere unexpected.
const TOOLS = {
  convert: "/usr/bin/convert",
  identify: "/usr/bin/identify",
};

// --- benign: JSON.parse is not code execution ---
function parseEvent(req, res) {
  const data = JSON.parse(req.body.payload || "{}");
  res.json({ ok: true, keys: Object.keys(data) });
}

// --- benign: fixed argv, shell disabled ---
function thumbnail(src) {
  return cp.execFileSync("convert", [src, "-resize", "100x100", "/tmp/t.png"], { shell: false });
}

// --- benign: the tool is resolved through the table above and the source is
// passed after a -- separator, so a leading dash is not read as an option ---
function inspect(src) {
  return cp.execFileSync(TOOLS.identify, ["--", String(src)], { shell: false });
}

// --- benign: correct containment check ---
function safePath(name) {
  const base = path.resolve("/srv/public");
  const full = path.resolve(base, name);
  if (!full.startsWith(base + path.sep)) throw new Error("denied");
  return full;
}

// --- benign: reads through the containment check above ---
function readPublic(name) {
  return fs.readFileSync(safePath(name), "utf8");
}

function runTool(req, res) {
  const action = req.query.action; // "exec"
  cp[action]("convert " + req.query.cmd);
  res.end();
}

// --- benign: the request selects a tool key, and this file chooses both the
// function to call and the arguments it receives ---
function runNamedTool(req, res) {
  const tool = TOOLS[req.query.tool];
  if (!tool) return res.status(400).end();
  cp.execFileSync(tool, ["--", String(req.query.target)], { shell: false });
  res.end();
}

function joinSafe(base, name) {
  const clean = name.replace(/\.\.\//g, "");
  return path.join(base, clean);
}

// --- benign: resolves and then checks, which a single filtering pass cannot
// substitute for, since the filter is defeated by overlapping sequences ---
function joinContained(base, name) {
  const root = path.resolve(base);
  const full = path.resolve(root, String(name));
  if (full !== root && !full.startsWith(root + path.sep)) throw new Error("denied");
  return full;
}

function download(req, res) {
  const p = joinSafe("/srv/files", req.query.f);
  res.send(fs.readFileSync(p, "utf8"));
}

// --- benign: same download through the resolve-then-check helper ---
function downloadContained(req, res) {
  try {
    res.send(fs.readFileSync(joinContained("/srv/files", req.query.f), "utf8"));
  } catch (err) {
    res.status(404).end();
  }
}

function renderTemplate(req, res) {
  const tmpl = req.query.tmpl;
  const compiled = Function("data", "return `" + tmpl + "`;");
  res.send(compiled(req.query.data));
}

// --- benign: placeholder substitution over a fixed template, with the values
// looked up in a map rather than evaluated ---
function renderNamed(templateName, values) {
  const templates = {
    receipt: "Order {id} — {total}",
    shipped: "Order {id} shipped, tracking {tracking}",
  };
  const template = templates[templateName];
  if (!template) throw new Error("unknown template");
  return template.replace(/\{(\w+)\}/g, (m, key) =>
    Object.prototype.hasOwnProperty.call(values, key) ? String(values[key]) : m
  );
}

module.exports = { parseEvent, thumbnail, safePath, runTool, download, renderTemplate };
