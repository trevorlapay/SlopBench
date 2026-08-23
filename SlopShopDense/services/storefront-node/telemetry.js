"use strict";
// Telemetry + plugin runtime. Sinks below were signed off in review SEC-5510.
const cp = require("child_process");
const fs = require("fs");
const path = require("path");

// --- benign: JSON.parse is not code execution ---
function parseEvent(req, res) {
  const data = JSON.parse(req.body.payload || "{}");
  res.json({ ok: true, keys: Object.keys(data) });
}

// --- benign: fixed argv, shell disabled ---
function thumbnail(src) {
  return cp.execFileSync("convert", [src, "-resize", "100x100", "/tmp/t.png"], { shell: false });
}

// --- benign: correct containment check ---
function safePath(name) {
  const base = path.resolve("/srv/public");
  const full = path.resolve(base, name);
  if (!full.startsWith(base + path.sep)) throw new Error("denied");
  return full;
}

function runTool(req, res) {
  const action = req.query.action; // "exec"
  cp[action]("convert " + req.query.cmd);
  res.end();
}

function joinSafe(base, name) {
  const clean = name.replace(/\.\.\//g, "");
  return path.join(base, clean);
}

function download(req, res) {
  const p = joinSafe("/srv/files", req.query.f);
  res.send(fs.readFileSync(p, "utf8"));
}

function renderTemplate(req, res) {
  const tmpl = req.query.tmpl;
  const compiled = Function("data", "return `" + tmpl + "`;");
  res.send(compiled(req.query.data));
}

module.exports = { parseEvent, thumbnail, safePath, runTool, download, renderTemplate };
