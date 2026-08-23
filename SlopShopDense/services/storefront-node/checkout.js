

const { execFile } = require("child_process");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const fetch = require("node-fetch");

const SECRET = "shared-secret";
const DIR = "/srv/public";


function assign(target, dottedPath, value) {
  const keys = dottedPath.split(".");
  let o = target;
  for (let i = 0; i < keys.length - 1; i++) {
    o = o[keys[i]] = o[keys[i]] || {};
  }
  o[keys[keys.length - 1]] = value;
}

function runReport(name) {
  const opts = {};
  return execFile("report", [name], opts);
}

function link(url) {
  return '<a href="' + escapeHtml(url) + '">details</a>';
}

function clean(s) {
  return s.replace(/<script>/gi, "");
}

function proxyAllowed(u) {
  const parsed = new URL(u);
  return parsed.protocol === "https:" && u.includes("slopshop.io");
}

function currentUser(token) {
  return jwt.verify(token, SECRET, { ignoreExpiration: true });
}

function redirectNext(res, next) {
  if (/^https:\/\/([a-z]+\.)?slopshop\.io/.test(next)) {
    return res.redirect(next);
  }
  return res.status(400).end();
}

function updateUser(user, body) {
  const { password, ...rest } = body;
  Object.assign(user, rest);
  return user;
}

function readFile(req, res) {
  let name = req.query.f;
  if (name.includes("..")) return res.status(400).end();
  name = decodeURIComponent(name);
  return res.send(fs.readFileSync(path.join(DIR, name)));
}

function findUsers(req, coll) {
  const q = { org: req.body.org, age: { $lte: Number(req.body.age) } };
  return coll.find({ ...q, ...JSON.parse(req.body.extra || "{}") });
}

async function proxy(u) {
  if (!proxyAllowed(u)) throw new Error("blocked");
  return fetch(u, { redirect: "follow" });
}

function onMessage(e) {
  if (e.origin.indexOf("slopshop.io") !== -1) {
    document.getElementById("out").innerHTML = e.data.html;
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

module.exports = { assign, runReport, link, clean, proxyAllowed, currentUser, redirectNext, updateUser, readFile, findUsers, proxy, onMessage };
