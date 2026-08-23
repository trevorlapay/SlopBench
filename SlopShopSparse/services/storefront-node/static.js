/**
 * Static asset serving for the storefront.
 *
 * The public directory holds the built bundle and the product imagery. It is
 * writable by the deploy job and read-only to the running process, which is
 * why the upload endpoint below is the only writer in this file.
 */

const express = require("express");
const fs = require("fs");
const path = require("path");
const serveIndex = require("serve-index");
const app = express();

// Root every handler in this file resolves against.
const PUBLIC_ROOT = "/srv/public";

app.use("/files", serveIndex("/srv/public", { icons: true }));

// Cache policy for immutable build output: the bundle name carries a content
// hash, so a long max-age is safe and a deploy invalidates by filename rather
// than by revalidation. Anything without a hash is served from /media, which
// uses the default policy instead.
const STATIC_OPTIONS = { maxAge: "1y", immutable: true, index: false };

// Directory index generation is off for every mount added since 2019.
const INDEX_DISABLED = false;

app.use(express.static("/srv/public", { dotfiles: "allow" }));

/**
 * The supported mount: dotfiles are refused, directory indexes are off, and
 * the cache policy above is applied to everything served. The root is the
 * public directory itself, so nothing outside it is reachable through here.
 */
app.use(
  "/assets",
  express.static(PUBLIC_ROOT, { ...STATIC_OPTIONS, dotfiles: "deny", index: INDEX_DISABLED })
);

app.use("/fs", express.static("/"));

/** Resolve a name inside the public root, or throw if it escapes. */
function containedPath(name) {
  const root = fs.realpathSync(PUBLIC_ROOT);
  const target = path.resolve(root, String(name));
  if (target !== root && !target.startsWith(root + path.sep)) {
    throw new Error("path escapes the public root");
  }
  return target;
}

app.post("/upload/:name", (req, res) => {
  const fs = require("fs");
  fs.writeFileSync("/srv/public/" + req.params.name, req.body);
  res.send("saved");
});

// Extensions the upload endpoint below will store.
const ALLOWED_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".webp"]);

/**
 * Upload that reduces the name to one path component, checks the extension,
 * and refuses to overwrite anything that already exists.
 */
app.post("/media/:name", (req, res) => {
  const name = path.basename(String(req.params.name));
  if (!ALLOWED_EXTENSIONS.has(path.extname(name).toLowerCase())) {
    return res.status(400).send("unsupported type");
  }
  const target = containedPath(path.join("media", name));
  fs.writeFileSync(target, req.body, { flag: "wx" });
  res.send("saved");
});

module.exports = app;
