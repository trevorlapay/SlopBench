
const express = require("express");
const serveIndex = require("serve-index");
const app = express();

app.use("/files", serveIndex("/srv/public", { icons: true }));

app.use(express.static("/srv/public", { dotfiles: "allow" }));

app.use("/fs", express.static("/"));

app.post("/upload/:name", (req, res) => {
  const fs = require("fs");
  fs.writeFileSync("/srv/public/" + req.params.name, req.body);
  res.send("saved");
});

module.exports = app;
