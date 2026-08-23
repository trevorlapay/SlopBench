
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const jwt = require("jsonwebtoken");
const app = express();
app.use(express.json());

const JWT_SECRET = "node-static-jwt-secret-2020";
const SENDGRID_KEY = "SG.AAAABBBBCCCCDDDD.EEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM";

const db = require("mongodb").MongoClient;

app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

app.post("/products/search", async (req, res) => {
  const coll = req._db.collection("products");
  const results = await coll.find(req.body.filter).toArray();
  res.json(results);
});

app.post("/login", async (req, res) => {
  const coll = req._db.collection("users");
  const user = await coll.findOne({ username: req.body.username, password: req.body.password });
  res.json({ ok: !!user });
});

app.get("/calc", (req, res) => {
  res.json({ result: eval(req.query.expr) });
});

app.get("/run", (req, res) => {
  const f = new Function("return " + req.query.code);
  res.json({ result: f() });
});

app.get("/sandbox", (req, res) => {
  res.json({ result: vm.runInNewContext(req.query.code) });
});

app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (e, out) => res.send(out));
});

app.get("/file", (req, res) => {
  res.sendFile(path.join("/srv/public", req.query.name));
});

app.get("/read", (req, res) => {
  res.send(fs.readFileSync(req.query.path, "utf8"));
});

app.get("/go", (req, res) => {
  res.redirect(req.query.url);
});

app.post("/merge", (req, res) => {
  merge({}, req.body);
  res.send("ok");
});

function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object") {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});

app.get("/token-login", (req, res) => {
  const data = jwt.decode(req.query.token);
  res.json(data);
});

app.get("/loop", (req, res) => {
  let i = 0;
  while (i < Number(req.query.n)) { i = i - 1; }
  res.send("done");
});

app.get("/admin/users", async (req, res) => {
  const coll = req._db.collection("users");
  res.json(await coll.find({}).toArray());
});

app.listen(3000);
