// Practice 03: Shop API (Node.js / Express / MongoDB)
// Login, settings, orders, payment webhooks, product search, report templates.
// Find every vulnerability, give the exact line, the exploit, and the fix. Time yourself: 30 minutes.

const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { MongoClient, ObjectId } = require("mongodb");

const app = express();
app.use(express.json());

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;                                                              // LINE 13: NOT A VULN: secret comes from the environment, not hardcoded
let db;
MongoClient.connect(process.env.MONGO_URL).then((client) => { db = client.db("shop"); });

app.use((req, res, next) => {
  const origin = req.headers.origin;
  res.setHeader("Access-Control-Allow-Origin", origin || "*");                                                  // LINE 19: [HIGH] CORS reflects ANY Origin...
  res.setHeader("Access-Control-Allow-Credentials", "true");                                                    // LINE 20: [HIGH] ...together with credentials -> any website can call the API as the logged-in victim and read the responses. Use an origin allow-list
  next();
});

function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  const claims = jwt.decode(token);                                                                             // LINE 26: [CRITICAL] jwt.decode() does NOT verify the signature -> forge any id/role. Use jwt.verify(token, key, { algorithms: ["HS256"] })
  if (!claims) return res.sendStatus(401);
  req.user = claims;
  next();
}

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await db.collection("users").findOne({ email: email, password: password });                      // LINE 34: [CRITICAL] NoSQL injection: {"email":"admin@shop.com","password":{"$ne":null}} matches without knowing the password. Also passwords are stored and compared in plaintext. Cast inputs to strings; hash with argon2/bcrypt
  if (!user) return res.sendStatus(401);
  const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_KEY, { expiresIn: "1h" });          // LINE 36: NOT A VULN: signed with an env key and has an expiry (the bug is on the verify side, in auth())
  res.json({ token });
});

function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);                                                                          // LINE 44: [HIGH] Prototype pollution: recursive merge with no block on __proto__ / constructor / prototype keys
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.patch("/settings", auth, async (req, res) => {
  const settings = (await db.collection("settings").findOne({ userId: req.user.id })) || {};
  merge(settings, req.body);                                                                                    // LINE 54: [HIGH] Body {"__proto__":{"isAdmin":true}} pollutes Object.prototype for the WHOLE process -> every object now has isAdmin = true
  await db.collection("settings").updateOne({ userId: req.user.id }, { $set: settings }, { upsert: true });
  res.json(settings);
});

app.get("/admin/orders", auth, async (req, res) => {
  if (!req.user.isAdmin) return res.sendStatus(403);                                                            // LINE 60: [HIGH] Broken admin check: isAdmin is inherited after prototype pollution, and req.user comes from an unverified token anyway. Check an explicit role from a verified token (own property)
  res.json(await db.collection("orders").find().toArray());
});

app.get("/orders/:id", auth, async (req, res) => {
  const order = await db.collection("orders").findOne({ _id: new ObjectId(req.params.id) });                    // LINE 65: [HIGH] BOLA: no userId filter -> any user reads any order (address, phone). Add userId: req.user.id. (A bad id also throws -> unhandled rejection in Express 4)
  res.json(order);
});

app.post("/webhooks/payment", (req, res) => {
  const sig = req.headers["x-signature"] || "";
  const expected = crypto.createHmac("sha256", WEBHOOK_SECRET).update(JSON.stringify(req.body)).digest("hex");
  if (sig !== expected) return res.sendStatus(401);                                                             // LINE 72: [LOW] Non-constant-time compare (use crypto.timingSafeEqual); HMAC is computed over re-serialized JSON instead of the raw body
  if (req.body.status === "paid") {
    db.collection("orders").updateOne({ _id: new ObjectId(req.body.orderId) }, { $set: { status: "paid" } });   // LINE 74: [MEDIUM] No timestamp/nonce -> a captured valid webhook can be REPLAYED; and the paid amount is never compared with the order total
  }
  res.sendStatus(200);
});

app.get("/products/search", async (req, res) => {
  const q = req.query.q || "";
  const products = await db.collection("products").find({ name: { $regex: q } }).toArray();                     // LINE 81: [MEDIUM] User input used as a regex: ReDoS on the database and regex injection (.* returns everything). Escape the input or use a text index
  res.json(products);
});

const EMAIL_RE = /^([a-zA-Z0-9_.-]+)+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;                                         // LINE 85: [MEDIUM] ReDoS: nested quantifier ([...]+)+ -> "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!" causes catastrophic backtracking and blocks the event loop (whole server)

app.post("/newsletter", (req, res) => {
  if (!EMAIL_RE.test(req.body.email)) return res.status(400).send("bad email");
  res.send("Thanks, " + req.body.email);                                                                        // LINE 89: NOT A VULN (today): the regex only allows letters, digits, _ . - @, so no < or > can reach this HTML response. It becomes XSS the moment validation changes
});

app.get("/r", (req, res) => {
  res.redirect(req.query.to);                                                                                   // LINE 93: [MEDIUM] Open redirect: /r?to=https://evil.net (phishing, OAuth redirect_uri chains)
});

app.post("/reports/preview", auth, (req, res) => {
  const render = new Function("data", "return `" + req.body.template + "`;");                                   // LINE 97: [CRITICAL] Code injection: the user template is compiled as a JS template literal -> ${process.mainModule.require('child_process').execSync('id')} = RCE
  res.send(render(req.body.data));
});

app.listen(3000);

// ================================================================================================
// ANSWER KEY SUMMARY (line numbers match the practice file)
//  CRITICAL line 26   jwt.decode() does NOT verify the signature -> forge any id/role. Use jwt.verify(token, key, { algorithms: ["HS256"] })
//  CRITICAL line 34   NoSQL injection: {"email":"admin@shop.com","password":{"$ne":null}} matches without knowing the password. Also passwords are stored and compared in pl
//  CRITICAL line 97   Code injection: the user template is compiled as a JS template literal -> ${process.mainModule.require('child_process').execSync('id')} = RCE
//  HIGH     line 19   CORS reflects ANY Origin...
//  HIGH     line 20   ...together with credentials -> any website can call the API as the logged-in victim and read the responses. Use an origin allow-list
//  HIGH     line 44   Prototype pollution: recursive merge with no block on __proto__ / constructor / prototype keys
//  HIGH     line 54   Body {"__proto__":{"isAdmin":true}} pollutes Object.prototype for the WHOLE process -> every object now has isAdmin = true
//  HIGH     line 60   Broken admin check: isAdmin is inherited after prototype pollution, and req.user comes from an unverified token anyway. Check an explicit role from a 
//  HIGH     line 65   BOLA: no userId filter -> any user reads any order (address, phone). Add userId: req.user.id. (A bad id also throws -> unhandled rejection in Express 
//  MEDIUM   line 74   No timestamp/nonce -> a captured valid webhook can be REPLAYED; and the paid amount is never compared with the order total
//  MEDIUM   line 81   User input used as a regex: ReDoS on the database and regex injection (.* returns everything). Escape the input or use a text index
//  MEDIUM   line 85   ReDoS: nested quantifier ([...]+)+ -> "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!" causes catastrophic backtracking and blocks the event loop (whole server)
//  MEDIUM   line 93   Open redirect: /r?to=https://evil.net (phishing, OAuth redirect_uri chains)
//  LOW      line 72   Non-constant-time compare (use crypto.timingSafeEqual); HMAC is computed over re-serialized JSON instead of the raw body
//  NOT A VULN (decoys you should say are safe): lines 13, 36, 89
//  Total real findings: 14
// ================================================================================================
