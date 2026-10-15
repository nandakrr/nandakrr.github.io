const express = require("express");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");
const axios = require("axios");
const app = express();

app.use(express.json());

const db = mysql.createConnection({                                                        // <-- LINE 9: [High] VULN-8 DB credentials HARDCODED in source (block lines 9-14)
  host: "localhost",
  user: "root",                                                                            // <-- LINE 11: [High] VULN-8 App connects as MySQL ROOT -> SQLi = full DB root (LOAD_FILE, INTO OUTFILE, all DBs)
  password: "root123",                                                                     // <-- LINE 12: [High] VULN-8 Hardcoded weak DB password
  database: "users_db"                                                                     // <-- LINE 13: NOT A VULN: multipleStatements is OFF by default -> stacked queries (; DROP) fail
});

const JWT_SECRET = "supersecretkey";                                                       // <-- LINE 16: [CRITICAL] VULN-4 HARDCODED GUESSABLE JWT SECRET -> hashcat -m 16500 -> forge role=admin

/* Login */
app.post("/login", (req, res) => {                                                         // <-- LINE 19: [Low/Med] No rate limit / lockout on login -> brute force
  const { username, password } = req.body;                                                 // <-- LINE 20: Fix trap: no typeof check. Even a parameterized mysqljs query is bypassable with {"password":{"password":1}}

  const query = `SELECT * FROM users WHERE username='${username}'`;                        // <-- LINE 22: [CRITICAL] VULN-1 SQL INJECTION: payload x' UNION SELECT 1,'admin','pwned','admin' -- -  with password=pwned

  db.query(query, (err, result) => {                                                       // <-- LINE 24: [CRITICAL] VULN-1 the injected query EXECUTES here
    if (err || result.length === 0) {                                                      // <-- LINE 25: NOT A VULN: same message for all failures -> no enumeration by response text
      return res.status(401).send("Invalid credentials");
    }

    if (password !== result[0].password) {                                                 // <-- LINE 29: [High] VULN-3 PLAINTEXT passwords stored & compared (not hashed); !== not constant-time
      return res.status(401).send("Invalid credentials");
    }

    const token = jwt.sign(                                                                // <-- LINE 33: Role frozen inside token (see line 36)
      { userId: result[0].id, role: result[0].role },
      JWT_SECRET,                                                                          // <-- LINE 35: [CRITICAL] VULN-4 weak secret used to sign
      { expiresIn: "24h" }                                                                 // <-- LINE 36: [Low] Role baked into a 24h token -> demotion doesn't apply until expiry, no revocation
    );

    res.json({ token });
  });
});

/* Auth Middleware */
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];                                  // <-- LINE 45: NOT A VULN: missing header -> undefined -> verify throws -> 401

  try {
    const decoded = jwt.verify(token, JWT_SECRET);                                         // <-- LINE 48: NOT A VULN (hardening only): rejects alg:none; still pin { algorithms: ['HS256'] }
    req.user = decoded;
    next();
  } catch {
    res.status(401).send("Unauthorized");
  }
}

/* Get User Profile */
app.get("/user/:id", authenticate, (req, res) => {                                         // <-- LINE 57: [Med/High] VULN-7 BOLA/IDOR: authenticated, but no check that :id is YOUR id
  const query = `SELECT id, username, email, role FROM users WHERE id=${req.params.id}`;   // <-- LINE 58: [CRITICAL] VULN-2 SQL INJECTION (numeric): /user/0 UNION SELECT id,username,password,role FROM users -- -

  db.query(query, (err, result) => {                                                       // <-- LINE 60: [CRITICAL] VULN-2 injected query EXECUTES here -> plaintext password comes back in 'email'
    if (err || result.length === 0) {
      return res.status(404).send("User not found");
    }
    res.json(result[0]);
  });
});                                                                                        // <-- LINE 66: [Med/High] VULN-7 another user's email/role returned

/* Internal Service Call */
app.post("/sync", authenticate, async (req, res) => {                                      // <-- LINE 69: [High] VULN-6 async handler, NO try/catch -> bad URL = unhandled rejection = PROCESS CRASH (Express 4, Node 15+)
  const { url } = req.body;                                                                // <-- LINE 70: [High/Crit] VULN-5 SSRF source: URL straight from request body

  const response = await axios.get(url, {                                                  // <-- LINE 72: [High/Crit] VULN-5 SSRF: fetches attacker URL (169.254.169.254, localhost), follows redirects, no timeout/size limit
    headers: {
      "X-User-Role": req.user.role                                                         // <-- LINE 74: [High] VULN-5b trust-me header: leaks to attacker server; forged admin token -> 'admin' sent to internal APIs
    }
  });

  res.json({ status: "synced", data: response.data });                                     // <-- LINE 78: [High/Crit] VULN-5 FULL-READ SSRF: internal response returned to attacker
});

app.listen(3000, () => {                                                                   // <-- LINE 81: [Low] No helmet/security headers, no HTTPS
  console.log("Server running on port 3000");
});

// ==================== SUMMARY (line numbers match the original code) ====================
// CRITICAL  Line 22,24   VULN-1 SQL injection in /login -> log in as anyone
// CRITICAL  Line 58,60   VULN-2 SQL injection in /user/:id -> dump plaintext passwords
// CRITICAL  Line 16,35   VULN-4 Hardcoded guessable JWT secret -> forge admin token
// HIGH/CRIT Line 70-78   VULN-5 Full-read SSRF (+ line 74 X-User-Role header trust)
// HIGH      Line 29      VULN-3 Plaintext passwords
// HIGH      Line 69      VULN-6 Unhandled async rejection -> any user crashes the server
// HIGH      Line 9-12    VULN-8 Hardcoded root DB credentials
// MED/HIGH  Line 57      VULN-7 BOLA / IDOR
// LOW       Line 19,36,81  rate limit, 24h frozen role, no headers
// CHAIN: line 58 SQLi dumps admin's plaintext password -> log in -> line 72/74 /sync hits internal
//        services as 'admin' or pulls cloud credentials. Line 69: any user can crash the server.
