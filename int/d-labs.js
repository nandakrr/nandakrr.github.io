// ============ CODE REVIEW DRILLS ============
// bad = 1-based line numbers that contain the vulnerability (source or sink lines a reviewer must point at)
window.DRILLS = [
{id:"idor",lang:"Node.js",title:"Invoice download",ctx:"Express API. Any logged-in customer can call this.",
 code:`const express = require('express');
const router = express.Router();

router.get('/invoices/:id', requireLogin, async (req, res) => {
  const invoice = await Invoice.findById(req.params.id);
  if (!invoice) return res.status(404).end();
  res.json(invoice);
});`,bad:[5],
 vuln:"Insecure Direct Object Reference (IDOR / BOLA)",cwe:"CWE-639",
 why:"The query uses only the ID from the URL. Nothing checks that the invoice belongs to the logged-in customer, so changing the ID returns other customers' invoices.",
 fix:`const invoice = await Invoice.findOne({
  _id: req.params.id,
  customerId: req.user.id   // ownership enforced in the query
});
if (!invoice) return res.status(404).end(); // same answer for "not found" and "not yours"`,
 fu:["How would you find every endpoint with this pattern across 200 services?","Would switching to UUIDs fix it?","What test would stop it coming back?"]},
{id:"sqli",lang:"Python",title:"Product search",ctx:"Flask app using a raw database connection.",
 code:`@app.route("/search")
def search():
    term = request.args.get("q", "")
    sort = request.args.get("sort", "name")
    sql = f"SELECT id, name FROM products WHERE name LIKE '%{term}%' ORDER BY {sort}"
    rows = db.execute(sql).fetchall()
    return jsonify([dict(r) for r in rows])`,bad:[5],
 vuln:"SQL injection (in both the value and the ORDER BY column)",cwe:"CWE-89",
 why:"User input is formatted straight into the SQL string. The search term can break out of the quotes, and the sort column can inject anything after ORDER BY. Identifiers like column names cannot be parameterised, so they need an allow-list.",
 fix:`SORTABLE = {"name": "name", "price": "price", "newest": "created_at"}
col = SORTABLE.get(sort, "name")                      # allow-list for identifiers
sql = f"SELECT id, name FROM products WHERE name LIKE ? ORDER BY {col}"
rows = db.execute(sql, (f"%{term}%",)).fetchall()      # bound parameter for values`,
 fu:["What is second-order SQL injection?","Why doesn't escaping quotes fully fix this?","How would a least-privilege DB user change the impact?"]},
{id:"deser",lang:"Java",title:"Cart import",ctx:"Spring Boot endpoint that lets users upload a saved cart.",
 code:`@PostMapping("/import")
public ResponseEntity<String> importCart(@RequestBody byte[] body) throws Exception {
    ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(body));
    Cart cart = (Cart) in.readObject();
    cartService.save(cart);
    return ResponseEntity.ok("imported");
}`,bad:[3,4],
 vuln:"Insecure deserialisation leading to remote code execution",cwe:"CWE-502",
 why:"readObject() on attacker bytes instantiates any serialisable class on the classpath before the cast happens. Gadget chains in common libraries turn that into code execution.",
 fix:`// Accept JSON with a strict schema instead of native Java objects
@PostMapping(value = "/import", consumes = "application/json")
public ResponseEntity<String> importCart(@Valid @RequestBody CartImportDto dto) {
    cartService.save(dto.toCart(currentUser()));
    return ResponseEntity.ok("imported");
}
// If native serialisation is unavoidable: ObjectInputFilter allow-list of classes`,
 fu:["Why does the cast to Cart not protect you?","What is a gadget chain?","Where else does deserialisation hide (YAML, Jackson default typing)?"]},
{id:"ssrf",lang:"Node.js",title:"Webhook tester",ctx:"Customers can test their webhook URL from the dashboard. The service runs on AWS.",
 code:`app.post('/webhooks/test', requireLogin, async (req, res) => {
  const { url } = req.body;
  if (!url.startsWith('http')) {
    return res.status(400).json({ error: 'invalid url' });
  }
  const r = await fetch(url);
  const text = await r.text();
  res.json({ status: r.status, body: text.slice(0, 500) });
});`,bad:[3,6,8],
 vuln:"Server-side request forgery (full-read SSRF)",cwe:"CWE-918",
 why:"Any URL starting with 'http' is fetched from inside the VPC, including http://169.254.169.254/ (instance metadata) and internal services. Returning the body lets the attacker read the response.",
 fix:`const target = new URL(url);
if (target.protocol !== 'https:') return res.status(400).end();
const addrs = await dns.promises.lookup(target.hostname, { all: true });
if (addrs.some(a => isPrivateOrLinkLocal(a.address))) return res.status(400).end();
// connect to the vetted IP (prevents DNS rebinding), no redirects,
// route through an egress proxy, and return only the status code
const r = await fetchViaEgressProxy(target, { pinnedIp: addrs[0].address, redirect: 'manual' });
res.json({ status: r.status });`,
 fu:["How does DNS rebinding bypass a check-then-fetch?","What does IMDSv2 change?","Why return only the status code?"]},
{id:"path",lang:"Python",title:"Export download",ctx:"Logged-in users download their CSV exports.",
 code:`BASE = "/srv/app/exports"

@app.route("/download")
@login_required
def download():
    name = request.args.get("file")
    path = os.path.join(BASE, name)
    return send_file(path)`,bad:[7,8],
 vuln:"Path traversal, plus missing ownership check",cwe:"CWE-22",
 why:"file=../../../etc/passwd escapes the folder, and os.path.join discards BASE completely if name is absolute (/etc/passwd). Even inside the folder, any user can download any other user's export.",
 fix:`export = Export.query.filter_by(id=request.args.get("id"), user_id=current_user.id).first_or_404()
path = os.path.realpath(os.path.join(BASE, export.filename))
if not path.startswith(BASE + os.sep):
    abort(400)
return send_file(path, as_attachment=True)`,
 fu:["Why is os.path.join with an absolute path dangerous?","Better design: why not reference files by database ID?","What about S3 instead of local disk?"]},
{id:"jwt",lang:"Go",title:"Auth middleware",ctx:"Middleware in front of every API route.",
 code:`func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
        token, _, err := new(jwt.Parser).ParseUnverified(raw, jwt.MapClaims{})
        if err != nil {
            http.Error(w, "unauthorized", 401)
            return
        }
        claims := token.Claims.(jwt.MapClaims)
        ctx := context.WithValue(r.Context(), "user", claims["sub"])
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}`,bad:[4],
 vuln:"JWT signature never verified (authentication bypass)",cwe:"CWE-347",
 why:"ParseUnverified decodes the token without checking the signature, expiry, issuer or audience. Anyone can craft a token with any sub and become any user.",
 fix:`token, err := jwt.Parse(raw, keyFunc,                 // key from IdP JWKS
    jwt.WithValidMethods([]string{"RS256"}),           // pin the algorithm
    jwt.WithIssuer("https://auth.example.com/"),
    jwt.WithAudience("orders-api"),
    jwt.WithExpirationRequired())
if err != nil || !token.Valid {
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
}`,
 fu:["What is algorithm confusion (RS256 to HS256)?","How do you revoke a JWT early?","Should a context key be a plain string?"]},
{id:"redirect",lang:"Node.js",title:"Login callback",ctx:"Runs after the IdP redirects back. Session-based app.",
 code:`app.get('/login/callback', async (req, res) => {
  const user = await completeLogin(req);
  req.session.userId = user.id;
  const next = req.query.next || '/dashboard';
  res.redirect(next);
});`,bad:[3,5],
 vuln:"Open redirect, and session fixation",cwe:"CWE-601 / CWE-384",
 why:"next can be https://evil.com, sending freshly logged-in users to a phishing page (and in OAuth flows it can leak codes or tokens). The session ID is also not regenerated at login, so an attacker who planted a session ID before login now shares the logged-in session.",
 fix:`req.session.regenerate(err => {             // new session ID after login
  if (err) return res.status(500).end();
  req.session.userId = user.id;
  const next = req.query.next;
  res.redirect(isSafeRedirect(next) ? next : '/dashboard'); // relative paths or allow-listed hosts only
});`,
 fu:["How does an open redirect become an OAuth token theft?","Why check for // and /\\ in relative paths?","What is session fixation vs hijacking?"]},
{id:"cmd",lang:"Python",title:"Network diagnostics",ctx:"Admin-only page to ping a host.",
 code:`@app.route("/tools/ping", methods=["POST"])
@admin_required
def ping():
    host = request.form["host"]
    out = subprocess.run(f"ping -c 2 {host}", shell=True, capture_output=True, text=True)
    return {"output": out.stdout}`,bad:[5],
 vuln:"OS command injection",cwe:"CWE-78",
 why:"shell=True with an interpolated string lets host=8.8.8.8; cat /etc/passwd run extra commands. Admin-only lowers likelihood but a CSRF or a compromised admin makes it RCE on the server.",
 fix:`import ipaddress
try:
    ip = ipaddress.ip_address(request.form["host"])      # validate strictly
except ValueError:
    abort(400)
out = subprocess.run(["ping", "-c", "2", str(ip)],       # argument list, no shell
                     capture_output=True, text=True, timeout=5)`,
 fu:["Does removing shell=True alone solve argument injection?","Why does 'admin only' not make this low risk?"]},
{id:"reactxss",lang:"React",title:"Public profile",ctx:"Profiles are visible to every visitor. All fields are user-editable.",
 code:`function Profile({ user }) {
  return (
    <div className="profile">
      <h2>{user.displayName}</h2>
      <a href={user.website}>Website</a>
      <div dangerouslySetInnerHTML={{ __html: user.bio }} />
    </div>
  );
}`,bad:[5,6],
 vuln:"Stored XSS (raw HTML bio and javascript: URLs)",cwe:"CWE-79",
 why:"dangerouslySetInnerHTML renders the bio as raw HTML, so <img src=x onerror=...> runs for every visitor. The website link can be javascript:...; older React versions render it, so validate the scheme anyway.",
 fix:`import DOMPurify from 'dompurify';
const safeUrl = /^https?:\\/\\//i.test(user.website) ? user.website : undefined;
<a href={safeUrl} rel="noopener noreferrer">Website</a>
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(user.bio) }} />
// plus a strict CSP as defence in depth`,
 fu:["Why is line 4 safe?","What does a nonce-based CSP add?","Would HttpOnly cookies stop the damage?"]},
{id:"mass",lang:"Java",title:"Update my profile",ctx:"The User entity has fields: id, email, name, phone, role, isAdmin, tenantId.",
 code:`@PutMapping("/users/me")
public User updateMe(@AuthenticationPrincipal Principal p, @RequestBody User update) {
    User user = userRepo.findByEmail(p.getName());
    BeanUtils.copyProperties(update, user, "id");
    return userRepo.save(user);
}`,bad:[2,4],
 vuln:"Mass assignment (privilege escalation)",cwe:"CWE-915",
 why:"The request body binds directly to the entity and every property except id is copied, so a user can send {\"role\":\"ADMIN\",\"isAdmin\":true,\"tenantId\":\"other\"}. The response also returns the full entity.",
 fix:`public record ProfileUpdate(@Size(max = 100) String name, @Pattern(regexp = "\\\\+?[0-9 ]{7,20}") String phone) {}

@PutMapping("/users/me")
public ProfileView updateMe(@AuthenticationPrincipal Principal p, @Valid @RequestBody ProfileUpdate in) {
    User user = userRepo.findByEmail(p.getName());
    user.setName(in.name());
    user.setPhone(in.phone());
    return ProfileView.from(userRepo.save(user));   // response DTO, no internal fields
}`,
 fu:["How would you find this pattern with Semgrep?","Why is returning the entity also a problem?"]},
{id:"ssti",lang:"Python",title:"Greeting page",ctx:"Flask with Jinja2.",
 code:`@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    template = "<h1>Hello " + name + "!</h1>"
    return render_template_string(template)`,bad:[4,5],
 vuln:"Server-side template injection leading to RCE",cwe:"CWE-1336",
 why:"The name becomes part of the template source, so ?name={{7*7}} renders 49 and Jinja2 payloads can reach Python internals and run commands.",
 fix:`return render_template_string("<h1>Hello {{ name }}!</h1>", name=name)
# the template is constant; user input is passed as data and auto-escaped`,
 fu:["How is this different from XSS?","How would you detect it quickly in a test?"]},
{id:"race",lang:"Node.js",title:"Coupon redemption",ctx:"Each coupon code may be used once. Credit goes to the user's wallet.",
 code:`app.post('/coupons/redeem', requireLogin, async (req, res) => {
  const coupon = await Coupon.findOne({ code: req.body.code });
  if (!coupon || coupon.used) {
    return res.status(400).json({ error: 'invalid coupon' });
  }
  await Wallet.credit(req.user.id, coupon.amount);
  coupon.used = true;
  await coupon.save();
  res.json({ ok: true });
});`,bad:[3,8],
 vuln:"Race condition (time-of-check to time-of-use)",cwe:"CWE-362",
 why:"The check (line 3) and the update (line 8) are separate steps, and the wallet is credited in between. Twenty parallel requests all see used=false and all credit the wallet.",
 fix:`// claim the coupon atomically; only one request can win
const coupon = await Coupon.findOneAndUpdate(
  { code: req.body.code, used: false },
  { $set: { used: true, usedBy: req.user.id, usedAt: new Date() } },
  { new: true }
);
if (!coupon) return res.status(400).json({ error: 'invalid coupon' });
await Wallet.credit(req.user.id, coupon.amount);   // ideally in the same transaction`,
 fu:["How would you test this (single-packet attack)?","How do idempotency keys help in payments?"]},
{id:"token",lang:"Python",title:"Password reset tokens",ctx:"Tokens are emailed to users as a 6-digit code.",
 code:`import random, time

def create_reset_token(user):
    random.seed(int(time.time()))
    token = str(random.randint(100000, 999999))
    db.save_reset(user.id, token, expires=time.time() + 86400)
    return token

def verify_reset(user_id, token):
    return db.get_reset(user_id) == token`,bad:[4,5,6,10],
 vuln:"Predictable, brute-forceable, long-lived reset tokens",cwe:"CWE-330 / CWE-640",
 why:"Seeding with the current second makes the token reproducible. A 6-digit code can be brute-forced without rate limits, it lives for 24 hours, it is stored in plain text, it is not single-use, and == leaks timing.",
 fix:`import secrets, hashlib, hmac, time

def create_reset_token(user):
    token = secrets.token_urlsafe(32)                       # CSPRNG, 256 bits
    db.save_reset(user.id, hashlib.sha256(token.encode()).hexdigest(),
                  expires=time.time() + 900)                  # 15 minutes
    return token

def verify_reset(user_id, token):
    rec = db.pop_reset(user_id)                               # single use
    return rec and rec.expires > time.time() and hmac.compare_digest(
        rec.hash, hashlib.sha256(token.encode()).hexdigest())`,
 fu:["Why store a hash of the token?","What else must happen after a successful reset?"]},
{id:"iam",lang:"AWS IAM",title:"Reports Lambda role",ctx:"The Lambda only needs to read objects from the bucket acme-reports.",
 code:`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReportsLambda",
      "Effect": "Allow",
      "Action": ["s3:*", "iam:PassRole", "lambda:*"],
      "Resource": "*"
    }
  ]
}`,bad:[7,8],
 vuln:"Over-privileged role with a privilege-escalation path",cwe:"CWE-269",
 why:"s3:* on * gives every bucket in the account. iam:PassRole plus lambda:* lets anyone who controls this function create a new Lambda with a more powerful role and escalate.",
 fix:`{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ReadReports",
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::acme-reports/*"
  }]
}`,
 fu:["How would you find what permissions it really uses?","What condition limits iam:PassRole when it is genuinely needed?"]},
{id:"tf",lang:"Terraform",title:"Customer exports bucket",ctx:"Holds CSV exports with customer data.",
 code:`resource "aws_s3_bucket" "exports" {
  bucket = "acme-customer-exports"
}

resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "exports" {
  bucket = aws_s3_bucket.exports.id
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "\${aws_s3_bucket.exports.arn}/*"
    }]
  })
}`,bad:[7,8,9,10,18],
 vuln:"Publicly readable bucket of customer data",cwe:"CWE-732",
 why:"Block Public Access is switched off and the bucket policy allows Principal * to read every object. Anyone who learns an object key can download customer exports.",
 fix:`resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
# no public policy; share files with short-lived pre-signed URLs
# add SSE-KMS encryption, versioning, and an account-level BPA enforced by SCP`,
 fu:["Which Checkov check catches this?","How would you stop it at the organisation level?"]},
{id:"gha",lang:"GitHub Actions",title:"PR preview workflow",ctx:"Runs for pull requests from forks of a public repo.",
 code:`name: pr-preview
on: pull_request_target

permissions: write-all

jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm run build
        env:
          DEPLOY_TOKEN: \${{ secrets.DEPLOY_TOKEN }}
      - run: echo "Building \${{ github.event.pull_request.title }}"`,bad:[2,4,12,15,16],
 vuln:"Untrusted PR code runs with secrets and write access, plus script injection",cwe:"CWE-829 / CWE-94",
 why:"pull_request_target runs in the base repo's context with secrets. Checking out the fork's head and running npm scripts executes attacker code with DEPLOY_TOKEN and a write-all token. The PR title is also injected into a shell command.",
 fix:`on: pull_request            # untrusted code gets no secrets
permissions:
  contents: read
jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4   # pin third-party actions to a commit SHA
      - run: npm ci && npm run build
      - run: echo "Building $TITLE"
        env:
          TITLE: \${{ github.event.pull_request.title }}   # pass as env, never inline
# deploy previews from a separate workflow_run job that only consumes build artifacts`,
 fu:["Why is passing values through env safer?","How does OIDC remove the need for DEPLOY_TOKEN?"]},
{id:"docker",lang:"Dockerfile",title:"API image",ctx:"Built in CI and pushed to the company registry.",
 code:`FROM node:latest
ARG NPM_TOKEN
WORKDIR /app
COPY . .
RUN echo "//registry.npmjs.org/:_authToken=\${NPM_TOKEN}" > .npmrc && npm install
EXPOSE 3000
CMD ["node", "server.js"]`,bad:[1,4,5,7],
 vuln:"Secret baked into the image, unpinned base, root user, oversized context",cwe:"CWE-798 / CWE-250",
 why:"The npm token is written to .npmrc and stays in the layer. COPY . . can include .env and .git. node:latest is unpinned and large. There is no USER, so the app runs as root.",
 fix:`FROM node:22-slim@sha256:<digest> AS build
WORKDIR /app
COPY package*.json ./
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci --omit=dev
COPY src ./src

FROM gcr.io/distroless/nodejs22-debian12
COPY --from=build /app /app
USER nonroot
CMD ["/app/src/server.js"]
# plus a .dockerignore excluding .env, .git, tests`,
 fu:["How would you find secrets already in old images?","Why multi-stage?"]},
{id:"k8s",lang:"Kubernetes",title:"Log agent pod",ctx:"A vendor's log collector deployed in the production cluster.",
 code:`apiVersion: v1
kind: Pod
metadata:
  name: log-agent
spec:
  hostPID: true
  containers:
    - name: agent
      image: registry.example.com/log-agent:1.4
      securityContext:
        privileged: true
      volumeMounts:
        - name: host-root
          mountPath: /host
  volumes:
    - name: host-root
      hostPath:
        path: /`,bad:[6,11,18],
 vuln:"Effective root on the node (container escape by design)",cwe:"CWE-250",
 why:"privileged: true, the host PID namespace and the whole host filesystem mounted at /host mean anyone who compromises this container controls the node and every pod on it.",
 fix:`spec:
  containers:
    - name: agent
      image: registry.example.com/log-agent@sha256:<digest>
      securityContext:
        runAsNonRoot: true
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities: { drop: ["ALL"] }
      volumeMounts:
        - name: varlog
          mountPath: /var/log
          readOnly: true
  volumes:
    - name: varlog
      hostPath: { path: /var/log }   # only what it needs, read-only
# enforce with Pod Security Admission (restricted) or Kyverno; exceptions reviewed`,
 fu:["How would admission control stop this being deployed?","What if the vendor insists it needs privileged?"]},
{id:"cors",lang:"Node.js",title:"CORS middleware",ctx:"API at api.example.com uses session cookies.",
 code:`app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
});`,bad:[4,5],
 vuln:"CORS reflects any origin with credentials",cwe:"CWE-942",
 why:"Any website can make the victim's browser call the API with cookies and read the response, so an attacker page can steal account data.",
 fix:`const ALLOWED = new Set(['https://app.example.com', 'https://admin.example.com']);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  res.setHeader('Vary', 'Origin');
  next();
});`,
 fu:["Why can't you use * with credentials?","Why is a regex like /example\\.com$/ unsafe?"]}
];

// ============ THREAT MODEL LAB ============
window.TM = [
{id:"upload",title:"Profile picture upload",asked:"Common at Meta, Google and SaaS companies",
 brief:"Users upload a profile picture from web and mobile. Images are resized by a worker and shown on profiles, in comments and in emails.",
 comps:["Browser / app","API service","Upload bucket (S3)","Resize worker","Public CDN","Email service"],
 flows:[["User","API","multipart upload",true],["API","Upload bucket","store original",false],["Bucket","Resize worker","event + read",false],["Worker","CDN bucket","resized images",false],["CDN","Every viewer","serve image",true]],
 threats:[["T","Stored XSS: SVG or HTML file served inline from our domain","Allow-list types by content; re-encode to PNG/JPEG; serve from a separate domain with Content-Disposition and nosniff","Critical"],
  ["I","Original uploads in a public or guessable bucket expose private images","Private bucket, random object keys, short-lived signed URLs for originals","High"],
  ["E","Malicious image exploits the image library (RCE in the worker)","Sandbox the worker (no network, minimal IAM), patch the library, limit formats","High"],
  ["D","Decompression bomb or huge files exhaust memory","Size and pixel-dimension limits before decoding; timeouts; rate limits per user","Medium"],
  ["I","EXIF metadata leaks GPS location","Strip metadata during re-encoding","Medium"],
  ["S","User sets someone else's picture (IDOR on avatar update)","Ownership check from the session, not a userId parameter","High"],
  ["R","No record of abusive uploads","Log uploader, hash and timestamp; moderation hooks","Low"]],
 first:["Re-encode every image and serve from a separate sandboxed domain (kills XSS and polyglots)","Private storage with signed URLs plus a sandboxed, patched worker"],
 fu:["What if the image library itself has a CVE?","How do you handle GIF animations or HEIC?","How would you moderate illegal content?"],
 check:["Drew trust boundaries before listing threats","Mentioned stored XSS via SVG/HTML","Mentioned storage exposure (bucket access)","Mentioned the image parser as attack surface","Mentioned size/decompression DoS","Mentioned EXIF/privacy","Ranked threats and named the top two"]},
{id:"payments",title:"Payment-token microservice",asked:"Reported at Amazon and fintech companies",
 brief:"A Payments service stores card tokens from a payment provider and charges customers. Orders service calls it; the provider calls back with webhooks.",
 comps:["Orders service","Payments service","Token vault DB","Payment provider","Webhook endpoint","Admin console"],
 flows:[["Orders","Payments","charge(amount, token)",true],["Payments","Provider","API call",true],["Provider","Webhook endpoint","payment events",true],["Payments","Token vault","read/write tokens",false],["Support agent","Admin console","refunds",true]],
 threats:[["S","Forged 'payment succeeded' webhook marks orders paid","Verify HMAC signature and timestamp; re-query the provider before fulfilment","Critical"],
  ["T","Amount or currency tampered between services","Server-side price calculation; signed internal requests; idempotency keys","High"],
  ["S","Another internal service calls Payments directly","mTLS service identity; policy allowing only Orders; NetworkPolicy","High"],
  ["I","Token vault breach exposes payment tokens","Tokens useless outside our merchant account; KMS encryption; isolated account; least-privilege DB access","High"],
  ["R","Refund disputes with no audit trail","Immutable audit log of charges and refunds with user and request ID","Medium"],
  ["E","Support agent issues unlimited refunds","Role limits, dual approval above a threshold, alerts on anomalies","High"],
  ["D","Retry storms cause double charges","Idempotency keys on every charge; exactly-once processing","High"]],
 first:["Verify every webhook and re-confirm status with the provider","Idempotency plus server-side amounts so money can't be duplicated or altered"],
 fu:["How do you keep PCI scope small?","How would you rotate the provider API key without downtime?","What changes if you expand to multiple regions?"]
 ,check:["Mentioned tokenisation / PCI scope","Mentioned webhook authenticity","Mentioned idempotency and double-charge","Mentioned service-to-service authentication","Mentioned insider/refund abuse","Mentioned audit logging"]},
{id:"messaging",title:"End-to-end encrypted messaging",asked:"Reported at Meta (Signal-like app)",
 brief:"A mobile messaging app with one-to-one and group chats, end-to-end encryption, attachments, and multi-device support.",
 comps:["Mobile clients","Key distribution server","Message relay","Attachment storage","Push notification service","Contact discovery"],
 flows:[["Client","Key server","publish/fetch public keys",true],["Client","Relay","encrypted messages",true],["Client","Attachment store","encrypted blobs",true],["Relay","Push service","notification",true],["Client","Contact discovery","hashed phone numbers",true]],
 threats:[["S","Server substitutes a public key and performs a MITM","Safety numbers / key verification, key transparency logs, alerts on key change","Critical"],
  ["I","Metadata (who talks to whom, when) collected even with E2EE","Sealed sender, minimal logging, padding, short retention","High"],
  ["I","Contact discovery leaks users' address books","Private set intersection or secure enclaves; rate limits","High"],
  ["E","Compromised device or new linked device reads all messages","Device linking requires confirmation on existing device; notify on new device; forward secrecy","High"],
  ["T","Malicious attachment exploits the client parser","Sandboxed media parsing, memory-safe decoders, fuzzing","High"],
  ["I","Push notifications reveal message content","Send only a wake-up signal; fetch and decrypt on device","Medium"],
  ["D","Spam and abuse are hard to moderate with E2EE","Rate limits, reporting that shares the reported messages, reputation","Medium"]],
 first:["Key verification and key transparency to stop server-side MITM","Device-linking controls plus forward secrecy (Double Ratchet) to limit compromise"],
 fu:["How does the Double Ratchet give forward secrecy?","How would you handle backups without breaking E2EE?","What can law enforcement still get?"],
 check:["Identified the key server as the critical trust point","Discussed metadata, not just content","Mentioned forward secrecy","Mentioned multi-device risk","Mentioned client-side parsing attack surface","Mentioned abuse and spam trade-off"]},
{id:"agent",title:"LLM support agent with tools",asked:"Increasingly common everywhere (and fits Tenarai-style AI work)",
 brief:"A customer support chatbot uses RAG over help articles and past tickets, can look up orders, and can issue refunds up to $200.",
 comps:["Chat UI","Agent orchestrator","LLM","Vector store (tickets + docs)","Orders API tool","Refund API tool"],
 flows:[["Customer","Agent","chat messages",true],["Agent","Vector store","retrieve context",false],["Agent","LLM","prompt + context",true],["LLM","Agent","tool calls",true],["Agent","Refund API","issue refund",false]],
 threats:[["E","Prompt injection (direct or hidden in a ticket) triggers refunds","Refund tool enforces limits server-side, per-user scope, human approval above threshold","Critical"],
  ["I","Retrieval returns other customers' tickets","Filter retrieval by the authenticated customer before the LLM sees it","Critical"],
  ["I","System prompt or API keys leak","No secrets in prompts; tools use their own scoped credentials","Medium"],
  ["T","Model output rendered as HTML/markdown executes script or exfiltrates via image URLs","Encode output; block external images/links or allow-list them","High"],
  ["S","Agent acts on a different user's order","Tools take the user from the session, never from model-generated parameters","High"],
  ["D","Cost exhaustion with long or looping conversations","Token and tool-call budgets, rate limits","Medium"],
  ["R","No trace of why a refund happened","Log prompts, retrieved docs and tool calls with request IDs","Medium"]],
 first:["Authorization in the tools, not the prompt: user-scoped, server-enforced refund limits and approvals","Per-customer retrieval filtering so data can't leak across users"],
 fu:["The prompt says 'never refund more than $200'. Is that a control?","How would you red-team this before launch?","How do you test indirect injection?"],
 check:["Treated model output as untrusted","Put limits in tool code, not the prompt","Covered indirect prompt injection","Covered cross-customer data leakage in RAG","Covered insecure output handling","Covered logging/observability"]},
{id:"webhooks",title:"Customer-configured webhooks",asked:"Common at SaaS and developer-platform companies (Stripe, GitHub style)",
 brief:"Customers register a URL; your platform sends signed JSON events to it when things change, with retries.",
 comps:["Customer dashboard","Webhook config API","Event queue","Delivery workers","Customer endpoints (internet)"],
 flows:[["Customer","Config API","register URL",true],["Platform","Event queue","events",false],["Workers","Customer URL","HTTP POST",true],["Workers","Logs/dashboard","delivery results",false]],
 threats:[["E","SSRF: URL points to internal services or cloud metadata","Resolve and block private/link-local IPs at connect time, no redirects, egress proxy in an isolated network","Critical"],
  ["I","Response bodies shown in the dashboard leak internal data","Show only status code and timing","High"],
  ["S","Receivers can't tell real events from forged ones","HMAC signature with timestamp, documented verification, secret rotation","High"],
  ["I","Events sent to a URL the customer no longer controls","Verification challenge when registering; alert on repeated failures","Medium"],
  ["D","Slow endpoints tie up workers; huge fan-out","Timeouts, per-customer concurrency limits, circuit breakers","Medium"],
  ["I","Events include more data than needed","Thin events with IDs; consumer fetches details with auth","Medium"]],
 first:["SSRF-safe delivery from an isolated egress network","Signed events with timestamps so receivers can verify"],
 fu:["How does DNS rebinding defeat a simple IP check?","How would you rotate signing secrets without breaking customers?"],
 check:["Spotted SSRF immediately","Mentioned DNS rebinding / connect-time checks","Mentioned signing for receivers","Mentioned not reflecting response bodies","Mentioned DoS controls"]},
{id:"reset",title:"Password reset and account recovery",asked:"Classic design question at every level",
 brief:"Users who forget their password request a reset link by email. Support can also help users who lost access to their email.",
 comps:["Login page","Reset API","Email provider","Token store","Support console"],
 flows:[["User","Reset API","request reset",true],["Reset API","Email provider","send link",true],["User","Reset API","submit token + new password",true],["Support agent","Support console","manual recovery",true]],
 threats:[["S","Predictable or brute-forceable reset tokens","CSPRNG tokens, stored hashed, short expiry, single use, rate limits","Critical"],
  ["S","Host header poisoning sends links to attacker domain","Build links from configuration, never from the request Host","High"],
  ["I","Response reveals whether an email is registered","Identical responses and timing","Low"],
  ["S","Social engineering of support for manual recovery","Strict identity verification, cooling-off period, notify the old email, dual approval","High"],
  ["E","Existing sessions survive the reset","Invalidate sessions and refresh tokens after reset","High"],
  ["R","No trail of recovery actions","Audit log and user notification","Medium"]],
 first:["Strong single-use, short-lived tokens with rate limits","Support recovery treated as a high-risk flow with verification and notifications"],
 fu:["What if the user's email account is compromised?","How do passkeys change recovery?"],
 check:["Covered token randomness, expiry, single use","Covered host header poisoning","Covered user enumeration","Covered support social engineering","Covered session invalidation"]}
];

// ============ TRIAGE LAB ============
window.TRIAGE = [
{id:"t-idor",title:"Access other customers' invoices",reporter:"High",
 body:"GET /api/v2/invoices/{id} returns invoice PDFs. Invoice IDs are sequential integers. Logged in as user A, I requested IDs 10400 to 10450 and received 51 invoices belonging to other customers, including names, addresses and amounts.",
 verdict:"Valid",sev:"High",vec:"AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
 why:"Classic BOLA. CVSS gives 6.5 (Medium) because only confidentiality is affected, but sequential IDs make every customer's PII trivially harvestable, so most programmes rate it High. This is where context overrides the raw score.",
 next:"Confirm scope (all invoices? other object types?), check logs for prior exploitation, hotfix with an ownership check, and add two-user authorization tests."},
{id:"t-self",title:"XSS in my profile nickname",reporter:"Medium",
 body:"The nickname field on /settings accepts <script>alert(1)</script> and it fires on my own settings page. The nickname is not shown anywhere else. The settings form has a CSRF token.",
 verdict:"Informative",sev:"None",vec:"",
 why:"Self-XSS: only the attacker sees it and it cannot be triggered on another user (CSRF-protected form, not rendered elsewhere). Fix it as a hygiene issue, but it is not a valid security impact for most programmes.",
 next:"Thank the researcher, explain why, ask if they can show it rendering for another user. Still fix the missing encoding as defence in depth."},
{id:"t-hdr",title:"Missing X-Frame-Options on www",reporter:"Medium",
 body:"https://www.example.com (marketing site) does not send X-Frame-Options or CSP frame-ancestors, so it can be framed. Clickjacking possible.",
 verdict:"Informative",sev:"None",vec:"",
 why:"Clickjacking needs a sensitive one-click action on the framed page. A static marketing page has none, so there is no impact.",
 next:"Close as informative with a short explanation. Setting the header centrally at the CDN is still good hygiene."},
{id:"t-ssrf",title:"SSRF in invoice PDF generator to AWS credentials",reporter:"Critical",
 body:"The 'export to PDF' feature renders HTML with a headless browser. Including <iframe src=\"http://169.254.169.254/latest/meta-data/iam/security-credentials/pdf-role\"> in the invoice note returns temporary AWS credentials inside the PDF. I stopped after confirming the credentials were valid with sts get-caller-identity.",
 verdict:"Valid",sev:"Critical",vec:"AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
 why:"Any user can obtain the PDF service's IAM credentials. Scope changes from the app to the AWS account, and what the role can do determines the full impact. The researcher stopped at a safe proof.",
 next:"Treat as an incident: revoke the role's sessions, check CloudTrail for use of those credentials, enforce IMDSv2, block metadata from the renderer, sanitise HTML input, and reduce the role's permissions."},
{id:"t-stored",title:"Stored XSS in support ticket, fires in agent console",reporter:"High",
 body:"The ticket subject is rendered unescaped in the internal support console. A customer can submit a ticket whose subject contains a script; when a support agent opens the ticket, it runs in the agent's session on support.example.com, which can view any customer account.",
 verdict:"Valid",sev:"High",vec:"AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
 why:"An ordinary customer can attack privileged staff and act with their access across all customers. User interaction is needed (an agent opens the ticket), which is routine.",
 next:"Fix output encoding in the console, add a strict CSP to internal tools, review agent session scope, and search existing tickets for payloads."},
{id:"t-rate",title:"No rate limit on login",reporter:"High",
 body:"I sent 1,000 login attempts for my own account in 2 minutes from one IP with no lockout, CAPTCHA or delay. The final correct password succeeded. MFA is not enabled by default.",
 verdict:"Valid",sev:"Medium",vec:"AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
 why:"Unlimited attempts plus no default MFA makes credential stuffing and brute force practical. Many programmes rate missing rate limits as Low or Informative unless impact is shown; here login is the most sensitive endpoint, so Medium is defensible.",
 next:"Add per-account and per-IP throttling, breached-password checks and bot detection on login, and push MFA adoption. Check logs for stuffing campaigns."},
{id:"t-git",title:"Exposed .git directory with live secrets",reporter:"Critical",
 body:"https://legacy.example.com/.git/ is accessible. I reconstructed the repository and found config/production.yml containing a live Stripe secret key (sk_live_...). I did not use the key beyond confirming it is valid with a read-only balance call.",
 verdict:"Valid",sev:"Critical",vec:"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
 why:"Unauthenticated access to source code and a live payment secret that can read and create charges and refunds.",
 next:"Rotate the Stripe key immediately, review Stripe logs for misuse, block /.git at the server, scan all hosts for exposed VCS folders, and move secrets out of the repo."},
{id:"t-redir",title:"Open redirect on logout",reporter:"Medium",
 body:"https://app.example.com/logout?next=https://evil.com redirects the user to any external site after logging out.",
 verdict:"Valid",sev:"Low",vec:"AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
 why:"On its own, an open redirect mainly helps phishing. CVSS gives 4.3, but most programmes rate it Low unless it chains into something worse, such as leaking OAuth codes or tokens.",
 next:"Fix with an allow-list of relative paths. Ask whether the same parameter is used in the OAuth flow, which would raise severity."},
{id:"t-takeover",title:"Subdomain takeover on status.example.com",reporter:"High",
 body:"status.example.com is a CNAME to example-status.s3-website-us-east-1.amazonaws.com, which did not exist. I created the bucket in my own account and now serve a proof page on status.example.com. Session cookies are host-only on app.example.com.",
 verdict:"Valid",sev:"Medium",vec:"AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
 why:"An attacker controls content on a trusted subdomain: convincing phishing, possible abuse of parent-domain cookies or CORS/CSP allow-lists that trust *.example.com. Host-only session cookies limit it to Medium.",
 next:"Remove or repoint the DNS record, reclaim the bucket name, check CORS/CSP/OAuth allow-lists for wildcards, and add monitoring for dangling records."}
];

// ============ INCIDENT SIMULATIONS ============
window.IR = [
{id:"key",title:"AWS access key leaked on GitHub",intro:"Friday 18:40. GitHub secret scanning alerts that an AWS access key for the ci-deployer IAM user was pushed to a public repository 25 minutes ago.",
 steps:[
  {q:"What do you do first?",o:[["Deactivate the access key and confirm no other secrets are in that commit",2,"Correct. Contain first. Attackers scan GitHub for keys within minutes."],["Open a ticket for the owning team to rotate the key on Monday",0,"Far too slow. Keys are often abused within minutes of exposure."],["Start reviewing CloudTrail to see if it was used before doing anything",1,"Investigation matters, but every minute the key is live is more risk. Deactivate first, then investigate."]]},
  {q:"The key is disabled. Next?",o:[["Delete the IAM user so it can't happen again",0,"Deleting destroys context and may break CI. Preserve evidence first."],["Search CloudTrail across all regions for every API call made with that key since the push",2,"Right. Scope the blast radius across all regions; attackers often spin up resources in unused regions."],["Rewrite git history to remove the key",1,"Worth doing later, but the key is already public and cached. Scoping comes first."]]},
  {q:"CloudTrail shows CreateUser 'support-svc', CreateAccessKey for it, and RunInstances (GPU) in 3 regions. What now?",o:[["Remove the persistence: disable the new user and keys, terminate the instances after snapshotting one, and look for other new roles, Lambdas or policies",2,"Yes. Remove persistence comprehensively and preserve evidence. The attacker created a backdoor user."],["Terminate the instances; the attacker only wanted crypto-mining",1,"Mining is likely, but the new IAM user is persistence. Leaving it lets the attacker back in."],["Wait and watch the attacker to learn their goals",0,"Not appropriate in production with a live backdoor and a growing bill."]]},
  {q:"It's contained. What do you communicate, and to whom?",o:[["Incident channel with security lead, cloud platform owner and finance (cost); written summary with timeline; legal if any data access is possible",2,"Good. Scope who needs to know, including cost and legal. Data access checks decide notification obligations."],["Nothing until the post-mortem next week",0,"Stakeholders need timely updates during an incident."],["Email the whole company about the leaked key",0,"Over-sharing and distracting. Keep communication to the people who need to act."]]},
  {q:"How do you prevent it from happening again?",o:[["Replace the IAM user with OIDC federation from CI to a scoped role, add pre-commit and push-protection secret scanning, and SCPs to block IAM user creation",2,"This removes the long-lived key entirely and adds prevention and detection. That's the class-level fix."],["Remind developers not to commit secrets",0,"Awareness alone won't stop it recurring."],["Rotate all keys every 30 days",1,"Helps a little, but the root cause is a long-lived key existing at all."]]}
 ],summary:["Contain in minutes: disable the key","Scope with CloudTrail across all regions","Remove persistence, preserve evidence","Communicate to the right people, including cost and legal","Fix the class: no long-lived keys (OIDC), push protection, SCP guardrails"]},
{id:"ato",title:"Account takeover wave",intro:"Monday 02:10. Login failures jumped from 200/hour to 90,000/hour from thousands of IPs. Successful logins from new countries are up 15x.",
 steps:[
  {q:"First move?",o:[["Tighten WAF rate limits and enable bot challenges on /login, then confirm it's credential stuffing",2,"Contain the attack surface quickly while you confirm what's happening."],["Block all logins until morning",0,"Takes the whole product down for every legitimate user. Too blunt."],["Block the top 10 IPs",1,"Stuffing campaigns use thousands of rotating IPs; this barely dents it."]]},
  {q:"How do you find the affected accounts?",o:[["Accounts with a success after failures from attack infrastructure, new device or country, and logins from IPs seen in the failure flood",2,"Correct. Combine signals to identify likely compromised accounts."],["Every account that logged in tonight",0,"Too broad; you'd lock out normal users."],["Wait for customers to complain",0,"Reactive and slow; damage continues."]]},
  {q:"You've found 1,800 likely compromised accounts. Action?",o:[["Revoke their sessions and refresh tokens, force password reset, notify them, and check what they did after login (payouts, email changes)",2,"Cut access, then investigate actions like payout or email changes, which attackers make first."],["Force password reset only",1,"Active sessions and refresh tokens would keep working. Revoke them too."],["Email users to recommend changing their passwords",0,"The attacker stays logged in."]]},
  {q:"Long-term fix?",o:[["Breached-password checks, risk-based MFA, per-account throttling, login anomaly detection, and step-up auth for sensitive changes",2,"Layered controls address the class of attack."],["Make passwords require 16 characters",0,"Doesn't help with reused credentials, which is what stuffing exploits."],["Add a CAPTCHA to every page",1,"Some help on login, but it hurts users and is bypassable by solving services."]]}
 ],summary:["Rate-limit and challenge at the edge","Identify compromised accounts with combined signals","Revoke sessions and tokens, reset, notify, review post-login actions","Fix with breached-password checks, MFA and anomaly detection"]},
{id:"zero",title:"Critical library CVE with no patch",intro:"Public advisory: remote code execution in an XML library used across your Java services. A proof of concept is on GitHub. No fixed version yet.",
 steps:[
  {q:"First hour?",o:[["Use SBOMs and image scans to list every service that ships the vulnerable version, including transitive copies",2,"Know your exposure precisely before acting."],["Ask each team in Slack if they use the library",0,"Slow and unreliable; teams often don't know their transitive dependencies."],["Wait for the vendor patch",0,"A public PoC means exploitation may start now."]]},
  {q:"12 services include it. How do you prioritise?",o:[["Check reachability (is the vulnerable parser called with attacker-controlled input?), exposure and trigger conditions, then bucket them",2,"Reachability plus exposure separates emergencies from routine patching."],["Treat all 12 as critical and page every team",1,"Safe but wasteful; some services may not even load the code."],["Sort by CVSS score",0,"Every service has the same CVSS; it doesn't tell you which are exposed."]]},
  {q:"Two internet-facing services parse customer XML uploads. Containment?",o:[["Disable external entities in parser config, add a WAF virtual patch, restrict egress, and consider pausing the feature",2,"Layered mitigation while waiting for a fix. Disabling the trigger is the strongest step."],["Add a WAF rule only",1,"Useful but bypassable; combine with config changes and egress limits."],["Remove the library from the services",0,"Usually not feasible in hours and likely breaks the feature."]]},
  {q:"How do you handle the remaining risk?",o:[["Hunt logs for exploitation, brief the client in business terms, and record a time-bound risk acceptance with an owner",2,"Detection plus documented, owned, time-limited acceptance."],["Close the issue since mitigations are in place",0,"Residual risk must stay tracked until the fix ships."],["Keep it within the security team",0,"The business owner must understand and accept residual risk."]]}
 ],summary:["Inventory with SBOM and image scans","Prioritise by reachability and exposure","Contain: disable the trigger, virtual patch, restrict egress","Hunt, communicate, document a time-bound acceptance; upgrade everywhere when fixed"]}
];

// ============ CODING LAB ============
window.CODING = [
{id:"brute",fn:"failedLoginIPs",title:"Find brute-force IPs",
 prompt:"Each log line looks like <code>2026-10-09T02:10:01Z FAIL user=alice ip=203.0.113.5</code> or <code>... OK user=bob ip=...</code>. Some lines are malformed. Return the IPs with at least <code>threshold</code> FAIL entries, sorted by failure count (highest first), ties by IP ascending.",
 starter:`function failedLoginIPs(lines, threshold) {
  // your code here
  return [];
}`,
 tests:[
  {label:"threshold 3",args:()=>[window.__LOGS(),3],exp:["2.2.2.2","1.1.1.1"]},
  {label:"threshold 1",args:()=>[window.__LOGS(),1],exp:["2.2.2.2","1.1.1.1","3.3.3.3"]},
  {label:"threshold 6",args:()=>[window.__LOGS(),6],exp:[]},
  {label:"OK lines and a user named FAILUSER are ignored",args:()=>[["t OK user=FAILUSER ip=9.9.9.9","t OK user=x ip=9.9.9.9"],1],exp:[]}
 ],
 hints:["Use an object or Map to count per IP in one pass.","A regex like /\\sFAIL\\s.*\\bip=([0-9a-fA-F:.]+)/ pulls out the IP only for FAIL lines.","Sort with (a, b) => counts[b] - counts[a] || a.localeCompare(b)."],
 sol:`function failedLoginIPs(lines, threshold) {
  const counts = {};
  for (const line of lines) {
    const m = line.match(/\\sFAIL\\s.*\\bip=([0-9a-fA-F:.]+)/);
    if (m) counts[m[1]] = (counts[m[1]] || 0) + 1;
  }
  return Object.keys(counts)
    .filter(ip => counts[ip] >= threshold)
    .sort((a, b) => counts[b] - counts[a] || a.localeCompare(b));
}`,
 py:`import re
from collections import Counter

PAT = re.compile(r"\\sFAIL\\s.*\\bip=([0-9a-fA-F:.]+)")

def failed_login_ips(lines, threshold):
    counts = Counter(m.group(1) for line in lines if (m := PAT.search(line)))
    hits = [ip for ip, n in counts.items() if n >= threshold]
    return sorted(hits, key=lambda ip: (-counts[ip], ip))`,
 talk:"Mention streaming huge files line by line, time windows (sliding deque), and flagging a success after many failures."},
{id:"secrets",fn:"findSecrets",title:"Detect leaked secrets",
 prompt:"Return every AWS access key ID (<code>AKIA</code> or <code>ASIA</code> followed by 16 uppercase letters or digits) and GitHub classic token (<code>ghp_</code> followed by 36 letters or digits) in the text, in order of appearance, as <code>\"aws:&lt;value&gt;\"</code> or <code>\"github:&lt;value&gt;\"</code>. They must be whole words.",
 starter:`function findSecrets(text) {
  // your code here
  return [];
}`,
 tests:[
  {label:"one of each",args:()=>["key=AKIAIOSFODNN7EXAMPLE and token ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8 here"],exp:["aws:AKIAIOSFODNN7EXAMPLE","github:ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"]},
  {label:"too short",args:()=>["AKIA1234 is not a key"],exp:[]},
  {label:"not a whole word",args:()=>["xAKIAIOSFODNN7EXAMPLE"],exp:[]},
  {label:"lowercase is not a key",args:()=>["akiaiosfodnn7example"],exp:[]},
  {label:"temporary (ASIA) key",args:()=>["creds: ASIAABCDEFGHIJKLMNOP"],exp:["aws:ASIAABCDEFGHIJKLMNOP"]}
 ],
 hints:["One global regex with alternation keeps the order of appearance.","\\b marks word boundaries.","Loop with re.exec(text) until it returns null."],
 sol:`function findSecrets(text) {
  const re = /\\b(?:(?:AKIA|ASIA)[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})\\b/g;
  const out = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    out.push((m[0].startsWith('ghp_') ? 'github:' : 'aws:') + m[0]);
  }
  return out;
}`,
 py:`import re
PAT = re.compile(r"\\b(?:(?:AKIA|ASIA)[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})\\b")

def find_secrets(text):
    return [("github:" if m.startswith("ghp_") else "aws:") + m for m in PAT.findall(text)]`,
 talk:"Mention entropy checks for generic secrets, verifying whether a key is live, push protection, and that the response is to rotate first."},
{id:"redirect",fn:"isSafeRedirect",title:"Safe redirect check",
 prompt:"Return <code>true</code> only for a relative path that starts with a single <code>/</code> (not <code>//</code> or <code>/\\</code>), or an absolute <code>https</code> URL whose host is exactly <code>app.example.com</code>. Reject anything with whitespace or control characters.",
 starter:`function isSafeRedirect(target) {
  // your code here
  return false;
}`,
 tests:[
  {label:"/dashboard",args:()=>["/dashboard"],exp:true},
  {label:"//evil.com",args:()=>["//evil.com"],exp:false},
  {label:"/\\evil.com",args:()=>["/\\evil.com"],exp:false},
  {label:"/<TAB>/evil.com (browsers strip tabs)",args:()=>["/\t/evil.com"],exp:false},
  {label:"https://app.example.com/settings",args:()=>["https://app.example.com/settings"],exp:true},
  {label:"https://APP.EXAMPLE.COM/x",args:()=>["https://APP.EXAMPLE.COM/x"],exp:true},
  {label:"https://app.example.com.evil.com/",args:()=>["https://app.example.com.evil.com/"],exp:false},
  {label:"http://app.example.com/",args:()=>["http://app.example.com/"],exp:false},
  {label:"javascript:alert(1)",args:()=>["javascript:alert(1)"],exp:false},
  {label:"empty string",args:()=>[""],exp:false}
 ],
 hints:["Check whitespace/control characters first: /[\\u0000-\\u001F\\s]/.","For absolute URLs, parse with new URL() and compare protocol and hostname exactly.","new URL() lowercases the hostname for you."],
 sol:`function isSafeRedirect(target) {
  if (typeof target !== 'string' || target.length === 0) return false;
  if (/[\\u0000-\\u001F\\s]/.test(target)) return false;
  if (target.startsWith('/')) {
    return !target.startsWith('//') && !target.startsWith('/\\\\');
  }
  try {
    const u = new URL(target);
    return u.protocol === 'https:' && u.hostname === 'app.example.com';
  } catch (e) {
    return false;
  }
}`,
 py:`from urllib.parse import urlsplit
import re

def is_safe_redirect(target: str) -> bool:
    if not target or re.search(r"[\\x00-\\x1f\\s]", target):
        return False
    if target.startswith("/"):
        return not target.startswith("//") and not target.startswith("/\\\\")
    parts = urlsplit(target)
    return parts.scheme == "https" and (parts.hostname or "") == "app.example.com"`,
 talk:"Explain why string checks like startsWith('https://app.example.com') fail, and why allow-lists beat block-lists."},
{id:"jwt",fn:"jwtProblems",title:"JWT sanity checker",
 prompt:"Given a JWT string and the current time <code>now</code> (seconds), decode the header and payload (Base64url) and return a sorted array of problems: <code>\"alg-none\"</code> if alg is none (any case), <code>\"no-exp\"</code> if exp is missing, <code>\"expired\"</code> if exp &lt;= now, <code>\"wrong-aud\"</code> if aud is not <code>\"orders-api\"</code>. Return <code>[\"malformed\"]</code> if it can't be decoded or doesn't have 3 parts. (Signature checking is out of scope here.)",
 starter:`function jwtProblems(token, now) {
  // your code here
  return [];
}`,
 tests:[
  {label:"valid token",args:()=>[window.__JWT({alg:"RS256"},{exp:2000,aud:"orders-api"}),1000],exp:[]},
  {label:"alg none",args:()=>[window.__JWT({alg:"none"},{exp:2000,aud:"orders-api"}),1000],exp:["alg-none"]},
  {label:"expired",args:()=>[window.__JWT({alg:"RS256"},{exp:500,aud:"orders-api"}),1000],exp:["expired"]},
  {label:"exp equal to now counts as expired",args:()=>[window.__JWT({alg:"HS256"},{exp:1000,aud:"orders-api"}),1000],exp:["expired"]},
  {label:"several problems",args:()=>[window.__JWT({alg:"NONE"},{aud:"billing-api"}),1000],exp:["alg-none","no-exp","wrong-aud"]},
  {label:"malformed",args:()=>["abc.def",1000],exp:["malformed"]}
 ],
 hints:["Base64url: replace - with + and _ with /, then add = padding to a multiple of 4, then atob().","Wrap decoding in try/catch to return ['malformed'].","Sort the array before returning."],
 sol:`function jwtProblems(token, now) {
  const parts = token.split('.');
  if (parts.length !== 3) return ['malformed'];
  const dec = s => JSON.parse(atob(
    s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)));
  let header, payload;
  try { header = dec(parts[0]); payload = dec(parts[1]); }
  catch (e) { return ['malformed']; }
  const problems = [];
  if (String(header.alg).toLowerCase() === 'none') problems.push('alg-none');
  if (typeof payload.exp !== 'number') problems.push('no-exp');
  else if (payload.exp <= now) problems.push('expired');
  if (payload.aud !== 'orders-api') problems.push('wrong-aud');
  return problems.sort();
}`,
 py:`import base64, json

def jwt_problems(token, now):
    parts = token.split(".")
    if len(parts) != 3:
        return ["malformed"]
    dec = lambda s: json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
    try:
        header, payload = dec(parts[0]), dec(parts[1])
    except Exception:
        return ["malformed"]
    p = []
    if str(header.get("alg", "")).lower() == "none": p.append("alg-none")
    if not isinstance(payload.get("exp"), (int, float)): p.append("no-exp")
    elif payload["exp"] <= now: p.append("expired")
    if payload.get("aud") != "orders-api": p.append("wrong-aud")
    return sorted(p)`,
 talk:"Say clearly that real validation must verify the signature with a pinned algorithm and keys from JWKS; this script only lints claims."},
{id:"join",fn:"safeJoin",title:"Path traversal guard",
 prompt:"Given a base directory and a user-supplied relative path (forward slashes only), return the normalised absolute path if it stays inside base, otherwise <code>null</code>. Reject absolute user paths and null bytes. Ignore empty and <code>.</code> segments; <code>..</code> goes up one level but must never go above base.",
 starter:`function safeJoin(base, userPath) {
  // your code here
  return null;
}`,
 tests:[
  {label:"simple file",args:()=>["/srv/files","report.pdf"],exp:"/srv/files/report.pdf"},
  {label:"../etc/passwd",args:()=>["/srv/files","../etc/passwd"],exp:null},
  {label:"a/../../etc",args:()=>["/srv/files","a/../../etc"],exp:null},
  {label:"a/./b/../c.txt",args:()=>["/srv/files","a/./b/../c.txt"],exp:"/srv/files/a/c.txt"},
  {label:"absolute path",args:()=>["/srv/files","/etc/passwd"],exp:null},
  {label:"double slash",args:()=>["/srv/files","a//b"],exp:"/srv/files/a/b"},
  {label:"null byte",args:()=>["/srv/files","a.txt\u0000.png"],exp:null}
 ],
 hints:["Split base into segments and remember its length.","Walk the user path segments; pop on '..' but return null if that would go below base.","Join with '/' and add the leading slash."],
 sol:`function safeJoin(base, userPath) {
  if (userPath.startsWith('/') || userPath.includes('\\0')) return null;
  const parts = base.split('/').filter(Boolean);
  const depth = parts.length;
  for (const seg of userPath.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (parts.length === depth) return null;
      parts.pop();
    } else {
      parts.push(seg);
    }
  }
  return '/' + parts.join('/');
}`,
 py:`import os

def safe_join(base, user_path):
    if user_path.startswith("/") or "\\0" in user_path:
        return None
    base = os.path.realpath(base)
    full = os.path.realpath(os.path.join(base, user_path))   # also resolves symlinks
    return full if full.startswith(base + os.sep) else None`,
 talk:"Mention that real code should resolve symlinks (realpath), decode URL encoding before checking, and preferably map IDs to files instead of accepting names."}
];

// ============ BEHAVIORAL ============
window.BEH = [
{id:"tmay",q:"Tell me about yourself.",tests:"Clarity, level, and why this role.",lp:["Ownership"],
 guide:"90 seconds: present (current scope and one impact number), past (two proof points: CVEs, runtime security work), future (why this role). End with a hook they can ask about.",
 outline:"I'm a senior application security engineer with [X] years across web, API, mobile and cloud. Right now I [current scope] and recently [impact with a number]. Before that I [proof point, e.g. Kubernetes runtime security at AccuKnox] and found [CVEs]. I'm looking to [move from finding to preventing at scale], which is why this role fits."},
{id:"conflict",q:"Tell me about a time you disagreed with an engineering team about a security fix.",tests:"Influence without authority, judgement, respect.",lp:["Have Backbone; Disagree and Commit","Earn Trust"],
 guide:"Show you understood their constraint, brought evidence (exploit, impact), offered options, and that the right person decided. Include what you'd do differently.",
 outline:"S: [team] wanted to ship [feature] with [issue]. T: I had to get the risk reduced without blocking the launch. A: I reproduced it, showed [impact] in a 10-minute demo, proposed [mitigation] for launch plus [full fix] in [sprint], and documented a risk acceptance with [owner]. R: Shipped on time, fix landed in [N] days; the team now asks for reviews earlier."},
{id:"fail",q:"Tell me about a time you failed or made a mistake.",tests:"Honesty, ownership, learning. A story with no real mistake reads as fiction.",lp:["Ownership","Learn and Be Curious"],
 guide:"Pick a real mistake with real consequences, own it in the first sentence, explain the fix and the system change you made so it couldn't recur.",
 outline:"S/T: I [missed / misjudged] [what]. Impact: [consequence]. A: I [told who, how fast], fixed [immediate], then changed [process/tool]. R: [measurable improvement]. Learning: I now [behaviour]."},
{id:"influence",q:"Describe a time you convinced leadership to invest in security.",tests:"Business framing, data, prioritisation.",lp:["Think Big","Dive Deep"],
 guide:"Translate risk into money, customers, compliance or speed. Show the decision you asked for and the result.",
 outline:"S: [problem with data: e.g. N criticals open, MTTR M days]. T: Get [budget/headcount/time]. A: Built a one-page case: risk in business terms, options with cost, recommended option, success metric. R: Approved; [metric] improved from [a] to [b]."},
{id:"ambiguity",q:"Tell me about a time you had to deliver with incomplete information.",tests:"Prioritisation under uncertainty.",lp:["Bias for Action"],
 guide:"Show how you scoped quickly, stated assumptions, made a reversible decision, and adjusted.",
 outline:"S: [situation with unknowns]. A: listed what I knew and didn't, chose [reversible action], set a checkpoint, told stakeholders my assumptions. R: [outcome], and what new information changed."},
{id:"scale",q:"How have you scaled security beyond yourself?",tests:"Senior-level leverage: automation, paved roads, champions.",lp:["Invent and Simplify"],
 guide:"Pick one thing that kept working without you: a tool, rule set, template, training, or champions programme. Give adoption and impact numbers.",
 outline:"S: I was the bottleneck for [reviews/triage]. A: built [automation / custom rules / template / champions]. R: [N teams adopted], [time saved], [findings reduced by X%]."},
{id:"incident",q:"Walk me through a security incident you handled.",tests:"Calm sequence, communication, honesty about mistakes.",lp:["Ownership","Deliver Results"],
 guide:"Detect, contain, scope, eradicate, recover, learn. Include one thing that went wrong in the response and what you changed.",
 outline:"Detection: [signal]. Containment: [first action and time]. Scope: [how]. Communication: [who, cadence]. Root cause: [cause]. Fix: [class-level change]. What I'd do differently: [honest point]."},
{id:"customer",q:"Tell me about explaining a technical risk to a non-technical stakeholder or client.",tests:"Communication for consulting roles.",lp:["Customer Obsession"],
 guide:"Use the impact sentence: who could do what to whom, how likely, what it costs to fix. Show the decision they made.",
 outline:"S: [client/stakeholder] wanted [launch]. A: I explained '[plain-language impact]', gave two options with effort, recommended one. R: They chose [option]; [outcome]."},
{id:"why",q:"Why this company / why leave pentesting for product security?",tests:"Motivation and fit.",lp:[],
 guide:"Connect your past (finding bugs) to their need (preventing them at scale). Mention something specific about their product or engineering culture.",
 outline:"I've spent [years] finding [what]; I want to build the systems that stop those bugs from shipping. [Company] is interesting because [specific: product, scale, AI work]. My offensive background makes guardrails realistic."},
{id:"priorit",q:"You have 50 open high findings and a launch next week. What do you do?",tests:"Risk-based prioritisation; not calling everything critical.",lp:["Deliver Results"],
 guide:"Re-score with context, pick the few that matter for this launch, offer mitigations, document the rest with owners and dates.",
 outline:"I'd re-rank by exploitability and exposure for the launch scope, fix the top [3-5] that are reachable from the internet, mitigate others (flags, WAF, config), and record time-bound acceptances for the rest with owners."}
];

window.LOOPS = [
 ["Big tech (Google, Meta, Amazon, Microsoft)","Recruiter → tech screen (coding + security) → 4-6 onsite rounds: coding, security design/threat model, domain deep dive (web, cloud, detection), code review, behavioral (Amazon: Leadership Principles in every round)","Fundamentals depth, coding bar, structured design thinking, behavioral evidence"],
 ["Product/SaaS companies (Stripe, Atlassian, Datadog, Cloudflare)","Screen → 4-5 rounds: threat model a feature, cloud IAM or infra, code review or coding (practical: parse logs, spot bug in a diff), incident scenario, behavioral","Prioritisation under ambiguity, pragmatic fixes, partnering with engineers"],
 ["Fintech / payments (Razorpay, banks)","Screen → code review, threat model of payment flows, PCI and API security, triage exercise, managerial round","Payment flow risks, compliance, gateway and API security"],
 ["Security vendors / bug bounty platforms (HackerOne, Bugcrowd, SentinelOne)","Screen → live triage with CVSS scoring, vuln explanation (XSS, SQLi, CSRF, CORS), report writing, customer-facing scenario","Clear severity reasoning, writing quality, customer handling"],
 ["Consulting / services (Tenarai, Big 4)","Technical (AWS, DevSecOps, appsec) → client-communication round → HR","Explaining risk to clients, negotiating fixes, breadth across stacks"]
];
