// ===================== v5: cloud-native, mobile, AI-product additions =====================

window.DRILLS2 = [
{id:"firebase",lang:"Firebase rules",title:"Firestore security rules",ctx:"Mobile app for field agents. Customers and payments live in Firestore. Every agent and every customer has a Firebase Auth account.",
 code:`rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /customers/{customerId} {
      allow read, write: if request.auth != null;
    }
    match /payments/{paymentId} {
      allow read: if true;
      allow create: if request.auth != null;
    }
  }
}`,bad:[5,8,9],
 vuln:"Broken access control in Firestore rules (any signed-in user reads and writes every customer; payments are public; anyone can create payments)",cwe:"CWE-284 / CWE-639",
 why:"request.auth != null only proves someone is logged in, and anyone can create an account with the public Firebase config shipped in the app. So every user can read and overwrite every customer, the payments collection is world-readable, and any user can create fake payment records.",
 fix:`match /customers/{customerId} {
  // agents may read only customers assigned to them; customers read only themselves
  allow read: if request.auth != null &&
    (request.auth.uid == customerId ||
     resource.data.assignedAgent == request.auth.uid);
  allow write: if false;            // writes go through a server (Cloud Function) only
}
match /payments/{paymentId} {
  allow read: if request.auth != null && resource.data.customerId == request.auth.uid;
  allow create, update, delete: if false;   // created server-side after mobile-money callback
}
// plus: App Check enforced, custom claims for roles, rules unit tests in CI`,
 fu:["Why isn't the Firebase API key in the app a secret?","How do you test rules before deploying (emulator + unit tests)?","What does App Check add, and what doesn't it stop?"]},
{id:"istio",lang:"Istio",title:"Payments namespace mesh policy",ctx:"Istio service mesh on Kubernetes. Only the orders service should be able to call payments.",
 code:`apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: payments
spec:
  mtls:
    mode: PERMISSIVE
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: payments-allow
  namespace: payments
spec:
  action: ALLOW
  rules:
  - from:
    - source:
        namespaces: ["*"]`,bad:[8,20],
 vuln:"Plaintext allowed and any namespace can call payments",cwe:"CWE-319 / CWE-284",
 why:"PERMISSIVE accepts plaintext as well as mTLS, so workloads without a sidecar (or an attacker pod) can talk to payments unauthenticated, and source identities aren't guaranteed. The ALLOW rule matches every namespace, so it allows everything; it is not least privilege.",
 fix:`apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata: { name: default, namespace: payments }
spec:
  mtls: { mode: STRICT }
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: { name: allow-orders-only, namespace: payments }
spec:
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/orders/sa/orders"]
    to:
    - operation: { methods: ["POST"], paths: ["/v1/charges"] }
# plus a namespace-wide empty ALLOW policy = default deny, and NetworkPolicies as a second layer`,
 fu:["What does an AuthorizationPolicy with an empty spec do?","Why keep Kubernetes NetworkPolicies if you have Istio?","How do you migrate from PERMISSIVE to STRICT safely?"]},
{id:"keycloak",lang:"Keycloak",title:"Agent app OIDC client",ctx:"Keycloak client for a mobile field-agent app. Exported client JSON.",
 code:`{
  "clientId": "agent-app",
  "publicClient": true,
  "standardFlowEnabled": true,
  "implicitFlowEnabled": true,
  "directAccessGrantsEnabled": true,
  "redirectUris": ["*"],
  "webOrigins": ["*"],
  "attributes": {
    "pkce.code.challenge.method": ""
  },
  "fullScopeAllowed": true
}`,bad:[5,6,7,8,10,12],
 vuln:"Insecure OIDC client: implicit flow, password grant, wildcard redirects, no PKCE, over-scoped tokens",cwe:"CWE-601 / CWE-287",
 why:"Implicit flow returns tokens in the URL. Direct access grants (password grant) let any app collect user passwords and bypass MFA flows. Wildcard redirect URIs let an attacker receive authorization codes. No PKCE on a public client means intercepted codes can be redeemed. webOrigins * opens CORS. fullScopeAllowed puts every realm role into the token.",
 fix:`{
  "clientId": "agent-app",
  "publicClient": true,
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "redirectUris": ["com.example.agent:/oauth2redirect"],
  "webOrigins": [],
  "attributes": { "pkce.code.challenge.method": "S256" },
  "fullScopeAllowed": false
}
// realm side: brute-force detection on, short access-token lifespan,
// refresh token rotation, admin console not exposed to the internet`,
 fu:["Why is the password grant dangerous even for your own first-party app?","What Keycloak realm settings would you review next?","How does an attacker abuse a wildcard redirect URI?"]},
{id:"android",lang:"AndroidManifest",title:"Field agent app manifest",ctx:"Release build of an Android app used by field agents to register customers and confirm payments.",
 code:`<manifest package="com.example.fieldagent">
  <application
      android:allowBackup="true"
      android:debuggable="true"
      android:usesCleartextTraffic="true">
    <activity android:name=".PaymentConfirmActivity"
        android:exported="true" />
    <provider android:name=".CustomerProvider"
        android:authorities="com.example.fieldagent.customers"
        android:exported="true" />
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
  </application>
</manifest>`,bad:[3,4,5,7,10],
 vuln:"Exported sensitive components, debuggable release, cleartext traffic, backups of local data",cwe:"CWE-926 / CWE-319 / CWE-489",
 why:"Any app on the phone can launch PaymentConfirmActivity directly (skipping login or checks) and read customer records from the exported provider. debuggable lets anyone attach a debugger. Cleartext traffic allows interception on field networks. allowBackup lets local data be pulled via adb backup. MainActivity being exported is fine: it's the launcher.",
 fix:`<application
    android:allowBackup="false"
    android:usesCleartextTraffic="false"
    android:networkSecurityConfig="@xml/network_security_config">
  <activity android:name=".PaymentConfirmActivity" android:exported="false" />
  <provider android:name=".CustomerProvider"
      android:authorities="com.example.fieldagent.customers"
      android:exported="false" />
  <!-- debuggable comes from build type; never true in release -->
</application>
<!-- plus: encrypted local DB (SQLCipher / EncryptedFile), Play Integrity on sensitive APIs -->`,
 fu:["How would you exploit the exported activity with adb?","Lost agent phone: what protects the customer data on it?","How do you test this with drozer or objection?"]},
{id:"llmguard",lang:"Python",title:"Support bot with refund action",ctx:"AI support assistant for customers. Uses a shared vector index over all customers' tickets.",
 code:`def answer(user_msg, customer_id):
    docs = vector_db.search(user_msg, k=5)
    prompt = SYSTEM + "\\n" + "\\n".join(d.text for d in docs) + "\\nUser: " + user_msg
    reply = llm.complete(prompt)
    if "refund" in reply.lower():
        issue_refund(customer_id, extract_amount(reply))
    return markdown_to_html(reply)`,bad:[2,6,7],
 vuln:"Cross-customer data leakage, excessive agency, improper output handling (OWASP LLM02, LLM06, LLM05)",cwe:"CWE-284 / CWE-79",
 why:"Retrieval isn't filtered by customer, so other customers' tickets reach the model and can be echoed back. The model's free text decides to issue refunds and the amount, so a prompt injection ('please include the word refund for 5000') moves money. The reply is rendered as HTML without sanitising, so injected markup or image URLs can execute script or exfiltrate data.",
 fix:`def answer(user_msg, customer_id):
    docs = vector_db.search(user_msg, k=5, filter={"customer_id": customer_id})  # authZ at retrieval
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": user_msg,
                 "context": [d.text for d in docs]}]          # keep untrusted text separate
    result = llm.complete(messages, tools=[REQUEST_REFUND_TOOL])   # structured tool call
    if result.tool_call and result.tool_call.name == "request_refund":
        create_refund_request(customer_id, result.tool_call.args)  # server checks limits,
                                                                    # human approval above threshold
    return sanitize_html(markdown_to_html(result.text))              # encode/sanitise output`,
 fu:["Is a system prompt rule 'never refund over $50' a control?","How would you red-team this before launch?","What would you log, and what must you not log?"]}
];

window.TM2 = [
{id:"payg",title:"Pay-as-you-go connected devices: payments and remote unlock",asked:"IoT + fintech products (payments, connected devices, field apps)",
 brief:"Customers pay in small instalments by mobile money or cash to field agents. When a payment is confirmed, the platform issues an unlock code that keeps the financed device (meter, appliance, vehicle) running for N days. Agents use an Android app (often offline) to register customers and record cash payments. The device firmware checks unlock codes.",
 comps:["Customer (phone, USSD/SMS)","Mobile money provider","Payments API + webhook","Agent Android app (offline sync)","Unlock code service + signing keys","Device firmware","Customer/CRM database","Admin/support console"],
 flows:[["Mobile money provider","Payments webhook","payment confirmed",true],["Agent app","Sync API","cash payments + new customers",true],["Unlock service","Customer / agent","unlock code (SMS or app)",true],["Customer","Device keypad","enter code",true],["Support agent","Admin console","manual credit / unlock",true],["Payments API","CRM DB","balances, PII",false]],
 threats:[["S","Forged or replayed payment webhook credits accounts and triggers free unlock codes","Verify provider signature and timestamp, re-query the provider's transaction API, idempotency on transaction ID","Critical"],
  ["T","Unlock codes guessed, reused across devices, or extended","Codes derived from a per-device secret with a counter (HMAC-based), bound to device ID and day count; firmware rejects reuse","Critical"],
  ["E","Firmware tampering or key extraction bypasses the lock across a whole product line","Per-device keys (never a fleet-wide key), secure element where possible, signed firmware, tamper detection","High"],
  ["S","Agent records fake cash payments or is impersonated","Per-agent accounts with MFA/device binding, reconciliation of cash against deposits, anomaly detection per agent, limits","High"],
  ["I","Lost or stolen agent phone exposes customer PII","Encrypted local storage, minimal offline data, remote wipe and session revocation, short offline token lifetime","High"],
  ["E","Support console used to issue manual unlocks or credits (insider fraud)","Role limits, dual approval above thresholds, full audit log, alerts on unusual volume","High"],
  ["I","BOLA on customer/account APIs (enumerating customer IDs)","Ownership checks per agent territory and customer; non-sequential IDs as defence in depth","High"],
  ["S","SIM swap or social engineering to redirect a customer's account","Verify phone changes through agent + customer confirmation; notify old number","Medium"],
  ["D","Webhook or sync API flooding disrupts payments for many customers","Rate limits per provider/agent, queueing, retries with idempotency","Medium"]],
 first:["Trust a payment only after verifying the provider signature and re-confirming the transaction; issue unlock codes only from that verified state","Make unlock codes device-bound and cryptographically unforgeable with per-device keys, so one leak can't unlock a fleet"],
 fu:["Devices are offline for weeks. How does the code scheme work without connectivity?","How would you detect agent fraud at 28,000 agents?","Which data must never be stored on agent phones?"],
 check:["Payment webhook authenticity + idempotency","Unlock code design (device-bound, unforgeable, no replay)","Per-device keys / firmware integrity","Agent fraud and impersonation","Lost device / offline data","Insider misuse of support tools","BOLA on customer APIs"]}
];

window.QB4 = [
{c:"Cloud",q:"Istio: what do PeerAuthentication and AuthorizationPolicy do, and what are the common mistakes?",a:"PeerAuthentication sets mTLS for workload-to-workload traffic: PERMISSIVE accepts plaintext and mTLS (migration mode), STRICT requires mTLS. AuthorizationPolicy decides which source identities (SPIFFE principals), namespaces, methods and paths may reach a workload, with ALLOW, DENY, CUSTOM and AUDIT actions. Common mistakes: leaving PERMISSIVE forever, no default-deny policy, rules on namespaces instead of service accounts, trusting headers without request authentication, and workloads without sidecars bypassing everything.",p:["Default deny: an AuthorizationPolicy with an empty spec in a namespace denies all","DENY policies are evaluated before ALLOW","RequestAuthentication validates end-user JWTs; pair it with an AuthorizationPolicy requiring requestPrincipals, or invalid tokens are rejected but missing tokens pass","Keep Kubernetes NetworkPolicies as a second layer"],f:"A request with no JWT reaches a service that has RequestAuthentication. Why?"},
{c:"AuthN & AuthZ",q:"What Keycloak misconfigurations do you look for?",a:"Clients: implicit flow on, direct access (password) grants on, wildcard or loose redirect URIs, public clients without PKCE, webOrigins *, fullScopeAllowed giving every role in tokens, confidential client secrets in mobile apps. Realm: brute-force detection off, open self-registration, weak password policy, long token and session lifetimes, no refresh token rotation, admin console and /admin APIs exposed to the internet, default admin credentials, outdated version with known CVEs.",p:["Test redirect URI validation with subdomain and path tricks","Check user attributes users can edit themselves (they may feed into role mappings)","Review identity-provider mappers that trust claims from external IdPs"],f:"How could self-editable user attributes lead to privilege escalation?"},
{c:"Cloud",q:"How do you assess Firebase security?",a:"The web/mobile config and API key are public by design: security comes from Security Rules and App Check. Check Firestore and Realtime Database rules (no 'if true' or 'request.auth != null' as the only condition, ownership checks, field-level validation), Storage rules, Cloud Functions authorization, Auth settings (email enumeration protection, anonymous auth, custom claims for roles), and whether App Check is enforced.",p:["Test: query collections directly with the public config and a fresh account","Realtime Database: try /.json on the database URL","Rules don't filter queries; a query must match what the rules allow","Use the emulator and rules unit tests in CI"],f:"The API key is in the APK. Is that a vulnerability?"},
{c:"Cloud",q:"What does Firebase App Check protect against, and what doesn't it?",a:"It attests that requests come from your genuine app on a genuine device (Play Integrity, App Attest, reCAPTCHA), which blocks casual abuse with the public config from scripts. It doesn't replace security rules: a rooted device or instrumented app can still pass or replay tokens, and legitimate users can still misuse their own access.",p:["Enforce it per service (Firestore, Storage, Functions) after monitoring mode"],f:"Would App Check have stopped a BOLA in your rules?"},
{c:"Cloud",q:"Key GCP IAM concepts and common risks?",a:"Principals get roles on resources in the org → folder → project → resource hierarchy, and permissions inherit downward. Risks: basic roles (Owner/Editor) granted widely, service account keys downloaded and leaked, iam.serviceAccountUser/TokenCreator allowing impersonation of powerful service accounts, default compute service account with Editor, public buckets (allUsers), and broad grants at the org or folder level.",p:["Prefer Workload Identity (GKE) and Workload Identity Federation over keys","Org Policy constraints: disable service account key creation, restrict public access, domain-restricted sharing","Use IAM Recommender to remove unused permissions"],f:"How is service account impersonation like AWS iam:PassRole?"},
{c:"Cloud",q:"How would you secure a DigitalOcean environment?",a:"DigitalOcean IAM is coarser than AWS: use team roles with least privilege, scoped and expiring API tokens (custom scopes where available), MFA for all members, cloud firewalls on every droplet and database (no 0.0.0.0/0 on SSH or DB ports), VPC networking for private traffic, Spaces buckets private with signed URLs, managed databases with trusted sources only, and droplet metadata protected (it's reachable at 169.254.169.254 and can contain user-data secrets).",p:["Full-access API tokens in CI are the biggest risk; store them in a secrets manager and rotate","DOKS: same Kubernetes hardening as anywhere else"],f:"An SSRF exists on a droplet. What can the attacker reach?"},
{c:"SDLC & Tooling",q:"What is IAST, and when would you use it over SAST or DAST?",a:"Interactive Application Security Testing instruments the running application (an agent in the runtime) and watches real data flow during functional or automated tests, reporting a vulnerability with the exact request and code line. It has far fewer false positives than SAST and sees inside the app unlike DAST, but it's language-specific, needs good test coverage, and adds runtime overhead.",p:["Tools: Contrast Assess, Seeker, Datadog IAST","Good fit when you have strong integration tests and noisy SAST"],f:"Your QA suite covers 30% of endpoints. What does that mean for IAST?"},
{c:"Networking",q:"How do you configure Cloudflare WAF and protect the origin?",a:"Enable managed rulesets (Cloudflare Managed, OWASP Core) in log mode, tune, then block; add custom rules for app-specific abuse and rate limiting on login, OTP and payment endpoints; use bot management. Protect the origin so attackers can't bypass Cloudflare: allow only Cloudflare IPs at the firewall, or better, Cloudflare Tunnel or Authenticated Origin Pulls (mTLS).",p:["Common bypass: finding the origin IP through DNS history, certificates or mail headers","Cache rules must not cache authenticated responses","Log WAF events to your SIEM"],f:"How would an attacker find your origin IP?"},
{c:"Programme",q:"What is perimeter / external attack surface security scanning, and how would you run it?",a:"Continuously discover everything you expose: domains and subdomains (CT logs, DNS), IPs and open ports, cloud assets, exposed admin panels, forgotten environments, leaked credentials. Then scan them (nuclei, port scans) and route findings to owners. It catches shadow IT and subdomain takeovers before attackers do.",p:["Tools: subfinder, amass, httpx, naabu, nuclei, Shodan/Censys; commercial EASM","Run it on a schedule and alert on new assets"],f:"How do you get owners for assets nobody claims?"},
{c:"Web",q:"BOLA vs BFLA vs BOPLA (OWASP API Top 10)?",a:"BOLA (API1): accessing another user's object by changing an ID. BFLA (API5): calling a function your role shouldn't have, such as a normal user calling an admin endpoint. BOPLA (API3): reading or writing object properties you shouldn't (excessive data exposure and mass assignment).",p:["Your CVE-2023-2240 is a BFLA example: role checks in the UI, not on the API controller","Test with a role × endpoint × object matrix"],f:"How do you prevent BFLA in a microservices system?"},
{c:"AI & LLM",q:"How do you security-review an AI-native product, model pipeline and inference service?",a:"Treat it as a system: data (sources, consent, poisoning, PII in training and RAG data), model supply chain (where models and weights come from, signed artefacts, no unsafe pickle loading, dependency scanning), training and fine-tuning pipeline (access control, isolation, secrets), inference service (authentication, per-tenant authorization, rate and cost limits, input size limits, logging), the application layer (prompt injection, tools and agency, output handling), and monitoring (abuse, drift, data leakage).",p:["Model files in pickle format can execute code on load; prefer safetensors","Inference endpoints are APIs: same BOLA, auth and rate-limit testing","Model extraction and membership inference for high-value models"],f:"Where in this pipeline would you put your first three controls?"},
{c:"AI & LLM",q:"How do you implement guardrails for a production AI feature?",a:"Layers, not one filter: input controls (authentication, rate limits, length limits, injection and PII detection), retrieval controls (permission filtering), constrained tools (allow-listed functions, server-side authorization, human approval for risky actions), output controls (schema/structured output validation, PII and secret filtering, HTML encoding, moderation), and monitoring with evaluation suites that run on every prompt or model change.",p:["Tools: NeMo Guardrails, Guardrails AI, Llama Guard, cloud content filters","A guardrail that's only in the system prompt is not a control","Measure false positives too; over-blocking pushes users to bypass"],f:"Which guardrail would you never rely on alone, and why?"},
{c:"AI & LLM",q:"What are the risks of using third-party AI APIs insecurely?",a:"API keys embedded in mobile or web clients (anyone can extract and use them), sending PII or secrets to providers without approval or data-processing terms, prompts and responses logged with sensitive data, trusting model output as safe input to other systems, no rate or cost limits (denial of wallet), and no fallback when the provider is down or changes behaviour.",p:["Route through a backend or gateway that holds keys and applies policy","Check provider data retention and training settings"],f:"A mobile app calls the AI provider directly with a key. What do you recommend?"},
{c:"AI for security",q:"Describe an AI-based security tool you'd build to reduce manual toil.",a:"Pick one with a clear metric. Example: an LLM triage assistant for SAST findings that pulls the code around the source and sink, checks for sanitisers, proposes true/false positive with reasoning and a fix, and posts it to the ticket. Build an evaluation set from past human-triaged findings, measure precision/recall, run in advisory mode first, and keep humans approving Critical findings.",p:["Other ideas: PR security reviewer for risky diffs, bug bounty duplicate detection, threat-model first drafts from design docs, security questionnaire answering from approved sources","Your real example: Claude + Burp MCP workflows and the bug bounty skills you built"],f:"How did you measure that the tool actually helped?"},
{c:"Mobile",q:"How do you secure an Android app used by field staff who work offline?",a:"Minimise data stored offline, encrypt it (SQLCipher or Jetpack Security), use short-lived offline tokens that need periodic re-authentication, bind the app to enrolled devices (MDM or device attestation), support remote wipe and session revocation, sign and integrity-check sync payloads, detect rooting and tampering for high-risk actions, and reconcile offline transactions server-side.",p:["Lost and stolen phones are the main threat model, not just remote attackers","Server must never trust offline data blindly; validate on sync"],f:"An agent's phone is stolen. Walk through what happens next."},
{c:"Programme",q:"How would you run application security training for engineers and product managers?",a:"Different content for each audience. Engineers: short, stack-specific sessions built from your own real findings, hands-on labs, secure patterns and paved roads. Product managers: how to spot risky features (payments, auth, PII, AI), abuse cases in requirements, and when to involve security. Measure recurrence of trained vulnerability classes and requests for early reviews.",p:["Keep it under an hour; follow up with office hours and champions"],f:"How do you know the training worked?"},
{c:"Programme",q:"How do you onboard an application into an SSDLC programme?",a:"Inventory it (owners, repos, environments, data classification, architecture), set a risk tier, connect scanners (SAST, SCA, secrets, IaC, container) to its pipeline in report mode, run a baseline threat model and pentest for high tiers, agree SLAs and a backlog for existing findings, name a security champion, and turn on gates once the baseline is triaged.",p:["Track onboarding as a checklist per app; report coverage across the portfolio"],f:"How long should onboarding take for a typical service?"},
{c:"Detection & IR",q:"How do you handle a product-layer security incident (for example a BOLA being exploited)?",a:"Confirm and scope from logs (which endpoint, which accounts, since when), contain quickly (hotfix, feature flag, WAF rule, revoke abused tokens), preserve evidence, assess data exposure with legal and privacy for notification duties, fix the root cause and the class (authorization tests, shared library), then a blameless post-incident review with tracked actions.",p:["Your role in product incidents: technical lead for the app layer alongside the SOC"],f:"How do you work out exactly which records were accessed?"},
{c:"Programme",q:"What are the security risks specific to a pay-as-you-go and mobile-money business?",a:"Payment confirmation fraud (forged callbacks, replay), unlock code forgery or sharing, device tampering to bypass the lock, agent fraud (fake cash payments, ghost customers), insider misuse of manual credits, customer PII on agent phones, SIM swap and social engineering of customers, and API abuse at scale given millions of payments per day.",p:["Fraud and security overlap: work closely with the fraud and finance teams","See the 'Pay-as-you-go connected devices' threat model in the lab"],f:"Which single control would reduce fraud the most?"}
];
