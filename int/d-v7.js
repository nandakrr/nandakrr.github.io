// ===================== v7: Security headers & CSP lab =====================

window.HDR_REF = [
{h:"Content-Security-Policy",short:"CSP",prevents:"XSS impact, data injection, clickjacking (frame-ancestors), base-tag hijacking, mixed content",
 good:"script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
 values:[["default-src","Fallback for most fetch directives (script, style, img, connect, font, media, object, frame, worker…). Does NOT cover base-uri, form-action, frame-ancestors, sandbox, report-*."],
  ["script-src","Where scripts may load from and which inline scripts may run. The most important directive."],
  ["'self'","Same origin (scheme + host + port). Risky if users can upload files or there are JSONP endpoints on your origin."],
  ["'none'","Nothing allowed."],
  ["'nonce-<random>'","Allows scripts carrying a matching nonce attribute. Must be fresh, unpredictable (≥128 bits) per response, never reused or cached."],
  ["'sha256-<hash>'","Allows an inline script whose exact content hashes to this value. Good for static inline scripts."],
  ["'strict-dynamic'","Trust propagates: scripts loaded by an already-trusted (nonced/hashed) script are allowed; host allow-lists and 'self' are then ignored in CSP3 browsers."],
  ["'unsafe-inline'","Allows all inline scripts and event handlers, which defeats most XSS protection. Ignored by CSP2+ browsers when a nonce or hash is present (kept only as a fallback for very old browsers)."],
  ["'unsafe-eval'","Allows eval(), new Function(), setTimeout(string). Often required by old frameworks; widens attack surface."],
  ["'wasm-unsafe-eval'","Allows WebAssembly compilation without allowing JavaScript eval."],
  ["'unsafe-hashes'","Lets hashes match inline event handlers (onclick=…). Use sparingly."],
  ["https: / data: / blob: / *","Scheme or wildcard sources. In script-src they allow scripts from any HTTPS site or from data: URLs, effectively no protection."],
  ["object-src 'none'","Blocks plugins (<object>, <embed>). Always set it."],
  ["base-uri 'none' or 'self'","Stops an injected <base href> from redirecting relative script URLs, even nonced ones, to the attacker."],
  ["frame-ancestors","Who may frame this page: 'none', 'self', or origins. Modern replacement for X-Frame-Options; overrides it when both are present. Not supported in a <meta> CSP."],
  ["form-action","Where forms may submit. Limits form-based exfiltration and injected forms."],
  ["connect-src","fetch/XHR/WebSocket/EventSource destinations. Limits data exfiltration by injected script."],
  ["upgrade-insecure-requests","Rewrites http:// subresources to https://."],
  ["require-trusted-types-for 'script'","Enables Trusted Types: dangerous DOM sinks (innerHTML, eval) only accept typed values from approved policies. Strong DOM-XSS control."],
  ["sandbox","Applies iframe-style sandbox restrictions to the page itself."],
  ["report-to / report-uri","Where violation reports go. report-to (with the Reporting-Endpoints header) is the modern form; report-uri is deprecated but still widely supported."],
  ["Content-Security-Policy-Report-Only","Same syntax, reports violations without blocking. Use it to roll out a policy safely."]]},
{h:"Strict-Transport-Security",short:"HSTS",prevents:"SSL stripping and downgrade to HTTP; cookie theft over HTTP",
 good:"max-age=31536000; includeSubDomains; preload",
 values:[["max-age","Seconds the browser forces HTTPS. 31536000 (1 year) is the norm; 0 removes the policy."],
  ["includeSubDomains","Applies to every subdomain. Make sure all subdomains support HTTPS first."],
  ["preload","Signals consent to be built into browsers' preload lists (needs max-age ≥ 1 year, includeSubDomains, and submission to hstspreload.org). Fixes the first-visit gap but is slow to undo."],
  ["Only over HTTPS","Browsers ignore HSTS received over plain HTTP."]]},
{h:"X-Frame-Options",short:"XFO",prevents:"Clickjacking",
 good:"DENY (or SAMEORIGIN); prefer CSP frame-ancestors as well",
 values:[["DENY","No framing at all."],["SAMEORIGIN","Only same-origin pages may frame it."],["ALLOW-FROM uri","Obsolete; ignored by modern browsers. Use frame-ancestors instead."]]},
{h:"X-Content-Type-Options",short:"nosniff",prevents:"MIME sniffing: a user-uploaded file being executed as script or style",
 good:"nosniff",
 values:[["nosniff","The only valid value. Browsers block scripts and stylesheets whose Content-Type doesn't match, and it strengthens cross-origin read blocking."]]},
{h:"Referrer-Policy",short:"Referrer",prevents:"Leaking URLs (tokens, IDs, paths) to other sites via the Referer header",
 good:"strict-origin-when-cross-origin (or no-referrer for sensitive apps)",
 values:[["no-referrer","Never send."],["same-origin","Full URL to same origin, nothing cross-origin."],["strict-origin","Origin only, and nothing on HTTPS→HTTP."],["strict-origin-when-cross-origin","Full URL same-origin, origin only cross-origin, nothing on downgrade. Browser default today."],["origin / origin-when-cross-origin","Origin only (cross-origin), but still sent on downgrade."],["no-referrer-when-downgrade","Full URL to any HTTPS site. Leaky."],["unsafe-url","Always full URL, even to HTTP. Avoid."]]},
{h:"Permissions-Policy",short:"Permissions",prevents:"Abuse of powerful browser features by your page or embedded third parties",
 good:"camera=(), microphone=(), geolocation=(), payment=(), usb=()",
 values:[["feature=()","Disabled everywhere."],["feature=(self)","Only your origin."],["feature=(self \"https://partner.example\")","Your origin plus a named origin."],["Replaces Feature-Policy","Older header with different syntax."]]},
{h:"Cross-Origin-Opener-Policy",short:"COOP",prevents:"Cross-window attacks and XS-Leaks via window.opener; needed for cross-origin isolation",
 good:"same-origin",
 values:[["same-origin","Cross-origin windows can't keep a reference to this one."],["same-origin-allow-popups","Keeps references to popups you open (useful for OAuth/payment popups)."],["unsafe-none","Default, no isolation."]]},
{h:"Cross-Origin-Embedder-Policy",short:"COEP",prevents:"Loading cross-origin resources that haven't opted in; with COOP enables cross-origin isolation (SharedArrayBuffer, precise timers)",
 good:"require-corp (or credentialless)",
 values:[["require-corp","Every cross-origin resource must send CORP or CORS."],["credentialless","Cross-origin no-cors requests are sent without credentials instead."]]},
{h:"Cross-Origin-Resource-Policy",short:"CORP",prevents:"Other sites embedding your resources (Spectre-style data leaks, hotlinking of private files)",
 good:"same-origin (or same-site) for private resources",
 values:[["same-origin","Only your origin may load it."],["same-site","Your registrable domain."],["cross-origin","Anyone (for public CDNs)."]]},
{h:"Set-Cookie attributes",short:"Cookies",prevents:"Session theft (XSS, sniffing), CSRF, cookie tossing from subdomains",
 good:"__Host-session=…; Path=/; Secure; HttpOnly; SameSite=Lax",
 values:[["Secure","HTTPS only."],["HttpOnly","Not readable by JavaScript."],["SameSite=Strict|Lax|None","Cross-site sending: never / top-level GET navigations only / always (None requires Secure)."],["__Host- prefix","Requires Secure, Path=/, no Domain: can't be set or overwritten by subdomains."],["Domain","Omit for host-only cookies; setting it shares the cookie with all subdomains."],["Max-Age / Expires","Persistent cookie; omit for a session cookie."]]},
{h:"Cache-Control",short:"Caching",prevents:"Sensitive responses stored in browser, proxy or CDN caches (shared computers, cache poisoning/deception)",
 good:"no-store for authenticated/sensitive responses",
 values:[["no-store","Never store anywhere."],["private","Browser may store; shared caches may not."],["no-cache","Store but revalidate every time (still stored!)."],["public, max-age=…","For static public assets only."]]},
{h:"CORS headers",short:"CORS",prevents:"Other origins reading your responses (when configured correctly)",
 good:"Access-Control-Allow-Origin: <exact trusted origin>; Vary: Origin; credentials only if needed",
 values:[["Access-Control-Allow-Origin","* (public data, no credentials) or one exact origin. Never reflect arbitrary origins with credentials."],["Access-Control-Allow-Credentials: true","Allows cookies; cannot be combined with *."],["Vary: Origin","Prevents caches serving one origin's CORS response to another."],["Access-Control-Allow-Methods / -Headers / -Max-Age","Preflight answers."]]},
{h:"Legacy / remove",short:"Legacy",prevents:"(Mostly obsolete, sometimes harmful)",
 good:"X-XSS-Protection: 0 (or omit); remove Server/X-Powered-By version banners",
 values:[["X-XSS-Protection","Old XSS filter, removed from modern browsers. '1; mode=block' could itself create leaks; set 0 or omit. Rely on CSP."],["Expect-CT","Deprecated; Certificate Transparency is enforced by default."],["Public-Key-Pins (HPKP)","Removed from browsers; risk of locking users out."],["Server / X-Powered-By / X-AspNet-Version","Version banners help attackers fingerprint; remove or genericise. Low severity on their own."]]},
{h:"Other useful",short:"Other",prevents:"Specific risks",
 good:"Context-dependent",
 values:[["Clear-Site-Data: \"cache\", \"cookies\", \"storage\"","Send on logout to wipe client-side state."],["Content-Disposition: attachment","For user downloads, so files aren't rendered inline on your origin."],["Content-Type with charset","Prevents charset-sniffing XSS (e.g. UTF-7 tricks in old browsers)."],["Reporting-Endpoints","Defines named endpoints for CSP and other reports (used with report-to)."]]}
];

// ---------- CSP analyzer ----------
window.CSP_BYPASS_HOSTS=["googleapis.com","ajax.googleapis.com","cdnjs.cloudflare.com","cdn.jsdelivr.net","unpkg.com","gstatic.com","google.com","www.google.com","accounts.google.com","yandex.ru","vk.com","facebook.com","connect.facebook.net","twitter.com","raw.githubusercontent.com","github.io","herokuapp.com","firebaseapp.com","appspot.com","amazonaws.com","cloudfront.net","azurewebsites.net","netlify.app","vercel.app"];
window.analyzeCSP=function(policy,reportOnly){
 const out=[];const add=(sev,t,why,fix)=>out.push({sev,t,why,fix});
 if(!policy||!policy.trim()){add("High","No Content-Security-Policy","Nothing limits where scripts load from or whether inline script runs, so any XSS executes freely.","Start with a nonce-based policy in Report-Only, then enforce.");return out}
 const dirs={};policy.split(";").map(s=>s.trim()).filter(Boolean).forEach(d=>{const p=d.split(/\s+/);const n=p[0].toLowerCase();if(!dirs[n])dirs[n]=p.slice(1)});
 if(reportOnly)add("Medium","Report-Only: nothing is enforced","Content-Security-Policy-Report-Only only reports violations. It's right for rollout, but it doesn't block attacks.","Move to the enforcing header once reports are clean.");
 const script=dirs["script-src"]||dirs["script-src-elem"]||dirs["default-src"];const scriptName=dirs["script-src"]?"script-src":dirs["script-src-elem"]?"script-src-elem":"default-src";
 if(!script)add("High","No script-src or default-src","Scripts are unrestricted.","Add script-src with nonces or hashes.");
 else{
  const s=script.map(x=>x.toLowerCase());const hasNonce=s.some(x=>x.startsWith("'nonce-")),hasHash=s.some(x=>/^'sha(256|384|512)-/.test(x)),strict=s.includes("'strict-dynamic'");
  if(s.includes("'unsafe-inline'")&&!hasNonce&&!hasHash)add("High",`'unsafe-inline' in ${scriptName}`,"Any injected inline script or event handler (onerror=…) runs. This removes most of CSP's XSS protection.","Replace with per-response nonces or hashes; move handlers into script files.");
  if(s.includes("'unsafe-inline'")&&(hasNonce||hasHash))add("Info","'unsafe-inline' alongside a nonce/hash","CSP2+ browsers ignore 'unsafe-inline' when a nonce or hash is present; it's only a fallback for very old browsers. Fine.","");
  if(s.includes("'unsafe-eval'"))add("Medium",`'unsafe-eval' in ${scriptName}`,"eval/new Function/setTimeout(string) are allowed, so DOM-XSS via eval sinks and many script gadgets work.","Remove; refactor code or libraries that need eval. Use 'wasm-unsafe-eval' if only WebAssembly needs it.");
  if(s.includes("*"))add("High",`Wildcard * in ${scriptName}`,"Scripts from any host are allowed.","Use nonces or specific hosts.");
  ["https:","http:","data:","blob:"].forEach(sc=>{if(s.includes(sc))add(strict&&(hasNonce||hasHash)?"Info":(sc==="https:"?"High":sc==="data:"?"High":"Medium"),`Scheme source ${sc} in ${scriptName}`,strict&&(hasNonce||hasHash)?"Ignored by CSP3 browsers because 'strict-dynamic' is present; it is only a fallback for old browsers that don't understand nonces.":sc==="data:"?"<script src=\"data:text/javascript,alert(1)\"> is allowed.":sc==="https:"?"Any HTTPS site can host the attacker's script.":`Scripts can load via ${sc}.`,"Remove scheme sources from script directives.")});
  s.filter(x=>/^https?:\/\//.test(x)||/^\*\./.test(x)||/^[a-z0-9-]+\.[a-z.]+/.test(x)).forEach(h=>{const host=h.replace(/^https?:\/\//,"").replace(/^\*\./,"").split("/")[0];
   if(h.startsWith("http://"))add("Medium",`Plain-HTTP source ${h}`,"A network attacker can replace that script.","Use https:// sources only.");
   if(h.startsWith("*."))add("Medium",`Wildcard subdomain ${h}`,"Any subdomain (including taken-over or user-content ones) can serve scripts.","List exact hosts.");
   if(CSP_BYPASS_HOSTS.some(b=>host===b||host.endsWith("."+b)))add(strict?"Info":"High",`Known bypass-prone host: ${h}`,strict?"Host allow-lists are ignored when 'strict-dynamic' is present (CSP3 browsers), so this only matters for old browsers.":"Hosts like this serve JSONP endpoints, old AngularJS, or user-controlled content that can be used to run attacker script while staying 'allowed'.","Prefer nonces + 'strict-dynamic' over host allow-lists.")});
  if(s.includes("'self'")&&!strict)add("Low",`'self' in ${scriptName}`,"Fine if your origin has no user-uploaded files served as script and no JSONP endpoints; otherwise it's a bypass.","Serve user uploads from a separate domain; avoid JSONP.");
  if(strict&&!hasNonce&&!hasHash)add("High","'strict-dynamic' without a nonce or hash","Nothing is trusted to start with, so scripts break; teams then loosen the policy.","Pair 'strict-dynamic' with nonces or hashes.");
  s.filter(x=>x.startsWith("'nonce-")).forEach(n=>{const v=n.slice(7,-1);if(v.length<16)add("Medium","Short nonce","Nonces should be at least 128 bits of randomness, fresh per response.","Generate with a CSPRNG per response; never cache pages that contain a nonce.")});
  if(hasNonce&&strict&&!s.includes("'unsafe-eval'")&&!s.includes("*"))add("Good","Nonce + 'strict-dynamic'","This is the recommended 'strict CSP' pattern.","");
 }
 const obj=dirs["object-src"]||dirs["default-src"];if(!obj||!obj.map(x=>x.toLowerCase()).includes("'none'"))add("Medium","object-src isn't 'none'","Plugins (<object>/<embed>) can load content and historically bypassed CSP.","Add object-src 'none'.");
 if(!dirs["base-uri"])add("Medium","Missing base-uri","default-src doesn't cover it. An injected <base href=//evil> redirects relative script URLs, even nonced ones.","Add base-uri 'none' (or 'self').");
 if(!dirs["frame-ancestors"])add("Medium","Missing frame-ancestors","default-src doesn't cover it, so framing is allowed unless X-Frame-Options is set: clickjacking.","Add frame-ancestors 'none' (or 'self').");
 if(!dirs["form-action"])add("Low","Missing form-action","Injected forms can submit data anywhere.","Add form-action 'self'.");
 if(dirs["connect-src"]&&dirs["connect-src"].includes("*"))add("Low","connect-src *","Injected script can exfiltrate to any host.","Restrict connect-src to your APIs.");
 if(!dirs["require-trusted-types-for"])add("Info","No Trusted Types","Optional, but the strongest control against DOM XSS in large apps.","Consider require-trusted-types-for 'script' (start in Report-Only).");
 if(!dirs["report-to"]&&!dirs["report-uri"])add("Info","No reporting","You won't see violations or attacks.","Add report-to (with Reporting-Endpoints) or report-uri.");
 if(dirs["report-uri"]&&!dirs["report-to"])add("Info","report-uri only","report-uri is deprecated but still widely supported; adding report-to future-proofs it.","");
 return out;
};

// ---------- Response header analyzer ----------
window.analyzeHeaders=function(raw){
 const out=[];const add=(sev,t,why,fix)=>out.push({sev,t,why,fix});
 const lines=raw.split(/\r?\n/).map(l=>l.trim()).filter(Boolean);const H={};const cookies=[];
 let isHTTPS=true;
 lines.forEach(l=>{const m=l.match(/^([A-Za-z0-9-]+)\s*:\s*(.*)$/);if(!m)return;const k=m[1].toLowerCase(),v=m[2];if(k==="set-cookie")cookies.push(v);else H[k]=H[k]?H[k]+", "+v:v});
 const csp=H["content-security-policy"],cspro=H["content-security-policy-report-only"];
 if(csp)analyzeCSP(csp,false).forEach(f=>out.push(Object.assign({},f,{t:"CSP: "+f.t})));
 else if(cspro)analyzeCSP(cspro,true).forEach(f=>out.push(Object.assign({},f,{t:"CSP: "+f.t})));
 else add("High","No Content-Security-Policy","No defence-in-depth against XSS or framing control via CSP.","Add a nonce-based CSP.");
 const hsts=H["strict-transport-security"];
 if(!hsts)add("Medium","No Strict-Transport-Security","Users can be downgraded to HTTP (SSL stripping) on first or typed-in visits.","Strict-Transport-Security: max-age=31536000; includeSubDomains");
 else{const ma=+(hsts.match(/max-age=(\d+)/i)||[])[1];if(!ma)add("Medium","HSTS without valid max-age","Not effective.","Set max-age=31536000.");else if(ma<15768000)add("Low",`HSTS max-age is short (${ma}s)`,"Protection lapses quickly; preload requires one year.","Use 31536000.");if(!/includesubdomains/i.test(hsts))add("Low","HSTS without includeSubDomains","Subdomains (and cookies scoped to the parent domain) can still be attacked over HTTP.","Add includeSubDomains once all subdomains are HTTPS.");if(/preload/i.test(hsts))add("Info","HSTS preload","Good, but hard to undo; only if every subdomain is HTTPS forever.","")}
 const xfo=H["x-frame-options"];const fa=(csp||"").toLowerCase().includes("frame-ancestors");
 if(!xfo&&!fa)add("Medium","No framing protection","Neither X-Frame-Options nor CSP frame-ancestors: clickjacking is possible if the page has sensitive one-click actions.","X-Frame-Options: DENY and/or frame-ancestors 'none'.");
 if(xfo&&/allow-from/i.test(xfo))add("Medium","X-Frame-Options ALLOW-FROM","Obsolete: modern browsers ignore it, so there's no protection.","Use CSP frame-ancestors.");
 const xcto=H["x-content-type-options"];if(!xcto||xcto.toLowerCase().trim()!=="nosniff")add("Low","X-Content-Type-Options isn't nosniff","Browsers may sniff an uploaded file as script or HTML.","X-Content-Type-Options: nosniff");
 const rp=(H["referrer-policy"]||"").toLowerCase();if(!rp)add("Info","No Referrer-Policy","Browsers default to strict-origin-when-cross-origin, which is acceptable; set it explicitly for clarity and older browsers.","Referrer-Policy: strict-origin-when-cross-origin");else if(/unsafe-url|no-referrer-when-downgrade/.test(rp))add("Medium",`Leaky Referrer-Policy (${rp})`,"Full URLs, including tokens or IDs in paths and query strings, leak to other sites.","strict-origin-when-cross-origin or no-referrer.");
 if(!H["permissions-policy"])add("Low","No Permissions-Policy","Your page or embedded third parties can request camera, microphone, geolocation and similar.","Permissions-Policy: camera=(), microphone=(), geolocation=()");
 const xxss=H["x-xss-protection"];if(xxss&&/1/.test(xxss))add("Info","X-XSS-Protection enabled","Obsolete; modern browsers removed the filter, and mode=block has caused leaks.","Set X-XSS-Protection: 0 or remove; rely on CSP.");
 ["server","x-powered-by","x-aspnet-version","x-aspnetmvc-version"].forEach(k=>{if(H[k]&&/\d/.test(H[k]))add("Low",`Version disclosure: ${k}: ${H[k]}`,"Helps attackers match known CVEs. Low on its own.","Remove or genericise the header.")});
 const acao=H["access-control-allow-origin"],acac=(H["access-control-allow-credentials"]||"").toLowerCase()==="true";
 if(acao){if(acao.trim()==="*"&&acac)add("Info","ACAO * with credentials","Browsers reject this combination, so credentialed reads fail. Developers often 'fix' it by reflecting Origin, which is dangerous.","Use an exact allow-list of origins.");else if(acao.trim()==="null")add("High","ACAO: null","Sandboxed iframes and data: URLs have origin 'null', so attackers can satisfy it.","Never allow null.");else if(acac&&acao.trim()!=="*")add("Info",`Credentialed CORS for ${acao}`,"Fine if that origin is on a strict allow-list. Test whether the server reflects any Origin you send.","Exact allow-list + Vary: Origin.");if(acao.trim()!=="*"&&!/origin/i.test(H["vary"]||""))add("Low","Dynamic ACAO without Vary: Origin","Caches may serve one origin's CORS response to another.","Add Vary: Origin.")}
 const cc=(H["cache-control"]||"").toLowerCase();if(cookies.length&&!/no-store|private/.test(cc))add("Low","Authenticated response may be cached","Sets cookies but isn't marked no-store/private, so shared caches or the browser may keep sensitive data.","Cache-Control: no-store for authenticated pages.");
 cookies.forEach(c=>{const name=c.split("=")[0].trim(),l=c.toLowerCase();const sens=/sess|auth|token|jwt|sid|login/.test(name.toLowerCase());
  if(!/;\s*secure/.test(l))add(sens?"High":"Medium",`Cookie ${name} missing Secure`,"Sent over plain HTTP where it can be sniffed.","Add Secure.");
  if(sens&&!/;\s*httponly/.test(l))add("Medium",`Cookie ${name} missing HttpOnly`,"Readable by JavaScript, so XSS can steal the session.","Add HttpOnly.");
  if(!/samesite/.test(l))add("Low",`Cookie ${name} has no SameSite`,"Browser defaults vary (Chromium uses Lax); set it explicitly.","SameSite=Lax (or Strict).");
  if(/samesite=none/.test(l)&&!/;\s*secure/.test(l))add("Medium",`Cookie ${name}: SameSite=None without Secure`,"Browsers reject it; and None sends the cookie on all cross-site requests (CSRF exposure).","Use Lax unless cross-site use is needed; None requires Secure.");
  if(/domain=/.test(l))add("Low",`Cookie ${name} sets Domain`,"Shared with every subdomain, so a compromised or taken-over subdomain can read or overwrite it.","Make it host-only, ideally with the __Host- prefix.");
  if(sens&&!name.startsWith("__Host-"))add("Info",`Cookie ${name} could use __Host- prefix`,"The prefix guarantees Secure, Path=/ and no Domain.","Rename to __Host-"+name+".")});
 return out;
};

window.HDR_SAMPLES=[
{n:"Typical legacy app",raw:`HTTP/1.1 200 OK
Server: Apache/2.4.29 (Ubuntu)
X-Powered-By: PHP/7.2.24
Content-Type: text/html
Set-Cookie: PHPSESSID=8f2a...; path=/
X-XSS-Protection: 1; mode=block
X-Frame-Options: ALLOW-FROM https://partner.example.com
Content-Security-Policy: default-src 'self' https://ajax.googleapis.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://ajax.googleapis.com`},
{n:"Modern SPA, almost right",raw:`HTTP/2 200
content-type: text/html; charset=utf-8
strict-transport-security: max-age=86400
content-security-policy: script-src 'nonce-r4nd0m' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'
referrer-policy: no-referrer-when-downgrade
set-cookie: session=eyJ...; Secure; SameSite=None; Domain=.example.com
access-control-allow-origin: https://app.example.com
access-control-allow-credentials: true
x-content-type-options: nosniff`},
{n:"Hardened",raw:`HTTP/2 200
content-type: text/html; charset=utf-8
strict-transport-security: max-age=31536000; includeSubDomains; preload
content-security-policy: script-src 'nonce-q9Xp2LmZr7Tc4VbN8sKd' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; require-trusted-types-for 'script'; report-to csp
reporting-endpoints: csp="https://reports.example.com/csp"
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=(), payment=()
cross-origin-opener-policy: same-origin
cache-control: no-store
set-cookie: __Host-session=eyJ...; Path=/; Secure; HttpOnly; SameSite=Lax`}
];
window.CSP_SAMPLES=[
 ["Classic weak policy","default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://*.googleapis.com"],
 ["Allow-list only","script-src 'self' https://www.google.com https://cdn.jsdelivr.net; object-src 'none'"],
 ["Strict CSP (recommended)","script-src 'nonce-q9Xp2LmZr7Tc4VbN8sKd' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"],
 ["Looks strict but isn't","default-src 'none'; script-src data: 'self'; style-src 'self'"]
];

window.HDR_QUIZ=[
 {q:"A page sends: script-src 'self' 'unsafe-inline'. An attacker finds reflected XSS. Does CSP stop <img src=x onerror=alert(1)>?",o:["Yes","No"],a:1,why:"'unsafe-inline' allows inline event handlers, so the payload runs."},
 {q:"script-src 'nonce-abc123' 'unsafe-inline'. Does an injected inline script without the nonce run in Chrome?",o:["Yes","No"],a:1,why:"When a nonce or hash is present, CSP2+ browsers ignore 'unsafe-inline'."},
 {q:"default-src 'self'. Is clickjacking prevented?",o:["Yes","No"],a:1,why:"frame-ancestors doesn't fall back to default-src. You need frame-ancestors or X-Frame-Options."},
 {q:"A page has a nonced <script src=\"/js/app.js\"> and no base-uri. The attacker injects <base href=\"https://evil.example/\">. What happens?",o:["Nothing, the script is nonced","The nonced script now loads from evil.example"],a:1,why:"The relative URL resolves against the injected base, and the nonce still matches. Set base-uri 'none'."},
 {q:"script-src https://ajax.googleapis.com. Can that be bypassed?",o:["No, it's a trusted Google host","Yes"],a:1,why:"It hosts old AngularJS versions and other libraries usable as script gadgets, so attacker-controlled markup can execute."},
 {q:"Two CSP headers are sent. Which one applies?",o:["The first","The last","Both: a resource must pass every policy"],a:2,why:"Multiple policies are all enforced; the effective policy is the most restrictive combination."},
 {q:"Can frame-ancestors be set in a <meta http-equiv> CSP?",o:["Yes","No"],a:1,why:"frame-ancestors, report-uri and sandbox are ignored in meta CSP. Use the header."},
 {q:"HSTS received over plain HTTP: does the browser apply it?",o:["Yes","No"],a:1,why:"It's only honoured over HTTPS; otherwise a MITM could inject it."},
 {q:"What does HSTS preload solve that normal HSTS doesn't?",o:["Certificate errors","The very first visit before the browser has seen the header"],a:1,why:"Preloaded domains are HTTPS-only from the first request."},
 {q:"Missing X-Frame-Options on a static marketing page: severity?",o:["High","Informational/Low"],a:1,why:"Clickjacking needs a sensitive action to trick the user into. No action, no real impact."},
 {q:"Referrer-Policy: unsafe-url on a page whose URL contains a password-reset token. Risk?",o:["None","The token leaks to third-party scripts' and links' servers via Referer"],a:1,why:"Full URLs, including query strings, are sent to every destination."},
 {q:"Is X-XSS-Protection: 1; mode=block a recommended control today?",o:["Yes","No"],a:1,why:"Browsers removed the XSS auditor; the header is obsolete. Use CSP; set 0 or omit it."},
 {q:"Access-Control-Allow-Origin: * with Allow-Credentials: true. What happens?",o:["Any site can read authenticated data","Browsers reject credentialed reads"],a:1,why:"The spec forbids * with credentials. The danger is when developers reflect Origin to make it work."},
 {q:"Cache-Control: no-cache on an account page. Is it stored in caches?",o:["No","Yes, it can be stored but must be revalidated"],a:1,why:"no-cache still allows storage. Use no-store for sensitive pages."},
 {q:"Does a CSP fix XSS?",o:["Yes","No, it reduces impact; output encoding fixes it"],a:1,why:"CSP is defence in depth. The bug is still there and may be exploitable via bypasses or non-script injection."}
];

window.QB6=[
{c:"Security headers",q:"Which security headers would you set on a modern web application, and why?",a:"Content-Security-Policy (nonce-based with 'strict-dynamic', object-src 'none', base-uri 'none', frame-ancestors) against XSS and clickjacking; Strict-Transport-Security against downgrade; X-Content-Type-Options: nosniff against MIME sniffing; Referrer-Policy: strict-origin-when-cross-origin against URL leakage; Permissions-Policy to switch off unused powerful features; COOP same-origin against cross-window attacks; Cache-Control: no-store on authenticated pages; and secure cookie attributes.",p:["Set them centrally (CDN, reverse proxy or framework middleware), not per route","Remove version banners; X-XSS-Protection is obsolete"],f:"Which one gives the most protection, and which is hardest to deploy?"},
{c:"Security headers",q:"Explain CSP nonces vs hashes vs allow-lists.",a:"Allow-lists name hosts that may serve script; they're easy to bypass if any allowed host has JSONP, old AngularJS or user content. Nonces are random per-response values: only script tags with the matching nonce attribute run. Hashes allow an inline script whose exact content matches. Nonces suit server-rendered pages; hashes suit static inline scripts. The recommended 'strict CSP' is nonces or hashes plus 'strict-dynamic'.",p:["Nonces must be unpredictable, fresh per response, and pages carrying them must not be cached and reused"],f:"How do you use nonces with a CDN-cached static site?"},
{c:"Security headers",q:"What does 'strict-dynamic' do?",a:"It lets scripts that are already trusted (by nonce or hash) load further scripts, so you don't need to list every third-party host. In CSP3 browsers it makes host allow-lists and 'self' ignored. Old browsers fall back to the other sources in the policy, which is why strict policies often add https: and 'unsafe-inline' as harmless fallbacks.",p:[],f:"Why is 'https:' in a strict CSP not a weakness?"},
{c:"Security headers",q:"How would you roll out CSP on a large legacy app without breaking it?",a:"Inventory inline scripts, event handlers and third-party scripts. Deploy Content-Security-Policy-Report-Only with a target policy and a reporting endpoint. Refactor inline handlers into files and add nonces through templates. Triage reports (ignoring extension noise), iterate, then enforce, starting with high-risk pages. Keep the reporting endpoint running after enforcement.",p:["Start with object-src 'none' and base-uri 'none', which rarely break anything","Trusted Types next, also via Report-Only"],f:"How do you filter noise in CSP reports?"},
{c:"Security headers",q:"List common CSP bypasses.",a:"'unsafe-inline' or 'unsafe-eval' left in place; allow-listed hosts with JSONP endpoints, AngularJS or user-uploaded content; 'self' when the origin serves uploads or JSONP; missing base-uri (base tag hijack); missing object-src; wildcards or scheme sources (https:, data:); script gadgets in frameworks; nonce reuse or leakage; and dangling markup to steal data without script.",p:["Tools: Google CSP Evaluator, and this lab's analyzer"],f:"Which of these does 'strict-dynamic' neutralise?"},
{c:"Security headers",q:"X-Frame-Options vs CSP frame-ancestors?",a:"Both prevent clickjacking. X-Frame-Options supports DENY and SAMEORIGIN (ALLOW-FROM is obsolete). frame-ancestors supports multiple specific origins and wildcards and overrides X-Frame-Options in modern browsers. Send both for coverage: XFO for old browsers, frame-ancestors as the real control. frame-ancestors doesn't work in meta tags and doesn't fall back to default-src.",p:[],f:"How do you allow one partner to frame a page?"},
{c:"Security headers",q:"Explain HSTS and its risks.",a:"Strict-Transport-Security tells the browser to use only HTTPS for the domain for max-age seconds, stopping SSL stripping. includeSubDomains extends it to subdomains; preload puts the domain into browsers' built-in lists to protect the first visit. Risks: includeSubDomains or preload breaks any subdomain that isn't HTTPS, and preload is slow to undo.",p:["Only honoured when received over HTTPS","Roll out with a short max-age, then increase"],f:"What's the first-visit problem?"},
{c:"Security headers",q:"Referrer-Policy values: which would you choose and why?",a:"strict-origin-when-cross-origin for most apps (full URL within your site, only origin to others, nothing on HTTPS→HTTP; it's the browser default). no-referrer for highly sensitive apps or pages with tokens in URLs. Avoid unsafe-url and no-referrer-when-downgrade, which leak full URLs.",p:["Better still: don't put secrets in URLs"],f:"Which value breaks analytics, and how do you handle that?"},
{c:"Security headers",q:"What are COOP, COEP and CORP, and when do they matter?",a:"COOP isolates your window from cross-origin windows (stopping window.opener tricks and some XS-Leaks). CORP lets a resource say who may embed it. COEP requires every cross-origin resource to opt in with CORP or CORS. COOP same-origin plus COEP require-corp gives cross-origin isolation, needed for SharedArrayBuffer and precise timers and a Spectre mitigation.",p:["Use same-origin-allow-popups when you rely on OAuth or payment popups"],f:"How do these relate to XS-Leaks?"},
{c:"Security headers",q:"Is a missing security header a vulnerability? How do you rate it?",a:"Usually it's a hardening gap, not a vulnerability by itself. Rate by context: missing CSP matters more on an app with XSS-prone features; missing X-Frame-Options matters only if there's a sensitive action to clickjack; missing HSTS matters for login and payment sites. Most bug bounty programmes treat missing headers alone as informational.",p:["Interviewers like hearing that you rate by impact, not by checklist"],f:"When would a missing header be High?"},
{c:"Security headers",q:"How do security headers interact with a CDN or reverse proxy?",a:"Headers are often set or stripped at the edge. Set them centrally (CDN rules, ingress controller, framework middleware) so every route gets them, check that error pages and redirects also carry them, make sure caches don't serve one user's nonce or cookies to another, and verify at the edge, not just the origin.",p:["Cloudflare, Nginx and API gateways can add headers; app frameworks have helpers (Helmet for Node.js, Spring Security headers)"],f:"How would you test that every response has the headers?"},
{c:"Security headers",q:"What headers matter for a JSON API (no HTML)?",a:"Content-Type: application/json with nosniff (so responses can't be rendered as HTML), Cache-Control: no-store for authenticated data, strict CORS (exact origins, Vary: Origin, credentials only if needed), HSTS, and a restrictive CSP such as default-src 'none'; frame-ancestors 'none' as a cheap backstop. Remove version banners.",p:[],f:"Why would an API ever need CSP?"},
{c:"Security headers",q:"Explain Trusted Types.",a:"A CSP feature (require-trusted-types-for 'script') that makes dangerous DOM sinks like innerHTML and eval reject plain strings. Code must pass values created by named policies that sanitise or validate them, which makes DOM XSS sinks auditable in one place.",p:["Roll out in Report-Only; libraries may need updates"],f:"How does it differ from a sanitiser like DOMPurify?"},
{c:"Security headers",q:"Which cookie attributes would you require for a session cookie?",a:"__Host- prefix, Secure, HttpOnly, SameSite=Lax (Strict where usability allows), Path=/, no Domain, and a short lifetime with server-side expiry.",p:["SameSite=None only for genuine cross-site needs, and then add CSRF tokens"],f:"Why does the __Host- prefix matter?"}
];
