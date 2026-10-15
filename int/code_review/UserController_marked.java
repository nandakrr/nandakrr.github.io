@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Value("${internal.service.url}")
    private String internalServiceUrl;

    @PostMapping("/login")                                                    // <-- LINE 11: [Low/Med] No rate limit / lockout on login -> password brute force
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {

        String query = "SELECT id, username, password_hash, role " +          // <-- LINE 14: [CRITICAL] VULN-1 SQL INJECTION starts here: username concatenated into the query
                       "FROM users WHERE username = '" +                      // <-- LINE 15: [CRITICAL] VULN-1 SQLi (cont.) the quote ' is opened here...
                       request.getUsername() + "'";                           // <-- LINE 16: [CRITICAL] VULN-1 SQLi (cont.) ...and raw user input inserted. Payload: x' UNION SELECT 1,'admin','<your bcrypt hash>','ADMIN' --

        List<Map<String, Object>> users = jdbcTemplate.queryForList(query);   // <-- LINE 18: [CRITICAL] VULN-1 the injected query EXECUTES here

        if (users.isEmpty()) {                                                // <-- LINE 20: [Low] User enumeration by timing: unknown user returns fast (no bcrypt), real user is slow
            return ResponseEntity.status(401).build();
        }

        Map<String, Object> user = users.get(0);

        if (BCrypt.checkpw(request.getPassword(),                             // <-- LINE 26: NOT A VULN: bcrypt is fine; the hash it checks comes from the injectable query (line 14-16)
                user.get("password_hash").toString())) {

            String token = Jwts.builder()                                     // <-- LINE 29: [Medium] VULN-9 No .setExpiration() anywhere in this builder -> token valid FOREVER
                    .setSubject(user.get("username").toString())
                    .claim("role", user.get("role"))                          // <-- LINE 31: Role placed in token: whoever can forge a token (line 34) picks their own role
                    .signWith(
                        SignatureAlgorithm.HS256,
                        "secret123"                                           // <-- LINE 34: [CRITICAL] VULN-2 HARDCODED WEAK JWT SECRET -> hashcat -m 16500 cracks it -> forge role=ADMIN
                    )
                    .compact();

            return ResponseEntity.ok(Map.of("token", token));
        }

        return ResponseEntity.status(401).build();
    }

    @GetMapping("/user/{id}")                                                 // <-- LINE 44: [High] VULN-5 BOLA starts: endpoint takes ANY id, no ownership check below
    public ResponseEntity<?> getUser(
            @PathVariable String id,
            @RequestHeader("Authorization") String token) {

        Claims claims = Jwts.parser()
                .setSigningKey("secret123")                                   // <-- LINE 50: [CRITICAL] VULN-2 same hardcoded secret
                .parseClaimsJws(token.replace("Bearer ", ""))                 // <-- LINE 51: NOT A VULN: parseClaimsJws rejects alg:none tokens
                .getBody();

        String role = claims.get("role").toString();                          // <-- LINE 54: [High] VULN-5 BOLA: role is read but NEVER used to authorize; also NullPointerException if claim missing

        String query = "SELECT * FROM users WHERE id=" + id;                  // <-- LINE 56: [High] VULN-3 SQL INJECTION (numeric, no quotes): /api/user/0 UNION SELECT ... -- ; VULN-4 SELECT * returns password_hash

        Map<String, Object> user =
                jdbcTemplate.queryForMap(query);                              // <-- LINE 59: [High] VULN-3 the injected query EXECUTES here

        return ResponseEntity.ok(user);                                       // <-- LINE 61: [High] VULN-4 returns the full row including password_hash to the client
    }

    @PostMapping("/import")                                                   // <-- LINE 64: [High] No Authorization header / token check on /import at all (unauthenticated)
    public ResponseEntity<?> importXml(
            @RequestBody String xml) throws Exception {                       // <-- LINE 66: [CRITICAL] VULN-7 attacker-controlled XML body enters here

        DocumentBuilderFactory dbf =
                DocumentBuilderFactory.newInstance();                         // <-- LINE 69: [CRITICAL] VULN-7 XXE: default factory allows DTD + external entities (fix: disallow-doctype-decl = true)

        DocumentBuilder db =
                dbf.newDocumentBuilder();

        Document doc = db.parse(                                              // <-- LINE 74: [CRITICAL] VULN-7 XXE FIRES here: <!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]> -> file read
                new InputSource(
                        new StringReader(xml)));

        String callbackUrl =                                                  // <-- LINE 78: [CRITICAL] VULN-6 SSRF source: URL taken from attacker's XML
                doc.getElementsByTagName("url")
                        .item(0)
                        .getTextContent();

        URL url = new URL(callbackUrl);                                       // <-- LINE 83: [CRITICAL] VULN-6 SSRF: no allow-list, no scheme/IP check

        HttpURLConnection con =
                (HttpURLConnection) url.openConnection();                     // <-- LINE 86: [CRITICAL] VULN-6 SSRF: server connects to attacker URL (169.254.169.254, internal hosts); follows redirects. (file:// fails due to cast)

        con.setRequestMethod("GET");                                          // <-- LINE 88: [Low] No connect/read timeouts set -> thread exhaustion

        BufferedReader in =                                                   // <-- LINE 90: [Low] Reader/connection never closed -> resource leak
                new BufferedReader(
                        new InputStreamReader(
                                con.getInputStream()));                       // <-- LINE 93: [CRITICAL] VULN-6 SSRF request actually sent here

        StringBuilder response =
                new StringBuilder();

        String inputLine;

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }

        return ResponseEntity.ok(response.toString());                        // <-- LINE 104: [CRITICAL] VULN-6 FULL-READ SSRF: internal response returned to the attacker
    }

    @GetMapping("/admin/export")
    public ResponseEntity<?> exportUsers(
            @RequestHeader("Authorization") String token)
            throws IOException {

        Claims claims = Jwts.parser()
                .setSigningKey("secret123")                                   // <-- LINE 113: [CRITICAL] VULN-2 same hardcoded secret
                .parseClaimsJws(token.replace("Bearer ", ""))
                .getBody();

        if (claims.get("role") != null) {                                     // <-- LINE 117: [High] VULN-8 BFLA: '!= null' is TRUE for every user (login always sets a role) -> any user exports all users
            File file =
                new File("/opt/app/export/users.csv");                        // <-- LINE 119: NOT A VULN: fixed path, no path traversal

            return ResponseEntity.ok(                                         // <-- LINE 121: [High] VULN-8 every user's data returned to a non-admin
                Files.readString(file.toPath()));
        }

        return ResponseEntity.status(403).build();
    }
}

// ==================== SUMMARY (line numbers match the original code) ====================
// CRITICAL  Line 14-18   VULN-1 SQL injection in /login -> log in as anyone
// CRITICAL  Line 34,50,113 VULN-2 Hardcoded weak JWT secret 'secret123' -> forge admin token
// CRITICAL  Line 69,74   VULN-7 XXE -> file read
// CRITICAL  Line 78-104  VULN-6 Full-read SSRF -> cloud metadata / internal services
// HIGH      Line 56,59   VULN-3 SQL injection in /user/{id}
// HIGH      Line 56,61   VULN-4 SELECT * leaks password_hash
// HIGH      Line 44,54   VULN-5 BOLA / IDOR (role read, never checked)
// HIGH      Line 64      /import has no authentication
// HIGH      Line 117     VULN-8 BFLA: role != null lets any user export
// MEDIUM    Line 29      VULN-9 JWT has no expiry
// LOW       Line 11,20,54,88,90  rate limit, timing enumeration, NPE, no timeouts, resource leak
// CHAIN: line 14-16 SQLi (or crack line 34 secret) -> ADMIN token -> line 117 export dumps all users.
//        line 64 unauthenticated /import -> line 74 XXE + line 86 SSRF -> files + cloud credentials.
