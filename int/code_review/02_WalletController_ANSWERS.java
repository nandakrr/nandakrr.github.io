// Practice 02: Wallet / payments service (Java / Spring Boot)
// Money transfers, coupons, profile updates, password reset, statement import.
// Find every vulnerability, give the exact line, the exploit, and the fix. Time yourself: 30 minutes.

@RestController
@RequestMapping("/api/wallet")
public class WalletController {

    @Autowired private AccountRepository accounts;
    @Autowired private CouponRepository coupons;
    @Autowired private UserRepository users;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private MailService mail;

    private static final Logger log = LoggerFactory.getLogger(WalletController.class);
    private final Random random = new Random();                                                           // LINE 16: [HIGH] java.util.Random is not cryptographically secure (predictable); it is used for reset tokens below. Use SecureRandom

    @PostMapping("/transfer")
    public ResponseEntity<?> transfer(@AuthenticationPrincipal User me,
                                      @RequestBody TransferRequest req) {
        Account from = accounts.findById(req.getFromAccountId()).orElseThrow();                           // LINE 21: [CRITICAL] BOLA: fromAccountId comes from the request and is never checked to belong to `me` -> drain anyone's account
        Account to = accounts.findById(req.getToAccountId()).orElseThrow();

        if (from.getBalance().compareTo(req.getAmount()) < 0) {                                           // LINE 24: [HIGH] No check that amount > 0: amount = -500 passes this check and REVERSES the transfer (pulls money out of `to`)
            return ResponseEntity.badRequest().body("insufficient funds");
        }
        from.setBalance(from.getBalance().subtract(req.getAmount()));                                     // LINE 27: [HIGH] Race condition (TOCTOU): read-check-write with no transaction or lock; parallel requests all pass the balance check -> overdraft. Fix: @Transactional + SELECT ... FOR UPDATE, @Version, or an atomic UPDATE ... WHERE balance >= ?
        to.setBalance(to.getBalance().add(req.getAmount()));
        accounts.save(from);
        accounts.save(to);
        log.info("transfer {} from {} to {}", req.getAmount(), from.getId(), to.getId());                 // LINE 31: NOT A VULN: parameterized SLF4J logging of ids and amount
        return ResponseEntity.ok().build();
    }

    @PostMapping("/coupons/redeem")                                                                       // LINE 35: [MEDIUM] No rate limit -> coupon codes can be brute-forced
    public ResponseEntity<?> redeem(@AuthenticationPrincipal User me, @RequestParam String code) {
        Coupon c = coupons.findByCode(code);                                                              // LINE 37: NOT A VULN: Spring Data derived query is parameterized
        if (c == null || c.isUsed()) {
            return ResponseEntity.badRequest().body("invalid coupon");
        }
        Account acc = accounts.findByOwnerId(me.getId());
        acc.setBalance(acc.getBalance().add(c.getValue()));                                               // LINE 42: [HIGH] Race condition: the isUsed() check and setUsed(true) aren't atomic -> 20 parallel requests redeem one coupon 20 times. Fix: UPDATE coupons SET used=true WHERE code=? AND used=false, then check rows affected == 1
        accounts.save(acc);
        c.setUsed(true);
        coupons.save(c);
        return ResponseEntity.ok(acc.getBalance());
    }

    @PutMapping("/profile")
    public ResponseEntity<?> updateProfile(@AuthenticationPrincipal User me,
                                           @RequestBody User update) {                                    // LINE 51: [HIGH] Mass assignment: binds the whole User entity -> {"role":"ADMIN","kycVerified":true,"password":"..."} is saved. Use a DTO with only the allowed fields
        update.setId(me.getId());                                                                         // LINE 52: NOT A VULN (on its own): id is forced to the caller's, so this isn't BOLA; the problem is all the other fields
        users.save(update);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/password-reset")
    public ResponseEntity<?> requestReset(@RequestParam String email) {
        User u = users.findByEmail(email);
        if (u == null) {
            return ResponseEntity.status(404).body("no account for " + email);                            // LINE 61: [LOW] Account enumeration: unknown emails get a different response. Always return the same 200 message
        }
        String token = String.valueOf(100000 + random.nextInt(900000));                                   // LINE 63: [HIGH] Predictable (java.util.Random) 6-digit token = 900k guesses, no rate limit, no expiry -> account takeover. Use SecureRandom, 128-bit, expiring, single-use
        u.setResetToken(token);
        users.save(u);
        log.info("reset token for {} is {}", email, token);                                               // LINE 66: [HIGH] Secret written to logs: anyone with log access can reset any password
        mail.send(email, "Reset your password", "Your code: " + token);
        return ResponseEntity.ok("sent");
    }

    @PostMapping("/password-reset/confirm")
    public ResponseEntity<?> confirmReset(@RequestParam String email,
                                          @RequestParam String token,
                                          @RequestParam String newPassword) {
        User u = users.findByEmail(email);
        if (u != null && token.equals(u.getResetToken())) {                                               // LINE 76: [MEDIUM] Token never expires and isn't cleared after use (reusable); no attempt limit. String.equals timing is minor next to that
            u.setPassword(passwordEncoder.encode(newPassword));                                           // LINE 77: NOT A VULN: password is hashed with the configured PasswordEncoder (e.g. BCrypt)
            users.save(u);
            return ResponseEntity.ok().build();
        }
        return ResponseEntity.status(400).build();
    }

    @PostMapping(value = "/statements/import", consumes = "application/octet-stream")
    public ResponseEntity<?> importStatement(@RequestBody byte[] body) throws Exception {
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(body));
        Statement s = (Statement) in.readObject();                                                        // LINE 87: [CRITICAL] Java insecure deserialization: readObject() runs gadget chains BEFORE the cast happens (ysoserial payloads) -> RCE. Use JSON, or an ObjectInputFilter allow-list
        return ResponseEntity.ok(s.getLines().size());
    }

    @GetMapping("/continue")
    public void continueTo(@RequestParam String next, HttpServletResponse resp) throws IOException {
        if (next.contains("example.com")) {                                                               // LINE 93: [MEDIUM] Open redirect: contains() is bypassed by https://example.com.evil.net or https://evil.net/?example.com. Parse the URL and compare the host exactly, or allow only relative paths
            resp.sendRedirect(next);
        } else {
            resp.sendRedirect("/");
        }
    }
}

// ================================================================================================
// ANSWER KEY SUMMARY (line numbers match the practice file)
//  CRITICAL line 21   BOLA: fromAccountId comes from the request and is never checked to belong to `me` -> drain anyone's account
//  CRITICAL line 87   Java insecure deserialization: readObject() runs gadget chains BEFORE the cast happens (ysoserial payloads) -> RCE. Use JSON, or an ObjectInputFilter 
//  HIGH     line 16   java.util.Random is not cryptographically secure (predictable); it is used for reset tokens below. Use SecureRandom
//  HIGH     line 24   No check that amount > 0: amount = -500 passes this check and REVERSES the transfer (pulls money out of `to`)
//  HIGH     line 27   Race condition (TOCTOU): read-check-write with no transaction or lock; parallel requests all pass the balance check -> overdraft. Fix: @Transactional 
//  HIGH     line 42   Race condition: the isUsed() check and setUsed(true) aren't atomic -> 20 parallel requests redeem one coupon 20 times. Fix: UPDATE coupons SET used=tr
//  HIGH     line 51   Mass assignment: binds the whole User entity -> {"role":"ADMIN","kycVerified":true,"password":"..."} is saved. Use a DTO with only the allowed fields
//  HIGH     line 63   Predictable (java.util.Random) 6-digit token = 900k guesses, no rate limit, no expiry -> account takeover. Use SecureRandom, 128-bit, expiring, single
//  HIGH     line 66   Secret written to logs: anyone with log access can reset any password
//  MEDIUM   line 35   No rate limit -> coupon codes can be brute-forced
//  MEDIUM   line 76   Token never expires and isn't cleared after use (reusable); no attempt limit. String.equals timing is minor next to that
//  MEDIUM   line 93   Open redirect: contains() is bypassed by https://example.com.evil.net or https://evil.net/?example.com. Parse the URL and compare the host exactly, or
//  LOW      line 61   Account enumeration: unknown emails get a different response. Always return the same 200 message
//  NOT A VULN (decoys you should say are safe): lines 31, 37, 52, 77
//  Total real findings: 13
// ================================================================================================
