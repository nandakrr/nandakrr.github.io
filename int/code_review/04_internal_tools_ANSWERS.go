// Practice 04: Internal tools service (Go / net/http / PostgreSQL)
// Login, network ping, report download, avatar fetch, personal notes.
// Find every vulnerability, give the exact line, the exploit, and the fix. Time yourself: 30 minutes.

package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	_ "github.com/lib/pq"
)

var db *sql.DB
var sessions = map[string]string{}                                                                              // LINE 24: [MEDIUM] Plain map read and written from concurrent handlers with no mutex -> data race; Go aborts with "concurrent map writes" (DoS). Use sync.Mutex or sync.Map

func newToken() string {
	b := make([]byte, 16)
	rand.Read(b)                                                                                                   // LINE 28: [HIGH] math/rand is NOT a CSPRNG -> predictable session tokens. Use crypto/rand
	return fmt.Sprintf("%x", b)
}

func login(w http.ResponseWriter, r *http.Request) {                                                            // LINE 32: [LOW] No rate limiting or lockout -> password brute force
	user := r.FormValue("user")
	pass := r.FormValue("pass")
	var id string
	err := db.QueryRow("SELECT id FROM users WHERE name=$1 AND pw_hash=crypt($2, pw_hash)", user, pass).Scan(&id)  // LINE 36: NOT A VULN: parameterized ($1, $2), and pgcrypto crypt() checks against a salted hash
	if err != nil {
		http.Error(w, "invalid", http.StatusUnauthorized)
		return
	}
	tok := newToken()
	sessions[tok] = id
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: tok, HttpOnly: true})                                       // LINE 43: [LOW] Session cookie missing Secure and SameSite
	w.WriteHeader(http.StatusNoContent)
}

func userID(r *http.Request) string {
	c, err := r.Cookie("sid")
	if err != nil {
		return ""
	}
	return sessions[c.Value]
}

func ping(w http.ResponseWriter, r *http.Request) {
	if userID(r) == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput()                                         // LINE 61: [CRITICAL] Command injection: host=8.8.8.8;cat /etc/passwd. Use exec.Command("ping", "-c", "1", host) after validating host (net.ParseIP; also reject a leading "-")
	w.Write(out)
}

func download(w http.ResponseWriter, r *http.Request) {
	if userID(r) == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name := r.URL.Query().Get("name")
	path := filepath.Join("/data/reports", name)                                                                   // LINE 71: [HIGH] Path traversal: Join CLEANS the path, so name=../../etc/passwd becomes /etc/passwd. Check the result stays under /data/reports (or use os.Root in Go 1.24+)
	http.ServeFile(w, r, path)                                                                                     // LINE 72: NOT A VULN by itself, and NOT a protection either: ServeFile only rejects ".." in r.URL.Path (here that's /download), not in this argument
}

func fetchAvatar(w http.ResponseWriter, r *http.Request) {
	if userID(r) == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	u := r.URL.Query().Get("url")
	if !strings.HasPrefix(u, "https://cdn.example.com") {                                                          // LINE 81: [HIGH] Prefix check is bypassable: https://cdn.example.com.evil.net/ or https://cdn.example.com@evil.net/. Parse with url.Parse and compare Host exactly
		http.Error(w, "bad url", http.StatusBadRequest)
		return
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}     // LINE 85: [HIGH] TLS verification disabled -> MITM. The client also follows redirects (evil.net -> http://169.254.169.254/ = SSRF) and has no timeout
	resp, err := client.Get(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)                                                             // LINE 88: [LOW] Raw error text returned (leaks internal hostnames and IPs; helps map the network through the SSRF)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)                                                                                          // LINE 92: [HIGH] Full-read SSRF: the fetched body goes straight back to the caller, with no size limit
}

type Note struct {
	Owner string `json:"owner"`
	Body  string `json:"body"`
}

func notes(w http.ResponseWriter, r *http.Request) {
	uid := userID(r)
	if uid == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodPost {
		var n Note
		json.NewDecoder(r.Body).Decode(&n)                                                                            // LINE 108: [LOW] Decode error ignored; no body size limit (use http.MaxBytesReader)
		if _, err := db.Exec("INSERT INTO notes(owner, body) VALUES($1, $2)", n.Owner, n.Body); err != nil {          // LINE 109: [HIGH] owner is taken from the request body, not the session -> write notes as any user (mass assignment / BOLA). Use uid
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		return
	}
	order := r.URL.Query().Get("order")
	rows, err := db.Query(fmt.Sprintf("SELECT body FROM notes WHERE owner=$1 ORDER BY created_at %s", order), uid)  // LINE 117: [HIGH] SQL injection via order (fmt.Sprintf into the query string); only owner is parameterized. Allow-list "ASC"/"DESC"
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var body string
		rows.Scan(&body)
		out = append(out, body)
	}
	json.NewEncoder(w).Encode(out)                                                                                 // LINE 129: NOT A VULN: JSON encoding escapes <, > and & by default
}

func main() {
	var err error
	db, err = sql.Open("postgres", os.Getenv("DATABASE_URL"))                                                      // LINE 134: NOT A VULN: credentials come from the environment
	if err != nil {
		panic(err)
	}
	http.HandleFunc("/login", login)
	http.HandleFunc("/ping", ping)
	http.HandleFunc("/download", download)
	http.HandleFunc("/avatar", fetchAvatar)
	http.HandleFunc("/notes", notes)
	http.ListenAndServe(":8080", nil)                                                                              // LINE 143: [LOW] Plain HTTP and no server timeouts (Slowloris); the error is ignored
}

// ================================================================================================
// ANSWER KEY SUMMARY (line numbers match the practice file)
//  CRITICAL line 61   Command injection: host=8.8.8.8;cat /etc/passwd. Use exec.Command("ping", "-c", "1", host) after validating host (net.ParseIP; also reject a leading "
//  HIGH     line 28   math/rand is NOT a CSPRNG -> predictable session tokens. Use crypto/rand
//  HIGH     line 71   Path traversal: Join CLEANS the path, so name=../../etc/passwd becomes /etc/passwd. Check the result stays under /data/reports (or use os.Root in Go 1
//  HIGH     line 81   Prefix check is bypassable: https://cdn.example.com.evil.net/ or https://cdn.example.com@evil.net/. Parse with url.Parse and compare Host exactly
//  HIGH     line 85   TLS verification disabled -> MITM. The client also follows redirects (evil.net -> http://169.254.169.254/ = SSRF) and has no timeout
//  HIGH     line 92   Full-read SSRF: the fetched body goes straight back to the caller, with no size limit
//  HIGH     line 109  owner is taken from the request body, not the session -> write notes as any user (mass assignment / BOLA). Use uid
//  HIGH     line 117  SQL injection via order (fmt.Sprintf into the query string); only owner is parameterized. Allow-list "ASC"/"DESC"
//  MEDIUM   line 24   Plain map read and written from concurrent handlers with no mutex -> data race; Go aborts with "concurrent map writes" (DoS). Use sync.Mutex or sync.M
//  LOW      line 32   No rate limiting or lockout -> password brute force
//  LOW      line 43   Session cookie missing Secure and SameSite
//  LOW      line 88   Raw error text returned (leaks internal hostnames and IPs; helps map the network through the SSRF)
//  LOW      line 108  Decode error ignored; no body size limit (use http.MaxBytesReader)
//  LOW      line 143  Plain HTTP and no server timeouts (Slowloris); the error is ignored
//  NOT A VULN (decoys you should say are safe): lines 36, 72, 129, 134
//  Total real findings: 14
// ================================================================================================
