import base64
import json
import math
import os

import jwt
import requests
from flask import request, jsonify, g




def InternalAuth():                                                                           # LINE 13: [CRITICAL] InternalAuth never verifies the JWT signature (see line 19 and 93)
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "missing authorization"}), 401

    token = auth[7:]
    claims = _decode_payload(token)                                                           # LINE 19: [CRITICAL] claims come from an UNVERIFIED token: forge {"user_id":1,"role":"admin"} with any signature
    if claims is None:
        return jsonify({"error": "invalid token"}), 401

    g.user_id = claims.get("user_id")
    g.email   = claims.get("email")
    g.role    = claims.get("role")                                                            # LINE 25: [CRITICAL] role trusted from the forged token -> admin on every route


_rsa_public_key = None

def _load_rsa_key():
    global _rsa_public_key
    if _rsa_public_key is None:
        from cryptography.hazmat.primitives import serialization
        path = os.path.join(os.path.dirname(__file__), "../keys/public.pem")                  # LINE 34: NOT A VULN: fixed path, no user input -> no directory traversal
        with open(path, "rb") as f:
            _rsa_public_key = serialization.load_pem_public_key(f.read())
    return _rsa_public_key

def RSAAuth():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "missing authorization"}), 401

    token = auth[7:]
    try:
        pub = _load_rsa_key()
        claims = jwt.decode(token, pub, algorithms=["RS256", "HS256"])                        # LINE 47: [HIGH] RS256 + HS256 allowed with the same key = algorithm-confusion pattern. (pub is a key object here, so PyJWT's HMAC raises TypeError -> uncaught 500.) Fix: algorithms=['RS256']
        g.user_id = claims.get("user_id")
        g.email   = claims.get("email")
        g.role    = claims.get("role")
    except jwt.PyJWTError as exc:
        return jsonify({"error": str(exc)}), 401                                              # LINE 52: [LOW] str(exc) leaks internal error details to the client


# ── OAuthAuth ─────────────────────────────────────────────────────────────────
# Used by /oauth/** routes. Resolves the signing key from the jku/kid in
# the token header to support key rotation across multiple OAuth providers.

def OAuthAuth():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "missing authorization"}), 401

    token = auth[7:]
    try:
        header = _decode_header(token)
        jku = header.get("jku")                                                               # LINE 67: [CRITICAL] jku is read from the attacker's own token header
        kid = header.get("kid")

        if not jku or not kid:
            return jsonify({"error": "token missing jku or kid"}), 401

        public_key = _fetch_jwks_key(jku, kid)                                                # LINE 73: [CRITICAL] JKU INJECTION: signing key fetched from attacker URL -> host your own JWKS, sign any token -> auth bypass on /oauth/**
        claims = jwt.decode(token, public_key, algorithms=["RS256"])                          # LINE 74: [CRITICAL] token 'verified' against the attacker's key -> passes

        g.user_id = claims.get("user_id")
        g.email   = claims.get("email")
        g.role    = claims.get("role")
    except Exception as exc:
        return jsonify({"error": str(exc)}), 401                                              # LINE 80: [LOW/MED] str(exc) leaks errors from the jku fetch -> SSRF response oracle


# ── helpers ───────────────────────────────────────────────────────────────────

def _pad(s):
    return s + "=" * (4 - len(s) % 4)

def _decode_payload(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = base64.urlsafe_b64decode(_pad(parts[1]))                                    # LINE 93: [CRITICAL] payload only base64-decoded; signature (parts[2]) is never checked
        return json.loads(payload)
    except Exception:
        return None

def _decode_header(token: str) -> dict:
    parts = token.split(".")
    raw = base64.urlsafe_b64decode(_pad(parts[0]))
    return json.loads(raw)

def _fetch_jwks_key(jku: str, kid: str):
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.backends import default_backend

    resp = requests.get(jku, timeout=5)                                                       # LINE 107: [HIGH] SSRF: attacker-supplied jku URL fetched before any auth (internal hosts, 169.254.169.254). Fix: allow-list trusted JWKS URLs
    resp.raise_for_status()
    jwks = resp.json()

    for key_data in jwks.get("keys", []):
        if key_data.get("kid") == kid and key_data.get("kty") == "RSA":
            n = int.from_bytes(base64.urlsafe_b64decode(_pad(key_data["n"])), "big")
            e = int.from_bytes(base64.urlsafe_b64decode(_pad(key_data["e"])), "big")
            return RSAPublicNumbers(e, n).public_key(default_backend())

    raise ValueError(f"kid '{kid}' not found in JWKS")




from flask import Blueprint, request, jsonify, g
from db.connection import get_db
from services.report_service import get_audit_log
from services.user_service import get_user_stats

admin_bp = Blueprint("admin", __name__)


def _require_auth():                                                                          # LINE 130: [HIGH] only checks logged-in, never role == admin -> every admin_bp route is BFLA
    if not getattr(g, "user_id", None):
        return jsonify({"error": "unauthorized"}), 401


@admin_bp.route("/users", methods=["GET"])
def list_users():
    err = _require_auth()                                                                     # LINE 137: [HIGH] BFLA: any logged-in user lists ALL users
    if err:
        return err

    db   = get_db()
    rows = db.execute(
        "SELECT id, username, email, role, created_at FROM users ORDER BY id ASC"             # LINE 143: NOT A VULN: static query, no user input -> no SQLi
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])                                   # LINE 148: [HIGH] BFLA (admin function, no admin check): any user deletes ANY user
def delete_user(user_id):
    err = _require_auth()
    if err:
        return err

    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (user_id,))                                    # LINE 155: NOT A VULN: parameterized (?) -> no SQLi
    db.commit()
    return "", 204


@admin_bp.route("/audit-logs", methods=["GET"])                                               # LINE 160: [HIGH] BFLA (no admin check) + SQL injection via user_id/from/to
def audit_logs():
    err = _require_auth()
    if err:
        return err

    user_filter = request.args.get("user_id", "")                                             # LINE 166: [HIGH] user_id -> unparameterized SQL at line 337
    from_date   = request.args.get("from", "")                                                # LINE 167: [HIGH] from -> SQL injection at line 339
    to_date     = request.args.get("to", "")                                                  # LINE 168: [HIGH] to -> SQL injection at line 341

    entries = get_audit_log(user_filter or None, from_date or None, to_date or None)
    return jsonify({"entries": entries, "count": len(entries)})


@admin_bp.route("/stats/users", methods=["GET"])                                              # LINE 174: [HIGH] BFLA (no admin check) + SQL injection via group_by
def user_stats_admin():
    err = _require_auth()
    if err:
        return err

    group_by = request.args.get("group_by", "role")                                           # LINE 180: [HIGH] group_by -> SQL injection at line 429-430
    stats    = get_user_stats(group_by)
    return jsonify(stats)


@admin_bp.route("/users/<int:user_id>/role", methods=["PATCH"])                               # LINE 185: [CRITICAL] BFLA -> privilege escalation: any user PATCHes their own role to 'admin'
def update_role(user_id):
    err = _require_auth()
    if err:
        return err

    data = request.get_json()
    role = data.get("role")                                                                   # LINE 192: [LOW] role value not validated against an allowed list
    if not role:
        return jsonify({"error": "role required"}), 400

    db = get_db()
    db.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))                         # LINE 197: NOT A VULN: parameterized (?, ?) -> no SQLi (the bug is the missing admin check, line 185)
    db.commit()
    return jsonify({"message": "role updated"})





# ===== users.py =====



from flask import Blueprint, request, jsonify, g
from services.user_service import (
    get_user_by_id, update_password, search_users, hash_pwd,
    update_profile_field, get_user_stats,
)

users_bp = Blueprint("users", __name__)


@users_bp.route("/search", methods=["GET"])                                                   # LINE 218: [HIGH] /search has NO authentication
def search():
    term  = request.args.get("q", "")
    sort  = request.args.get("sort", "created_at")                                            # LINE 221: [HIGH] sort -> ORDER BY injection (line 380)
    order = request.args.get("order", "DESC")                                                 # LINE 222: [HIGH] order -> ORDER BY injection (line 380)

    results = search_users(term, sort, order)                                                 # LINE 224: [HIGH] term/sort/order -> SQL injection in search_users (line 379-380), unauthenticated
    return jsonify({"results": results, "count": len(results)})


@users_bp.route("/account/password", methods=["POST"])
def change_password():
    user_id = getattr(g, "user_id", None)
    if not user_id:
        return jsonify({"error": "unauthorized"}), 401

    data             = request.get_json()
    current_password = data.get("current_password", "")
    new_password     = data.get("new_password", "")

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "user not found"}), 404

    if user["password_hash"] != hash_pwd(current_password):                                   # LINE 242: [MEDIUM] compares an UNSALTED SHA-256 hash (line 361) with != (not constant-time)
        return jsonify({"error": "current password is incorrect"}), 401

    update_password(user["username"], new_password)                                           # LINE 245: [CRITICAL] SECOND-ORDER SQLi: register username admin'-- , change your password -> line 413 overwrites ADMIN's password
    return jsonify({"message": "password updated"})


@users_bp.route("/account/profile", methods=["PATCH"])                                        # LINE 249: [CRITICAL] mass assignment + SQL injection via field/value (line 421)
def update_profile():
    user_id = getattr(g, "user_id", None)
    if not user_id:
        return jsonify({"error": "unauthorized"}), 401

    data  = request.get_json()
    field = data.get("field", "")                                                             # LINE 256: [CRITICAL] attacker chooses ANY column (role, password_hash, email...)
    value = data.get("value", "")                                                             # LINE 257: [CRITICAL] value -> SQL injection at line 421

    if not field or not value:
        return jsonify({"error": "field and value are required"}), 400

    update_profile_field(user_id, field, value)                                               # LINE 262: [CRITICAL] field='role', value='admin' -> make yourself admin
    return jsonify({"message": "profile updated"})


@users_bp.route("/stats", methods=["GET"])                                                    # LINE 266: [HIGH] /stats has NO authentication
def user_stats():
    group_by = request.args.get("group_by", "role")                                           # LINE 268: [HIGH] group_by -> SQL injection (line 429-430), unauthenticated
    stats = get_user_stats(group_by)
    return jsonify(stats)


# ===== report_service.py =====




from db.connection import get_db


def list_by_owner(owner_id: int):
    db   = get_db()
    rows = db.execute(
        "SELECT id, title, owner_id, visibility, created_at FROM reports WHERE owner_id=? ORDER BY created_at DESC",  # LINE 284: NOT A VULN: parameterized (owner_id=?)
        (owner_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def find_by_id(report_id: int):
    db  = get_db()
    row = db.execute(
        "SELECT id, title, content, owner_id, visibility, file_path, created_at FROM reports WHERE id=?",  # LINE 293: NOT A VULN: parameterized (id=?)
        (report_id,),
    ).fetchone()
    return dict(row) if row else None


def log_access(user_id: int, report_id: int):
    db = get_db()
    db.execute(
        "INSERT INTO access_log (user_id, report_id, accessed_at) VALUES (?,?,CURRENT_TIMESTAMP)",  # LINE 302: NOT A VULN: parameterized (?,?)
        (user_id, report_id),
    )
    db.commit()


def filter_reports(owner_id: int, status=None, tag=None, from_date=None, to_date=None,
                   sort="created_at", order="DESC"):
    db  = get_db()
    sql = (
        f"SELECT id, title, owner_id, visibility, created_at "
        f"FROM reports WHERE owner_id={owner_id}"                                             # LINE 313: [MEDIUM] owner_id in f-string: ': int' is only a type hint, not enforced
    )
    if status:
        sql += f" AND status='{status}'"                                                      # LINE 316: [HIGH] SQL injection via status
    if tag:
        sql += f" AND tags LIKE '%{tag}%'"                                                    # LINE 318: [HIGH] SQL injection via tag
    if from_date:
        sql += f" AND created_at >= '{from_date}'"                                            # LINE 320: [HIGH] SQL injection via from_date
    if to_date:
        sql += f" AND created_at <= '{to_date}'"                                              # LINE 322: [HIGH] SQL injection via to_date
    sql += f" ORDER BY {sort} {order}"                                                        # LINE 323: [HIGH] ORDER BY injection via sort/order (can't parameterize -> use an allow-list)
    return [dict(r) for r in db.execute(sql).fetchall()]


def bulk_fetch(ids: str):
    db  = get_db()
    sql = "SELECT id, title, owner_id, visibility, created_at FROM reports WHERE id IN (" + ids + ")"  # LINE 329: [HIGH] SQL injection via ids + BOLA: no owner_id filter -> read anyone's reports
    return [dict(r) for r in db.execute(sql).fetchall()]


def get_audit_log(user_filter=None, from_date=None, to_date=None):
    db  = get_db()
    sql = "SELECT user_id, report_id, accessed_at FROM access_log WHERE 1=1"
    if user_filter:
        sql += " AND user_id=" + user_filter                                                  # LINE 337: [HIGH] SQL injection via user_filter (numeric, no quotes)
    if from_date:
        sql += f" AND accessed_at >= '{from_date}'"                                           # LINE 339: [HIGH] SQL injection via from_date
    if to_date:
        sql += f" AND accessed_at <= '{to_date}'"                                             # LINE 341: [HIGH] SQL injection via to_date
    sql += " ORDER BY accessed_at DESC"
    return [dict(r) for r in db.execute(sql).fetchall()]



# ===== user_service.py =====


import hashlib
from datetime import datetime, timedelta, timezone

import jwt
from db.connection import get_db

JWT_SECRET    = "hs256-platform-secret"                                                       # LINE 356: [HIGH] hardcoded, guessable HS256 secret -> forge any token. Load from a secret manager
JWT_ALGORITHM = "HS256"


def hash_pwd(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()                                      # LINE 361: [HIGH] unsalted single SHA-256 for passwords -> GPU-crackable. Use argon2id/bcrypt


def find_by_credentials(username: str, password: str):
    db = get_db()
    sql = (
        f"SELECT id, username, email, role FROM users "
        f"WHERE username='{username}' AND password_hash='{hash_pwd(password)}'"               # LINE 368: [CRITICAL] LOGIN SQL INJECTION: username = admin'--  comments out the password check -> log in as admin
    )
    cursor = db.execute(sql)                                                                  # LINE 370: [CRITICAL] injected login query executes here
    row = cursor.fetchone()
    return dict(row) if row else None


def search_users(term: str, sort: str = "created_at", order: str = "DESC"):
    db = get_db()
    sql = (
        f"SELECT id, username, email, role, created_at FROM users "
        f"WHERE username LIKE '%{term}%' OR email LIKE '%{term}%' "                           # LINE 379: [HIGH] SQL injection via term (UNION SELECT ... password_hash ...)
        f"ORDER BY {sort} {order}"                                                            # LINE 380: [HIGH] ORDER BY injection via sort/order
    )
    rows = db.execute(sql).fetchall()
    return [dict(r) for r in rows]


def username_exists(username: str) -> bool:
    db = get_db()
    row = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()         # LINE 388: NOT A VULN: parameterized
    return row is not None


def create_user(username: str, email: str, full_name: str, password: str):
    db = get_db()
    db.execute(
        "INSERT INTO users (username, email, full_name, password_hash) VALUES (?,?,?,?)",     # LINE 395: NOT A VULN: parameterized (but stores unsalted SHA-256, line 361)
        (username, email, full_name, hash_pwd(password)),
    )
    db.commit()


def get_user_by_id(user_id: int):
    db = get_db()
    row = db.execute(
        "SELECT id, username, email, role, password_hash FROM users WHERE id=?", (user_id,)   # LINE 404: NOT A VULN: parameterized (password_hash only used internally)
    ).fetchone()
    return dict(row) if row else None


def update_password(username: str, new_password: str):
    db = get_db()
    sql = (
        f"UPDATE users SET password_hash='{hash_pwd(new_password)}', "                        # LINE 412: NOT A VULN: hex hash output can't inject
        f"updated_at=CURRENT_TIMESTAMP WHERE username='{username}'"                           # LINE 413: [CRITICAL] SECOND-ORDER SQLi: stored username placed in f-string -> account takeover
    )
    db.execute(sql)
    db.commit()


def update_profile_field(user_id: int, field: str, value: str):
    db  = get_db()
    sql = f"UPDATE users SET {field}='{value}', updated_at=CURRENT_TIMESTAMP WHERE id={user_id}"  # LINE 421: [CRITICAL] SQL injection in field AND value + mass assignment (SET role='admin')
    db.execute(sql)
    db.commit()


def get_user_stats(group_by: str):
    db  = get_db()
    sql = (
        f"SELECT {group_by}, COUNT(*) AS total, MAX(created_at) AS latest "                   # LINE 429: [HIGH] SQL injection via group_by (column name)
        f"FROM users GROUP BY {group_by}"                                                     # LINE 430: [HIGH] SQL injection via group_by
    )
    return [dict(r) for r in db.execute(sql).fetchall()]


def build_token(user_id, email: str, role: str) -> str:                                       # LINE 435: [HIGH] tokens signed with the hardcoded secret from line 356 (exp=24h is fine)
    payload = {
        "user_id": user_id,
        "email":   email,
        "role":    role,
        "iat":     datetime.now(tz=timezone.utc).timestamp(),
        "exp":     (datetime.now(tz=timezone.utc) + timedelta(hours=24)).timestamp(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)                           # LINE 443: [HIGH] signs with the hardcoded secret


####################################################################################################
# SUMMARY (line numbers match the original file)
#
# CRITICAL  13/19/93   InternalAuth never verifies the signature -> forge any user/role
# CRITICAL  67/73      jku injection -> attacker-hosted JWKS -> forge any token
# CRITICAL  368/370    Login SQL injection: admin'-- -> log in as admin
# CRITICAL  245/413    Second-order SQLi in update_password -> take over admin
# CRITICAL  249/421    Mass assignment + SQLi in update_profile_field -> become admin
# CRITICAL  185        BFLA: any user sets their own role to admin
# HIGH      107        SSRF via jku fetch (unauthenticated)
# HIGH      47         RS256 + HS256 mixed (algorithm-confusion pattern)
# HIGH      130        _require_auth has no admin check -> all admin routes BFLA (137, 148, 160, 174)
# HIGH      160-168/337-341  audit-log SQL injection
# HIGH      174-180/266-268/429-430  group_by SQL injection (/stats is unauthenticated)
# HIGH      218-224/379-380  /search unauthenticated + SQL injection
# HIGH      313-323    filter_reports SQL injection (status, tag, dates, sort, order)
# HIGH      329        bulk_fetch SQL injection + BOLA
# HIGH      356/435/443  hardcoded JWT secret
# HIGH      361        unsalted SHA-256 password hashing
# LOW       52/80      str(exc) error leakage
#
# NOT VULNERABLE: 34, 143, 155, 197, 284, 293, 302, 388, 395, 404, 412 (no user input or parameterized with ?).
# sqlite3 execute() runs one statement, so stacked queries (; DROP TABLE) fail; UNION/boolean still work.
#
# CHAIN: forge a token (line 19 or 73) OR login SQLi (368) -> PATCH own role to admin (185)
#        -> delete users (148), read audit logs (160), dump hashes via /search (379).
####################################################################################################
