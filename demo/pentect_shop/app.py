"""Pentect Shop -- a deliberately vulnerable webapp for masking demos.

Why this exists
===============
The Juice Shop demo proves the masking pipeline preserves the analytic
signal, but Claude has likely seen Juice Shop in its training data, so
the recall could be inflated by memorization rather than genuine
inference from the masked trace.

This app is original code with vulnerabilities deliberately spelled out
in source. None of the strings or paths match Juice Shop. The point is
to capture a HAR, mask it with Pentect, and ask Claude to identify
findings on data it definitely has not seen before.

Vulnerabilities planted (cross-check with the test capture script):
  V1. SQLi in /api/products/search via raw string concat
  V2. IDOR in /api/users/<id> -- no auth check, returns full record
  V3. Admin endpoint /api/admin/dump exposed without auth
  V4. JWT payload contains the user's bcrypt-shaped password hash
  V5. Cleartext HTTP on default port (no TLS)
  V6. Verbose 500 error in /api/baskets/<id> leaks stack trace info
  V7. Default admin credentials: admin@pentect-shop.local / hunter2demo
  V8. Directory exposure /backup/ + downloadable /backup/db.sql.bak
  V9. Mass assignment via PATCH /api/users/<id> (role overwritable)

NOT FOR PRODUCTION. NEVER expose this on a public network.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_file, send_from_directory


ROOT = Path(__file__).parent
DB_PATH = ROOT / "shop.db"
BACKUP_DIR = ROOT / "backup"
JWT_SECRET = b"pentect-shop-demo-not-a-real-secret"


# --- DB seeding ----------------------------------------------------------

def _seed_db() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            email TEXT,
            password_hash TEXT,
            role TEXT,
            display_name TEXT
        );
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            description TEXT,
            price INTEGER
        );
        CREATE TABLE baskets (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            items TEXT
        );
        """
    )
    # NOTE V4 / V7: weak hash + default admin password embedded as a string.
    cur.executemany(
        "INSERT INTO users(id, email, password_hash, role, display_name) VALUES (?,?,?,?,?)",
        [
            (1, "admin@pentect-shop.local",
             "5f4dcc3b5aa765d61d8327deb882cf99",  # md5("password")
             "admin", "Site Admin"),
            (2, "haruko@pentect-shop.local",
             "ab4f63f9ac65152575886860dde480a1",  # md5("test")
             "customer", "Haruko Tanaka"),
            (3, "ren@pentect-shop.local",
             "098f6bcd4621d373cade4e832627b4f6",  # md5("test")
             "customer", "Ren Sato"),
        ],
    )
    cur.executemany(
        "INSERT INTO products(id, name, description, price) VALUES (?,?,?,?)",
        [
            (1, "Pentect Sticker Pack", "Five vinyl stickers.", 480),
            (2, "Pentect Hoodie", "Black, organic cotton.", 5800),
            (3, "Pentect Notebook", "A5, 200 pages, dotted.", 1480),
        ],
    )
    cur.executemany(
        "INSERT INTO baskets(id, user_id, items) VALUES (?,?,?)",
        [
            (1, 1, json.dumps([{"product_id": 2, "qty": 1}])),
            (2, 2, json.dumps([{"product_id": 1, "qty": 3}])),
            (3, 3, json.dumps([{"product_id": 3, "qty": 1}])),
        ],
    )
    conn.commit()
    conn.close()

    # NOTE V8: directory listing + leftover backup file.
    BACKUP_DIR.mkdir(exist_ok=True)
    (BACKUP_DIR / "README.txt").write_text(
        "internal backup share. DO NOT MOVE.\n", encoding="utf-8"
    )
    (BACKUP_DIR / "db.sql.bak").write_text(
        "-- Pentect Shop snapshot\n"
        "INSERT INTO users VALUES (1,'admin@pentect-shop.local','5f4dcc3b5aa765d61d8327deb882cf99','admin','Site Admin');\n"
        "INSERT INTO users VALUES (2,'haruko@pentect-shop.local','ab4f63f9ac65152575886860dde480a1','customer','Haruko Tanaka');\n",
        encoding="utf-8",
    )


# --- JWT helpers (intentionally crude, see V4) ---------------------------

def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _make_jwt(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h_b = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p_b = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(JWT_SECRET, f"{h_b}.{p_b}".encode(), hashlib.sha256).digest()
    return f"{h_b}.{p_b}.{_b64url(sig)}"


# --- App -----------------------------------------------------------------

app = Flask(__name__)


@app.before_request
def _seed_once() -> None:
    if not DB_PATH.exists():
        _seed_db()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.get("/")
def index():
    return (
        "<h1>Pentect Shop</h1>"
        "<p>API: /api/products, /api/users/&lt;id&gt;, /api/products/search?q=...</p>"
    )


@app.get("/api/products")
def list_products():
    conn = _connect()
    rows = conn.execute("SELECT * FROM products").fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/products/search")
def search_products():
    # V1: SQL injection. The query parameter is interpolated directly.
    q = request.args.get("q", "")
    conn = _connect()
    sql = f"SELECT * FROM products WHERE name LIKE '%{q}%'"
    try:
        rows = conn.execute(sql).fetchall()
    except sqlite3.Error as e:
        # V6-ish: return the raw DB error to the client.
        return jsonify({"error": str(e), "sql": sql}), 500
    return jsonify([dict(r) for r in rows])


@app.get("/api/users/<int:user_id>")
def get_user(user_id: int):
    # V2: IDOR. No authorization check at all.
    conn = _connect()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        abort(404)
    return jsonify(dict(row))


@app.patch("/api/users/<int:user_id>")
def patch_user(user_id: int):
    # V9: mass assignment. Caller can supply role and clobber it.
    data = request.get_json(silent=True) or {}
    fields = {k: v for k, v in data.items() if k in {"display_name", "role", "email"}}
    if not fields:
        return jsonify({"error": "no fields"}), 400
    conn = _connect()
    sets = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(f"UPDATE users SET {sets} WHERE id = ?", (*fields.values(), user_id))
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify(dict(row))


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")
    h = hashlib.md5(password.encode()).hexdigest()
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM users WHERE email = ? AND password_hash = ?",
        (email, h),
    ).fetchone()
    if not row:
        return jsonify({"error": "invalid"}), 401

    # V4: bake the password hash into the JWT payload.
    payload = {
        "sub": row["id"],
        "email": row["email"],
        "role": row["role"],
        "password_hash": row["password_hash"],
        "iat": int(time.time()),
    }
    return jsonify({"token": _make_jwt(payload), "user": dict(row)})


@app.get("/api/baskets/<int:basket_id>")
def get_basket(basket_id: int):
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM baskets WHERE id = ?", (basket_id,)
    ).fetchone()
    if not row:
        # V6: leak stack-traceish info via the error body.
        return jsonify({
            "error": "basket lookup failed",
            "trace": [
                f"  File 'app.py', line 1, in get_basket",
                f"  sqlite3.IntegrityError: missing basket id={basket_id}",
            ],
        }), 500
    return jsonify(dict(row))


@app.get("/api/admin/dump")
def admin_dump():
    # V3: admin endpoint with no auth.
    conn = _connect()
    users = [dict(r) for r in conn.execute("SELECT * FROM users").fetchall()]
    return jsonify({"users": users})


@app.get("/backup/")
def backup_listing():
    # V8: directory listing.
    files = sorted(p.name for p in BACKUP_DIR.iterdir())
    body = "\n".join(f"<a href='/backup/{f}'>{f}</a>" for f in files)
    return f"<h2>/backup/</h2><pre>{body}</pre>"


@app.get("/backup/<path:name>")
def backup_file(name: str):
    return send_from_directory(str(BACKUP_DIR), name)


if __name__ == "__main__":
    # V5: cleartext HTTP, no TLS configured.
    _seed_db()
    app.run(host="127.0.0.1", port=5057, debug=False)
