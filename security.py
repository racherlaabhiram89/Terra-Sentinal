"""Authentication, encryption, record signing and tamper-evident audit trail."""
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import time

import jwt
from cryptography.fernet import Fernet

SECRET = os.environ.get("APAAR_SECRET", "dev-only-secret-change-me-before-deploying")
_fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(("enc:" + SECRET).encode()).digest()))


def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------- passwords / API keys ----------
def hash_password(pw, salt=None):
    salt = salt or secrets.token_hex(8)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 120_000)
    return f"{salt}${dk.hex()}"


def check_password(pw, stored):
    salt = stored.split("$")[0]
    return hmac.compare_digest(hash_password(pw, salt), stored)


def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()


def new_api_key():
    return "apaar_" + secrets.token_urlsafe(32)


# ---------- JWT ----------
def make_token(user):
    payload = {"sub": user["username"], "role": user["role"],
               "inst": user["institution_id"], "exp": int(time.time()) + 8 * 3600}
    return jwt.encode(payload, SECRET, algorithm="HS256")


def decode_token(token):
    return jwt.decode(token, SECRET, algorithms=["HS256"])


# ---------- PII encryption at rest ----------
def enc(value):
    return _fernet.encrypt(value.encode()).decode() if value else ""


def dec(value):
    try:
        return _fernet.decrypt(value.encode()).decode() if value else ""
    except Exception:
        return ""


# ---------- masking ----------
def mask_name(name):
    return " ".join(p[0] + "*" * (len(p) - 1) for p in (name or "").split())


def mask_apaar(a):
    return "X" * 8 + (a or "")[-4:]


# ---------- verifiable record signature ----------
def sign(payload: dict) -> str:
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()


# ---------- hash-chained audit log ----------
def audit(conn, actor, role, action, target="", detail=""):
    last = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["hash"] if last else "GENESIS"
    ts = now()
    h = hashlib.sha256(f"{prev}|{ts}|{actor}|{role}|{action}|{target}|{detail}".encode()).hexdigest()
    conn.execute("INSERT INTO audit_log(ts,actor,role,action,target,detail,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?)",
                 (ts, actor, role, action, target, detail, prev, h))


def audit_chain_ok(conn):
    prev = "GENESIS"
    for r in conn.execute("SELECT * FROM audit_log ORDER BY id"):
        h = hashlib.sha256(f"{prev}|{r['ts']}|{r['actor']}|{r['role']}|{r['action']}|{r['target']}|{r['detail']}".encode()).hexdigest()
        if r["prev_hash"] != prev or r["hash"] != h:
            return False, r["id"]
        prev = r["hash"]
    return True, None
