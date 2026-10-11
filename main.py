"""CV Studio Auth Backend — login + admin approval for the CV Studio desktop app.

Deploy: Render free web service (see README).
Admin: set ADMIN_KEY env var on Render; open /admin and enter the key.
"""
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

BASE = Path(__file__).parent
DATA_DIR = BASE / "data"
DATA_DIR.mkdir(exist_ok=True)
DB = DATA_DIR / "app.db"

ADMIN_KEY = os.environ.get("ADMIN_KEY", "")


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with db() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS users(
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT NOT NULL,
                 email TEXT UNIQUE NOT NULL,
                 pw_hash TEXT NOT NULL,
                 salt TEXT NOT NULL,
                 status TEXT NOT NULL DEFAULT 'pending',
                 created_at REAL NOT NULL)"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS tokens(
                 token_hash TEXT PRIMARY KEY,
                 user_id INTEGER NOT NULL,
                 created_at REAL NOT NULL)"""
        )


init_db()

app = FastAPI(title="CV Studio Auth")


# ---------- helpers ----------
def hash_pw(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 200_000
    ).hex()


def check_admin(key: str):
    if not ADMIN_KEY or not key or not hmac.compare_digest(key, ADMIN_KEY):
        raise HTTPException(status_code=403, detail="Admin key required")


def get_user_by_token(token: str):
    th = hashlib.sha256(token.encode()).hexdigest()
    with db() as c:
        row = c.execute(
            "SELECT u.* FROM tokens t JOIN users u ON u.id=t.user_id "
            "WHERE t.token_hash=?",
            (th,),
        ).fetchone()
    return row


# simple in-memory login throttle: 10 attempts / 5 min per IP
_attempts: dict = {}


def throttled(ip: str) -> bool:
    now = time.time()
    lst = [t for t in _attempts.get(ip, []) if now - t < 300]
    _attempts[ip] = lst
    return len(lst) >= 10


def note_attempt(ip: str):
    _attempts.setdefault(ip, []).append(time.time())


# ---------- models ----------
class RegisterIn(BaseModel):
    name: str
    email: str
    password: str


class LoginIn(BaseModel):
    email: str
    password: str


# ---------- public API ----------
@app.post("/api/register")
def register(body: RegisterIn):
    name = body.name.strip()[:80]
    email = body.email.strip().lower()[:120]
    if not name or "@" not in email or len(body.password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Give your name, a valid email and a 6+ character password.",
        )
    salt = secrets.token_hex(16)
    try:
        with db() as c:
            c.execute(
                "INSERT INTO users(name,email,pw_hash,salt,status,created_at)"
                " VALUES(?,?,?,?, 'pending', ?)",
                (name, email, hash_pw(body.password, salt), salt,
                 time.time()),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=400, detail="This email is already registered."
        )
    return {"ok": True,
            "message": "Request received. The admin will approve your account."}


@app.post("/api/login")
def login(body: LoginIn, request: Request):
    ip = request.client.host if request.client else "?"
    if throttled(ip):
        raise HTTPException(status_code=429,
                            detail="Too many attempts. Wait a few minutes.")
    email = body.email.strip().lower()
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE email=?",
                        (email,)).fetchone()
    if not row or not hmac.compare_digest(
            row["pw_hash"], hash_pw(body.password, row["salt"])):
        note_attempt(ip)
        raise HTTPException(status_code=401,
                            detail="Wrong email or password.")
    if row["status"] == "pending":
        raise HTTPException(
            status_code=403,
            detail="Your account is waiting for admin approval.")
    if row["status"] == "disabled":
        raise HTTPException(status_code=403,
                            detail="This account has been disabled.")
    token = secrets.token_urlsafe(32)
    th = hashlib.sha256(token.encode()).hexdigest()
    with db() as c:
        c.execute("INSERT INTO tokens(token_hash,user_id,created_at)"
                  " VALUES(?,?,?)", (th, row["id"], time.time()))
    return {"token": token, "name": row["name"], "email": row["email"]}


@app.get("/api/me")
def me(authorization: str = Header(default="")):
    token = authorization.replace("Bearer ", "").strip()
    row = get_user_by_token(token) if token else None
    if not row or row["status"] != "approved":
        raise HTTPException(status_code=401, detail="Not logged in")
    return {"name": row["name"], "email": row["email"]}


@app.get("/api/health")
def health():
    return {"ok": True}


# ---------- admin ----------
ADMIN_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CV Studio — Admin</title>
<style>
body{font-family:-apple-system,'Segoe UI',sans-serif;background:#101216;color:#e8eaed;
max-width:760px;margin:0 auto;padding:24px}
.card{background:#1a1d22;border:1px solid #2c3138;border-radius:12px;padding:18px;margin-bottom:14px}
h1{font-size:20px}h2{font-size:15px;margin-bottom:10px}
button{background:#2f7cf6;color:#fff;border:none;border-radius:8px;padding:8px 14px;
font-size:13px;cursor:pointer;font-weight:600;margin-right:8px}
button.red{background:#a33}button.gray{background:#33373d}
input{background:#262b32;color:#e8eaed;border:1px solid #3d434c;border-radius:8px;
padding:10px 12px;font-size:14px;width:100%;box-sizing:border-box}
table{width:100%;border-collapse:collapse;font-size:14px}
td,th{padding:8px;border-bottom:1px solid #2c3138;text-align:left}
.st-pending{color:#fbbc04}.st-approved{color:#81c995}.st-disabled{color:#f28b82}
.tabs button{margin-bottom:12px}
#login{display:block}#panel{display:none}
</style></head><body>
<h1>CV Studio — Admin</h1>
<div class="card" id="login">
  <h2>Enter admin key</h2>
  <input type="password" id="key" placeholder="ADMIN_KEY from Render dashboard">
  <div style="margin-top:10px"><button onclick="go()">Open</button></div>
</div>
<div id="panel">
  <div class="card"><div class="tabs">
    <button onclick="load('pending')">Pending</button>
    <button onclick="load('approved')">Approved</button>
    <button onclick="load('all')">All</button>
  </div><div id="list"></div></div>
</div>
<script>
let KEY='';
function go(){KEY=document.getElementById('key').value;
 document.getElementById('login').style.display='none';
 document.getElementById('panel').style.display='block';load('pending');}
async function api(p,opt){const r=await fetch(p,{...opt,headers:{'X-Admin-Key':KEY,
 ...(opt&&opt.headers||{})}});return r.json();}
async function load(f){const d=await api('/admin/api/users?f='+f);
 document.getElementById('list').innerHTML='<table><tr><th>Name</th><th>Email</th>'+
 '<th>Status</th><th></th></tr>'+d.users.map(u=>'<tr><td>'+u.name+'</td><td>'+u.email+
 '</td><td class="st-'+u.status+'">'+u.status+'</td><td>'+
 (u.status==='pending'?'<button onclick="act('+u.id+',\'approve\')">Approve</button>'+
 '<button class="red" onclick="act('+u.id+',\'reject\')">Reject</button>':'')+
 (u.status==='approved'?'<button class="red" onclick="act('+u.id+',\'disable\')">Disable</button>':'')+
 '</td></tr>').join('')+'</table>';}
async function act(id,a){await api('/admin/api/users/'+id+'/'+a,{method:'POST'});load('pending');}
</script></body></html>"""


@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    return ADMIN_HTML


@app.get("/admin/api/users")
def admin_users(f: str = "pending", x_admin_key: str = Header(default="")):
    check_admin(x_admin_key)
    q = "SELECT id,name,email,status,created_at FROM users"
    if f == "pending":
        q += " WHERE status='pending'"
    elif f == "approved":
        q += " WHERE status='approved'"
    q += " ORDER BY created_at DESC"
    with db() as c:
        rows = c.execute(q).fetchall()
    return {"users": [dict(r) for r in rows]}


@app.post("/admin/api/users/{uid}/{action}")
def admin_action(uid: int, action: str,
                 x_admin_key: str = Header(default="")):
    check_admin(x_admin_key)
    mapping = {"approve": "approved", "reject": "disabled",
               "disable": "disabled"}
    if action not in mapping:
        raise HTTPException(status_code=400, detail="bad action")
    with db() as c:
        c.execute("UPDATE users SET status=? WHERE id=?",
                  (mapping[action], uid))
        if mapping[action] == "disabled":
            c.execute("DELETE FROM tokens WHERE user_id=?", (uid,))
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0",
                port=int(os.environ.get("PORT", 8000)))
