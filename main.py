"""CV Studio auth backend — FastAPI + SQLite/Turso. Run: uvicorn main:app --host 0.0.0.0 --port $PORT
Env: ADMIN_KEY (required for /admin).
     TURSO_URL + TURSO_TOKEN (optional): when set, accounts live in a free Turso
         cloud database and SURVIVE Render restarts/redeploys.
     Without them, data goes to ./data/app.db on the container disk, which
     Render's free plan WIPES on every restart/redeploy.
"""
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator

try:
    import libsql_experimental as libsql
    HAVE_LIBSQL = True
except ImportError:
    libsql = None
    HAVE_LIBSQL = False

ADMIN_KEY = os.environ.get("ADMIN_KEY", "")
TURSO_URL = os.environ.get("TURSO_URL", "").strip()
TURSO_TOKEN = os.environ.get("TURSO_TOKEN", "").strip()

DATA_DIR = Path(os.environ.get("DATA_DIR", "./data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB = DATA_DIR / "app.db"
BUILD = "2026-10-12"

if TURSO_URL and TURSO_TOKEN and HAVE_LIBSQL:
    STORAGE = "turso"
else:
    if (TURSO_URL or TURSO_TOKEN) and not HAVE_LIBSQL:
        print("WARNING: TURSO_URL/TURSO_TOKEN set but libsql client not installed; "
              "using local SQLite (data will NOT persist on Render).")
    STORAGE = "sqlite-local"

app = FastAPI(title="CV Studio Auth")


class _LibsqlCursor:
    """Wraps a libsql cursor so rows come back as dicts like sqlite3.Row."""
    def __init__(self, cur):
        self._cur = cur
        self._cols = [d[0] for d in cur.description] if cur.description else []

    def _conv(self, r):
        return dict(zip(self._cols, tuple(r))) if self._cols else r

    def fetchone(self):
        r = self._cur.fetchone()
        return None if r is None else self._conv(r)

    def fetchall(self):
        return [self._conv(r) for r in self._cur.fetchall()]


class _LibsqlConn:
    def __init__(self, raw):
        self._raw = raw

    def execute(self, sql, args=()):
        return _LibsqlCursor(self._raw.execute(sql, args))

    def commit(self):
        self._raw.commit()

    def close(self):
        self._raw.close()


def db():
    if STORAGE == "turso":
        return _LibsqlConn(libsql.connect(TURSO_URL, auth_token=TURSO_TOKEN))
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    c = db()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
        pw_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
        created_at REAL NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS tokens(
        token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
        created_at REAL NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS attempts(
        ip TEXT PRIMARY KEY, fails INTEGER NOT NULL, window_start REAL NOT NULL)""")
    c.commit()
    c.close()


init_db()


def hash_pw(pw: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${h}"


def check_pw(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$")
    except ValueError:
        return False
    calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()
    return hmac.compare_digest(calc, h)


def need_admin(x_admin_key: str = Header(default="")):
    if not ADMIN_KEY or x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "Admin key required")
    return True


def client_ip(req: Request) -> str:
    fwd = req.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (req.client.host if req.client else "?")



def throttle_ok(ip: str) -> bool:
    now = time.time()
    c = db()
    row = c.execute("SELECT fails, window_start FROM attempts WHERE ip=?", (ip,)).fetchone()
    if row and now - row["window_start"] < 300 and row["fails"] >= 10:
        c.close()
        return False
    c.close()
    return True


def throttle_hit(ip: str):
    now = time.time()
    c = db()
    row = c.execute("SELECT fails, window_start FROM attempts WHERE ip=?", (ip,)).fetchone()
    if row and now - row["window_start"] < 300:
        c.execute("UPDATE attempts SET fails=fails+1 WHERE ip=?", (ip,))
    else:
        c.execute("REPLACE INTO attempts(ip,fails,window_start) VALUES(?,?,?)",
                  (ip, 1, now))
    c.commit()
    c.close()


def throttle_clear(ip: str):
    c = db()
    c.execute("DELETE FROM attempts WHERE ip=?", (ip,))
    c.commit()
    c.close()


def _check_email(v: str) -> str:
    v = v.strip().lower()
    if "@" not in v or "." not in v.rsplit("@", 1)[-1] or len(v) < 5:
        raise ValueError("Enter a valid email address.")
    return v


class Register(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: str = Field(min_length=3, max_length=120)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def _email_ok(cls, v):
        return _check_email(v)


class Login(BaseModel):
    email: str = Field(min_length=3, max_length=120)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def _email_ok(cls, v):
        return _check_email(v)


@app.get("/api/health")
def health():
    return {"ok": True, "build": BUILD, "storage": STORAGE}


@app.post("/api/register")
def register(r: Register):
    c = db()
    exists = c.execute("SELECT id FROM users WHERE email=?",
                       (r.email.lower(),)).fetchone()
    if exists:
        c.close()
        raise HTTPException(400, "This email is already registered.")
    c.execute("INSERT INTO users(name,email,pw_hash,status,created_at) VALUES(?,?,?,?,?)",
              (r.name.strip(), r.email.lower(), hash_pw(r.password),
               "pending", time.time()))
    c.commit()
    c.close()
    return {"ok": True,
            "message": "Request received. The admin will approve your account, then you can sign in."}


@app.post("/api/login")
def login(r: Login, request: Request):
    ip = client_ip(request)
    if not throttle_ok(ip):
        raise HTTPException(429, "Too many attempts. Try again in a few minutes.")
    c = db()
    u = c.execute("SELECT * FROM users WHERE email=?", (r.email.lower(),)).fetchone()
    if not u or not check_pw(r.password, u["pw_hash"]):
        c.close()
        throttle_hit(ip)
        raise HTTPException(401, "Email or password is wrong.")
    if u["status"] == "pending":
        c.close()
        raise HTTPException(403, "Your account is waiting for admin approval.")
    if u["status"] != "approved":
        c.close()
        raise HTTPException(403, "This account has been disabled.")
    throttle_clear(ip)
    token = secrets.token_urlsafe(32)
    th = hashlib.sha256(token.encode()).hexdigest()
    c.execute("INSERT INTO tokens(token_hash,user_id,created_at) VALUES(?,?,?)",
              (th, u["id"], time.time()))
    c.commit()
    c.close()
    return {"ok": True, "token": token, "name": u["name"]}


def user_from_token(auth: str):
    if not auth or not auth.startswith("Bearer "):
        return None
    th = hashlib.sha256(auth[7:].encode()).hexdigest()
    c = db()
    t = c.execute("SELECT user_id FROM tokens WHERE token_hash=?", (th,)).fetchone()
    if not t:
        c.close()
        return None
    u = c.execute("SELECT id,name,email,status FROM users WHERE id=?",
                  (t["user_id"],)).fetchone()
    c.close()
    if not u or u["status"] != "approved":
        return None
    return u


@app.get("/api/me")
def me(request: Request):
    u = user_from_token(request.headers.get("authorization", ""))
    if not u:
        raise HTTPException(401, "Not signed in.")
    return {"ok": True, "name": u["name"], "email": u["email"]}


@app.get("/admin/api/users")
def admin_list(f: str = "pending", ok: bool = Depends(need_admin)):
    q = "SELECT id,name,email,status,created_at FROM users"
    if f in ("pending", "approved", "disabled"):
        q += " WHERE status=? ORDER BY created_at DESC"
        args = (f,)
    else:
        q += " ORDER BY created_at DESC"
        args = ()
    c = db()
    rows = [dict(r) for r in c.execute(q, args).fetchall()]
    c.close()
    return {"users": rows}


@app.post("/admin/api/users/{uid}/approve")
def admin_approve(uid: int, ok: bool = Depends(need_admin)):
    c = db()
    c.execute("UPDATE users SET status='approved' WHERE id=?", (uid,))
    c.commit()
    c.close()
    return {"ok": True}


@app.post("/admin/api/users/{uid}/reject")
def admin_reject(uid: int, ok: bool = Depends(need_admin)):
    c = db()
    c.execute("DELETE FROM users WHERE id=? AND status='pending'", (uid,))
    c.commit()
    c.close()
    return {"ok": True}


@app.post("/admin/api/users/{uid}/disable")
def admin_disable(uid: int, ok: bool = Depends(need_admin)):
    c = db()
    c.execute("UPDATE users SET status='disabled' WHERE id=?", (uid,))
    c.execute("DELETE FROM tokens WHERE user_id=?", (uid,))
    c.commit()
    c.close()
    return {"ok": True}


ADMIN_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CV Studio - Admin</title>
<style>
body{font-family:-apple-system,'Segoe UI',sans-serif;background:#101216;color:#e8eaed;
 max-width:760px;margin:0 auto;padding:32px 16px}
.card{background:#1a1d22;border:1px solid #2c3138;border-radius:12px;padding:24px}
input{width:100%;box-sizing:border-box;background:#0f1114;border:1px solid #2c3138;
 color:#e8eaed;border-radius:8px;padding:10px;font-size:15px}
button{background:#1a73e8;color:#fff;border:0;border-radius:8px;padding:9px 18px;
 font-size:14px;cursor:pointer;margin:2px 4px 2px 0}
button.red{background:#5f2120}
table{width:100%;border-collapse:collapse;font-size:14px;margin-top:12px}
td,th{padding:8px;border-bottom:1px solid #2c3138;text-align:left}
.st-pending{color:#fbbc04}.st-approved{color:#81c995}.st-disabled{color:#f28b82}
#keymsg{color:#f28b82;font-size:13px;margin-top:8px;min-height:18px}
.build{color:#5f6368;font-size:11px;margin-top:14px}
.filters{margin:14px 0 4px}
</style></head><body>
<div id="login" class="card">
  <h2>Enter admin key</h2>
  <input type="password" id="key" placeholder="ADMIN_KEY from Render dashboard"
         onkeydown="if(event.key==='Enter')go()">
  <div style="margin-top:10px"><button onclick="go()">Open</button></div>
  <div id="keymsg"></div>
  <div class="build">build __BUILD__ · storage: __STORAGE__ - if you do not see this line, the new file has not deployed yet</div>
</div>
<div id="panel" class="card" style="display:none">
  <h2>Account approvals</h2>
  <div class="filters">
    <button onclick="load('pending')">Pending</button>
    <button onclick="load('approved')">Approved</button>
    <button onclick="load('all')">All</button>
  </div>
  <div id="list"><p>Loading...</p></div>
</div>
<script>
var KEY='';
async function api(p,opt){
  opt=opt||{};
  var h={'X-Admin-Key':KEY};
  if(opt.headers){for(var k in opt.headers){h[k]=opt.headers[k];}}
  var r=await fetch(p,{method:opt.method||'GET',headers:h});
  var d=await r.json();
  if(!r.ok){throw new Error(d.detail||('Error '+r.status));}
  return d;
}
async function go(){
  KEY=document.getElementById('key').value;
  var msg=document.getElementById('keymsg');
  msg.textContent='';
  if(!KEY){msg.textContent='Type the admin key first.';return;}
  try{
    await api('/admin/api/users?f=pending');
    document.getElementById('login').style.display='none';
    document.getElementById('panel').style.display='block';
    load('pending');
  }catch(e){
    msg.textContent=e.message+' - check the ADMIN_KEY value in your Render dashboard (Environment tab).';
  }
}
async function load(f){
  var box=document.getElementById('list');
  try{
    var d=await api('/admin/api/users?f='+f);
    var rows=d.users.map(function(u){
      var btns='';
      if(u.status==='pending'){
        btns=`<button onclick="act(${u.id},'approve')">Approve</button>`+
             `<button class="red" onclick="act(${u.id},'reject')">Reject</button>`;
      }else if(u.status==='approved'){
        btns=`<button class="red" onclick="act(${u.id},'disable')">Disable</button>`;
      }
      return `<tr><td>${u.name}</td><td>${u.email}</td>`+
             `<td class="st-${u.status}">${u.status}</td><td>${btns}</td></tr>`;
    }).join('');
    box.innerHTML='<table><tr><th>Name</th><th>Email</th><th>Status</th><th></th></tr>'+
                  rows+'</table>';
  }catch(e){
    box.innerHTML='<p style="color:#f28b82">'+e.message+'</p>';
  }
}
async function act(id,a){
  try{await api('/admin/api/users/'+id+'/'+a,{method:'POST'});load('pending');}
  catch(e){alert(e.message);}
}
</script>
</body></html>
""".replace("__BUILD__", BUILD).replace("__STORAGE__", STORAGE)


@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    return ADMIN_HTML


@app.get("/", response_class=HTMLResponse)
def index():
    return """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CV Studio Auth</title>
<style>
body{font-family:-apple-system,'Segoe UI',sans-serif;background:#101216;color:#e8eaed;
 max-width:640px;margin:0 auto;padding:40px 20px}
.card{background:#1a1d22;border:1px solid #2c3138;border-radius:12px;padding:24px}
h1{font-size:20px;margin-bottom:8px}
p{font-size:14px;color:#9aa0a6;line-height:1.7}
a{color:#8ab4f8}
</style></head><body>
<div class="card"><h1>CV Studio - login server</h1>
<p>This server handles sign-in and account approvals for the CV Studio app.</p>
<p><a href="/admin">Admin approval page</a> (needs your ADMIN_KEY)<br>
App users sign in inside CV Studio, not here.</p>
<p>Status: running</p></div>
</body></html>
"""
