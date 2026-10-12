# CV Studio Auth Backend

Login + admin-approval service for the CV Studio desktop app (single app
combining Background Changer and Face Swap).

## Deploy on Render (free)

1. Push this folder to a GitHub repo (e.g. `cv-studio-auth`).
2. Render dashboard → New → Web Service → connect the repo.
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - Plan: Free
3. Environment → add `ADMIN_KEY` = a long random secret (only you know it).
4. **Keep the user list permanent (do this once):** Render's free tier wipes
   the container disk on every redeploy/restart, which deletes the SQLite
   user list. To stop that, use a free Turso cloud database (no card needed):
   - Sign up at https://turso.tech → create a database → copy its URL
     (looks like `libsql://xxxx.turso.io`) and create an auth token.
   - Render dashboard → your service → Environment → add
     `TURSO_URL` = the database URL and `TURSO_TOKEN` = the token.
   - Redeploy. Open `https://<your-url>/api/health` — it should say
     `"storage": "turso"`. Accounts now survive redeploys forever.
   - Without these two variables the app still works, but the user list
     resets on every Render restart (free-plan limitation).
5. Deploy. Note the public URL, e.g. `https://cv-studio-auth.onrender.com`
6. Open `https://<your-url>/admin`, enter the ADMIN_KEY, approve user requests.

## API

- `POST /api/register` {name, email, password} → account created as `pending`
- `POST /api/login` {email, password} → {token, name, email} (only if approved)
- `GET /api/me` (Authorization: Bearer TOKEN) → {name, email}
- `GET /admin` → approval dashboard (needs ADMIN_KEY)

## Notes

- Passwords are hashed with PBKDF2-SHA256 (stdlib, no extra deps).
- Tokens are random 32-byte strings; only their SHA-256 is stored.
- SQLite lives in `./data/app.db` and is used only when `TURSO_URL`/`TURSO_TOKEN`
  are not set. On Render's free tier the disk is ephemeral — without Turso,
  every redeploy/restart resets the user list and people must re-register.
- Login is throttled: 10 attempts / 5 min per IP.
