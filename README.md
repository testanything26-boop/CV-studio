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
4. Deploy. Note the public URL, e.g. `https://cv-studio-auth.onrender.com`
5. Open `https://<your-url>/admin`, enter the ADMIN_KEY, approve user requests.

## API

- `POST /api/register` {name, email, password} → account created as `pending`
- `POST /api/login` {email, password} → {token, name, email} (only if approved)
- `GET /api/me` (Authorization: Bearer TOKEN) → {name, email}
- `GET /admin` → approval dashboard (needs ADMIN_KEY)

## Notes

- Passwords are hashed with PBKDF2-SHA256 (stdlib, no extra deps).
- Tokens are random 32-byte strings; only their SHA-256 is stored.
- SQLite lives in `./data/app.db`. On Render's free tier the disk is
  ephemeral — if the service is redeployed the user list resets and people
  re-register (approval takes seconds). For a handful of users this is fine.
- Login is throttled: 10 attempts / 5 min per IP.
