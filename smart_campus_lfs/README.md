# Smart Campus Lost & Found System

Flask + SQLite web app. Students report lost/found items; the system suggests matches
(difflib text similarity on title, description, location within the same category),
notifies owners, and lets owners/admins approve claims.

## Run
    pip install -r requirements.txt
    python app.py          # http://127.0.0.1:5000

On first development startup, a random one-time admin password is printed in the server log unless `INITIAL_ADMIN_PASSWORD` is set. Set `INITIAL_ADMIN_EMAIL` and a password of at least 12 characters before startup to choose credentials. If `INITIAL_ADMIN_PASSWORD` is set, it is applied to existing admin accounts at each startup; unset it after bootstrap if you want password-reset changes to persist. Existing databases using the old `admin123` password are rotated on startup.

## Optional email and security settings
- `SECRET_KEY`: use a long, random value in production. Password reset links are signed with this key and expire after one hour.
- `APP_ENV`: defaults to `development`; set to `production` to require a configured secret/admin password and disable Flask debug mode.
- `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD`: create the initial admin account; production startup requires a password when seeding or rotating the default account.
- `DATABASE_PATH`: optional SQLite database path, useful for isolated test runs.
- `COLLEGE_EMAIL_DOMAIN`: optional exact signup domain allowlist; unset by default, so any syntactically valid email address can register. Set it to your campus domain (for example, `aiktc.ac.in`) to enforce one.
- `REPORTS_PER_HOUR`: per-account report limit; defaults to `5`.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, and `SMTP_FROM`: configure outgoing email. Port 587 with `SMTP_USE_TLS=true` is the default; set `SMTP_USE_SSL=true` for an SSL SMTP endpoint such as port 465.

Email notifications are skipped when `SMTP_HOST` is unset. Configure SMTP to deliver match, claim, and password-reset messages.

## Tests
    python -m unittest discover -s tests

## Architecture
- Database: SQLite (`schema.sql`): users, items, claims, notifications
- Backend: `app.py` routes, auth (hashed passwords, sessions), matching engine, file uploads
- Frontend: Jinja2 templates in `templates/`, `static/style.css`
- Flow: report -> auto-match + notify -> claim with proof -> approve -> item resolved
