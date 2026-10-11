"""Smart Campus Lost & Found System - Flask + SQLite backend."""
import csv, difflib, io, os, secrets, smtplib, sqlite3, ssl, uuid
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from flask import (Flask, g, render_template, request, redirect,
                   url_for, session, flash, abort, make_response)
from flask_wtf.csrf import CSRFProtect
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from urllib.parse import urlsplit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE = os.path.dirname(os.path.abspath(__file__))

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

if load_dotenv:
    load_dotenv(os.path.join(BASE, ".env"))
DB_PATH = os.environ.get("DATABASE_PATH") or os.path.join(BASE, "lostfound.db")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR") or os.path.join(BASE, "static", "uploads")
ALLOWED = {"png", "jpg", "jpeg", "gif", "webp"}
CATEGORIES = ["Electronics", "ID / Cards", "Books & Notes", "Bags", "Keys",
              "Clothing", "Wallet / Money", "Accessories", "Other"]
MATCH_THRESHOLD = 0.45
PER_PAGE = 12
REPORT_EXPIRY_DAYS = 60
REPORTS_PER_HOUR = max(1, int(os.environ.get("REPORTS_PER_HOUR", "5")))
PASSWORD_RESET_TTL = 3600
COLLEGE_EMAIL_DOMAIN = os.environ.get("COLLEGE_EMAIL_DOMAIN", "").strip().lower().lstrip("@")
APP_ENV = os.environ.get("APP_ENV", "development").strip().lower()
SECRET_KEY = os.environ.get("SECRET_KEY", "").strip()
if SECRET_KEY == "change-me-in-production":
    SECRET_KEY = ""
if not SECRET_KEY:
    if APP_ENV == "production":
        raise RuntimeError("Set a strong SECRET_KEY before starting in production.")
    SECRET_KEY = secrets.token_hex(32)
INITIAL_ADMIN_PASSWORD = os.environ.get("INITIAL_ADMIN_PASSWORD", "")
if INITIAL_ADMIN_PASSWORD and len(INITIAL_ADMIN_PASSWORD) < 12:
    raise RuntimeError("INITIAL_ADMIN_PASSWORD must contain at least 12 characters.")
INITIAL_ADMIN_EMAIL = os.environ.get("INITIAL_ADMIN_EMAIL", "").strip().lower()

app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY,
                  APP_ENV=APP_ENV,
                  INITIAL_ADMIN_PASSWORD=INITIAL_ADMIN_PASSWORD,
                  INITIAL_ADMIN_EMAIL=INITIAL_ADMIN_EMAIL,
                  MAX_CONTENT_LENGTH=5 * 1024 * 1024,
                  SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=APP_ENV == "production",
                  COLLEGE_EMAIL_DOMAIN=COLLEGE_EMAIL_DOMAIN,
                  COPYRIGHT_NOTICE=os.environ.get(
                      "COPYRIGHT_NOTICE",
                      "© 2026 Campus Lost & Found. All content, branding, design, text, images, and database materials are protected by copyright. Commercial use, redistribution, scraping, cloning, or reuse without prior written permission is prohibited."
                  ),
                  SMTP_HOST=os.environ.get("SMTP_HOST", ""),
                  SMTP_PORT=int(os.environ.get("SMTP_PORT", "587")),
                  SMTP_USER=os.environ.get("SMTP_USER", ""),
                  SMTP_PASSWORD=os.environ.get("SMTP_PASSWORD", ""),
                  SMTP_FROM=os.environ.get("SMTP_FROM", ""),
                  SMTP_USE_TLS=os.environ.get("SMTP_USE_TLS", "true").lower() in ("1", "true", "yes"),
                  SMTP_USE_SSL=os.environ.get("SMTP_USE_SSL", "false").lower() in ("1", "true", "yes"))
csrf = CSRFProtect(app)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------- Database layer ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=30)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA busy_timeout = 30000")
    return g.db

@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()

def ensure_table_columns(conn, table_name, required_columns):
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table_name})")}
    for column_name, column_sql in required_columns:
        if column_name not in existing:
            conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_sql}")


def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    try:
        with open(os.path.join(BASE, "schema.sql")) as f:
            conn.executescript(f.read())

        ensure_table_columns(conn, "users", [
            ("phone", "TEXT"),
            ("is_banned", "INTEGER NOT NULL DEFAULT 0"),
        ])
        ensure_table_columns(conn, "items", [
            ("image", "TEXT"),
            ("date_event", "TEXT"),
            ("status", "TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved'))"),
            ("created_at", "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"),
        ])
        ensure_table_columns(conn, "claims", [
            ("status", "TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected'))"),
            ("created_at", "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"),
        ])
        ensure_table_columns(conn, "notifications", [
            ("item_id", "INTEGER REFERENCES items(id) ON DELETE CASCADE"),
            ("is_read", "INTEGER NOT NULL DEFAULT 0"),
            ("created_at", "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"),
        ])

        conn.execute("CREATE INDEX IF NOT EXISTS idx_items_status ON items(status, type, category)")

        admins = conn.execute(
            "SELECT id,email,password_hash FROM users WHERE role='admin' ORDER BY id"
        ).fetchall()
        if not admins:
            admin_email = app.config["INITIAL_ADMIN_EMAIL"] or (
                f"admin@{COLLEGE_EMAIL_DOMAIN}" if COLLEGE_EMAIL_DOMAIN else "admin@campus.edu"
            )
            password = app.config["INITIAL_ADMIN_PASSWORD"]
            generated_password = not password
            if generated_password:
                if app.config["APP_ENV"] == "production":
                    raise RuntimeError("Set INITIAL_ADMIN_PASSWORD before creating the production admin.")
                password = secrets.token_urlsafe(24)
            conn.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')",
                         ("Campus Admin", admin_email, generate_password_hash(password)))
            if generated_password:
                app.logger.warning("One-time local admin password for %s: %s", admin_email, password)
        else:
            for admin in admins:
                configured_password = app.config["INITIAL_ADMIN_PASSWORD"]
                if configured_password:
                    if not check_password_hash(admin[2], configured_password):
                        conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                                     (generate_password_hash(configured_password), admin[0]))
                    continue
                if check_password_hash(admin[2], "admin123"):
                    if app.config["APP_ENV"] == "production":
                        raise RuntimeError(
                            "The default admin password is still active. Set INITIAL_ADMIN_PASSWORD."
                        )
                    password = secrets.token_urlsafe(24)
                    conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                                 (generate_password_hash(password), admin[0]))
                    app.logger.warning("Rotated the default admin password for %s: %s",
                                       admin[1], password)
        conn.commit()
    finally:
        conn.close()


def item_is_expired(item):
    if item["status"] != "open":
        return False
    try:
        created = datetime.strptime(item["created_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return False
    return datetime.now(timezone.utc) - created > timedelta(days=REPORT_EXPIRY_DAYS)


def parse_positive_int(value, default=1):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def valid_event_date(value):
    try:
        return date.fromisoformat(value) <= date.today()
    except (TypeError, ValueError):
        return False


def safe_redirect_target(target):
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return url_for("index")
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or any(ord(char) < 32 for char in target):
        return url_for("index")
    return target


def delete_uploaded_file(filename):
    if not filename:
        return
    path = os.path.join(UPLOAD_DIR, os.path.basename(filename))
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        app.logger.warning("Could not remove uploaded file: %s", filename)

# ---------- Auth helpers ----------
def current_user():
    uid = session.get("uid")
    return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() if uid else None

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        user = current_user()
        if not user:
            flash("Please log in first.", "warn")
            return redirect(url_for("login", next=request.path))
        if user["is_banned"]:
            session.clear()
            flash("This account is disabled. Contact campus administration.", "error")
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if current_user()["role"] != "admin":
            abort(403)
        return fn(*a, **kw)
    return wrapper

@app.context_processor
def inject_globals():
    user, unread = current_user(), 0
    if user:
        unread = db().execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0",
                              (user["id"],)).fetchone()[0]
    return dict(user=user, unread=unread, categories=CATEGORIES,
                college_email_domain=app.config["COLLEGE_EMAIL_DOMAIN"],
                current_endpoint=request.endpoint)

def send_email(to_address, subject, body):
    """Send an email when SMTP is configured; keep mail failures non-fatal."""
    host = app.config["SMTP_HOST"]
    if not host:
        app.logger.warning("Email not sent: SMTP_HOST is not configured.")
        return False
    if not to_address:
        app.logger.warning("Email not sent: recipient address is missing.")
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = app.config["SMTP_FROM"] or app.config["SMTP_USER"] or "noreply@localhost"
    message["To"] = to_address
    message.set_content(body)
    try:
        if app.config["SMTP_USE_SSL"]:
            with smtplib.SMTP_SSL(host, app.config["SMTP_PORT"], timeout=10,
                                  context=ssl.create_default_context()) as server:
                if app.config["SMTP_USER"]:
                    server.login(app.config["SMTP_USER"], app.config["SMTP_PASSWORD"])
                server.send_message(message)
        else:
            with smtplib.SMTP(host, app.config["SMTP_PORT"], timeout=10) as server:
                if app.config["SMTP_USE_TLS"]:
                    server.starttls(context=ssl.create_default_context())
                if app.config["SMTP_USER"]:
                    server.login(app.config["SMTP_USER"], app.config["SMTP_PASSWORD"])
                server.send_message(message)
    except (OSError, smtplib.SMTPException):
        app.logger.exception("Email delivery failed.")
        return False
    return True

def send_user_email(user_id, subject, body):
    user = db().execute("SELECT email FROM users WHERE id=?", (user_id,)).fetchone()
    return send_email(user["email"], subject, body) if user else False

# ---------- Smart matching ----------
def similarity(a, b):
    return difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio()

def match_score(x, y):
    """Score two items 0..1 from title, description and location similarity."""
    if x["category"] != y["category"]:
        return 0.0
    return (0.5 * similarity(x["title"], y["title"]) +
            0.35 * similarity(x["description"], y["description"]) +
            0.15 * similarity(x["location"], y["location"]))

def find_matches(item, limit=5):
    other = "found" if item["type"] == "lost" else "lost"
    rows = db().execute("SELECT * FROM items WHERE type=? AND status='open' AND created_at >= datetime('now', '-60 days') AND category=? AND id!=?",
                        (other, item["category"], item["id"])).fetchall()
    scored = sorted(((match_score(item, r), r) for r in rows), key=lambda t: -t[0])
    return [(round(s * 100), r) for s, r in scored if s >= MATCH_THRESHOLD][:limit]

def notify_matches(item_id):
    item = db().execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    email_jobs = []
    for pct, other in find_matches(item):
        for owner, target in ((item["user_id"], other), (other["user_id"], item)):
            message = f'Possible match ({pct}%): "{target["title"]}"'
            db().execute("INSERT INTO notifications(user_id,item_id,message) VALUES(?,?,?)",
                         (owner, target["id"], message))
            link = url_for("item", item_id=target["id"], _external=True)
            email_jobs.append((owner, "Possible lost & found match",
                               f"A possible match was found: {target['title']} ({pct}% similar).\n\nView report: {link}"))
    db().commit()
    for user_id, subject, body in email_jobs:
        send_user_email(user_id, subject, body)

# ---------- Public routes ----------
@app.route("/copyright")
def copyright():
    return render_template("copyright.html", copyright_notice=app.config["COPYRIGHT_NOTICE"])

@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    typ = request.args.get("type", "")
    cat = request.args.get("category", "")
    days = request.args.get("days", "all")
    sort = request.args.get("sort", "newest")
    page = parse_positive_int(request.args.get("page", "1"), default=1)

    sql, args = "SELECT i.*, u.name AS owner FROM items i JOIN users u ON u.id=i.user_id WHERE i.status='open' AND i.created_at >= datetime('now', '-60 days')", []
    if q:
        sql += " AND (i.title LIKE ? OR i.description LIKE ? OR i.location LIKE ?)"
        args += [f"%{q}%"] * 3
    if typ in ("lost", "found"):
        sql += " AND i.type=?"; args.append(typ)
    if cat in CATEGORIES:
        sql += " AND i.category=?"; args.append(cat)
    if days in ("7", "30", "60"):
        sql += " AND i.created_at >= datetime('now', ? || ' days')"
        args.append(f"-{days}")

    total = db().execute(f"SELECT COUNT(*) FROM ({sql})", args).fetchone()[0]
    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE) if total else 1
    page = min(page, total_pages)
    order = "ORDER BY i.created_at DESC" if sort != "oldest" else "ORDER BY i.created_at ASC"
    items = db().execute(sql + " " + order + " LIMIT ? OFFSET ?", args + [PER_PAGE, (page - 1) * PER_PAGE]).fetchall()
    stats = db().execute("""SELECT SUM(type='lost' AND status='open' AND created_at >= datetime('now','-60 days')) lost,
        SUM(type='found' AND status='open' AND created_at >= datetime('now','-60 days')) found,
        SUM(status='resolved') resolved FROM items""").fetchone()
    query_params = {k: v for k, v in request.args.to_dict().items() if k != "page"}
    return render_template("index.html", items=items, stats=stats, q=q, typ=typ, cat=cat, days=days,
                           sort=sort, page=page, total_pages=total_pages, query_params=query_params)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name, email, phone, pw = (request.form.get(k, "").strip() for k in ("name", "email", "phone", "password"))
        email = email.lower()
        email_domain = email.rsplit("@", 1)[-1] if "@" in email else ""
        email_parts = email.rsplit("@", 1)
        email_is_valid = (len(email_parts) == 2 and bool(email_parts[0]) and "." in email_parts[1]
                          and not any(char.isspace() for char in email))
        if not (name and email_is_valid and len(pw) >= 6):
            flash("Enter your name, email and a password of at least 6 characters.", "error")
        elif app.config["COLLEGE_EMAIL_DOMAIN"] and email_domain != app.config["COLLEGE_EMAIL_DOMAIN"]:
            flash(f"Use your college email ending in @{app.config['COLLEGE_EMAIL_DOMAIN']}.", "domain")
        elif db().execute("SELECT 1 FROM users WHERE email=?", (email.lower(),)).fetchone():
            flash("That email is already registered. Try logging in.", "error")
        else:
            cur = db().execute("INSERT INTO users(name,email,phone,password_hash) VALUES(?,?,?,?)",
                               (name, email.lower(), phone or None, generate_password_hash(pw)))
            db().commit(); session["uid"] = cur.lastrowid
            return redirect(url_for("index"))
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = db().execute("SELECT * FROM users WHERE email=?", (request.form.get("email", "").lower(),)).fetchone()
        if u and check_password_hash(u["password_hash"], request.form.get("password", "")):
            if u["is_banned"]:
                flash("This account is disabled. Contact campus administration.", "error")
            else:
                session["uid"] = u["id"]
                return redirect(safe_redirect_target(request.args.get("next", "")))
        else:
            flash("Wrong email or password.", "error")
    return render_template("auth.html", mode="login")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = db().execute("SELECT id,email FROM users WHERE email=?", (email,)).fetchone()
        if user:
            token = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="password-reset").dumps(user["email"])
            link = url_for("reset_password", token=token, _external=True)
            send_email(user["email"], "Reset your campus lost & found password",
                       f"Use this link to reset your password. It expires in one hour.\n\n{link}")
        flash("If that email is registered, a password reset link has been sent.", "ok")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="password-reset")
    try:
        email = serializer.loads(token, max_age=PASSWORD_RESET_TTL)
    except (BadSignature, SignatureExpired):
        flash("That reset link is invalid or expired. Request a new one.", "error")
        return redirect(url_for("forgot_password"))

    user = db().execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if not user:
        flash("That reset link is invalid or expired. Request a new one.", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
        elif password != confirmation:
            flash("Passwords do not match.", "error")
        else:
            db().execute("UPDATE users SET password_hash=? WHERE id=?",
                         (generate_password_hash(password), user["id"]))
            db().commit()
            flash("Your password has been reset. Log in with the new password.", "ok")
            return redirect(url_for("login"))
    return render_template("reset_password.html")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.errorhandler(403)
def forbidden_error(_):
    flash("You do not have permission to do that.", "error")
    return redirect(url_for("index"))

@app.errorhandler(404)
def not_found_error(_):
    flash("The page you requested could not be found.", "warn")
    return redirect(url_for("index"))

# ---------- Items ----------
@app.route("/report", methods=["GET", "POST"])
@login_required
def report():
    if request.method == "POST":
        f = request.form
        typ, title, desc = f.get("type"), f.get("title", "").strip(), f.get("description", "").strip()
        cat, loc, when = f.get("category"), f.get("location", "").strip(), f.get("date_event", "")
        if typ not in ("lost", "found") or cat not in CATEGORIES or not (title and desc and loc and when):
            flash("Please fill in every field.", "error")
        elif not valid_event_date(when):
            flash("Enter a valid event date that is today or earlier.", "error")
        elif db().execute("SELECT COUNT(*) FROM items WHERE user_id=? AND created_at >= datetime('now','-1 hour')",
                          (session["uid"],)).fetchone()[0] >= REPORTS_PER_HOUR:
            flash(f"You can post up to {REPORTS_PER_HOUR} reports per hour. Please try again later.", "error")
        else:
            existing = db().execute(
                "SELECT id FROM items WHERE user_id=? AND type=? AND title=? AND location=? AND date_event=? AND created_at >= datetime('now','-1 hour') LIMIT 1",
                (session["uid"], typ, title, loc, when)
            ).fetchone()
            if existing:
                flash("You already posted a very similar report recently. Review the existing item instead.", "warn")
                return redirect(url_for("item", item_id=existing["id"]))
            image, file = None, request.files.get("image")
            if file and file.filename:
                ext = file.filename.rsplit(".", 1)[-1].lower()
                if ext not in ALLOWED:
                    flash("Image must be png, jpg, gif or webp.", "error")
                    return render_template("report.html", today=date.today().isoformat())
                image = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
                file.save(os.path.join(UPLOAD_DIR, image))
            cur = db().execute("""INSERT INTO items(user_id,type,title,description,category,location,date_event,image)
                VALUES(?,?,?,?,?,?,?,?)""", (session["uid"], typ, title, desc, cat, loc, when, image))
            db().commit(); notify_matches(cur.lastrowid)
            flash("Report posted. We'll notify you if a likely match appears.", "ok")
            return redirect(url_for("item", item_id=cur.lastrowid))
    return render_template("report.html", today=date.today().isoformat())

@app.route("/item/<int:item_id>")
def item(item_id):
    it = db().execute("SELECT i.*, u.name AS owner FROM items i JOIN users u ON u.id=i.user_id WHERE i.id=?",
                      (item_id,)).fetchone() or abort(404)
    me = current_user()
    is_mgr = bool(me and (me["id"] == it["user_id"] or me["role"] == "admin"))
    claims = db().execute("SELECT c.*, u.name, u.email, u.phone FROM claims c JOIN users u ON u.id=c.user_id "
                          "WHERE item_id=? ORDER BY c.created_at DESC", (item_id,)).fetchall() if is_mgr else []
    expired = item_is_expired(it)
    return render_template("item.html", it=it, is_mgr=is_mgr, claims=claims,
                           matches=find_matches(it) if it["status"] == "open" and not expired else [],
                           expired=expired)

@app.route("/item/<int:item_id>/claim", methods=["POST"])
@login_required
def claim(item_id):
    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    it = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone() or abort(404)
    msg = request.form.get("message", "").strip()
    if it["user_id"] == session["uid"] or it["status"] != "open":
        conn.rollback()
        flash("You can't claim this item.", "error")
    elif not msg:
        conn.rollback()
        flash("Describe proof of ownership (or where you found it).", "error")
    elif conn.execute("SELECT 1 FROM claims WHERE item_id=? AND user_id=? AND status IN ('pending','approved')",
                      (item_id, session["uid"])).fetchone():
        conn.rollback()
        flash("You already have an active claim for this item.", "warn")
    else:
        conn.execute("INSERT INTO claims(item_id,user_id,message) VALUES(?,?,?)", (item_id, session["uid"], msg))
        conn.execute("INSERT INTO notifications(user_id,item_id,message) VALUES(?,?,?)",
                     (it["user_id"], item_id, f"New claim on \"{it['title']}\""))
        conn.commit()
        claimant = current_user()
        link = url_for("item", item_id=item_id, _external=True)
        send_user_email(it["user_id"], "New claim on your campus report",
                f"{claimant['name']} sent a claim for {it['title']}.\n\nView report: {link}")
        flash("Claim sent to the poster.", "ok")
    return redirect(url_for("item", item_id=item_id))

@app.route("/claim/<int:claim_id>/<action>", methods=["POST"])
@login_required
def decide_claim(claim_id, action):
    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    c = conn.execute("SELECT c.*, i.user_id AS owner_id, i.title, i.status AS item_status "
                     "FROM claims c JOIN items i ON i.id=c.item_id WHERE c.id=?", (claim_id,)).fetchone()
    if not c:
        conn.rollback()
        abort(404)
    if action not in ("approve", "reject") or (session["uid"] != c["owner_id"] and current_user()["role"] != "admin"):
        conn.rollback()
        abort(403)
    if c["status"] != "pending" or c["item_status"] != "open":
        conn.rollback()
        flash("This claim can no longer be changed.", "warn")
        return redirect(url_for("item", item_id=c["item_id"]))
    status = "approved" if action == "approve" else "rejected"
    changed = conn.execute("UPDATE claims SET status=? WHERE id=? AND status='pending'", (status, claim_id))
    if changed.rowcount != 1:
        conn.rollback()
        flash("This claim can no longer be changed.", "warn")
        return redirect(url_for("item", item_id=c["item_id"]))
    rejected_claims = []
    if status == "approved":
        updated_item = conn.execute("UPDATE items SET status='resolved' WHERE id=? AND status='open'",
                                    (c["item_id"],))
        if updated_item.rowcount != 1:
            conn.rollback()
            flash("This item has already been resolved.", "warn")
            return redirect(url_for("item", item_id=c["item_id"]))
        rejected_claims = conn.execute(
            "SELECT id,user_id FROM claims WHERE item_id=? AND id!=? AND status='pending'",
            (c["item_id"], claim_id)
        ).fetchall()
        conn.execute("UPDATE claims SET status='rejected' WHERE item_id=? AND id!=? AND status='pending'",
                     (c["item_id"], claim_id))
        for rejected in rejected_claims:
            conn.execute("INSERT INTO notifications(user_id,item_id,message) VALUES(?,?,?)",
                         (rejected["user_id"], c["item_id"],
                          f'The report "{c["title"]}" was resolved with another claim.'))
    conn.execute("INSERT INTO notifications(user_id,item_id,message) VALUES(?,?,?)",
                 (c["user_id"], c["item_id"], f"Your claim on \"{c['title']}\" was {status}."))
    conn.commit()
    link = url_for("item", item_id=c["item_id"], _external=True)
    send_user_email(c["user_id"], f"Your claim was {status}",
                    f"Your claim on {c['title']} was {status}.\n\nView report: {link}")
    for rejected in rejected_claims:
        send_user_email(rejected["user_id"], "Claim update",
                        f'The report "{c["title"]}" was resolved with another claim.\n\nView report: {link}')
    return redirect(url_for("item", item_id=c["item_id"]))


@app.route("/item/<int:item_id>/edit", methods=["GET", "POST"])
@login_required
def edit_item(item_id):
    it = db().execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone() or abort(404)
    if session["uid"] != it["user_id"] and current_user()["role"] != "admin":
        abort(403)
    if request.method == "POST":
        f = request.form
        typ, title, desc = f.get("type"), f.get("title", "").strip(), f.get("description", "").strip()
        cat, loc, when = f.get("category"), f.get("location", "").strip(), f.get("date_event", "")
        if typ not in ("lost", "found") or cat not in CATEGORIES or not (title and desc and loc and when):
            flash("Please fill in every field.", "error")
            return render_template("report.html", today=date.today().isoformat(), mode="edit", item=it)
        if not valid_event_date(when):
            flash("Enter a valid event date that is today or earlier.", "error")
            return render_template("report.html", today=date.today().isoformat(), mode="edit", item=it)
        image = it["image"]
        old_image = it["image"]
        file = request.files.get("image")
        if file and file.filename:
            ext = file.filename.rsplit(".", 1)[-1].lower()
            if ext not in ALLOWED:
                flash("Image must be png, jpg, gif or webp.", "error")
                return render_template("report.html", today=date.today().isoformat(), mode="edit", item=it)
            image = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
            file.save(os.path.join(UPLOAD_DIR, image))
        db().execute("UPDATE items SET type=?,title=?,description=?,category=?,location=?,date_event=?,image=? WHERE id=?",
                     (typ, title, desc, cat, loc, when, image, item_id))
        db().commit()
        if image != old_image and old_image:
            delete_uploaded_file(old_image)
        flash("Report updated.", "ok")
        return redirect(url_for("item", item_id=item_id))
    return render_template("report.html", today=date.today().isoformat(), mode="edit", item=it)


@app.route("/item/<int:item_id>/resolve", methods=["POST"])
@login_required
def resolve_item(item_id):
    it = db().execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone() or abort(404)
    if session["uid"] != it["user_id"] and current_user()["role"] != "admin":
        abort(403)
    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    updated = conn.execute("UPDATE items SET status='resolved' WHERE id=? AND status='open'", (item_id,))
    if updated.rowcount:
        pending = conn.execute("SELECT id,user_id FROM claims WHERE item_id=? AND status='pending'",
                               (item_id,)).fetchall()
        conn.execute("UPDATE claims SET status='rejected' WHERE item_id=? AND status='pending'", (item_id,))
        title = it["title"]
        for claim_row in pending:
            conn.execute("INSERT INTO notifications(user_id,item_id,message) VALUES(?,?,?)",
                         (claim_row["user_id"], item_id,
                          f'The report "{title}" was resolved by its owner.'))
        conn.commit()
        link = url_for("item", item_id=item_id, _external=True)
        for claim_row in pending:
            send_user_email(claim_row["user_id"], "Claim update",
                            f'The report "{title}" was resolved by its owner.\n\nView report: {link}')
    else:
        conn.rollback()
    flash("Report marked as resolved.", "ok")
    return redirect(url_for("item", item_id=item_id))


@app.route("/item/<int:item_id>/delete", methods=["POST"])
@login_required
def delete_item(item_id):
    it = db().execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone() or abort(404)
    if session["uid"] != it["user_id"] and current_user()["role"] != "admin":
        abort(403)
    db().execute("DELETE FROM items WHERE id=?", (item_id,)); db().commit()
    delete_uploaded_file(it["image"])
    flash("Report removed.", "ok")
    return redirect(url_for("admin" if current_user()["role"] == "admin" else "dashboard"))

# ---------- Dashboard / Admin ----------
@app.route("/dashboard")
@login_required
def dashboard():
    uid = session["uid"]
    mine = db().execute("SELECT * FROM items WHERE user_id=? ORDER BY created_at DESC", (uid,)).fetchall()
    unread_count = db().execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0",
                                (uid,)).fetchone()[0]
    notes = db().execute("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 30", (uid,)).fetchall()
    db().execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (uid,)); db().commit()
    return render_template("dashboard.html", mine=mine, notes=notes, unread_count=unread_count)

@app.route("/admin")
@admin_required
def admin():
    d = db()
    stats = d.execute("""SELECT (SELECT COUNT(*) FROM users) users, (SELECT COUNT(*) FROM items) items,
        (SELECT COUNT(*) FROM items WHERE status='resolved') resolved,
        (SELECT COUNT(*) FROM claims WHERE status='pending') pending""").fetchone()
    items = d.execute("SELECT i.*, u.name AS owner FROM items i JOIN users u ON u.id=i.user_id "
                      "ORDER BY i.created_at DESC").fetchall()
    pending = d.execute("SELECT c.*, i.title, u.name FROM claims c JOIN items i ON i.id=c.item_id "
                        "JOIN users u ON u.id=c.user_id WHERE c.status='pending'").fetchall()
    users = d.execute("SELECT id,name,email,role,is_banned FROM users ORDER BY role DESC,name").fetchall()
    categories = d.execute("SELECT category,COUNT(*) AS count FROM items GROUP BY category ORDER BY category").fetchall()
    locations = d.execute("SELECT location,COUNT(*) AS count FROM items GROUP BY location ORDER BY location").fetchall()
    timeline = d.execute("""SELECT date(created_at) AS day,
        SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) AS open_count,
        SUM(CASE WHEN status='resolved' THEN 1 ELSE 0 END) AS resolved_count
        FROM items WHERE created_at >= datetime('now','-30 days')
        GROUP BY date(created_at) ORDER BY day""").fetchall()
    charts = {
        "categories": {"labels": [r["category"] for r in categories], "values": [r["count"] for r in categories]},
        "locations": {"labels": [r["location"] for r in locations], "values": [r["count"] for r in locations]},
        "timeline": {"labels": [r["day"] for r in timeline],
                     "open": [r["open_count"] for r in timeline],
                     "resolved": [r["resolved_count"] for r in timeline]},
    }
    return render_template("admin.html", stats=stats, items=items, pending=pending,
                           users=users, charts=charts)

@app.route("/admin/users/<int:user_id>/toggle-ban", methods=["POST"])
@admin_required
def toggle_ban_user(user_id):
    target = db().execute("SELECT id,role,is_banned FROM users WHERE id=?", (user_id,)).fetchone() or abort(404)
    if target["role"] == "admin":
        abort(403)
    is_banned = 0 if target["is_banned"] else 1
    db().execute("UPDATE users SET is_banned=? WHERE id=?", (is_banned, user_id))
    db().commit()
    flash("User unbanned." if not is_banned else "User banned.", "ok")
    return redirect(url_for("admin"))

@app.route("/admin/reports.csv")
@admin_required
def export_reports():
    rows = db().execute("""SELECT i.id,i.title,i.type,i.category,i.location,i.status,u.name AS owner,
        u.email AS owner_email,i.date_event,i.created_at FROM items i JOIN users u ON u.id=i.user_id
        ORDER BY i.created_at DESC""").fetchall()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(("ID", "Title", "Type", "Category", "Location", "Status", "Owner",
                     "Owner email", "Event date", "Posted at"))
    for row in rows:
        values = [row[key] for key in ("id", "title", "type", "category", "location", "status",
                                        "owner", "owner_email", "date_event", "created_at")]
        writer.writerow([f"'{value}" if isinstance(value, str) and value.startswith(("=", "+", "-", "@")) else value
                         for value in values])
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=campus-reports.csv"
    return response

init_db()
if __name__ == "__main__":
    app.run(debug=APP_ENV == "development")
