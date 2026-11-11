"""ZAD OSINT - API Selling Platform (Flask + SQLite)
Credit: POKA BROTHER
"""
import os, io, re, math, base64, sqlite3, secrets
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import quote

import requests, qrcode
try:
    import psycopg2, psycopg2.extras
except ImportError:  # only needed when DATABASE_URL is used
    psycopg2 = None
from flask import (Flask, g, render_template, request, redirect, url_for,
                   session, flash, abort, Response, jsonify, send_from_directory)
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "data.db"))
DATABASE_URL = os.environ.get("DATABASE_URL", "")
PG = DATABASE_URL.startswith("postgres")   # PostgreSQL (e.g. free Neon) keeps data on Render free plan
if not PG:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)

app = Flask(__name__, static_folder=None, template_folder=BASE)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=timedelta(days=14))

DEFAULT_SETTINGS = {
    "site_name": "ZAD OSINT",
    "tagline": "Premium API marketplace",
    "upi_id": "sunny8127@fam",
    "payee": "ZAD OSINT",
    "verify_url": "https://famsytem.onrender.com/api/v1/verify-payment",
    "verify_mode": "auto",   # auto | post_json | post_form | get  (auto = detect & remember)
    "last_verify_raw": "",
    "announcement": "Welcome to ZAD OSINT - buy an API, pay by UPI, get your key instantly.",
    "credit": "POKA BROTHER",
    "unique_paise": "1",      # "1" = add 1-99 paise to each order so payments can be matched safely
    "order_minutes": "15",    # QR validity
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id {PK}, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, is_admin INTEGER DEFAULT 0, is_banned INTEGER DEFAULT 0, created_at TEXT);
CREATE TABLE IF NOT EXISTS categories(
  id {PK}, name TEXT UNIQUE NOT NULL, icon TEXT DEFAULT 'fa-solid fa-layer-group');
CREATE TABLE IF NOT EXISTS apis(
  id {PK}, slug TEXT UNIQUE NOT NULL, title TEXT NOT NULL, description TEXT,
  target_url TEXT NOT NULL, price {REAL} NOT NULL, days INTEGER DEFAULT 30, category_id INTEGER,
  icon TEXT DEFAULT 'fa-solid fa-bolt', active INTEGER DEFAULT 1, hits INTEGER DEFAULT 0, created_at TEXT);
CREATE TABLE IF NOT EXISTS orders(
  id {PK}, user_id INTEGER, api_id INTEGER, amount {REAL},
  status TEXT DEFAULT 'pending', utr TEXT, attempts INTEGER DEFAULT 0, note TEXT, created_at TEXT,
  expires_at TEXT, last_check TEXT);
CREATE INDEX IF NOT EXISTS idx_orders_utr ON orders(utr);
CREATE TABLE IF NOT EXISTS subs(
  id {PK}, user_id INTEGER, api_id INTEGER, api_key TEXT UNIQUE,
  started_at TEXT, expires_at TEXT, hits INTEGER DEFAULT 0, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
"""

# ---------- time helpers (all UTC) ----------
def now():
    return datetime.utcnow().replace(microsecond=0)

def iso(dt):
    return dt.isoformat(sep=" ")

def parse(s):
    return datetime.fromisoformat(s)

def days_left(exp):
    """Whole days remaining, rounded up: 30 today -> 29 tomorrow -> ... -> 0 expired."""
    if isinstance(exp, str):
        exp = parse(exp)
    return max(0, math.ceil((exp - now()).total_seconds() / 86400))

def slugify(t):
    return re.sub(r"[^a-z0-9]+", "-", t.lower()).strip("-") or secrets.token_hex(3)

# ---------- db (SQLite by default, PostgreSQL when DATABASE_URL is set) ----------
def pg_sql(sql):
    """Translate our (SQLite-style) SQL for PostgreSQL. Returns (sql, wants_returning_id)."""
    s = sql.replace("?", "%s")
    ret = s.lstrip().upper().startswith("INSERT") and "ON CONFLICT" not in s.upper()
    if ret:
        s = s.rstrip().rstrip(";") + " RETURNING id"
    return s, ret

class PGCur:
    def __init__(self, cur, ret):
        self.cur, self.rowcount, self.lastrowid = cur, cur.rowcount, None
        if ret:
            r = cur.fetchone()
            self.lastrowid = r["id"] if r else None
    def fetchall(self):
        return self.cur.fetchall() if self.cur.description else []

class Conn:
    def __init__(self):
        if PG:
            self.raw = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor, connect_timeout=15)
        else:
            self.raw = sqlite3.connect(DB_PATH, timeout=15)
            self.raw.row_factory = sqlite3.Row
            self.raw.execute("PRAGMA journal_mode=WAL")
    def execute(self, sql, args=()):
        if not PG:
            return self.raw.execute(sql, args)
        s, ret = pg_sql(sql)
        cur = self.raw.cursor()
        try:
            cur.execute(s, args)
        except Exception:
            self.raw.rollback()
            raise
        return PGCur(cur, ret)
    def commit(self):
        self.raw.commit()
    def close(self):
        self.raw.close()

DB_INTEGRITY = (sqlite3.IntegrityError,) + ((psycopg2.IntegrityError,) if PG else ())

def get_db():
    if "db" not in g:
        g.db = Conn()
    return g.db

@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db:
        db.close()

def q(sql, args=(), one=False):
    rows = get_db().execute(sql, args).fetchall()
    return (rows[0] if rows else None) if one else rows

def ex(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur.lastrowid

def set_setting(k, v):
    ex("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v))

def init_db():
    c = Conn()
    if PG:
        c.execute("SELECT pg_advisory_lock(727272)")   # two gunicorn workers must not create tables at once
    schema = SCHEMA.replace("{PK}", "SERIAL PRIMARY KEY" if PG else "INTEGER PRIMARY KEY AUTOINCREMENT") \
                   .replace("{REAL}", "DOUBLE PRECISION" if PG else "REAL")
    for stmt in [x.strip() for x in schema.split(";") if x.strip()]:
        c.execute(stmt)
    if not PG:
        cols = {r[1] for r in c.execute("PRAGMA table_info(orders)").fetchall()}
        for col in ("expires_at", "last_check"):
            if col not in cols:
                c.execute("ALTER TABLE orders ADD COLUMN %s TEXT" % col)
    for k, v in DEFAULT_SETTINGS.items():
        c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO NOTHING", (k, v))
    if not c.execute("SELECT 1 FROM categories").fetchall():
        for n, i in [("OSINT", "fa-solid fa-user-secret"), ("Number Info", "fa-solid fa-phone"),
                     ("Vehicle", "fa-solid fa-car"), ("Social Media", "fa-solid fa-share-nodes"),
                     ("Telegram", "fa-brands fa-telegram"), ("Tools", "fa-solid fa-screwdriver-wrench")]:
            c.execute("INSERT INTO categories(name,icon) VALUES(?,?)", (n, i))
    au, ap = os.environ.get("ADMIN_USER"), os.environ.get("ADMIN_PASS")
    if au and ap:   # env vars are the source of truth for the admin login (re-applied on every boot)
        row = c.execute("SELECT id FROM users WHERE username=?", (au,)).fetchall()
        if row:
            c.execute("UPDATE users SET password_hash=?, is_admin=1, is_banned=0 WHERE id=?",
                      (generate_password_hash(ap), row[0]["id"]))
        else:
            c.execute("INSERT INTO users(username,email,password_hash,is_admin,created_at) VALUES(?,?,?,1,?)",
                      (au, au.lower() + "@admin.local", generate_password_hash(ap), iso(now())))
    elif not c.execute("SELECT 1 FROM users WHERE is_admin=1").fetchall():
        c.execute("INSERT INTO users(username,email,password_hash,is_admin,created_at) VALUES('admin','admin@admin.local',?,1,?)",
                  (generate_password_hash("admin123"), iso(now())))
    c.commit()
    c.close()

init_db()

def settings():
    if "S" not in g:
        g.S = {r["key"]: r["value"] for r in q("SELECT * FROM settings")}
        for k, v in DEFAULT_SETTINGS.items():
            g.S.setdefault(k, v)
    return g.S

# ---------- security / session ----------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]

@app.before_request
def load_user():
    g.user = None
    uid = session.get("uid")
    if uid:
        u = q("SELECT * FROM users WHERE id=?", (uid,), one=True)
        if u and not u["is_banned"]:
            g.user = u
        else:
            session.clear()
    if request.method == "POST" and not request.path.startswith("/g/"):
        if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
            abort(400, "Invalid CSRF token. Refresh the page and try again.")

@app.context_processor
def inject():
    return dict(S=settings(), user=g.get("user"), csrf=csrf_token, days_left=days_left,
                parse=parse)

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user:
            return redirect(url_for("login", next=request.path))
        return f(*a, **k)
    return w

def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if not g.user["is_admin"]:
            abort(403)
        return f(*a, **k)
    return w

@app.route("/style.css")
def style_css():
    return send_from_directory(BASE, "style.css", mimetype="text/css", max_age=3600)

@app.route("/health")
def health():
    """For uptime pingers (keeps the free Render instance awake)."""
    try:
        q("SELECT 1")
        return "ok"
    except Exception:
        return "db error", 500

# ---------- auth ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("store"))
    if request.method == "POST":
        ident = request.form.get("username", "").strip()
        u = q("SELECT * FROM users WHERE username=? OR email=?", (ident, ident.lower()), one=True)
        if u and check_password_hash(u["password_hash"], request.form.get("password", "")):
            if u["is_banned"]:
                flash("Your account is suspended. Contact support.", "err")
            else:
                session.clear()
                session.permanent = True
                session["uid"] = u["id"]
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("store"))
        else:
            flash("Wrong username or password.", "err")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("store"))
    if request.method == "POST":
        un = request.form.get("username", "").strip()
        em = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", un):
            flash("Username: 3-20 letters, numbers or underscore.", "err")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", em):
            flash("Enter a valid email.", "err")
        elif len(pw) < 6:
            flash("Password must be at least 6 characters.", "err")
        elif q("SELECT 1 FROM users WHERE username=? OR email=?", (un, em), one=True):
            flash("Username or email already registered.", "err")
        else:
            uid = ex("INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)",
                     (un, em, generate_password_hash(pw), iso(now())))
            session.clear()
            session["uid"] = uid
            flash("Account created. Welcome!", "ok")
            return redirect(url_for("store"))
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- store ----------
@app.route("/")
@login_required
def store():
    cats = q("SELECT * FROM categories ORDER BY name")
    apis = q("""SELECT a.*, c.name AS cat FROM apis a LEFT JOIN categories c ON c.id=a.category_id
                WHERE a.active=1 ORDER BY a.id DESC""")
    mine = {r["api_id"]: r for r in q("SELECT * FROM subs WHERE user_id=? AND active=1", (g.user["id"],))}
    return render_template("store.html", cats=cats, apis=apis, mine=mine)

@app.route("/dashboard")
@login_required
def dashboard():
    subs = q("""SELECT s.*, a.title, a.slug, a.icon, a.days FROM subs s JOIN apis a ON a.id=s.api_id
                WHERE s.user_id=? ORDER BY s.expires_at DESC""", (g.user["id"],))
    orders = q("""SELECT o.*, a.title FROM orders o JOIN apis a ON a.id=o.api_id
                  WHERE o.user_id=? ORDER BY o.id DESC LIMIT 20""", (g.user["id"],))
    return render_template("dashboard.html", subs=subs, orders=orders,
                           base=request.host_url.rstrip("/"))

# ---------- payment ----------
def qr_b64(text):
    img = qrcode.make(text, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

def upi_link(order, api):
    S = settings()
    return "upi://pay?pa=%s&pn=%s&am=%.2f&cu=INR&tn=%s" % (
        quote(S["upi_id"]), quote(S["payee"]), order["amount"], quote("ZAD%d" % order["id"]))

FAIL_WORDS = ("fail", "failed", "pending", "reject", "cancel", "expired", "invalid", "error")
TXN_KEYS = ("utr", "txn_id", "txnId", "txn", "transaction_id", "transactionId", "payment_id", "rrn", "reference", "ref_no")

MODES = ("post_json", "post_form", "get")

def _try_mode(mode, url, payload):
    if mode == "post_json":
        return requests.post(url, json=payload, timeout=30)
    if mode == "post_form":
        return requests.post(url, data=payload, timeout=30)
    return requests.get(url, params=payload, timeout=30)

def call_verify(payload):
    """Calls the payment gateway's /api/v1/verify-payment. In 'auto' mode it tries POST-JSON, POST-form
    and GET, keeps the first one that answers with a usable JSON reply, and remembers it.
    The raw reply is stored so the admin can see it (Admin -> Settings)."""
    S = settings()
    url = S["verify_url"]
    pref = S.get("verify_mode", "auto")
    order = [pref] if pref in MODES else list(MODES)
    last = None
    for mode in order:
        try:
            r = _try_mode(mode, url, payload)
            data = r.json()
        except Exception as e:
            last_raw = "%s -> error: %s" % (mode, str(e)[:200])
            _save_raw(last_raw)
            continue
        raw = "%s -> HTTP %s %s" % (mode, r.status_code, r.text[:600])
        _save_raw(raw)
        if isinstance(data, dict):
            last = data
            if r.status_code not in (400, 405, 415, 422):
                if pref == "auto":
                    set_setting("verify_mode", mode)
                    g.pop("S", None)
                return data
    return last

def _save_raw(raw):
    if settings().get("last_verify_raw") != raw:
        set_setting("last_verify_raw", raw)
        g.pop("S", None)

def _ok(d):
    flag = d.get("success", d.get("verified", d.get("valid", d.get("paid"))))
    status = str(d.get("status", d.get("payment_status", ""))).lower()
    if flag is True or str(flag).lower() == "true":
        return True
    return status in ("success", "successful", "verified", "paid", "completed", "ok", "credited", "received", "confirmed")

def _txn(d):
    for k in TXN_KEYS:
        if d.get(k) not in (None, "", False):
            return str(d[k])
    return None

def parse_verdict(data, amount, note):
    """Understands several common response shapes. Returns (ok, message, txn_id)."""
    if not isinstance(data, dict):
        return False, "Verification service unreachable. Retrying...", None
    msg = str(data.get("message") or data.get("msg") or "")
    nested = data.get("data") if isinstance(data.get("data"), dict) else {}
    cands = [("top", data)]
    if nested:
        cands.append(("top", nested))
    for k in ("data", "transactions", "payments", "result"):
        if isinstance(data.get(k), list):
            cands += [("row", x) for x in data[k] if isinstance(x, dict)]
    for kind, d in cands:
        if kind == "top":
            ok = _ok(d) or (bool(nested) and _ok(nested) and d is data)
        else:
            ok = not any(w in str(d.get("status", "")).lower() for w in FAIL_WORDS)
        if not ok:
            continue
        paid = d.get("amount", data.get("amount"))
        try:
            if paid is not None and float(paid) + 0.001 < float(amount):
                continue
            if paid is not None and kind == "row" and float(paid) > float(amount) + 1:
                continue
        except (TypeError, ValueError):
            pass
        tag = str(d.get("note") or d.get("remark") or d.get("tn") or "")
        if kind == "row" and tag and note and note.lower() not in tag.lower():
            continue
        return True, msg or "Payment verified", _txn(d)
    return False, msg or "Payment not received yet", None

def check_order(order, utr=None):
    """Asks the verify API whether this order was paid. Returns (ok, msg, txn)."""
    note = "ZAD%d" % order["id"]
    payload = {"amount": order["amount"], "note": note, "order_id": note, "upi_id": settings()["upi_id"]}
    if utr:
        payload["utr"] = utr
    ok, msg, txn = parse_verdict(call_verify(payload), order["amount"], note)
    txn = utr or txn
    if ok and txn and q("SELECT 1 FROM orders WHERE utr=? AND status='paid' AND id<>?", (txn, order["id"]), one=True):
        return False, "This payment was already used for another order.", None
    return ok, msg, txn

def activate_sub(user_id, api_id, days):
    s = q("SELECT * FROM subs WHERE user_id=? AND api_id=?", (user_id, api_id), one=True)
    if s:
        base = max(now(), parse(s["expires_at"]))
        ex("UPDATE subs SET expires_at=?, active=1 WHERE id=?", (iso(base + timedelta(days=days)), s["id"]))
    else:
        ex("INSERT INTO subs(user_id,api_id,api_key,started_at,expires_at) VALUES(?,?,?,?,?)",
           (user_id, api_id, "zad_" + secrets.token_urlsafe(24), iso(now()), iso(now() + timedelta(days=days))))

def finalize_order(order, txn, msg):
    """Atomic: only the first caller flips pending->paid and activates (no double activation)."""
    db = get_db()
    cur = db.execute("UPDATE orders SET status='paid', utr=?, note=? WHERE id=? AND status IN ('pending','expired')",
                     (txn, msg, order["id"]))
    db.commit()
    if cur.rowcount == 1:
        api = q("SELECT days FROM apis WHERE id=?", (order["api_id"],), one=True)
        activate_sub(order["user_id"], order["api_id"], api["days"])
        return True
    return False

def order_amount(api):
    base = float(api["price"])
    if settings()["unique_paise"] != "1":
        return base
    used = {round(r["amount"] - base, 2) for r in
            q("SELECT amount FROM orders WHERE api_id=? AND status='pending' AND expires_at>?", (api["id"], iso(now())))}
    for p in range(1, 100):
        if round(p / 100, 2) not in used:
            return round(base + p / 100, 2)
    return base

@app.route("/buy/<int:api_id>")
@login_required
def buy(api_id):
    api = q("SELECT * FROM apis WHERE id=? AND active=1", (api_id,), one=True) or abort(404)
    order = q("""SELECT * FROM orders WHERE user_id=? AND api_id=? AND status='pending' AND expires_at>?
                 ORDER BY id DESC""", (g.user["id"], api_id, iso(now())), one=True)
    if order and not (0 <= order["amount"] - api["price"] < 1):
        order = None
    if not order:
        mins = int(settings().get("order_minutes") or 15)
        oid = ex("INSERT INTO orders(user_id,api_id,amount,created_at,expires_at) VALUES(?,?,?,?,?)",
                 (g.user["id"], api_id, order_amount(api), iso(now()), iso(now() + timedelta(minutes=mins))))
        order = q("SELECT * FROM orders WHERE id=?", (oid,), one=True)
    link = upi_link(order, api)
    left = max(0, int((parse(order["expires_at"]) - now()).total_seconds()))
    return render_template("buy.html", api=api, order=order, link=link, qr=qr_b64(link), left=left)

@app.route("/order-status/<int:oid>")
@login_required
def order_status(oid):
    """Polled by the checkout page every few seconds - verifies in the background."""
    o = q("SELECT * FROM orders WHERE id=? AND user_id=?", (oid, g.user["id"]), one=True) or abort(404)
    if o["status"] == "paid":
        return jsonify(status="paid", url=url_for("dashboard"))
    left = int((parse(o["expires_at"]) - now()).total_seconds()) if o["expires_at"] else 0
    if left <= 0:
        if o["status"] == "pending":
            ex("UPDATE orders SET status='expired' WHERE id=? AND status='pending'", (oid,))
        return jsonify(status="expired")
    last = parse(o["last_check"]) if o["last_check"] else None
    if not last or (now() - last).total_seconds() >= 3:
        ex("UPDATE orders SET last_check=? WHERE id=?", (iso(now()), oid))
        ok, msg, txn = check_order(o)
        if ok:
            if finalize_order(o, txn, "Auto-verified: " + msg):
                flash("Payment received! Your API is now active.", "ok")
            return jsonify(status="paid", url=url_for("dashboard"))
    return jsonify(status="pending", left=left)

@app.route("/verify", methods=["POST"])
@login_required
def verify():
    """Manual fallback: user pastes the UTR if auto-detection is slow."""
    order = q("SELECT * FROM orders WHERE id=? AND user_id=?",
              (request.form.get("order_id", type=int), g.user["id"]), one=True) or abort(404)
    back = redirect(url_for("buy", api_id=order["api_id"]))
    utr = request.form.get("utr", "").strip()
    if order["status"] == "paid":
        flash("This order is already completed.", "err"); return back
    if not re.fullmatch(r"[A-Za-z0-9]{10,25}", utr):
        flash("Enter a valid UTR / transaction ID (10-25 characters).", "err"); return back
    if order["attempts"] >= 5:
        flash("Too many attempts on this order. Contact support.", "err"); return back
    ex("UPDATE orders SET attempts=attempts+1 WHERE id=?", (order["id"],))
    ok, msg, txn = check_order(order, utr)
    if ok and finalize_order(order, txn, msg):
        flash("Payment verified! Your API key is ready.", "ok")
        return redirect(url_for("dashboard"))
    flash("Verification failed: " + msg, "err")
    return back

# ---------- API gateway (hides the real URL, enforces expiry) ----------
@app.route("/g/<slug>")
def gateway(slug):
    key = request.args.get("key") or request.headers.get("X-API-Key", "")
    api = q("SELECT * FROM apis WHERE slug=? AND active=1", (slug,), one=True)
    if not api:
        return jsonify(ok=False, error="API not found"), 404
    s = q("""SELECT s.*, u.is_banned FROM subs s JOIN users u ON u.id=s.user_id
             WHERE s.api_key=? AND s.api_id=?""", (key, api["id"]), one=True)
    if not s or not s["active"] or s["is_banned"]:
        return jsonify(ok=False, error="Invalid API key"), 401
    if parse(s["expires_at"]) <= now():
        return jsonify(ok=False, error="Subscription expired. Renew from your dashboard."), 403
    params = [(k, v) for k, v in request.args.items(multi=True) if k != "key"]
    try:
        r = requests.get(api["target_url"], params=params, timeout=25)
    except Exception:
        return jsonify(ok=False, error="Upstream API error"), 502
    ex("UPDATE subs SET hits=hits+1 WHERE id=?", (s["id"],))
    ex("UPDATE apis SET hits=hits+1 WHERE id=?", (api["id"],))
    return Response(r.content, status=r.status_code,
                    content_type=r.headers.get("Content-Type", "application/json"))

# ---------- admin ----------
TABS = ["dashboard", "apis", "categories", "users", "orders", "subs", "settings"]

@app.route("/admin")
@app.route("/admin/<tab>")
@admin_required
def admin(tab="dashboard"):
    if tab not in TABS:
        abort(404)
    d = {}
    if tab == "dashboard":
        d = dict(
            users=q("SELECT COUNT(*) c FROM users", one=True)["c"],
            apis=q("SELECT COUNT(*) c FROM apis", one=True)["c"],
            active=q("SELECT COUNT(*) c FROM subs WHERE active=1 AND expires_at>?", (iso(now()),), one=True)["c"],
            revenue=q("SELECT COALESCE(SUM(amount),0) c FROM orders WHERE status='paid'", one=True)["c"],
            pending=q("SELECT COUNT(*) c FROM orders WHERE status='pending' AND attempts>0", one=True)["c"],
            hits=q("SELECT COALESCE(SUM(hits),0) c FROM apis", one=True)["c"],
            recent=q("""SELECT o.*, u.username, a.title FROM orders o JOIN users u ON u.id=o.user_id
                        JOIN apis a ON a.id=o.api_id WHERE o.status='paid' ORDER BY o.id DESC LIMIT 8"""))
    elif tab == "apis":
        d = dict(rows=q("""SELECT a.*, c.name cat FROM apis a LEFT JOIN categories c ON c.id=a.category_id
                           ORDER BY a.id DESC"""), cats=q("SELECT * FROM categories ORDER BY name"),
                 edit=q("SELECT * FROM apis WHERE id=?", (request.args.get("edit", type=int),), one=True))
    elif tab == "categories":
        d = dict(rows=q("SELECT * FROM categories ORDER BY name"))
    elif tab == "users":
        d = dict(rows=q("""SELECT u.*, (SELECT COUNT(*) FROM subs s WHERE s.user_id=u.id AND s.expires_at>?) act
                           FROM users u ORDER BY u.id DESC""", (iso(now()),)),
                 apis=q("SELECT id,title FROM apis ORDER BY title"))
    elif tab == "orders":
        d = dict(rows=q("""SELECT o.*, u.username, a.title FROM orders o JOIN users u ON u.id=o.user_id
                           JOIN apis a ON a.id=o.api_id ORDER BY o.id DESC LIMIT 200"""))
    elif tab == "subs":
        d = dict(rows=q("""SELECT s.*, u.username, a.title FROM subs s JOIN users u ON u.id=s.user_id
                           JOIN apis a ON a.id=s.api_id ORDER BY s.expires_at DESC"""))
    return render_template("admin.html", tab=tab, tabs=TABS, **d)

@app.route("/admin/do/<action>", methods=["POST"])
@admin_required
def admin_do(action):
    f = request.form
    tab = f.get("tab", "dashboard")
    try:
        if action == "api_save":
            title = f["title"].strip()
            vals = (title, f.get("description", "").strip(), f["target_url"].strip(), float(f["price"]),
                    int(f.get("days") or 30), f.get("category_id", type=int),
                    f.get("icon", "").strip() or "fa-solid fa-bolt", 1 if f.get("active") else 0)
            aid = f.get("id", type=int)
            if not re.match(r"https?://", vals[2]):
                raise ValueError("URL must start with http:// or https://")
            if aid:
                ex("""UPDATE apis SET title=?,description=?,target_url=?,price=?,days=?,category_id=?,icon=?,active=?
                      WHERE id=?""", vals + (aid,))
            else:
                slug, n = slugify(title), 1
                while q("SELECT 1 FROM apis WHERE slug=?", (slug,), one=True):
                    n += 1; slug = "%s-%d" % (slugify(title), n)
                ex("""INSERT INTO apis(title,description,target_url,price,days,category_id,icon,active,slug,created_at)
                      VALUES(?,?,?,?,?,?,?,?,?,?)""", vals + (slug, iso(now())))
            flash("API saved.", "ok")
        elif action == "api_toggle":
            ex("UPDATE apis SET active=1-active WHERE id=?", (f.get("id", type=int),))
        elif action == "api_delete":
            ex("DELETE FROM apis WHERE id=?", (f.get("id", type=int),))
            ex("DELETE FROM subs WHERE api_id=?", (f.get("id", type=int),))
            flash("API deleted.", "ok")
        elif action == "cat_save":
            ex("INSERT INTO categories(name,icon) VALUES(?,?)",
               (f["name"].strip(), f.get("icon", "").strip() or "fa-solid fa-layer-group"))
            flash("Category saved.", "ok")
        elif action == "cat_delete":
            ex("UPDATE apis SET category_id=NULL WHERE category_id=?", (f.get("id", type=int),))
            ex("DELETE FROM categories WHERE id=?", (f.get("id", type=int),))
        elif action == "user_ban":
            ex("UPDATE users SET is_banned=1-is_banned WHERE id=? AND is_admin=0", (f.get("id", type=int),))
        elif action == "user_delete":
            uid = f.get("id", type=int)
            ex("DELETE FROM subs WHERE user_id=?", (uid,))
            ex("DELETE FROM orders WHERE user_id=?", (uid,))
            ex("DELETE FROM users WHERE id=? AND is_admin=0", (uid,))
            flash("User deleted.", "ok")
        elif action == "user_grant":
            activate_sub(f.get("id", type=int), f.get("api_id", type=int), f.get("days", type=int) or 30)
            flash("Access granted.", "ok")
        elif action == "user_pass":
            ex("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(f["password"]), f.get("id", type=int)))
            flash("Password changed.", "ok")
        elif action == "order_approve":
            o = q("SELECT * FROM orders WHERE id=?", (f.get("id", type=int),), one=True)
            if o and o["status"] != "paid":
                a = q("SELECT days FROM apis WHERE id=?", (o["api_id"],), one=True)
                ex("UPDATE orders SET status='paid', note='Approved by admin' WHERE id=?", (o["id"],))
                activate_sub(o["user_id"], o["api_id"], a["days"])
                flash("Order approved and subscription activated.", "ok")
        elif action == "order_reject":
            ex("UPDATE orders SET status='failed', note='Rejected by admin' WHERE id=?", (f.get("id", type=int),))
        elif action == "sub_extend":
            s = q("SELECT * FROM subs WHERE id=?", (f.get("id", type=int),), one=True)
            ex("UPDATE subs SET expires_at=?, active=1 WHERE id=?",
               (iso(max(now(), parse(s["expires_at"])) + timedelta(days=f.get("days", type=int) or 30)), s["id"]))
            flash("Subscription extended.", "ok")
        elif action == "sub_revoke":
            ex("UPDATE subs SET active=1-active WHERE id=?", (f.get("id", type=int),))
        elif action == "verify_test":
            amt = float(f["amount"])
            data = call_verify({"amount": amt, "note": "ZADTEST", "order_id": "ZADTEST", "upi_id": settings()["upi_id"]})
            flash("Test sent. Reply received - see 'Last gateway reply' below." if data is not None
                  else "No usable JSON reply from the gateway - see 'Last gateway reply' below.", "ok" if data is not None else "err")
        elif action == "settings_save":
            for k in DEFAULT_SETTINGS:
                if k in f:
                    set_setting(k, f[k].strip())
            flash("Settings saved.", "ok")
        else:
            abort(404)
    except (KeyError, ValueError, TypeError) as e:
        flash("Error: %s" % e, "err")
    except DB_INTEGRITY:
        flash("Duplicate or invalid data.", "err")
    return redirect(url_for("admin", tab=tab))

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def err(e):
    return render_template("error.html", e=e), e.code

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
