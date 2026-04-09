"""
ScratchXI — Campus Security Alert System
==========================================
Four roles: student | staff | security | admin

Role responsibilities:
  admin    — incident oversight, assignment, reassignment, closing incidents,
             monitoring all users, analytics, broadcasts
  security — field ops: view assigned tasks, accept, submit feedback + evidence,
             report new incidents
  staff    — view dashboard, alerts, history, chat (read + limited send)
  student  — view dashboard, alerts, history, chat (read + limited send)
"""

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify, abort)
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import escape as _escape
from dotenv import load_dotenv
load_dotenv()
import os, secrets, smtplib, logging, threading, time, functools, html
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, date, timedelta
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from forms import (
    RegistrationForm, LoginForm, AlertForm, FeedbackForm,
    DUT_CAMPUSES, DUT_BLOCKS, INCIDENT_TYPES, SEVERITY_LEVELS,
    PRIORITY_LEVELS, ROLES, PUBLIC_ROLES, FEEDBACK_STATUSES, ALERT_STATUSES,
    TASK_STATUSES, allowed_image,
    STUDENT_DOMAIN, STAFF_DOMAIN,  # for template hints
)

# ── Database imports ───────────────────────────────────────
# PostgreSQL for production (Render), SQLite for local dev
import sqlite3
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    import psycopg2
    import psycopg2.extras

# ── Setup ──────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'scratchxi_secure_key_dut_2026_change_in_prod')

# Session cookie security
app.config['SESSION_COOKIE_HTTPONLY'] = True   # JS cannot read the cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection on cross-site requests
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=20)  # idle timeout
SESSION_TIMEOUT_MINUTES = 20

# File upload security
MAX_UPLOAD_BYTES  = 5 * 1024 * 1024   # 5 MB hard limit
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf'}
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_BYTES

# itsdangerous serializer for password reset tokens
_ts = URLSafeTimedSerializer(app.secret_key, salt='scratchxi-pw-reset-2026')

# Track used reset tokens so each link works exactly once
_used_reset_tokens: set = set()
_token_lock = threading.Lock()

socketio = SocketIO(app, async_mode='threading', cors_allowed_origins='*')

DB_PATH       = os.path.join(os.path.dirname(__file__), 'database', 'database.db')
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── Logging ────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger('scratchxi')

# ── In-memory rate limiter (no external library needed) ────
_rate_store: dict = {}
_rate_lock  = threading.Lock()

def _rate_check(key: str, max_calls: int, window_secs: int) -> bool:
    now = time.time()
    with _rate_lock:
        times = _rate_store.get(key, [])
        times = [t for t in times if now - t < window_secs]
        if len(times) >= max_calls:
            _rate_store[key] = times
            return False
        times.append(now)
        _rate_store[key] = times
        return True


# ── Chat moderation state ──────────────────────────────────
_mod_lock      = threading.Lock()
_muted_users:  set = set()
_chat_locked:  bool = False
_msg_cooldown: dict = {}
MSG_COOLDOWN_SECS = 3


def _is_muted(user_id: int) -> bool:
    with _mod_lock:
        return user_id in _muted_users


def _set_muted(user_id: int, mute: bool):
    with _mod_lock:
        if mute:
            _muted_users.add(user_id)
        else:
            _muted_users.discard(user_id)


def _is_chat_locked() -> bool:
    with _mod_lock:
        return _chat_locked


def _set_chat_locked(locked: bool):
    global _chat_locked
    with _mod_lock:
        _chat_locked = locked


def _check_msg_cooldown(user_id: int) -> bool:
    now = time.time()
    with _mod_lock:
        last = _msg_cooldown.get(user_id, 0)
        if now - last < MSG_COOLDOWN_SECS:
            return False
        _msg_cooldown[user_id] = now
        return True


# ── CSRF helpers ───────────────────────────────────────────
def _csrf_token() -> str:
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_hex(32)
    return session['_csrf']

def _csrf_valid() -> bool:
    submitted = (request.form.get('_csrf_token') or
                 request.headers.get('X-CSRF-Token') or '')
    expected  = session.get('_csrf', '')
    return submitted and expected and hmac.compare_digest(submitted, expected)

import hmac

@app.context_processor
def _inject_csrf():
    return {'csrf_token': _csrf_token}


# ── XSS sanitiser ──────────────────────────────────────────
def sanitise(text: str) -> str:
    import re as _re
    if not text:
        return ''
    text = str(text).strip()
    text = _re.sub(r'<script[^>]*?>.*?</script>', '', text, flags=_re.IGNORECASE | _re.DOTALL)
    text = _re.sub(r'<[^>]+>', '', text)
    text = _re.sub(r'(?i)javascript:', '', text)
    return text

def check_session_timeout():
    if 'user_id' in session:
        last = session.get('last_active')
        now  = datetime.utcnow()
        if last:
            try:
                last_dt = datetime.fromisoformat(last)
                if (now - last_dt).total_seconds() > SESSION_TIMEOUT_MINUTES * 60:
                    session.clear()
                    flash('Your session has expired. Please sign in again.', 'info')
                    return redirect(url_for('login'))
            except (ValueError, TypeError):
                session.clear()
                return redirect(url_for('login'))
        session['last_active'] = now.isoformat()


@app.after_request
def set_security_headers(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma']        = 'no-cache'
    response.headers['Expires']       = '0'
    response.headers['X-Frame-Options']        = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy']        = 'strict-origin-when-cross-origin'
    return response


@app.errorhandler(413)
def file_too_large(e):
    flash('File is too large. Maximum allowed size is 5 MB.', 'error')
    return redirect(request.referrer or url_for('index'))


@app.errorhandler(404)
def not_found(e):
    return render_template('base.html'), 404


@app.errorhandler(403)
def forbidden(e):
    flash('Access denied.', 'error')
    return redirect(url_for('index'))


CHAT_DAILY_LIMIT = 20
BLOCKED_WORDS = ['fuck','shit','bitch','asshole','bastard','damn','crap',
                 'idiot','stupid','moron','jerk','piss']

def contains_profanity(text):
    t = text.lower()
    return any(w in t for w in BLOCKED_WORDS)

# ── Email config ───────────────────────────────────────────
BASE_URL      = os.environ.get('BASE_URL', 'http://localhost:5000')
MAIL_SERVER   = os.environ.get('MAIL_SERVER',   'smtp.gmail.com')
MAIL_PORT     = int(os.environ.get('MAIL_PORT', 587))
MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
MAIL_FROM     = os.environ.get('MAIL_FROM',     'noreply@scratchxi.dut.ac.za')
RESET_TOKEN_HOURS = 2


def send_reset_email(to_email, token, user_name):
    if not MAIL_USERNAME:
        print(f'\n[DEV] Password reset for {to_email}: token={token}\n')
        return True
    try:
        reset_url = f'{BASE_URL}/reset-password/{token}'
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'ScratchXI — Password Reset Request'
        msg['From']    = MAIL_FROM
        msg['To']      = to_email
        text = f"""Hi {user_name},\n\nA password reset was requested for your ScratchXI account.\n\nReset link: {reset_url}\n\nThis link expires in {RESET_TOKEN_HOURS} hours. If you did not request this, ignore this email.\n\nScratchXI — DUT Campus Security Platform"""
        html_body = f"""<html><body style='font-family:sans-serif;color:#121212;'>
        <h2 style='color:#0A2952;'>ScratchXI Password Reset</h2>
        <p>Hi {user_name},</p>
        <p>A password reset was requested for your account.</p>
        <p><a href='{reset_url}' style='background:#0A2952;color:#fff;padding:10px 22px;border-radius:6px;text-decoration:none;display:inline-block;margin:12px 0;'>Reset My Password</a></p>
        <p style='color:#718096;font-size:0.85em;'>Link expires in {RESET_TOKEN_HOURS} hours. If you didn't request this, ignore this email.</p>
        <hr style='border:none;border-top:1px solid #eee;margin:20px 0;'>
        <p style='color:#718096;font-size:0.78em;'>ScratchXI — Durban University of Technology Campus Security Platform</p>
        </body></html>"""
        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(MAIL_USERNAME, MAIL_PASSWORD)
            srv.sendmail(MAIL_FROM, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f'[EMAIL ERROR] {e}')
        return False


# ═══════════════════════════════════════════════════════════
# DATABASE HELPERS — PostgreSQL (production) + SQLite (local)
# ═══════════════════════════════════════════════════════════

def _using_pg():
    """Return True if we are using PostgreSQL."""
    return DATABASE_URL is not None


class PgRowWrapper:
    """Wraps a psycopg2 row (tuple) with column names so row['col'] works like sqlite3.Row."""
    def __init__(self, cursor, row):
        self._data = {}
        if row and cursor.description:
            for i, col in enumerate(cursor.description):
                self._data[col.name] = row[i]

    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self._data.values())[key]
        return self._data[key]

    def __contains__(self, key):
        return key in self._data

    def keys(self):
        return self._data.keys()

    def values(self):
        return self._data.values()

    def items(self):
        return self._data.items()


class PgCursorWrapper:
    """Wraps a psycopg2 cursor so that:
       - execute() converts ? placeholders to %s for PostgreSQL
       - fetchone() / fetchall() return dict-like row objects
    """
    def __init__(self, cursor):
        self._cur = cursor

    def execute(self, sql, params=None):
        sql = sql.replace('?', '%s')
        self._cur.execute(sql, params or ())
        return self

    def executescript(self, sql):
        self._cur.execute(sql)
        return self

    def fetchone(self):
        row = self._cur.fetchone()
        if row is None:
            return None
        return PgRowWrapper(self._cur, row)

    def fetchall(self):
        rows = self._cur.fetchall()
        return [PgRowWrapper(self._cur, r) for r in rows]

    @property
    def description(self):
        return self._cur.description


class PgConnectionWrapper:
    """Wraps a psycopg2 connection so it behaves like sqlite3 connection:
       - .execute() works directly on the connection
       - Context manager support (with get_db() as c)
    """
    def __init__(self, conn):
        self._conn = conn
        self._cursor = None

    def execute(self, sql, params=None):
        cur = self._conn.cursor()
        wrapper = PgCursorWrapper(cur)
        wrapper.execute(sql, params)
        return wrapper

    def executescript(self, sql):
        cur = self._conn.cursor()
        wrapper = PgCursorWrapper(cur)
        wrapper.executescript(sql)
        return wrapper

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self._conn.commit()
        self._conn.close()
        return False


def get_db():
    if _using_pg():
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False  # we commit in __exit__
        return PgConnectionWrapper(conn)
    else:
        c = sqlite3.connect(DB_PATH)
        c.row_factory = sqlite3.Row
        return c


def require_login():
    return 'user_id' not in session

def require_role(*roles):
    return session.get('user_role') not in roles

def save_upload(file_obj, prefix=''):
    if not file_obj or not file_obj.filename:
        return None
    fname = secure_filename(file_obj.filename)
    if not fname:
        return None
    ext = fname.rsplit('.', 1)[-1].lower() if '.' in fname else ''
    if ext not in ALLOWED_EXTENSIONS:
        flash(f'File type .{ext} is not allowed. Accepted: jpg, jpeg, png, pdf.', 'error')
        return None
    file_obj.seek(0, 2)
    size = file_obj.tell()
    file_obj.seek(0)
    if size > MAX_UPLOAD_BYTES:
        flash('File exceeds 5 MB limit.', 'error')
        return None
    ts     = datetime.now().strftime('%Y%m%d%H%M%S')
    stored = f"{prefix}{ts}_{fname}"
    dest   = os.path.join(app.config['UPLOAD_FOLDER'], stored)
    if not os.path.abspath(dest).startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
        return None
    file_obj.save(dest)
    return stored

def get_chat_count_today(user_id):
    today = date.today().isoformat()
    with get_db() as c:
        if _using_pg():
            r = c.execute(
                "SELECT COUNT(*) FROM messages "
                "WHERE sender_id=? AND timestamp::date = ?::date AND is_deleted=0",
                (user_id, today)
            ).fetchone()
        else:
            r = c.execute(
                "SELECT COUNT(*) FROM messages "
                "WHERE sender_id=? AND DATE(timestamp)=? AND is_deleted=0",
                (user_id, today)
            ).fetchone()
    return r[0] if r else 0

def audit_log(action: str, detail: str = ''):
    uid  = session.get('user_id')
    name = session.get('user_name', 'anonymous')
    ip   = request.remote_addr or 'unknown'
    try:
        with get_db() as c:
            c.execute(
                "INSERT INTO audit_log (user_id, user_name, action, detail, ip_address) "
                "VALUES (?,?,?,?,?)",
                (uid, name, action, detail[:500], ip)
            )
    except Exception:
        pass
    logger.info('[AUDIT] user=%s action=%s detail=%s ip=%s', name, action, detail[:120], ip)


def init_db():
    """Initialise database tables. Works for both PostgreSQL and SQLite."""
    schema = os.path.join(os.path.dirname(__file__), 'database', 'schema.sql')

    if _using_pg():
        # PostgreSQL: just run the schema file (it uses CREATE TABLE IF NOT EXISTS)
        with get_db() as c:
            with open(schema) as f:
                c.executescript(f.read())
    else:
        # SQLite: run schema + column migrations
        with get_db() as c:
            with open(schema) as f:
                c.executescript(f.read())
            # ── alerts column migrations ────────────────────────
            cols = [r[1] for r in c.execute("PRAGMA table_info(alerts)").fetchall()]
            for col, defn in [('campus','TEXT'),('block','TEXT'),
                              ('image_filename','TEXT'),('priority',"TEXT DEFAULT 'medium'"),
                              ('record_type',"TEXT DEFAULT 'incident'")]:
                if col not in cols:
                    c.execute(f'ALTER TABLE alerts ADD COLUMN {col} {defn}')
            mcols = [r[1] for r in c.execute("PRAGMA table_info(messages)").fetchall()]
            if 'is_deleted' not in mcols:
                c.execute("ALTER TABLE messages ADD COLUMN is_deleted INTEGER DEFAULT 0")
            if 'room' not in mcols:
                c.execute("ALTER TABLE messages ADD COLUMN room TEXT DEFAULT 'main_chat'")
            ucols = [r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()]
            if 'is_banned' not in ucols:
                c.execute("ALTER TABLE users ADD COLUMN is_banned INTEGER NOT NULL DEFAULT 0")
            c.execute('''CREATE TABLE IF NOT EXISTS attendance (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                security_id  INTEGER NOT NULL REFERENCES users(id),
                clock_in     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                clock_out    DATETIME,
                availability TEXT NOT NULL DEFAULT 'available',
                campus       TEXT,
                shift        TEXT,
                date_str     TEXT NOT NULL,
                is_active    INTEGER NOT NULL DEFAULT 1
            )''')
            _att_cols = [r[1] for r in c.execute('PRAGMA table_info(attendance)').fetchall()]
            if 'campus' not in _att_cols:
                c.execute('ALTER TABLE attendance ADD COLUMN campus TEXT')
            if 'shift' not in _att_cols:
                c.execute('ALTER TABLE attendance ADD COLUMN shift TEXT')
            c.execute('''CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                token TEXT NOT NULL UNIQUE,
                expires_at DATETIME NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER,
                user_name  TEXT,
                action     TEXT NOT NULL,
                detail     TEXT,
                ip_address TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )''')

    # ── Hardcoded admin accounts ─────────────────────────────
    with get_db() as c:
        for username in ('admin1', 'admin2'):
            existing = c.execute(
                "SELECT id FROM users WHERE email=?",
                (f"{username}@scratchxi.internal",)
            ).fetchone()
            if not existing:
                c.execute(
                    "INSERT INTO users (name, email, password_hash, role) VALUES (?,?,?,?)",
                    (
                        username,
                        f"{username}@scratchxi.internal",
                        generate_password_hash("TwilightScratch12#"),
                        "admin",
                    )
                )
        print("✅ Admin accounts ready (admin1 / admin2).")
    print('✅ Database ready.')


# ═══════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════

@app.route('/')
def index():
    if 'user_id' not in session:
        return render_template('homepage.html')
    role = session.get('user_role')
    if role == 'admin':    return redirect(url_for('admin_dashboard'))
    if role == 'security': return redirect(url_for('security_dashboard'))
    if role == 'staff':    return redirect(url_for('staff_dashboard'))
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        ip_key = f'login:{request.remote_addr}'
        if not _rate_check(ip_key, max_calls=5, window_secs=60):
            flash('Too many login attempts. Please wait a minute before trying again.', 'error')
            return render_template('login.html'), 429
        if not _csrf_valid():
            flash('Security token invalid. Please try again.', 'error')
            return render_template('login.html')
        form = LoginForm(request.form)
        ok, errs = form.validate()
        if not ok:
            for m in errs.values(): flash(m, 'error')
            return render_template('login.html')
        with get_db() as c:
            user = c.execute('SELECT * FROM users WHERE email=?', (form.email,)).fetchone()
        if user and check_password_hash(user['password_hash'], form.password):
            session.clear()
            session.update({'user_id': user['id'], 'user_name': user['name'],
                            'user_role': user['role'],
                            'last_active': datetime.utcnow().isoformat()})
            flash(f'Welcome back, {user["name"]}!', 'success')
            role = user['role']
            if role == 'admin':    return redirect(url_for('admin_dashboard'))
            if role == 'security': return redirect(url_for('security_dashboard'))
            if role == 'staff':    return redirect(url_for('staff_dashboard'))
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        if not _csrf_valid():
            flash('Security token invalid. Please try again.', 'error')
            return render_template('register.html', roles=PUBLIC_ROLES, form=None)
        form = RegistrationForm(request.form)
        if request.form.get('role') == 'admin':
            flash('Admin accounts cannot be created through registration.', 'error')
            return render_template('register.html', roles=PUBLIC_ROLES, form=form)
        ok, errs = form.validate()
        if not ok:
            for m in errs.values(): flash(m, 'error')
            return render_template('register.html', roles=PUBLIC_ROLES, form=form)
        try:
            with get_db() as c:
                c.execute(
                    'INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)',
                    (form.name, form.email,
                     generate_password_hash(form.password), form.role)
                )
            flash('Account created. Please log in.', 'success')
            return redirect(url_for('login'))
        except (sqlite3.IntegrityError, Exception) as e:
            # Catch both sqlite3.IntegrityError and psycopg2.errors.UniqueViolation
            if 'unique' in str(e).lower() or 'duplicate' in str(e).lower() or 'integrity' in str(e).lower():
                flash('This email is already registered.', 'error')
            else:
                raise
    return render_template('register.html', roles=PUBLIC_ROLES, form=None)


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))


# ── Admin Login ───────────────────────────────────────────
ADMIN_CREDENTIALS = {
    'admin1': generate_password_hash('TwilightScratch12#'),
    'admin2': generate_password_hash('TwilightScratch12#'),
}

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        ip_key = f'admin_login:{request.remote_addr}'
        if not _rate_check(ip_key, max_calls=5, window_secs=60):
            flash('Too many attempts. Please wait before trying again.', 'error')
            return render_template('admin_login.html'), 429
        if not _csrf_valid():
            flash('Security token invalid. Please try again.', 'error')
            return render_template('admin_login.html')
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')

        if username not in ADMIN_CREDENTIALS:
            flash('Invalid admin credentials.', 'error')
            return render_template('admin_login.html')

        if not check_password_hash(ADMIN_CREDENTIALS[username], password):
            flash('Invalid admin credentials.', 'error')
            audit_log('admin_login_fail', f'username={username}')
            return render_template('admin_login.html')

        with get_db() as c:
            user = c.execute(
                "SELECT * FROM users WHERE email=?",
                (f"{username}@scratchxi.internal",)
            ).fetchone()

        if not user:
            flash('Admin account not initialised. Restart the server.', 'error')
            return render_template('admin_login.html')

        session.clear()
        session['user_id']    = user['id']
        session['user_name']  = user['name']
        session['user_role']  = 'admin'
        session['last_active']= datetime.utcnow().isoformat()
        audit_log('admin_login', f'username={username}')
        flash(f'Welcome, {username}. Admin session active.', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_login.html')


# ═══════════════════════════════════════════════════════════
# STUDENT / STAFF DASHBOARD
# ═══════════════════════════════════════════════════════════

@app.route('/dashboard')
def dashboard():
    if require_login(): return redirect(url_for('login'))
    search   = request.args.get('q','').strip()
    campus_f = request.args.get('campus','').strip()
    page     = max(1, int(request.args.get('page', 1)))
    per_page = 10
    with get_db() as c:
        conds = ["a.status NOT IN ('closed','resolved')"]; params = []
        if search:
            conds.append("(a.incident_type LIKE ? OR a.description LIKE ? OR a.block LIKE ?)")
            params += [f'%{search}%']*3
        if campus_f:
            conds.append("a.campus=?"); params.append(campus_f)
        where = ' AND '.join(conds)
        total  = c.execute(f'SELECT COUNT(*) FROM alerts a WHERE {where}', params).fetchone()[0]
        alerts = c.execute(
            f'''SELECT a.*, u.name as reporter_name FROM alerts a
                JOIN users u ON a.reported_by=u.id
                WHERE {where} ORDER BY a.created_at DESC LIMIT ? OFFSET ?''',
            params+[per_page,(page-1)*per_page]
        ).fetchall()
        broadcasts = c.execute(
            'SELECT b.*,u.name as sender_name FROM broadcasts b '
            'JOIN users u ON b.sent_by=u.id ORDER BY b.sent_at DESC LIMIT 20'
        ).fetchall()
    return render_template('dashboard.html',
        alerts=alerts, broadcasts=broadcasts, search=search, campus_f=campus_f,
        page=page, total_pages=max(1,(total+per_page-1)//per_page),
        campuses=[campus_item[0] for campus_item in DUT_CAMPUSES if campus_item[0]])


# ═══════════════════════════════════════════════════════════
# STAFF DASHBOARD
# ═══════════════════════════════════════════════════════════

@app.route('/staff')
def staff_dashboard():
    if require_login(): return redirect(url_for('login'))
    if require_role('staff'):
        flash('Access denied.', 'error'); return redirect(url_for('index'))
    search   = request.args.get('q', '').strip()
    campus_f = request.args.get('campus', '').strip()
    page     = max(1, int(request.args.get('page', 1)))
    per_page = 10
    with get_db() as c:
        conds  = ["a.status NOT IN ('closed','resolved')"]; params = []
        if search:
            conds.append("(a.incident_type LIKE ? OR a.description LIKE ? OR a.block LIKE ?)")
            params += [f'%{search}%'] * 3
        if campus_f:
            conds.append("a.campus=?"); params.append(campus_f)
        where = ' AND '.join(conds)
        total  = c.execute(f'SELECT COUNT(*) FROM alerts a WHERE {where}', params).fetchone()[0]
        alerts = c.execute(
            f'''SELECT a.*, u.name as reporter_name FROM alerts a
                JOIN users u ON a.reported_by=u.id
                WHERE {where} ORDER BY a.created_at DESC LIMIT ? OFFSET ?''',
            params + [per_page, (page - 1) * per_page]
        ).fetchall()
        broadcasts = c.execute(
            'SELECT b.*, u.name as sender_name FROM broadcasts b '
            'JOIN users u ON b.sent_by=u.id ORDER BY b.sent_at DESC LIMIT 20'
        ).fetchall()
        stats = {
            'total':    c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
            'open':     c.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0],
            'resolved': c.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('resolved','closed')").fetchone()[0],
            'my_reports': c.execute(
                "SELECT COUNT(*) FROM alerts WHERE reported_by=?",
                (session['user_id'],)
            ).fetchone()[0],
        }
    return render_template('staff_dashboard.html',
        alerts=alerts, broadcasts=broadcasts, stats=stats,
        search=search, campus_f=campus_f,
        page=page, total_pages=max(1, (total + per_page - 1) // per_page),
        campuses=[campus_item[0] for campus_item in DUT_CAMPUSES if campus_item[0]])


# ═══════════════════════════════════════════════════════════
# ADMIN DASHBOARD
# ═══════════════════════════════════════════════════════════

@app.route('/admin')
def admin_dashboard():
    if require_login(): return redirect(url_for('login'))
    if require_role('admin'):
        flash('Access denied.', 'error'); return redirect(url_for('index'))
    search   = request.args.get('q','').strip()
    campus_f = request.args.get('campus','').strip()
    status_f = request.args.get('status','').strip()
    priority_f = request.args.get('priority','').strip()
    page     = max(1, int(request.args.get('page',1)))
    per_page = 15
    with get_db() as c:
        conds = []; params = []
        if search:
            conds.append("(a.incident_type LIKE ? OR a.description LIKE ? OR a.block LIKE ?)")
            params += [f'%{search}%']*3
        if campus_f:
            conds.append("a.campus=?"); params.append(campus_f)
        if status_f:
            conds.append("a.status=?"); params.append(status_f)
        if priority_f:
            conds.append("a.priority=?"); params.append(priority_f)
        where = ('WHERE ' + ' AND '.join(conds)) if conds else ''
        total  = c.execute(f'SELECT COUNT(*) FROM alerts a {where}', params).fetchone()[0]
        alerts = c.execute(
            f'''SELECT a.*, u.name as reporter_name,
                (SELECT sec.name FROM assignments asgn JOIN users sec ON asgn.security_id=sec.id
                 WHERE asgn.alert_id=a.id AND asgn.is_active=1 LIMIT 1) as assigned_to,
                (SELECT asgn.task_status FROM assignments asgn
                 WHERE asgn.alert_id=a.id AND asgn.is_active=1 LIMIT 1) as task_status
                FROM alerts a JOIN users u ON a.reported_by=u.id
                {where} ORDER BY
                CASE a.priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium' THEN 3 ELSE 4 END,
                a.created_at DESC LIMIT ? OFFSET ?''',
            params+[per_page,(page-1)*per_page]
        ).fetchall()
        broadcasts = c.execute(
            'SELECT b.*,u.name as sender_name FROM broadcasts b '
            'JOIN users u ON b.sent_by=u.id ORDER BY b.sent_at DESC LIMIT 20'
        ).fetchall()
        today = date.today().isoformat()
        security_officers = c.execute(
            """SELECT u.id, u.name,
               CASE WHEN a.is_active=1 AND a.date_str=? AND a.availability='available'
                    THEN 1 ELSE 0 END as is_available,
               a.clock_in,
               COALESCE(a.campus,'') as current_campus,
               COALESCE(a.shift,'')  as current_shift
               FROM users u
               LEFT JOIN attendance a ON a.security_id=u.id AND a.is_active=1 AND a.date_str=?
               WHERE u.role='security'
               ORDER BY is_available DESC, u.name""",
            (today, today)
        ).fetchall()
        stats = {
            'open': c.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0],
            'assigned': c.execute("SELECT COUNT(*) FROM alerts WHERE status='assigned'").fetchone()[0],
            'investigating': c.execute("SELECT COUNT(*) FROM alerts WHERE status='under_investigation'").fetchone()[0],
            'resolved': c.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('resolved','closed')").fetchone()[0],
            'total': c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        }
    return render_template('admin_dashboard.html',
        alerts=alerts, broadcasts=broadcasts, stats=stats,
        security_officers=security_officers,
        search=search, campus_f=campus_f, status_f=status_f, priority_f=priority_f,
        page=page, total_pages=max(1,(total+per_page-1)//per_page),
        campuses=[campus_item[0] for campus_item in DUT_CAMPUSES if campus_item[0]],
        alert_statuses=ALERT_STATUSES, priority_levels=PRIORITY_LEVELS)


@app.route('/admin/assign', methods=['POST'])
def assign_incident():
    if require_login() or require_role('admin'):
        return jsonify({'error':'Unauthorized'}), 403
    data        = request.get_json()
    alert_id    = data.get('alert_id')
    security_id = data.get('security_id')
    notes       = data.get('notes', '')
    if not alert_id or not security_id:
        return jsonify({'error':'Missing fields'}), 400
    with get_db() as c:
        c.execute("UPDATE assignments SET is_active=0 WHERE alert_id=? AND is_active=1",
                  (alert_id,))
        c.execute(
            "INSERT INTO assignments (alert_id,security_id,assigned_by,notes) VALUES (?,?,?,?)",
            (alert_id, security_id, session['user_id'], notes)
        )
        c.execute("UPDATE alerts SET status='assigned' WHERE id=?", (alert_id,))
        c.execute("INSERT INTO alert_updates (alert_id,updated_by,status) VALUES (?,?,?)",
                  (alert_id, session['user_id'], 'assigned'))
        officer = c.execute("SELECT name FROM users WHERE id=?", (security_id,)).fetchone()
    officer_name = officer['name'] if officer else 'Unknown'
    audit_log('assign_incident', f'alert_id={alert_id} officer={officer_name}')
    socketio.emit('incident_assigned', {
        'alert_id': alert_id, 'officer': officer_name, 'new_status': 'assigned'
    })
    return jsonify({'success': True, 'officer': officer_name})


@app.route('/admin/update_status', methods=['POST'])
def admin_update_status():
    if require_login() or require_role('admin'):
        return jsonify({'error':'Unauthorized'}), 403
    data      = request.get_json()
    alert_id  = data.get('alert_id')
    new_status = data.get('status')
    valid = [s[0] for s in ALERT_STATUSES]
    if new_status not in valid:
        return jsonify({'error':'Invalid status'}), 400
    with get_db() as c:
        c.execute("UPDATE alerts SET status=? WHERE id=?", (new_status, alert_id))
        c.execute("INSERT INTO alert_updates (alert_id,updated_by,status) VALUES (?,?,?)",
                  (alert_id, session['user_id'], new_status))
    audit_log('status_change', f'alert_id={alert_id} new_status={new_status}')
    socketio.emit('alert_status_update', {
        'alert_id': alert_id, 'new_status': new_status, 'updated_by': session['user_name']
    })
    return jsonify({'success': True})


@app.route('/admin/delete_alert', methods=['POST'])
def admin_delete_alert():
    if require_login() or require_role('admin'):
        return jsonify({'error':'Unauthorized'}), 403
    alert_id = request.get_json().get('alert_id')
    with get_db() as c:
        c.execute('DELETE FROM alerts WHERE id=?', (alert_id,))
    audit_log('delete_alert', f'alert_id={alert_id}')
    socketio.emit('alert_deleted', {'alert_id': alert_id})
    return jsonify({'success': True})


@app.route('/admin/incident/<int:alert_id>')
def admin_incident_detail(alert_id):
    if require_login() or require_role('admin'):
        flash('Access denied.', 'error'); return redirect(url_for('index'))
    with get_db() as c:
        alert = c.execute(
            'SELECT a.*,u.name as reporter_name FROM alerts a '
            'JOIN users u ON a.reported_by=u.id WHERE a.id=?', (alert_id,)
        ).fetchone()
        if not alert:
            flash('Incident not found.', 'error'); return redirect(url_for('admin_dashboard'))
        feedback = c.execute(
            'SELECT f.*,u.name as submitted_by_name FROM feedback f '
            'JOIN users u ON f.submitted_by=u.id '
            'WHERE f.alert_id=? ORDER BY f.submitted_at DESC', (alert_id,)
        ).fetchall()
        evidence = c.execute(
            'SELECT e.*,u.name as uploaded_by_name FROM evidence e '
            'JOIN users u ON e.uploaded_by=u.id '
            'WHERE e.alert_id=? ORDER BY e.uploaded_at DESC', (alert_id,)
        ).fetchall()
        assignments = c.execute(
            'SELECT asgn.*,sec.name as security_name,adm.name as assigned_by_name '
            'FROM assignments asgn '
            'JOIN users sec ON asgn.security_id=sec.id '
            'JOIN users adm ON asgn.assigned_by=adm.id '
            'WHERE asgn.alert_id=? ORDER BY asgn.assigned_at DESC', (alert_id,)
        ).fetchall()
        updates = c.execute(
            'SELECT au.*,u.name as updated_by_name FROM alert_updates au '
            'JOIN users u ON au.updated_by=u.id '
            'WHERE au.alert_id=? ORDER BY au.timestamp DESC', (alert_id,)
        ).fetchall()
        security_officers = c.execute(
            "SELECT id,name FROM users WHERE role='security' ORDER BY name"
        ).fetchall()
    return render_template('admin_incident_detail.html',
        alert=alert, feedback=feedback, evidence=evidence,
        assignments=assignments, updates=updates,
        security_officers=security_officers,
        alert_statuses=ALERT_STATUSES)


# ═══════════════════════════════════════════════════════════
# SECURITY DASHBOARD
# ═══════════════════════════════════════════════════════════

@app.route('/security')
def security_dashboard():
    if require_login(): return redirect(url_for('login'))
    if require_role('security'):
        flash('Access denied.', 'error'); return redirect(url_for('index'))
    uid      = session['user_id']
    search   = request.args.get('q', '').strip()
    campus_f = request.args.get('campus', '').strip()
    page     = max(1, int(request.args.get('page', 1)))
    per_page = 10
    with get_db() as c:
        my_tasks = c.execute(
            '''SELECT a.*, asgn.id as asgn_id, asgn.task_status, asgn.notes as asgn_notes,
                      asgn.assigned_at, u.name as reporter_name
               FROM assignments asgn
               JOIN alerts a ON asgn.alert_id=a.id
               JOIN users u ON a.reported_by=u.id
               WHERE asgn.security_id=? AND asgn.is_active=1
               ORDER BY
               CASE a.priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2
               WHEN 'medium' THEN 3 ELSE 4 END, asgn.assigned_at DESC''',
            (uid,)
        ).fetchall()
        stats = {
            'assigned':    sum(1 for t in my_tasks if t['task_status']=='assigned'),
            'accepted':    sum(1 for t in my_tasks if t['task_status']=='accepted'),
            'in_progress': sum(1 for t in my_tasks if t['task_status']=='in_progress'),
            'submitted':   sum(1 for t in my_tasks if t['task_status']=='submitted'),
        }
        conds = ["a.status NOT IN ('closed','resolved','false_alarm')"]; params = []
        if search:
            conds.append("(a.incident_type LIKE ? OR a.description LIKE ? OR a.block LIKE ?)")
            params += [f'%{search}%'] * 3
        if campus_f:
            conds.append("a.campus=?"); params.append(campus_f)
        where = ' AND '.join(conds)
        total  = c.execute(f'SELECT COUNT(*) FROM alerts a WHERE {where}', params).fetchone()[0]
        active_alerts = c.execute(
            f'''SELECT a.*, u.name as reporter_name FROM alerts a
                JOIN users u ON a.reported_by=u.id
                WHERE {where}
                ORDER BY
                CASE a.priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium' THEN 3 ELSE 4 END,
                a.created_at DESC LIMIT ? OFFSET ?''',
            params + [per_page, (page - 1) * per_page]
        ).fetchall()
        broadcasts = c.execute(
            'SELECT b.*,u.name as sender_name FROM broadcasts b '
            'JOIN users u ON b.sent_by=u.id ORDER BY b.sent_at DESC LIMIT 10'
        ).fetchall()
    return render_template('security_dashboard.html',
        tasks=my_tasks, stats=stats,
        active_alerts=active_alerts, broadcasts=broadcasts,
        search=search, campus_f=campus_f,
        page=page, total_pages=max(1, (total + per_page - 1) // per_page),
        campuses=[ci[0] for ci in DUT_CAMPUSES if ci[0]])


@app.route('/security/task/<int:alert_id>')
def security_task_detail(alert_id):
    if require_login() or require_role('security'):
        flash('Access denied.', 'error'); return redirect(url_for('index'))
    uid = session['user_id']
    with get_db() as c:
        assignment = c.execute(
            'SELECT * FROM assignments WHERE alert_id=? AND security_id=? AND is_active=1',
            (alert_id, uid)
        ).fetchone()
        if not assignment:
            flash('Task not found or not assigned to you.', 'error')
            return redirect(url_for('security_dashboard'))
        alert = c.execute(
            'SELECT a.*,u.name as reporter_name FROM alerts a '
            'JOIN users u ON a.reported_by=u.id WHERE a.id=?', (alert_id,)
        ).fetchone()
        feedback = c.execute(
            'SELECT * FROM feedback WHERE alert_id=? AND submitted_by=? '
            'ORDER BY submitted_at DESC', (alert_id, uid)
        ).fetchall()
        evidence = c.execute(
            'SELECT * FROM evidence WHERE alert_id=? AND uploaded_by=? '
            'ORDER BY uploaded_at DESC', (alert_id, uid)
        ).fetchall()
    return render_template('security_task_detail.html',
        alert=alert, assignment=assignment,
        feedback=feedback, evidence=evidence,
        feedback_statuses=FEEDBACK_STATUSES)


@app.route('/security/accept_task', methods=['POST'])
def accept_task():
    if require_login() or require_role('security'):
        return jsonify({'error':'Unauthorized'}), 403
    data     = request.get_json()
    alert_id = data.get('alert_id')
    uid      = session['user_id']
    now      = datetime.now().isoformat()
    with get_db() as c:
        c.execute(
            "UPDATE assignments SET task_status='accepted', accepted_at=? "
            "WHERE alert_id=? AND security_id=? AND is_active=1",
            (now, alert_id, uid)
        )
        c.execute("UPDATE alerts SET status='under_investigation' WHERE id=?", (alert_id,))
        c.execute("INSERT INTO alert_updates (alert_id,updated_by,status) VALUES (?,?,?)",
                  (alert_id, uid, 'under_investigation'))
    socketio.emit('alert_status_update', {
        'alert_id': alert_id, 'new_status': 'under_investigation',
        'updated_by': session['user_name']
    })
    return jsonify({'success': True})


@app.route('/security/update_task_status', methods=['POST'])
def update_task_status():
    if require_login() or require_role('security'):
        return jsonify({'error':'Unauthorized'}), 403
    data       = request.get_json()
    alert_id   = data.get('alert_id')
    new_status = data.get('task_status')
    if new_status not in TASK_STATUSES:
        return jsonify({'error':'Invalid task status'}), 400
    uid = session['user_id']
    alert_status_map = {
        'requires_reinforcements': 'requires_reinforcements',
        'false_alarm':             'false_alarm',
        'resolved':                'resolved',
        'in_progress':             'under_investigation',
        'accepted':                'under_investigation',
    }
    with get_db() as c:
        c.execute(
            "UPDATE assignments SET task_status=? "
            "WHERE alert_id=? AND security_id=? AND is_active=1",
            (new_status, alert_id, uid)
        )
        if new_status in alert_status_map:
            new_alert_status = alert_status_map[new_status]
            c.execute("UPDATE alerts SET status=? WHERE id=?",
                      (new_alert_status, alert_id))
            c.execute("INSERT INTO alert_updates (alert_id,updated_by,status) VALUES (?,?,?)",
                      (alert_id, uid, new_alert_status))
    socketio.emit('alert_status_update', {
        'alert_id': alert_id,
        'new_status': alert_status_map.get(new_status, new_status),
        'updated_by': session.get('user_name', 'Security')
    })
    return jsonify({'success': True, 'task_status': new_status})


@app.route('/security/submit_feedback/<int:alert_id>', methods=['GET','POST'])
def submit_feedback(alert_id):
    if require_login() or require_role('security'):
        flash('Access denied.', 'error'); return redirect(url_for('index'))
    uid = session['user_id']
    with get_db() as c:
        assignment = c.execute(
            'SELECT * FROM assignments WHERE alert_id=? AND security_id=? AND is_active=1',
            (alert_id, uid)
        ).fetchone()
        if not assignment:
            flash('Task not found.', 'error')
            return redirect(url_for('security_dashboard'))

    if request.method == 'POST':
        if not _csrf_valid():
            flash('Security token invalid. Please try again.', 'error')
            return redirect(url_for('security_task_detail', alert_id=alert_id))
        form = FeedbackForm(request.form, request.files)
        ok, errs = form.validate()
        if not ok:
            for m in errs.values(): flash(m, 'error')
            return redirect(url_for('security_task_detail', alert_id=alert_id))

        evidence_filename = save_upload(form.image, prefix='ev_')
        now = datetime.now().isoformat()
        with get_db() as c:
            c.execute(
                'INSERT INTO feedback '
                '(alert_id,assignment_id,submitted_by,notes,status_update) '
                'VALUES (?,?,?,?,?)',
                (alert_id, assignment['id'], uid,
                 form.notes, form.status_update)
            )
            if evidence_filename:
                c.execute(
                    'INSERT INTO evidence (alert_id,uploaded_by,filename) VALUES (?,?,?)',
                    (alert_id, uid, evidence_filename)
                )
            c.execute(
                "UPDATE assignments SET task_status='submitted', submitted_at=? "
                "WHERE id=?", (now, assignment['id'])
            )
            status_map = {
                'Incident Resolved':           'resolved',
                'Investigation Completed':     'resolved',
                'Requires Reinforcements':     'requires_reinforcements',
                'Escalated':                   'escalated',
                'False Alarm':                 'false_alarm',
                'Under Investigation':         'under_investigation',
                'Unable to Access Location':   'under_investigation',
                'Emergency Response Requested':'escalated',
            }
            new_alert_status = status_map.get(form.status_update, 'under_investigation')
            c.execute("UPDATE alerts SET status=? WHERE id=?", (new_alert_status, alert_id))
            c.execute("INSERT INTO alert_updates (alert_id,updated_by,status) VALUES (?,?,?)",
                      (alert_id, uid, new_alert_status))

        socketio.emit('alert_status_update', {
            'alert_id': alert_id, 'new_status': new_alert_status,
            'updated_by': session['user_name']
        })
        flash('Investigation report submitted successfully.', 'success')
        return redirect(url_for('security_task_detail', alert_id=alert_id))

    with get_db() as c:
        alert = c.execute('SELECT * FROM alerts WHERE id=?', (alert_id,)).fetchone()
    return render_template('submit_feedback.html',
        alert=alert, assignment=assignment,
        feedback_statuses=FEEDBACK_STATUSES)


@app.route('/security/report', methods=['GET','POST'])
def security_report_incident():
    if require_login() or require_role('security'):
        flash('Access denied.', 'error'); return redirect(url_for('index'))
    ctx = dict(campuses=DUT_CAMPUSES, dut_blocks=DUT_BLOCKS,
               incident_types=INCIDENT_TYPES, severity_levels=SEVERITY_LEVELS,
               priority_levels=PRIORITY_LEVELS, back_url=url_for('security_dashboard'))
    if request.method == 'POST':
        form = AlertForm(request.form, request.files)
        ok, errs = form.validate()
        if not ok:
            for m in errs.values(): flash(m, 'error')
            return render_template('report_incident.html', **ctx)
        image_filename = save_upload(form.image, prefix='inc_')
        location_full  = f"{form.campus} — {form.block}"
        with get_db() as c:
            c.execute(
                'INSERT INTO alerts (incident_type,location,campus,block,description,'
                'reported_by,severity,priority,status,image_filename) '
                "VALUES (?,?,?,?,?,?,?,?,'open',?)",
                (form.resolved_incident_type, location_full, form.campus,
                 form.block, form.description, session['user_id'],
                 form.severity, form.priority, image_filename)
            )
            alert = c.execute(
                'SELECT a.*,u.name as reporter_name FROM alerts a '
                'JOIN users u ON a.reported_by=u.id ORDER BY a.id DESC LIMIT 1'
            ).fetchone()
        socketio.emit('receive_alert', {
            'id': alert['id'], 'incident_type': alert['incident_type'],
            'location': alert['location'], 'campus': alert['campus'] or '',
            'description': alert['description'], 'severity': alert['severity'],
            'priority': alert['priority'], 'status': alert['status'],
            'reporter_name': alert['reporter_name'],
            'image_filename': alert['image_filename'] or '',
            'created_at': str(alert['created_at']),
        })
        flash('Incident reported successfully. All security personnel have been notified.', 'success')
        return redirect(url_for('security_dashboard'))
    return render_template('report_incident.html', **ctx)


# ═══════════════════════════════════════════════════════════
# SHARED ROUTES
# ═══════════════════════════════════════════════════════════

@app.route('/history')
def alert_history():
    if require_login(): return redirect(url_for('login'))
    if session.get('user_role') == 'student':
        flash('Alert history is not available for student accounts.', 'info')
        return redirect(url_for('dashboard'))
    search   = request.args.get('q','').strip()
    campus_f = request.args.get('campus','').strip()
    page     = max(1, int(request.args.get('page', 1)))
    per_page = 15
    with get_db() as c:
        conds = ["a.status IN ('resolved','closed','false_alarm')"]; params = []
        if search:
            conds.append("(a.incident_type LIKE ? OR a.description LIKE ?)")
            params += [f'%{search}%']*2
        if campus_f:
            conds.append("a.campus=?"); params.append(campus_f)
        where = ' AND '.join(conds)
        total    = c.execute(f'SELECT COUNT(*) FROM alerts a WHERE {where}', params).fetchone()[0]
        resolved = c.execute(
            f'''SELECT a.*, u.name as reporter_name,
                (SELECT u2.name FROM users u2 JOIN alert_updates au ON au.updated_by=u2.id
                 WHERE au.alert_id=a.id AND au.status IN ('resolved','closed')
                 ORDER BY au.timestamp DESC LIMIT 1) as resolved_by,
                (SELECT au.timestamp FROM alert_updates au
                 WHERE au.alert_id=a.id AND au.status IN ('resolved','closed')
                 ORDER BY au.timestamp DESC LIMIT 1) as resolved_at
                FROM alerts a JOIN users u ON a.reported_by=u.id
                WHERE {where} ORDER BY a.created_at DESC LIMIT ? OFFSET ?''',
            params+[per_page,(page-1)*per_page]
        ).fetchall()
    return render_template('history.html',
        resolved=resolved, search=search, campus_f=campus_f,
        page=page, total_pages=max(1,(total+per_page-1)//per_page),
        campuses=[campus_item[0] for campus_item in DUT_CAMPUSES if campus_item[0]])


@app.route('/analytics')
def analytics():
    if require_login(): return redirect(url_for('login'))
    with get_db() as c:
        by_campus   = c.execute("SELECT campus,COUNT(*) as count FROM alerts WHERE campus IS NOT NULL AND campus!='' GROUP BY campus ORDER BY count DESC").fetchall()
        by_type     = c.execute("SELECT incident_type,COUNT(*) as count FROM alerts GROUP BY incident_type ORDER BY count DESC").fetchall()
        by_severity = c.execute("SELECT severity,COUNT(*) as count FROM alerts GROUP BY severity ORDER BY count DESC").fetchall()
        by_priority = c.execute("SELECT priority,COUNT(*) as count FROM alerts WHERE priority IS NOT NULL GROUP BY priority ORDER BY count DESC").fetchall()
        by_status   = c.execute("SELECT status,COUNT(*) as count FROM alerts GROUP BY status").fetchall()
        hotspots    = c.execute("SELECT campus,block,COUNT(*) as count FROM alerts WHERE campus IS NOT NULL AND block IS NOT NULL GROUP BY campus,block ORDER BY count DESC LIMIT 5").fetchall()
        # Monthly query — works for both PostgreSQL and SQLite
        if _using_pg():
            monthly = list(reversed(c.execute("SELECT TO_CHAR(created_at, 'YYYY-MM') as month,COUNT(*) as count FROM alerts GROUP BY month ORDER BY month DESC LIMIT 6").fetchall()))
        else:
            monthly = list(reversed(c.execute("SELECT strftime('%Y-%m',created_at) as month,COUNT(*) as count FROM alerts GROUP BY month ORDER BY month DESC LIMIT 6").fetchall()))
        total_alerts   = c.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        total_resolved = c.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('resolved','closed')").fetchone()[0]
        total_active   = c.execute("SELECT COUNT(*) FROM alerts WHERE status NOT IN ('resolved','closed','false_alarm')").fetchone()[0]
        total_users    = c.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    return render_template('analytics.html',
        by_campus=by_campus, by_type=by_type, by_severity=by_severity,
        by_priority=by_priority, by_status=by_status, hotspots=hotspots, monthly=monthly,
        total_alerts=total_alerts, total_resolved=total_resolved,
        total_active=total_active, total_users=total_users)


@app.route('/chat')
def chat():
    if require_login(): return redirect(url_for('login'))
    with get_db() as c:
        messages = list(reversed(c.execute(
            "SELECT m.*,u.name as sender_name,u.role as sender_role "
            "FROM messages m JOIN users u ON m.sender_id=u.id "
            "WHERE m.is_deleted=0 AND (m.room='main_chat' OR m.room IS NULL) "
            "ORDER BY m.timestamp DESC LIMIT 50"
        ).fetchall()))
        # Active users query — works for both PostgreSQL and SQLite
        if _using_pg():
            active_users = c.execute(
                """SELECT DISTINCT u.id, u.name, u.role,
                   COALESCE(u.is_banned, 0) as is_banned
                   FROM messages m JOIN users u ON m.sender_id=u.id
                   WHERE m.is_deleted=0
                     AND m.room='main_chat'
                     AND m.timestamp >= NOW() - INTERVAL '24 hours'
                     AND u.role NOT IN ('admin','security')
                   ORDER BY u.name"""
            ).fetchall()
        else:
            active_users = c.execute(
                """SELECT DISTINCT u.id, u.name, u.role,
                   COALESCE(u.is_banned, 0) as is_banned
                   FROM messages m JOIN users u ON m.sender_id=u.id
                   WHERE m.is_deleted=0
                     AND m.room='main_chat'
                     AND m.timestamp >= datetime('now','-24 hours')
                     AND u.role NOT IN ('admin','security')
                   ORDER BY u.name"""
            ).fetchall()
    role = session.get('user_role')
    messages_today = get_chat_count_today(session['user_id']) \
                     if role not in ('admin',) else 0
    with _mod_lock:
        current_muted = set(_muted_users)
    return render_template('chat.html', messages=messages,
                           messages_today=messages_today,
                           chat_limit=CHAT_DAILY_LIMIT,
                           active_users=active_users,
                           muted_users=current_muted,
                           chat_locked=_is_chat_locked())


@app.route('/private-chat')
def private_chat():
    if require_login(): return redirect(url_for('login'))
    if require_role('admin', 'security'):
        flash('Access denied. This channel is for security personnel only.', 'error')
        return redirect(url_for('chat'))
    with get_db() as c:
        messages = list(reversed(c.execute(
            "SELECT m.*,u.name as sender_name,u.role as sender_role "
            "FROM messages m JOIN users u ON m.sender_id=u.id "
            "WHERE m.is_deleted=0 AND m.room='private_admin_security' "
            "ORDER BY m.timestamp DESC LIMIT 100"
        ).fetchall()))
    return render_template('private_chat.html', messages=messages)


@app.route('/delete_message', methods=['POST'])
def delete_message():
    if require_login() or require_role('admin'):
        return jsonify({'error':'Unauthorized'}), 403
    data = request.get_json(); mid = data.get('message_id')
    with get_db() as c:
        c.execute('UPDATE messages SET is_deleted=1 WHERE id=?', (mid,))
        c.execute('INSERT INTO deleted_messages (message_id,deleted_by,reason) VALUES (?,?,?)',
                  (mid, session['user_id'], data.get('reason','Moderation')))
    socketio.emit('message_deleted', {'message_id': mid})
    return jsonify({'success': True})


# ═══════════════════════════════════════════════════════════
# REST API
# ═══════════════════════════════════════════════════════════

@app.route('/api/alerts')
def api_alerts():
    if require_login(): return jsonify({'error':'Authentication required'}), 401
    with get_db() as c:
        rows = c.execute(
            'SELECT a.id,a.incident_type,a.location,a.campus,a.block,'
            'a.description,a.severity,a.priority,a.status,a.created_at,'
            'u.name as reported_by FROM alerts a JOIN users u ON a.reported_by=u.id '
            'ORDER BY a.created_at DESC'
        ).fetchall()
    return jsonify({'count': len(rows), 'alerts': [{k: str(v) for k, v in dict(zip(r.keys(), r.values())).items()} for r in rows]})


@app.route('/api/users')
def api_users():
    if require_login() or require_role('admin'):
        return jsonify({'error':'Unauthorized'}), 403
    with get_db() as c:
        rows = c.execute(
            'SELECT id,name,email,role,created_at FROM users ORDER BY created_at DESC'
        ).fetchall()
    return jsonify({'count': len(rows), 'users': [{k: str(v) for k, v in dict(zip(r.keys(), r.values())).items()} for r in rows]})


@app.route('/api/analytics')
def api_analytics():
    if require_login(): return jsonify({'error':'Authentication required'}), 401
    with get_db() as c:
        by_campus = c.execute("SELECT campus,COUNT(*) as count FROM alerts WHERE campus!='' GROUP BY campus").fetchall()
        by_type   = c.execute("SELECT incident_type,COUNT(*) as count FROM alerts GROUP BY incident_type").fetchall()
    return jsonify({
        'by_campus': [{k: str(v) for k, v in dict(zip(r.keys(), r.values())).items()} for r in by_campus],
        'by_type':   [{k: str(v) for k, v in dict(zip(r.keys(), r.values())).items()} for r in by_type],
    })


# ═══════════════════════════════════════════════════════════
# CHAT BAN ROUTES
# ═══════════════════════════════════════════════════════════

@app.route('/chat/ban/<int:target_id>', methods=['POST'])
def ban_user(target_id):
    if require_login() or require_role('admin', 'security'):
        return jsonify({'error': 'Unauthorized'}), 403
    with get_db() as c:
        target = c.execute('SELECT role FROM users WHERE id=?', (target_id,)).fetchone()
        if not target:
            return jsonify({'error': 'User not found'}), 404
        if target['role'] in ('admin', 'security'):
            return jsonify({'error': 'Cannot ban admin or security users'}), 400
        c.execute('UPDATE users SET is_banned=1 WHERE id=?', (target_id,))
    _set_muted(target_id, True)
    audit_log('ban_user', f'target_user_id={target_id}')
    socketio.emit('you_are_muted', {
        'message': 'You have been permanently banned from chat by security.'
    }, room=f'user_{target_id}')
    socketio.emit('user_muted', {'user_id': target_id})
    return jsonify({'success': True})


@app.route('/chat/unban/<int:target_id>', methods=['POST'])
def unban_user(target_id):
    if require_login() or require_role('admin', 'security'):
        return jsonify({'error': 'Unauthorized'}), 403
    with get_db() as c:
        c.execute('UPDATE users SET is_banned=0 WHERE id=?', (target_id,))
    _set_muted(target_id, False)
    audit_log('unban_user', f'target_user_id={target_id}')
    socketio.emit('you_are_unmuted', {
        'message': 'Your chat ban has been lifted.'
    }, room=f'user_{target_id}')
    socketio.emit('user_unmuted', {'user_id': target_id})
    return jsonify({'success': True})


# ═══════════════════════════════════════════════════════════
# SOCKET IO
# ═══════════════════════════════════════════════════════════

@socketio.on('connect')
def handle_connect():
    print(f'Connected: {request.sid}')
    if 'user_id' in session:
        from flask_socketio import join_room as _jr
        _jr(f"user_{session['user_id']}")
        uid = session['user_id']
        with get_db() as c:
            row = c.execute('SELECT is_banned FROM users WHERE id=?', (uid,)).fetchone()
            if row and row['is_banned']:
                _set_muted(uid, True)

@socketio.on('disconnect')
def handle_disconnect(): print(f'Disconnected: {request.sid}')

@socketio.on('join_room_event')
def on_join_room(data):
    room = data.get('room', 'main_chat')
    role = session.get('user_role', 'student')
    if room == 'private_admin_security' and role not in ('admin', 'security'):
        emit('chat_error', {'message': 'Access denied to private channel.'})
        return
    from flask_socketio import join_room as _join_room
    _join_room(room)
    emit('system_msg', {'text': f'Joined {room} channel.'})

@socketio.on('send_message')
def handle_message(data):
    if 'user_id' not in session: return
    user_id = session['user_id']
    role    = session.get('user_role', 'student')
    room    = data.get('room', 'main_chat')
    is_mod  = role in ('admin', 'security')

    if room == 'private_admin_security' and not is_mod:
        emit('chat_error', {'message': 'Access denied to private channel.'})
        return

    if not is_mod and room == 'main_chat':
        with get_db() as c:
            banned = c.execute('SELECT is_banned FROM users WHERE id=?', (user_id,)).fetchone()
            if banned and banned['is_banned']:
                emit('chat_error', {'message': 'You are banned from chat.'})
                return
        if _is_muted(user_id):
            emit('chat_error', {'message': 'You have been muted by security and cannot send messages.'})
            return
        if _is_chat_locked():
            emit('chat_error', {'message': 'Chat is currently locked by security. Only security personnel can send messages.'})
            return
        if not _check_msg_cooldown(user_id):
            emit('chat_error', {'message': f'Please wait {MSG_COOLDOWN_SECS} seconds before sending again.'})
            return
        if get_chat_count_today(user_id) >= CHAT_DAILY_LIMIT:
            emit('chat_error', {'message': f'Daily limit of {CHAT_DAILY_LIMIT} messages reached.'})
            return

    message = sanitise(data.get('message', ''))
    if not message: return
    if contains_profanity(message):
        emit('chat_error', {'message': 'Message contains inappropriate language and was not sent.'})
        return
    message = message[:500]

    receiver_role = 'all' if is_mod else 'admin'
    with get_db() as c:
        c.execute('INSERT INTO messages (sender_id,receiver_role,message,room) VALUES (?,?,?,?)',
                  (user_id, receiver_role, message, room))
        # Get last inserted message id — works for both PG and SQLite
        if _using_pg():
            msg_id = c.execute("SELECT id FROM messages ORDER BY id DESC LIMIT 1").fetchone()[0]
        else:
            msg_id = c.execute('SELECT last_insert_rowid()').fetchone()[0]
    emit('receive_message', {
        'id': msg_id, 'message': message,
        'sender_name': sanitise(session.get('user_name', 'Unknown')),
        'sender_role': role,
        'timestamp': datetime.now().strftime('%H:%M'),
        'room': room,
    }, broadcast=True)

@socketio.on('send_private_message')
def handle_private_message(data):
    role = session.get('user_role', 'student')
    if role not in ('admin', 'security'):
        emit('chat_error', {'message': 'Access denied.'})
        return
    message = sanitise(data.get('message', ''))
    if not message or 'user_id' not in session: return
    message = message[:500]
    if contains_profanity(message):
        emit('chat_error', {'message': 'Message contains inappropriate language.'})
        return
    with get_db() as c:
        c.execute(
            "INSERT INTO messages (sender_id,receiver_role,message,room) VALUES (?,?,?,?)",
            (session['user_id'], 'security', message, 'private_admin_security')
        )
        if _using_pg():
            msg_id = c.execute("SELECT id FROM messages ORDER BY id DESC LIMIT 1").fetchone()[0]
        else:
            msg_id = c.execute('SELECT last_insert_rowid()').fetchone()[0]
    emit('receive_private_message', {
        'id': msg_id, 'message': message,
        'sender_name': sanitise(session.get('user_name','Unknown')),
        'sender_role': role,
        'timestamp': datetime.now().strftime('%H:%M'),
    }, room='private_admin_security')

@socketio.on('broadcast_alert')
def handle_broadcast(data):
    if 'user_id' not in session: return
    if session.get('user_role') not in ('admin',): return
    message = sanitise(data.get('message',''))
    if not message: return
    message = message[:300]
    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    with get_db() as c:
        c.execute('INSERT INTO broadcasts (message,sent_by) VALUES (?,?)',
                  (message, session['user_id']))
    emit('emergency_broadcast', {
        'message': message,
        'sender': session.get('user_name','Admin'),
        'timestamp': now,
    }, broadcast=True)


# ═══════════════════════════════════════════════════════════
# CHAT MODERATION
# ═══════════════════════════════════════════════════════════

@socketio.on('mute_user')
def handle_mute_user(data):
    if 'user_id' not in session: return
    if session.get('user_role') not in ('admin', 'security'): return
    target_id = data.get('user_id')
    if not target_id: return
    target_id = int(target_id)
    _set_muted(target_id, True)
    audit_log('mute_user', f'target_user_id={target_id}')
    emit('you_are_muted', {
        'message': 'You have been muted by security. You cannot send messages at this time.'
    }, room=f'user_{target_id}')
    emit('user_muted', {'user_id': target_id}, broadcast=True)


@socketio.on('unmute_user')
def handle_unmute_user(data):
    if 'user_id' not in session: return
    if session.get('user_role') not in ('admin', 'security'): return
    target_id = data.get('user_id')
    if not target_id: return
    target_id = int(target_id)
    _set_muted(target_id, False)
    audit_log('unmute_user', f'target_user_id={target_id}')
    emit('you_are_unmuted', {
        'message': 'Your mute has been lifted. You may send messages again.'
    }, room=f'user_{target_id}')
    emit('user_unmuted', {'user_id': target_id}, broadcast=True)


@socketio.on('lockdown_chat')
def handle_lockdown_chat():
    if 'user_id' not in session: return
    if session.get('user_role') not in ('admin', 'security'): return
    _set_chat_locked(True)
    audit_log('lockdown_chat', 'public chat locked')
    emit('chat_lockdown', {
        'message': '🔒 Chat has been locked by security. Only security personnel can send messages.'
    }, broadcast=True)


@socketio.on('unlock_chat')
def handle_unlock_chat():
    if 'user_id' not in session: return
    if session.get('user_role') not in ('admin', 'security'): return
    _set_chat_locked(False)
    audit_log('unlock_chat', 'public chat unlocked')
    emit('chat_unlocked', {
        'message': '🔓 Chat has been reopened by security.'
    }, broadcast=True)


@socketio.on('delete_message_socket')
def handle_delete_message_socket(data):
    if 'user_id' not in session: return
    if session.get('user_role') not in ('admin',): return
    msg_id = data.get('message_id')
    if not msg_id: return
    with get_db() as c:
        c.execute('UPDATE messages SET is_deleted=1 WHERE id=?', (msg_id,))
        c.execute('INSERT INTO deleted_messages (message_id,deleted_by,reason) VALUES (?,?,?)',
                  (msg_id, session['user_id'], 'Moderation'))
    audit_log('delete_message', f'message_id={msg_id}')
    emit('message_deleted', {'message_id': msg_id}, broadcast=True)


# ═══════════════════════════════════════════════════════════
# STUDENT / STAFF — REPORT INCIDENT
# ═══════════════════════════════════════════════════════════

@app.route('/report', methods=['GET','POST'])
def report_incident():
    if require_login(): return redirect(url_for('login'))
    if require_role('student','staff','security','admin'):
        flash('Access denied.', 'error'); return redirect(url_for('index'))
    role = session.get('user_role', 'student')
    back = url_for('staff_dashboard') if role == 'staff' else url_for('dashboard')
    ctx = dict(campuses=DUT_CAMPUSES, dut_blocks=DUT_BLOCKS,
               incident_types=INCIDENT_TYPES, severity_levels=SEVERITY_LEVELS,
               priority_levels=PRIORITY_LEVELS, back_url=back)
    if request.method == 'POST':
        form = AlertForm(request.form, request.files)
        ok, errs = form.validate()
        if not ok:
            for m in errs.values(): flash(m, 'error')
            return render_template('report_incident.html', **ctx)

        image_filename = save_upload(form.image, prefix='rep_')
        location_full  = f"{form.campus} — {form.block}"
        with get_db() as c:
            c.execute(
                'INSERT INTO alerts (incident_type,location,campus,block,description,'
                'reported_by,severity,priority,status,image_filename) '
                "VALUES (?,?,?,?,?,?,?,?,'open',?)",
                (form.resolved_incident_type, location_full, form.campus, form.block,
                 form.description, session['user_id'], form.severity, form.priority,
                 image_filename)
            )
            alert = c.execute(
                'SELECT a.*,u.name as reporter_name FROM alerts a '
                'JOIN users u ON a.reported_by=u.id ORDER BY a.id DESC LIMIT 1'
            ).fetchone()
        socketio.emit('receive_alert', {
            'id': alert['id'], 'incident_type': alert['incident_type'],
            'location': alert['location'], 'campus': alert['campus'] or '',
            'description': alert['description'], 'severity': alert['severity'],
            'priority': alert['priority'], 'status': alert['status'],
            'reporter_name': alert['reporter_name'],
            'image_filename': alert['image_filename'] or '',
            'created_at': str(alert['created_at']),
        })
        flash('Incident reported successfully. Our security team will be notified.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('report_incident.html', **ctx)


# ═══════════════════════════════════════════════════════════
# SECURITY ATTENDANCE REGISTER
# ═══════════════════════════════════════════════════════════

@app.route('/security/attendance', methods=['GET', 'POST'])
def security_attendance():
    if require_login() or require_role('security'):
        flash('Access denied.', 'error'); return redirect(url_for('index'))
    uid   = session['user_id']
    today = date.today().isoformat()

    VALID_SHIFTS = ['Day Shift (07:00-15:00)', 'Evening Shift (15:00-23:00)', 'Night Shift (23:00-07:00)']
    CAMPUSES = [v for v,_ in DUT_CAMPUSES if v]

    if request.method == 'POST':
        if not _csrf_valid():
            flash('Security token invalid. Please try again.', 'error')
            return redirect(url_for('security_attendance'))
        action = request.form.get('action')
        with get_db() as c:
            active = c.execute(
                "SELECT * FROM attendance WHERE security_id=? AND is_active=1 AND date_str=?",
                (uid, today)
            ).fetchone()

            if action == 'clock_in' and not active:
                campus = request.form.get('campus', '').strip()
                shift  = request.form.get('shift',  '').strip()
                avail  = request.form.get('availability', 'available')
                if not campus:
                    flash('Please select a campus before clocking in.', 'error')
                    return redirect(url_for('security_attendance'))
                if shift not in VALID_SHIFTS:
                    flash('Please select a valid shift before clocking in.', 'error')
                    return redirect(url_for('security_attendance'))
                c.execute(
                    "INSERT INTO attendance (security_id, date_str, availability, campus, shift) VALUES (?,?,?,?,?)",
                    (uid, today, avail, campus, shift)
                )
                flash(f'Clocked in — {campus} · {shift}', 'success')

            elif action == 'clock_out' and active:
                if _using_pg():
                    c.execute(
                        "UPDATE attendance SET clock_out=NOW(), is_active=0 WHERE id=?",
                        (active['id'],)
                    )
                else:
                    c.execute(
                        "UPDATE attendance SET clock_out=CURRENT_TIMESTAMP, is_active=0 WHERE id=?",
                        (active['id'],)
                    )
                flash('Clocked out. Have a safe day.', 'success')

            elif action == 'set_availability' and active:
                avail = request.form.get('availability', 'available')
                c.execute(
                    "UPDATE attendance SET availability=? WHERE id=?",
                    (avail, active['id'])
                )
                flash(f'Availability updated to {avail}.', 'success')

        return redirect(url_for('security_attendance'))

    with get_db() as c:
        active = c.execute(
            "SELECT * FROM attendance WHERE security_id=? AND is_active=1 AND date_str=?",
            (uid, today)
        ).fetchone()
        history = c.execute(
            "SELECT * FROM attendance WHERE security_id=? ORDER BY clock_in DESC LIMIT 14",
            (uid,)
        ).fetchall()

    return render_template('security_attendance.html',
        active=active, history=history, today=today,
        campuses=CAMPUSES, shifts=VALID_SHIFTS)


@app.route('/admin/attendance')
def admin_attendance():
    if require_login() or require_role('admin'):
        flash('Access denied.', 'error'); return redirect(url_for('index'))
    today = date.today().isoformat()
    with get_db() as c:
        on_campus = c.execute(
            """SELECT a.*, u.name as security_name, u.email,
               COALESCE(a.campus,'—') as campus,
               COALESCE(a.shift,'—')  as shift
               FROM attendance a JOIN users u ON a.security_id=u.id
               WHERE a.is_active=1 AND a.date_str=?
               ORDER BY a.clock_in DESC""",
            (today,)
        ).fetchall()
        all_security = c.execute(
            "SELECT id, name, email FROM users WHERE role='security' ORDER BY name"
        ).fetchall()
    clocked_ids = {r['security_id'] for r in on_campus}
    off_campus  = [s for s in all_security if s['id'] not in clocked_ids]
    return render_template('admin_attendance.html',
        on_campus=on_campus, off_campus=off_campus, today=today)


@app.route('/security/team')
def security_team_view():
    if require_login() or require_role('security'):
        flash('Access denied.', 'error'); return redirect(url_for('index'))
    with get_db() as c:
        incidents = c.execute(
            """SELECT a.*, u.name as reporter_name,
               (SELECT sec.name FROM assignments asgn
                JOIN users sec ON asgn.security_id=sec.id
                WHERE asgn.alert_id=a.id AND asgn.is_active=1 LIMIT 1) as assigned_to,
               (SELECT asgn.task_status FROM assignments asgn
                WHERE asgn.alert_id=a.id AND asgn.is_active=1 LIMIT 1) as task_status
               FROM alerts a JOIN users u ON a.reported_by=u.id
               WHERE a.status NOT IN ('closed','resolved','false_alarm')
               ORDER BY CASE a.priority
                 WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                 WHEN 'medium' THEN 3 ELSE 4 END,
               a.created_at DESC"""
        ).fetchall()
    return render_template('security_team_view.html', incidents=incidents)


# ═══════════════════════════════════════════════════════════
# FORGOT PASSWORD / RESET
# ═══════════════════════════════════════════════════════════

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        if not _rate_check(f'reset:{request.remote_addr}', max_calls=3, window_secs=300):
            flash('Too many password reset requests. Please wait 5 minutes.', 'error')
            return render_template('forgot_password.html'), 429
        if not _csrf_valid():
            flash('Security token invalid. Please try again.', 'error')
            return render_template('forgot_password.html')
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash('Please enter your email address.', 'error')
            return render_template('forgot_password.html')

        with get_db() as c:
            user = c.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()

        if user:
            token = _ts.dumps(email)
            sent  = send_reset_email(email, token, user['name'])
            if sent:
                flash(f'Password reset instructions sent to {email}. Check your inbox.', 'success')
            else:
                flash('Could not send email. Please contact the administrator.', 'error')
        else:
            flash(f'If {email} is registered, a reset link has been sent.', 'info')

        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    with _token_lock:
        if token in _used_reset_tokens:
            flash('This reset link has already been used. Please request a new one.', 'error')
            return redirect(url_for('forgot_password'))
    try:
        email = _ts.loads(token, max_age=RESET_TOKEN_HOURS * 3600)
    except SignatureExpired:
        flash('This reset link has expired. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash('This reset link is invalid or has already been used.', 'error')
        return redirect(url_for('login'))

    with get_db() as c:
        user = c.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    if not user:
        flash('Account not found.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        from forms import validate_password_strength
        new_password = request.form.get('password', '')
        confirm      = request.form.get('confirm', '')

        if new_password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token, email=email)

        pw_err = validate_password_strength(new_password)
        if pw_err:
            flash(pw_err, 'error')
            return render_template('reset_password.html', token=token, email=email)

        with get_db() as c:
            c.execute(
                "UPDATE users SET password_hash=? WHERE id=?",
                (generate_password_hash(new_password), user['id'])
            )
        with _token_lock:
            _used_reset_tokens.add(token)
        audit_log('password_reset', f'email={email}')
        flash('Password reset successfully. Please sign in with your new password.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token, email=email)


# ═══════════════════════════════════════════════════════════
# CHAT HISTORY
# ═══════════════════════════════════════════════════════════

@app.route('/chat/history')
def chat_history():
    if require_login(): return redirect(url_for('login'))
    if require_role('admin', 'security', 'staff'):
        flash('Access restricted.', 'error'); return redirect(url_for('chat'))
    with get_db() as c:
        if _using_pg():
            archived = c.execute(
                """SELECT m.*, u.name as sender_name, u.role as sender_role
                   FROM messages m JOIN users u ON m.sender_id=u.id
                   WHERE m.is_deleted=0
                   AND m.timestamp < NOW() - INTERVAL '24 hours'
                   ORDER BY m.timestamp DESC LIMIT 200"""
            ).fetchall()
        else:
            archived = c.execute(
                """SELECT m.*, u.name as sender_name, u.role as sender_role
                   FROM messages m JOIN users u ON m.sender_id=u.id
                   WHERE m.is_deleted=0
                   AND m.timestamp < datetime('now', '-24 hours')
                   ORDER BY m.timestamp DESC LIMIT 200"""
            ).fetchall()
    return render_template('chat_history.html', messages=archived)


# ═══════════════════════════════════════════════════════════
# PAST ALERTS
# ═══════════════════════════════════════════════════════════

@app.route('/past-alerts')
def past_alerts():
    if require_login(): return redirect(url_for('login'))
    if require_role('admin', 'security', 'staff'):
        flash('Access restricted.', 'error'); return redirect(url_for('index'))
    search   = request.args.get('q', '').strip()
    campus_f = request.args.get('campus', '').strip()
    page     = max(1, int(request.args.get('page', 1)))
    per_page = 20
    with get_db() as c:
        conds  = ["a.status IN ('resolved','closed','false_alarm')"]; params = []
        if search:
            conds.append("(a.incident_type LIKE ? OR a.description LIKE ?)")
            params += [f'%{search}%'] * 2
        if campus_f:
            conds.append("a.campus=?"); params.append(campus_f)
        where  = ' AND '.join(conds)
        total  = c.execute(f'SELECT COUNT(*) FROM alerts a WHERE {where}', params).fetchone()[0]
        alerts = c.execute(
            f"""SELECT a.*, u.name as reporter_name FROM alerts a
                JOIN users u ON a.reported_by=u.id
                WHERE {where} ORDER BY a.created_at DESC LIMIT ? OFFSET ?""",
            params + [per_page, (page - 1) * per_page]
        ).fetchall()
    return render_template('past_alerts.html',
        alerts=alerts, search=search, campus_f=campus_f,
        page=page, total_pages=max(1, (total + per_page - 1) // per_page),
        campuses=[campus_item[0] for campus_item in DUT_CAMPUSES if campus_item[0]])


@app.route('/api/attendance')
def api_attendance():
    if require_login() or require_role('admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    today = date.today().isoformat()
    with get_db() as c:
        rows = c.execute(
            """SELECT a.security_id, u.name, a.availability, a.clock_in
               FROM attendance a JOIN users u ON a.security_id=u.id
               WHERE a.is_active=1 AND a.date_str=?
               ORDER BY a.clock_in DESC""",
            (today,)
        ).fetchall()
    return jsonify({'on_campus': [{k: str(v) for k, v in dict(zip(r.keys(), r.values())).items()} for r in rows]})


@app.route('/emergency-response')
def emergency_response():
    if require_login(): return redirect(url_for('login'))
    return render_template('emergency_response.html')


# ═══════════════════════════════════════════════════════════
# SPECIAL REQUEST
# ═══════════════════════════════════════════════════════════

SPECIAL_REQUEST_CATEGORIES = [
    ('', 'Select request type…'),
    ('Safe Escort Request',          'Safe Escort Request'),
    ('Transport Safety Request',     'Transport Safety Request'),
    ('Access Assistance',            'Access Assistance'),
    ('Elevator Locked-In Assistance','Elevator Locked-In Assistance'),
    ('Medical Assistance',           'Medical Assistance'),
    ('Safety Check',                 'Safety Check'),
]


@app.route('/special-request', methods=['GET', 'POST'])
def special_request():
    if require_login(): return redirect(url_for('login'))
    if require_role('student'):
        flash('Special requests are for students only.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        if not _csrf_valid():
            flash('Security token invalid. Please try again.', 'error')
            return redirect(url_for('special_request'))

        req_type    = sanitise(request.form.get('request_type', '').strip())
        campus      = request.form.get('campus', '').strip()
        description = sanitise(request.form.get('description', '').strip())
        building    = sanitise(request.form.get('building', '').strip())
        floor_info  = sanitise(request.form.get('floor_info', '').strip())

        valid_types = [v for v,_ in SPECIAL_REQUEST_CATEGORIES if v]
        if req_type not in valid_types:
            flash('Please select a valid request type.', 'error')
            return redirect(url_for('special_request'))
        if not campus:
            flash('Please select your campus.', 'error')
            return redirect(url_for('special_request'))
        if len(description) < 5:
            flash('Please provide a brief description.', 'error')
            return redirect(url_for('special_request'))
        if req_type == 'Elevator Locked-In Assistance' and not building:
            flash('Please enter the building name for elevator assistance.', 'error')
            return redirect(url_for('special_request'))

        location_parts = [campus]
        if building:
            location_parts.append(f'Building: {building}')
        if floor_info:
            location_parts.append(f'Floor: {floor_info}')
        location_full = ' — '.join(location_parts)

        with get_db() as c:
            c.execute(
                "INSERT INTO alerts "
                "(incident_type, location, campus, block, description, "
                "reported_by, severity, priority, status, record_type) "
                "VALUES (?,?,?,?,?,?,?,?,'open','special_request')",
                (req_type, location_full, campus,
                 building or '', description,
                 session['user_id'], 'medium', 'medium')
            )
            alert = c.execute(
                'SELECT a.*,u.name as reporter_name FROM alerts a '
                'JOIN users u ON a.reported_by=u.id ORDER BY a.id DESC LIMIT 1'
            ).fetchone()

        socketio.emit('receive_alert', {
            'id': alert['id'], 'incident_type': req_type,
            'location': location_full, 'campus': campus,
            'description': description, 'severity': 'medium',
            'priority': 'medium', 'status': 'open',
            'reporter_name': alert['reporter_name'],
            'image_filename': '', 'created_at': str(alert['created_at']),
            'record_type': 'special_request',
        })
        flash('Special request submitted. Security will respond shortly.', 'success')
        return redirect(url_for('dashboard'))

    campuses = [v for v,_ in DUT_CAMPUSES if v]
    return render_template('special_request.html',
        categories=SPECIAL_REQUEST_CATEGORIES,
        campuses=campuses)


if __name__ == '__main__':
    print('📦 Initialising database...')
    init_db()
    print('🚀 ScratchXI — http://localhost:5000')
    debug_mode = os.environ.get('DEBUG', 'true').lower() == 'true'
    socketio.run(app, debug=False, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
