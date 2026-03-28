from flask import Flask, request, jsonify, session, send_file, abort, redirect, send_from_directory
import sqlite3, bcrypt, os, secrets, hashlib, time, threading, shutil, re, json
from werkzeug.utils import secure_filename
from functools import wraps
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

app = Flask(__name__, static_folder='static')
app.secret_key = secrets.token_hex(32)

DB        = 'meshcloud.db'
STORAGE   = 'storage'
TRASH_DIR = 'trash'
MAX_QUOTA_DEFAULT = 500 * 1024 * 1024   # 500MB default

MAX_LOGIN_ATTEMPTS    = 5
MAX_RECOVERY_ATTEMPTS = 5
LOCKOUT_MINUTES       = 15
LOCKOUT_ESCALATION    = 2

BLOCKED_EXTENSIONS = {
    '.exe','.bat','.cmd','.com','.scr','.vbs','.js','.jse',
    '.wsf','.wsh','.msi','.dll','.ps1','.reg','.hta','.jar',
    '.sh','.bash','.zsh','.csh','.rb','.pl','.php','.asp','.elf'
}
MALWARE_SIGS = [b'MZ', b'\x7fELF', b'#!/']

# ── Config ────────────────────────────────────────────────────────────────────

def load_config():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'admin.conf')
    defaults = {
        'ADMIN_USERNAME': 'admin',
        'ADMIN_PASSWORD': 'changeme123',
    }
    if not os.path.exists(path):
        with open(path, 'w') as f:
            for k, v in defaults.items():
                f.write(f'{k}={v}\n')
        print(f'[MeshCloud] Created config at {path}')
    cfg = dict(defaults)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                k, v = line.split('=', 1)
                cfg[k.strip()] = v.strip()
    return cfg

CFG = load_config()
ADMIN_USERNAME = CFG['ADMIN_USERNAME']
ADMIN_PASSWORD = CFG['ADMIN_PASSWORD']

# ── Encryption key per user ───────────────────────────────────────────────────


# ── DB ────────────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def migrate(conn, table, col, sql):
    cols = [r[1] for r in conn.execute(f'PRAGMA table_info({table})').fetchall()]
    if col not in cols:
        try: conn.execute(sql)
        except: pass

def init_db():
    os.makedirs(STORAGE, exist_ok=True)
    os.makedirs(TRASH_DIR, exist_ok=True)
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            username              TEXT UNIQUE NOT NULL,
            password_hash         TEXT NOT NULL,
            display_name          TEXT DEFAULT '',
            security_question     TEXT NOT NULL DEFAULT '',
            security_answer_hash  TEXT NOT NULL DEFAULT '',
            recovery_token        TEXT,
            recovery_token_plain  TEXT,
            recovery_expires      INTEGER,
            recovery_device_ip    TEXT,
            recovery_device_name  TEXT,
            login_attempts        INTEGER DEFAULT 0,
            login_locked_until    INTEGER DEFAULT 0,
            login_lockout_count   INTEGER DEFAULT 0,
            recovery_attempts     INTEGER DEFAULT 0,
            recovery_locked_until INTEGER DEFAULT 0,
            recovery_lockout_count INTEGER DEFAULT 0,
            is_locked             INTEGER DEFAULT 0,
            quota                 INTEGER DEFAULT 524288000,
            storage_used          INTEGER DEFAULT 0,
            bandwidth_up          INTEGER DEFAULT 0,
            bandwidth_down        INTEGER DEFAULT 0,
            created_at            INTEGER DEFAULT (strftime('%s','now'))
        );
        CREATE TABLE IF NOT EXISTS folders (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            name       TEXT NOT NULL,
            parent_id  INTEGER DEFAULT NULL,
            created_at INTEGER DEFAULT (strftime('%s','now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS files (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            folder_id   INTEGER DEFAULT NULL,
            filename    TEXT NOT NULL,
            filepath    TEXT NOT NULL,
            size        INTEGER NOT NULL,
            encrypted   INTEGER DEFAULT 0,
            uploaded_at INTEGER DEFAULT (strftime('%s','now')),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (folder_id) REFERENCES folders(id)
        );
        CREATE TABLE IF NOT EXISTS trash (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            orig_file_id INTEGER,
            filename     TEXT NOT NULL,
            trashpath    TEXT NOT NULL,
            size         INTEGER NOT NULL,
            deleted_at   INTEGER DEFAULT (strftime('%s','now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            user_id     INTEGER NOT NULL,
            expires     INTEGER NOT NULL,
            ip_address  TEXT,
            device_name TEXT,
            last_seen   INTEGER DEFAULT (strftime('%s','now'))
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            type       TEXT NOT NULL,
            message    TEXT NOT NULL,
            read       INTEGER DEFAULT 0,
            created_at INTEGER DEFAULT (strftime('%s','now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS messages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user   INTEGER NOT NULL,
            to_user     INTEGER NOT NULL,
            body        TEXT NOT NULL,
            read        INTEGER DEFAULT 0,
            created_at  INTEGER DEFAULT (strftime('%s','now')),
            FOREIGN KEY (from_user) REFERENCES users(id),
            FOREIGN KEY (to_user)   REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS friends (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            friend_id  INTEGER NOT NULL,
            status     TEXT DEFAULT 'pending',
            created_at INTEGER DEFAULT (strftime('%s','now')),
            UNIQUE(user_id, friend_id)
        );
        CREATE TABLE IF NOT EXISTS file_transfers (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user   INTEGER NOT NULL,
            to_user     INTEGER NOT NULL,
            file_id     INTEGER NOT NULL,
            filename    TEXT NOT NULL,
            size        INTEGER NOT NULL,
            status      TEXT DEFAULT 'pending',
            created_at  INTEGER DEFAULT (strftime('%s','now')),
            resolved_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            username   TEXT,
            ip_address TEXT,
            detail     TEXT,
            success    INTEGER DEFAULT 0,
            created_at INTEGER DEFAULT (strftime('%s','now'))
        );
    ''')
    # Migrations for existing installs
    for col, sql in [
        ('display_name',          "ALTER TABLE users ADD COLUMN display_name TEXT DEFAULT ''"),
        ('quota',                 'ALTER TABLE users ADD COLUMN quota INTEGER DEFAULT 524288000'),
        ('bandwidth_up',          'ALTER TABLE users ADD COLUMN bandwidth_up INTEGER DEFAULT 0'),
        ('bandwidth_down',        'ALTER TABLE users ADD COLUMN bandwidth_down INTEGER DEFAULT 0'),
        ('folder_id',             'ALTER TABLE files ADD COLUMN folder_id INTEGER DEFAULT NULL'),
        ('encrypted',             'ALTER TABLE files ADD COLUMN encrypted INTEGER DEFAULT 0'),
    ]:
        tbl = 'users' if 'quota' in col or 'bandwidth' in col or 'display' in col else 'files'
        migrate(conn, tbl, col, sql)
    migrate(conn, 'sessions', 'ip_address',  'ALTER TABLE sessions ADD COLUMN ip_address TEXT')
    migrate(conn, 'sessions', 'device_name', 'ALTER TABLE sessions ADD COLUMN device_name TEXT')
    migrate(conn, 'sessions', 'last_seen',   'ALTER TABLE sessions ADD COLUMN last_seen INTEGER')
    for col in ['login_attempts','login_locked_until','login_lockout_count',
                'recovery_attempts','recovery_locked_until','recovery_lockout_count',
                'is_locked','security_question','security_answer_hash',
                'recovery_token_plain','recovery_device_ip','recovery_device_name']:
        migrate(conn, 'users', col, f'ALTER TABLE users ADD COLUMN {col} TEXT DEFAULT ""')
    conn.commit()
    conn.close()

def fmt_size(b):
    b = b or 0
    if b < 1024: return f'{b} B'
    if b < 1024**2: return f'{b/1024:.1f} KB'
    if b < 1024**3: return f'{b/1024**2:.1f} MB'
    return f'{b/1024**3:.2f} GB'

# ── Background tasks ──────────────────────────────────────────────────────────

def background_tasks():
    while True:
        time.sleep(3600)
        try:
            conn = get_db()
            now  = int(time.time())
            # Expire recovery tokens
            conn.execute('''UPDATE users SET recovery_token=NULL, recovery_token_plain=NULL,
                recovery_expires=NULL, recovery_device_ip=NULL, recovery_device_name=NULL
                WHERE recovery_expires IS NOT NULL AND recovery_expires < ?''', (now,))
            # Expire sessions
            conn.execute('DELETE FROM sessions WHERE expires < ?', (now,))
            # Auto-empty trash after 30 days
            old_trash = conn.execute(
                'SELECT * FROM trash WHERE deleted_at < ?', (now - 86400*30,)
            ).fetchall()
            for t in old_trash:
                try: os.remove(t['trashpath'])
                except: pass
            conn.execute('DELETE FROM trash WHERE deleted_at < ?', (now - 86400*30,))
            # Trim audit logs > 30 days
            conn.execute('DELETE FROM audit_logs WHERE created_at < ?', (now - 86400*30,))
            conn.commit()
            conn.close()
        except Exception as ex:
            print(f'[cleanup error] {ex}')

threading.Thread(target=background_tasks, daemon=True).start()

# ── Helpers ───────────────────────────────────────────────────────────────────

def get_client_ip():
    return request.headers.get('X-Real-IP') or request.remote_addr or 'unknown'

def get_device_name():
    ua = request.headers.get('User-Agent', '')
    if 'Windows' in ua: return 'Windows'
    if 'iPhone' in ua: return 'iPhone'
    if 'iPad' in ua:   return 'iPad'
    if 'Mac' in ua:    return 'Mac'
    if 'Android' in ua: return 'Android'
    if 'Linux' in ua:  return 'Linux'
    return 'Unknown'

def log_event(etype, username=None, detail=None, success=False):
    try:
        conn = get_db()
        conn.execute('INSERT INTO audit_logs (event_type,username,ip_address,detail,success) VALUES (?,?,?,?,?)',
                     (etype, username, get_client_ip(), detail, 1 if success else 0))
        conn.commit()
        conn.close()
    except: pass

def push_notification(user_id, ntype, message):
    try:
        conn = get_db()
        conn.execute('INSERT INTO notifications (user_id,type,message) VALUES (?,?,?)',
                     (user_id, ntype, message))
        conn.commit()
        conn.close()
    except: pass


def get_current_user():
    token = session.get('token')
    if not token: return None
    conn = get_db()
    now  = int(time.time())
    row  = conn.execute(
        'SELECT u.* FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token=? AND s.expires>?',
        (token, now)
    ).fetchone()
    if row:
        conn.execute('UPDATE sessions SET last_seen=?, ip_address=? WHERE token=?',
                     (now, get_client_ip(), token))
        conn.commit()
    conn.close()
    return row

def user_storage_dir(username):
    path = os.path.join(STORAGE, username)
    os.makedirs(path, exist_ok=True)
    return path

def user_trash_dir(username):
    path = os.path.join(TRASH_DIR, username)
    os.makedirs(path, exist_ok=True)
    return path

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('admin_authed'):
            return jsonify({'error': 'Unauthorized'}), 401
        return fn(*args, **kwargs)
    return wrapper

def calc_lockout(count):
    return min(int(LOCKOUT_MINUTES * (LOCKOUT_ESCALATION ** count)), 480) * 60

def check_file_safety(data, filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext in BLOCKED_EXTENSIONS:
        return False, f'File type {ext} is blocked for security reasons'
    for sig in MALWARE_SIGS:
        if data[:8].startswith(sig):
            return False, 'File appears to be an executable and was blocked'
    return True, 'ok'

def unique_path(directory, filename):
    base, ext = os.path.splitext(filename)
    path = os.path.join(directory, filename)
    i = 1
    while os.path.exists(path):
        filename = f'{base}_{i}{ext}'
        path = os.path.join(directory, filename)
        i += 1
    return path, filename

# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def register():
    d  = request.json or {}
    un = (d.get('username') or '').strip().lower()
    pw = d.get('password') or ''
    if len(un) < 3 or not re.match(r'^[a-z0-9_]+$', un):
        return jsonify({'error': 'Username: 3+ chars, letters/numbers/underscore only'}), 400
    if len(pw) < 6:
        return jsonify({'error': 'Password must be 6+ chars'}), 400
    pw_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO users (username, password_hash) VALUES (?,?)',
            (un, pw_hash))
        conn.commit()
        user_storage_dir(un)
        log_event('REGISTER', un, 'Account created', success=True)
        return jsonify({'ok': True})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already taken'}), 409
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    d   = request.json or {}
    un  = (d.get('username') or '').strip().lower()
    pw  = d.get('password') or ''
    ip  = get_client_ip()
    now = int(time.time())
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username=?', (un,)).fetchone()
    if not user:
        conn.close()
        log_event('LOGIN_FAIL', un, f'Unknown user from {ip}')
        return jsonify({'error': 'Invalid credentials'}), 401
    if user['is_locked']:
        conn.close()
        log_event('LOGIN_BLOCKED', un, 'Admin-locked account')
        return jsonify({'error': 'Account locked. Contact your admin.'}), 403
    locked_until = user['login_locked_until'] or 0
    if locked_until > now:
        mins = int((locked_until - now) / 60) + 1
        conn.close()
        return jsonify({'error': f'Too many failed attempts. Try again in {mins} min.'}), 429
    if not bcrypt.checkpw(pw.encode(), user['password_hash'].encode()):
        attempts = (user['login_attempts'] or 0) + 1
        if attempts >= MAX_LOGIN_ATTEMPTS:
            lcount = (user['login_lockout_count'] or 0) + 1
            lsecs  = calc_lockout(lcount - 1)
            conn.execute('UPDATE users SET login_attempts=0, login_locked_until=?, login_lockout_count=? WHERE id=?',
                         (now + lsecs, lcount, user['id']))
            conn.commit(); conn.close()
            log_event('LOGIN_LOCKOUT', un, f'Locked {lsecs//60}m after {MAX_LOGIN_ATTEMPTS} fails')
            return jsonify({'error': f'Too many attempts. Locked for {lsecs//60} minutes.'}), 429
        conn.execute('UPDATE users SET login_attempts=? WHERE id=?', (attempts, user['id']))
        conn.commit(); conn.close()
        log_event('LOGIN_FAIL', un, f'Wrong password, attempt {attempts}')
        return jsonify({'error': f'Invalid credentials. {MAX_LOGIN_ATTEMPTS - attempts} attempt(s) left.'}), 401
    token  = secrets.token_hex(32)
    exp    = now + 86400 * 7
    device = get_device_name()
    conn.execute('UPDATE users SET login_attempts=0, login_locked_until=0 WHERE id=?', (user['id'],))
    conn.execute('INSERT INTO sessions (token,user_id,expires,ip_address,device_name,last_seen) VALUES (?,?,?,?,?,?)',
                 (token, user['id'], exp, ip, device, now))
    conn.commit(); conn.close()
    session['token'] = token
    # Store password hash in session for encryption key derivation
    log_event('LOGIN_SUCCESS', un, f'{ip} / {device}', success=True)
    return jsonify({'ok': True, 'username': un, 'display_name': user['display_name'] or un})

@app.route('/api/logout', methods=['POST'])
def logout():
    token = session.pop('token', None)
    if token:
        conn = get_db()
        conn.execute('DELETE FROM sessions WHERE token=?', (token,))
        conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/me')
def me():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    unread_notifs = conn.execute(
        'SELECT COUNT(*) FROM notifications WHERE user_id=? AND read=0', (user['id'],)
    ).fetchone()[0]
    unread_msgs = conn.execute(
        'SELECT COUNT(*) FROM messages WHERE to_user=? AND read=0', (user['id'],)
    ).fetchone()[0]
    pending_transfers = conn.execute(
        "SELECT COUNT(*) FROM file_transfers WHERE to_user=? AND status='pending'", (user['id'],)
    ).fetchone()[0]
    conn.close()
    quota = user['quota'] or MAX_QUOTA_DEFAULT
    return jsonify({
        'username':           user['username'],
        'display_name':       user['display_name'] or user['username'],
        'storage_used':       user['storage_used'],
        'quota':              quota,
        'unread_notifs':      unread_notifs,
        'unread_msgs':        unread_msgs,
        'pending_transfers':  pending_transfers,
    })

# ── Account management ────────────────────────────────────────────────────────

@app.route('/api/account/change-password', methods=['POST'])
def change_password():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    d      = request.json or {}
    cur_pw = d.get('current_password') or ''
    new_pw = d.get('new_password') or ''
    if not bcrypt.checkpw(cur_pw.encode(), user['password_hash'].encode()):
        log_event('CHANGE_PW_FAIL', user['username'], 'Wrong current password')
        return jsonify({'error': 'Current password is incorrect'}), 401
    if len(new_pw) < 6:
        return jsonify({'error': 'New password must be 6+ chars'}), 400
    pw_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    conn = get_db()
    conn.execute('UPDATE users SET password_hash=? WHERE id=?', (pw_hash, user['id']))
    conn.commit(); conn.close()
    log_event('CHANGE_PW', user['username'], 'Password changed', success=True)
    return jsonify({'ok': True})

@app.route('/api/account/update-profile', methods=['POST'])
def update_profile():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    d    = request.json or {}
    name = (d.get('display_name') or '').strip()[:50]
    conn = get_db()
    conn.execute('UPDATE users SET display_name=? WHERE id=?', (name, user['id']))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/account/sessions')
def my_sessions():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    now  = int(time.time())
    rows = conn.execute(
        'SELECT token, ip_address, device_name, last_seen, expires FROM sessions WHERE user_id=? AND expires>? ORDER BY last_seen DESC',
        (user['id'], now)
    ).fetchall()
    conn.close()
    current = session.get('token')
    result  = []
    for r in rows:
        last = r['last_seen'] or 0
        result.append({
            'token_prefix': r['token'][:8] + '...',
            'token_id':     r['token'],
            'ip':           r['ip_address'] or 'unknown',
            'device':       r['device_name'] or 'unknown',
            'last_seen':    time.strftime('%b %d %H:%M', time.localtime(last)) if last else 'N/A',
            'is_current':   r['token'] == current,
            'expires':      time.strftime('%b %d', time.localtime(r['expires'])),
        })
    return jsonify(result)

@app.route('/api/account/revoke-session', methods=['POST'])
def revoke_session():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    token_id = (request.json or {}).get('token_id')
    conn = get_db()
    conn.execute('DELETE FROM sessions WHERE token=? AND user_id=?', (token_id, user['id']))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

# ── Password Recovery ─────────────────────────────────────────────────────────

@app.route('/api/get-security-question', methods=['POST'])
def get_security_question():
    # Kept for backward compat but no longer used
    return jsonify({'question': ''}), 404

@app.route('/api/check-username', methods=['POST'])
def check_username():
    d  = request.json or {}
    un = (d.get('username') or '').strip().lower()
    conn = get_db()
    row = conn.execute('SELECT id FROM users WHERE username=?', (un,)).fetchone()
    conn.close()
    if not row: return jsonify({'error': 'User not found'}), 404
    return jsonify({'ok': True})

@app.route('/api/request-recovery', methods=['POST'])
def request_recovery():
    """User submits a recovery request — admin must approve by generating a code."""
    d   = request.json or {}
    un  = (d.get('username') or '').strip().lower()
    ip  = get_client_ip()
    now = int(time.time())
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username=?', (un,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    # Mark pending request (reuse recovery_device_ip/name fields as request metadata)
    # Set a placeholder token so it shows up in admin pending list
    conn.execute('''UPDATE users SET recovery_token='PENDING', recovery_token_plain=NULL,
                    recovery_expires=?, recovery_device_ip=?, recovery_device_name='Awaiting admin approval'
                    WHERE id=?''', (now + 86400, ip, user['id']))
    conn.commit(); conn.close()
    log_event('RECOVERY_REQUEST', un, f'From {ip}', success=True)
    return jsonify({'ok': True})

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    d    = request.json or {}
    un   = (d.get('username') or '').strip().lower()
    code = (d.get('recovery_code') or '').strip().upper()
    npw  = d.get('new_password') or ''
    if len(npw) < 6:
        return jsonify({'error': 'Password must be 6+ chars'}), 400
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username=?', (un,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    if user['recovery_token'] != hashlib.sha256(code.encode()).hexdigest() \
       or (user['recovery_expires'] or 0) < int(time.time()):
        conn.close()
        return jsonify({'error': 'Invalid or expired code'}), 400
    pw_hash = bcrypt.hashpw(npw.encode(), bcrypt.gensalt()).decode()
    conn.execute('''UPDATE users SET password_hash=?, recovery_token=NULL, recovery_token_plain=NULL,
                    recovery_expires=NULL, login_attempts=0, login_locked_until=0 WHERE id=?''',
                 (pw_hash, user['id']))
    conn.commit(); conn.close()
    log_event('RESET_SUCCESS', un, 'Password reset', success=True)
    return jsonify({'ok': True})

# ── Folders ───────────────────────────────────────────────────────────────────

@app.route('/api/folders')
def list_folders():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn    = get_db()
    folders = conn.execute(
        'SELECT * FROM folders WHERE user_id=? ORDER BY name', (user['id'],)
    ).fetchall()
    conn.close()
    return jsonify([dict(f) for f in folders])

@app.route('/api/folders', methods=['POST'])
def create_folder():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    d         = request.json or {}
    name      = (d.get('name') or '').strip()[:80]
    parent_id = d.get('parent_id')
    if not name:
        return jsonify({'error': 'Folder name required'}), 400
    conn = get_db()
    cur  = conn.execute(
        'INSERT INTO folders (user_id, name, parent_id) VALUES (?,?,?)',
        (user['id'], name, parent_id)
    )
    conn.commit()
    fid = cur.lastrowid
    conn.close()
    return jsonify({'ok': True, 'id': fid})

@app.route('/api/folders/<int:folder_id>', methods=['DELETE'])
def delete_folder(folder_id):
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    folder = conn.execute('SELECT * FROM folders WHERE id=? AND user_id=?', (folder_id, user['id'])).fetchone()
    if not folder:
        conn.close()
        return jsonify({'error': 'Folder not found'}), 404
    # Move files inside to root
    conn.execute('UPDATE files SET folder_id=NULL WHERE folder_id=? AND user_id=?', (folder_id, user['id']))
    conn.execute('DELETE FROM folders WHERE id=?', (folder_id,))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/files/<int:file_id>/move', methods=['POST'])
def move_file(file_id):
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    folder_id = (request.json or {}).get('folder_id')
    conn = get_db()
    conn.execute('UPDATE files SET folder_id=? WHERE id=? AND user_id=?',
                 (folder_id, file_id, user['id']))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

# ── Files ─────────────────────────────────────────────────────────────────────

@app.route('/api/files')
def list_files():
    user      = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    folder_id = request.args.get('folder_id')
    query_str = request.args.get('q', '').strip().lower()
    conn = get_db()
    if query_str:
        files = conn.execute(
            'SELECT * FROM files WHERE user_id=? AND LOWER(filename) LIKE ? ORDER BY uploaded_at DESC',
            (user['id'], f'%{query_str}%')
        ).fetchall()
    elif folder_id is not None:
        fid   = int(folder_id) if folder_id else None
        files = conn.execute(
            'SELECT * FROM files WHERE user_id=? AND folder_id IS ? ORDER BY uploaded_at DESC',
            (user['id'], fid)
        ).fetchall()
    else:
        files = conn.execute(
            'SELECT * FROM files WHERE user_id=? ORDER BY uploaded_at DESC', (user['id'],)
        ).fetchall()
    conn.close()
    return jsonify([dict(f) for f in files])

@app.route('/api/upload', methods=['POST'])
def upload():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    f         = request.files['file']
    filename  = secure_filename(f.filename)
    folder_id = request.form.get('folder_id')
    if not filename: return jsonify({'error': 'Invalid filename'}), 400
    file_data = f.read()
    file_size = len(file_data)
    safe, reason = check_file_safety(file_data, filename)
    if not safe:
        log_event('FILE_BLOCKED', user['username'], f'{filename}: {reason}')
        return jsonify({'error': reason}), 400
    quota = user['quota'] or MAX_QUOTA_DEFAULT
    conn  = get_db()
    u     = conn.execute('SELECT storage_used FROM users WHERE id=?', (user['id'],)).fetchone()
    if u['storage_used'] + file_size > quota:
        conn.close()
        return jsonify({'error': 'Storage quota exceeded'}), 413
    storage_dir     = user_storage_dir(user['username'])
    save_path, filename = unique_path(storage_dir, filename)
    with open(save_path, 'wb') as out:
        out.write(file_data)
    conn.execute('INSERT INTO files (user_id, folder_id, filename, filepath, size) VALUES (?,?,?,?,?)',
                 (user['id'], folder_id or None, filename, save_path, file_size))
    conn.execute('UPDATE users SET storage_used=storage_used+?, bandwidth_up=bandwidth_up+? WHERE id=?',
                 (file_size, file_size, user['id']))
    conn.commit(); conn.close()
    log_event('FILE_UPLOAD', user['username'], f'{filename} ({fmt_size(file_size)})', success=True)
    return jsonify({'ok': True, 'filename': filename, 'size': file_size})

@app.route('/api/download/<int:file_id>')
def download(file_id):
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    f    = conn.execute('SELECT * FROM files WHERE id=? AND user_id=?', (file_id, user['id'])).fetchone()
    if not f:
        conn.close()
        abort(404)
    file_size = f['size']
    conn.execute('UPDATE users SET bandwidth_down=bandwidth_down+? WHERE id=?', (file_size, user['id']))
    conn.commit(); conn.close()
    return send_file(f['filepath'], as_attachment=True, download_name=f['filename'])

@app.route('/api/delete', methods=['POST'])
def delete_files():
    """Bulk delete - moves to trash"""
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    ids  = (request.json or {}).get('ids', [])
    if not ids: return jsonify({'error': 'No file IDs provided'}), 400
    conn = get_db()
    moved = 0
    for file_id in ids:
        f = conn.execute('SELECT * FROM files WHERE id=? AND user_id=?', (file_id, user['id'])).fetchone()
        if not f: continue
        trash_dir  = user_trash_dir(user['username'])
        trash_path, _ = unique_path(trash_dir, f['filename'])
        try:
            shutil.move(f['filepath'], trash_path)
        except:
            continue
        conn.execute('INSERT INTO trash (user_id, orig_file_id, filename, trashpath, size) VALUES (?,?,?,?,?)',
                     (user['id'], f['id'], f['filename'], trash_path, f['size']))
        conn.execute('UPDATE users SET storage_used=MAX(0,storage_used-?) WHERE id=?', (f['size'], user['id']))
        conn.execute('DELETE FROM files WHERE id=?', (f['id'],))
        moved += 1
    conn.commit(); conn.close()
    return jsonify({'ok': True, 'moved': moved})

@app.route('/api/delete/<int:file_id>', methods=['DELETE'])
def delete_file_single(file_id):
    """Single file delete - keeps backward compat"""
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    f    = conn.execute('SELECT * FROM files WHERE id=? AND user_id=?', (file_id, user['id'])).fetchone()
    if not f:
        conn.close()
        abort(404)
    trash_dir  = user_trash_dir(user['username'])
    trash_path, _ = unique_path(trash_dir, f['filename'])
    try:
        shutil.move(f['filepath'], trash_path)
        conn.execute('INSERT INTO trash (user_id, orig_file_id, filename, trashpath, size) VALUES (?,?,?,?,?)',
                     (user['id'], f['id'], f['filename'], trash_path, f['size']))
    except:
        pass
    conn.execute('UPDATE users SET storage_used=MAX(0,storage_used-?) WHERE id=?', (f['size'], user['id']))
    conn.execute('DELETE FROM files WHERE id=?', (file_id,))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

# ── Trash ─────────────────────────────────────────────────────────────────────

@app.route('/api/trash')
def list_trash():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn  = get_db()
    items = conn.execute(
        'SELECT * FROM trash WHERE user_id=? ORDER BY deleted_at DESC', (user['id'],)
    ).fetchall()
    conn.close()
    now = int(time.time())
    return jsonify([{**dict(i),
        'days_left': max(0, 30 - int((now - i['deleted_at']) / 86400)),
        'deleted_fmt': time.strftime('%b %d', time.localtime(i['deleted_at']))
    } for i in items])

@app.route('/api/trash/restore/<int:trash_id>', methods=['POST'])
def restore_trash(trash_id):
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    item = conn.execute('SELECT * FROM trash WHERE id=? AND user_id=?', (trash_id, user['id'])).fetchone()
    if not item:
        conn.close()
        return jsonify({'error': 'Not found'}), 404
    storage_dir = user_storage_dir(user['username'])
    restore_path, filename = unique_path(storage_dir, item['filename'])
    try:
        shutil.move(item['trashpath'], restore_path)
    except Exception as e:
        conn.close()
        return jsonify({'error': f'Could not restore: {e}'}), 500
    conn.execute('INSERT INTO files (user_id, filename, filepath, size) VALUES (?,?,?,?)',
                 (user['id'], filename, restore_path, item['size']))
    conn.execute('UPDATE users SET storage_used=storage_used+? WHERE id=?', (item['size'], user['id']))
    conn.execute('DELETE FROM trash WHERE id=?', (trash_id,))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/trash/<int:trash_id>', methods=['DELETE'])
def delete_from_trash(trash_id):
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    item = conn.execute('SELECT * FROM trash WHERE id=? AND user_id=?', (trash_id, user['id'])).fetchone()
    if not item:
        conn.close()
        return jsonify({'error': 'Not found'}), 404
    try: os.remove(item['trashpath'])
    except: pass
    conn.execute('DELETE FROM trash WHERE id=?', (trash_id,))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/trash/empty', methods=['POST'])
def empty_trash():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn  = get_db()
    items = conn.execute('SELECT * FROM trash WHERE user_id=?', (user['id'],)).fetchall()
    for item in items:
        try: os.remove(item['trashpath'])
        except: pass
    conn.execute('DELETE FROM trash WHERE user_id=?', (user['id'],))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

# ── Notifications ─────────────────────────────────────────────────────────────

@app.route('/api/notifications')
def get_notifications():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50',
        (user['id'],)
    ).fetchall()
    conn.close()
    return jsonify([{**dict(r),
        'time_fmt': time.strftime('%b %d %H:%M', time.localtime(r['created_at']))
    } for r in rows])

@app.route('/api/notifications/read', methods=['POST'])
def mark_notifications_read():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    conn.execute('UPDATE notifications SET read=1 WHERE user_id=?', (user['id'],))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

# ── Messages ──────────────────────────────────────────────────────────────────

@app.route('/api/messages/<friend_username>')
def get_messages(friend_username):
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn   = get_db()
    friend = conn.execute('SELECT id FROM users WHERE username=?', (friend_username,)).fetchone()
    if not friend:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    rows = conn.execute('''
        SELECT m.*, u.username as from_username FROM messages m
        JOIN users u ON m.from_user=u.id
        WHERE (m.from_user=? AND m.to_user=?) OR (m.from_user=? AND m.to_user=?)
        ORDER BY m.created_at ASC LIMIT 200
    ''', (user['id'], friend['id'], friend['id'], user['id'])).fetchall()
    # Mark as read
    conn.execute('UPDATE messages SET read=1 WHERE to_user=? AND from_user=?',
                 (user['id'], friend['id']))
    conn.commit(); conn.close()
    return jsonify([{**dict(r),
        'time_fmt': time.strftime('%H:%M', time.localtime(r['created_at'])),
        'mine': r['from_user'] == user['id']
    } for r in rows])

@app.route('/api/messages/send', methods=['POST'])
def send_message():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    d    = request.json or {}
    to   = (d.get('to_username') or '').strip().lower()
    body = (d.get('body') or '').strip()[:2000]
    if not body: return jsonify({'error': 'Empty message'}), 400
    conn   = get_db()
    target = conn.execute('SELECT id FROM users WHERE username=?', (to,)).fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    # Must be friends
    fship = conn.execute('''SELECT id FROM friends WHERE status='accepted' AND
        ((user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?))''',
        (user['id'], target['id'], target['id'], user['id'])).fetchone()
    if not fship:
        conn.close()
        return jsonify({'error': 'Can only message friends'}), 403
    conn.execute('INSERT INTO messages (from_user, to_user, body) VALUES (?,?,?)',
                 (user['id'], target['id'], body))
    push_notification(target['id'], 'message', f'New message from {user["username"]}')
    conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/messages/conversations')
def conversations():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    rows = conn.execute('''
        SELECT u.id, u.username, u.display_name,
               (SELECT body FROM messages WHERE (from_user=u.id AND to_user=?) OR (from_user=? AND to_user=u.id)
                ORDER BY created_at DESC LIMIT 1) as last_msg,
               (SELECT COUNT(*) FROM messages WHERE from_user=u.id AND to_user=? AND read=0) as unread
        FROM users u
        WHERE u.id IN (
            SELECT CASE WHEN user_id=? THEN friend_id ELSE user_id END
            FROM friends WHERE (user_id=? OR friend_id=?) AND status='accepted'
        )
        ORDER BY (SELECT created_at FROM messages
                  WHERE (from_user=u.id AND to_user=?) OR (from_user=? AND to_user=u.id)
                  ORDER BY created_at DESC LIMIT 1) DESC NULLS LAST
    ''', (user['id'], user['id'], user['id'],
          user['id'], user['id'], user['id'],
          user['id'], user['id'])).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ── Friends ───────────────────────────────────────────────────────────────────

@app.route('/api/friends')
def get_friends():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    friends = conn.execute('''
        SELECT u.id, u.username, u.display_name FROM friends f
        JOIN users u ON (CASE WHEN f.user_id=? THEN f.friend_id ELSE f.user_id END)=u.id
        WHERE (f.user_id=? OR f.friend_id=?) AND f.status='accepted' AND u.id!=?
    ''', (user['id'], user['id'], user['id'], user['id'])).fetchall()
    pending_in = conn.execute('''
        SELECT f.id as invite_id, u.username FROM friends f
        JOIN users u ON f.user_id=u.id WHERE f.friend_id=? AND f.status='pending'
    ''', (user['id'],)).fetchall()
    pending_out = conn.execute('''
        SELECT f.id as invite_id, u.username FROM friends f
        JOIN users u ON f.friend_id=u.id WHERE f.user_id=? AND f.status='pending'
    ''', (user['id'],)).fetchall()
    conn.close()
    return jsonify({'friends': [dict(r) for r in friends],
                    'pending_in': [dict(r) for r in pending_in],
                    'pending_out': [dict(r) for r in pending_out]})

@app.route('/api/friends/invite', methods=['POST'])
def invite_friend():
    user   = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    target_un = (request.json or {}).get('username', '').strip().lower()
    conn   = get_db()
    target = conn.execute('SELECT id FROM users WHERE username=?', (target_un,)).fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    if target['id'] == user['id']:
        conn.close()
        return jsonify({'error': 'Cannot add yourself'}), 400
    existing = conn.execute('''SELECT id FROM friends WHERE
        (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)''',
        (user['id'], target['id'], target['id'], user['id'])).fetchone()
    if existing:
        conn.close()
        return jsonify({'error': 'Already friends or invite pending'}), 409
    conn.execute('INSERT INTO friends (user_id, friend_id) VALUES (?,?)', (user['id'], target['id']))
    push_notification(target['id'], 'friend_request', f'{user["username"]} sent you a friend request')
    conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/friends/accept/<int:invite_id>', methods=['POST'])
def accept_friend(invite_id):
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    f    = conn.execute('SELECT * FROM friends WHERE id=? AND friend_id=?', (invite_id, user['id'])).fetchone()
    if not f:
        conn.close()
        return jsonify({'error': 'Not found'}), 404
    conn.execute("UPDATE friends SET status='accepted' WHERE id=?", (invite_id,))
    # Notify sender
    sender = conn.execute('SELECT username FROM users WHERE id=?', (f['user_id'],)).fetchone()
    push_notification(f['user_id'], 'friend_accepted', f'{user["username"]} accepted your friend request')
    conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/friends/decline/<int:invite_id>', methods=['POST'])
def decline_friend(invite_id):
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    conn.execute('DELETE FROM friends WHERE id=? AND friend_id=?', (invite_id, user['id']))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/friends/remove/<int:friend_id>', methods=['DELETE'])
def remove_friend(friend_id):
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    conn.execute('''DELETE FROM friends WHERE
        (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)''',
        (user['id'], friend_id, friend_id, user['id']))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

# ── File Transfers ────────────────────────────────────────────────────────────

@app.route('/api/transfers')
def get_transfers():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    incoming = conn.execute('''
        SELECT t.*, u.username as from_username FROM file_transfers t
        JOIN users u ON t.from_user=u.id WHERE t.to_user=? AND t.status='pending'
        ORDER BY t.created_at DESC''', (user['id'],)).fetchall()
    outgoing = conn.execute('''
        SELECT t.*, u.username as to_username FROM file_transfers t
        JOIN users u ON t.to_user=u.id WHERE t.from_user=? AND t.status='pending'
        ORDER BY t.created_at DESC''', (user['id'],)).fetchall()
    conn.close()
    return jsonify({'incoming': [dict(r) for r in incoming],
                    'outgoing': [dict(r) for r in outgoing]})

@app.route('/api/transfers/send', methods=['POST'])
def send_file_transfer():
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    d    = request.json or {}
    fid  = d.get('file_id')
    to   = (d.get('to_username') or '').strip().lower()
    conn = get_db()
    target = conn.execute('SELECT id FROM users WHERE username=?', (to,)).fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    fship = conn.execute('''SELECT id FROM friends WHERE status='accepted' AND
        ((user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?))''',
        (user['id'], target['id'], target['id'], user['id'])).fetchone()
    if not fship:
        conn.close()
        return jsonify({'error': 'Can only send files to friends'}), 403
    f = conn.execute('SELECT * FROM files WHERE id=? AND user_id=?', (fid, user['id'])).fetchone()
    if not f:
        conn.close()
        return jsonify({'error': 'File not found'}), 404
    conn.execute('INSERT INTO file_transfers (from_user,to_user,file_id,filename,size) VALUES (?,?,?,?,?)',
                 (user['id'], target['id'], fid, f['filename'], f['size']))
    push_notification(target['id'], 'file_transfer', f'{user["username"]} sent you a file: {f["filename"]}')
    conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/transfers/accept/<int:tid>', methods=['POST'])
def accept_transfer(tid):
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    t    = conn.execute('SELECT * FROM file_transfers WHERE id=? AND to_user=? AND status=?',
                        (tid, user['id'], 'pending')).fetchone()
    if not t:
        conn.close()
        return jsonify({'error': 'Transfer not found'}), 404
    src = conn.execute('SELECT * FROM files WHERE id=?', (t['file_id'],)).fetchone()
    if not src or not os.path.exists(src['filepath']):
        conn.close()
        return jsonify({'error': 'Source file no longer exists'}), 404
    quota = user['quota'] or MAX_QUOTA_DEFAULT
    u     = conn.execute('SELECT storage_used FROM users WHERE id=?', (user['id'],)).fetchone()
    if u['storage_used'] + t['size'] > quota:
        conn.close()
        return jsonify({'error': 'Not enough storage quota'}), 413
    storage_dir = user_storage_dir(user['username'])
    save_path, filename = unique_path(storage_dir, t['filename'])
    shutil.copy2(src['filepath'], save_path)
    fsize = os.path.getsize(save_path)
    conn.execute('INSERT INTO files (user_id, filename, filepath, size) VALUES (?,?,?,?)',
                 (user['id'], filename, save_path, fsize))
    conn.execute('UPDATE users SET storage_used=storage_used+? WHERE id=?', (fsize, user['id']))
    conn.execute("UPDATE file_transfers SET status='accepted', resolved_at=? WHERE id=?",
                 (int(time.time()), tid))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/transfers/decline/<int:tid>', methods=['POST'])
def decline_transfer(tid):
    user = get_current_user()
    if not user: return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    conn.execute("UPDATE file_transfers SET status='declined', resolved_at=? WHERE id=? AND to_user=?",
                 (int(time.time()), tid, user['id']))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

# ── Admin API ─────────────────────────────────────────────────────────────────

@app.route('/admin/api/login', methods=['POST'])
def admin_login():
    d = request.json or {}
    if d.get('username') == ADMIN_USERNAME and d.get('password') == ADMIN_PASSWORD:
        session['admin_authed'] = True
        log_event('ADMIN_LOGIN', ADMIN_USERNAME, get_client_ip(), success=True)
        return jsonify({'ok': True})
    log_event('ADMIN_LOGIN_FAIL', d.get('username'), f'Failed from {get_client_ip()}')
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_authed', None)
    return redirect('/admin')

@app.route('/api/admin/stats')
@admin_required
def admin_stats():
    conn = get_db()
    now  = int(time.time())
    user_count    = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    file_count    = conn.execute('SELECT COUNT(*) FROM files').fetchone()[0]
    pending_count = conn.execute(
        'SELECT COUNT(*) FROM users WHERE recovery_token IS NOT NULL AND recovery_expires > ?', (now,)
    ).fetchone()[0]
    total_storage = conn.execute('SELECT COALESCE(SUM(storage_used),0) FROM users').fetchone()[0]
    # Recovery
    recovery_rows = conn.execute('''
        SELECT id, username, recovery_token, recovery_token_plain, recovery_expires, recovery_device_ip, recovery_device_name
        FROM users WHERE recovery_token IS NOT NULL ORDER BY recovery_expires
    ''').fetchall()
    recovery = []
    for r in recovery_rows:
        exp     = (r['recovery_expires'] or 0) < now
        pending = r['recovery_token_plain'] is None or r['recovery_token'] == 'PENDING'
        recovery.append({
            'id': r['id'], 'username': r['username'],
            'code': r['recovery_token_plain'] or '(unavailable)',
            'expires_str': time.strftime('%H:%M', time.localtime(r['recovery_expires'])) if r['recovery_expires'] else 'N/A',
            'mins_left': max(0, int(((r['recovery_expires'] or 0) - now) / 60)),
            'expired': exp,
            'pending': pending,
            'device_ip': r['recovery_device_ip'] or 'unknown',
            'device_name': r['recovery_device_name'] or 'unknown',
        })
    # Users
    users_raw = conn.execute('''
        SELECT u.id, u.username, u.display_name, u.storage_used, u.quota,
               u.bandwidth_up, u.bandwidth_down, u.created_at,
               u.is_locked, u.login_attempts, u.login_locked_until,
               u.recovery_locked_until, u.recovery_attempts,
               COUNT(f.id) as file_count
        FROM users u LEFT JOIN files f ON f.user_id=u.id
        GROUP BY u.id ORDER BY u.created_at DESC
    ''').fetchall()
    users = [{
        'id': u['id'], 'username': u['username'],
        'display_name': u['display_name'] or '',
        'storage': fmt_size(u['storage_used']),
        'quota': fmt_size(u['quota'] or MAX_QUOTA_DEFAULT),
        'quota_raw': u['quota'] or MAX_QUOTA_DEFAULT,
        'pct': round(min(100, (u['storage_used'] or 0) / (u['quota'] or MAX_QUOTA_DEFAULT) * 100), 1),
        'bandwidth_up': fmt_size(u['bandwidth_up'] or 0),
        'bandwidth_down': fmt_size(u['bandwidth_down'] or 0),
        'files': u['file_count'],
        'joined': time.strftime('%b %d %Y', time.localtime(u['created_at'])),
        'is_locked': bool(u['is_locked']),
        'login_locked': (u['login_locked_until'] or 0) > now,
        'recovery_locked': (u['recovery_locked_until'] or 0) > now,
        'attempts': u['login_attempts'] or 0,
        'recovery_attempts': u['recovery_attempts'] or 0,
    } for u in users_raw]
    # Sessions
    sess_rows = conn.execute('''
        SELECT s.ip_address, s.device_name, s.last_seen, s.expires, u.username
        FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.expires > ? ORDER BY s.last_seen DESC
    ''', (now,)).fetchall()
    sessions = [{
        'username': s['username'], 'ip_address': s['ip_address'] or 'unknown',
        'device_name': s['device_name'] or 'unknown',
        'last_seen': time.strftime('%H:%M:%S', time.localtime(s['last_seen'])) if s['last_seen'] else 'N/A',
        'mins_ago': int((now - (s['last_seen'] or 0)) / 60),
        'online': int((now - (s['last_seen'] or 0)) / 60) < 15,
        'expires': time.strftime('%b %d %H:%M', time.localtime(s['expires'])),
    } for s in sess_rows]
    # Logs
    log_rows = conn.execute(
        'SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100'
    ).fetchall()
    logs = [{
        'type': r['event_type'], 'user': r['username'] or '—',
        'ip': r['ip_address'] or '—', 'detail': r['detail'] or '',
        'success': bool(r['success']),
        'time': time.strftime('%b %d %H:%M:%S', time.localtime(r['created_at'])),
    } for r in log_rows]
    # Health
    health = {'available': HAS_PSUTIL}
    if HAS_PSUTIL:
        du = psutil.disk_usage(os.path.abspath(STORAGE))
        health.update({
            'cpu_pct':    psutil.cpu_percent(interval=0.5),
            'ram_pct':    psutil.virtual_memory().percent,
            'ram_used':   fmt_size(psutil.virtual_memory().used),
            'ram_total':  fmt_size(psutil.virtual_memory().total),
            'disk_free':  fmt_size(du.free),
            'disk_total': fmt_size(du.total),
            'disk_pct':   round(du.percent, 1),
        })
    conn.close()
    return jsonify({'stats': {'users': user_count, 'files': file_count,
                               'pending': pending_count, 'total_storage': fmt_size(total_storage)},
                    'recovery': recovery, 'users': users, 'sessions': sessions,
                    'logs': logs, 'health': health})

@app.route('/api/admin/set-quota/<int:user_id>', methods=['POST'])
@admin_required
def admin_set_quota(user_id):
    mb = (request.json or {}).get('quota_mb', 500)
    conn = get_db()
    conn.execute('UPDATE users SET quota=? WHERE id=?', (int(mb) * 1024 * 1024, user_id))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/admin/generate-recovery/<int:user_id>', methods=['POST'])
@admin_required
def admin_generate_recovery(user_id):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    token      = secrets.token_hex(16).upper()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn.execute('''UPDATE users SET recovery_token=?, recovery_token_plain=?,
                    recovery_expires=?, recovery_device_ip=?, recovery_device_name=?
                    WHERE id=?''', (token_hash, token, int(time.time())+3600,
                                    'Admin generated', 'Admin Panel', user_id))
    conn.commit(); conn.close()
    return jsonify({'ok': True, 'code': token})

@app.route('/api/admin/delete-user/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    for d in [os.path.join(STORAGE, user['username']), os.path.join(TRASH_DIR, user['username'])]:
        if os.path.exists(d): shutil.rmtree(d)
    for tbl in ['files','sessions','friends','file_transfers','notifications','messages','trash']:
        col = 'user_id' if tbl not in ('friends','file_transfers','messages') else None
        if tbl == 'friends':
            conn.execute('DELETE FROM friends WHERE user_id=? OR friend_id=?', (user_id, user_id))
        elif tbl == 'file_transfers':
            conn.execute('DELETE FROM file_transfers WHERE from_user=? OR to_user=?', (user_id, user_id))
        elif tbl == 'messages':
            conn.execute('DELETE FROM messages WHERE from_user=? OR to_user=?', (user_id, user_id))
        else:
            conn.execute(f'DELETE FROM {tbl} WHERE user_id=?', (user_id,))
    conn.execute('DELETE FROM users WHERE id=?', (user_id,))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/admin/toggle-lock/<int:user_id>', methods=['POST'])
@admin_required
def admin_toggle_lock(user_id):
    conn = get_db()
    user = conn.execute('SELECT id, username, is_locked FROM users WHERE id=?', (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'Not found'}), 404
    new = 0 if user['is_locked'] else 1
    conn.execute('UPDATE users SET is_locked=? WHERE id=?', (new, user_id))
    conn.commit(); conn.close()
    log_event('ADMIN_LOCK', user['username'], 'locked' if new else 'unlocked', success=True)
    return jsonify({'ok': True, 'locked': bool(new)})

@app.route('/api/admin/unlock-attempts/<int:user_id>', methods=['POST'])
@admin_required
def admin_unlock_attempts(user_id):
    conn = get_db()
    conn.execute('''UPDATE users SET login_attempts=0, login_locked_until=0,
                    recovery_attempts=0, recovery_locked_until=0 WHERE id=?''', (user_id,))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/admin/dismiss-recovery/<int:user_id>', methods=['POST'])
@admin_required
def admin_dismiss_recovery(user_id):
    conn = get_db()
    conn.execute('''UPDATE users SET recovery_token=NULL, recovery_token_plain=NULL,
                    recovery_expires=NULL, recovery_device_ip=NULL, recovery_device_name=NULL
                    WHERE id=?''', (user_id,))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

# ── Serve pages ───────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/admin')
def admin_panel():
    return send_from_directory('static', 'admin.html')

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
