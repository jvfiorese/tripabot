# -*- coding: utf-8 -*-
"""
TripaBot License Server — Banco de Dados
Usa PostgreSQL se DATABASE_URL estiver definida (Railway),
senão usa SQLite local (desenvolvimento).
"""

import os
import sqlite3
from datetime import datetime, timezone

# ── Detecta modo ──────────────────────────────────────────────
_DB_URL = os.environ.get('DATABASE_URL', '')
if _DB_URL.startswith('postgres://'):
    _DB_URL = _DB_URL.replace('postgres://', 'postgresql://', 1)
USE_PG = bool(_DB_URL)

if USE_PG:
    import psycopg2
    import psycopg2.extras
    print(f"[DB] PostgreSQL (Railway) ✓")
else:
    _SQLITE_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'tripabot.db'))
    print(f"[DB] SQLite: {_SQLITE_PATH}")


# ── Conexão ───────────────────────────────────────────────────

def _conn():
    if USE_PG:
        c = psycopg2.connect(_DB_URL)
        c.autocommit = False
        return c
    else:
        c = sqlite3.connect(_SQLITE_PATH, timeout=10)
        c.row_factory = sqlite3.Row
        return c


def _q(sql):
    """Troca ? por %s para PostgreSQL."""
    return sql.replace('?', '%s') if USE_PG else sql


def _one(cur):
    row = cur.fetchone()
    if row is None:
        return None
    return dict(row) if USE_PG else dict(row)


def _all(cur):
    rows = cur.fetchall()
    return [dict(r) for r in rows]


def _run(conn, sql, params=()):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) if USE_PG else conn.cursor()
    cur.execute(_q(sql), params)
    return cur


def _now():
    return datetime.now(timezone.utc).isoformat()


# ── Init ──────────────────────────────────────────────────────

def init_db():
    conn = _conn()
    cur = conn.cursor()

    if USE_PG:
        statements = [
            """CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name TEXT,
                status TEXT DEFAULT 'trial',
                created_at TEXT NOT NULL,
                trial_expires TEXT,
                paid_expires TEXT,
                last_verified TEXT,
                payment_notes TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS licenses (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                plan TEXT NOT NULL,
                lic_content TEXT NOT NULL,
                is_revoked INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS payments (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                method TEXT DEFAULT 'pix',
                status TEXT DEFAULT 'pending',
                notes TEXT,
                created_at TEXT NOT NULL,
                approved_at TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS admin_tokens (
                token TEXT PRIMARY KEY,
                expires_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS download_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                lic_content TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS login_attempts (
                id SERIAL PRIMARY KEY,
                ip TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS device_sessions (
                id SERIAL PRIMARY KEY,
                email TEXT NOT NULL,
                ip TEXT NOT NULL,
                user_agent TEXT,
                timestamp TEXT NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
            "CREATE INDEX IF NOT EXISTS idx_lic_uid ON licenses(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_lic_email ON licenses(email)",
            "CREATE INDEX IF NOT EXISTS idx_pay_uid ON payments(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_pay_status ON payments(status)",
            "CREATE INDEX IF NOT EXISTS idx_attempts_ip ON login_attempts(ip)",
            "CREATE INDEX IF NOT EXISTS idx_device_sessions_email ON device_sessions(email)",
            "CREATE INDEX IF NOT EXISTS idx_device_sessions_timestamp ON device_sessions(timestamp)",
        ]
        for stmt in statements:
            cur.execute(stmt)
    else:
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name TEXT,
                status TEXT DEFAULT 'trial',
                created_at TEXT NOT NULL,
                trial_expires TEXT,
                paid_expires TEXT,
                last_verified TEXT,
                payment_notes TEXT
            );
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                plan TEXT NOT NULL,
                lic_content TEXT NOT NULL,
                is_revoked INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                method TEXT DEFAULT 'pix',
                status TEXT DEFAULT 'pending',
                notes TEXT,
                created_at TEXT NOT NULL,
                approved_at TEXT
            );
            CREATE TABLE IF NOT EXISTS admin_tokens (
                token TEXT PRIMARY KEY,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS download_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                lic_content TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS device_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                ip TEXT NOT NULL,
                user_agent TEXT,
                timestamp TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_lic_uid ON licenses(user_id);
            CREATE INDEX IF NOT EXISTS idx_lic_email ON licenses(email);
            CREATE INDEX IF NOT EXISTS idx_pay_uid ON payments(user_id);
            CREATE INDEX IF NOT EXISTS idx_pay_status ON payments(status);
            CREATE INDEX IF NOT EXISTS idx_attempts_ip ON login_attempts(ip);
            CREATE INDEX IF NOT EXISTS idx_device_sessions_email ON device_sessions(email);
            CREATE INDEX IF NOT EXISTS idx_device_sessions_timestamp ON device_sessions(timestamp);
        """)

    conn.commit()
    conn.close()
    print("[DB] Tabelas inicializadas ✓")


# ── Usuários ──────────────────────────────────────────────────

def create_user(email, password_hash, name=None):
    email = email.lower().strip()
    conn = _conn()
    try:
        cur = _run(conn, """
            INSERT INTO users (email, password_hash, name, created_at)
            VALUES (?, ?, ?, ?)
        """, (email, password_hash, name, _now()))
        conn.commit()
        cur2 = _run(conn, "SELECT * FROM users WHERE email = ?", (email,))
        return _one(cur2)
    except Exception:
        conn.rollback()
        return None
    finally:
        conn.close()


def get_user_by_email(email):
    conn = _conn()
    try:
        cur = _run(conn, "SELECT * FROM users WHERE email = ?", (email.lower().strip(),))
        return _one(cur)
    finally:
        conn.close()


def get_user_by_id(user_id):
    conn = _conn()
    try:
        cur = _run(conn, "SELECT * FROM users WHERE id = ?", (user_id,))
        return _one(cur)
    finally:
        conn.close()


def get_all_users():
    conn = _conn()
    try:
        cur = _run(conn, """
            SELECT u.*,
                   COUNT(p.id) as total_payments,
                   SUM(CASE WHEN p.status = 'pending' THEN 1 ELSE 0 END) as pending_payments
            FROM users u
            LEFT JOIN payments p ON p.user_id = u.id
            GROUP BY u.id
            ORDER BY u.created_at DESC
        """)
        return _all(cur)
    finally:
        conn.close()


def update_user_status(user_id, status, paid_expires=None):
    conn = _conn()
    try:
        if paid_expires:
            _run(conn, "UPDATE users SET status=?, paid_expires=? WHERE id=?", (status, paid_expires, user_id))
        else:
            _run(conn, "UPDATE users SET status=? WHERE id=?", (status, user_id))
        conn.commit()
    finally:
        conn.close()


def update_user_trial(user_id, trial_expires):
    conn = _conn()
    try:
        _run(conn, "UPDATE users SET status='trial', trial_expires=? WHERE id=?", (trial_expires, user_id))
        conn.commit()
    finally:
        conn.close()


def update_last_verified(user_id):
    conn = _conn()
    try:
        _run(conn, "UPDATE users SET last_verified=? WHERE id=?", (_now(), user_id))
        conn.commit()
    finally:
        conn.close()


# ── Licenças ──────────────────────────────────────────────────

def save_license(user_id, email, issued_at, expires_at, plan, lic_content):
    conn = _conn()
    try:
        _run(conn, """
            INSERT INTO licenses (user_id, email, issued_at, expires_at, plan, lic_content, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, email, issued_at, expires_at, plan, lic_content, _now()))
        conn.commit()
    finally:
        conn.close()


def get_latest_license(user_id):
    conn = _conn()
    try:
        cur = _run(conn, """
            SELECT * FROM licenses WHERE user_id=? AND is_revoked=0
            ORDER BY created_at DESC LIMIT 1
        """, (user_id,))
        return _one(cur)
    finally:
        conn.close()


def revoke_all_licenses(user_id):
    conn = _conn()
    try:
        _run(conn, "UPDATE licenses SET is_revoked=1 WHERE user_id=?", (user_id,))
        conn.commit()
    finally:
        conn.close()


def is_license_revoked(email, issued_at):
    conn = _conn()
    try:
        cur = _run(conn, "SELECT is_revoked FROM licenses WHERE email=? AND issued_at=?", (email, issued_at))
        row = _one(cur)
        if not row:
            return True
        return bool(row.get('is_revoked', 0))
    finally:
        conn.close()


# ── Pagamentos ────────────────────────────────────────────────

def create_payment(user_id, amount=20.0, notes=''):
    conn = _conn()
    try:
        if USE_PG:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(_q("INSERT INTO payments (user_id, amount, notes, created_at) VALUES (?, ?, ?, ?) RETURNING id"),
                        (user_id, amount, notes, _now()))
            payment_id = cur.fetchone()['id']
        else:
            cur = _run(conn, "INSERT INTO payments (user_id, amount, notes, created_at) VALUES (?, ?, ?, ?)",
                       (user_id, amount, notes, _now()))
            payment_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit()
        return payment_id
    finally:
        conn.close()


def get_pending_payments():
    conn = _conn()
    try:
        cur = _run(conn, """
            SELECT p.*, u.email, u.name, u.status
            FROM payments p JOIN users u ON u.id = p.user_id
            WHERE p.status = 'pending'
            ORDER BY p.created_at DESC
        """)
        return _all(cur)
    finally:
        conn.close()


def approve_payment(payment_id):
    conn = _conn()
    try:
        _run(conn, "UPDATE payments SET status='approved', approved_at=? WHERE id=?", (_now(), payment_id))
        conn.commit()
    finally:
        conn.close()


def reject_payment(payment_id):
    conn = _conn()
    try:
        _run(conn, "UPDATE payments SET status='rejected' WHERE id=?", (payment_id,))
        conn.commit()
    finally:
        conn.close()


# ── Admin Tokens ──────────────────────────────────────────────

def get_db():
    """Compatibilidade com server.py que usa get_db() diretamente."""
    return _conn()


# ── Download Tokens ───────────────────────────────────────────

def save_download_token(token, user_id, lic_content, expires_at):
    conn = _conn()
    try:
        _run(conn, """
            INSERT INTO download_tokens (token, user_id, lic_content, expires_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (token) DO UPDATE SET lic_content=EXCLUDED.lic_content
        """ if USE_PG else """
            INSERT OR REPLACE INTO download_tokens (token, user_id, lic_content, expires_at)
            VALUES (?, ?, ?, ?)
        """, (token, user_id, lic_content, expires_at))
        conn.commit()
    finally:
        conn.close()


def save_device_session(email, ip, user_agent=''):
    """Registra uma sessão de dispositivo (para IP telemetry)."""
    conn = _conn()
    try:
        _run(conn, """
            INSERT INTO device_sessions (email, ip, user_agent, timestamp)
            VALUES (?, ?, ?, ?)
        """, (email, ip, user_agent, _now()))
        conn.commit()
    except Exception as e:
        print(f"[DB] Erro ao salvar device_session: {e}")
    finally:
        conn.close()


def get_user_ip_history(email, days=30):
    """Retorna histórico de IPs de um usuário nos últimos N dias."""
    conn = _conn()
    try:
        cutoff_date = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        cur = _run(conn, """
            SELECT DISTINCT ip, COUNT(*) as access_count
            FROM device_sessions
            WHERE email = ? AND timestamp > ?
            GROUP BY ip
            ORDER BY access_count DESC
        """, (email, cutoff_date))
        return _all(cur)
    finally:
        conn.close()


def get_all_ip_history(days=30):
    """Retorna histórico de todos os usuários para detecção de fraude."""
    conn = _conn()
    try:
        cutoff_date = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        cur = _run(conn, """
            SELECT email, COUNT(DISTINCT ip) as unique_ips, GROUP_CONCAT(DISTINCT ip, ',') as ips
            FROM device_sessions
            WHERE timestamp > ?
            GROUP BY email
            ORDER BY unique_ips DESC
        """, (cutoff_date,))
        return _all(cur)
    finally:
        conn.close()


def get_download_token(token):
    conn = _conn()
    try:
        if USE_PG:
            conn.autocommit = False
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("BEGIN")
            cur.execute("SELECT * FROM download_tokens WHERE token = %s FOR UPDATE", (token,))
            row = cur.fetchone()
            if row:
                cur.execute("DELETE FROM download_tokens WHERE token = %s", (token,))
                conn.commit()
                return dict(row)
            conn.rollback()
            return None
        else:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute("SELECT * FROM download_tokens WHERE token=?", (token,))
            row = cur.fetchone()
            if row:
                conn.execute("DELETE FROM download_tokens WHERE token=?", (token,))
                conn.commit()
                return dict(row)
            conn.rollback()
            return None
    except Exception:
        conn.rollback()
        return None
    finally:
        conn.close()
