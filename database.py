# -*- coding: utf-8 -*-
"""
TripaBot License Server — Módulo de Banco de Dados
SQLite local + PostgreSQL no Railway (auto-detectado via DATABASE_URL)
"""

import os
import sqlite3
from datetime import datetime
from contextlib import contextmanager

# Railway fornece DATABASE_URL quando PostgreSQL está adicionado
# Corrige postgres:// → postgresql:// (psycopg2 exige essa forma)
_raw_db_url = os.environ.get('DATABASE_URL', '')
DATABASE_URL = _raw_db_url.replace('postgres://', 'postgresql://', 1) if _raw_db_url else None
IS_POSTGRES = bool(DATABASE_URL)

if IS_POSTGRES:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    print(f"[DB] Modo PostgreSQL (Railway) detectado")
else:
    DB_PATH = os.path.join(os.path.dirname(__file__), 'tripabot.db')
    print(f"[DB] Modo SQLite local: {DB_PATH}")


@contextmanager
def get_db():
    """Retorna conexão com o banco de dados correto."""
    if IS_POSTGRES:
        conn = psycopg2.connect(DATABASE_URL)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()


def _row(row):
    """Converte qualquer row para dict."""
    if row is None:
        return None
    if isinstance(row, dict):
        return dict(row)
    return dict(row)


def _Q(q):
    """Troca ? por %s se for PostgreSQL."""
    if IS_POSTGRES:
        return q.replace('?', '%s')
    return q


def _exec(conn, sql, params=()):
    """Executa SQL retornando cursor."""
    sql = _Q(sql)
    if IS_POSTGRES:
        cur = conn.cursor(cursor_factory=RealDictCursor)
    else:
        cur = conn.cursor()
    cur.execute(sql, params)
    return cur


def _fetchone(conn, sql, params=()):
    cur = _exec(conn, sql, params)
    row = cur.fetchone()
    cur.close()
    return _row(row)


def _fetchall(conn, sql, params=()):
    cur = _exec(conn, sql, params)
    rows = cur.fetchall()
    cur.close()
    return [_row(r) for r in rows]


def init_db():
    """Cria as tabelas se não existirem."""
    with get_db() as conn:
        if IS_POSTGRES:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id            SERIAL PRIMARY KEY,
                    email         TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    name          TEXT,
                    status        TEXT DEFAULT 'trial',
                    created_at    TEXT NOT NULL,
                    trial_expires TEXT,
                    paid_expires  TEXT,
                    last_verified TEXT,
                    payment_notes TEXT
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    id          SERIAL PRIMARY KEY,
                    user_id     INTEGER NOT NULL,
                    email       TEXT NOT NULL,
                    issued_at   TEXT NOT NULL,
                    expires_at  TEXT NOT NULL,
                    plan        TEXT NOT NULL,
                    lic_content TEXT NOT NULL,
                    is_revoked  INTEGER DEFAULT 0,
                    created_at  TEXT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS payments (
                    id          SERIAL PRIMARY KEY,
                    user_id     INTEGER NOT NULL,
                    amount      REAL NOT NULL,
                    method      TEXT DEFAULT 'pix',
                    status      TEXT DEFAULT 'pending',
                    notes       TEXT,
                    created_at  TEXT NOT NULL,
                    approved_at TEXT
                )
            """)
            cur.close()
        else:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    email         TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    name          TEXT,
                    status        TEXT DEFAULT 'trial',
                    created_at    TEXT NOT NULL,
                    trial_expires TEXT,
                    paid_expires  TEXT,
                    last_verified TEXT,
                    payment_notes TEXT
                );
                CREATE TABLE IF NOT EXISTS licenses (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id     INTEGER NOT NULL,
                    email       TEXT NOT NULL,
                    issued_at   TEXT NOT NULL,
                    expires_at  TEXT NOT NULL,
                    plan        TEXT NOT NULL,
                    lic_content TEXT NOT NULL,
                    is_revoked  INTEGER DEFAULT 0,
                    created_at  TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS payments (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id     INTEGER NOT NULL,
                    amount      REAL NOT NULL,
                    method      TEXT DEFAULT 'pix',
                    status      TEXT DEFAULT 'pending',
                    notes       TEXT,
                    created_at  TEXT NOT NULL,
                    approved_at TEXT
                );
            """)
    print("[DB] Tabelas inicializadas com sucesso")


# ─── USUÁRIOS ──────────────────────────────────────────────────────────────

def create_user(email, password_hash, name=None):
    email = email.lower().strip()
    now = datetime.utcnow().isoformat() + 'Z'
    with get_db() as conn:
        try:
            _exec(conn, """
                INSERT INTO users (email, password_hash, name, created_at)
                VALUES (?, ?, ?, ?)
            """, (email, password_hash, name, now))
            return _fetchone(conn, "SELECT * FROM users WHERE email = ?", (email,))
        except Exception as e:
            print(f"[DB] create_user error: {e}")
            return None


def get_user_by_email(email):
    with get_db() as conn:
        return _fetchone(conn, "SELECT * FROM users WHERE email = ?", (email.lower().strip(),))


def get_user_by_id(user_id):
    with get_db() as conn:
        return _fetchone(conn, "SELECT * FROM users WHERE id = ?", (user_id,))


def get_all_users():
    sql = """
        SELECT u.*,
               COUNT(p.id) as total_payments,
               SUM(CASE WHEN p.status = 'pending' THEN 1 ELSE 0 END) as pending_payments
        FROM users u
        LEFT JOIN payments p ON p.user_id = u.id
        GROUP BY u.id
        ORDER BY u.created_at DESC
    """
    with get_db() as conn:
        return _fetchall(conn, sql)


def update_user_status(user_id, status, paid_expires=None):
    with get_db() as conn:
        if paid_expires:
            _exec(conn, "UPDATE users SET status=?, paid_expires=? WHERE id=?",
                  (status, paid_expires, user_id))
        else:
            _exec(conn, "UPDATE users SET status=? WHERE id=?", (status, user_id))


def update_user_trial(user_id, trial_expires):
    with get_db() as conn:
        _exec(conn, "UPDATE users SET status='trial', trial_expires=? WHERE id=?",
              (trial_expires, user_id))


def update_last_verified(user_id):
    now = datetime.utcnow().isoformat() + 'Z'
    with get_db() as conn:
        _exec(conn, "UPDATE users SET last_verified=? WHERE id=?", (now, user_id))


# ─── LICENÇAS ──────────────────────────────────────────────────────────────

def save_license(user_id, email, issued_at, expires_at, plan, lic_content):
    now = datetime.utcnow().isoformat() + 'Z'
    with get_db() as conn:
        _exec(conn, """
            INSERT INTO licenses (user_id, email, issued_at, expires_at, plan, lic_content, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, email, issued_at, expires_at, plan, lic_content, now))


def get_latest_license(user_id):
    with get_db() as conn:
        return _fetchone(conn, """
            SELECT * FROM licenses
            WHERE user_id=? AND is_revoked=0
            ORDER BY created_at DESC LIMIT 1
        """, (user_id,))


def revoke_all_licenses(user_id):
    with get_db() as conn:
        _exec(conn, "UPDATE licenses SET is_revoked=1 WHERE user_id=?", (user_id,))


def is_license_revoked(email, issued_at):
    with get_db() as conn:
        row = _fetchone(conn, """
            SELECT is_revoked FROM licenses WHERE email=? AND issued_at=?
        """, (email, issued_at))
        if not row:
            return True  # não encontrada = revogada
        return bool(row['is_revoked'])


# ─── PAGAMENTOS ────────────────────────────────────────────────────────────

def create_payment(user_id, amount=50.0, notes=''):
    now = datetime.utcnow().isoformat() + 'Z'
    with get_db() as conn:
        if IS_POSTGRES:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute(
                "INSERT INTO payments (user_id, amount, notes, created_at) VALUES (%s, %s, %s, %s) RETURNING id",
                (user_id, amount, notes, now)
            )
            payment_id = cur.fetchone()['id']
            cur.close()
        else:
            _exec(conn, "INSERT INTO payments (user_id, amount, notes, created_at) VALUES (?, ?, ?, ?)",
                  (user_id, amount, notes, now))
            payment_id = _fetchone(conn, "SELECT last_insert_rowid() as id")['id']
        return payment_id


def get_pending_payments():
    sql = """
        SELECT p.*, u.email, u.name, u.status
        FROM payments p
        JOIN users u ON u.id = p.user_id
        WHERE p.status = 'pending'
        ORDER BY p.created_at DESC
    """
    with get_db() as conn:
        return _fetchall(conn, sql)


def approve_payment(payment_id):
    now = datetime.utcnow().isoformat() + 'Z'
    with get_db() as conn:
        _exec(conn, "UPDATE payments SET status='approved', approved_at=? WHERE id=?",
              (now, payment_id))


def reject_payment(payment_id):
    with get_db() as conn:
        _exec(conn, "UPDATE payments SET status='rejected' WHERE id=?", (payment_id,))
