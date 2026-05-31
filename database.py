# -*- coding: utf-8 -*-
"""
TripaBot License Server — Database Module
Auto-detecta PostgreSQL (Railway) ou usa SQLite (local)
"""

import os
import sqlite3
from datetime import datetime

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURAÇÃO: DATABASE_URL vem do Railway (PostgreSQL) ou None (SQLite)
# ──────────────────────────────────────────────────────────────────────────────

DATABASE_URL = os.environ.get('DATABASE_URL')

# Tenta importar psycopg2 se DATABASE_URL existir
psycopg2 = None
if DATABASE_URL:
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        # Corrige postgres:// → postgresql://
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
        USE_POSTGRES = True
        print("[DB] ✓ PostgreSQL detectado (Railway)")
    except ImportError:
        USE_POSTGRES = False
        DATABASE_URL = None
        print("[DB] ✗ PostgreSQL não disponível, usando SQLite")
else:
    USE_POSTGRES = False

if not USE_POSTGRES:
    DB_PATH = os.path.join(os.path.dirname(__file__), 'tripabot.db')
    print(f"[DB] ✓ SQLite: {DB_PATH}")


# ──────────────────────────────────────────────────────────────────────────────
# CONEXÃO: Abstração para SQLite e PostgreSQL
# ──────────────────────────────────────────────────────────────────────────────

class DB:
    @staticmethod
    def connect():
        """Retorna conexão apropriada."""
        if USE_POSTGRES:
            return psycopg2.connect(DATABASE_URL, sslmode='require')
        else:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            return conn

    @staticmethod
    def execute(sql, params=(), fetch=None):
        """Executa SQL e retorna resultado."""
        conn = DB.connect()
        try:
            if USE_POSTGRES:
                cur = conn.cursor(cursor_factory=RealDictCursor)
                sql = sql.replace('?', '%s')
            else:
                cur = conn.cursor()

            cur.execute(sql, params)

            if fetch == 'one':
                result = cur.fetchone()
                return dict(result) if result else None
            elif fetch == 'all':
                results = cur.fetchall()
                return [dict(r) for r in results]
            else:
                conn.commit()
                if USE_POSTGRES:
                    try:
                        cur.execute("SELECT lastval()")
                        lastid = cur.fetchone()[0]
                        return lastid
                    except:
                        return None
                else:
                    return cur.lastrowid
        finally:
            conn.close()


# ──────────────────────────────────────────────────────────────────────────────
# INIT
# ──────────────────────────────────────────────────────────────────────────────

def init_db():
    """Cria tabelas se não existirem."""
    conn = DB.connect()
    cur = conn.cursor()

    if USE_POSTGRES:
        # PostgreSQL
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
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
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                plan TEXT NOT NULL,
                lic_content TEXT NOT NULL,
                is_revoked INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS payments (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                method TEXT DEFAULT 'pix',
                status TEXT DEFAULT 'pending',
                notes TEXT,
                created_at TEXT NOT NULL,
                approved_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
    else:
        # SQLite
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
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                method TEXT DEFAULT 'pix',
                status TEXT DEFAULT 'pending',
                notes TEXT,
                created_at TEXT NOT NULL,
                approved_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        """)

    conn.commit()
    conn.close()
    print("[DB] ✓ Tabelas criadas/verificadas")


# ──────────────────────────────────────────────────────────────────────────────
# USUÁRIOS
# ──────────────────────────────────────────────────────────────────────────────

def create_user(email, password_hash, name=None):
    """Cria novo usuário."""
    email = email.lower().strip()
    now = datetime.utcnow().isoformat() + 'Z'
    try:
        DB.execute(
            "INSERT INTO users (email, password_hash, name, created_at) VALUES (?, ?, ?, ?)",
            (email, password_hash, name, now)
        )
        return get_user_by_email(email)
    except:
        return None


def get_user_by_email(email):
    """Busca usuário por email."""
    return DB.execute(
        "SELECT * FROM users WHERE email = ?",
        (email.lower().strip(),),
        fetch='one'
    )


def get_user_by_id(user_id):
    """Busca usuário por ID."""
    return DB.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,),
        fetch='one'
    )


def get_all_users():
    """Lista todos os usuários."""
    return DB.execute("""
        SELECT u.*,
               COUNT(p.id) as total_payments,
               SUM(CASE WHEN p.status = 'pending' THEN 1 ELSE 0 END) as pending_payments
        FROM users u
        LEFT JOIN payments p ON p.user_id = u.id
        GROUP BY u.id
        ORDER BY u.created_at DESC
    """, fetch='all')


def update_user_status(user_id, status, paid_expires=None):
    """Atualiza status do usuário."""
    if paid_expires:
        DB.execute(
            "UPDATE users SET status=?, paid_expires=? WHERE id=?",
            (status, paid_expires, user_id)
        )
    else:
        DB.execute(
            "UPDATE users SET status=? WHERE id=?",
            (status, user_id)
        )


def update_user_trial(user_id, trial_expires):
    """Define expiração do trial."""
    DB.execute(
        "UPDATE users SET status='trial', trial_expires=? WHERE id=?",
        (trial_expires, user_id)
    )


def update_last_verified(user_id):
    """Atualiza timestamp de verificação."""
    now = datetime.utcnow().isoformat() + 'Z'
    DB.execute(
        "UPDATE users SET last_verified=? WHERE id=?",
        (now, user_id)
    )


# ──────────────────────────────────────────────────────────────────────────────
# LICENÇAS
# ──────────────────────────────────────────────────────────────────────────────

def save_license(user_id, email, issued_at, expires_at, plan, lic_content):
    """Salva licença."""
    now = datetime.utcnow().isoformat() + 'Z'
    DB.execute(
        """INSERT INTO licenses (user_id, email, issued_at, expires_at, plan, lic_content, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (user_id, email, issued_at, expires_at, plan, lic_content, now)
    )


def get_latest_license(user_id):
    """Retorna licença mais recente."""
    return DB.execute(
        """SELECT * FROM licenses WHERE user_id=? AND is_revoked=0
           ORDER BY created_at DESC LIMIT 1""",
        (user_id,),
        fetch='one'
    )


def revoke_all_licenses(user_id):
    """Revoga todas as licenças."""
    DB.execute(
        "UPDATE licenses SET is_revoked=1 WHERE user_id=?",
        (user_id,)
    )


def is_license_revoked(email, issued_at):
    """Verifica se licença foi revogada."""
    result = DB.execute(
        "SELECT is_revoked FROM licenses WHERE email=? AND issued_at=?",
        (email, issued_at),
        fetch='one'
    )
    if not result:
        return True
    return bool(result.get('is_revoked', 0) if isinstance(result, dict) else result[0])


# ──────────────────────────────────────────────────────────────────────────────
# PAGAMENTOS
# ──────────────────────────────────────────────────────────────────────────────

def create_payment(user_id, amount=50.0, notes=''):
    """Registra pagamento."""
    now = datetime.utcnow().isoformat() + 'Z'
    return DB.execute(
        "INSERT INTO payments (user_id, amount, notes, created_at) VALUES (?, ?, ?, ?)",
        (user_id, amount, notes, now)
    )


def get_pending_payments():
    """Lista pagamentos pendentes."""
    return DB.execute("""
        SELECT p.*, u.email, u.name, u.status
        FROM payments p
        JOIN users u ON u.id = p.user_id
        WHERE p.status = 'pending'
        ORDER BY p.created_at DESC
    """, fetch='all')


def approve_payment(payment_id):
    """Aprova pagamento."""
    now = datetime.utcnow().isoformat() + 'Z'
    DB.execute(
        "UPDATE payments SET status='approved', approved_at=? WHERE id=?",
        (now, payment_id)
    )


def reject_payment(payment_id):
    """Rejeita pagamento."""
    DB.execute(
        "UPDATE payments SET status='rejected' WHERE id=?",
        (payment_id,)
    )
