"""
TripaBot License Server — Módulo de Banco de Dados (SQLite local + PostgreSQL Railway)
Gerencia usuários, licenças e pagamentos.
"""

import os
import sqlite3
from datetime import datetime
from contextlib import contextmanager

# Detecta se está no Railway (tem DATABASE_URL) ou local (usa SQLite)
DATABASE_URL = os.environ.get('DATABASE_URL')
IS_RAILWAY = DATABASE_URL is not None

if IS_RAILWAY:
    import psycopg2
    from psycopg2.extras import RealDictCursor
else:
    DB_PATH = os.path.join(os.path.dirname(__file__), 'tripabot.db')


@contextmanager
def get_db():
    """Retorna conexão com o banco de dados (SQLite ou PostgreSQL)."""
    if IS_RAILWAY:
        # PostgreSQL no Railway
        conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        conn.set_session(autocommit=False)
        yield conn
        conn.close()
    else:
        # SQLite local
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        yield conn
        conn.close()


def dict_from_row(row):
    """Converte row (SQLite ou PostgreSQL) para dict."""
    if row is None:
        return None
    if isinstance(row, dict):
        return row
    return dict(row)


def init_db():
    """Cria as tabelas se não existirem."""
    with get_db() as conn:
        if IS_RAILWAY:
            # PostgreSQL
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id          SERIAL PRIMARY KEY,
                    email       TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    name        TEXT,
                    status      TEXT DEFAULT 'trial',
                    created_at  TEXT NOT NULL,
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
                    created_at  TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
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
                    approved_at TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            conn.commit()
            cur.close()
            print("[DB] PostgreSQL no Railway inicializado")
        else:
            # SQLite
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    email       TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    name        TEXT,
                    status      TEXT DEFAULT 'trial',
                    created_at  TEXT NOT NULL,
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
                    created_at  TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS payments (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id     INTEGER NOT NULL,
                    amount      REAL NOT NULL,
                    method      TEXT DEFAULT 'pix',
                    status      TEXT DEFAULT 'pending',
                    notes       TEXT,
                    created_at  TEXT NOT NULL,
                    approved_at TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );
            """)
            conn.commit()
            print(f"[DB] SQLite local em {DB_PATH}")


# ─── USUÁRIOS ───────────────────────────────────────────────

def create_user(email, password_hash, name=None):
    """Cria novo usuário. Retorna dict ou None se email já existe."""
    with get_db() as conn:
        try:
            now = datetime.utcnow().isoformat() + 'Z'
            if IS_RAILWAY:
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO users (email, password_hash, name, created_at) VALUES (%s, %s, %s, %s)",
                    (email.lower().strip(), password_hash, name, now)
                )
                cur.execute("SELECT * FROM users WHERE email = %s", (email.lower().strip(),))
                user = cur.fetchone()
                cur.close()
                return dict_from_row(user)
            else:
                conn.execute(
                    "INSERT INTO users (email, password_hash, name, created_at) VALUES (?, ?, ?, ?)",
                    (email.lower().strip(), password_hash, name, now)
                )
                user = conn.execute("SELECT * FROM users WHERE email = ?", (email.lower().strip(),)).fetchone()
                conn.commit()
                return dict_from_row(user)
        except Exception as e:
            print(f"[DB] Error creating user: {e}")
            return None


def get_user_by_email(email):
    """Busca usuário por email."""
    with get_db() as conn:
        if IS_RAILWAY:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE email = %s", (email.lower().strip(),))
            user = cur.fetchone()
            cur.close()
        else:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email.lower().strip(),)).fetchone()
        return dict_from_row(user)


def get_user_by_id(user_id):
    """Busca usuário por ID."""
    with get_db() as conn:
        if IS_RAILWAY:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            cur.close()
        else:
            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict_from_row(user)


def get_all_users():
    """Lista todos os usuários (para o painel admin)."""
    with get_db() as conn:
        if IS_RAILWAY:
            cur = conn.cursor()
            cur.execute("""
                SELECT u.*,
                       COUNT(p.id) as total_payments,
                       SUM(CASE WHEN p.status = 'pending' THEN 1 ELSE 0 END) as pending_payments
                FROM users u
                LEFT JOIN payments p ON p.user_id = u.id
                GROUP BY u.id
                ORDER BY u.created_at DESC
            """)
            users = cur.fetchall()
            cur.close()
        else:
            users = conn.execute("""
                SELECT u.*,
                       COUNT(p.id) as total_payments,
                       SUM(CASE WHEN p.status = 'pending' THEN 1 ELSE 0 END) as pending_payments
                FROM users u
                LEFT JOIN payments p ON p.user_id = u.id
                GROUP BY u.id
                ORDER BY u.created_at DESC
            """).fetchall()
        return [dict_from_row(u) for u in users]


def update_user_status(user_id, status, paid_expires=None):
    """Atualiza status e data de expiração do usuário."""
    with get_db() as conn:
        if IS_RAILWAY:
            cur = conn.cursor()
            if paid_expires:
                cur.execute(
                    "UPDATE users SET status=%s, paid_expires=%s WHERE id=%s",
                    (status, paid_expires, user_id)
                )
            else:
                cur.execute("UPDATE users SET status=%s WHERE id=%s", (status, user_id))
            conn.commit()
            cur.close()
        else:
            if paid_expires:
                conn.execute(
                    "UPDATE users SET status=?, paid_expires=? WHERE id=?",
                    (status, paid_expires, user_id)
                )
            else:
                conn.execute("UPDATE users SET status=? WHERE id=?", (status, user_id))
            conn.commit()


def update_user_trial(user_id, trial_expires):
    """Define data de expiração do trial."""
    with get_db() as conn:
        if IS_RAILWAY:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET status='trial', trial_expires=%s WHERE id=%s",
                (trial_expires, user_id)
            )
            conn.commit()
            cur.close()
        else:
            conn.execute(
                "UPDATE users SET status='trial', trial_expires=? WHERE id=?",
                (trial_expires, user_id)
            )
            conn.commit()


def update_last_verified(user_id):
    """Atualiza timestamp da última verificação online."""
    with get_db() as conn:
        now = datetime.utcnow().isoformat() + 'Z'
        if IS_RAILWAY:
            cur = conn.cursor()
            cur.execute("UPDATE users SET last_verified=%s WHERE id=%s", (now, user_id))
            conn.commit()
            cur.close()
        else:
            conn.execute("UPDATE users SET last_verified=? WHERE id=?", (now, user_id))
            conn.commit()


# ─── LICENÇAS ───────────────────────────────────────────────

def save_license(user_id, email, issued_at, expires_at, plan, lic_content):
    """Salva licença gerada no banco."""
    with get_db() as conn:
        now = datetime.utcnow().isoformat() + 'Z'
        if IS_RAILWAY:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO licenses (user_id, email, issued_at, expires_at, plan, lic_content, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (user_id, email, issued_at, expires_at, plan, lic_content, now))
            conn.commit()
            cur.close()
        else:
            conn.execute("""
                INSERT INTO licenses (user_id, email, issued_at, expires_at, plan, lic_content, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user_id, email, issued_at, expires_at, plan, lic_content, now))
            conn.commit()


def get_latest_license(user_id):
    """Retorna a licença mais recente do usuário."""
    with get_db() as conn:
        if IS_RAILWAY:
            cur = conn.cursor()
            cur.execute("""
                SELECT * FROM licenses
                WHERE user_id=%s AND is_revoked=0
                ORDER BY created_at DESC
                LIMIT 1
            """, (user_id,))
            lic = cur.fetchone()
            cur.close()
        else:
            lic = conn.execute("""
                SELECT * FROM licenses
                WHERE user_id=? AND is_revoked=0
                ORDER BY created_at DESC
                LIMIT 1
            """, (user_id,)).fetchone()
        return dict_from_row(lic)


def revoke_all_licenses(user_id):
    """Revoga todas as licenças do usuário."""
    with get_db() as conn:
        if IS_RAILWAY:
            cur = conn.cursor()
            cur.execute("UPDATE licenses SET is_revoked=1 WHERE user_id=%s", (user_id,))
            conn.commit()
            cur.close()
        else:
            conn.execute("UPDATE licenses SET is_revoked=1 WHERE user_id=?", (user_id,))
            conn.commit()


def is_license_revoked(email, issued_at):
    """Verifica se uma licença específica foi revogada."""
    with get_db() as conn:
        if IS_RAILWAY:
            cur = conn.cursor()
            cur.execute("""
                SELECT is_revoked FROM licenses
                WHERE email=%s AND issued_at=%s
            """, (email, issued_at))
            lic = cur.fetchone()
            cur.close()
        else:
            lic = conn.execute("""
                SELECT is_revoked FROM licenses
                WHERE email=? AND issued_at=?
            """, (email, issued_at)).fetchone()

        if not lic:
            return True  # Licença não encontrada = revogada
        return bool(lic[0] if isinstance(lic, tuple) else lic['is_revoked'])


# ─── PAGAMENTOS ─────────────────────────────────────────────

def create_payment(user_id, amount=50.0, notes=''):
    """Registra um pagamento pendente."""
    with get_db() as conn:
        now = datetime.utcnow().isoformat() + 'Z'
        if IS_RAILWAY:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO payments (user_id, amount, notes, created_at) VALUES (%s, %s, %s, %s)",
                (user_id, amount, notes, now)
            )
            cur.execute("SELECT LASTVAL()")
            payment_id = cur.fetchone()[0]
            conn.commit()
            cur.close()
        else:
            conn.execute(
                "INSERT INTO payments (user_id, amount, notes, created_at) VALUES (?, ?, ?, ?)",
                (user_id, amount, notes, now)
            )
            payment_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.commit()
        return payment_id


def get_pending_payments():
    """Lista pagamentos pendentes para o painel admin."""
    with get_db() as conn:
        if IS_RAILWAY:
            cur = conn.cursor()
            cur.execute("""
                SELECT p.*, u.email, u.name, u.status
                FROM payments p
                JOIN users u ON u.id = p.user_id
                WHERE p.status = 'pending'
                ORDER BY p.created_at DESC
            """)
            payments = cur.fetchall()
            cur.close()
        else:
            payments = conn.execute("""
                SELECT p.*, u.email, u.name, u.status
                FROM payments p
                JOIN users u ON u.id = p.user_id
                WHERE p.status = 'pending'
                ORDER BY p.created_at DESC
            """).fetchall()
        return [dict_from_row(p) for p in payments]


def approve_payment(payment_id):
    """Marca pagamento como aprovado."""
    with get_db() as conn:
        now = datetime.utcnow().isoformat() + 'Z'
        if IS_RAILWAY:
            cur = conn.cursor()
            cur.execute(
                "UPDATE payments SET status='approved', approved_at=%s WHERE id=%s",
                (now, payment_id)
            )
            conn.commit()
            cur.close()
        else:
            conn.execute(
                "UPDATE payments SET status='approved', approved_at=? WHERE id=?",
                (now, payment_id)
            )
            conn.commit()


def reject_payment(payment_id):
    """Marca pagamento como rejeitado."""
    with get_db() as conn:
        if IS_RAILWAY:
            cur = conn.cursor()
            cur.execute("UPDATE payments SET status='rejected' WHERE id=%s", (payment_id,))
            conn.commit()
            cur.close()
        else:
            conn.execute("UPDATE payments SET status='rejected' WHERE id=?", (payment_id,))
            conn.commit()
