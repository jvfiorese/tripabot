"""
TripaBot License Server — Módulo de Banco de Dados (SQLite)
Gerencia usuários, licenças e pagamentos.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'tripabot.db')


def get_db():
    """Retorna conexão com o banco de dados."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Permite acessar colunas por nome
    return conn


def init_db():
    """Cria as tabelas se não existirem."""
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name        TEXT,
            status      TEXT DEFAULT 'trial',
            -- status: 'trial' | 'active' | 'expired' | 'revoked'
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
            -- plan: 'trial_30d' | 'annual_365d'
            lic_content TEXT NOT NULL,
            -- conteúdo base64 do arquivo .lic
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
            -- status: 'pending' | 'approved' | 'rejected'
            notes       TEXT,
            created_at  TEXT NOT NULL,
            approved_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    conn.commit()
    conn.close()
    print(f"[DB] Banco de dados inicializado em {DB_PATH}")


# ─── USUÁRIOS ───────────────────────────────────────────────

def create_user(email, password_hash, name=None):
    """Cria novo usuário. Retorna id ou None se email já existe."""
    conn = get_db()
    try:
        now = datetime.utcnow().isoformat() + 'Z'
        conn.execute(
            "INSERT INTO users (email, password_hash, name, created_at) VALUES (?, ?, ?, ?)",
            (email.lower().strip(), password_hash, name, now)
        )
        conn.commit()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email.lower().strip(),)).fetchone()
        return dict(user)
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def get_user_by_email(email):
    """Busca usuário por email."""
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email.lower().strip(),)).fetchone()
    conn.close()
    return dict(user) if user else None


def get_user_by_id(user_id):
    """Busca usuário por ID."""
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None


def get_all_users():
    """Lista todos os usuários (para o painel admin)."""
    conn = get_db()
    users = conn.execute("""
        SELECT u.*,
               COUNT(p.id) as total_payments,
               SUM(CASE WHEN p.status = 'pending' THEN 1 ELSE 0 END) as pending_payments
        FROM users u
        LEFT JOIN payments p ON p.user_id = u.id
        GROUP BY u.id
        ORDER BY u.created_at DESC
    """).fetchall()
    conn.close()
    return [dict(u) for u in users]


def update_user_status(user_id, status, paid_expires=None):
    """Atualiza status e data de expiração do usuário."""
    conn = get_db()
    if paid_expires:
        conn.execute(
            "UPDATE users SET status=?, paid_expires=? WHERE id=?",
            (status, paid_expires, user_id)
        )
    else:
        conn.execute("UPDATE users SET status=? WHERE id=?", (status, user_id))
    conn.commit()
    conn.close()


def update_user_trial(user_id, trial_expires):
    """Define data de expiração do trial."""
    conn = get_db()
    conn.execute(
        "UPDATE users SET status='trial', trial_expires=? WHERE id=?",
        (trial_expires, user_id)
    )
    conn.commit()
    conn.close()


def update_last_verified(user_id):
    """Atualiza timestamp da última verificação online."""
    conn = get_db()
    now = datetime.utcnow().isoformat() + 'Z'
    conn.execute("UPDATE users SET last_verified=? WHERE id=?", (now, user_id))
    conn.commit()
    conn.close()


# ─── LICENÇAS ───────────────────────────────────────────────

def save_license(user_id, email, issued_at, expires_at, plan, lic_content):
    """Salva licença gerada no banco."""
    conn = get_db()
    now = datetime.utcnow().isoformat() + 'Z'
    conn.execute("""
        INSERT INTO licenses (user_id, email, issued_at, expires_at, plan, lic_content, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, email, issued_at, expires_at, plan, lic_content, now))
    conn.commit()
    conn.close()


def get_latest_license(user_id):
    """Retorna a licença mais recente do usuário."""
    conn = get_db()
    lic = conn.execute("""
        SELECT * FROM licenses
        WHERE user_id=? AND is_revoked=0
        ORDER BY created_at DESC
        LIMIT 1
    """, (user_id,)).fetchone()
    conn.close()
    return dict(lic) if lic else None


def revoke_all_licenses(user_id):
    """Revoga todas as licenças do usuário."""
    conn = get_db()
    conn.execute("UPDATE licenses SET is_revoked=1 WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()


def is_license_revoked(email, issued_at):
    """Verifica se uma licença específica foi revogada."""
    conn = get_db()
    lic = conn.execute("""
        SELECT is_revoked FROM licenses
        WHERE email=? AND issued_at=?
    """, (email, issued_at)).fetchone()
    conn.close()
    if not lic:
        return True  # Licença não encontrada = revogada
    return bool(lic['is_revoked'])


# ─── PAGAMENTOS ─────────────────────────────────────────────

def create_payment(user_id, amount=50.0, notes=''):
    """Registra um pagamento pendente."""
    conn = get_db()
    now = datetime.utcnow().isoformat() + 'Z'
    conn.execute(
        "INSERT INTO payments (user_id, amount, notes, created_at) VALUES (?, ?, ?, ?)",
        (user_id, amount, notes, now)
    )
    conn.commit()
    payment_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return payment_id


def get_pending_payments():
    """Lista pagamentos pendentes para o painel admin."""
    conn = get_db()
    payments = conn.execute("""
        SELECT p.*, u.email, u.name, u.status
        FROM payments p
        JOIN users u ON u.id = p.user_id
        WHERE p.status = 'pending'
        ORDER BY p.created_at DESC
    """).fetchall()
    conn.close()
    return [dict(p) for p in payments]


def approve_payment(payment_id):
    """Marca pagamento como aprovado."""
    conn = get_db()
    now = datetime.utcnow().isoformat() + 'Z'
    conn.execute(
        "UPDATE payments SET status='approved', approved_at=? WHERE id=?",
        (now, payment_id)
    )
    conn.commit()
    conn.close()


def reject_payment(payment_id):
    """Marca pagamento como rejeitado."""
    conn = get_db()
    conn.execute("UPDATE payments SET status='rejected' WHERE id=?", (payment_id,))
    conn.commit()
    conn.close()
