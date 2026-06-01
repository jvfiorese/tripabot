"""
TripaBot License Server
Flask server para autenticação, geração de licenças e painel admin.

Rotas:
  GET  /                         → Página de registro
  GET  /admin                    → Painel admin
  POST /api/register             → Registra novo usuário + gera trial .lic
  POST /api/login                → Login + retorna .lic mais recente
  GET  /api/verify               → Verifica se licença ainda é válida (online check)
  GET  /api/download-lic/<token> → Baixa arquivo .lic gerado
  POST /api/report-payment       → Usuário reporta que pagou Pix
  POST /api/admin/login          → Login do admin
  GET  /api/admin/users          → Lista usuários (admin)
  GET  /api/admin/payments       → Lista pagamentos pendentes (admin)
  POST /api/admin/approve/<id>   → Aprova pagamento + gera licença anual (admin)
  POST /api/admin/reject/<id>    → Rejeita pagamento (admin)
  POST /api/admin/revoke/<id>    → Revoga acesso do usuário (admin)
"""

import os
import re
import json
import base64
import secrets
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
from dotenv import load_dotenv
from flask import Flask, request, jsonify, send_from_directory, abort, Response
from flask_cors import CORS

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

from database import (
    init_db, create_user, get_user_by_email, get_user_by_id, get_all_users,
    update_user_status, update_user_trial, update_last_verified,
    save_license, get_latest_license, revoke_all_licenses, is_license_revoked,
    create_payment, get_pending_payments, approve_payment, reject_payment,
    save_download_token, get_download_token
)
from license_gen import generate_license, verify_license_content

# ─── Configuração ────────────────────────────────────────────
load_dotenv()

SECRET_KEY      = os.environ.get('TRIPABOT_SECRET_KEY', '')
ADMIN_PASSWORD  = os.environ.get('ADMIN_PASSWORD', '')
PIX_KEY         = os.environ.get('PIX_KEY', 'Configure PIX_KEY no .env')
CONTACT_EMAIL   = os.environ.get('CONTACT_EMAIL', '')
APP_VERSION     = '1.1.0'

# Tokens de admin — usa funções do database.py (compatível com SQLite e PostgreSQL)
def _admin_token_valid(token):
    from database import _run, _one, _conn, USE_PG
    conn = _conn()
    try:
        cur = _run(conn, "SELECT 1 FROM admin_tokens WHERE token=? AND expires_at > ?",
                   (token, datetime.now(timezone.utc).isoformat()))
        return cur.fetchone() is not None
    finally:
        conn.close()

def _admin_token_save(token):
    from database import _run, _conn, USE_PG
    expires = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()
    conn = _conn()
    try:
        if USE_PG:
            _run(conn, """INSERT INTO admin_tokens (token, expires_at) VALUES (?, ?)
                          ON CONFLICT (token) DO UPDATE SET expires_at=EXCLUDED.expires_at""",
                 (token, expires))
        else:
            _run(conn, "INSERT OR REPLACE INTO admin_tokens (token, expires_at) VALUES (?, ?)",
                 (token, expires))
        conn.commit()
    finally:
        conn.close()

if not SECRET_KEY:
    print("⚠️  ATENÇÃO: TRIPABOT_SECRET_KEY não definida no .env!")
if not ADMIN_PASSWORD:
    print("⚠️  ATENÇÃO: ADMIN_PASSWORD não definida no .env!")

app = Flask(__name__, static_folder='static', static_url_path='')

# CORS: permite file:// (HTML offline) + domínio em produção
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Headers de segurança em todas as respostas
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# ─── Helpers ─────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def admin_required(f):
    """Decorator que exige token de admin válido."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Admin-Token') or request.args.get('token')
        if not token or not _admin_token_valid(token):
            return jsonify({'error': 'Não autorizado'}), 401
        return f(*args, **kwargs)
    return decorated


def _make_download_token(user_id: int, lic_content: str) -> str:
    """Gera token de download temporário (30 min) — salvo no banco."""
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    save_download_token(token, user_id, lic_content, expires_at)
    return token


# ─── Páginas Estáticas ────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/admin')
def admin():
    return send_from_directory('static', 'admin.html')


@app.route('/renovar')
def renovar():
    return send_from_directory('static', 'renovar.html')


@app.route('/api/config')
def api_config():
    """Configurações públicas do servidor (sem dados sensíveis)."""
    return jsonify({'pix_key': PIX_KEY, 'contact_email': CONTACT_EMAIL, 'version': APP_VERSION})


@app.route('/download-html')
def download_html():
    """Força download do tripabot.html (com Content-Disposition: attachment)."""
    html_path = os.path.join(app.static_folder, 'tripabot.html')
    if not os.path.exists(html_path):
        return jsonify({'error': 'Arquivo não encontrado'}), 404
    return send_from_directory(
        app.static_folder,
        'tripabot.html',
        as_attachment=True,
        download_name='TripaBot.html'
    )


# ─── API Pública ─────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def api_register():
    """Registra novo usuário e gera trial de 30 dias."""
    data = request.get_json(silent=True) or {}
    email    = (data.get('email') or '').strip().lower()
    password = (data.get('password') or '').strip()
    name     = (data.get('name') or '').strip()

    if not email or not password:
        return jsonify({'error': 'Email e senha são obrigatórios'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Senha deve ter no mínimo 6 caracteres'}), 400
    if not EMAIL_REGEX.match(email):
        return jsonify({'error': 'Email inválido'}), 400

    pw_hash = hash_password(password)
    user = create_user(email, pw_hash, name)

    if not user:
        return jsonify({'error': 'Este email já está cadastrado'}), 409

    # Gera licença trial (30 dias)
    lic = generate_license(email, days=30)
    save_license(user['id'], email, lic['issued_at'], lic['expires_at'], lic['plan'], lic['lic_content'])
    update_user_trial(user['id'], lic['expires_at'])

    # Token de download
    dl_token = _make_download_token(user['id'], lic['lic_content'])

    return jsonify({
        'success': True,
        'message': 'Conta criada! Baixe seus arquivos abaixo.',
        'email':       email,
        'expires_at':  lic['expires_at'],
        'plan':        lic['plan'],
        'download_token': dl_token,
    }), 201


@app.route('/api/login', methods=['POST'])
def api_login():
    """Login do usuário. Retorna token de download da licença mais recente."""
    data = request.get_json(silent=True) or {}
    email    = (data.get('email') or '').strip().lower()
    password = (data.get('password') or '').strip()

    if not email or not password:
        return jsonify({'error': 'Email e senha são obrigatórios'}), 400

    user = get_user_by_email(email)
    if not user or not check_password(password, user['password_hash']):
        return jsonify({'error': 'Email ou senha incorretos'}), 401

    if user['status'] == 'revoked':
        return jsonify({'error': 'Acesso revogado. Entre em contato com o suporte.'}), 403

    lic = get_latest_license(user['id'])
    if not lic:
        return jsonify({'error': 'Nenhuma licença encontrada'}), 404

    dl_token = _make_download_token(user['id'], lic['lic_content'])
    update_last_verified(user['id'])

    return jsonify({
        'success': True,
        'email':       email,
        'status':      user['status'],
        'expires_at':  lic['expires_at'],
        'plan':        lic['plan'],
        'download_token': dl_token,
    })


@app.route('/api/verify', methods=['POST'])
def api_verify():
    """
    Verificação online da licença.
    Chamado pelo TripaBot.html quando há internet disponível.
    """
    data = request.get_json(silent=True) or {}
    lic_content = (data.get('lic_content') or '').strip()
    email       = (data.get('email') or '').strip().lower()

    print(f"[VERIFY] Request from {email[:10] if email else '?'}...")

    if not lic_content or not email:
        print(f"[VERIFY] Missing data: lic={bool(lic_content)}, email={bool(email)}")
        return jsonify({'valid': False, 'reason': 'missing_data'}), 400

    # Verifica assinatura e expiração
    result = verify_license_content(lic_content)
    if not result['valid']:
        print(f"[VERIFY] Invalid signature/expiration: {result.get('reason')}")
        return jsonify(result)

    # Verifica se usuário foi revogado no banco
    user = get_user_by_email(email)
    if not user:
        print(f"[VERIFY] User not found: {email}")
        return jsonify({'valid': False, 'reason': 'user_not_found'})

    print(f"[VERIFY] User status: {user['status']} (id={user['id']})")
    if user['status'] == 'revoked':
        print(f"[VERIFY] ❌ USER REVOKED: {email}")
        return jsonify({'valid': False, 'reason': 'revoked'})

    # Verifica se a licença específica foi revogada
    try:
        payload = json.loads(base64.b64decode(lic_content).decode())
        issued = payload.get('issued')
        if is_license_revoked(email, issued):
            print(f"[VERIFY] ❌ LICENSE REVOKED: {email} issued={issued}")
            return jsonify({'valid': False, 'reason': 'license_revoked'})
    except Exception as e:
        print(f"[VERIFY] Exception parsing lic_content: {e}")
        return jsonify({'valid': False, 'reason': 'invalid_format'})

    print(f"[VERIFY] ✅ VALID: {email}")
    update_last_verified(user['id'])
    return jsonify({**result, 'email': email})


@app.route('/api/download-lic/<token>')
def download_lic(token):
    """Download do arquivo tripabot.lic via token temporário (one-time use)."""
    token_data = get_download_token(token)
    if not token_data:
        return jsonify({'error': 'Link expirado ou inválido. Faça login novamente.'}), 404

    # Verifica expiração com datetime aware
    try:
        expires_dt = datetime.fromisoformat(token_data['expires_at'].replace('Z', '+00:00'))
        if datetime.now(timezone.utc) > expires_dt:
            return jsonify({'error': 'Link expirado. Faça login novamente.'}), 410
    except ValueError:
        return jsonify({'error': 'Token inválido'}), 404

    return Response(
        token_data['lic_content'],
        mimetype='application/octet-stream',
        headers={'Content-Disposition': 'attachment; filename="tripabot.lic"'}
    )


@app.route('/api/report-payment', methods=['POST'])
def api_report_payment():
    """Usuário reporta que pagou Pix. Cria pagamento pendente."""
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = (data.get('password') or '').strip()
    notes = (data.get('notes') or '').strip()

    user = get_user_by_email(email)
    if not user or not check_password(password, user['password_hash']):
        return jsonify({'error': 'Email ou senha incorretos'}), 401

    payment_id = create_payment(user['id'], amount=20.0, notes=notes)
    return jsonify({
        'success': True,
        'message': 'Pagamento registrado! Aguarde aprovação (normalmente em 24h).',
        'payment_id': payment_id,
    })


# ─── API Admin ────────────────────────────────────────────────

def _rate_limit_check(ip: str) -> bool:
    """Retorna True se o IP está bloqueado (>= 5 falhas nos últimos 5 min). Persiste no banco."""
    from database import _run, _one, _conn
    now = datetime.now(timezone.utc)
    window_start = (now - timedelta(minutes=5)).isoformat()
    conn = _conn()
    try:
        cur = _run(conn, """
            SELECT COUNT(*) as cnt FROM login_attempts
            WHERE ip=? AND created_at > ?
        """, (ip, window_start))
        row = _one(cur)
        return (row['cnt'] if row else 0) >= 5
    except Exception:
        return False
    finally:
        conn.close()

def _rate_limit_record(ip: str):
    """Registra uma tentativa falha para o IP."""
    from database import _run, _conn
    conn = _conn()
    try:
        _run(conn, "INSERT INTO login_attempts (ip, created_at) VALUES (?, ?)",
             (ip, datetime.now(timezone.utc).isoformat()))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

def _rate_limit_clear(ip: str):
    """Remove tentativas falhas do IP após login bem-sucedido."""
    from database import _run, _conn
    conn = _conn()
    try:
        _run(conn, "DELETE FROM login_attempts WHERE ip=?", (ip,))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

@app.route('/api/admin/login', methods=['POST'])
def api_admin_login():
    """Login do admin com senha do .env. Rate limiting persistente: 5 tentativas/5min."""
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()

    if _rate_limit_check(ip):
        logger.warning(f"[ADMIN] Rate limit atingido para IP {ip}")
        return jsonify({'error': 'Muitas tentativas. Aguarde 5 minutos.'}), 429

    data = request.get_json(silent=True) or {}
    password = (data.get('password') or '').strip()

    if not ADMIN_PASSWORD or password != ADMIN_PASSWORD:
        _rate_limit_record(ip)
        logger.warning(f"[ADMIN] Senha incorreta para IP {ip}")
        return jsonify({'error': 'Senha incorreta'}), 401

    _rate_limit_clear(ip)
    token = secrets.token_urlsafe(32)
    _admin_token_save(token)
    logger.info(f"[ADMIN] Login bem-sucedido de IP {ip}")
    return jsonify({'success': True, 'token': token})


@app.route('/api/admin/users')
@admin_required
def api_admin_users():
    """Lista todos os usuários."""
    users = get_all_users()
    return jsonify(users)


@app.route('/api/admin/payments')
@admin_required
def api_admin_payments():
    """Lista pagamentos pendentes."""
    payments = get_pending_payments()
    return jsonify(payments)


@app.route('/api/admin/approve/<int:payment_id>', methods=['POST'])
@admin_required
def api_admin_approve(payment_id):
    """Aprova pagamento e gera licença anual para o usuário."""
    payments = get_pending_payments()
    payment = next((p for p in payments if p['id'] == payment_id), None)
    if not payment:
        return jsonify({'error': 'Pagamento não encontrado'}), 404

    email   = payment['email']
    user_id = payment['user_id']

    # Gera licença anual (365 dias)
    lic = generate_license(email, days=365)
    save_license(user_id, email, lic['issued_at'], lic['expires_at'], lic['plan'], lic['lic_content'])

    # Atualiza status do usuário
    update_user_status(user_id, 'active', paid_expires=lic['expires_at'])
    approve_payment(payment_id)

    # Token de download para o admin enviar ao usuário
    dl_token = _make_download_token(user_id, lic['lic_content'])
    dl_url = f"/api/download-lic/{dl_token}"

    return jsonify({
        'success': True,
        'email':       email,
        'expires_at':  lic['expires_at'],
        'download_url': dl_url,
        'message': f"Licença gerada para {email}. Envie o link de download ou informe que o usuário faça login novamente.",
    })


@app.route('/api/admin/reject/<int:payment_id>', methods=['POST'])
@admin_required
def api_admin_reject(payment_id):
    """Rejeita pagamento."""
    reject_payment(payment_id)
    return jsonify({'success': True})


@app.route('/api/admin/revoke/<int:user_id>', methods=['POST'])
@admin_required
def api_admin_revoke(user_id):
    """Revoga todo o acesso de um usuário."""
    user = get_user_by_id(user_id)
    revoke_all_licenses(user_id)
    update_user_status(user_id, 'revoked')
    logger.warning(f"[ADMIN] Usuário revogado: id={user_id} email={user['email'] if user else '?'}")
    return jsonify({'success': True})


@app.route('/api/admin/generate-lic/<int:user_id>', methods=['POST'])
@admin_required
def api_admin_generate_lic(user_id):
    """Admin gera licença manual para um usuário (30 ou 365 dias)."""
    data = request.get_json(silent=True) or {}
    try:
        days = int(data.get('days', 365))
        days = max(1, min(days, 3650))  # entre 1 dia e 10 anos
    except (ValueError, TypeError):
        days = 365

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'Usuário não encontrado'}), 404

    email = user['email']
    lic = generate_license(email, days=days)
    save_license(user_id, email, lic['issued_at'], lic['expires_at'], lic['plan'], lic['lic_content'])

    status = 'trial' if days <= 30 else 'active'
    expires = lic['expires_at']
    if days <= 30:
        update_user_trial(user_id, expires)
    else:
        update_user_status(user_id, status, paid_expires=expires)

    dl_token = _make_download_token(user_id, lic['lic_content'])

    return jsonify({
        'success': True,
        'email':       email,
        'expires_at':  expires,
        'plan':        lic['plan'],
        'download_url': f"/api/download-lic/{dl_token}",
    })


# ─── Inicialização do banco (roda com gunicorn E com python server.py) ────────
init_db()

# ─── Main ─────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'True').lower() == 'true'
    print(f"\n{'='*50}")
    print(f"  TripaBot License Server")
    print(f"  Rodando em: http://localhost:{port}")
    print(f"  Painel admin: http://localhost:{port}/admin")
    print(f"{'='*50}\n")
    app.run(host='0.0.0.0', port=port, debug=debug)
