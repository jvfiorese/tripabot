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
import json
import base64
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
from dotenv import load_dotenv
from flask import Flask, request, jsonify, send_from_directory, abort, Response
from flask_cors import CORS

from database import (
    init_db, create_user, get_user_by_email, get_user_by_id, get_all_users,
    update_user_status, update_user_trial, update_last_verified,
    save_license, get_latest_license, revoke_all_licenses, is_license_revoked,
    create_payment, get_pending_payments, approve_payment, reject_payment
)
from license_gen import generate_license, verify_license_content

# ─── Configuração ────────────────────────────────────────────
load_dotenv()

SECRET_KEY      = os.environ.get('TRIPABOT_SECRET_KEY', '')
ADMIN_PASSWORD  = os.environ.get('ADMIN_PASSWORD', '')
ADMIN_TOKEN_STORE = {}  # token → timestamp (em memória, suficiente para 1 admin)

if not SECRET_KEY:
    print("⚠️  ATENÇÃO: TRIPABOT_SECRET_KEY não definida no .env!")
if not ADMIN_PASSWORD:
    print("⚠️  ATENÇÃO: ADMIN_PASSWORD não definida no .env!")

app = Flask(__name__, static_folder='static', static_url_path='')

# CORS: permite requisições de qualquer origem, incluindo file://
# Necessário para o HTML funcionar quando aberto localmente (file://)
CORS(app, resources={r"/api/*": {"origins": "*"}})

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
        if not token or token not in ADMIN_TOKEN_STORE:
            return jsonify({'error': 'Não autorizado'}), 401
        return f(*args, **kwargs)
    return decorated


def _make_download_token(user_id: int, lic_content: str) -> str:
    """Gera token de download temporário (30 min)."""
    token = secrets.token_urlsafe(32)
    # Armazena em memória (simples, funciona para poucos usuários)
    if not hasattr(app, '_download_tokens'):
        app._download_tokens = {}
    app._download_tokens[token] = {
        'user_id':     user_id,
        'lic_content': lic_content,
        'expires_at':  datetime.now(timezone.utc) + timedelta(minutes=30)
    }
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
    if '@' not in email:
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
    """Download do arquivo tripabot.lic via token temporário."""
    if not hasattr(app, '_download_tokens'):
        abort(404)

    token_data = app._download_tokens.get(token)
    if not token_data:
        abort(404)

    now = datetime.now(timezone.utc)
    if now > token_data['expires_at']:
        del app._download_tokens[token]
        return jsonify({'error': 'Token expirado. Faça login novamente.'}), 410

    lic_content = token_data['lic_content']
    # Remove token após uso (one-time download)
    del app._download_tokens[token]

    return Response(
        lic_content,
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

    payment_id = create_payment(user['id'], amount=50.0, notes=notes)
    return jsonify({
        'success': True,
        'message': 'Pagamento registrado! Aguarde aprovação (normalmente em 24h).',
        'payment_id': payment_id,
    })


# ─── API Admin ────────────────────────────────────────────────

@app.route('/api/admin/login', methods=['POST'])
def api_admin_login():
    """Login do admin com senha do .env."""
    data = request.get_json(silent=True) or {}
    password = (data.get('password') or '').strip()

    if not ADMIN_PASSWORD or password != ADMIN_PASSWORD:
        return jsonify({'error': 'Senha incorreta'}), 401

    token = secrets.token_urlsafe(32)
    ADMIN_TOKEN_STORE[token] = datetime.now(timezone.utc)
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
    revoke_all_licenses(user_id)
    update_user_status(user_id, 'revoked')
    return jsonify({'success': True})


@app.route('/api/admin/generate-lic/<int:user_id>', methods=['POST'])
@admin_required
def api_admin_generate_lic(user_id):
    """Admin gera licença manual para um usuário (30 ou 365 dias)."""
    data = request.get_json(silent=True) or {}
    days = int(data.get('days', 365))

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


# ─── Main ─────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'True').lower() == 'true'
    print(f"\n{'='*50}")
    print(f"  TripaBot License Server")
    print(f"  Rodando em: http://localhost:{port}")
    print(f"  Painel admin: http://localhost:{port}/admin")
    print(f"{'='*50}\n")
    app.run(host='0.0.0.0', port=port, debug=debug)
