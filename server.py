"""
TripaBot License Server
Flask server para autenticação, geração de licenças e painel admin.

Rotas:
  GET  /                         → Página de registro
  GET  /admin                    → Painel admin
  POST /api/register             → Registra novo usuário + gera trial .lic
  POST /api/login                → Login + retorna .lic mais recente
  GET  /api/verify               → Verifica se licença ainda é válida (online check)
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
import hmac
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
    save_download_token, get_download_token,
    save_device_session, get_user_ip_history, get_all_ip_history,
    update_ip_whitelist, get_ip_whitelist,
    set_email_verify_token, consume_email_verify_token
)
from license_gen import generate_license, verify_license_content

# ─── Configuração ────────────────────────────────────────────
load_dotenv()

SECRET_KEY      = os.environ.get('TRIPABOT_SECRET_KEY', '')
ADMIN_PASSWORD  = os.environ.get('ADMIN_PASSWORD', '')
PIX_KEY         = os.environ.get('PIX_KEY', 'Configure PIX_KEY no .env')
CONTACT_EMAIL   = os.environ.get('CONTACT_EMAIL', '')
APP_VERSION     = '1.5.0'  # Email verification
RESEND_API_KEY  = os.environ.get('RESEND_API_KEY', '')
BASE_URL        = os.environ.get('BASE_URL', 'https://tripabot-production.up.railway.app')
FROM_EMAIL      = os.environ.get('FROM_EMAIL', 'noreply@tripabot.com.br')

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
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = _conn()
    try:
        # A3: Limpa tokens expirados antes de salvar o novo
        _run(conn, "DELETE FROM admin_tokens WHERE expires_at < ?", (now_iso,))
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

def _cleanup_old_login_attempts():
    """M4: Remove tentativas de login com mais de 24h — evita crescimento ilimitado da tabela."""
    from database import _run, _conn
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    conn = _conn()
    try:
        _run(conn, "DELETE FROM login_attempts WHERE created_at < ?", (cutoff,))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

# P1-F: SECRET_KEY obrigatória — para execução se não estiver definida
if not SECRET_KEY:
    raise RuntimeError("TRIPABOT_SECRET_KEY não está definida. Configure no .env ou nas variáveis de ambiente do Railway.")
if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD não está definida. Configure no .env ou nas variáveis de ambiente do Railway.")

app = Flask(__name__, static_folder='static', static_url_path='')

# CORS restrito ao domínio configurado (app 100% online)
_CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*')
CORS(app, resources={r"/api/*": {"origins": _CORS_ORIGINS}})

# P2-F: Headers de segurança em todas as respostas
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' https://tripabot-production.up.railway.app"
    )
    return response

# ─── Helpers ─────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def send_verification_email(email: str, token: str) -> bool:
    """
    Envia email de verificação via Resend.
    Retorna True se enviado com sucesso, False em caso de erro.
    Se RESEND_API_KEY não estiver configurada, loga o link e retorna True
    (modo dev — permite testar sem envio real).
    """
    link = f"{BASE_URL}/api/verify-email?token={token}"

    if not RESEND_API_KEY:
        logger.warning(f"[EMAIL] RESEND_API_KEY não configurada — modo dev. Link: {link}")
        return True  # Em dev, "sucesso" sem envio real

    try:
        import resend
        resend.api_key = RESEND_API_KEY
        params = {
            "from": FROM_EMAIL,
            "to": [email],
            "subject": "Ative sua conta TripaBot 🔬",
            "html": f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
             background:#f0f4f8;margin:0;padding:40px 20px;">
  <div style="max-width:480px;margin:0 auto;background:white;border-radius:16px;
              box-shadow:0 4px 24px rgba(0,0,0,0.10);padding:40px 36px;text-align:center;">
    <div style="font-size:48px;margin-bottom:16px;">🔬</div>
    <h1 style="font-size:22px;color:#222;margin-bottom:8px;">Bem-vindo ao TripaBot!</h1>
    <p style="font-size:14px;color:#666;line-height:1.6;margin-bottom:28px;">
      Confirme seu email para ativar sua conta trial de <strong>30 dias grátis</strong>.
    </p>
    <a href="{link}"
       style="display:inline-block;background:#1565c0;color:white;padding:14px 32px;
              text-decoration:none;border-radius:8px;font-size:15px;font-weight:600;">
      ✅ Ativar Minha Conta
    </a>
    <p style="font-size:12px;color:#aaa;margin-top:24px;">
      Link válido por 24 horas.<br>
      Se você não criou esta conta, ignore este email.
    </p>
    <hr style="border:none;border-top:1px solid #f0f0f0;margin:24px 0;">
    <p style="font-size:11px;color:#ccc;">
      TripaBot — Ferramenta de apoio clínico para residentes<br>
      <a href="{BASE_URL}" style="color:#bbb;">{BASE_URL}</a>
    </p>
  </div>
</body>
</html>""",
        }
        resend.Emails.send(params)
        logger.info(f"[EMAIL] Verificação enviada para {_mask_email(email)}")
        return True
    except Exception as e:
        logger.error(f"[EMAIL] Erro ao enviar verificação: {e}")
        return False


def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def _mask_email(email: str) -> str:
    """P2-E: Anonimiza email para logs (ex: jo***@gmail.com)."""
    if not email or '@' not in email:
        return '***'
    local, domain = email.split('@', 1)
    return local[:2] + '***@' + domain


def _get_client_ip() -> str:
    """Extrai IP real do cliente (considera X-Forwarded-For do Railway)."""
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or 'unknown'


def admin_required(f):
    """Decorator que exige token de admin válido (apenas via header, nunca query string)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # P1-B: Apenas header — token em query string expõe em logs do servidor
        token = request.headers.get('X-Admin-Token')
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



@app.route('/app', methods=['GET', 'POST'])
def app_online():
    """
    Serve tripabot.html para uso online.
    P1-C: Token aceito via POST body (JSON) ou query string como fallback.
    POST é preferível pois não expõe o token em logs do servidor.
    """
    # Tenta POST body primeiro (mais seguro), depois query string (compatibilidade)
    token = ''
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        token = data.get('token', '').strip()
    if not token:
        token = request.args.get('token', '').strip()

    if not token:
        # Retorna página de erro amigável (não JSON)
        return Response(
            '<html><body style="font-family:sans-serif;padding:40px;text-align:center">'
            '<h2>⚠️ Acesso inválido</h2><p>Faça login em '
            '<a href="/">tripabot.com.br</a> para acessar o app.</p></body></html>',
            mimetype='text/html', status=400
        )

    # Verifica se token é válido (one-time-use — consumido aqui)
    token_data = get_download_token(token)
    if not token_data:
        return Response(
            '<html><body style="font-family:sans-serif;padding:40px;text-align:center">'
            '<h2>⏰ Link expirado</h2><p>Faça login novamente em '
            '<a href="/">tripabot.com.br</a>.</p></body></html>',
            mimetype='text/html', status=401
        )

    # Lê o HTML
    html_path = os.path.join(app.static_folder, 'tripabot.html')
    if not os.path.exists(html_path):
        return jsonify({'error': 'Arquivo não encontrado'}), 404

    with open(html_path, 'r', encoding='utf-8') as f:
        html_content = f.read()

    # Busca dados do usuário para o menu de conta
    user = get_user_by_id(token_data['user_id'])
    lic_data = {}
    try:
        import base64 as _b64, json as _json
        payload_b64 = token_data['lic_content']
        lic_data = _json.loads(_b64.b64decode(payload_b64).decode())
    except Exception:
        pass

    user_info = {
        'email':         user['email'] if user else '',
        'plan':          lic_data.get('plan', user['status'] if user else 'trial'),
        'expires_at':    lic_data.get('expires', ''),
        'contact_email': CONTACT_EMAIL,
        'version':       APP_VERSION,
    }

    # Injeta licença + info do usuário (json.dumps escapa automaticamente)
    injection = (
        f"\n<script>"
        f"window.__LIC_CONTENT__ = {json.dumps(token_data['lic_content'])};"
        f"window.__USER_INFO__ = {json.dumps(user_info)};"
        f"</script>\n"
    )
    html_content = html_content.replace('</head>', f'{injection}</head>')

    return Response(html_content, mimetype='text/html')


# ─── API Pública ─────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def api_register():
    """Registra novo usuário e gera trial de 30 dias."""
    # C2: Rate limiting — previne criação em massa de contas falsas
    ip = _get_client_ip()
    if _rate_limit_check(ip):
        return jsonify({'error': 'Muitas tentativas. Aguarde alguns minutos antes de criar uma nova conta.'}), 429

    data = request.get_json(silent=True) or {}
    email    = (data.get('email') or '').strip().lower()
    password = (data.get('password') or '').strip()
    name     = (data.get('name') or '').strip()

    # P2-C: Limites de comprimento
    if len(email) > 254 or len(password) > 128 or len(name) > 100:
        return jsonify({'error': 'Dados muito longos'}), 400
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

    # C1: Verificação de email — gera token de ativação (24h)
    verify_token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
    set_email_verify_token(user['id'], verify_token, expires)

    # Envia email de confirmação
    email_sent = send_verification_email(email, verify_token)
    if not email_sent:
        logger.error(f"[REGISTER] Falha ao enviar email para {_mask_email(email)}")
        # Mesmo com falha no email, conta foi criada — não reverter (pode reenviar depois)

    return jsonify({
        'success': True,
        'email_pending': True,
        'message': 'Conta criada! Verifique seu email para ativar o TripaBot.',
        'email': email,
    }), 201


@app.route('/api/verify-email')
def api_verify_email():
    """
    C1: Ativa conta após clique no link de verificação de email.
    Gera licença trial de 30 dias e redireciona para o app.
    """
    from flask import redirect
    token = request.args.get('token', '').strip()

    if not token or len(token) > 128:
        return Response("""
            <html><body style="font-family:sans-serif;padding:60px;text-align:center">
            <h2>⚠️ Link inválido</h2>
            <p>Este link é inválido ou já foi utilizado.</p>
            <a href="/">Criar nova conta</a>
            </body></html>""", mimetype='text/html', status=400)

    user = consume_email_verify_token(token)

    if not user:
        return Response("""
            <html><body style="font-family:sans-serif;padding:60px;text-align:center">
            <h2>⏰ Link expirado</h2>
            <p>Este link expirou (válido por 24h) ou já foi utilizado.</p>
            <p>Crie uma nova conta ou entre em contato com o suporte.</p>
            <a href="/">← Voltar ao início</a>
            </body></html>""", mimetype='text/html', status=400)

    # Gera licença trial de 30 dias agora que o email foi verificado
    email = user['email']
    lic = generate_license(email, days=30)
    save_license(user['id'], email, lic['issued_at'], lic['expires_at'], lic['plan'], lic['lic_content'])
    update_user_trial(user['id'], lic['expires_at'])

    # Gera token de acesso e redireciona direto para o app
    dl_token = _make_download_token(user['id'], lic['lic_content'])
    logger.info(f"[VERIFY-EMAIL] ✅ Email verificado: {_mask_email(email)}")

    return redirect(f'/app?token={dl_token}')


@app.route('/api/login', methods=['POST'])
def api_login():
    """Login do usuário. Retorna token de download da licença mais recente."""
    # P1-A: Rate limiting em /api/login (reutiliza as funções do admin)
    ip = _get_client_ip()
    if _rate_limit_check(ip):
        return jsonify({'error': 'Muitas tentativas. Aguarde 5 minutos.'}), 429

    data = request.get_json(silent=True) or {}
    email    = (data.get('email') or '').strip().lower()
    password = (data.get('password') or '').strip()

    # P2-C: Limites de comprimento
    if len(email) > 254 or len(password) > 128:
        return jsonify({'error': 'Dados inválidos'}), 400
    if not email or not password:
        return jsonify({'error': 'Email e senha são obrigatórios'}), 400

    user = get_user_by_email(email)
    if not user or not check_password(password, user['password_hash']):
        _rate_limit_record(ip)  # Registra falha
        return jsonify({'error': 'Email ou senha incorretos'}), 401

    _rate_limit_clear(ip)  # Login bem-sucedido limpa tentativas

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

    # P2-C: Limites de comprimento (lic_content base64 de ~500 bytes → ~700 chars)
    if len(lic_content) > 4096 or len(email) > 254:
        return jsonify({'valid': False, 'reason': 'invalid_format'}), 400

    logger.info(f"[VERIFY] Request from {_mask_email(email)}")

    if not lic_content or not email:
        return jsonify({'valid': False, 'reason': 'missing_data'}), 400

    # Verifica assinatura HMAC e expiração (única verificação criptográfica — cliente não tem a chave)
    result = verify_license_content(lic_content)
    if not result['valid']:
        logger.warning(f"[VERIFY] Inválido ({result.get('reason')}): {_mask_email(email)}")
        return jsonify(result)

    # Bug 3: Garante que o email do request bate com o email DENTRO da licença assinada
    # (impede usar licença de A com email de B para injetar telemetria incorreta)
    if result.get('email') != email:
        logger.warning(f"[VERIFY] Email mismatch: req={_mask_email(email)} lic={_mask_email(result.get('email','?'))}")
        return jsonify({'valid': False, 'reason': 'email_mismatch'})

    # Verifica se usuário foi revogado no banco
    user = get_user_by_email(email)
    if not user:
        logger.warning(f"[VERIFY] Usuário não encontrado: {_mask_email(email)}")
        return jsonify({'valid': False, 'reason': 'user_not_found'})

    if user['status'] == 'revoked':
        logger.warning(f"[VERIFY] ❌ Revogado: {_mask_email(email)}")
        return jsonify({'valid': False, 'reason': 'revoked'})

    # Verifica se a licença específica foi revogada
    try:
        payload = json.loads(base64.b64decode(lic_content).decode())
        issued = payload.get('issued')
        if is_license_revoked(email, issued):
            logger.warning(f"[VERIFY] ❌ Licença revogada: {_mask_email(email)}")
            return jsonify({'valid': False, 'reason': 'license_revoked'})
    except Exception:
        return jsonify({'valid': False, 'reason': 'invalid_format'})

    logger.info(f"[VERIFY] ✅ Válido: {_mask_email(email)}")
    update_last_verified(user['id'])

    # Registra IP + timestamp para IP telemetry
    ip = _get_client_ip()
    user_agent = request.headers.get('User-Agent', '')
    save_device_session(email, ip, user_agent)

    return jsonify({**result, 'email': email})



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
    cutoff_24h = (now - timedelta(hours=24)).isoformat()
    conn = _conn()
    try:
        # M4: Limpa registros antigos (>24h) para evitar crescimento ilimitado
        try:
            _run(conn, "DELETE FROM login_attempts WHERE created_at < ?", (cutoff_24h,))
            conn.commit()
        except Exception:
            pass
        cur = _run(conn, """
            SELECT COUNT(*) as cnt FROM login_attempts
            WHERE ip=? AND created_at > ?
        """, (ip, window_start))
        row = _one(cur)
        return (row['cnt'] if row else 0) >= 5
    except Exception:
        return True  # P2-A: Falha fechada — se banco cair, bloquear por segurança
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
    ip = _get_client_ip()

    if _rate_limit_check(ip):
        logger.warning(f"[ADMIN] Rate limit: IP {ip}")
        return jsonify({'error': 'Muitas tentativas. Aguarde 5 minutos.'}), 429

    data = request.get_json(silent=True) or {}
    password = (data.get('password') or '').strip()

    # P1-E: Comparação timing-safe para prevenir timing attacks
    # Ambos devem ser strings não-vazias
    if not password or not ADMIN_PASSWORD or not hmac.compare_digest(password, ADMIN_PASSWORD):
        _rate_limit_record(ip)
        logger.warning(f"[ADMIN] Senha incorreta: IP {ip}")
        return jsonify({'error': 'Senha incorreta'}), 401

    _rate_limit_clear(ip)
    token = secrets.token_urlsafe(32)
    _admin_token_save(token)
    logger.info(f"[ADMIN] Login: IP {ip}")
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

    return jsonify({
        'success': True,
        'email':       email,
        'expires_at':  lic['expires_at'],
        'message': f"Licença aprovada para {email}. O usuário pode fazer login para acessar o app.",
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


@app.route('/api/admin/ip-history/<email>')
@admin_required
def api_admin_ip_history(email):
    """Mostra histórico de IPs de um usuário específico."""
    email = email.lower().strip()
    ip_history = get_user_ip_history(email, days=30)
    return jsonify({'email': email, 'ip_history': ip_history})


@app.route('/api/admin/whitelist/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def api_admin_whitelist(user_id):
    """Lê ou atualiza a lista de IPs confiáveis de um usuário."""
    if request.method == 'GET':
        whitelist = get_ip_whitelist(user_id)
        return jsonify({'user_id': user_id, 'ip_whitelist': whitelist})

    data = request.get_json(silent=True) or {}
    raw = data.get('ip_whitelist', '')
    # Limpa: remove espaços extras, valida formato mínimo
    ips = [ip.strip() for ip in raw.replace('\n', ',').split(',') if ip.strip()]
    clean = ','.join(ips)
    update_ip_whitelist(user_id, clean)
    logger.info(f"[ADMIN] Whitelist atualizada: user_id={user_id} ips={clean}")
    return jsonify({'success': True, 'ip_whitelist': clean})


@app.route('/api/admin/fraud-report')
@admin_required
def api_admin_fraud_report():
    """
    Relatório de detecção de fraude.
    Retorna usuários com múltiplos IPs, excluindo IPs whitelistados da contagem.
    """
    # P2-D: Validação de range nos parâmetros de query
    days = max(1, min(request.args.get('days', 30, type=int), 365))
    min_ips = max(1, min(request.args.get('min_ips', 3, type=int), 100))

    all_history = get_all_ip_history(days=days)

    result = []
    for item in all_history:
        all_ips = [ip.strip() for ip in (item.get('ips') or '').split(',') if ip.strip()]
        whitelist = [ip.strip() for ip in (item.get('ip_whitelist') or '').split(',') if ip.strip()]

        trusted = [ip for ip in all_ips if ip in whitelist]
        suspicious = [ip for ip in all_ips if ip not in whitelist]
        unique_suspicious = len(set(suspicious))

        result.append({
            'email': item['email'],
            'unique_ips': item['unique_ips'],
            'unique_suspicious': unique_suspicious,
            'trusted_ips': list(set(trusted)),
            'suspicious_ips': list(set(suspicious)),
            'all_ips': list(set(all_ips)),
            'risk_level': 'high' if unique_suspicious >= 10 else 'medium' if unique_suspicious >= 4 else 'low'
        })

    # Ordena por IPs suspeitos
    result.sort(key=lambda x: x['unique_suspicious'], reverse=True)
    suspicious_count = sum(1 for r in result if r['unique_suspicious'] >= min_ips)

    return jsonify({
        'total_users': len(result),
        'suspicious_count': suspicious_count,
        'days_analyzed': days,
        'users': result
    })


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

    # Gera token para /app (acesso online imediato)
    dl_token = _make_download_token(user_id, lic['lic_content'])

    return jsonify({
        'success': True,
        'email':       email,
        'expires_at':  expires,
        'plan':        lic['plan'],
        'app_url': f"/app?token={dl_token}",
        'message': f"Licença gerada para {email}. O usuário pode fazer login para acessar o app.",
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
