"""
TripaBot License Server — Gerador de Licenças
Gera arquivos .lic encriptados e assinados com HMAC-SHA256.
"""

import hmac
import hashlib
import json
import base64
import secrets
import os
from datetime import datetime, timedelta, timezone

# Chave secreta lida do ambiente
SECRET_KEY = os.environ.get('TRIPABOT_SECRET_KEY', '')


def _sign(content: str) -> str:
    """Gera assinatura HMAC-SHA256 do conteúdo."""
    return hmac.new(
        SECRET_KEY.encode('utf-8'),
        content.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def generate_license(email: str, days: int) -> dict:
    """
    Gera arquivo de licença encriptado.

    Args:
        email: email do usuário
        days: quantidade de dias de validade (30 = trial, 365 = anual)

    Returns:
        dict com:
            - lic_content: string base64 para salvar como tripabot.lic
            - issued_at: data de emissão (ISO)
            - expires_at: data de expiração (ISO)
            - plan: nome do plano
    """
    if not SECRET_KEY:
        raise ValueError("TRIPABOT_SECRET_KEY não está configurada!")

    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=days)

    issued_at  = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    expires_at = expires.strftime('%Y-%m-%dT%H:%M:%SZ')
    plan       = 'trial_30d' if days <= 30 else 'annual_365d'
    nonce      = secrets.token_hex(16)

    # Conteúdo a ser assinado (ordem fixa e determinística)
    to_sign = f"{email}|{issued_at}|{expires_at}|{plan}|{nonce}"
    signature = _sign(to_sign)

    # Payload completo
    payload = {
        'v':                1,
        'email':            email.lower().strip(),
        'issued':           issued_at,
        'expires':          expires_at,
        'plan':             plan,
        'nonce':            nonce,
        'sig':              signature,
    }

    # Serializa e codifica em base64
    lic_content = base64.b64encode(
        json.dumps(payload, separators=(',', ':')).encode('utf-8')
    ).decode('utf-8')

    return {
        'lic_content': lic_content,
        'issued_at':   issued_at,
        'expires_at':  expires_at,
        'plan':        plan,
    }


def verify_license_content(lic_content: str) -> dict:
    """
    Verifica se um arquivo .lic é válido.
    Usado pelo servidor durante /api/verify.

    Returns:
        dict com 'valid' (bool) e informações adicionais.
    """
    if not SECRET_KEY:
        return {'valid': False, 'reason': 'server_error'}

    try:
        payload = json.loads(base64.b64decode(lic_content).decode('utf-8'))
    except Exception:
        return {'valid': False, 'reason': 'invalid_format'}

    # P2-B: Valida campos obrigatórios antes de acessar (evita KeyError)
    required = ('email', 'issued', 'expires', 'plan', 'nonce', 'sig')
    if not all(payload.get(f) for f in required):
        return {'valid': False, 'reason': 'invalid_format'}

    email   = payload.get('email', '')
    issued  = payload.get('issued', '')
    expires = payload.get('expires', '')
    plan    = payload.get('plan', '')
    nonce   = payload.get('nonce', '')
    sig     = payload.get('sig', '')

    # Recalcula assinatura HMAC
    to_sign = f"{email}|{issued}|{expires}|{plan}|{nonce}"
    expected_sig = _sign(to_sign)

    if not hmac.compare_digest(expected_sig, sig):
        return {'valid': False, 'reason': 'invalid_signature'}

    # Verifica expiração
    try:
        expires_dt = datetime.strptime(expires, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except Exception:
        return {'valid': False, 'reason': 'invalid_date'}

    now = datetime.now(timezone.utc)
    if now > expires_dt:
        return {'valid': False, 'reason': 'expired', 'email': email, 'expires': expires}

    return {'valid': True, 'email': email, 'issued': issued, 'expires': expires, 'plan': plan}
