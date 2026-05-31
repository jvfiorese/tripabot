# -*- coding: utf-8 -*-
"""
TripaBot Setup Script
Configura o TripaBot.html com a chave de licença do servidor.

Execute este script UMA VEZ após configurar o .env:
    python setup_tripabot.py

Isso irá:
1. Ler a TRIPABOT_SECRET_KEY do arquivo .env
2. Embutir a chave (dividida em partes) no TripaBot.html
3. Gerar o TripaBot_licenciado.html pronto para distribuição

O TripaBot_licenciado.html é o arquivo que você distribui para os usuários.
"""

import os
import sys
import shutil
from pathlib import Path

# Diretórios
SERVER_DIR = Path(__file__).parent
PROJECT_DIR = SERVER_DIR.parent
TRIPABOT_SRC  = PROJECT_DIR / 'TripaBot.html'
TRIPABOT_DEST = SERVER_DIR / 'static' / 'tripabot.html'
ENV_FILE      = SERVER_DIR / '.env'


def read_env():
    """Lê variáveis do .env sem usar python-dotenv."""
    env = {}
    if not ENV_FILE.exists():
        return env
    for line in ENV_FILE.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            env[k.strip()] = v.strip()
    return env


def inject_license_code(html_content: str, secret_key: str, server_url: str = 'http://localhost:5000') -> str:
    """
    Injeta o código de validação de licença no TripaBot.html.
    Substitui o placeholder __TB_LICENSE_CODE__ pelo código real.
    """
    # Divide a chave em 4 partes (ofuscação leve)
    p1 = secret_key[0:16]
    p2 = secret_key[16:32]
    p3 = secret_key[32:48]
    p4 = secret_key[48:]
    # Remove trailing slash da URL
    server_url = server_url.rstrip('/')

    # Código de validação a ser injetado
    license_js = f"""
        // ======================================================
        // SISTEMA DE LICENÇA TRIPABOT — NÃO MODIFIQUE
        // ======================================================

        // URL do servidor de licenças (absoluta, funciona offline e online)
        const _tbServer = '{server_url}';

        // Chave de verificação (distribuída com o arquivo)
        function _tbK() {{
            const _a='{p1}',_b='{p2}',_c='{p3}',_d='{p4}';
            return _a+_b+_c+_d;
        }}

        // Calcula HMAC-SHA256 (igual ao servidor Python)
        async function _tbHmac(msg) {{
            const enc = new TextEncoder();
            const key = await crypto.subtle.importKey(
                'raw', enc.encode(_tbK()),
                {{name:'HMAC',hash:'SHA-256'}}, false, ['sign']
            );
            const buf = await crypto.subtle.sign('HMAC', key, enc.encode(msg));
            return Array.from(new Uint8Array(buf))
                .map(b => b.toString(16).padStart(2,'0')).join('');
        }}

        // Valida conteúdo do arquivo .lic
        async function tbValidateLicContent(licContent) {{
            try {{
                const p = JSON.parse(atob(licContent.trim()));
                if (!p.email || !p.issued || !p.expires || !p.sig) {{
                    return {{authorized:false, reason:'invalid_format'}};
                }}
                const toSign = `${{p.email}}|${{p.issued}}|${{p.expires}}|${{p.plan}}|${{p.nonce}}`;
                const expected = await _tbHmac(toSign);
                if (expected !== p.sig) return {{authorized:false, reason:'invalid_signature'}};
                const now = new Date(), exp = new Date(p.expires);
                if (now > exp) return {{authorized:false, reason:'expired', expires:p.expires, email:p.email}};
                return {{authorized:true, email:p.email, expires:p.expires, plan:p.plan}};
            }} catch(e) {{
                return {{authorized:false, reason:'invalid_format'}};
            }}
        }}

        // Verifica licença online (quando tem internet).
        // Usa URL absoluta para funcionar mesmo quando HTML é aberto como arquivo local.
        // Retorna resposta do servidor se conectado, ou null se offline.
        // OFFLINE-FIRST: falha de conexão = permitir acesso local.
        // Só bloqueia se o servidor EXPLICITAMENTE rejeitar (revogado, etc).
        async function tbVerifyOnline(licContent) {{
            try {{
                const p = JSON.parse(atob(licContent.trim()));
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 8000); // 8s timeout
                const res = await fetch(_tbServer + '/api/verify', {{
                    method:'POST',
                    headers:{{'Content-Type':'application/json'}},
                    body: JSON.stringify({{lic_content: licContent, email: p.email}}),
                    signal: controller.signal
                }});
                clearTimeout(timeout);
                if (res.ok) return await res.json();
                // Servidor respondeu mas com erro HTTP → retorna resposta de erro
                return {{valid: false, reason: 'server_error', status: res.status}};
            }} catch(e) {{
                // Sem conexão / timeout / servidor offline → null = modo offline
                return null;
            }}
        }}

        // Mostra tela de seleção de licença
        function tbShowLicenseScreen(reason, expires) {{
            document.getElementById('tb-app').style.display = 'none';
            const screen = document.getElementById('tb-license-screen');
            screen.style.display = 'flex';

            const msgEl = document.getElementById('tb-lic-msg');
            const siteUrl = _tbServer;
            if (reason === 'no_license') {{
                msgEl.innerHTML = 'Selecione seu arquivo <strong>tripabot.lic</strong> para continuar.';
            }} else if (reason === 'expired') {{
                const d = expires ? new Date(expires).toLocaleDateString('pt-BR') : '—';
                msgEl.innerHTML = `Sua licença expirou em <strong>${{d}}</strong>.<br>Acesse o site para renovar.`;
            }} else if (reason === 'invalid_signature') {{
                msgEl.innerHTML = '⚠️ Arquivo de licença inválido ou corrompido.<br>Faça login no site para baixar novamente.';
            }} else if (reason === 'revoked') {{
                msgEl.innerHTML = '⊘ <strong>Acesso Revogado</strong><br>Sua licença foi cancelada pelo administrador.<br>Entre em contato para mais informações.';
            }} else if (reason === 'server_error') {{
                msgEl.innerHTML = '⚠️ <strong>Erro no Servidor</strong><br>Não conseguimos validar sua licença.<br>Tente novamente mais tarde.';
            }} else if (reason === 'connection_failed') {{
                msgEl.innerHTML = '📡 <strong>Sem Conexão</strong><br>Verifique sua internet e tente novamente.';
            }} else {{
                msgEl.innerHTML = 'Arquivo de licença inválido.<br>Faça login no site para baixar novamente.';
            }}
        }}

        // Desbloqueia o app
        function tbUnlockApp(email, expires) {{
            document.getElementById('tb-license-screen').style.display = 'none';
            document.getElementById('tb-app').style.display = 'block';

            // Mostra info no rodapé (opcional)
            const d = new Date(expires).toLocaleDateString('pt-BR');
            console.log(`[TripaBot] Licença válida: ${{email}} até ${{d}}`);
        }}

        // Processo principal de validação
        async function tbInitLicense() {{
            // 1. Tenta ler do cache (localStorage ou sessionStorage)
            let cached = tbReadLic();

            if (!cached) {{
                // Nenhum cache → mostra tela de seleção
                tbShowLicenseScreen('no_license');
                return;
            }}

            // 2. Valida localmente
            let result;
            try {{
                result = await tbValidateLicContent(cached);
            }} catch(e) {{
                // crypto.subtle falhou (file:// sem HTTPS) → tenta só online
                console.warn('[TripaBot] Validação local falhou, modo online:', e);
                try {{
                    const p = JSON.parse(atob(cached.trim()));
                    result = {{ authorized: true, email: p.email||'', expires: p.expires||'', plan: p.plan||'' }};
                }} catch(e2) {{
                    tbClearLic();
                    tbShowLicenseScreen('no_license');
                    return;
                }}
            }}

            if (!result.authorized) {{
                tbClearLic();
                tbShowLicenseScreen(result.reason, result.expires);
                return;
            }}

            // 3. Se online, valida com servidor (detecta revogações)
            let online = null;
            try {{ online = await tbVerifyOnline(cached); }} catch(e) {{ online = null; }}

            // null = offline, permite acesso (offline-first)
            const REASONS_TO_BLOCK = ['revoked', 'license_revoked', 'user_not_found'];
            if (online !== null && !online.valid && REASONS_TO_BLOCK.includes(online.reason)) {{
                tbClearLic();
                tbShowLicenseScreen(online.reason, result.expires);
                return;
            }}

            // 4. Tudo OK!
            tbUnlockApp(result.email, result.expires);

            // 5. Avisa se expira em breve (< 15 dias) — toast não bloqueante
            const now = new Date(), exp = new Date(result.expires);
            const daysLeft = Math.floor((exp - now) / (1000 * 60 * 60 * 24));
            if (daysLeft > 0 && daysLeft <= 15) {{
                setTimeout(() => {{
                    const toast = document.createElement('div');
                    toast.style.cssText = 'position:fixed;bottom:24px;right:24px;background:#e65100;color:white;padding:14px 18px;border-radius:8px;font-size:13px;z-index:99999;max-width:280px;line-height:1.5;box-shadow:0 4px 12px rgba(0,0,0,0.2)';
                    toast.textContent = `⚠️ Sua licença expira em ${{daysLeft}} dia${{daysLeft>1?'s':''}}.`;
                    document.body.appendChild(toast);
                    setTimeout(() => toast.remove(), 8000);
                }}, 2000);
            }}
        }}

        // Mostra erro na tela de licença
        function tbShowErr(msg) {{
            const el = document.getElementById('tb-lic-err');
            if (el) {{ el.textContent = msg; el.style.display = 'block'; }}
        }}

        // Salva licença (tenta localStorage, cai para sessionStorage se falhar)
        function tbSaveLic(content) {{
            try {{ localStorage.setItem('tb_lic_v1', content); return true; }}
            catch(e) {{
                try {{ sessionStorage.setItem('tb_lic_v1', content); return true; }}
                catch(e2) {{ return false; }}
            }}
        }}

        // Lê licença salva
        function tbReadLic() {{
            try {{ return localStorage.getItem('tb_lic_v1'); }} catch(e) {{}}
            try {{ return sessionStorage.getItem('tb_lic_v1'); }} catch(e) {{}}
            return null;
        }}

        // Remove licença salva
        function tbClearLic() {{
            try {{ localStorage.removeItem('tb_lic_v1'); }} catch(e) {{}}
            try {{ sessionStorage.removeItem('tb_lic_v1'); }} catch(e) {{}}
        }}

        // Lê e processa arquivo .lic selecionado pelo usuário
        async function tbLoadLicFile(file) {{
            const btnEl = document.getElementById('tb-lic-btn');
            const errEl = document.getElementById('tb-lic-err');

            // Reseta estado
            if (errEl) errEl.style.display = 'none';
            if (btnEl) {{ btnEl.textContent = '⏳ Lendo arquivo...'; btnEl.disabled = true; }}

            try {{
                // 1. Lê o conteúdo do arquivo
                let content;
                try {{
                    content = await file.text();
                }} catch(e) {{
                    tbShowErr('❌ Não foi possível ler o arquivo. Tente novamente.');
                    return;
                }}

                if (!content || content.trim().length < 10) {{
                    tbShowErr('❌ Arquivo vazio ou inválido.');
                    return;
                }}

                // 2. Valida localmente (assinatura + expiração)
                if (btnEl) btnEl.textContent = '⏳ Validando assinatura...';
                let result;
                try {{
                    result = await tbValidateLicContent(content);
                }} catch(e) {{
                    // crypto.subtle pode falhar em file:// sem HTTPS
                    // Tenta continuar com verificação online
                    console.warn('[TripaBot] Validação local falhou, tentando online:', e);
                    result = {{ authorized: true, email: '', expires: '', plan: '' }};
                    try {{
                        const p = JSON.parse(atob(content.trim()));
                        result.email = p.email || '';
                        result.expires = p.expires || '';
                    }} catch(e2) {{
                        tbShowErr('❌ Arquivo .lic inválido ou corrompido.');
                        return;
                    }}
                }}

                if (!result.authorized) {{
                    if (result.reason === 'expired') {{
                        const d = result.expires ? new Date(result.expires).toLocaleDateString('pt-BR') : '?';
                        tbShowErr(`❌ Licença expirada em ${{d}}. Faça login no site para renovar.`);
                    }} else if (result.reason === 'invalid_signature') {{
                        tbShowErr('❌ Arquivo inválido. Baixe um novo fazendo login no site.');
                    }} else {{
                        tbShowErr('❌ Arquivo .lic inválido. Baixe um novo fazendo login no site.');
                    }}
                    return;
                }}

                // 3. Verifica online (detecta revogação)
                if (btnEl) btnEl.textContent = '⏳ Verificando com servidor...';
                let online = null;
                try {{
                    online = await tbVerifyOnline(content.trim());
                }} catch(e) {{
                    online = null; // offline = permitido
                }}

                const BLOCK = ['revoked', 'license_revoked', 'user_not_found'];
                if (online !== null && !online.valid && BLOCK.includes(online.reason)) {{
                    tbShowLicenseScreen(online.reason, result.expires);
                    return;
                }}

                // 4. Salva e abre o app
                tbSaveLic(content.trim());
                tbUnlockApp(result.email, result.expires);

            }} catch(e) {{
                console.error('[TripaBot] Erro inesperado:', e);
                tbShowErr('❌ Erro inesperado: ' + (e.message || 'tente novamente'));
            }} finally {{
                if (btnEl) {{ btnEl.textContent = '📂 Selecionar tripabot.lic'; btnEl.disabled = false; }}
            }}
        }}

        // Inicia sistema de licença — funciona mesmo se DOM já carregou
        if (document.readyState === 'loading') {{
            window.addEventListener('DOMContentLoaded', tbInitLicense);
        }} else {{
            // DOM já está pronto (script carregado de forma diferida)
            tbInitLicense();
        }}
        // ======================================================
        // FIM SISTEMA DE LICENÇA
        // ======================================================
    """

    license_css = """
        /* ── TELA DE LICENÇA TRIPABOT ─────────────────────── */
        #tb-license-screen {
            display: none;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: #f0f4f8;
            z-index: 9999;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        }
        .tb-lic-card {
            background: white;
            border-radius: 16px;
            box-shadow: 0 4px 24px rgba(0,0,0,0.12);
            padding: 40px 36px;
            width: 100%;
            min-width: 280px;
            max-width: 440px;
            text-align: center;
        }
        .tb-lic-logo { font-size: 36px; margin-bottom: 8px; }
        .tb-lic-card h2 { font-size: 24px; color: #e85252; font-weight: 800; margin-bottom: 4px; }
        .tb-lic-card .sub { font-size: 13px; color: #999; margin-bottom: 28px; }
        #tb-lic-msg { font-size: 14px; color: #555; line-height: 1.7; margin-bottom: 20px;
                       background: #f8f9fa; border-radius: 8px; padding: 12px 16px; }
        #tb-lic-msg strong { color: #e85252; }
        .tb-lic-btn {
            display: block; padding: 13px 28px;
            background: #e85252; color: white;
            border: none; border-radius: 8px;
            font-size: 15px; font-weight: 600; cursor: pointer;
            margin-bottom: 10px; width: 100%;
            text-decoration: none;
        }
        .tb-lic-btn:hover { background: #c94444; }
        .tb-lic-btn:disabled { background: #ccc; cursor: not-allowed; }
        .tb-lic-btn-outline {
            display: block; padding: 11px 28px;
            background: white; color: #e85252;
            border: 2px solid #e85252; border-radius: 8px;
            font-size: 14px; font-weight: 600; cursor: pointer;
            margin-bottom: 10px; width: 100%;
            text-decoration: none; box-sizing: border-box;
        }
        .tb-lic-btn-outline:hover { background: #fff5f5; }
        #tb-lic-err { color: #c62828; font-size: 12px; display: none; margin-top: 8px;
                       background: #ffebee; padding: 8px 12px; border-radius: 6px; }
        .tb-lic-divider { display: flex; align-items: center; gap: 10px;
                           margin: 16px 0; color: #ccc; font-size: 12px; }
        .tb-lic-divider::before, .tb-lic-divider::after {
            content: ''; flex: 1; height: 1px; background: #eee; }
        .tb-lic-footer { margin-top: 20px; font-size: 11px; color: #bbb; }
    """

    license_html = f"""
    <!-- TELA DE LICENÇA TRIPABOT -->
    <div id="tb-license-screen">
        <div class="tb-lic-card">
            <div class="tb-lic-logo">🩺</div>
            <h2>TripaBot</h2>
            <p class="sub">Padronização Médica · Gastroenterologia HBDF</p>

            <div id="tb-lic-msg">
                Selecione seu arquivo <strong>tripabot.lic</strong> para continuar.
            </div>

            <!-- Selecionar .lic existente -->
            <input type="file" id="tb-lic-input" accept=".lic" style="display:none"
                onchange="if(this.files[0]) tbLoadLicFile(this.files[0])">
            <button id="tb-lic-btn" class="tb-lic-btn"
                onclick="document.getElementById('tb-lic-input').click()">
                📂 Selecionar tripabot.lic
            </button>
            <div id="tb-lic-err"></div>

            <div class="tb-lic-divider">ou</div>

            <!-- Criar conta nova -->
            <a href="{server_url}" target="_blank" class="tb-lic-btn-outline">
                ✨ Criar conta grátis (30 dias)
            </a>

            <!-- Já tem conta, renovar -->
            <a href="{server_url}/?tab=login" target="_blank" style="
                display: block; font-size: 13px; color: #888;
                text-decoration: none; margin-top: 8px; padding: 6px;">
                Já tenho conta → Entrar e baixar licença
            </a>

            <div class="tb-lic-footer">30 dias grátis · depois R$ 50/ano</div>
        </div>
    </div>

    <!-- APP (oculto até validação) -->
    <div id="tb-app" style="display:none">
    """

    # ── Injeção com validação de sucesso ─────────────────────────
    original = html_content

    # 1. CSS
    css_marker = '</style>\n</head>'
    if css_marker not in html_content:
        # Tenta variante sem espaços no início da linha
        css_marker = '</style>\n</head>'
    new_content = html_content.replace(css_marker, license_css + '\n' + css_marker, 1)
    if new_content == html_content:
        print("⚠️  Aviso: Não encontrou </style></head> para injetar CSS. Adicionando antes de </head>.")
        new_content = html_content.replace('</head>', '<style>' + license_css + '</style>\n</head>', 1)
    html_content = new_content

    # 2. HTML da tela de licença
    body_marker = '<body>'
    # Procura qualquer variante de abertura do body
    import re as _re
    body_match = _re.search(r'<body[^>]*>', html_content)
    if body_match:
        end_of_body_tag = body_match.end()
        html_content = html_content[:end_of_body_tag] + '\n' + license_html + html_content[end_of_body_tag:]
    else:
        print("❌ ERRO: Não encontrou <body> no HTML. Verifique o TripaBot.html original.")
        sys.exit(1)

    # 3. Fecha o div do app antes de </body>
    html_content = html_content.replace('\n</body>', '\n    </div><!-- #tb-app -->\n</body>', 1)

    # 4. Injeta JS antes do último </script>
    last_script_close = html_content.rfind('</script>')
    if last_script_close == -1:
        print("❌ ERRO: Não encontrou </script> no HTML.")
        sys.exit(1)
    html_content = html_content[:last_script_close] + license_js + '\n    </script>' + html_content[last_script_close + len('</script>'):]

    # 5. Valida que injeção foi bem-sucedida
    missing = []
    if 'tbInitLicense' not in html_content: missing.append('tbInitLicense')
    if 'tb-license-screen' not in html_content: missing.append('tb-license-screen')
    if 'tb-app' not in html_content: missing.append('tb-app')
    if missing:
        print(f"❌ ERRO CRÍTICO: Injeção incompleta! Faltando: {missing}")
        print("   O arquivo HTML pode ter estrutura diferente do esperado.")
        sys.exit(1)

    return html_content


def main():
    print("=" * 55)
    print("  TripaBot Setup — Configuração de Licença")
    print("=" * 55)

    # 1. Verifica .env
    if not ENV_FILE.exists():
        print(f"\n❌ Arquivo .env não encontrado em:\n   {ENV_FILE}")
        print("\nCrie o arquivo .env copiando .env.example:")
        print("   copy .env.example .env")
        print("   (e depois edite com sua chave secreta)")
        sys.exit(1)

    env = read_env()
    secret_key = env.get('TRIPABOT_SECRET_KEY', '')

    if not secret_key or 'TROQUE_AQUI' in secret_key:
        print("\n❌ TRIPABOT_SECRET_KEY não está configurada no .env!")
        print("   Gere uma chave com:")
        print("   python -c \"import secrets; print(secrets.token_hex(32))\"")
        sys.exit(1)

    if len(secret_key) < 64:
        print(f"\n⚠️  TRIPABOT_SECRET_KEY muito curta ({len(secret_key)} chars). Use no mínimo 64.")
        sys.exit(1)

    print(f"\n✓ Chave secreta: {secret_key[:8]}...{secret_key[-4:]} ({len(secret_key)} chars)")

    # 2. Lê TripaBot.html original
    if not TRIPABOT_SRC.exists():
        print(f"\n❌ TripaBot.html não encontrado em:\n   {TRIPABOT_SRC}")
        sys.exit(1)

    print(f"✓ Lendo TripaBot.html de:\n   {TRIPABOT_SRC}")
    html = TRIPABOT_SRC.read_text(encoding='utf-8')

    # 3. Verifica se já foi configurado
    if 'tbInitLicense' in html:
        print("\n⚠️  TripaBot.html já parece configurado!")
        resp = input("   Reconfigurar mesmo assim? (s/N): ").strip().lower()
        if resp != 's':
            print("   Cancelado.")
            sys.exit(0)

    # 4. Lê URL do servidor
    server_url = env.get('TRIPABOT_SERVER_URL', 'http://localhost:5000').rstrip('/')
    print(f"✓ URL do servidor: {server_url}")
    if not server_url.startswith('https://') and 'localhost' not in server_url and '127.0.0.1' not in server_url:
        print("⚠️  AVISO: TRIPABOT_SERVER_URL não usa HTTPS. Inseguro em produção!")

    # 5. Injeta código de licença
    print("✓ Injetando sistema de licença...")
    html_modificado = inject_license_code(html, secret_key, server_url)

    # 5. Salva saída
    TRIPABOT_DEST.parent.mkdir(parents=True, exist_ok=True)
    TRIPABOT_DEST.write_text(html_modificado, encoding='utf-8')

    print(f"✓ TripaBot licenciado salvo em:\n   {TRIPABOT_DEST}")

    print("\n" + "=" * 55)
    print("  Setup concluído! Próximos passos:")
    print("=" * 55)
    print("""
  1. Inicie o servidor:
     python server.py

  2. Acesse: http://localhost:5000
     (Página de registro para usuários)

  3. Painel admin: http://localhost:5000/admin
     (Para gerenciar usuários e pagamentos)

  4. O arquivo TripaBot que os usuários receberão:
     static/tripabot.html

  Tudo certo! 🎉
""")


if __name__ == '__main__':
    main()
