"""
api/utils/security.py
─────────────────────────────────────────────────────────────────────────────
Utilitários de segurança do PreviSwit — inspirados no fluxo do DefectDojo.

Padrão de segurança extraído do DefectDojo:
  • Token de reset gerado via HMAC-SHA256 sobre (user_id + timestamp + hash da senha)
  • Token codificado em base64-urlsafe com ID de utilizador como uidb64 (como Django faz)
  • Expiração configurável (padrão: 1 hora = 3600 segundos)
  • Envio de e-mail com link que inclui uidb64 + token na querystring
  • Ao usar o token, ele é invalidado (single-use via timestamp de criação)
  • Rate limiting conceptual: o endpoint não revela se o e-mail existe (anti-enumeration)

Adaptações para FastAPI / Python puro:
  • Sem Django ORM — usa ficheiro JSON como "base de dados" de tokens (pode ser
    substituído por Redis ou DB real em produção)
  • Sem Django's PasswordResetTokenGenerator — reimplementado com hmac + hashlib
  • Envio de e-mail via smtplib assíncrono (aiosmtplib) com fallback para debug
  • Hashing de passwords com passlib (bcrypt)
"""

import os
import json
import hmac
import base64
import hashlib
import secrets
import logging
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Tuple

from passlib.context import CryptContext

logger = logging.getLogger(__name__)

# ─── Configurações ──────────────────────────────────────────────────────────

# Lidas do ambiente (.env ou variáveis de sistema)
SECRET_KEY: str = os.getenv("SECRET_KEY", "insecure-dev-key-change-in-production")
SITE_URL: str = os.getenv("SITE_URL", "http://localhost:8000")
SITE_NAME: str = os.getenv("SITE_NAME", "PreviSwit ASPM")

# Tempo de expiração do token de reset (segundos) — DefectDojo usa PASSWORD_RESET_TIMEOUT
# Padrão Django = 259200 (3 dias), aqui usamos 3600 (1 hora) por maior segurança
PASSWORD_RESET_TIMEOUT: int = int(os.getenv("PASSWORD_RESET_TIMEOUT", "3600"))

# Configurações SMTP (opcionais — fallback para log em modo debug)
SMTP_HOST: str = os.getenv("SMTP_HOST", "")
SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER: str = os.getenv("SMTP_USER", "")
SMTP_PASS: str = os.getenv("SMTP_PASS", "")
EMAIL_FROM: str = os.getenv("EMAIL_FROM", "noreply@previswit.local")

# Armazenamento de tokens de reset (ficheiro JSON — substituir por Redis em produção)
_TOKENS_FILE = Path(os.getenv("DATA_DIR", "data")) / "reset_tokens.json"

# ─── Hashing de Passwords (bcrypt via passlib) ───────────────────────────────

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    """Retorna o hash bcrypt de uma password em texto plano."""
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verifica se a password em texto plano corresponde ao hash armazenado."""
    return _pwd_context.verify(plain, hashed)


# ─── Geração e Validação de Tokens de Reset ─────────────────────────────────

class PasswordResetTokenGenerator:
    """
    Gerador de tokens de reset seguro.

    Inspirado no Django's PasswordResetTokenGenerator mas sem ORM.
    Usa HMAC-SHA256 sobre: SECRET_KEY + user_id + timestamp + password_hash_fragment
    para garantir que:
      1. O token só é válido para aquele utilizador específico
      2. O token expira após PASSWORD_RESET_TIMEOUT segundos
      3. O token é invalidado após a password ser alterada (single-use)
    """

    _SALT = "previswit-password-reset"

    def make_token(self, user_id: str, password_hash_fragment: str) -> Tuple[str, str]:
        """
        Gera um par (uidb64, token) para o link de reset.

        Args:
            user_id: ID único do utilizador (string ou int convertido)
            password_hash_fragment: Fragmento do hash da password atual
                                    (primeiros 10 chars) — invalida o token
                                    automaticamente após o reset

        Returns:
            Tuple (uidb64, token) onde:
              - uidb64: user_id codificado em base64 urlsafe (como Django faz)
              - token:  HMAC hex de 32 bytes + timestamp encoded
        """
        timestamp = int(datetime.now(timezone.utc).timestamp())
        uidb64 = base64.urlsafe_b64encode(str(user_id).encode()).decode().rstrip("=")

        token = self._make_hash_value(user_id, timestamp, password_hash_fragment)
        # Formato: <timestamp_hex>-<hmac_hex> (mesmo padrão do Django)
        token_str = f"{timestamp:x}-{token}"
        return uidb64, token_str

    def _make_hash_value(self, user_id: str, timestamp: int, pwd_fragment: str) -> str:
        """Cria o valor HMAC que compõe o token."""
        key = f"{self._SALT}:{SECRET_KEY}".encode()
        message = f"{user_id}:{timestamp}:{pwd_fragment}".encode()
        return hmac.new(key, message, hashlib.sha256).hexdigest()

    def check_token(
        self,
        token_str: str,
        user_id: str,
        password_hash_fragment: str,
    ) -> bool:
        """
        Valida um token de reset.

        Verifica:
          1. Formato correto (timestamp-hmac)
          2. HMAC válido (não adulterado)
          3. Não expirado (< PASSWORD_RESET_TIMEOUT segundos)
          4. Password ainda não alterada (hash_fragment idêntico ao da geração)

        Returns:
            True se o token é válido e não expirou, False caso contrário.
        """
        if not token_str or "-" not in token_str:
            return False

        try:
            ts_hex, provided_hmac = token_str.split("-", 1)
            timestamp = int(ts_hex, 16)
        except (ValueError, TypeError):
            logger.warning("Token de reset com formato inválido para user_id=%s", user_id)
            return False

        # Valida o HMAC (timing-safe comparison)
        expected_hmac = self._make_hash_value(user_id, timestamp, password_hash_fragment)
        if not hmac.compare_digest(expected_hmac, provided_hmac):
            logger.warning("Token de reset com HMAC inválido para user_id=%s", user_id)
            return False

        # Valida a expiração
        now = int(datetime.now(timezone.utc).timestamp())
        age_seconds = now - timestamp
        if age_seconds > PASSWORD_RESET_TIMEOUT:
            logger.info(
                "Token de reset expirado para user_id=%s (idade=%ds, limite=%ds)",
                user_id, age_seconds, PASSWORD_RESET_TIMEOUT,
            )
            return False

        return True

    def decode_uid(self, uidb64: str) -> Optional[str]:
        """Descodifica o uidb64 de volta para o user_id string."""
        try:
            # Adiciona padding se necessário
            padding = 4 - len(uidb64) % 4
            if padding != 4:
                uidb64 += "=" * padding
            return base64.urlsafe_b64decode(uidb64).decode()
        except Exception:
            return None


# Instância singleton (reutilizável em toda a aplicação)
token_generator = PasswordResetTokenGenerator()


# ─── Armazenamento Simples de Tokens (JSON file — substituir por Redis) ──────

def _load_tokens() -> dict:
    """Carrega o store de tokens do ficheiro JSON."""
    if not _TOKENS_FILE.exists():
        return {}
    try:
        return json.loads(_TOKENS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_tokens(tokens: dict) -> None:
    """Persiste o store de tokens no ficheiro JSON."""
    _TOKENS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _TOKENS_FILE.write_text(json.dumps(tokens, indent=2), encoding="utf-8")


def store_reset_token(user_id: str, uidb64: str, token: str) -> None:
    """
    Persiste o par (uidb64, token) no store.

    Em produção, substituir por Redis com TTL = PASSWORD_RESET_TIMEOUT.
    """
    tokens = _load_tokens()
    tokens[user_id] = {
        "uidb64": uidb64,
        "token": token,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_tokens(tokens)


def invalidate_reset_token(user_id: str) -> None:
    """Remove o token de reset de um utilizador (após uso bem-sucedido)."""
    tokens = _load_tokens()
    tokens.pop(str(user_id), None)
    _save_tokens(tokens)


# ─── Envio de E-mail ─────────────────────────────────────────────────────────

def _build_reset_link(uidb64: str, token: str) -> str:
    """Constrói o link de reset completo."""
    return f"{SITE_URL}/reset-password?uid={uidb64}&token={token}"


def _build_email_body(username: str, reset_link: str) -> str:
    """
    Template de e-mail de reset de password.

    Mantém o mesmo tom e estrutura do DefectDojo (forgot_password.tpl),
    mas em HTML puro para clientes modernos.
    """
    expiry_minutes = PASSWORD_RESET_TIMEOUT // 60
    return f"""
Olá {username},

Recebemos um pedido de recuperação de password para a sua conta em {SITE_NAME}.

Para definir uma nova password, clique no link abaixo:
{reset_link}

⚠️ Este link expira em {expiry_minutes} minutos.

Se não foi você a solicitar este reset, ignore este e-mail.
A sua password não foi alterada.

Atenciosamente,
Equipa {SITE_NAME}

---
Por razões de segurança, nunca partilhe este link com ninguém.
""".strip()


async def send_reset_email(to_email: str, username: str, reset_link: str) -> bool:
    """
    Envia o e-mail de recuperação de password de forma assíncrona.

    • Se as variáveis SMTP estiverem configuradas: usa aiosmtplib
    • Caso contrário: imprime o link no log (modo debug/desenvolvimento)

    Returns:
        True se o envio foi bem-sucedido, False caso contrário.
    """
    subject = f"[{SITE_NAME}] Recuperação de Password"
    body = _build_email_body(username, reset_link)

    # ── Modo debug: sem SMTP configurado ──────────────────────────────────
    if not SMTP_HOST or not SMTP_USER:
        logger.warning(
            "SMTP não configurado — modo debug. Link de reset para %s:\n%s",
            to_email,
            reset_link,
        )
        # Em desenvolvimento, imprime no stdout para facilitar testes
        print(f"\n{'='*60}")
        print(f"[DEBUG] E-mail de reset para: {to_email}")
        print(f"[DEBUG] Link: {reset_link}")
        print(f"{'='*60}\n")
        return True

    # ── Envio real via aiosmtplib ─────────────────────────────────────────
    try:
        import aiosmtplib
        from email.message import EmailMessage

        msg = EmailMessage()
        msg["From"] = EMAIL_FROM
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)

        await aiosmtplib.send(
            msg,
            hostname=SMTP_HOST,
            port=SMTP_PORT,
            username=SMTP_USER,
            password=SMTP_PASS,
            start_tls=True,
        )
        logger.info("E-mail de reset enviado para %s", to_email)
        return True

    except ImportError:
        logger.error(
            "aiosmtplib não instalado. Execute: pip install aiosmtplib. "
            "Link de reset (fallback): %s",
            reset_link,
        )
        return False
    except Exception as exc:
        logger.error("Falha ao enviar e-mail de reset para %s: %s", to_email, exc)
        return False
