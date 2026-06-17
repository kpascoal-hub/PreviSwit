"""
api/routers/auth.py
─────────────────────────────────────────────────────────────────────────────
Router de Autenticação — PreviSwit ASPM

Endpoints implementados (inspirados no fluxo DefectDojo):
  POST /auth/forgot-password   → Inicia o fluxo de reset (envia e-mail)
  POST /auth/reset-password    → Confirma o reset com o token recebido
  GET  /auth/validate-token    → Valida se um token ainda está activo (UX helper)

Boas práticas de segurança seguidas (extraídas do DefectDojo):
  ─── Anti-enumeration ───────────────────────────────────────────────────────
  • O endpoint /forgot-password retorna SEMPRE a mesma resposta genérica,
    independentemente de o e-mail existir ou não. Isto evita que um atacante
    enumere quais e-mails estão registados no sistema.

  ─── Tokens seguros ─────────────────────────────────────────────────────────
  • Token gerado com HMAC-SHA256 (ver api/utils/security.py)
  • Token inclui o timestamp de criação → expira automaticamente
  • Token é invalidado após o reset bem-sucedido (single-use)
  • Token inclui fragmento do hash da password → invalida se a password
    já tiver sido alterada por outro meio

  ─── Rate limiting conceptual ────────────────────────────────────────────────
  • Em produção, adicionar middleware de rate limiting (ex: slowapi) para
    limitar pedidos por IP. O DefectDojo usa @dojo_ratelimit para o efeito.

  ─── Validação de passwords ──────────────────────────────────────────────────
  • Mínimo 8 caracteres, com validação de complexidade (Pydantic validators)
  • Confirmação obrigatória (new_password == confirm_password)

Nota: Este router usa um "user store" simplificado em JSON para demonstração.
Em produção, substituir pelas suas queries ao banco de dados real.
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, status, BackgroundTasks, Query
from pydantic import BaseModel, EmailStr, field_validator, model_validator

from api.utils.security import (
    hash_password,
    verify_password,
    token_generator,
    store_reset_token,
    invalidate_reset_token,
    send_reset_email,
    _build_reset_link,
    _load_tokens,
    PASSWORD_RESET_TIMEOUT,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


# ─── Schemas Pydantic ────────────────────────────────────────────────────────

class ForgotPasswordRequest(BaseModel):
    """Corpo do pedido de recuperação de password."""
    email: EmailStr

    model_config = {"str_strip_whitespace": True}


class ResetPasswordRequest(BaseModel):
    """Corpo do pedido de confirmação de reset de password."""
    uid: str
    token: str
    new_password: str
    confirm_password: str

    model_config = {"str_strip_whitespace": True}

    @field_validator("new_password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        """Valida complexidade mínima da password."""
        if len(v) < 8:
            raise ValueError("A password deve ter pelo menos 8 caracteres.")
        if not any(c.isupper() for c in v):
            raise ValueError("A password deve conter pelo menos uma letra maiúscula.")
        if not any(c.isdigit() for c in v):
            raise ValueError("A password deve conter pelo menos um número.")
        return v

    @model_validator(mode="after")
    def passwords_match(self) -> "ResetPasswordRequest":
        """Verifica que new_password e confirm_password são iguais."""
        if self.new_password != self.confirm_password:
            raise ValueError("As passwords não coincidem.")
        return self


class GenericMessageResponse(BaseModel):
    """Resposta genérica com mensagem informativa."""
    message: str
    detail: Optional[str] = None


class TokenValidationResponse(BaseModel):
    """Resposta da validação de token."""
    valid: bool
    message: str


# ─── Stub de User Store ──────────────────────────────────────────────────────
# Em produção, substituir pelas suas funções de acesso ao banco de dados.

import json
import os
from pathlib import Path

_USERS_FILE = Path(os.getenv("DATA_DIR", "data")) / "users.json"


def _load_users() -> dict:
    """Carrega o dicionário de utilizadores do store JSON."""
    if not _USERS_FILE.exists():
        return {}
    try:
        return json.loads(_USERS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_users(users: dict) -> None:
    """Persiste o dicionário de utilizadores."""
    _USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _USERS_FILE.write_text(json.dumps(users, indent=2), encoding="utf-8")


def _find_user_by_email(email: str) -> Optional[dict]:
    """
    Procura um utilizador pelo e-mail (case-insensitive).

    Returns:
        Dicionário com os dados do utilizador, ou None se não encontrado.
        Formato esperado: {"id": str, "username": str, "email": str, "password_hash": str}
    """
    users = _load_users()
    email_lower = email.lower()
    for user_id, user_data in users.items():
        if user_data.get("email", "").lower() == email_lower:
            return {"id": user_id, **user_data}
    return None


def _find_user_by_id(user_id: str) -> Optional[dict]:
    """Procura um utilizador pelo ID."""
    users = _load_users()
    user_data = users.get(user_id)
    if user_data:
        return {"id": user_id, **user_data}
    return None


def _update_user_password(user_id: str, new_password_hash: str) -> None:
    """Atualiza o hash da password de um utilizador."""
    users = _load_users()
    if user_id in users:
        users[user_id]["password_hash"] = new_password_hash
        # Stamp do momento do reset (equivalente ao uci.password_last_reset do DefectDojo)
        from datetime import datetime, timezone
        users[user_id]["password_last_reset"] = datetime.now(timezone.utc).isoformat()
        _save_users(users)


# ─── Endpoints ───────────────────────────────────────────────────────────────

@router.post(
    "/forgot-password",
    response_model=GenericMessageResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Inicia o fluxo de recuperação de password",
    description=(
        "Envia um e-mail com link de reset se o endereço existir no sistema. "
        "A resposta é sempre genérica para evitar enumeração de utilizadores "
        "(anti-enumeration — padrão DefectDojo)."
    ),
)
async def forgot_password(
    body: ForgotPasswordRequest,
    background_tasks: BackgroundTasks,
) -> GenericMessageResponse:
    """
    Endpoint: POST /auth/forgot-password

    Fluxo (espelhando o DojoPasswordResetView do DefectDojo):
      1. Procura o utilizador pelo e-mail fornecido
      2. Se encontrado: gera token HMAC seguro + envia e-mail em background
      3. Se não encontrado: retorna a MESMA resposta (anti-enumeration)
      4. O envio de e-mail é feito em background para não bloquear a resposta

    Anti-enumeration: nunca revela se o e-mail existe ou não.
    """
    user = _find_user_by_email(body.email)

    if user:
        # Fragmento do hash da password atual (invalida o token após reset)
        pwd_hash = user.get("password_hash", "")
        pwd_fragment = pwd_hash[:12] if pwd_hash else "no-hash"

        # Gera o par (uidb64, token) — mesmo conceito do Django's PasswordResetTokenGenerator
        uidb64, token = token_generator.make_token(
            user_id=user["id"],
            password_hash_fragment=pwd_fragment,
        )

        # Persiste o token para futura validação
        store_reset_token(user_id=user["id"], uidb64=uidb64, token=token)

        # Constrói o link (formato: SITE_URL/reset-password?uid=...&token=...)
        reset_link = _build_reset_link(uidb64, token)

        logger.info(
            "Reset de password solicitado para user_id=%s (email=%s)",
            user["id"], body.email,
        )

        # Envia e-mail em background (não bloqueia a resposta — mesmo padrão Dojo)
        background_tasks.add_task(
            send_reset_email,
            to_email=body.email,
            username=user.get("username", body.email),
            reset_link=reset_link,
        )
    else:
        # Anti-enumeration: não revela que o e-mail não existe
        # Mas logamos internamente para auditoria
        logger.info(
            "Reset de password solicitado para e-mail não registado: %s",
            body.email,
        )

    # Resposta sempre igual — independentemente de o e-mail existir
    return GenericMessageResponse(
        message=(
            "Se o endereço de e-mail estiver registado no sistema, "
            "receberá em breve um link para recuperar a sua password."
        )
    )


@router.post(
    "/reset-password",
    response_model=GenericMessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Confirma o reset de password com o token recebido",
    description=(
        "Valida o token do link de reset e actualiza a password do utilizador. "
        "O token é de uso único e expira após o tempo configurado."
    ),
)
async def reset_password(body: ResetPasswordRequest) -> GenericMessageResponse:
    """
    Endpoint: POST /auth/reset-password

    Fluxo (espelhando o DojoPasswordResetConfirmView do DefectDojo):
      1. Descodifica o uidb64 para obter o user_id
      2. Procura o utilizador no store
      3. Valida o token HMAC (formato, HMAC, expiração, hash_fragment)
      4. Faz o hash da nova password e actualiza no store
      5. Invalida o token (single-use — nunca pode ser reutilizado)
      6. Regista o timestamp do reset (equivalente ao password_last_reset do Dojo)

    Respostas:
      200 — Reset bem-sucedido
      400 — Token inválido, expirado, ou passwords não coincidem (Pydantic)
      404 — Utilizador não encontrado
    """
    # ── 1. Descodifica o uidb64 ──────────────────────────────────────────
    user_id = token_generator.decode_uid(body.uid)
    if not user_id:
        logger.warning("reset-password: uidb64 inválido recebido: %s", body.uid)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Link de reset inválido ou corrompido.",
        )

    # ── 2. Procura o utilizador ──────────────────────────────────────────
    user = _find_user_by_id(user_id)
    if not user:
        logger.warning("reset-password: utilizador não encontrado para user_id=%s", user_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Utilizador não encontrado.",
        )

    # ── 3. Valida o token HMAC ───────────────────────────────────────────
    pwd_hash = user.get("password_hash", "")
    pwd_fragment = pwd_hash[:12] if pwd_hash else "no-hash"

    token_valid = token_generator.check_token(
        token_str=body.token,
        user_id=user_id,
        password_hash_fragment=pwd_fragment,
    )

    if not token_valid:
        logger.warning(
            "reset-password: token inválido ou expirado para user_id=%s", user_id
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "O link de reset é inválido ou já expirou. "
                f"Os links têm validade de {PASSWORD_RESET_TIMEOUT // 60} minutos. "
                "Por favor, solicite um novo link."
            ),
        )

    # ── 4. Actualiza a password ──────────────────────────────────────────
    new_hash = hash_password(body.new_password)
    _update_user_password(user_id=user_id, new_password_hash=new_hash)

    logger.info(
        "Password actualizada com sucesso para user_id=%s", user_id
    )

    # ── 5. Invalida o token (single-use) ─────────────────────────────────
    invalidate_reset_token(user_id=user_id)

    return GenericMessageResponse(
        message="A sua password foi actualizada com sucesso. Pode agora fazer login."
    )


@router.get(
    "/validate-token",
    response_model=TokenValidationResponse,
    status_code=status.HTTP_200_OK,
    summary="Valida se um token de reset ainda está activo",
    description=(
        "Endpoint auxiliar para o frontend verificar se o token do link ainda é válido "
        "antes de mostrar o formulário de nova password. "
        "Melhora a UX ao dar feedback imediato em vez de esperar pelo submit."
    ),
)
async def validate_reset_token(
    uid: str = Query(..., description="uidb64 do utilizador (do link de reset)"),
    token: str = Query(..., description="Token de reset (do link de reset)"),
) -> TokenValidationResponse:
    """
    Endpoint: GET /auth/validate-token?uid=...&token=...

    Verifica se o token é válido sem efectuar o reset.
    Útil para o frontend mostrar/esconder o formulário de reset.
    """
    user_id = token_generator.decode_uid(uid)
    if not user_id:
        return TokenValidationResponse(valid=False, message="Link inválido ou corrompido.")

    user = _find_user_by_id(user_id)
    if not user:
        return TokenValidationResponse(valid=False, message="Utilizador não encontrado.")

    pwd_hash = user.get("password_hash", "")
    pwd_fragment = pwd_hash[:12] if pwd_hash else "no-hash"

    is_valid = token_generator.check_token(
        token_str=token,
        user_id=user_id,
        password_hash_fragment=pwd_fragment,
    )

    if is_valid:
        return TokenValidationResponse(
            valid=True,
            message="Token válido. Pode definir uma nova password.",
        )
    else:
        return TokenValidationResponse(
            valid=False,
            message=(
                f"O link expirou ou já foi utilizado. "
                f"Os links têm validade de {PASSWORD_RESET_TIMEOUT // 60} minutos."
            ),
        )
