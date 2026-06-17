"""
PreviSwit AI-ASPM — Core: Security
JWT, bcrypt e helpers de autenticação/autorização.
"""
import os
import hashlib
import hmac
import base64
from datetime import datetime, timedelta
from typing import Optional

SECRET_KEY = os.getenv("SECRET_KEY", "previswit-changeme-replace-in-production")
TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "60"))

# ── JWT minimalista (sem dependência de python-jose) ───────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    return base64.urlsafe_b64decode(data + "=" * padding)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Gera um JWT simples assinado com HMAC-SHA256."""
    import json
    import time

    payload = {**data}
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=TOKEN_EXPIRE_MINUTES))
    payload["exp"] = int(expire.timestamp())
    payload["iat"] = int(datetime.utcnow().timestamp())

    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url_encode(json.dumps(payload).encode())
    signing_input = f"{header}.{body}"
    sig = hmac.new(SECRET_KEY.encode(), signing_input.encode(), hashlib.sha256).digest()
    signature = _b64url_encode(sig)
    return f"{signing_input}.{signature}"


def verify_token(token: str) -> Optional[dict]:
    """Verifica e decodifica um JWT. Retorna None se inválido ou expirado."""
    import json
    import time

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, body_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{body_b64}"
        expected_sig = hmac.new(SECRET_KEY.encode(), signing_input.encode(), hashlib.sha256).digest()
        expected_b64 = _b64url_encode(expected_sig)
        if not hmac.compare_digest(sig_b64, expected_b64):
            return None
        payload = json.loads(_b64url_decode(body_b64))
        if payload.get("exp", 0) < int(datetime.utcnow().timestamp()):
            return None
        return payload
    except Exception:
        return None


# ── Hashing de senhas ──────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Gera um hash seguro de senha usando PBKDF2-HMAC-SHA256."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260000)
    return base64.b64encode(salt + key).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Verifica se uma senha corresponde ao hash armazenado."""
    try:
        decoded = base64.b64decode(hashed.encode())
        salt = decoded[:16]
        stored_key = decoded[16:]
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260000)
        return hmac.compare_digest(key, stored_key)
    except Exception:
        return False


# ── RBAC ───────────────────────────────────────────────────────────────────────

ROLE_PERMISSIONS = {
    "admin":     ["read", "write", "delete", "admin"],
    "analyst":   ["read", "write"],
    "developer": ["read", "write"],
    "viewer":    ["read"],
}


def has_permission(role: str, permission: str) -> bool:
    """Verifica se uma role possui uma permissão específica."""
    return permission in ROLE_PERMISSIONS.get(role, [])
