# PreviSwit AI-ASPM
# Copyright (C) 2026 PreviSwit Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""
PreviSwit AI-ASPM — Router: Settings & Users
Configurações da plataforma, usuários e RBAC.
"""
from fastapi import APIRouter, HTTPException
import json
import os
import uuid
from datetime import datetime

router = APIRouter(prefix="/settings", tags=["Settings & Users"])

DATA_FILE_USERS = os.path.join(os.path.dirname(__file__), "..", "..", "data", "users.json")
DATA_FILE_SETTINGS = os.path.join(os.path.dirname(__file__), "..", "..", "data", "settings.json")

VALID_ROLES = ["admin", "analyst", "developer", "viewer"]


def _load_users() -> list:
    if not os.path.exists(DATA_FILE_USERS):
        return []
    with open(DATA_FILE_USERS, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_users(data: list) -> None:
    os.makedirs(os.path.dirname(DATA_FILE_USERS), exist_ok=True)
    with open(DATA_FILE_USERS, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def _load_settings() -> dict:
    if not os.path.exists(DATA_FILE_SETTINGS):
        return {
            "organization_name": "PreviSwit Organization",
            "timezone": "America/Sao_Paulo",
            "language": "pt-BR",
            "scan_default_pipeline": "all",
            "notification_email": "",
            "auto_triage_enabled": True,
            "sla_enabled": True,
        }
    with open(DATA_FILE_SETTINGS, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_settings(data: dict) -> None:
    os.makedirs(os.path.dirname(DATA_FILE_SETTINGS), exist_ok=True)
    with open(DATA_FILE_SETTINGS, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


# ── Configurações Gerais ───────────────────────────────────────────────────────

@router.get("/", summary="Obter configurações gerais da plataforma")
def get_settings():
    """Retorna as configurações globais da plataforma."""
    return _load_settings()


@router.put("/", summary="Atualizar configurações gerais")
def update_settings(body: dict):
    """Atualiza as configurações globais da plataforma."""
    settings = _load_settings()
    settings.update(body)
    settings["updated_at"] = datetime.utcnow().isoformat()
    _save_settings(settings)
    return {"message": "Configurações atualizadas", "settings": settings}


# ── Gestão de Usuários ─────────────────────────────────────────────────────────

@router.get("/users", summary="Listar usuários")
def list_users():
    """Retorna todos os usuários cadastrados (sem senhas)."""
    users = _load_users()
    # Remove campos sensíveis
    safe_users = [{k: v for k, v in u.items() if k not in ("password_hash", "password")} for u in users]
    return {"users": safe_users, "total": len(safe_users)}


@router.post("/users", summary="Criar usuário")
def create_user(body: dict):
    """Cria um novo usuário na plataforma com role RBAC."""
    role = body.get("role", "viewer")
    if role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Role inválida. Use: {VALID_ROLES}")

    username = body.get("username")
    if not username:
        raise HTTPException(status_code=400, detail="Campo 'username' é obrigatório")

    users = _load_users()
    if any(u["username"] == username for u in users):
        raise HTTPException(status_code=409, detail=f"Usuário '{username}' já existe")

    user = {
        "id": str(uuid.uuid4()),
        "username": username,
        "email": body.get("email", ""),
        "full_name": body.get("full_name", username),
        "role": role,
        "is_active": True,
        "password_hash": "PLACEHOLDER_USE_AUTH_ROUTER",
        "created_at": datetime.utcnow().isoformat(),
        "last_login": None,
    }
    users.append(user)
    _save_users(users)

    safe_user = {k: v for k, v in user.items() if k != "password_hash"}
    return {"message": "Usuário criado com sucesso", "user": safe_user}


@router.patch("/users/{user_id}/role", summary="Alterar role de usuário")
def update_user_role(user_id: str, body: dict):
    """Altera a role RBAC de um usuário."""
    new_role = body.get("role")
    if new_role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Role inválida. Use: {VALID_ROLES}")

    users = _load_users()
    for i, u in enumerate(users):
        if u["id"] == user_id:
            users[i]["role"] = new_role
            users[i]["updated_at"] = datetime.utcnow().isoformat()
            _save_users(users)
            safe_user = {k: v for k, v in users[i].items() if k != "password_hash"}
            return {"message": f"Role atualizada para '{new_role}'", "user": safe_user}
    raise HTTPException(status_code=404, detail="Usuário não encontrado")


@router.patch("/users/{user_id}/toggle", summary="Ativar/desativar usuário")
def toggle_user(user_id: str):
    """Ativa ou desativa um usuário da plataforma."""
    users = _load_users()
    for i, u in enumerate(users):
        if u["id"] == user_id:
            users[i]["is_active"] = not users[i].get("is_active", True)
            users[i]["updated_at"] = datetime.utcnow().isoformat()
            _save_users(users)
            status = "ativado" if users[i]["is_active"] else "desativado"
            safe_user = {k: v for k, v in users[i].items() if k != "password_hash"}
            return {"message": f"Usuário {status}", "user": safe_user}
    raise HTTPException(status_code=404, detail="Usuário não encontrado")


# ── Audit Log ─────────────────────────────────────────────────────────────────

@router.get("/audit", summary="Log de auditoria da plataforma")
def get_audit_log():
    """Retorna o log de atividades da plataforma (stub — a implementar com middleware)."""
    return {
        "message": "Audit log disponível via integração com sistema de logging centralizado.",
        "note": "Configure a variável LOG_LEVEL=audit para habilitar o registro completo.",
        "audit_events": [],
    }
