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
PreviSwit AI-ASPM — Router: Container Security (Trivy Image)
Análise de vulnerabilidades em imagens Docker via Trivy.

Fluxo:
  Frontend → POST /api/v1/containers/scan
           → FastAPI (aqui) → asyncio.create_task → run_trivy_image()
           → resultado disponível via GET /containers/scan-status/{id}

Endpoints:
  POST /api/v1/containers/scan                  — Dispara scan de imagem Docker
  GET  /api/v1/containers/scan-status/{scan_id} — Polling de status do scan
  GET  /api/v1/containers/scans                 — Histórico de scans em memória
  GET  /api/v1/containers/popular-images        — Imagens sugeridas para teste
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
import logging
import uuid
import asyncio

logger = logging.getLogger("previswit.containers")

router = APIRouter(prefix="/containers", tags=["Container Security (Trivy Image)"])

# ─── Estado em Memória para Container Scans ───────────────────────────────────
# Estrutura: { scan_id: { status, image, data, error, started_at } }
CONTAINER_SCANS: dict = {}


class ContainerScanRequest(BaseModel):
    image_name: str          # Ex: "nginx:latest", "ubuntu:22.04", "node:18-alpine"
    pull_policy: Optional[str] = "auto"  # "auto" | "always" | "never"


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post(
    "/scan",
    summary="Disparar scan de vulnerabilidades em imagem Docker",
    description=(
        "Recebe o nome de uma imagem Docker e executa o Trivy para análise de CVEs.\n\n"
        "O scan ocorre em background. Use o `scan_id` retornado para fazer polling em "
        "`GET /containers/scan-status/{scan_id}`.\n\n"
        "**Exemplos de imagem:** `nginx:latest`, `ubuntu:22.04`, `node:18-alpine`, `python:3.12-slim`"
    ),
)
async def start_container_scan(body: ContainerScanRequest):
    """Inicia scan de imagem Docker via Trivy e retorna scan_id para polling."""
    if not body.image_name or not body.image_name.strip():
        raise HTTPException(status_code=400, detail="Campo 'image_name' não pode estar vazio.")

    image = body.image_name.strip()
    scan_id = str(uuid.uuid4())[:8]

    CONTAINER_SCANS[scan_id] = {
        "status":     "PENDING",
        "image":      image,
        "data":       None,
        "error":      None,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }

    asyncio.create_task(_execute_container_scan(scan_id, image))

    return {
        "scan_id":    scan_id,
        "status":     "PENDING",
        "image":      image,
        "message":    f"Scan iniciado. Faça polling em GET /api/v1/containers/scan-status/{scan_id}",
        "started_at": CONTAINER_SCANS[scan_id]["started_at"],
    }


async def _execute_container_scan(scan_id: str, image: str) -> None:
    """Executa o scan Trivy em background e atualiza CONTAINER_SCANS."""
    from core.scanners.container_runner import run_trivy_image

    CONTAINER_SCANS[scan_id]["status"] = "RUNNING"
    logger.info("[ContainerScan:%s] Iniciando Trivy para imagem '%s'", scan_id, image)

    try:
        result = await run_trivy_image(image)

        CONTAINER_SCANS[scan_id]["status"] = "CONCLUÍDO"
        CONTAINER_SCANS[scan_id]["data"]   = result
        logger.info(
            "[ContainerScan:%s] Concluído — %s CVEs encontrados",
            scan_id, result.get("stats", {}).get("total", "?")
        )
    except Exception as e:
        logger.exception("[ContainerScan:%s] Erro inesperado", scan_id)
        CONTAINER_SCANS[scan_id]["status"] = "ERROR"
        CONTAINER_SCANS[scan_id]["error"]  = str(e)


@router.get(
    "/scan-status/{scan_id}",
    summary="Polling de status do scan de container",
)
def container_scan_status(scan_id: str):
    """Retorna o status atual e resultado (quando disponível) de um scan em andamento."""
    scan = CONTAINER_SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' não encontrado.")

    return {
        "scan_id":    scan_id,
        "status":     scan["status"],
        "image":      scan["image"],
        "data":       scan["data"],
        "error":      scan["error"],
        "started_at": scan.get("started_at"),
    }


@router.get(
    "/scans",
    summary="Listar histórico de scans de container",
)
def list_container_scans():
    """Retorna o histórico de scans de imagens Docker em memória."""
    return {
        "scans": [
            {
                "scan_id":    sid,
                "status":     s["status"],
                "image":      s["image"],
                "started_at": s.get("started_at"),
                "total_vulns": s["data"].get("stats", {}).get("total") if s["data"] else None,
            }
            for sid, s in CONTAINER_SCANS.items()
        ],
        "total": len(CONTAINER_SCANS),
    }


@router.get(
    "/popular-images",
    summary="Lista de imagens Docker populares para teste rápido",
)
def popular_images():
    """Sugestões de imagens comuns para demonstração ou teste de scan."""
    return {
        "images": [
            {"name": "nginx:latest",       "description": "Web server — CVEs comuns conhecidos"},
            {"name": "ubuntu:22.04",       "description": "Base OS — múltiplas CVEs de sistema"},
            {"name": "node:18-alpine",     "description": "Node.js slim — superfície reduzida"},
            {"name": "python:3.12-slim",   "description": "Python slim — baseline limpa"},
            {"name": "postgres:15",        "description": "Banco de dados — CVEs de dependências"},
            {"name": "redis:7-alpine",     "description": "Cache em memória — imagem minimalista"},
        ]
    }
