"""
PreviSwit AI-ASPM — Router: Cloud Security & IaC (CSPM)
Orquestrador de análise estática de Infraestrutura como Código.

Fluxo:
  Frontend → POST /api/v1/cloud/iac-scan
           → FastAPI (aqui) → clone efêmero + run_full_iac_scan()
           → resultado retorna via HTTP polling

Endpoints:
  POST /api/v1/cloud/iac-scan              — Dispara scan IaC (Checkov + Trivy config)
  GET  /api/v1/cloud/iac-scan-status/{id}  — Polling de status do scan
  GET  /api/v1/cloud/providers             — Lista provedores cloud configurados
"""
from fastapi import APIRouter, HTTPException, Header as FastAPIHeader
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
import logging
import subprocess
import tempfile
import shutil
import json
import uuid
import asyncio

logger = logging.getLogger("previswit.cloud")

router = APIRouter(prefix="/cloud", tags=["Cloud Security & IaC (CSPM)"])

# ─── Estado em Memória para IaC Scans ─────────────────────────────────────────
IAC_SCANS = {}


class IaCScanRequest(BaseModel):
    repo_url: Optional[str] = ""        # URL Git para clone
    local_path: Optional[str] = ""      # Caminho local (alternativa ao clone)
    target_name: Optional[str] = ""     # Nome amigável do alvo
    scan_tools: Optional[list] = []     # ["checkov", "trivy"] ou vazio = ambos


class CloudProviderStatus(BaseModel):
    provider: str
    status: str = "disconnected"
    account_id: Optional[str] = None
    compliance_score: Optional[float] = None


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post(
    "/iac-scan",
    summary="Disparar scan IaC (Checkov + Trivy config)",
    description=(
        "Recebe URL de repositório ou caminho local e executa análise estática de IaC.\n\n"
        "Ferramentas: Checkov (Terraform, K8s, Docker, ARM, Bicep) + Trivy config.\n\n"
        "Retorna um `scan_id` para polling de status via GET /cloud/iac-scan-status/{id}."
    ),
)
async def start_iac_scan(body: IaCScanRequest):
    """Inicia scan IaC em background e retorna scan_id para polling."""
    if not body.repo_url and not body.local_path:
        raise HTTPException(status_code=400, detail="Forneça 'repo_url' ou 'local_path'.")

    scan_id = str(uuid.uuid4())[:8]
    target_label = body.target_name or body.repo_url or body.local_path

    IAC_SCANS[scan_id] = {
        "status": "PENDING",
        "target": target_label,
        "data": None,
        "error": None,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }

    # Executa em background
    asyncio.create_task(_execute_iac_scan(scan_id, body))

    return {
        "scan_id": scan_id,
        "status": "PENDING",
        "target": target_label,
        "message": f"Scan IaC iniciado. Faça polling em GET /api/v1/cloud/iac-scan-status/{scan_id}",
    }


async def _execute_iac_scan(scan_id: str, body: IaCScanRequest):
    """Executa o scan IaC de forma assíncrona."""
    from core.scanners.iac_runner import run_full_iac_scan, run_checkov_iac, run_trivy_iac

    IAC_SCANS[scan_id]["status"] = "RUNNING"
    tmp_dir = None

    try:
        target_path = body.local_path

        if body.repo_url:
            tmp_dir = tempfile.mkdtemp(prefix="previswit_iac_")
            clone_result = subprocess.run(
                ["git", "clone", "--depth", "1", body.repo_url, tmp_dir],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if clone_result.returncode != 0:
                IAC_SCANS[scan_id]["status"] = "ERROR"
                IAC_SCANS[scan_id]["error"] = f"Falha no clone: {clone_result.stderr[:500]}"
                return
            target_path = tmp_dir

        if not target_path:
            IAC_SCANS[scan_id]["status"] = "ERROR"
            IAC_SCANS[scan_id]["error"] = "Sem caminho alvo para varredura."
            return

        # Decide quais tools rodar
        tools = body.scan_tools if body.scan_tools else ["checkov", "trivy"]

        if len(tools) >= 2 or not tools:
            result = await run_full_iac_scan(target_path)
        elif "checkov" in tools:
            result = await run_checkov_iac(target_path)
        elif "trivy" in tools:
            result = await run_trivy_iac(target_path)
        else:
            result = await run_full_iac_scan(target_path)

        IAC_SCANS[scan_id]["status"] = "CONCLUÍDO"
        IAC_SCANS[scan_id]["data"] = result

    except Exception as e:
        logger.exception("Erro no scan IaC %s", scan_id)
        IAC_SCANS[scan_id]["status"] = "ERROR"
        IAC_SCANS[scan_id]["error"] = str(e)
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


@router.get(
    "/iac-scan-status/{scan_id}",
    summary="Polling de status do scan IaC",
)
def iac_scan_status(scan_id: str):
    """Retorna o status atual de um scan IaC em andamento."""
    scan = IAC_SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' não encontrado.")

    return {
        "scan_id": scan_id,
        "status": scan["status"],
        "target": scan["target"],
        "data": scan["data"],
        "error": scan["error"],
    }


@router.get(
    "/providers",
    summary="Listar provedores cloud e status de integração",
)
def list_cloud_providers():
    """
    Retorna os provedores cloud suportados e seu status de conexão.
    Futuramente, integrará com AWS STS, Azure AD e GCP IAM.
    """
    return {
        "providers": [
            {
                "id": "aws",
                "name": "Amazon Web Services",
                "status": "disconnected",
                "icon": "aws",
                "services_supported": ["EC2", "S3", "IAM", "Lambda", "EKS", "RDS"],
                "compliance_score": None,
            },
            {
                "id": "azure",
                "name": "Microsoft Azure",
                "status": "disconnected",
                "icon": "azure",
                "services_supported": ["VMs", "Blob Storage", "AKS", "Key Vault", "AD"],
                "compliance_score": None,
            },
            {
                "id": "gcp",
                "name": "Google Cloud Platform",
                "status": "disconnected",
                "icon": "gcp",
                "services_supported": ["GCE", "GCS", "GKE", "BigQuery", "IAM"],
                "compliance_score": None,
            },
        ],
        "total_connected": 0,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get(
    "/iac-scans",
    summary="Listar todos os scans IaC recentes",
)
def list_iac_scans():
    """Retorna histórico de scans IaC em memória."""
    return {
        "scans": [
            {
                "scan_id": sid,
                "status": s["status"],
                "target": s["target"],
                "started_at": s.get("started_at"),
            }
            for sid, s in IAC_SCANS.items()
        ],
        "total": len(IAC_SCANS),
    }
