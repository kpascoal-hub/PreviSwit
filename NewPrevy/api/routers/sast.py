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
PreviSwit AI-ASPM — Router: SAST Dispatch
Orquestrador HTTP→WebSocket para as ferramentas SAST individuais embarcadas no Agente.

Fluxo:
  Frontend → POST /api/v1/sast/scan
           → FastAPI (aqui) → manager.send_to_agent() via WebSocket
           → Agent (ws_listener) → run_semgrep | run_gitleaks | run_checkov
           → resultado retorna via WebSocket → Dashboard

Endpoints:
  POST /api/v1/sast/scan          — Dispara uma ferramenta SAST no agente
  GET  /api/v1/sast/tools         — Lista ferramentas disponíveis e status do agente
  GET  /api/v1/sast/status/{agent} — Verifica se o agente está conectado
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime, timezone
import logging
from core.scanners.cve_enricher import build_cve_report

logger = logging.getLogger("previswit.sast")

router = APIRouter(prefix="/sast", tags=["SAST Dispatch (Agent)"])

# ─── Estado em Memória para Scans em Background ───────────────────────────────
# Em um cenário real de produção pesada, usaríamos Redis/Celery.
# Aqui armazenamos: { scan_id: { "status": "PENDING"|"RUNNING"|"CONCLUÍDO"|"ERROR", "data": {...}, "error": "..." } }
REPO_SCANS = {}

# ─── Tipos aceitos ────────────────────────────────────────────────────────────
SASTAction = Literal["RUN_SEMGREP", "RUN_GITLEAKS", "RUN_CHECKOV"]

TOOL_META = {
    "RUN_SEMGREP": {
        "name": "Semgrep",
        "description": "SAST genérico multi-linguagem via análise de AST.",
        "category": "SAST",
        "supported_languages": ["Python", "JS", "Go", "Java", "Ruby", "PHP", "C/C++", "e mais"],
    },
    "RUN_GITLEAKS": {
        "name": "Gitleaks",
        "description": "Detecção de segredos, tokens e credenciais em código-fonte.",
        "category": "Secrets Detection",
        "supported_languages": ["Todos (análise de texto)"],
    },
    "RUN_CHECKOV": {
        "name": "Checkov",
        "description": "Análise estática de IaC: Terraform, Kubernetes, Dockerfile, ARM, Bicep.",
        "category": "IaC Security",
        "supported_languages": ["Terraform", "Kubernetes", "Dockerfile", "ARM", "CloudFormation"],
    },
}


class SASTScanRequest(BaseModel):
    action: SASTAction                     # "RUN_SEMGREP" | "RUN_GITLEAKS" | "RUN_CHECKOV"
    target: str                            # Caminho absoluto no container do Agente (ex: /app/repo)
    agent_id: Optional[str] = "agent_01"  # ID do agente alvo (padrão: agent_01)


# ─── Referência lazy ao manager do api.py ────────────────────────────────────
# O import é feito de forma lazy para evitar circular imports, já que o
# manager é instanciado no módulo api.py (o entry-point da aplicação).
def _get_manager():
    """Obtém o ConnectionManager instanciado em api.py."""
    import api.api as _api_module
    return _api_module.manager


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post(
    "/scan",
    summary="Disparar scan SAST individual no Agente",
    description=(
        "Envia um comando de scan para o Agente conectado via WebSocket.\n\n"
        "O resultado é retornado de forma assíncrona pelo WebSocket do Dashboard (`/ws/web_dashboard`).\n\n"
        "**Ações disponíveis:** `RUN_SEMGREP`, `RUN_GITLEAKS`, `RUN_CHECKOV`"
    ),
)
async def dispatch_sast_scan(body: SASTScanRequest):
    """
    Despacha um comando SAST para o Agente via WebSocket.
    O Agente executa o scan e retorna o resultado pelo túnel WebSocket do Dashboard.
    """
    if not body.target.strip():
        raise HTTPException(status_code=400, detail="Campo 'target' não pode estar vazio.")

    manager = _get_manager()

    # Verifica se o agente está conectado
    if body.agent_id not in manager.agent_ws:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Agente '{body.agent_id}' não está conectado ao servidor. "
                "Verifique se o container do Agente está rodando e conectado via WebSocket."
            ),
        )

    # Monta o comando no protocolo esperado pelo ws_listener.py do Agente
    command = {
        "action": body.action,
        "target": body.target,
        "requested_at": datetime.now(timezone.utc).isoformat(),
    }

    await manager.send_to_agent(body.agent_id, command)

    tool_info = TOOL_META.get(body.action, {})

    return {
        "status": "dispatched",
        "message": f"Comando '{body.action}' enviado para o agente '{body.agent_id}'.",
        "agent_id": body.agent_id,
        "action": body.action,
        "tool": tool_info.get("name", body.action),
        "target": body.target,
        "note": "O resultado chegará de forma assíncrona pelo WebSocket do Dashboard (/ws/web_dashboard).",
        "dispatched_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get(
    "/tools",
    summary="Listar ferramentas SAST disponíveis",
)
def list_sast_tools():
    """Retorna os metadados das ferramentas SAST disponíveis no Agente."""
    return {
        "tools": [
            {"action": action, **meta}
            for action, meta in TOOL_META.items()
        ]
    }


@router.get(
    "/status/{agent_id}",
    summary="Verificar status de conexão de um Agente",
)
def agent_status(agent_id: str):
    """Verifica se um Agente específico está conectado ao servidor via WebSocket."""
    manager = _get_manager()
    connected = agent_id in manager.agent_ws
    return {
        "agent_id": agent_id,
        "connected": connected,
        "status": "online" if connected else "offline",
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get(
    "/agents",
    summary="Listar todos os Agentes conectados",
)
def list_connected_agents():
    """Retorna a lista de todos os Agentes atualmente conectados ao servidor."""
    manager = _get_manager()
    agents = list(manager.agent_ws.keys())
    return {
        "connected_agents": agents,
        "count": len(agents),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


# ─── Endpoint: Análise de Commit Individual (SAST + AI) ──────────────────────

class CommitAnalyzeRequest(BaseModel):
    sha:     str                          # Hash completo do commit
    message: Optional[str] = ""          # Mensagem do commit
    author:  Optional[str] = ""          # Autor do commit
    date:    Optional[str] = ""          # Data do commit (ISO 8601)
    branch:  Optional[str] = ""          # Branch de origem
    files:   Optional[list] = []         # Lista de arquivos alterados (patch diff)
    repo_url: Optional[str] = ""         # URL do repositório para clonagem
    gemini_key: Optional[str] = None     # Chave Gemini BYOK (alternativa ao Header)

from fastapi import Header as FastAPIHeader
import subprocess
import os
import shutil
import tempfile
import json
import hashlib

FINDINGS_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "data", "findings.json")

def _authenticated_clone_url(repo_url: str, github_token: Optional[str]) -> str:
    """Injeta o token GitHub na URL para clonar repositórios privados via HTTPS."""
    if not github_token or not repo_url.startswith("https://"):
        return repo_url
    if "@" in repo_url.split("://", 1)[1].split("/", 1)[0]:
        return repo_url  # já tem credenciais embutidas
    return repo_url.replace("https://", f"https://x-access-token:{github_token}@", 1)

def _load_findings() -> list:
    if not os.path.exists(FINDINGS_FILE):
        return []
    try:
        with open(FINDINGS_FILE, "r", encoding="utf-8") as f:
            data = f.read().strip()
            return json.loads(data) if data and data != "null" else []
    except Exception:
        return []

def _save_findings_file(data: list) -> None:
    os.makedirs(os.path.dirname(FINDINGS_FILE), exist_ok=True)
    with open(FINDINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)

def _persist_findings_from_scan(
    repo_url: str, sha: str,
    semgrep_data: dict, trivy_data: dict,
    gitleaks_data: list, checkov_data,
) -> int:
    """
    Converte resultados de scanner em findings e salva em findings.json.
    Usa dedup_key (md5) para evitar duplicatas ao re-escanear o mesmo commit.
    Retorna o número de novos findings salvos.
    """
    import uuid as _uuid
    asset_id = repo_url.rstrip("/").split("/")[-1]
    existing = _load_findings()
    existing_keys = {f.get("dedup_key") for f in existing if f.get("dedup_key")}
    new_findings = []
    now = datetime.now(timezone.utc).isoformat()
    _HIGH_SEV = {"HIGH", "CRITICAL"}

    def _dedup(key: str) -> str:
        return hashlib.md5(key.encode()).hexdigest()

    # ── Semgrep ──────────────────────────────────────────────────────────────
    for r in semgrep_data.get("results", []):
        sev = r.get("extra", {}).get("severity", "MEDIUM").upper()
        if sev not in _HIGH_SEV:
            continue
        rule_id = r.get("check_id", "unknown")
        path = r.get("path", "")
        dk = _dedup(f"{asset_id}|semgrep|{rule_id}|{path}")
        if dk in existing_keys:
            continue
        existing_keys.add(dk)
        new_findings.append({
            "id":          str(_uuid.uuid4()),
            "dedup_key":   dk,
            "name":        rule_id,
            "title":       r.get("extra", {}).get("message", rule_id)[:120],
            "description": r.get("extra", {}).get("message", ""),
            "severity":    sev,
            "status":      "open",
            "asset_id":    asset_id,
            "endpoint":    path,
            "tool":        "semgrep",
            "tags":        ["SAST"],
            "commit_sha":  sha,
            "repo_url":    repo_url,
            "created_at":  now,
            "updated_at":  now,
        })

    # ── Trivy ────────────────────────────────────────────────────────────────
    for result in trivy_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "").upper()
            if sev not in _HIGH_SEV:
                continue
            cve_id = vuln.get("VulnerabilityID", "unknown")
            pkg = vuln.get("PkgName", "")
            dk = _dedup(f"{asset_id}|trivy|{cve_id}|{pkg}")
            if dk in existing_keys:
                continue
            existing_keys.add(dk)
            new_findings.append({
                "id":            str(_uuid.uuid4()),
                "dedup_key":     dk,
                "name":          cve_id,
                "title":         vuln.get("Title", cve_id)[:120],
                "description":   vuln.get("Description", "")[:500],
                "severity":      sev,
                "status":        "open",
                "asset_id":      asset_id,
                "endpoint":      result.get("Target", ""),
                "tool":          "trivy",
                "tags":          ["SAST", "CVE"],
                "cve_id":        cve_id,
                "package":       pkg,
                "fixed_version": vuln.get("FixedVersion", ""),
                "commit_sha":    sha,
                "repo_url":      repo_url,
                "created_at":    now,
                "updated_at":    now,
            })

    # ── Gitleaks ─────────────────────────────────────────────────────────────
    for secret in (gitleaks_data if isinstance(gitleaks_data, list) else []):
        rule_id = secret.get("RuleID", "secret")
        path = secret.get("File", "")
        dk = _dedup(f"{asset_id}|gitleaks|{rule_id}|{path}")
        if dk in existing_keys:
            continue
        existing_keys.add(dk)
        new_findings.append({
            "id":          str(_uuid.uuid4()),
            "dedup_key":   dk,
            "name":        rule_id,
            "title":       f"Segredo exposto: {rule_id}",
            "description": f"Arquivo: {path}",
            "severity":    "CRITICAL",
            "status":      "open",
            "asset_id":    asset_id,
            "endpoint":    path,
            "tool":        "gitleaks",
            "tags":        ["SECRETS", "SAST"],
            "commit_sha":  sha,
            "repo_url":    repo_url,
            "created_at":  now,
            "updated_at":  now,
        })

    # ── Checkov ──────────────────────────────────────────────────────────────
    reports = checkov_data if isinstance(checkov_data, list) else ([checkov_data] if checkov_data else [])
    for report in reports:
        if not isinstance(report, dict):
            continue
        for check in report.get("results", {}).get("failed_checks", []):
            check_id = check.get("check_id", "unknown")
            path = check.get("repo_file_path", check.get("file_path", ""))
            dk = _dedup(f"{asset_id}|checkov|{check_id}|{path}")
            if dk in existing_keys:
                continue
            existing_keys.add(dk)
            new_findings.append({
                "id":          str(_uuid.uuid4()),
                "dedup_key":   dk,
                "name":        check_id,
                "title":       check.get("check_name", check_id)[:120],
                "description": f"IaC check falhou: {check_id}",
                "severity":    "HIGH",
                "status":      "open",
                "asset_id":    asset_id,
                "endpoint":    path,
                "tool":        "checkov",
                "tags":        ["IAC", "SAST"],
                "commit_sha":  sha,
                "repo_url":    repo_url,
                "created_at":  now,
                "updated_at":  now,
            })

    if new_findings:
        _save_findings_file(existing + new_findings)
        logger.info("[SAST] %d novos findings salvos de %s@%s", len(new_findings), asset_id, sha[:8])
    return len(new_findings)


@router.post(
    "/analyze-commit",
    summary="Análise SAST + AI de um commit individual",
    description=(
        "Recebe os dados de um commit e realiza varredura com Trivy executado via subprocess "
        "num clone efêmero do repositório."
    ),
)
async def analyze_commit(
    body: CommitAnalyzeRequest,
    x_gemini_key: Optional[str] = FastAPIHeader(default=None, alias="X-Gemini-Key"),
):
    """
    Execução de SAST Real (Trivy) via Gêmeo Efêmero
    """
    if not body.repo_url:
        return {
            "sha":             body.sha,
            "vulnerable":      False,
            "severity":        "UNKNOWN",
            "scan_status":     "SKIPPED",
            "scanner_results": {},
            "cve_report":      {},
            "tool_errors":     {"all": "repo_url não fornecido — clone impossível"},
            "tools_used":      [],
            "analyzed_at":     datetime.now(timezone.utc).isoformat(),
        }

    # Valores padrão — garantem que o retorno final nunca falha por escopo
    semgrep_data   = {}
    trivy_data     = {}
    gitleaks_data  = []
    checkov_data   = {}
    tool_errors    = {}
    diretorio_temporario = tempfile.mkdtemp(prefix="previswit_sast_")

    try:
        # 1. Clonagem Cirúrgica
        subprocess.run(["git", "clone", body.repo_url, diretorio_temporario],
                       capture_output=True, check=False)
        subprocess.run(["git", "checkout", body.sha],
                       cwd=diretorio_temporario, capture_output=True, check=False)

        # 2. Execução dos scanners — cada um isolado para não derrubar os demais

        # Semgrep
        try:
            semgrep_res = subprocess.run(
                ["semgrep", "scan", "--config", "auto", "--json", diretorio_temporario],
                capture_output=True, text=True,
            )
            semgrep_data = json.loads(semgrep_res.stdout) if semgrep_res.stdout else {}
        except FileNotFoundError:
            tool_errors["semgrep"] = "binário não encontrado"
        except Exception as e:
            tool_errors["semgrep"] = str(e)

        # Trivy
        try:
            trivy_res = subprocess.run(
                ["trivy", "fs", "--format", "json", diretorio_temporario],
                capture_output=True, text=True,
            )
            out_text = trivy_res.stdout
            if "{" in out_text:
                out_text = out_text[out_text.index("{"):]
            trivy_data = json.loads(out_text) if out_text else {}
        except FileNotFoundError:
            tool_errors["trivy"] = "binário não encontrado"
        except Exception as e:
            tool_errors["trivy"] = str(e)

        # Gitleaks
        try:
            gitleaks_res = subprocess.run(
                ["gitleaks", "detect", "--source", diretorio_temporario,
                 "--report-format", "json", "--no-git", "--exit-code", "0"],
                capture_output=True, text=True,
            )
            gitleaks_data = json.loads(gitleaks_res.stdout) if gitleaks_res.stdout else []
        except FileNotFoundError:
            tool_errors["gitleaks"] = "binário não encontrado"
        except Exception as e:
            tool_errors["gitleaks"] = str(e)

        # Checkov
        try:
            checkov_res = subprocess.run(
                ["checkov", "-d", diretorio_temporario, "-o", "json", "--soft-fail"],
                capture_output=True, text=True,
            )
            out_checkov = checkov_res.stdout
            if "{" in out_checkov or "[" in out_checkov:
                start = min(
                    (out_checkov.find(c) for c in ("{", "[") if c in out_checkov),
                )
                out_checkov = out_checkov[start:]
            checkov_data = json.loads(out_checkov) if out_checkov else {}
        except FileNotFoundError:
            tool_errors["checkov"] = "binário não encontrado"
        except Exception as e:
            tool_errors["checkov"] = str(e)

    finally:
        shutil.rmtree(diretorio_temporario, ignore_errors=True)

    # 3. Determinação de vulnerabilidade — apenas severidade HIGH/CRITICAL conta
    _HIGH_SEVERITY = {"HIGH", "CRITICAL"}

    semgrep_vuln = any(
        f.get("extra", {}).get("severity", "").upper() in _HIGH_SEVERITY
        for f in semgrep_data.get("results", [])
    )

    trivy_vuln = any(
        vuln.get("Severity", "").upper() in _HIGH_SEVERITY
        for result in trivy_data.get("Results", [])
        for vuln in result.get("Vulnerabilities", [])
    )

    gitleaks_vuln = bool(gitleaks_data)  # qualquer segredo exposto = crítico

    checkov_reports = checkov_data if isinstance(checkov_data, list) else [checkov_data]
    checkov_vuln = any(
        report.get("results", {}).get("failed_checks")
        for report in checkov_reports
        if isinstance(report, dict)
    )

    is_vulnerable = semgrep_vuln or trivy_vuln or gitleaks_vuln or checkov_vuln

    # 4. Mapeamento de severidade real
    all_tools_failed = len(tool_errors) == 4
    if all_tools_failed:
        severity    = "ERROR"
        scan_status = "ERROR"
    elif tool_errors:
        severity    = "HIGH" if is_vulnerable else "PARTIAL"
        scan_status = "PARTIAL"
    else:
        severity    = "HIGH" if is_vulnerable else "CLEAN"
        scan_status = "OK"

    scanner_results = {
        "semgrep":  semgrep_data,
        "trivy":    trivy_data,
        "gitleaks": gitleaks_data,
        "checkov":  checkov_data,
    }
    cve_report = build_cve_report(trivy_data, semgrep_data)

    # Persiste findings em findings.json para alimentar Assets & Findings pages
    if body.repo_url and is_vulnerable:
        _persist_findings_from_scan(
            repo_url=body.repo_url, sha=body.sha,
            semgrep_data=semgrep_data, trivy_data=trivy_data,
            gitleaks_data=gitleaks_data, checkov_data=checkov_data,
        )

    return {
        "sha":             body.sha,
        "vulnerable":      is_vulnerable,
        "severity":        severity,
        "scan_status":     scan_status,
        "scanner_results": scanner_results,
        "cve_report":      cve_report,
        "tool_errors":     tool_errors,
        "tools_used":      [t for t in ["semgrep", "trivy", "gitleaks", "checkov"] if t not in tool_errors],
        "analyzed_at":     datetime.now(timezone.utc).isoformat(),
    }


# ─── Pipeline Background (Repositório Completo) ──────────────────────────────

from fastapi import BackgroundTasks
import uuid

class RepoScanBackgroundRequest(BaseModel):
    repo_url: str
    target_name: str
    interval_minutes: int = 0
    ai_summary_level: str = "EXECUTIVO"
    scan_paths: list = []          # [] = análise completa; lista de caminhos = escopo restrito
    github_token: Optional[str] = ""   # token BYOK para clonar repositórios privados

def run_background_repo_scan(
    scan_id: str, repo_url: str, gemini_key: str,
    ai_summary_level: str, scan_paths: list = None, github_token: Optional[str] = "",
):
    """
    Clona o repositório, executa os 4 scanners SAST com tratamento
    de falha por ferramenta, e consolida o resultado.
    """
    logger.info("[SAST Background] Iniciando scan %s para %s", scan_id, repo_url)
    REPO_SCANS[scan_id]["status"] = "RUNNING"

    diretorio_temporario = tempfile.mkdtemp(prefix="previswit_bg_sast_")
    semgrep_data  = {}
    trivy_data    = {}
    gitleaks_data = []
    checkov_data  = {}
    tool_errors   = {}

    try:
        # ── 1. Clone ─────────────────────────────────────────────────────────
        clone_url = _authenticated_clone_url(repo_url, github_token)
        clone = subprocess.run(
            ["git", "clone", "--depth", "1", clone_url, diretorio_temporario],
            capture_output=True, text=True, check=False,
        )
        if clone.returncode != 0:
            logger.error("[SAST Background] git clone falhou para %s: %s", repo_url, clone.stderr[:200])
            REPO_SCANS[scan_id]["status"] = "ERROR"
            REPO_SCANS[scan_id]["error"] = f"git clone falhou: {clone.stderr[:200]}"
            return

        # ── 2. Determinar targets de scan ─────────────────────────────────────
        if scan_paths:
            targets = [
                os.path.join(diretorio_temporario, p.lstrip("/\\"))
                for p in scan_paths
            ]
            targets = [t for t in targets if os.path.exists(t)] or [diretorio_temporario]
        else:
            targets = [diretorio_temporario]

        primary_target = targets[0]

        # ── 3. Semgrep — usa p/security-audit (não precisa de registry online) ─
        try:
            semgrep_cmd = [
                "semgrep", "scan",
                "--config", "p/security-audit",
                "--json", "--no-git-ignore",
            ] + targets
            semgrep_res = subprocess.run(
                semgrep_cmd, capture_output=True, text=True, timeout=240,
            )
            # fallback: se p/security-audit falhar, tenta auto
            if semgrep_res.returncode not in (0, 1) or not semgrep_res.stdout:
                semgrep_res = subprocess.run(
                    ["semgrep", "scan", "--config", "auto", "--json", "--no-git-ignore"] + targets,
                    capture_output=True, text=True, timeout=240,
                )
            semgrep_data = json.loads(semgrep_res.stdout) if semgrep_res.stdout else {}
        except FileNotFoundError:
            tool_errors["semgrep"] = "binário não encontrado"
        except subprocess.TimeoutExpired:
            tool_errors["semgrep"] = "timeout (4 min)"
        except Exception as e:
            tool_errors["semgrep"] = str(e)

        # ── 4. Trivy ──────────────────────────────────────────────────────────
        try:
            trivy_res = subprocess.run(
                ["trivy", "fs", "--format", "json", primary_target],
                capture_output=True, text=True, timeout=240,
            )
            out_text = trivy_res.stdout
            if "{" in out_text:
                out_text = out_text[out_text.index("{"):]
            trivy_data = json.loads(out_text) if out_text else {}
        except FileNotFoundError:
            tool_errors["trivy"] = "binário não encontrado"
        except subprocess.TimeoutExpired:
            tool_errors["trivy"] = "timeout"
        except Exception as e:
            tool_errors["trivy"] = str(e)

        # ── 5. Gitleaks ───────────────────────────────────────────────────────
        try:
            gitleaks_res = subprocess.run(
                ["gitleaks", "detect", "--source", primary_target,
                 "--report-format", "json", "--no-git", "--exit-code", "0"],
                capture_output=True, text=True, timeout=120,
            )
            gitleaks_data = json.loads(gitleaks_res.stdout) if gitleaks_res.stdout else []
        except FileNotFoundError:
            tool_errors["gitleaks"] = "binário não encontrado"
        except subprocess.TimeoutExpired:
            tool_errors["gitleaks"] = "timeout"
        except Exception as e:
            tool_errors["gitleaks"] = str(e)

        # ── 6. Checkov ────────────────────────────────────────────────────────
        try:
            checkov_res = subprocess.run(
                ["checkov", "-d", primary_target, "-o", "json", "--soft-fail"],
                capture_output=True, text=True, timeout=120,
            )
            out_checkov = checkov_res.stdout
            if "{" in out_checkov or "[" in out_checkov:
                start = min(
                    (out_checkov.find(c) for c in ("{", "[") if c in out_checkov)
                )
                out_checkov = out_checkov[start:]
            checkov_data = json.loads(out_checkov) if out_checkov else {}
        except FileNotFoundError:
            tool_errors["checkov"] = "binário não encontrado"
        except subprocess.TimeoutExpired:
            tool_errors["checkov"] = "timeout"
        except Exception as e:
            tool_errors["checkov"] = str(e)

    except Exception as e:
        logger.error("[SAST Background] Erro inesperado no scan %s: %s", scan_id, e)
        REPO_SCANS[scan_id]["status"] = "ERROR"
        REPO_SCANS[scan_id]["error"] = str(e)
        return
    finally:
        shutil.rmtree(diretorio_temporario, ignore_errors=True)

    # ── 7. Determinação de vulnerabilidade (HIGH/CRITICAL apenas) ─────────────
    _HIGH_SEV = {"HIGH", "CRITICAL"}

    semgrep_vuln = any(
        f.get("extra", {}).get("severity", "").upper() in _HIGH_SEV
        for f in semgrep_data.get("results", [])
    )
    trivy_vuln = any(
        vuln.get("Severity", "").upper() in _HIGH_SEV
        for result in trivy_data.get("Results", [])
        for vuln in result.get("Vulnerabilities", [])
    )
    gitleaks_vuln = bool(gitleaks_data)
    checkov_reports = checkov_data if isinstance(checkov_data, list) else [checkov_data]
    checkov_vuln = any(
        report.get("results", {}).get("failed_checks")
        for report in checkov_reports if isinstance(report, dict)
    )

    is_vulnerable  = semgrep_vuln or trivy_vuln or gitleaks_vuln or checkov_vuln
    all_failed     = len(tool_errors) == 4
    severity       = "ERROR" if all_failed else ("HIGH" if is_vulnerable else "CLEAN")
    scan_status_v  = "ERROR" if all_failed else ("PARTIAL" if tool_errors else "OK")

    # ── 8. Contagens para exibição no painel ──────────────────────────────────
    def _trivy_high(td):
        return sum(
            1 for r in td.get("Results", [])
            for v in r.get("Vulnerabilities", [])
            if v.get("Severity", "").upper() in _HIGH_SEV
        )
    def _checkov_failed(cd):
        reports = cd if isinstance(cd, list) else [cd]
        return sum(
            len(r.get("results", {}).get("failed_checks", []))
            for r in reports if isinstance(r, dict)
        )

    counts = {
        "semgrep":  len([
            f for f in semgrep_data.get("results", [])
            if f.get("extra", {}).get("severity", "").upper() in _HIGH_SEV
        ]),
        "trivy":    _trivy_high(trivy_data),
        "gitleaks": len(gitleaks_data) if isinstance(gitleaks_data, list) else 0,
        "checkov":  _checkov_failed(checkov_data),
    }

    # ── 9. Gemini Insight ─────────────────────────────────────────────────────
    insight_text = ""
    if is_vulnerable and gemini_key:
        import time as _time

        foco_ia = (
            "detalhes técnicos das falhas, regras violadas e sugestões de correção (Visão Técnica)"
            if ai_summary_level == "TECNICO" else
            "impacto em controles ISO 27001 e SOC2 (Visão de Conformidade)"
            if ai_summary_level == "CONFORMIDADE" else
            "impacto de risco no negócio, sem se aprofundar em código (Visão Executiva)"
        )
        prompt = (
            f"Atue como Arquiteto Sênior de AppSec. Analisamos {repo_url} "
            f"(Semgrep {counts['semgrep']} achados HIGH/CRITICAL, "
            f"Trivy {counts['trivy']} CVEs HIGH/CRITICAL, "
            f"Gitleaks {counts['gitleaks']} segredos, "
            f"Checkov {counts['checkov']} falhas IaC). "
            f"Gere um resumo conciso (máx. 2 parágrafos) focado em: {foco_ia}. Apenas texto limpo."
        )

        # O Gemini devolve 503 UNAVAILABLE sob alta demanda — falha transitória.
        # Aplica a mesma política de resiliência já usada em ai_chat.py e no agente:
        # 3 tentativas com backoff. Antes havia tentativa única, então qualquer
        # soluço do provedor virava "Erro ao conectar" na tela.
        for attempt in range(3):
            try:
                from google import genai as _genai
                client = _genai.Client(api_key=gemini_key)
                response = client.models.generate_content(
                    model="gemini-2.5-flash", contents=prompt
                )
                if response.text:
                    insight_text = response.text.strip()
                break
            except Exception as e:
                err = str(e)
                transitorio = any(
                    m in err for m in ("503", "UNAVAILABLE", "429", "RESOURCE_EXHAUSTED")
                )
                logger.warning(
                    "Gemini insight tentativa %d/3 falhou: %s", attempt + 1, err[:160]
                )
                if transitorio and attempt < 2:
                    _time.sleep(2 ** (attempt + 1))   # 2s, depois 4s
                    continue

                logger.error("Erro Gemini insight (definitivo): %s", err)
                # Degrada com o dado real do scan em vez de deixar o painel sem saída.
                motivo = (
                    "o Gemini está com alta demanda"
                    if transitorio else "houve falha na chamada à IA"
                )
                insight_text = (
                    f"O resumo por IA não pôde ser gerado agora porque {motivo}. "
                    f"Resultado do scan: Semgrep {counts['semgrep']} achados HIGH/CRITICAL, "
                    f"Trivy {counts['trivy']} CVEs HIGH/CRITICAL, "
                    f"Gitleaks {counts['gitleaks']} segredos expostos, "
                    f"Checkov {counts['checkov']} falhas de IaC. "
                    f"Rode a análise novamente em alguns instantes para obter o texto."
                )
                break

    # ── 10. CVE enrichment ────────────────────────────────────────────────────
    cve_report = build_cve_report(trivy_data, semgrep_data)

    # ── 11. Persiste findings ─────────────────────────────────────────────────
    if is_vulnerable:
        _persist_findings_from_scan(
            repo_url=repo_url, sha="background",
            semgrep_data=semgrep_data, trivy_data=trivy_data,
            gitleaks_data=gitleaks_data, checkov_data=checkov_data,
        )

    REPO_SCANS[scan_id]["data"] = {
        "vulnerable":      is_vulnerable,
        "severity":        severity,
        "scan_status":     scan_status_v,
        "scanner_results": {
            "semgrep":  semgrep_data,
            "trivy":    trivy_data,
            "gitleaks": gitleaks_data,
            "checkov":  checkov_data,
        },
        "counts":          counts,
        "tool_errors":     tool_errors,
        "cve_report":      cve_report,
        "ai_insight":      insight_text,
        "scanned_paths":   scan_paths or [],
        "tools_used":      [t for t in ["semgrep", "trivy", "gitleaks", "checkov"] if t not in tool_errors],
        "analyzed_at":     datetime.now(timezone.utc).isoformat(),
    }
    REPO_SCANS[scan_id]["status"] = "CONCLUÍDO"
    logger.info("[SAST Background] Scan %s finalizado — vulnerable=%s", scan_id, is_vulnerable)

@router.post(
    "/schedule",
    summary="Dispara ou agenda um pipeline de scan em background",
)
async def scan_repo_schedule(
    body: RepoScanBackgroundRequest,
    background_tasks: BackgroundTasks,
    x_gemini_key: Optional[str] = FastAPIHeader(default=None, alias="X-Gemini-Key"),
):
    scan_id = str(uuid.uuid4())
    
    # Registra estado
    REPO_SCANS[scan_id] = {
        "status": "PENDING",
        "data": None,
        "error": None,
        "repo": body.repo_url,
        "target": body.target_name,
        "interval_minutes": body.interval_minutes,
        "ai_summary_level": body.ai_summary_level
    }
    
    # Enfileira task (Se fosse 1H ou 24H, poderiamos usar apscheduler,
    # mas para MVP a execução principal ocorre via task simples e 
    # o status CONCLUÍDO fica em memória).
    background_tasks.add_task(run_background_repo_scan, scan_id, body.repo_url, x_gemini_key, body.ai_summary_level, body.scan_paths, body.github_token)
    
    return {
        "scan_id": scan_id,
        "status": "PENDING",
        "message": "Orquestração SAST iniciada."
    }

@router.get(
    "/scan-status/{scan_id}",
    summary="Verifica o status de um scan em background",
)
async def check_scan_status(scan_id: str):
    if scan_id not in REPO_SCANS:
        raise HTTPException(status_code=404, detail="Scan não encontrado.")
    return REPO_SCANS[scan_id]

