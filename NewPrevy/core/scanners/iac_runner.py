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
PreviSwit AI-ASPM — core/scanners/iac_runner.py
Scanner dedicado à análise estática de Infraestrutura como Código (IaC).

Ferramentas embarcadas:
  - Checkov   (Terraform, Kubernetes, Dockerfile, ARM, Bicep, CloudFormation)
  - Trivy     (IaC scanning mode: trivy config)

Cada função executa seu binário via subprocess em uma thread separada
(asyncio.to_thread) para não bloquear o event-loop do WebSocket.
Os erros são capturados e retornados como dicts estruturados — NUNCA
crasham o container do Agente.
"""

import json
import asyncio
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("iac_runner")

# Timeout por ferramenta (segundos).
_TIMEOUT_CHECKOV = 300
_TIMEOUT_TRIVY   = 300


def _fallback(tool: str, reason: str, raw: str = "") -> dict:
    """Retorna um payload de erro padronizado sem causar crash."""
    return {
        "status": "error",
        "tool": tool,
        "reason": reason,
        "raw_output": raw[:2000] if raw else "",
        "ts": datetime.now(timezone.utc).isoformat(),
    }


# ── Checkov IaC ──────────────────────────────────────────────────────────────

def _checkov_iac_blocking(target_path: str) -> dict:
    """Executa checkov focado em IaC de forma síncrona."""
    target = Path(target_path)
    if not target.exists():
        return _fallback("checkov_iac", f"Caminho não encontrado: {target_path}")

    try:
        result = subprocess.run(
            [
                "checkov",
                "-d", str(target),
                "-o", "json",
                "--quiet",
                "--compact",
                "--framework", "all",   # Terraform, K8s, Docker, ARM, Bicep, CloudFormation
            ],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_CHECKOV,
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode == 2:
            return _fallback("checkov_iac", f"Checkov falhou internamente (code=2)", stderr)

        if not stdout:
            return {
                "status": "ok",
                "tool": "checkov_iac",
                "results": [],
                "stats": {"passed": 0, "failed": 0, "skipped": 0},
                "frameworks_detected": [],
                "ts": datetime.now(timezone.utc).isoformat(),
            }

        # Checkov pode retornar uma lista (um objeto por framework) ou um único dict
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            lines = [l for l in stdout.splitlines() if l.strip().startswith(("{", "["))]
            if not lines:
                return _fallback("checkov_iac", "JSON inválido na saída do Checkov", stdout[:500])
            parsed = json.loads(lines[-1])

        if isinstance(parsed, dict):
            parsed = [parsed]

        # Agrega estatísticas + extrai má-configurações
        total_passed = total_failed = total_skipped = 0
        misconfigurations = []
        frameworks_detected = []

        for framework_result in parsed:
            check_type = framework_result.get("check_type", "unknown")
            frameworks_detected.append(check_type)
            summary = framework_result.get("summary", {})
            total_passed  += summary.get("passed",  0)
            total_failed  += summary.get("failed",  0)
            total_skipped += summary.get("skipped", 0)

            # Extrai findings individuais formatados para a tabela do frontend
            failed_checks = framework_result.get("results", {}).get("failed_checks", [])
            for check in failed_checks:
                misconfigurations.append({
                    "id": check.get("check_id", "N/A"),
                    "resource": check.get("resource", check.get("name", "Recurso Desconhecido")),
                    "misconfiguration": check.get("check_name", check.get("name", "Sem Descrição")),
                    "severity": check.get("severity", check.get("check_result", {}).get("result", "MEDIUM")),
                    "framework": check_type,
                    "file_path": check.get("file_path", ""),
                    "file_line": check.get("file_line_range", []),
                    "guideline": check.get("guideline", ""),
                })

        return {
            "status": "ok",
            "tool": "checkov_iac",
            "results": parsed,
            "misconfigurations": misconfigurations,
            "frameworks_detected": list(set(frameworks_detected)),
            "stats": {
                "passed":  total_passed,
                "failed":  total_failed,
                "skipped": total_skipped,
            },
            "ts": datetime.now(timezone.utc).isoformat(),
        }

    except subprocess.TimeoutExpired:
        log.error("Checkov IaC excedeu timeout de %ds para %s", _TIMEOUT_CHECKOV, target_path)
        return _fallback("checkov_iac", f"Timeout após {_TIMEOUT_CHECKOV}s")
    except FileNotFoundError:
        return _fallback("checkov_iac", "Binário 'checkov' não encontrado no PATH. Verifique o Dockerfile.")
    except Exception as e:
        log.exception("Erro inesperado no Checkov IaC runner")
        return _fallback("checkov_iac", str(e))


async def run_checkov_iac(target_path: str) -> dict:
    """
    [Async] Executa o Checkov focado em IaC (Terraform, K8s, Docker, ARM, Bicep, CloudFormation).
    Retorna dict com 'status', 'results', 'misconfigurations' e 'stats'.
    """
    log.info("🏗️  [Checkov IaC] Iniciando scan em: %s", target_path)
    result = await asyncio.to_thread(_checkov_iac_blocking, target_path)
    stats = result.get("stats", {})
    log.info("✅ [Checkov IaC] Concluído — passed=%s failed=%s", stats.get("passed"), stats.get("failed"))
    return result


# ── Trivy Config (IaC) ──────────────────────────────────────────────────────

def _trivy_iac_blocking(target_path: str) -> dict:
    """Executa trivy config focado em IaC de forma síncrona."""
    target = Path(target_path)
    if not target.exists():
        return _fallback("trivy_iac", f"Caminho não encontrado: {target_path}")

    try:
        result = subprocess.run(
            [
                "trivy", "config",
                "--format", "json",
                "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
                str(target),
            ],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_TRIVY,
        )

        stdout = result.stdout.strip()

        if not stdout:
            return {
                "status": "ok",
                "tool": "trivy_iac",
                "results": {},
                "misconfigurations": [],
                "stats": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                "ts": datetime.now(timezone.utc).isoformat(),
            }

        # Trivy JSON pode estar embutido em logs
        if "{" in stdout:
            stdout = stdout[stdout.index("{"):]

        parsed = json.loads(stdout)

        # Extrai misconfigurations formatados
        misconfigurations = []
        total = critical = high = medium = low = 0

        results_list = parsed.get("Results", [])
        for res in results_list:
            misconf_list = res.get("Misconfigurations", [])
            for m in misconf_list:
                sev = m.get("Severity", "MEDIUM").upper()
                total += 1
                if sev == "CRITICAL": critical += 1
                elif sev == "HIGH": high += 1
                elif sev == "MEDIUM": medium += 1
                else: low += 1

                misconfigurations.append({
                    "id": m.get("ID", "N/A"),
                    "resource": m.get("Type", res.get("Target", "Recurso")),
                    "misconfiguration": m.get("Title", m.get("Message", "Sem Descrição")),
                    "severity": sev,
                    "framework": res.get("Type", "iac"),
                    "file_path": res.get("Target", ""),
                    "resolution": m.get("Resolution", ""),
                    "primary_url": m.get("PrimaryURL", ""),
                })

        return {
            "status": "ok",
            "tool": "trivy_iac",
            "results": parsed,
            "misconfigurations": misconfigurations,
            "stats": {
                "total": total,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
            "ts": datetime.now(timezone.utc).isoformat(),
        }

    except subprocess.TimeoutExpired:
        log.error("Trivy Config excedeu timeout de %ds para %s", _TIMEOUT_TRIVY, target_path)
        return _fallback("trivy_iac", f"Timeout após {_TIMEOUT_TRIVY}s")
    except json.JSONDecodeError as e:
        log.error("Trivy Config retornou JSON inválido: %s", e)
        return _fallback("trivy_iac", f"JSON inválido: {e}")
    except FileNotFoundError:
        return _fallback("trivy_iac", "Binário 'trivy' não encontrado no PATH. Verifique o Dockerfile.")
    except Exception as e:
        log.exception("Erro inesperado no Trivy IaC runner")
        return _fallback("trivy_iac", str(e))


async def run_trivy_iac(target_path: str) -> dict:
    """
    [Async] Executa o Trivy em modo config/IaC.
    Retorna dict com 'status', 'results', 'misconfigurations' e 'stats'.
    """
    log.info("🔍 [Trivy IaC] Iniciando scan em: %s", target_path)
    result = await asyncio.to_thread(_trivy_iac_blocking, target_path)
    stats = result.get("stats", {})
    log.info("✅ [Trivy IaC] Concluído — total=%s findings", stats.get("total", "?"))
    return result


# ── Orquestrador Combinado ───────────────────────────────────────────────────

async def run_full_iac_scan(target_path: str) -> dict:
    """
    [Async] Executa Checkov + Trivy em paralelo para cobertura máxima de IaC.
    Retorna dict unificado com misconfigurations de ambas as ferramentas.
    """
    log.info("🏗️  [IaC Full Scan] Iniciando scan combinado em: %s", target_path)

    checkov_result, trivy_result = await asyncio.gather(
        run_checkov_iac(target_path),
        run_trivy_iac(target_path),
    )

    # Unifica misconfigurations
    all_misconfigs = []
    all_misconfigs.extend(checkov_result.get("misconfigurations", []))
    all_misconfigs.extend(trivy_result.get("misconfigurations", []))

    # Deduplica por ID
    seen_ids = set()
    unique_misconfigs = []
    for m in all_misconfigs:
        mid = m.get("id", "") + m.get("resource", "") + m.get("file_path", "")
        if mid not in seen_ids:
            seen_ids.add(mid)
            unique_misconfigs.append(m)

    return {
        "status": "ok",
        "tools_used": ["checkov", "trivy"],
        "checkov": checkov_result,
        "trivy": trivy_result,
        "misconfigurations": unique_misconfigs,
        "stats": {
            "total_misconfigurations": len(unique_misconfigs),
            "checkov_passed": checkov_result.get("stats", {}).get("passed", 0),
            "checkov_failed": checkov_result.get("stats", {}).get("failed", 0),
            "trivy_critical": trivy_result.get("stats", {}).get("critical", 0),
            "trivy_high": trivy_result.get("stats", {}).get("high", 0),
        },
        "frameworks_detected": checkov_result.get("frameworks_detected", []),
        "ts": datetime.now(timezone.utc).isoformat(),
    }
