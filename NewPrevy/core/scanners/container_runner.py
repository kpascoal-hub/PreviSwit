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
PreviSwit AI-ASPM — core/scanners/container_runner.py
Scanner dedicado à análise de vulnerabilidades em imagens Docker via Trivy.

Fluxo:
  run_trivy_image(image_name) → subprocess Trivy → JSON normalizado
  (Chamado via asyncio.to_thread para não bloquear o event-loop)

Armadura de Falha Total:
  - FileNotFoundError   → Trivy não instalado no PATH
  - TimeoutExpired      → imagem gigante ou pull muito lento
  - JSONDecodeError     → output corrompido do Trivy
  - Exception genérica  → qualquer erro inesperado
  Em todos os casos retorna _fallback() sem crashar o container.
"""

import json
import asyncio
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("container_runner")

_TIMEOUT_TRIVY_IMAGE = 600   # 10 min — imagens grandes podem demorar no pull


def _fallback(tool: str, reason: str, raw: str = "") -> dict:
    """Retorna payload de erro padronizado sem causar crash."""
    return {
        "status": "error",
        "tool": tool,
        "reason": reason,
        "raw_output": raw[:2000] if raw else "",
        "ts": datetime.now(timezone.utc).isoformat(),
    }


# ── Trivy Image ───────────────────────────────────────────────────────────────

def _trivy_image_blocking(image_name: str) -> dict:
    """Executa trivy image de forma síncrona (chamado via asyncio.to_thread)."""
    if not image_name or not image_name.strip():
        return _fallback("trivy_image", "Nome da imagem não pode estar vazio.")

    image = image_name.strip()

    try:
        result = subprocess.run(
            [
                "trivy", "image",
                "--format", "json",
                "--severity", "CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN",
                "--timeout", "8m",
                image,
            ],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_TRIVY_IMAGE,
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        # Trivy retorna exit code 1 quando encontra vulnerabilidades (comportamento normal)
        # exit code >= 2 indica erros reais (imagem não encontrada, daemon offline, etc.)
        if result.returncode >= 2 and not stdout:
            log.warning("[Trivy Image] Código %d — stderr: %s", result.returncode, stderr[:500])
            return _fallback("trivy_image", f"Trivy falhou (code={result.returncode}): {stderr[:300]}", stderr)

        if not stdout:
            return {
                "status": "ok",
                "tool": "trivy_image",
                "image": image,
                "vulnerabilities": [],
                "stats": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
                "ts": datetime.now(timezone.utc).isoformat(),
            }

        # Trivy pode emitir logs antes do JSON — pula tudo até o primeiro '{'
        if "{" in stdout:
            stdout = stdout[stdout.index("{"):]

        parsed = json.loads(stdout)

        # ── Extrai e normaliza CVEs de todos os targets ────────────────────────
        vulnerabilities = []
        stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}

        for target in parsed.get("Results", []):
            target_name = target.get("Target", image)
            target_type = target.get("Type", "")

            for vuln in target.get("Vulnerabilities") or []:
                sev = (vuln.get("Severity") or "UNKNOWN").upper()
                stats["total"] += 1
                stats[sev.lower() if sev.lower() in stats else "unknown"] += 1

                vulnerabilities.append({
                    "cve_id":           vuln.get("VulnerabilityID", "N/A"),
                    "package":          vuln.get("PkgName", "—"),
                    "severity":         sev,
                    "installed_version": vuln.get("InstalledVersion", "—"),
                    "fixed_version":    vuln.get("FixedVersion") or "Sem correção disponível",
                    "title":            vuln.get("Title") or vuln.get("Description", "Sem descrição"),
                    "description":      vuln.get("Description", ""),
                    "primary_url":      vuln.get("PrimaryURL", ""),
                    "target":           target_name,
                    "target_type":      target_type,
                    "cvss_score":       _extract_cvss(vuln),
                    "references":       (vuln.get("References") or [])[:3],
                })

        # Ordena por severidade: CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN
        _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        vulnerabilities.sort(key=lambda v: _SEV_ORDER.get(v["severity"], 5))

        return {
            "status": "ok",
            "tool": "trivy_image",
            "image": image,
            "schema_version": parsed.get("SchemaVersion"),
            "artifact_name": parsed.get("ArtifactName", image),
            "artifact_type": parsed.get("ArtifactType", "container_image"),
            "vulnerabilities": vulnerabilities,
            "stats": stats,
            "ts": datetime.now(timezone.utc).isoformat(),
        }

    except subprocess.TimeoutExpired:
        log.error("[Trivy Image] Timeout de %ds para imagem '%s'", _TIMEOUT_TRIVY_IMAGE, image)
        return _fallback("trivy_image", f"Timeout após {_TIMEOUT_TRIVY_IMAGE}s. Imagem muito grande ou pull lento.")
    except json.JSONDecodeError as e:
        log.error("[Trivy Image] JSON inválido: %s", e)
        return _fallback("trivy_image", f"Saída JSON inválida do Trivy: {e}", stdout[:500] if 'stdout' in dir() else "")
    except FileNotFoundError:
        log.warning("[Trivy Image] Binário 'trivy' não encontrado no PATH.")
        return _fallback("trivy_image", "Binário 'trivy' não encontrado no PATH. Verifique o Dockerfile do Agente.")
    except Exception as e:
        log.exception("[Trivy Image] Erro inesperado para imagem '%s'", image)
        return _fallback("trivy_image", str(e))


def _extract_cvss(vuln: dict) -> float | None:
    """Extrai score CVSS do payload do Trivy (v2 ou v3)."""
    try:
        cvss = vuln.get("CVSS", {})
        for source in cvss.values():
            v3 = source.get("V3Score") or source.get("v3Score")
            if v3:
                return round(float(v3), 1)
            v2 = source.get("V2Score") or source.get("v2Score")
            if v2:
                return round(float(v2), 1)
    except Exception:
        pass
    return None


async def run_trivy_image(image_name: str) -> dict:
    """
    [Async] Executa o Trivy para análise de vulnerabilidades em imagem Docker.
    Retorna dict com 'status', 'image', 'vulnerabilities' e 'stats'.
    """
    log.info("🐳 [Trivy Image] Iniciando scan da imagem: %s", image_name)
    result = await asyncio.to_thread(_trivy_image_blocking, image_name)
    total = result.get("stats", {}).get("total", "?")
    log.info("✅ [Trivy Image] Concluído para '%s' — %s CVEs encontrados", image_name, total)
    return result
