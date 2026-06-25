"""
PreviSwit — core/scanners/sast_runner.py
Runners individuais e assíncronos para cada ferramenta SAST embarcada.

Ferramentas:
  - Semgrep   (SAST genérico via AST)
  - Gitleaks  (detecção de segredos/credenciais)
  - Checkov   (análise de IaC: Terraform, Kubernetes, Docker, etc.)

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

log = logging.getLogger("sast_runner")

# Timeout por ferramenta (segundos). Ajuste conforme o tamanho dos repos.
_TIMEOUT_SEMGREP  = 300
_TIMEOUT_GITLEAKS = 120
_TIMEOUT_CHECKOV  = 300


def _fallback(tool: str, reason: str, raw: str = "") -> dict:
    """Retorna um payload de erro padronizado sem causar crash."""
    return {
        "status": "error",
        "tool": tool,
        "reason": reason,
        "raw_output": raw[:2000] if raw else "",
        "ts": datetime.now(timezone.utc).isoformat(),
    }


# ── Semgrep ───────────────────────────────────────────────────────────────────

def _semgrep_blocking(target_path: str) -> dict:
    """Executa semgrep de forma síncrona (chamado via asyncio.to_thread)."""
    target = Path(target_path)
    if not target.exists():
        return _fallback("semgrep", f"Caminho não encontrado: {target_path}")

    try:
        result = subprocess.run(
            [
                "semgrep", "scan",
                "--config", "auto",
                "--json",
                "--timeout", "60",      # timeout por arquivo (semgrep interno)
                str(target),
            ],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SEMGREP,
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        # Semgrep retorna exit code 1 quando encontra findings (comportamento normal)
        # e exit code 2+ para erros reais.
        if result.returncode >= 2 and not stdout:
            log.warning("Semgrep retornou código %d — stderr: %s", result.returncode, stderr[:500])
            return _fallback("semgrep", f"Semgrep terminou com erro (code={result.returncode})", stderr)

        if not stdout:
            return {
                "status": "ok",
                "tool": "semgrep",
                "results": [],
                "stats": {"total_findings": 0},
                "ts": datetime.now(timezone.utc).isoformat(),
            }

        parsed = json.loads(stdout)
        findings = parsed.get("results", [])

        return {
            "status": "ok",
            "tool": "semgrep",
            "results": findings,
            "errors": parsed.get("errors", []),
            "stats": {
                "total_findings": len(findings),
                "severity_breakdown": _count_semgrep_severities(findings),
            },
            "ts": datetime.now(timezone.utc).isoformat(),
        }

    except subprocess.TimeoutExpired:
        log.error("Semgrep excedeu timeout de %ds para %s", _TIMEOUT_SEMGREP, target_path)
        return _fallback("semgrep", f"Timeout após {_TIMEOUT_SEMGREP}s")
    except json.JSONDecodeError as e:
        log.error("Semgrep retornou JSON inválido: %s", e)
        return _fallback("semgrep", f"JSON inválido na saída do semgrep: {e}", result.stdout[:500] if 'result' in dir() else "")
    except FileNotFoundError:
        return _fallback("semgrep", "Binário 'semgrep' não encontrado no PATH. Verifique o Dockerfile.")
    except Exception as e:
        log.exception("Erro inesperado no Semgrep runner")
        return _fallback("semgrep", str(e))


def _count_semgrep_severities(findings: list) -> dict:
    counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    for f in findings:
        sev = f.get("extra", {}).get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


async def run_semgrep(target_path: str) -> dict:
    """
    [Async] Executa o Semgrep SAST no caminho alvo.
    Retorna dict com 'status', 'results' e 'stats'.
    """
    log.info("🔍 [Semgrep] Iniciando scan em: %s", target_path)
    result = await asyncio.to_thread(_semgrep_blocking, target_path)
    count = result.get("stats", {}).get("total_findings", "?")
    log.info("✅ [Semgrep] Concluído — %s findings", count)
    return result


# ── Gitleaks ──────────────────────────────────────────────────────────────────

def _gitleaks_blocking(target_path: str) -> dict:
    """Executa gitleaks de forma síncrona (chamado via asyncio.to_thread)."""
    target = Path(target_path)
    if not target.exists():
        return _fallback("gitleaks", f"Caminho não encontrado: {target_path}")

    report_file = "/tmp/gitleaks_report.json"

    try:
        result = subprocess.run(
            [
                "gitleaks", "detect",
                "--source", str(target),
                "--report-format", "json",
                "--report-path", report_file,
                "--no-git",              # Não requer .git — analisa arquivos raw
                "--exit-code", "0",      # Não falha com exit 1 ao encontrar segredos
            ],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_GITLEAKS,
        )

        # Tenta ler o relatório JSON gerado
        try:
            with open(report_file, "r", encoding="utf-8") as fh:
                findings = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            findings = []

        return {
            "status": "ok",
            "tool": "gitleaks",
            "results": findings,
            "stats": {
                "total_secrets_found": len(findings),
                "types": list({f.get("RuleID", "unknown") for f in findings}),
            },
            "ts": datetime.now(timezone.utc).isoformat(),
        }

    except subprocess.TimeoutExpired:
        log.error("Gitleaks excedeu timeout de %ds", _TIMEOUT_GITLEAKS)
        return _fallback("gitleaks", f"Timeout após {_TIMEOUT_GITLEAKS}s")
    except FileNotFoundError:
        return _fallback("gitleaks", "Binário 'gitleaks' não encontrado. Verifique o Dockerfile.")
    except Exception as e:
        log.exception("Erro inesperado no Gitleaks runner")
        return _fallback("gitleaks", str(e))


async def run_gitleaks(target_path: str) -> dict:
    """
    [Async] Executa o Gitleaks para detecção de segredos e credenciais.
    Retorna dict com 'status', 'results' e 'stats'.
    """
    log.info("🔑 [Gitleaks] Iniciando scan em: %s", target_path)
    result = await asyncio.to_thread(_gitleaks_blocking, target_path)
    count = result.get("stats", {}).get("total_secrets_found", "?")
    log.info("✅ [Gitleaks] Concluído — %s segredos detectados", count)
    return result


# ── Checkov ───────────────────────────────────────────────────────────────────

def _checkov_blocking(target_path: str) -> dict:
    """Executa checkov de forma síncrona (chamado via asyncio.to_thread)."""
    target = Path(target_path)
    if not target.exists():
        return _fallback("checkov", f"Caminho não encontrado: {target_path}")

    try:
        result = subprocess.run(
            [
                "checkov",
                "-d", str(target),
                "-o", "json",
                "--quiet",              # Remove output de progresso
                "--compact",            # JSON compacto
            ],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_CHECKOV,
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        # Checkov retorna exit code 1 quando há falhas (comportamento normal)
        # exit code 2 indica erro real de execução
        if result.returncode == 2:
            return _fallback("checkov", f"Checkov falhou internamente (code=2)", stderr)

        if not stdout:
            return {
                "status": "ok",
                "tool": "checkov",
                "results": {},
                "stats": {"passed": 0, "failed": 0, "skipped": 0},
                "ts": datetime.now(timezone.utc).isoformat(),
            }

        # Checkov pode retornar uma lista (um objeto por framework) ou um único dict
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            # Tenta extrair o JSON do meio do output (algumas versões misturam logs)
            lines = [l for l in stdout.splitlines() if l.strip().startswith(("{", "["))]
            if not lines:
                return _fallback("checkov", "JSON inválido na saída do Checkov", stdout)
            parsed = json.loads(lines[-1])

        # Normaliza: garante que seja sempre uma lista de resultados por framework
        if isinstance(parsed, dict):
            parsed = [parsed]

        # Agrega estatísticas de todos os frameworks
        total_passed = total_failed = total_skipped = 0
        for framework_result in parsed:
            summary = framework_result.get("summary", {})
            total_passed  += summary.get("passed",  0)
            total_failed  += summary.get("failed",  0)
            total_skipped += summary.get("skipped", 0)

        return {
            "status": "ok",
            "tool": "checkov",
            "results": parsed,
            "stats": {
                "passed":  total_passed,
                "failed":  total_failed,
                "skipped": total_skipped,
            },
            "ts": datetime.now(timezone.utc).isoformat(),
        }

    except subprocess.TimeoutExpired:
        log.error("Checkov excedeu timeout de %ds para %s", _TIMEOUT_CHECKOV, target_path)
        return _fallback("checkov", f"Timeout após {_TIMEOUT_CHECKOV}s")
    except FileNotFoundError:
        return _fallback("checkov", "Binário 'checkov' não encontrado. Verifique o Dockerfile.")
    except Exception as e:
        log.exception("Erro inesperado no Checkov runner")
        return _fallback("checkov", str(e))


async def run_checkov(target_path: str) -> dict:
    """
    [Async] Executa o Checkov para análise de IaC (Terraform, K8s, Docker, etc.).
    Retorna dict com 'status', 'results' e 'stats'.
    """
    log.info("🏗️  [Checkov] Iniciando scan em: %s", target_path)
    result = await asyncio.to_thread(_checkov_blocking, target_path)
    stats = result.get("stats", {})
    log.info("✅ [Checkov] Concluído — passed=%s failed=%s", stats.get("passed"), stats.get("failed"))
    return result
