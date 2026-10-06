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
PreviSwit ASPM - Semgrep Parser
================================
Lógica extraída e adaptada do DefectDojo (dojo/tools/semgrep/parser.py).
Suporta dois formatos de output do Semgrep:
  - Resultado de regras SAST (campo "results")
  - Resultado de análise de dependências (campo "vulns")

Referência original: https://github.com/DefectDojo/django-DefectDojo

IMPORTANTE: Este módulo é 100% Python puro e assíncrono.
Não possui dependências de Django, banco de dados ou ORM.
"""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Mapeamento de severidade (formato Semgrep → PreviSwit)
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "Critical",
    "ERROR": "High",
    "HIGH": "High",
    "WARNING": "Medium",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Low",
}


def _convert_severity(val: str) -> str:
    """Normaliza a severidade do Semgrep para o padrão PreviSwit.

    Args:
        val: Severidade original do Semgrep (case-insensitive).

    Returns:
        String normalizada: "Critical", "High", "Medium" ou "Low".

    Raises:
        ValueError: Se o valor não for reconhecido.
    """
    normalized = _SEVERITY_MAP.get(val.upper())
    if normalized is None:
        raise ValueError(f"Severidade desconhecida do Semgrep: '{val}'")
    return normalized


# ---------------------------------------------------------------------------
# Extração de CWE
# ---------------------------------------------------------------------------

def _extract_cwe(cwe_value: str | list | None) -> int | None:
    """Extrai o número inteiro do CWE a partir de strings como 'CWE-89: SQL Injection'.

    Args:
        cwe_value: String ou lista de strings no formato 'CWE-<N>: <descrição>'.

    Returns:
        Inteiro com o número do CWE, ou None se não for possível extrair.
    """
    if not cwe_value:
        return None
    raw = cwe_value[0] if isinstance(cwe_value, list) else cwe_value
    try:
        # "CWE-89: SQL..." → split por ":" → "CWE-89" → split por "-" → "89"
        return int(raw.partition(":")[0].partition("-")[2])
    except (ValueError, IndexError):
        logger.warning("Não foi possível extrair CWE de: %s", raw)
        return None


# ---------------------------------------------------------------------------
# Construção de descrição
# ---------------------------------------------------------------------------

def _build_description(item: dict) -> str:
    """Constrói a descrição do achado a partir dos campos do item Semgrep.

    Args:
        item: Dicionário representando um resultado do Semgrep.

    Returns:
        String formatada em Markdown com mensagem e snippet de código.
    """
    extra = item.get("extra", {})
    description = ""

    message = extra.get("message", "")
    description += f"**Mensagem:** {message}\n"

    snippet = extra.get("lines")
    if snippet == "requires login":
        snippet = None  # Trata "requires login" como ausência de snippet

    if snippet is not None:
        # Workaround para evitar renderização incorreta de imagens Markdown
        if "<![" in snippet:
            snippet = snippet.replace("<![", "<! [")
            description += (
                f"**Snippet:** ***Atenção:*** Remova o espaço entre `!` e `[` para "
                f"obter o valor real.\n```{snippet}```\n"
            )
        else:
            description += f"**Snippet:**\n```{snippet}```\n"

    return description


# ---------------------------------------------------------------------------
# Parser SAST (campo "results")
# ---------------------------------------------------------------------------

def _parse_results(data: dict) -> list[dict]:
    """Processa a seção 'results' do JSON do Semgrep (modo SAST de regras).

    Args:
        data: Dicionário com o JSON completo do Semgrep.

    Returns:
        Lista de dicionários de achados (sem duplicatas por title+file+line).
    """
    dupes: dict[str, dict] = {}

    for item in data.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})

        try:
            severity = _convert_severity(extra.get("severity", "INFO"))
        except ValueError:
            severity = "Low"
            logger.warning("Severidade inválida para item: %s", item.get("check_id"))

        finding: dict[str, Any] = {
            "title": item.get("check_id"),
            "severity": severity,
            "description": _build_description(item),
            "file_path": item.get("path"),
            "line": item.get("start", {}).get("line"),
            "vuln_id_from_tool": item.get("check_id"),
            "unique_id_from_tool": None,
            "cwe": None,
            "references": None,
            "mitigation": None,
            "static_finding": True,
            "dynamic_finding": False,
            "nb_occurrences": 1,
            "tool": "semgrep",
            "scan_type": "sast",
        }

        # Fingerprint (unique_id)
        fingerprint = extra.get("fingerprint")
        if fingerprint and fingerprint != "requires login":
            finding["unique_id_from_tool"] = fingerprint

        # CWE
        finding["cwe"] = _extract_cwe(metadata.get("cwe"))

        # Referências
        refs = metadata.get("references")
        if refs and isinstance(refs, list):
            finding["references"] = "\n".join(refs)
        elif refs:
            finding["references"] = str(refs)

        # Mitigação
        if "fix" in extra:
            finding["mitigation"] = extra["fix"]
        elif "fix_regex" in extra:
            finding["mitigation"] = (
                "**Você pode aplicar este regex automaticamente:**\n\n```\n"
                + json.dumps(extra["fix_regex"])
                + "\n```\n"
            )

        # Deduplicação por title + file + line
        dupe_key = f"{finding['title']}|{finding['file_path']}|{finding['line']}"
        if dupe_key in dupes:
            dupes[dupe_key]["nb_occurrences"] += 1
        else:
            dupes[dupe_key] = finding

    return list(dupes.values())


# ---------------------------------------------------------------------------
# Parser de Dependências (campo "vulns")
# ---------------------------------------------------------------------------

def _parse_vulns(data: dict) -> list[dict]:
    """Processa a seção 'vulns' do JSON do Semgrep (modo Supply Chain / SCA).

    Args:
        data: Dicionário com o JSON completo do Semgrep.

    Returns:
        Lista de dicionários de achados (sem duplicatas por title+file+line).
    """
    dupes: dict[str, dict] = {}

    for item in data.get("vulns", []):
        advisory = item.get("advisory", {})
        dep_location = item.get("dependencyFileLocation", {})

        try:
            severity = _convert_severity(advisory.get("severity", "INFO"))
        except ValueError:
            severity = "Low"

        finding: dict[str, Any] = {
            "title": item.get("title"),
            "severity": severity,
            "description": advisory.get("description", ""),
            "file_path": dep_location.get("path"),
            "line": dep_location.get("startLine"),
            "vuln_id_from_tool": item.get("repositoryId"),
            "unique_id_from_tool": None,
            "cwe": None,
            "references": None,
            "mitigation": None,
            "static_finding": True,
            "dynamic_finding": False,
            "nb_occurrences": 1,
            "tool": "semgrep",
            "scan_type": "sca",
        }

        # CWE via advisory.references.cweIds
        cwe_ids = advisory.get("references", {}).get("cweIds")
        finding["cwe"] = _extract_cwe(cwe_ids)

        dupe_key = f"{finding['title']}|{finding['file_path']}|{finding['line']}"
        if dupe_key in dupes:
            dupes[dupe_key]["nb_occurrences"] += 1
        else:
            dupes[dupe_key] = finding

    return list(dupes.values())


# ---------------------------------------------------------------------------
# Ponto de entrada público (assíncrono)
# ---------------------------------------------------------------------------

async def parse_semgrep(raw_json: str | bytes | dict) -> list[dict]:
    """Parseia o output JSON bruto do Semgrep e retorna achados normalizados.

    Suporta dois modos:
    - **SAST**: JSON com campo ``"results"`` (regras de análise estática).
    - **SCA**: JSON com campo ``"vulns"`` (análise de dependências).

    Args:
        raw_json: JSON bruto do Semgrep. Pode ser:
            - ``str``: string JSON.
            - ``bytes``: bytes JSON.
            - ``dict``: dicionário já desserializado.

    Returns:
        Lista de dicionários, cada um representando um achado com os campos:

        .. code-block:: python

            {
                "title":               str,   # check_id ou título da vuln
                "severity":            str,   # Critical | High | Medium | Low
                "description":         str,   # Markdown com mensagem e snippet
                "file_path":           str,   # Caminho do arquivo afetado
                "line":                int,   # Linha do achado
                "vuln_id_from_tool":   str,   # check_id original
                "unique_id_from_tool": str,   # fingerprint (se disponível)
                "cwe":                 int,   # Número do CWE (se disponível)
                "references":          str,   # URLs de referência
                "mitigation":          str,   # Fix sugerido
                "static_finding":      bool,  # Sempre True
                "dynamic_finding":     bool,  # Sempre False
                "nb_occurrences":      int,   # Contagem de ocorrências
                "tool":                str,   # "semgrep"
                "scan_type":           str,   # "sast" ou "sca"
            }

    Raises:
        ValueError: Se o JSON for inválido ou o formato não for reconhecido.

    Example:
        >>> import asyncio, json
        >>> with open("semgrep-output.json") as f:
        ...     findings = asyncio.run(parse_semgrep(f.read()))
        >>> print(len(findings))
    """
    # Desserialização
    if isinstance(raw_json, dict):
        data = raw_json
    elif isinstance(raw_json, bytes):
        data = json.loads(raw_json.decode("utf-8"))
    else:
        data = json.loads(raw_json)

    findings: list[dict] = []

    if "results" in data:
        findings.extend(_parse_results(data))
    elif "vulns" in data:
        findings.extend(_parse_vulns(data))
    else:
        logger.warning(
            "Semgrep JSON não contém 'results' nem 'vulns'. "
            "Retornando lista vazia."
        )

    logger.info("Semgrep: %d achados encontrados.", len(findings))
    return findings
