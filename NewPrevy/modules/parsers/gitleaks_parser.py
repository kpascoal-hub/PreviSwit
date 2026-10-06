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
PreviSwit ASPM - Gitleaks Parser
==================================
Lógica extraída e adaptada do DefectDojo (dojo/tools/gitleaks/parser.py).
Suporta dois formatos de output do Gitleaks:
  - Formato legado (campo "rule" no objeto)
  - Formato atual v8+ (campo "Description" no objeto)

Referência original: https://github.com/DefectDojo/django-DefectDojo

IMPORTANTE: Este módulo é 100% Python puro e assíncrono.
Não possui dependências de Django, banco de dados ou ORM.
"""

import hashlib
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# CWE-798: Use of Hard-coded Credentials
_CWE_HARDCODED_CREDENTIALS = 798

# Palavras-chave que elevam a severidade de High → Critical
_CRITICAL_KEYWORDS = ("Github", "AWS", "Heroku")


# ---------------------------------------------------------------------------
# Formato Legado (Gitleaks < v8) — campo "rule"
# ---------------------------------------------------------------------------

def _parse_legacy_issue(issue: dict) -> dict[str, Any] | None:
    """Parseia um achado no formato legado do Gitleaks (< v8).

    Identifica o formato pelo campo ``"rule"`` no objeto.

    Args:
        issue: Dicionário representando um resultado do Gitleaks.

    Returns:
        Dicionário normalizado do achado, ou None se inválido.
    """
    file_path = issue.get("file", "")
    reason = issue.get("rule", "")
    line = issue.get("lineNumber")

    title = f"Hard Coded {reason}"

    # Constrói descrição detalhada
    description = f"**Commit:** {issue.get('commitMessage', '').rstrip(chr(10))}\n"
    description += f"**Commit Hash:** {issue.get('commit', '')}\n"
    description += f"**Commit Date:** {issue.get('date', '')}\n"
    description += (
        f"**Autor:** {issue.get('author', '')} "
        f"<{issue.get('email', '')}>\n"
    )
    description += f"**Motivo:** {reason}\n"
    description += f"**Caminho:** {file_path}\n"

    if line is not None:
        description += f"**Linha:** {line}\n"

    if "operation" in issue:
        description += f"**Operação:** {issue['operation']}\n"

    leak_url = issue.get("leakURL")
    if leak_url:
        description += f"**Leak URL:** [{leak_url}]({leak_url})\n"

    # Ofensor redactado para não vazar segredos nos logs
    raw_line = issue.get("line", "")
    offender = issue.get("offender", "")
    redacted = raw_line.replace(offender, "REDACTED") if offender else raw_line
    description += f"\n**String Encontrada:**\n\n```\n{redacted}\n```"

    # Severidade: Critical para serviços de alto risco, High para demais
    severity = "Critical" if any(kw in reason for kw in _CRITICAL_KEYWORDS) else "High"

    tags = issue.get("tags", "")
    tag_list = [t.strip() for t in tags.split(",")] if tags else []

    finding: dict[str, Any] = {
        "title": title,
        "description": description,
        "severity": severity,
        "file_path": file_path,
        "line": line,
        "cwe": _CWE_HARDCODED_CREDENTIALS,
        "tags": tag_list,
        "static_finding": True,
        "dynamic_finding": False,
        "nb_occurrences": 1,
        "tool": "gitleaks",
        "format": "legacy",
    }

    # Chave de deduplicação baseada no ofensor + arquivo + linha
    dupe_key = hashlib.sha256(
        (offender + file_path + str(line)).encode("utf-8")
    ).hexdigest()

    return finding, dupe_key


# ---------------------------------------------------------------------------
# Formato Atual (Gitleaks v8+) — campo "Description"
# ---------------------------------------------------------------------------

def _parse_current_issue(issue: dict) -> tuple[dict[str, Any], str] | None:
    """Parseia um achado no formato atual do Gitleaks (v8+).

    Identifica o formato pelo campo ``"Description"`` no objeto.

    Args:
        issue: Dicionário representando um resultado do Gitleaks.

    Returns:
        Tupla (dicionário do achado, chave de deduplicação), ou None se inválido.
    """
    reason = issue.get("Description", "")
    line = issue.get("StartLine")
    line = int(line) if line else 0

    match = issue.get("Match", "")
    secret = issue.get("Secret", "")
    file_path = issue.get("File", "")
    commit = issue.get("Commit", "")
    date = issue.get("Date", "")
    message = issue.get("Message", "")
    tags = issue.get("Tags")
    rule_id = issue.get("RuleID", "")

    title = f"Hard coded {reason} found in {file_path}"

    # Constrói descrição (GDPR: autor e email omitidos intencionalmente)
    description_parts: list[str] = []

    if secret:
        description_parts.append(f"**Secret:** {secret}")
    if match:
        description_parts.append(f"**Match:** {match}")
    if message:
        if "\n" in message:
            escaped = message.replace("```", "\\`\\`\\`")
            description_parts.append(
                f"**Commit message:**\n```\n{escaped}\n```"
            )
        else:
            description_parts.append(f"**Commit message:** {message}")
    if commit:
        description_parts.append(f"**Commit hash:** {commit}")
    if date:
        description_parts.append(f"**Commit date:** {date}")
    if rule_id:
        description_parts.append(f"**Rule Id:** {rule_id}")

    description = "\n".join(description_parts)

    severity = "High"

    finding: dict[str, Any] = {
        "title": title,
        "description": description,
        "severity": severity,
        "file_path": file_path,
        "line": line,
        "cwe": _CWE_HARDCODED_CREDENTIALS,
        "tags": tags if isinstance(tags, list) else ([tags] if tags else []),
        "static_finding": True,
        "dynamic_finding": False,
        "nb_occurrences": 1,
        "tool": "gitleaks",
        "format": "current",
    }

    # Chave de deduplicação: title + secret + line
    dupe_key = hashlib.md5(
        (title + secret + str(line)).encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()

    return finding, dupe_key


# ---------------------------------------------------------------------------
# Ponto de entrada público (assíncrono)
# ---------------------------------------------------------------------------

async def parse_gitleaks(raw_json: str | bytes | dict | list) -> list[dict]:
    """Parseia o output JSON bruto do Gitleaks e retorna achados normalizados.

    Detecta automaticamente o formato do JSON:
    - **Legado** (Gitleaks < v8): objetos com campo ``"rule"``.
    - **Atual** (Gitleaks v8+): objetos com campo ``"Description"``.

    Args:
        raw_json: JSON bruto do Gitleaks. Pode ser:
            - ``str``: string JSON.
            - ``bytes``: bytes JSON.
            - ``dict`` / ``list``: já desserializado.

    Returns:
        Lista de dicionários, cada um representando um achado com os campos:

        .. code-block:: python

            {
                "title":           str,   # Descrição do segredo encontrado
                "description":     str,   # Markdown com detalhes do commit
                "severity":        str,   # Critical | High
                "file_path":       str,   # Arquivo onde o segredo foi encontrado
                "line":            int,   # Linha do achado
                "cwe":             int,   # Sempre 798 (Hard-coded Credentials)
                "tags":            list,  # Tags associadas à regra
                "static_finding":  bool,  # Sempre True
                "dynamic_finding": bool,  # Sempre False
                "nb_occurrences":  int,   # Contagem de ocorrências (para achados mesclados)
                "tool":            str,   # "gitleaks"
                "format":          str,   # "legacy" ou "current"
            }

    Raises:
        ValueError: Se o JSON for inválido ou o formato de cada item não for reconhecido.

    Example:
        >>> import asyncio, json
        >>> with open("gitleaks-report.json") as f:
        ...     findings = asyncio.run(parse_gitleaks(f.read()))
        >>> print(len(findings))
    """
    # Desserialização
    if isinstance(raw_json, (dict, list)):
        data = raw_json
    elif isinstance(raw_json, bytes):
        data = json.loads(raw_json.decode("utf-8"))
    else:
        data = json.loads(raw_json)

    # Gitleaks retorna null para scans sem achados
    if data is None:
        logger.info("Gitleaks: JSON nulo — sem achados.")
        return []

    # Normaliza para lista (caso venha um único objeto)
    issues = data if isinstance(data, list) else [data]

    dupes: dict[str, dict] = {}

    for issue in issues:
        if issue.get("rule"):
            # Formato legado
            result = _parse_legacy_issue(issue)
            if result:
                finding, dupe_key = result
                if dupe_key not in dupes:
                    dupes[dupe_key] = finding

        elif issue.get("Description"):
            # Formato atual v8+
            result = _parse_current_issue(issue)
            if result:
                finding, dupe_key = result
                if dupe_key in dupes:
                    # Mescla ocorrências duplicadas
                    existing = dupes[dupe_key]
                    existing["description"] += "\n\n---\n\n" + finding["description"]
                    existing["nb_occurrences"] += 1
                else:
                    dupes[dupe_key] = finding
        else:
            raise ValueError(
                f"Formato de item Gitleaks não reconhecido: "
                f"{list(issue.keys())}"
            )

    findings = list(dupes.values())
    logger.info("Gitleaks: %d achados encontrados.", len(findings))
    return findings
