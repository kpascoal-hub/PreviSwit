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
PreviSwit ASPM - Checkov Parser
=================================
Lógica extraída e adaptada do DefectDojo (dojo/tools/checkov/parser.py).
Suporta o formato JSON de saída do Checkov para análise de Infrastructure as Code (IaC).

O Checkov pode gerar:
  - Um único objeto JSON (1 check_type)
  - Um array de objetos JSON (múltiplos check_types, ex.: terraform + kubernetes)

Apenas os ``failed_checks`` são importados (checks aprovados são ignorados).

Referência original: https://github.com/DefectDojo/django-DefectDojo

IMPORTANTE: Este módulo é 100% Python puro e assíncrono.
Não possui dependências de Django, banco de dados ou ORM.
"""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mapeamento de severidade (formato Checkov → PreviSwit)
# ---------------------------------------------------------------------------

# O Checkov usa strings livres; capitalize() já trata a maioria dos casos.
# Este mapa serve para casos especiais conhecidos.
_SEVERITY_ALIASES: dict[str, str] = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Info",
    "NONE": "Info",
    "UNKNOWN": "Medium",
}


def _normalize_severity(raw: str | None) -> str:
    """Normaliza a severidade do Checkov para o padrão PreviSwit.

    Args:
        raw: String de severidade bruta do Checkov.

    Returns:
        String normalizada. Padrão é ``"Medium"`` se ausente ou desconhecida.
    """
    if not raw:
        return "Medium"
    normalized = _SEVERITY_ALIASES.get(raw.upper())
    return normalized if normalized else raw.capitalize()


# ---------------------------------------------------------------------------
# Parsing de um único item de failed_check
# ---------------------------------------------------------------------------

def _parse_failed_check(node: dict, check_type: str) -> dict[str, Any] | None:
    """Parseia um único ``failed_check`` do relatório Checkov.

    Args:
        node: Dicionário representando um failed_check do Checkov.
        check_type: Tipo de verificação (ex: "terraform", "kubernetes", "dockerfile").

    Returns:
        Dicionário normalizado do achado, ou None se o nó for inválido.
    """
    if not node:
        return None

    # Título: nome do check
    title = node.get("check_name", "check_name não encontrado")

    # Descrição: composição estruturada
    description = f"**Check Type:** {check_type}\n"

    check_id = node.get("check_id")
    if check_id:
        description += f"**Check ID:** {check_id}\n"

    check_name = node.get("check_name")
    if check_name:
        description += f"**Check Name:** {check_name}\n"

    extra_desc = node.get("description")
    if extra_desc:
        description += f"\n{extra_desc}\n"

    # Mitigação: benchmarks de conformidade (ex: CIS, PCI-DSS)
    mitigation = ""
    benchmarks = node.get("benchmarks")
    if benchmarks:
        bm_keys = list(benchmarks.keys())
        if bm_keys:
            mitigation += "\n**Benchmarks:**\n"
            for bm_name in bm_keys:
                bm_entries = benchmarks.get(bm_name)
                if bm_entries:
                    for entry in bm_entries:
                        entry_name = entry.get("name", "")
                        entry_desc = entry.get("description", "")
                        mitigation += f"- {bm_name} # {entry_name} : {entry_desc}\n"

    # Arquivo e linha
    file_path = node.get("file_path")
    source_line: int | None = None
    file_line_range = node.get("file_line_range")
    if file_line_range and isinstance(file_line_range, list) and len(file_line_range) > 0:
        source_line = file_line_range[0]

    # Recurso afetado (componente IaC: ex "aws_s3_bucket.my_bucket")
    resource = node.get("resource")

    # Severidade
    severity = _normalize_severity(node.get("severity"))

    # Referência/guideline
    references = node.get("guideline", "")

    return {
        "title": title,
        "description": description,
        "severity": severity,
        "mitigation": mitigation if mitigation else None,
        "file_path": file_path,
        "line": source_line,
        "component_name": resource,
        "references": references if references else None,
        "check_id": check_id,
        "check_type": check_type,
        "static_finding": True,
        "dynamic_finding": False,
        "tool": "checkov",
        "scan_type": "iac",
    }


# ---------------------------------------------------------------------------
# Parsing de uma árvore de resultados (um check_type)
# ---------------------------------------------------------------------------

def _parse_check_type_tree(tree: dict) -> list[dict]:
    """Processa todos os ``failed_checks`` de uma seção de check_type.

    Args:
        tree: Dicionário representando o JSON de um check_type do Checkov.

    Returns:
        Lista de dicionários de achados.
    """
    check_type = tree.get("check_type", "unknown")
    failed_checks = tree.get("results", {}).get("failed_checks", [])

    items: list[dict] = []
    for node in failed_checks:
        item = _parse_failed_check(node, check_type)
        if item:
            items.append(item)

    return items


# ---------------------------------------------------------------------------
# Ponto de entrada público (assíncrono)
# ---------------------------------------------------------------------------

async def parse_checkov(raw_json: str | bytes | dict | list) -> list[dict]:
    """Parseia o output JSON bruto do Checkov e retorna achados normalizados.

    O Checkov pode gerar um único objeto JSON (1 ``check_type``) ou um array
    de objetos (múltiplos ``check_types``). Esta função normaliza ambos os casos.

    Apenas os ``failed_checks`` são retornados. Checks aprovados (``passed_checks``)
    e com erros (``parsing_errors``) são ignorados.

    Args:
        raw_json: JSON bruto do Checkov. Pode ser:
            - ``str``: string JSON.
            - ``bytes``: bytes JSON.
            - ``dict``: dicionário de um único check_type.
            - ``list``: lista de dicionários de múltiplos check_types.

    Returns:
        Lista de dicionários, cada um representando um achado com os campos:

        .. code-block:: python

            {
                "title":          str,        # Nome do check falho
                "description":    str,        # Markdown com check_type, ID e nome
                "severity":       str,        # Critical | High | Medium | Low | Info
                "mitigation":     str | None, # Benchmarks de conformidade
                "file_path":      str,        # Caminho do arquivo IaC afetado
                "line":           int | None, # Primeira linha do range afetado
                "component_name": str | None, # Recurso IaC (ex: "aws_s3_bucket.x")
                "references":     str | None, # Guideline/documentação
                "check_id":       str | None, # ID do check (ex: "CKV_AWS_18")
                "check_type":     str,        # Tipo: "terraform", "kubernetes", etc.
                "static_finding": bool,       # Sempre True
                "dynamic_finding":bool,       # Sempre False
                "tool":           str,        # "checkov"
                "scan_type":      str,        # "iac"
            }

    Raises:
        ValueError: Se o JSON for inválido.

    Example:
        >>> import asyncio
        >>> with open("checkov-results.json") as f:
        ...     findings = asyncio.run(parse_checkov(f.read()))
        >>> print(len(findings))
    """
    # Desserialização
    if isinstance(raw_json, (dict, list)):
        data = raw_json
    elif isinstance(raw_json, bytes):
        raw_str = raw_json.decode("utf-8")
        data = json.loads(raw_str)
    elif isinstance(raw_json, str):
        data = json.loads(raw_json)
    else:
        raise ValueError(
            f"Tipo de entrada inválido para parse_checkov: {type(raw_json)}"
        )

    # Normaliza para lista (1 ou N check_types)
    if isinstance(data, dict):
        trees = [data]
    elif isinstance(data, list):
        trees = data
    else:
        raise ValueError("Formato JSON do Checkov não reconhecido.")

    findings: list[dict] = []
    for tree in trees:
        check_type = tree.get("check_type", "unknown")
        items = _parse_check_type_tree(tree)
        findings.extend(items)
        logger.debug(
            "Checkov [%s]: %d failed_checks processados.", check_type, len(items)
        )

    logger.info("Checkov: %d achados encontrados no total.", len(findings))
    return findings
