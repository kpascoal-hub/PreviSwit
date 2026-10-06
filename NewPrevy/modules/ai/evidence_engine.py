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
Evidence Engine — coleta e estrutura evidências de cada finding para o relatório.
"""
from core.utils import safe_request


def collect(url: str, response=None) -> dict:
    """Coleta evidência técnica de uma URL."""
    if response is None:
        response = safe_request(url)

    if not response:
        return {"url": url, "status": None, "size": 0, "preview": ""}

    return {
        "url":     url,
        "status":  response.status_code,
        "size":    len(response.text),
        "server":  response.headers.get("Server",""),
        "powered": response.headers.get("X-Powered-By",""),
        "preview": response.text[:200].replace("\n"," "),
    }


def enrich_finding(finding: dict) -> dict:
    """Adiciona evidência ao finding se ainda não tiver."""
    if finding.get("evidence"):
        return finding
    url = finding.get("url","")
    if url:
        finding["evidence"] = collect(url)
    return finding
