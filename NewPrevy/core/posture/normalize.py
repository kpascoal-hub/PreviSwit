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
PreviSwit AI-ASPM — core.posture.normalize
===========================================
Canonicalização de findings e multiplicadores de risco.

PROBLEMA QUE ISSO RESOLVE
-------------------------
O `dedup_key` gravado por `sast.py` inclui o diretório temporário do scan:

    /tmp/previswit_sast__ssghxoa/Dockerfile      -> md5 A
    /tmp/previswit_bg_sast_839h0gj9/Dockerfile   -> md5 B

O mesmo check, no mesmo arquivo, do mesmo repositório, vira dois findings
distintos a cada rescan. Nos dados atuais isso infla 7 findings do Checkov
para 14 — e cada nova varredura infla mais.

Este módulo colapsa essas duplicatas EM TEMPO DE LEITURA. Nunca reescreve
`findings.json`: a página de Findings e a fila de triagem continuam vendo
os registros originais. As estatísticas de colapso são devolvidas para a
API expor o número, de modo que a contagem daqui nunca divirja em silêncio
da contagem de lá.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable

__all__ = [
    "normalize_path",
    "canonical_key",
    "canonicalize",
    "severity_of",
    "parse_dt",
    "age_days",
    "age_multiplier",
    "exploit_multiplier",
    "is_open",
]

# ── Caminhos ──────────────────────────────────────────────────────────────────

# Diretórios de scan efêmeros criados por sast.py / iac_runner.py.
# Cobre /tmp/previswit_sast__xxx, /tmp/previswit_bg_sast_xxx, C:\tmp\previswit_*
_TMP_SCAN_RE = re.compile(r"^(?:.*[/\\])?tmp[/\\]previswit[^/\\]*[/\\]", re.I)

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Status que NÃO contam como exposição ativa.
_CLOSED_STATUSES = frozenset({"closed", "false_positive", "resolved", "mitigated", "accepted"})


def normalize_path(p: str | None) -> str:
    """
    Remove o prefixo do diretório temporário de scan e normaliza separadores.

    >>> normalize_path("/tmp/previswit_sast__ssghxoa/Dockerfile")
    'Dockerfile'
    >>> normalize_path("/tmp/previswit_bg_sast_839h0gj9/.github/workflows/sast.yml")
    '.github/workflows/sast.yml'
    >>> normalize_path("requirements.txt")
    'requirements.txt'
    """
    return _TMP_SCAN_RE.sub("", (p or "")).replace("\\", "/").lstrip("/")


def severity_of(f: dict) -> str:
    """Severidade normalizada em UPPER. Desconhecida -> LOW (conservador: nunca zera risco)."""
    sev = str(f.get("severity") or "LOW").strip().upper()
    return sev if sev in _SEVERITIES else "LOW"


def is_open(f: dict) -> bool:
    """Um finding conta como exposição ativa?"""
    return str(f.get("status") or "open").strip().lower() not in _CLOSED_STATUSES


# ── Canonicalização ───────────────────────────────────────────────────────────

def canonical_key(f: dict) -> str:
    """
    Identidade estável de um finding, imune ao diretório temporário do scan.

    Componentes, em ordem de especificidade:
      tool     — quem achou
      ident    — cve_id > name > title (o identificador da regra/vulnerabilidade)
      package  — só o Trivy preenche; distingue a mesma CVE em pacotes diferentes
      path     — endpoint com o tmp/ removido
    """
    tool = str(f.get("tool") or "").strip().lower()
    ident = str(f.get("cve_id") or f.get("name") or f.get("title") or "").strip().upper()
    pkg = str(f.get("package") or "").strip().lower()
    path = normalize_path(f.get("endpoint"))
    return f"{tool}|{ident}|{pkg}|{path}"


def parse_dt(value: Any) -> datetime | None:
    """
    Converte um timestamp ISO em datetime tz-aware (UTC).

    Os dados têm as duas formas: `sast.py` grava com `+00:00`, `risk.py`
    grava naive via `utcnow()`. Naive é tratado como UTC.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value.strip():
        txt = value.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(txt)
        except ValueError:
            return None
    else:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def canonicalize(findings: Iterable[dict]) -> tuple[list[dict], dict]:
    """
    Colapsa duplicatas de scan e devolve `(unicos, stats)`.

    Na colisão mantém o registro de `created_at` MAIS ANTIGO. Idade é um input
    do risco (`age_multiplier`), então um rescan não pode zerar o relógio de um
    finding que está aberto há semanas.

    O registro sobrevivente ganha dois campos derivados (não persistidos):
        _canonical_key   — a chave usada no colapso
        _duplicate_count — quantos registros brutos mapearam nessa chave
    """
    best: dict[str, dict] = {}
    dup_count: dict[str, int] = {}
    raw_total = 0

    for f in findings:
        raw_total += 1
        key = canonical_key(f)
        dup_count[key] = dup_count.get(key, 0) + 1

        incumbent = best.get(key)
        if incumbent is None:
            best[key] = f
            continue

        # Mantém o mais antigo. Sem data -> perde para quem tem data.
        new_dt = parse_dt(f.get("created_at"))
        old_dt = parse_dt(incumbent.get("created_at"))
        if old_dt is None and new_dt is not None:
            best[key] = f
        elif new_dt is not None and old_dt is not None and new_dt < old_dt:
            best[key] = f

    unique: list[dict] = []
    for key, f in best.items():
        rec = dict(f)
        rec["_canonical_key"] = key
        rec["_duplicate_count"] = dup_count[key]
        unique.append(rec)

    stats = {
        "raw": raw_total,
        "canonical": len(unique),
        "collapsed": raw_total - len(unique),
    }
    return unique, stats


# ── Multiplicadores de risco ──────────────────────────────────────────────────

def age_days(f: dict, now: datetime | None = None) -> float:
    """Idade do finding em dias. Sem `created_at` -> 0.0 (não penaliza o desconhecido)."""
    created = parse_dt(f.get("created_at"))
    if created is None:
        return 0.0
    now = now or datetime.now(timezone.utc)
    return max(0.0, (now - created).total_seconds() / 86400.0)


def age_multiplier(f: dict, sla_days: dict[str, int], now: datetime | None = None) -> float:
    """
    1.0 -> 1.5 conforme o finding envelhece contra a SUA PRÓPRIA janela de SLA.

    Um CRITICAL aberto há 14 dias (SLA 7) está mais fora de política que um LOW
    aberto há 14 dias (SLA 180) — a normalização por SLA captura isso. Satura em
    +50% ao atingir 2x a janela: passado esse ponto o problema já é estrutural e
    continuar crescendo o multiplicador só distorce o ranking.
    """
    sla = sla_days.get(severity_of(f), 180) or 180
    return 1.0 + min(0.5, age_days(f, now) / (2.0 * sla))


def exploit_multiplier(f: dict, kev_ids: frozenset[str] | set[str] | None = None) -> float:
    """
    Peso de explorabilidade conhecida.

      1.30  CVE no CISA KEV (exploração comprovada em campo) ou segredo vazado
            (um segredo exposto não precisa de exploit: já é a credencial)
      1.15  existe `fixed_version` — o patch é público, logo a vulnerabilidade
            está descrita publicamente. Paridade de informação com o atacante.
      1.00  caso contrário
    """
    cve = str(f.get("cve_id") or "").strip().upper()
    if kev_ids and cve and cve in kev_ids:
        return 1.30

    tool = str(f.get("tool") or "").strip().lower()
    name = str(f.get("name") or "").strip().upper()
    if tool == "gitleaks" or name.startswith("CKV_SECRET_"):
        return 1.30

    if str(f.get("fixed_version") or "").strip():
        return 1.15

    return 1.00
