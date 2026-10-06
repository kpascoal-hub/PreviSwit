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
PreviSwit AI-ASPM — core.posture.store
=======================================
CRUD flat-JSON atômico para anotações, ações e configuração.

Segue o padrão de `api/routers/engagements.py`, com um endurecimento:
`_save` escreve num `.tmp` e faz `os.replace()`. Existem `.tmp` órfãos em
`data/` (findings.json.tmp, risk_history.json.tmp) — sinal de escrita
interrompida no passado. `os.replace()` é atômico no POSIX e no Windows.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "DATA_DIR", "ANNOTATIONS_FILE", "ACTIONS_FILE", "CONFIG_FILE", "FEED_CACHE_FILE",
    "load_json", "save_json", "now_iso", "new_id", "DEFAULT_CONFIG", "load_config",
]

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")

ANNOTATIONS_FILE = os.path.join(DATA_DIR, "posture_annotations.json")
ACTIONS_FILE = os.path.join(DATA_DIR, "posture_actions.json")
CONFIG_FILE = os.path.join(DATA_DIR, "posture_config.json")
FEED_CACHE_FILE = os.path.join(DATA_DIR, "posture_feed_cache.json")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return str(uuid.uuid4())


def load_json(path: str, default: Any) -> Any:
    """Lê JSON. Arquivo ausente ou corrompido devolve o default — nunca levanta."""
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return default


def save_json(path: str, data: Any) -> None:
    """Escrita atômica: grava no .tmp, fsync, depois os.replace()."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2, default=str)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


# ── Configuração ──────────────────────────────────────────────────────────────

DEFAULT_CONFIG: dict = {
    "labor_rate": {
        "currency": "BRL",
        "hourly": 180.0,
        "note": "Custo/hora blended de engenharia sênior, encargos incluídos.",
    },
    "fx": {
        "usd_brl": 5.45,
        "source": "manual",
        "updated_at": None,
    },
    "risk_half_point_ceq": 10.0,
    "bucket_size": 50.0,
    # Ferramentas que a organização declara operar, mesmo que tenham rodado
    # limpas. Sem isso, uma ferramenta sem findings pareceria ausente e seus
    # controles cairiam fora de escopo — a cobertura despencaria justamente
    # quando as coisas melhoram.
    "declared_tools": [],
}


def load_config() -> dict:
    """Config com defaults preenchidos para chaves ausentes."""
    stored = load_json(CONFIG_FILE, {})
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    for key, val in (stored or {}).items():
        if isinstance(val, dict) and isinstance(cfg.get(key), dict):
            cfg[key].update(val)
        else:
            cfg[key] = val
    return cfg
