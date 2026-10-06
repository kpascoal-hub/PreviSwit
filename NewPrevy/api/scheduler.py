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
PreviSwit — Scheduler de Pentests Contínuos
============================================
Motor de agendamento baseado no APScheduler (AsyncIOScheduler) que roda
dentro do loop assíncrono do FastAPI. Quando o gatilho Cron dispara,
despacha automaticamente { action: "START_SCAN", ... } para o WebSocket
do agente local, sem intervenção humana.

Uso:
    from api.scheduler import scheduler_state, add_routine, remove_routine

A instância do `manager` (ConnectionManager) é injetada em `init_scheduler()`.
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.cron import CronTrigger
    _APSCHEDULER_AVAILABLE = True
except ImportError:
    _APSCHEDULER_AVAILABLE = False

logger = logging.getLogger("previswit.scheduler")

# ── Frequência → expressão Cron ───────────────────────────────────────────────
FREQUENCY_TO_CRON: Dict[str, str] = {
    "daily":   "0 3 * * *",     # Diariamente às 03:00
    "weekly":  "0 3 * * 1",     # Semanalmente (segunda-feira às 03:00)
    "monthly": "0 3 1 * *",     # Mensalmente (dia 1 às 03:00)
}

# ── Estado global das rotinas (sobrevive ao ciclo de vida do FastAPI) ─────────
_routines: Dict[str, dict] = {}          # { routine_id: routine_dict }
_scheduler: Optional["AsyncIOScheduler"] = None
_manager = None                          # Injetado por init_scheduler()


def init_scheduler(manager_instance):
    """Inicializa o AsyncIOScheduler e injeta o ConnectionManager."""
    global _scheduler, _manager
    _manager = manager_instance

    if not _APSCHEDULER_AVAILABLE:
        logger.warning("APScheduler não instalado. Agendamentos não funcionarão. Instale com: pip install apscheduler")
        return

    _scheduler = AsyncIOScheduler(timezone="UTC")
    _scheduler.start()
    logger.info("✅ Scheduler de Pentests Contínuos iniciado.")


def _build_next_run(cron_expr: str) -> str:
    """Retorna a ISO string da próxima execução com base na expressão Cron."""
    if not _APSCHEDULER_AVAILABLE:
        return "—"
    try:
        trigger = CronTrigger.from_crontab(cron_expr, timezone="UTC")
        next_dt = trigger.get_next_fire_time(None, datetime.now(timezone.utc))
        return next_dt.isoformat() if next_dt else "—"
    except Exception:
        return "—"


def list_routines() -> List[dict]:
    """Retorna lista de rotinas agendadas (com next_run atualizado)."""
    result = []
    for r in _routines.values():
        updated = {**r}
        updated["next_run"] = _build_next_run(r["cron"])
        result.append(updated)
    return result


async def _fire_scan(routine_id: str):
    """Callback que o APScheduler executa na hora do Cron."""
    routine = _routines.get(routine_id)
    if not routine or routine.get("paused"):
        return

    if not _manager:
        logger.error("Scheduler: ConnectionManager não injetado.")
        return

    payload = {
        "action":   "START_SCAN",
        "target":   routine["target"],
        "pipeline": routine["pipeline"],
        "mode":     routine["mode"],
        "agent_id": "agent_01",
        "_source":  "scheduler",
        "_routine": routine_id,
    }

    agent_id = "agent_01"
    await _manager.send_to_agent(agent_id, payload)
    await _manager.send_to_dashboard({
        "action":  "LOG",
        "message": f"⏱️ [Scheduler] Rotina '{routine['name']}' disparada automaticamente → {routine['target']}",
    })

    # Atualiza o timestamp da última execução
    _routines[routine_id]["last_run"] = datetime.now(timezone.utc).isoformat()
    logger.info("Rotina '%s' disparada: target=%s", routine["name"], routine["target"])


def add_routine(
    name: str,
    target: str,
    pipeline: str,
    mode: str,
    frequency: str,
    cron_expr: Optional[str] = None,
) -> dict:
    """
    Cria e agenda uma nova rotina de Pentest Contínuo.

    Args:
        name:      Nome/rótulo da rotina.
        target:    URL ou repositório alvo.
        pipeline:  'p1' | 'p2' | 'p3'
        mode:      'safe' | 'hot'
        frequency: 'daily' | 'weekly' | 'monthly' | 'custom'
        cron_expr: Expressão Cron customizada (usada quando frequency='custom').

    Returns:
        Dicionário com os dados da rotina criada.
    """
    routine_id = str(uuid.uuid4())

    # Resolve a expressão Cron
    if frequency == "custom" and cron_expr:
        resolved_cron = cron_expr
    else:
        resolved_cron = FREQUENCY_TO_CRON.get(frequency, FREQUENCY_TO_CRON["daily"])

    routine = {
        "id":        routine_id,
        "name":      name or target,
        "target":    target,
        "pipeline":  pipeline,
        "mode":      mode,
        "frequency": frequency,
        "cron":      resolved_cron,
        "paused":    False,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_run":  None,
        "next_run":  _build_next_run(resolved_cron),
    }
    _routines[routine_id] = routine

    # Registra no APScheduler (se disponível)
    if _scheduler and _APSCHEDULER_AVAILABLE:
        try:
            trigger = CronTrigger.from_crontab(resolved_cron, timezone="UTC")
            _scheduler.add_job(
                _fire_scan,
                trigger=trigger,
                args=[routine_id],
                id=routine_id,
                replace_existing=True,
            )
            logger.info("Job agendado: %s | cron=%s", routine_id, resolved_cron)
        except Exception as e:
            logger.error("Erro ao agendar job %s: %s", routine_id, e)

    return routine


def pause_routine(routine_id: str) -> bool:
    """Pausa/despausa uma rotina. Retorna True se encontrou a rotina."""
    if routine_id not in _routines:
        return False
    _routines[routine_id]["paused"] = not _routines[routine_id]["paused"]
    if _scheduler and _APSCHEDULER_AVAILABLE:
        job = _scheduler.get_job(routine_id)
        if job:
            if _routines[routine_id]["paused"]:
                job.pause()
            else:
                job.resume()
    return True


def delete_routine(routine_id: str) -> bool:
    """Remove definitivamente uma rotina do scheduler e do estado."""
    if routine_id not in _routines:
        return False
    _routines.pop(routine_id)
    if _scheduler and _APSCHEDULER_AVAILABLE:
        try:
            _scheduler.remove_job(routine_id)
        except Exception:
            pass
    return True
