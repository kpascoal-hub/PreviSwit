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
PreviSwit — Router: Pentests Contínuos (Rotinas Agendadas)
===========================================================
Expõe as rotas REST para criar, listar, pausar e deletar rotinas de
Pentest Contínuo agendadas via APScheduler.

Endpoints:
  POST   /api/v1/schedules/         → Cria nova rotina
  GET    /api/v1/schedules/         → Lista rotinas ativas
  DELETE /api/v1/schedules/{id}     → Remove rotina
  PATCH  /api/v1/schedules/{id}/pause → Pausa/despausa rotina
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from api import scheduler as sched

router = APIRouter(prefix="/schedules", tags=["Pentests Contínuos (Scheduler)"])


class RoutineCreate(BaseModel):
    name:      Optional[str] = None
    target:    str
    pipeline:  str = "p1"       # p1 | p2 | p3
    mode:      str = "safe"     # safe | hot
    frequency: str = "daily"    # daily | weekly | monthly | custom
    cron_expr: Optional[str] = None  # só usado quando frequency='custom'


@router.post("/", status_code=201)
def create_routine(body: RoutineCreate):
    """Cria e agenda uma nova rotina de Pentest Contínuo."""
    if not body.target.strip():
        raise HTTPException(400, "Campo 'target' é obrigatório.")
    routine = sched.add_routine(
        name=body.name or body.target,
        target=body.target,
        pipeline=body.pipeline,
        mode=body.mode,
        frequency=body.frequency,
        cron_expr=body.cron_expr,
    )
    return {"status": "created", "routine": routine}


@router.get("/")
def list_routines():
    """Lista todas as rotinas agendadas (ativas e pausadas)."""
    return {"routines": sched.list_routines()}


@router.delete("/{routine_id}", status_code=200)
def delete_routine(routine_id: str):
    """Remove definitivamente uma rotina."""
    ok = sched.delete_routine(routine_id)
    if not ok:
        raise HTTPException(404, "Rotina não encontrada.")
    return {"status": "deleted", "id": routine_id}


@router.patch("/{routine_id}/pause", status_code=200)
def toggle_pause(routine_id: str):
    """Pausa ou despausa uma rotina (toggle)."""
    ok = sched.pause_routine(routine_id)
    if not ok:
        raise HTTPException(404, "Rotina não encontrada.")
    return {"status": "toggled", "id": routine_id}
