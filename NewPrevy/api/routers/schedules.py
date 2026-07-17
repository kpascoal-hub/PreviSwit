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
