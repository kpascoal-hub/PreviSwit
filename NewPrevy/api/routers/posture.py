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
PreviSwit AI-ASPM — Router: Posture, Compliance & Investment
=============================================================
O painel de Métricas de Risco inteiro, servido por API real.

Router único porque as seis features consomem a MESMA computação cara:
carregar findings -> canonicalizar -> classificar famílias -> calcular
exposição e dano por controle. Três routers separados importariam o mesmo
core de qualquer forma, com três lugares para divergir.

Toda a matemática vive em `core/posture/` (funções puras, sem FastAPI).
Este arquivo só faz HTTP, validação e montagem.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Any, Literal, Optional

from core.posture import feeds as feeds_mod
from core.posture.frameworks import compute_compliance
from core.posture.normalize import canonicalize, is_open
from core.posture.packages import build_packages
from core.posture.prompts import (
    SYSTEM_INSTRUCTION, build_grounding, build_prompt, deterministic_summary,
)
from core.posture.scoring import compute_posture
from core.posture.simulator import simulate as run_simulation
from core.posture.store import (
    ACTIONS_FILE, ANNOTATIONS_FILE, CONFIG_FILE, DEFAULT_CONFIG,
    load_config, load_json, new_id, now_iso, save_json,
)
from core.posture.taxonomy import FAMILY_LABELS, classify_all

router = APIRouter(prefix="/posture", tags=["Posture, Compliance & Investment"])

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")
FINDINGS_FILE = os.path.join(_DATA_DIR, "findings.json")
RISK_HISTORY_FILE = os.path.join(_DATA_DIR, "risk_history.json")
ENGAGEMENTS_FILE = os.path.join(_DATA_DIR, "engagements.json")


# ── Pipeline compartilhado ────────────────────────────────────────────────────

def _load_findings() -> list[dict]:
    data = load_json(FINDINGS_FILE, [])
    return data if isinstance(data, list) else []


def _tools_present(findings: list[dict], config: dict) -> list[str]:
    """
    Ferramentas cujo resultado podemos considerar como evidência.

    NÃO pode vir só dos findings: uma ferramenta que rodou e não achou nada
    pareceria ausente, e seus controles cairiam fora de escopo — a cobertura
    despencaria justamente quando a segurança melhora. Por isso a união com
    os engagements e com as ferramentas declaradas na configuração.
    """
    tools = {str(f.get("tool") or "").strip().lower() for f in findings if f.get("tool")}

    for e in load_json(ENGAGEMENTS_FILE, []) or []:
        for t in (e.get("scan_tools_used") or []):
            tools.add(str(t).strip().lower())

    for t in (config.get("declared_tools") or []):
        tools.add(str(t).strip().lower())

    tools.discard("")
    return sorted(tools)


def _active_acceptances(now: datetime) -> list[dict]:
    """Anotações do tipo risk_acceptance ainda não expiradas."""
    out = []
    for a in load_json(ANNOTATIONS_FILE, []) or []:
        if a.get("kind") != "risk_acceptance":
            continue
        exp = a.get("expires_at")
        if exp:
            try:
                if datetime.fromisoformat(str(exp).replace("Z", "+00:00")) < now:
                    continue
            except ValueError:
                pass
        out.append(a)
    return out


async def _pipeline(apply_acceptances: bool = False, asset_id: str | None = None) -> dict:
    """
    Carrega -> canonicaliza -> classifica. Ponto único de entrada de dados
    para todos os endpoints, garantindo números consistentes entre eles.
    """
    now = datetime.now(timezone.utc)
    config = load_config()
    raw = _load_findings()

    if asset_id:
        raw = [f for f in raw if f.get("asset_id") == asset_id]

    unique, dedup = canonicalize(raw)
    enriched, family_counts = classify_all(unique)

    exclusions: list[dict] = []
    if apply_acceptances:
        accepted = _active_acceptances(now)
        accepted_ids = {
            fid for a in accepted
            for fid in (a.get("finding_ids") or [])
        }
        accepted_scopes = {
            a.get("scope_ref") for a in accepted if a.get("scope") == "family"
        }
        kept = []
        for f in enriched:
            if f.get("id") in accepted_ids or f.get("_family") in accepted_scopes:
                exclusions.append({
                    "finding_id": f.get("id"), "title": f.get("title"),
                    "family": f.get("_family"), "reason": "risk_acceptance",
                })
            else:
                kept.append(f)
        enriched = kept

    kev_ids, kev_meta = await feeds_mod.get_kev_set()

    return {
        "now": now, "config": config, "findings": enriched,
        "dedup": dedup, "family_counts": family_counts,
        "tools": _tools_present(unique, config),
        "kev_ids": kev_ids, "kev_meta": kev_meta,
        "accepted_exclusions": exclusions,
        "half_point": float(config.get("risk_half_point_ceq") or 10.0),
    }


def _kev_matches(findings: list[dict], kev_ids) -> list[str]:
    if not kev_ids:
        return []
    return sorted({
        str(f.get("cve_id")).upper()
        for f in findings
        if is_open(f) and str(f.get("cve_id") or "").upper() in kev_ids
    })


# ── Snapshot ──────────────────────────────────────────────────────────────────

@router.get("/snapshot", summary="Postura de risco atual (chamada de page-load)")
async def get_snapshot(
    asset_id: Optional[str] = Query(None),
    apply_acceptances: bool = Query(False),
):
    ctx = await _pipeline(apply_acceptances, asset_id)
    snap = compute_posture(ctx["findings"], ctx["kev_ids"], ctx["now"], ctx["half_point"])

    # Tendência SÓ contra snapshots do mesmo engine.
    #
    # O histórico contém pontos gravados pela fórmula antiga (que saturava e
    # produzia 0/5/10/100). Comparar contra eles reportaria "piorou 58 pontos"
    # quando na verdade foi a MEDIÇÃO que mudou, não o risco. Isso seria uma
    # afirmação falsa numa tela executiva.
    history = load_json(RISK_HISTORY_FILE, []) or []
    comparable = [h for h in history if h.get("engine") == "posture_v2"]
    legacy_count = len(history) - len(comparable)

    trend, trend_delta, trend_basis = "stable", 0.0, "insufficient_history"
    if comparable:
        week_ago = (ctx["now"] - timedelta(days=7)).isoformat()
        older = [h for h in comparable if str(h.get("recorded_at", "")) < week_ago]
        if older:
            old = float(older[-1].get("score") or snap["risk_score"])
            trend_delta = round(snap["risk_score"] - old, 1)
            trend_basis = "comparable_snapshot"
            if trend_delta > 5:
                trend = "worsening"
            elif trend_delta < -5:
                trend = "improving"

    matches = _kev_matches(ctx["findings"], ctx["kev_ids"])

    return {
        **snap,
        "trend": trend,
        "trend_delta": trend_delta,
        "trend_basis": trend_basis,
        "history_legacy_points": legacy_count,
        "deduplication": ctx["dedup"],
        "family_counts": ctx["family_counts"],
        "family_labels": FAMILY_LABELS,
        "tools_present": ctx["tools"],
        "kev": {**ctx["kev_meta"], "matches": matches, "match_count": len(matches)},
        "accepted_exclusions": ctx["accepted_exclusions"],
        "acceptances_applied": apply_acceptances,
    }


@router.post("/snapshot/record", summary="Grava um snapshot no histórico (idempotente por dia)")
async def record_snapshot():
    """
    Escrita EXPLÍCITA de histórico.

    `GET /risk/score` fazia isso como efeito colateral, o que quebrava a
    idempotência do GET e encheu `risk_history.json` de ruído (16 amostras num
    dia, 40 em outro). Aqui é um POST, e faz upsert por dia.
    """
    ctx = await _pipeline()
    snap = compute_posture(ctx["findings"], ctx["kev_ids"], ctx["now"], ctx["half_point"])

    history = load_json(RISK_HISTORY_FILE, []) or []
    today = ctx["now"].date().isoformat()
    entry = {
        "score": snap["risk_score"],
        "score_base": snap["risk_score_base"],
        "level": snap["risk_level"],
        "open_findings": snap["open_findings"],
        "recorded_at": ctx["now"].isoformat(),
        # Carimbo do engine: pontos da fórmula antiga não são comparáveis com
        # estes e precisam ser identificáveis para não poluírem a tendência.
        "engine": "posture_v2",
    }

    replaced = False
    for i, h in enumerate(history):
        if str(h.get("recorded_at", ""))[:10] == today:
            history[i] = entry
            replaced = True
            break
    if not replaced:
        history.append(entry)

    save_json(RISK_HISTORY_FILE, history[-365:])
    return {"recorded": entry, "upserted": replaced, "total_snapshots": len(history)}


@router.get("/history", summary="Histórico do score, agregado por dia")
async def get_history(
    days: int = Query(30, ge=1, le=365),
    bucket: Literal["day", "raw"] = "day",
    include_legacy: bool = Query(False),
):
    """
    Série temporal do score.

    Por padrão devolve APENAS pontos do engine atual. Os snapshots gravados
    pela fórmula anterior mediam outra coisa (ela saturava em 100), e plotá-los
    na mesma linha sugeriria uma piora que nunca aconteceu. Use
    `include_legacy=true` para inspecioná-los, devidamente marcados.
    """
    history = load_json(RISK_HISTORY_FILE, []) or []
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = [h for h in history if str(h.get("recorded_at", "")) >= cutoff]

    legacy = [h for h in rows if h.get("engine") != "posture_v2"]
    if not include_legacy:
        rows = [h for h in rows if h.get("engine") == "posture_v2"]

    if bucket == "day":
        # Último valor de cada dia vence.
        by_day: dict[str, dict] = {}
        for h in rows:
            by_day[str(h.get("recorded_at", ""))[:10]] = h
        rows = [
            {
                **v, "date": k, "date_label": f"{k[8:10]}/{k[5:7]}",
                "is_legacy": v.get("engine") != "posture_v2",
            }
            for k, v in sorted(by_day.items())
        ]

    return {
        "history": rows,
        "total_snapshots": len(rows),
        "period_days": days,
        "bucket": bucket,
        "score_convention": "0 = melhor, 100 = pior",
        "legacy_points_excluded": 0 if include_legacy else len(legacy),
        "legacy_note": (
            f"{len(legacy)} snapshot(s) da fórmula anterior foram omitidos: mediam uma "
            f"escala diferente (saturava em 100) e não são comparáveis com os atuais."
        ) if legacy and not include_legacy else None,
    }


# ── Conformidade ──────────────────────────────────────────────────────────────

@router.get("/compliance", summary="Conformidade nos 7 frameworks com escopo honesto")
async def get_compliance(
    framework: Optional[str] = Query(None),
    asset_id: Optional[str] = Query(None),
    apply_acceptances: bool = Query(False),
):
    ctx = await _pipeline(apply_acceptances, asset_id)
    result = compute_compliance(ctx["findings"], ctx["tools"], ctx["kev_ids"], ctx["now"])

    if framework:
        fw = result["frameworks"].get(framework)
        if not fw:
            raise HTTPException(404, f"Framework '{framework}' não encontrado.")
        return {
            "framework": fw,
            "evidence": result["evidence"],
            "disclaimer": result["disclaimer"],
            "calculated_at": result["calculated_at"],
        }

    return {**result, "family_labels": FAMILY_LABELS, "deduplication": ctx["dedup"]}


# ── Pacotes e simulação ───────────────────────────────────────────────────────

@router.get("/packages", summary="Pacotes de remediação com custo estimado")
async def get_packages(asset_id: Optional[str] = Query(None)):
    ctx = await _pipeline(asset_id=asset_id)
    cfg = ctx["config"]
    pkgs = build_packages(
        ctx["findings"],
        float(cfg["labor_rate"]["hourly"]),
        float(cfg["fx"]["usd_brl"]),
        ctx["kev_ids"], ctx["now"],
    )
    return {
        "packages": pkgs, "total": len(pkgs),
        "total_cost": {
            "brl": round(sum(p["cost"]["brl"] for p in pkgs), 2),
            "usd": round(sum(p["cost"]["usd"] for p in pkgs), 2),
        },
        "total_hours": round(sum(p["hours"] for p in pkgs), 2),
        "labor_rate": cfg["labor_rate"], "fx": cfg["fx"],
    }


class SimulateRequest(BaseModel):
    budget: float = Field(..., gt=0, description="Orçamento disponível")
    currency: Literal["BRL", "USD"] = "BRL"
    asset_id: Optional[str] = None
    must_include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    apply_acceptances: bool = False


@router.post("/simulate", summary="Simulador de investimento em segurança")
async def post_simulate(body: SimulateRequest):
    """
    "Coloca R$ 20.000 — o que melhorar, o que exatamente, e por quê?"

    Seleção por knapsack 0/1 exato. Greedy erra de forma comprovável neste
    tipo de dado (gasta em itens pequenos e perde o item grande que domina),
    e a resposta traz `heuristic_baseline` demonstrando a diferença.
    """
    ctx = await _pipeline(body.apply_acceptances, body.asset_id)
    cfg = ctx["config"]
    rate = float(cfg["labor_rate"]["hourly"])
    fx = float(cfg["fx"]["usd_brl"])

    budget_brl = body.budget * fx if body.currency == "USD" else body.budget

    pkgs = build_packages(ctx["findings"], rate, fx, ctx["kev_ids"], ctx["now"])
    result = run_simulation(
        ctx["findings"], pkgs, budget_brl, body.currency, fx,
        bucket=float(cfg.get("bucket_size") or 50.0),
        must_include=body.must_include, exclude=body.exclude,
        kev_ids=ctx["kev_ids"], compliance_fn=compute_compliance,
        tools_present=ctx["tools"], now=ctx["now"], half_point=ctx["half_point"],
    )

    if result.get("error"):
        raise HTTPException(422, detail=result)

    return {
        **result,
        "labor_rate": cfg["labor_rate"],
        "deduplication": ctx["dedup"],
        "input_currency": body.currency,
    }


# ── Radar ─────────────────────────────────────────────────────────────────────

@router.get("/feeds", summary="Radar de ameaças — CISA, NVD e KEV")
async def get_feeds(limit: int = Query(20, ge=1, le=50), force: bool = Query(False)):
    """Nunca retorna 5xx por falha de rede: degrada com `degraded=true`."""
    try:
        data = await feeds_mod.fetch_all(force=force)
    except Exception as e:
        return {
            "items": [], "kev": None, "degraded": True,
            "errors": [f"{type(e).__name__}: {e}"],
            "cache": {"status": "error"},
        }

    items = sorted(
        (data.get("cisa") or []) + (data.get("nvd") or []),
        key=lambda x: str(x.get("published_at") or ""), reverse=True,
    )[:limit]

    ctx = await _pipeline()
    matches = _kev_matches(ctx["findings"], ctx["kev_ids"])
    kev = data.get("kev") or {}

    return {
        "items": items, "total": len(items),
        "kev": {
            "available": bool(kev.get("cve_ids")),
            "catalog_version": kev.get("catalog_version"),
            "date_released": kev.get("date_released"),
            "count": kev.get("count"),
            "recent": kev.get("recent", [])[:10],
            "your_matches": matches,
            "your_match_count": len(matches),
        },
        "cache": data.get("cache"), "degraded": data.get("degraded", False),
        "errors": data.get("errors", []),
    }


@router.get("/regulatory", summary="Timeline regulatória com relevância computada")
async def get_regulatory():
    ctx = await _pipeline()
    comp = compute_compliance(ctx["findings"], ctx["tools"], ctx["kev_ids"], ctx["now"])
    timeline = feeds_mod.regulatory_timeline(comp["family_damage"], ctx["now"])
    return {
        "timeline": timeline, "total": len(timeline),
        "applicable_count": sum(1 for t in timeline if t["applies_to_you"]),
        "note": (
            "Datas e links devem ser conferidos contra a fonte oficial. O campo "
            "`verified_at` indica quando cada entrada foi verificada pela última vez."
        ),
    }


# ── Anotações ─────────────────────────────────────────────────────────────────

class AnnotationCreate(BaseModel):
    title: str
    body: str = ""
    scope: Literal["global", "framework", "control", "family", "package", "finding"] = "global"
    scope_ref: Optional[str] = None
    kind: Literal["note", "risk_acceptance", "compensating_control", "evidence"] = "note"
    expires_at: Optional[str] = None
    finding_ids: list[str] = Field(default_factory=list)
    author: Optional[str] = None


class AnnotationPatch(BaseModel):
    title: Optional[str] = None
    body: Optional[str] = None
    kind: Optional[str] = None
    expires_at: Optional[str] = None
    scope_ref: Optional[str] = None
    finding_ids: Optional[list[str]] = None


@router.get("/annotations", summary="Listar anotações de risco")
def list_annotations(scope: Optional[str] = None, kind: Optional[str] = None):
    rows = load_json(ANNOTATIONS_FILE, []) or []
    if scope:
        rows = [r for r in rows if r.get("scope") == scope]
    if kind:
        rows = [r for r in rows if r.get("kind") == kind]
    now = datetime.now(timezone.utc)
    for r in rows:
        exp = r.get("expires_at")
        r["is_expired"] = False
        if exp:
            try:
                r["is_expired"] = datetime.fromisoformat(str(exp).replace("Z", "+00:00")) < now
            except ValueError:
                pass
    rows.sort(key=lambda r: str(r.get("created_at") or ""), reverse=True)
    return {"annotations": rows, "total": len(rows)}


@router.post("/annotations", status_code=201, summary="Criar anotação de risco")
async def create_annotation(body: AnnotationCreate):
    """
    A anotação embute `risk_snapshot`: a postura NO MOMENTO em que foi escrita.
    Um auditor precisa ver o contexto em que a decisão foi tomada, não o
    contexto de hoje. É o que ferramenta de GRC real faz.
    """
    ctx = await _pipeline()
    snap = compute_posture(ctx["findings"], ctx["kev_ids"], ctx["now"], ctx["half_point"])

    rec = {
        "id": new_id(),
        "scope": body.scope, "scope_ref": body.scope_ref, "kind": body.kind,
        "title": body.title, "body": body.body,
        "expires_at": body.expires_at,
        "finding_ids": body.finding_ids,
        "author": body.author,
        "created_at": now_iso(), "updated_at": now_iso(),
        "risk_snapshot": {
            "risk_score": snap["risk_score"], "risk_level": snap["risk_level"],
            "exposure_R": snap["exposure_R"], "open_findings": snap["open_findings"],
        },
    }
    rows = load_json(ANNOTATIONS_FILE, []) or []
    rows.append(rec)
    save_json(ANNOTATIONS_FILE, rows)
    return rec


@router.patch("/annotations/{annotation_id}", summary="Editar anotação")
def patch_annotation(annotation_id: str, body: AnnotationPatch):
    rows = load_json(ANNOTATIONS_FILE, []) or []
    for r in rows:
        if r.get("id") == annotation_id:
            for k, v in body.model_dump(exclude_unset=True).items():
                if v is not None:
                    r[k] = v
            r["updated_at"] = now_iso()
            save_json(ANNOTATIONS_FILE, rows)
            return r
    raise HTTPException(404, "Anotação não encontrada.")


@router.delete("/annotations/{annotation_id}", summary="Remover anotação")
def delete_annotation(annotation_id: str):
    rows = load_json(ANNOTATIONS_FILE, []) or []
    kept = [r for r in rows if r.get("id") != annotation_id]
    if len(kept) == len(rows):
        raise HTTPException(404, "Anotação não encontrada.")
    save_json(ANNOTATIONS_FILE, kept)
    return {"deleted": annotation_id}


# ── Plano de ação ─────────────────────────────────────────────────────────────

class ActionCreate(BaseModel):
    title: str
    description: str = ""
    source: Literal["manual", "simulator", "coverage_gap", "ai_insight"] = "manual"
    source_ref: Optional[str] = None
    package_id: Optional[str] = None
    finding_ids: list[str] = Field(default_factory=list)
    control_refs: list[str] = Field(default_factory=list)
    owner: Optional[str] = None
    due_date: Optional[str] = None
    estimated_hours: Optional[float] = None
    estimated_cost: Optional[dict] = None
    risk_points: Optional[float] = None


class ActionPatch(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[Literal["todo", "in_progress", "blocked", "done", "cancelled"]] = None
    owner: Optional[str] = None
    due_date: Optional[str] = None


def _derive_priority(finding_ids: list[str], findings: list[dict], kev_ids) -> str:
    """Prioridade é DERIVADA dos dados, não digitada pelo usuário."""
    idx = {str(f.get("id")): f for f in findings}
    mine = [idx[i] for i in map(str, finding_ids) if i in idx]
    if not mine:
        return "P3"
    if kev_ids and any(str(f.get("cve_id") or "").upper() in kev_ids for f in mine):
        return "P0"
    sevs = {str(f.get("severity") or "").upper() for f in mine}
    if "CRITICAL" in sevs:
        return "P1"
    if "HIGH" in sevs:
        return "P2"
    return "P3"


@router.get("/actions", summary="Listar itens do plano de ação")
async def list_actions(status: Optional[str] = None):
    """
    `is_overdue`, `findings_still_open` e `verification` são DERIVADOS na
    leitura contra o findings.json vivo — nunca gravados.

    Uma ação marcada `done` cujos findings continuam abertos volta como
    `verification: "unverified"`. É um loop de fechamento real: não dá para
    fingir progresso marcando caixinha.
    """
    ctx = await _pipeline()
    open_ids = {str(f.get("id")) for f in ctx["findings"] if is_open(f)}
    rows = load_json(ACTIONS_FILE, []) or []
    now = datetime.now(timezone.utc)

    out = []
    for r in rows:
        if status and r.get("status") != status:
            continue
        fids = [str(x) for x in (r.get("finding_ids") or [])]
        still_open = [i for i in fids if i in open_ids]

        overdue = False
        if r.get("due_date") and r.get("status") not in ("done", "cancelled"):
            try:
                overdue = datetime.fromisoformat(
                    str(r["due_date"]).replace("Z", "+00:00")
                ).replace(tzinfo=timezone.utc) < now
            except ValueError:
                pass

        if r.get("status") == "done":
            if not still_open:
                verification = "verified"
            elif len(still_open) < len(fids):
                verification = "partial"
            else:
                verification = "unverified"
        else:
            verification = "pending"

        out.append({
            **r,
            "priority": _derive_priority(fids, ctx["findings"], ctx["kev_ids"]),
            "findings_total": len(fids),
            "findings_still_open": len(still_open),
            "is_overdue": overdue,
            "verification": verification,
        })

    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    out.sort(key=lambda r: (order.get(r["priority"], 9), str(r.get("created_at") or "")))
    return {"actions": out, "total": len(out)}


@router.post("/actions", status_code=201, summary="Criar item do plano de ação")
def create_action(body: ActionCreate):
    rec = {
        "id": new_id(), **body.model_dump(),
        "status": "todo", "created_at": now_iso(), "updated_at": now_iso(),
        "completed_at": None,
    }
    rows = load_json(ACTIONS_FILE, []) or []
    rows.append(rec)
    save_json(ACTIONS_FILE, rows)
    return rec


@router.post("/actions/from-package/{package_id:path}", status_code=201,
             summary="Converter pacote de remediação em item de ação")
async def action_from_package(package_id: str):
    ctx = await _pipeline()
    cfg = ctx["config"]
    pkgs = build_packages(
        ctx["findings"], float(cfg["labor_rate"]["hourly"]),
        float(cfg["fx"]["usd_brl"]), ctx["kev_ids"], ctx["now"],
    )
    pkg = next((p for p in pkgs if p["id"] == package_id), None)
    if not pkg:
        raise HTTPException(404, f"Pacote '{package_id}' não encontrado.")

    comp = compute_compliance(ctx["findings"], ctx["tools"], ctx["kev_ids"], ctx["now"])
    refs = [
        f"{fw_key}:{c['id']}"
        for fw_key, fw in comp["frameworks"].items()
        for c in fw["controls"]
        if c["in_scope"] and pkg["family"] in c["families"]
    ]

    rec = {
        "id": new_id(),
        "title": pkg["title"],
        "description": " ".join(pkg["estimate"]["assumptions"]),
        "source": "simulator", "source_ref": package_id, "package_id": package_id,
        "finding_ids": pkg["finding_ids"], "control_refs": refs,
        "owner": None, "due_date": None,
        "estimated_hours": pkg["hours"], "estimated_cost": pkg["cost"],
        "risk_points": pkg["risk_points"],
        "status": "todo", "created_at": now_iso(), "updated_at": now_iso(),
        "completed_at": None,
    }
    rows = load_json(ACTIONS_FILE, []) or []
    rows.append(rec)
    save_json(ACTIONS_FILE, rows)
    return rec


@router.patch("/actions/{action_id}", summary="Atualizar item do plano de ação")
def patch_action(action_id: str, body: ActionPatch):
    rows = load_json(ACTIONS_FILE, []) or []
    for r in rows:
        if r.get("id") == action_id:
            data = body.model_dump(exclude_unset=True)
            for k, v in data.items():
                if v is not None:
                    r[k] = v
            if data.get("status") == "done" and not r.get("completed_at"):
                r["completed_at"] = now_iso()
            if data.get("status") and data["status"] != "done":
                r["completed_at"] = None
            r["updated_at"] = now_iso()
            save_json(ACTIONS_FILE, rows)
            return r
    raise HTTPException(404, "Item não encontrado.")


@router.delete("/actions/{action_id}", summary="Remover item do plano de ação")
def delete_action(action_id: str):
    rows = load_json(ACTIONS_FILE, []) or []
    kept = [r for r in rows if r.get("id") != action_id]
    if len(kept) == len(rows):
        raise HTTPException(404, "Item não encontrado.")
    save_json(ACTIONS_FILE, kept)
    return {"deleted": action_id}


# ── Configuração ──────────────────────────────────────────────────────────────

class ConfigPatch(BaseModel):
    labor_rate: Optional[dict] = None
    fx: Optional[dict] = None
    risk_half_point_ceq: Optional[float] = None
    bucket_size: Optional[float] = None
    declared_tools: Optional[list[str]] = None


@router.get("/config", summary="Configuração do painel de postura")
def get_config():
    return {"config": load_config(), "defaults": DEFAULT_CONFIG}


@router.patch("/config", summary="Atualizar configuração")
def patch_config(body: ConfigPatch):
    cfg = load_config()
    for k, v in body.model_dump(exclude_unset=True).items():
        if v is None:
            continue
        if isinstance(v, dict) and isinstance(cfg.get(k), dict):
            cfg[k].update(v)
        else:
            cfg[k] = v
    save_json(CONFIG_FILE, cfg)
    return {"config": cfg, "updated_at": now_iso()}


@router.post("/fx/refresh", summary="Atualizar cotação USD/BRL")
async def refresh_fx():
    """Falha de rede devolve 200 com o valor anterior e `degraded=true`."""
    cfg = load_config()
    try:
        import httpx
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.get("https://economia.awesomeapi.com.br/json/last/USD-BRL")
            r.raise_for_status()
            bid = float(r.json()["USDBRL"]["bid"])
        cfg["fx"] = {"usd_brl": round(bid, 4), "source": "awesomeapi", "updated_at": now_iso()}
        save_json(CONFIG_FILE, cfg)
        return {"fx": cfg["fx"], "degraded": False}
    except Exception as e:
        return {
            "fx": cfg["fx"], "degraded": True,
            "error": f"{type(e).__name__}: {e}",
            "note": "Mantida a cotação anterior.",
        }


@router.get("/exposure", summary="Exposição financeira estimada")
async def get_exposure():
    """
    A página antiga mostrava `CRITICAL * 50000` USD — número inventado.

    Aqui: sem os parâmetros do negócio, NÃO se devolve número nenhum. O que se
    devolve é o custo real de remediação (derivado do modelo de esforço) e o
    teto ESTATUTÁRIO da LGPD, que é fato legal citável, não estimativa.
    """
    ctx = await _pipeline()
    cfg = ctx["config"]
    pkgs = build_packages(
        ctx["findings"], float(cfg["labor_rate"]["hourly"]),
        float(cfg["fx"]["usd_brl"]), ctx["kev_ids"], ctx["now"],
    )
    total_brl = round(sum(p["cost"]["brl"] for p in pkgs), 2)

    return {
        "breach_exposure": {
            "available": False,
            "reason": "parameters_not_configured",
            "required_inputs": ["record_count", "cost_per_record", "breach_probability"],
            "note": (
                "Exposição a incidente exige parâmetros do negócio que a plataforma não "
                "tem como inferir. Sem eles, qualquer número seria inventado."
            ),
        },
        "remediation_cost": {
            "available": True,
            "brl": total_brl,
            "usd": round(total_brl / float(cfg["fx"]["usd_brl"]), 2),
            "hours": round(sum(p["hours"] for p in pkgs), 2),
            "packages": len(pkgs),
            "basis": "effort_hours_x_blended_rate",
        },
        "statutory_ceiling": {
            "framework": "LGPD",
            "reference": "Lei nº 13.709/2018, Art. 52, II",
            "description": "Multa de até 2% do faturamento no Brasil, limitada por infração.",
            "ceiling_brl": 50_000_000,
            "url": "https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm",
            "note": "Teto legal, não estimativa de exposição da organização.",
        },
    }


# ── IA aterrada ───────────────────────────────────────────────────────────────

class AiInsightRequest(BaseModel):
    focus: Literal["business", "technical", "board"] = "business"
    budget: Optional[float] = None
    currency: Literal["BRL", "USD"] = "BRL"


@router.post("/ai-insight", summary="Análise por IA, aterrada nos dados computados")
async def post_ai_insight(
    body: AiInsightRequest,
    x_gemini_key: str = Header(default=None, alias="X-Gemini-Key"),
):
    """
    Todo número entregue ao modelo vem da computação do servidor, e o bloco
    exato volta como `grounding` para a UI exibir ao lado da prosa.

    Sem chave ou com o Gemini fora, devolve 200 com `deterministic_summary`
    — os mesmos dados, renderizados por template. O painel nunca fica vazio
    e nunca fabrica.
    """
    ctx = await _pipeline()
    cfg = ctx["config"]
    fx = float(cfg["fx"]["usd_brl"])

    snap = compute_posture(ctx["findings"], ctx["kev_ids"], ctx["now"], ctx["half_point"])
    comp = compute_compliance(ctx["findings"], ctx["tools"], ctx["kev_ids"], ctx["now"])
    pkgs = build_packages(ctx["findings"], float(cfg["labor_rate"]["hourly"]), fx,
                          ctx["kev_ids"], ctx["now"])

    sim = None
    if body.budget and body.budget > 0:
        budget_brl = body.budget * fx if body.currency == "USD" else body.budget
        sim = run_simulation(
            ctx["findings"], pkgs, budget_brl, body.currency, fx,
            bucket=float(cfg.get("bucket_size") or 50.0),
            kev_ids=ctx["kev_ids"], compliance_fn=compute_compliance,
            tools_present=ctx["tools"], now=ctx["now"], half_point=ctx["half_point"],
        )

    grounding = build_grounding(
        snap, comp, pkgs, sim, _kev_matches(ctx["findings"], ctx["kev_ids"])
    )

    if not x_gemini_key:
        return {
            "response": None, "source": "deterministic_fallback",
            "unavailable_reason": "Header 'X-Gemini-Key' ausente. Configure a chave em Integrações.",
            "deterministic_summary": deterministic_summary(grounding),
            "grounding": grounding, "timestamp": now_iso(),
        }

    try:
        from core.ai_agents.repositorios_mapa_mental.agent import mapa_mental_agent
        text = await mapa_mental_agent.generate_insight(
            prompt=build_prompt(grounding, body.focus),
            api_key=x_gemini_key,
            system_instruction=SYSTEM_INSTRUCTION,
        )
        if text and text.strip().startswith("⚠️"):
            return {
                "response": None, "source": "deterministic_fallback",
                "unavailable_reason": text.strip(),
                "deterministic_summary": deterministic_summary(grounding),
                "grounding": grounding, "timestamp": now_iso(),
            }
        return {
            "response": text, "source": "gemini", "focus": body.focus,
            "grounding": grounding, "timestamp": now_iso(),
        }
    except Exception as e:
        return {
            "response": None, "source": "deterministic_fallback",
            "unavailable_reason": f"{type(e).__name__}: {e}",
            "deterministic_summary": deterministic_summary(grounding),
            "grounding": grounding, "timestamp": now_iso(),
        }
