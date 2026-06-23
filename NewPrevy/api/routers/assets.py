"""
PreviSwit AI-ASPM — Router: Assets & Products
Gestão de inventário de ativos digitais por categoria:
  REPOSITORY  → Repositórios (GitHub/GitLab)
  CLOUD       → Recursos Cloud (AWS/Azure/GCP)
  CONTAINER   → Imagens Docker / Kubernetes
  VM          → Máquinas Virtuais / Instâncias
  DOMAIN      → Domínios, APIs e Endpoints expostos
"""
from fastapi import APIRouter, HTTPException, Query, status
from typing import List, Optional
import json
import os
import uuid
from datetime import datetime

router = APIRouter(prefix="/assets", tags=["Assets & Products"])

DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "data", "assets.json")

# ── Tipos de ativo válidos ────────────────────────────────────────────────────
VALID_TYPES = {"REPOSITORY", "CLOUD", "CONTAINER", "VM", "DOMAIN"}

# ── Metadados por categoria (usados em /summary e /category) ─────────────────
CATEGORY_META = {
    "REPOSITORY": {
        "label":    "Repositórios",
        "hint":     "GitHub · GitLab · Bitbucket",
        "icon":     "git-branch",
        "color":    "purple",
        "extra_fields": ["provider", "repo_url", "default_branch", "visibility", "language"],
    },
    "CLOUD": {
        "label":    "Cloud",
        "hint":     "AWS · Azure · GCP",
        "icon":     "cloud",
        "color":    "sky",
        "extra_fields": ["provider", "region", "account_id", "service_type", "arn"],
    },
    "CONTAINER": {
        "label":    "Contêineres",
        "hint":     "Imagens Docker · Kubernetes",
        "icon":     "box",
        "color":    "cyan",
        "extra_fields": ["image_name", "registry", "tag", "digest", "base_os"],
    },
    "VM": {
        "label":    "Máquinas Virtuais",
        "hint":     "VMs · Instâncias · Bare Metal",
        "icon":     "monitor",
        "color":    "amber",
        "extra_fields": ["host", "ip_address", "os", "provider", "instance_type"],
    },
    "DOMAIN": {
        "label":    "Domínios & APIs",
        "hint":     "Endpoints expostos · APIs públicas",
        "icon":     "globe",
        "color":    "emerald",
        "extra_fields": ["host", "url", "protocol", "port", "api_type"],
    },
}


# ── I/O helpers ──────────────────────────────────────────────────────────────
def _load() -> List[dict]:
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        raw = f.read().strip()
        if not raw or raw == "null":
            return []
        return json.loads(raw)


def _save(data: List[dict]) -> None:
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def _build_asset(body: dict) -> dict:
    """Constrói um asset com todos os campos padrão + campos extras da categoria."""
    asset_type = body.get("asset_type", "").upper()
    meta        = CATEGORY_META.get(asset_type, {})
    extra_keys  = meta.get("extra_fields", [])

    asset = {
        "id":               str(uuid.uuid4()),
        "name":             body.get("name", "Unnamed Asset"),
        "description":      body.get("description", ""),
        "asset_type":       asset_type or None,
        "criticality":      body.get("criticality", "MEDIUM").upper(),
        "status":           body.get("status", "active"),
        "tags":             body.get("tags", []),
        "risk_score":       body.get("risk_score", 0),
        "findings_count":   body.get("findings_count", {"critical": 0, "high": 0, "medium": 0, "low": 0}),

        # Campos gerais opcionais
        "url":              body.get("url", ""),
        "host":             body.get("host", ""),
        "technology_stack": body.get("technology_stack", []),

        # Metadados de categoria
        "category_meta":    {k: body.get(k) for k in extra_keys if body.get(k) is not None},

        "created_at":       datetime.utcnow().isoformat(),
        "updated_at":       datetime.utcnow().isoformat(),
    }
    return asset


# ─────────────────────────────────────────────────────────────────────────────
#  ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/summary", summary="Resumo de ativos por categoria")
def get_assets_summary():
    """
    Retorna contadores agregados por categoria de ativo.
    Usado pelos cards da página 'Resumo de Ativos & Produtos'.

    Exemplo de resposta:
    ```json
    {
      "total": 12,
      "by_type": {
        "REPOSITORY": {"count": 4, "critical": 1, ...},
        "CLOUD":      {"count": 3, "critical": 0, ...},
        ...
      }
    }
    ```
    """
    assets = _load()
    by_type = {}

    for asset_type, meta in CATEGORY_META.items():
        subset = [a for a in assets if (a.get("asset_type") or "").upper() == asset_type]
        by_type[asset_type] = {
            "label":    meta["label"],
            "hint":     meta["hint"],
            "icon":     meta["icon"],
            "color":    meta["color"],
            "count":    len(subset),
            "critical": sum(1 for a in subset if a.get("criticality") == "CRITICAL"),
            "high":     sum(1 for a in subset if a.get("criticality") == "HIGH"),
            "medium":   sum(1 for a in subset if a.get("criticality") == "MEDIUM"),
            "low":      sum(1 for a in subset if a.get("criticality") == "LOW"),
        }

    return {
        "total":   len(assets),
        "critical": sum(1 for a in assets if a.get("criticality") == "CRITICAL"),
        "high":     sum(1 for a in assets if a.get("criticality") == "HIGH"),
        "by_type": by_type,
    }


@router.get("/", summary="Listar ativos com filtros")
def list_assets(
    asset_type: Optional[str] = Query(
        None,
        description="Filtrar por tipo: REPOSITORY | CLOUD | CONTAINER | VM | DOMAIN",
    ),
    criticality: Optional[str] = Query(
        None,
        description="Filtrar por criticidade: CRITICAL | HIGH | MEDIUM | LOW",
    ),
    status_filter: Optional[str] = Query(
        None, alias="status",
        description="Filtrar por status: active | inactive | archived",
    ),
    search: Optional[str] = Query(None, description="Busca por nome, host ou URL"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    """
    Retorna o inventário de ativos com filtros combinados.

    - **asset_type**: `REPOSITORY`, `CLOUD`, `CONTAINER`, `VM`, `DOMAIN`
    - **criticality**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
    - **status**: `active`, `inactive`, `archived`
    - **search**: busca parcial no nome, host ou URL
    """
    assets = _load()

    if asset_type:
        assets = [a for a in assets if (a.get("asset_type") or "").upper() == asset_type.upper()]
    if criticality:
        assets = [a for a in assets if (a.get("criticality") or "").upper() == criticality.upper()]
    if status_filter:
        assets = [a for a in assets if a.get("status") == status_filter]
    if search:
        q = search.lower()
        assets = [
            a for a in assets
            if q in (a.get("name") or "").lower()
            or q in (a.get("host") or "").lower()
            or q in (a.get("url") or "").lower()
        ]

    total  = len(assets)
    start  = (page - 1) * page_size
    paged  = assets[start: start + page_size]

    return {
        "assets":    paged,
        "total":     total,
        "page":      page,
        "page_size": page_size,
        "pages":     (total + page_size - 1) // page_size if total else 0,
    }


@router.post("/", status_code=status.HTTP_201_CREATED, summary="Criar novo ativo")
def create_asset(body: dict):
    """
    Registra um novo ativo na plataforma.

    **Campos comuns:**
    - `name` (str, obrigatório)
    - `asset_type` (str): `REPOSITORY` | `CLOUD` | `CONTAINER` | `VM` | `DOMAIN`
    - `criticality` (str): `CRITICAL` | `HIGH` | `MEDIUM` | `LOW`
    - `description`, `url`, `host`, `tags[]`, `technology_stack[]`

    **Campos extras por asset_type:**

    | Tipo        | Campos extras                                         |
    |-------------|-------------------------------------------------------|
    | REPOSITORY  | provider, repo_url, default_branch, visibility, language |
    | CLOUD       | provider, region, account_id, service_type, arn       |
    | CONTAINER   | image_name, registry, tag, digest, base_os            |
    | VM          | host, ip_address, os, provider, instance_type         |
    | DOMAIN      | host, url, protocol, port, api_type                   |
    """
    asset_type = (body.get("asset_type") or "").upper()
    if asset_type and asset_type not in VALID_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"asset_type inválido '{asset_type}'. Use: {sorted(VALID_TYPES)}",
        )

    assets = _load()
    asset  = _build_asset(body)
    assets.append(asset)
    _save(assets)
    return asset


# ── Endpoints por categoria ───────────────────────────────────────────────────

@router.get("/category/{asset_type}", summary="Listar ativos de uma categoria específica")
def list_assets_by_category(
    asset_type: str,
    criticality: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    """
    Atalho para listar ativos de uma categoria específica.

    - `GET /assets/category/REPOSITORY` → repositórios
    - `GET /assets/category/CLOUD`      → cloud
    - `GET /assets/category/CONTAINER`  → contêineres
    - `GET /assets/category/VM`         → máquinas virtuais
    - `GET /assets/category/DOMAIN`     → domínios & APIs

    Aceita filtros adicionais de `criticality` e `search`.
    """
    normalized = asset_type.upper()
    if normalized not in VALID_TYPES:
        raise HTTPException(
            status_code=404,
            detail=f"Categoria '{asset_type}' inválida. Use: {sorted(VALID_TYPES)}",
        )

    meta   = CATEGORY_META[normalized]
    assets = _load()
    subset = [a for a in assets if (a.get("asset_type") or "").upper() == normalized]

    if criticality:
        subset = [a for a in subset if (a.get("criticality") or "").upper() == criticality.upper()]
    if search:
        q = search.lower()
        subset = [
            a for a in subset
            if q in (a.get("name") or "").lower()
            or q in (a.get("host") or "").lower()
            or q in (a.get("url") or "").lower()
        ]

    total = len(subset)
    start = (page - 1) * page_size
    paged = subset[start: start + page_size]

    return {
        "category":  normalized,
        "meta":      meta,
        "assets":    paged,
        "total":     total,
        "page":      page,
        "page_size": page_size,
        "pages":     (total + page_size - 1) // page_size if total else 0,
        "counts": {
            "total":    total,
            "critical": sum(1 for a in subset if a.get("criticality") == "CRITICAL"),
            "high":     sum(1 for a in subset if a.get("criticality") == "HIGH"),
            "medium":   sum(1 for a in subset if a.get("criticality") == "MEDIUM"),
            "low":      sum(1 for a in subset if a.get("criticality") == "LOW"),
        },
    }


# ── CRUD por ID ───────────────────────────────────────────────────────────────

@router.get("/{asset_id}", summary="Detalhe de um ativo")
def get_asset(asset_id: str):
    """Retorna os detalhes completos de um ativo, incluindo metadados de categoria."""
    assets = _load()
    asset  = next((a for a in assets if a["id"] == asset_id), None)
    if not asset:
        raise HTTPException(status_code=404, detail="Ativo não encontrado")
    return asset


@router.put("/{asset_id}", summary="Atualizar ativo")
def update_asset(asset_id: str, body: dict):
    """Atualiza campos de um ativo existente (merge parcial)."""
    assets = _load()
    for i, a in enumerate(assets):
        if a["id"] == asset_id:
            # Não permite trocar o id nem o created_at
            body.pop("id", None)
            body.pop("created_at", None)
            if "asset_type" in body:
                body["asset_type"] = body["asset_type"].upper()
            assets[i] = {**a, **body, "updated_at": datetime.utcnow().isoformat()}
            _save(assets)
            return assets[i]
    raise HTTPException(status_code=404, detail="Ativo não encontrado")


@router.delete("/{asset_id}", summary="Remover ativo")
def delete_asset(asset_id: str):
    """Remove um ativo do inventário permanentemente."""
    assets = _load()
    filtered = [a for a in assets if a["id"] != asset_id]
    if len(filtered) == len(assets):
        raise HTTPException(status_code=404, detail="Ativo não encontrado")
    _save(filtered)
    return {"message": "Ativo removido com sucesso", "id": asset_id}


@router.get("/{asset_id}/attack-surface", summary="Superfície de ataque do ativo")
def get_attack_surface(asset_id: str):
    """Retorna os endpoints mapeados e expostos para um ativo."""
    assets = _load()
    asset  = next((a for a in assets if a["id"] == asset_id), None)
    if not asset:
        raise HTTPException(status_code=404, detail="Ativo não encontrado")
    return {
        "asset_id":   asset_id,
        "asset_name": asset.get("name"),
        "asset_type": asset.get("asset_type"),
        "endpoints":  asset.get("endpoints", []),
        "open_ports": asset.get("open_ports", []),
        "subdomains": asset.get("subdomains", []),
    }
