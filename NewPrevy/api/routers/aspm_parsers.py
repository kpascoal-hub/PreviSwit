"""
PreviSwit AI-ASPM — Router: ASPM Parsers (SAST / Secrets / IaC)
================================================================
Endpoints para ingestão de resultados brutos de ferramentas ASPM.
Os parsers extraem os achados e os normalizam automaticamente,
persistindo-os em findings.json seguindo o mesmo contrato do
router /findings existente.

Ferramentas suportadas:
  - Semgrep  → SAST (Static Application Security Testing)
  - Gitleaks → Secrets Detection
  - Checkov  → IaC (Infrastructure as Code) Security

Endpoints:
  POST /api/v1/integrations/parsers/semgrep    — ingestão Semgrep
  POST /api/v1/integrations/parsers/gitleaks   — ingestão Gitleaks
  POST /api/v1/integrations/parsers/checkov    — ingestão Checkov
  GET  /api/v1/integrations/parsers/           — listar capacidades
"""

import json
import os
import uuid
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status, UploadFile, File
from fastapi.responses import JSONResponse

# ─── Parsers ASPM ────────────────────────────────────────────────────────────
from modules.parsers.semgrep_parser  import parse_semgrep
from modules.parsers.gitleaks_parser import parse_gitleaks
from modules.parsers.checkov_parser  import parse_checkov

logger = logging.getLogger("aspm_parsers")

router = APIRouter(prefix="/integrations/parsers", tags=["ASPM Parsers (SAST/Secrets/IaC)"])

# ─── Persistência (mesmo arquivo que o router /findings usa) ──────────────────
_FINDINGS_FILE = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "findings.json"
)

# ─── Mapa de severidade: normaliza para o padrão interno UPPER ───────────────
_SEV_NORMALIZE = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
}


# ─── Helpers de I/O ──────────────────────────────────────────────────────────

def _load_findings() -> list[dict]:
    """Carrega findings.json, retornando lista vazia se não existir."""
    if not os.path.exists(_FINDINGS_FILE):
        return []
    with open(_FINDINGS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_findings(data: list[dict]) -> None:
    """Persiste a lista de findings em findings.json."""
    os.makedirs(os.path.dirname(_FINDINGS_FILE), exist_ok=True)
    with open(_FINDINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


# ─── Conversão Parser → Finding ──────────────────────────────────────────────

def _parser_finding_to_db(
    parsed: dict,
    *,
    engagement_id: Optional[str],
    asset_id: Optional[str],
    tool: str,
) -> dict:
    """Converte um achado normalizado pelo parser para o schema de findings.json.

    Mantém o mesmo contrato do ``POST /api/v1/findings`` para garantir
    compatibilidade total com o router de findings existente.

    Args:
        parsed:        Dicionário retornado pelo parser.
        engagement_id: UUID do engajamento (opcional).
        asset_id:      UUID do asset (opcional).
        tool:          Nome da ferramenta (semgrep | gitleaks | checkov).

    Returns:
        Dicionário pronto para ser persistido em findings.json.
    """
    # Normaliza severidade para UPPER (padrão interno)
    raw_sev = str(parsed.get("severity", "medium")).lower()
    severity = _SEV_NORMALIZE.get(raw_sev, "MEDIUM")

    # Constrói título seguro
    title = parsed.get("title") or f"[{tool.upper()}] Achado sem título"

    # Monta tags a partir do parser + metadata do scan
    tags = list(parsed.get("tags") or [])
    scan_type = parsed.get("scan_type")
    if scan_type and scan_type not in tags:
        tags.append(scan_type)
    if tool not in tags:
        tags.append(tool)

    # Campo "url" derivado do file_path para manter compatibilidade com findings.py
    file_path = parsed.get("file_path")

    # Metadados extras agrupados em raw_output para preservar contexto completo
    raw_output = {
        "file_path":           file_path,
        "line":                parsed.get("line"),
        "cwe":                 parsed.get("cwe"),
        "vuln_id_from_tool":   parsed.get("vuln_id_from_tool"),
        "unique_id_from_tool": parsed.get("unique_id_from_tool"),
        "check_id":            parsed.get("check_id"),
        "check_type":          parsed.get("check_type"),
        "component_name":      parsed.get("component_name"),
        "mitigation":          parsed.get("mitigation"),
        "references":          parsed.get("references"),
        "static_finding":      parsed.get("static_finding", True),
        "dynamic_finding":     parsed.get("dynamic_finding", False),
        "nb_occurrences":      parsed.get("nb_occurrences", 1),
        "format":              parsed.get("format"),
        "scan_type":           scan_type,
    }

    return {
        "id":                    str(uuid.uuid4()),
        "title":                 title,
        "description":           parsed.get("description", ""),
        "severity":              severity,
        "status":                "open",
        "asset_id":              asset_id,
        "engagement_id":         engagement_id,
        "cve_id":                None,
        "cvss_score":            None,
        "url":                   file_path,
        "endpoint":              file_path,
        "tool":                  tool,
        "raw_output":            raw_output,
        "ai_remediation":        None,
        "is_duplicate":          False,
        "duplicate_of":          None,
        "false_positive":        False,
        "false_positive_reason": None,
        "tags":                  tags,
        "created_at":            datetime.utcnow().isoformat(),
        "updated_at":            datetime.utcnow().isoformat(),
    }


def _dedup_key(finding: dict) -> str:
    """Gera chave de deduplicação baseada em title + file_path + tool.

    Achados idênticos vindos do mesmo arquivo pela mesma ferramenta
    não são persistidos duas vezes.
    """
    raw = finding.get("raw_output", {})
    return "|".join([
        finding.get("tool", ""),
        str(finding.get("title", "")),
        str(raw.get("file_path") or ""),
        str(raw.get("line") or ""),
    ])


async def _ingest(
    raw_json: str | bytes | dict | list,
    parser_fn,
    tool: str,
    engagement_id: Optional[str],
    asset_id: Optional[str],
) -> dict:
    """Core de ingestão: chama o parser, deduplicada e persiste.

    Args:
        raw_json:      JSON bruto da ferramenta.
        parser_fn:     Função async do parser correspondente.
        tool:          Identificador da ferramenta.
        engagement_id: UUID do engajamento opcional.
        asset_id:      UUID do asset opcional.

    Returns:
        Dicionário com métricas da operação de ingestão.
    """
    # ── 1. Parseia ────────────────────────────────────────────────────────
    try:
        parsed_findings = await parser_fn(raw_json)
    except (ValueError, json.JSONDecodeError) as exc:
        logger.warning("[%s] Erro ao parsear JSON: %s", tool, exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"JSON inválido ou formato não suportado: {exc}",
        ) from exc
    except Exception as exc:
        logger.exception("[%s] Erro inesperado no parser", tool)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro interno no parser {tool}: {exc}",
        ) from exc

    # ── 2. Converte para schema findings ─────────────────────────────────
    converted = [
        _parser_finding_to_db(p, engagement_id=engagement_id, asset_id=asset_id, tool=tool)
        for p in parsed_findings
    ]

    # ── 3. Deduplicação contra findings existentes ────────────────────────
    existing = _load_findings()
    existing_keys = {_dedup_key(f) for f in existing}

    new_findings = []
    duplicates_skipped = 0
    for finding in converted:
        key = _dedup_key(finding)
        if key in existing_keys:
            duplicates_skipped += 1
        else:
            new_findings.append(finding)
            existing_keys.add(key)

    # ── 4. Persiste novos achados ─────────────────────────────────────────
    if new_findings:
        _save_findings(existing + new_findings)

    # ── 5. Contadores por severidade ──────────────────────────────────────
    by_sev: dict[str, int] = {}
    for f in new_findings:
        sev = f.get("severity", "MEDIUM")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    logger.info(
        "[%s] Ingestão concluída: %d novos achados, %d duplicados ignorados.",
        tool, len(new_findings), duplicates_skipped,
    )

    return {
        "tool":                tool,
        "parsed_total":        len(parsed_findings),
        "imported":            len(new_findings),
        "duplicates_skipped":  duplicates_skipped,
        "by_severity":         by_sev,
        "engagement_id":       engagement_id,
        "asset_id":            asset_id,
        "findings":            new_findings,
        "ingested_at":         datetime.utcnow().isoformat(),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/",
    summary="Capacidades dos parsers ASPM",
    response_description="Lista de ferramentas ASPM suportadas e seus metadados.",
)
def list_parser_capabilities():
    """
    Retorna os parsers ASPM disponíveis na plataforma com metadados de cada um.

    Cada parser indica:
    - **tool**: Identificador da ferramenta.
    - **type**: Categoria (sast | secrets | iac).
    - **formats**: Formatos de input suportados.
    - **endpoint**: Rota de ingestão correspondente.
    """
    return {
        "parsers": [
            {
                "tool":        "semgrep",
                "name":        "Semgrep",
                "type":        "sast",
                "description": "Static Application Security Testing — análise de código-fonte com regras customizáveis.",
                "formats":     ["JSON (--json)", "Supply Chain (vulns)"],
                "endpoint":    "POST /api/v1/integrations/parsers/semgrep",
                "docs":        "https://semgrep.dev/docs/cli-reference/#semgrep-scan",
            },
            {
                "tool":        "gitleaks",
                "name":        "Gitleaks",
                "type":        "secrets",
                "description": "Detecção de segredos e credenciais expostos em repositórios Git.",
                "formats":     ["JSON legado (< v8)", "JSON atual (v8+)"],
                "endpoint":    "POST /api/v1/integrations/parsers/gitleaks",
                "docs":        "https://github.com/gitleaks/gitleaks#usage",
            },
            {
                "tool":        "checkov",
                "name":        "Checkov",
                "type":        "iac",
                "description": "Infrastructure as Code Security — analisa Terraform, Kubernetes, Dockerfile, etc.",
                "formats":     ["JSON single check_type", "JSON multi check_type (array)"],
                "endpoint":    "POST /api/v1/integrations/parsers/checkov",
                "docs":        "https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html",
            },
        ],
        "total": 3,
        "usage": {
            "via_upload":  "Envie o arquivo JSON como multipart/form-data no campo 'file'.",
            "via_body":    "Envie o JSON bruto no body da requisição (Content-Type: application/json).",
            "query_params": {
                "engagement_id": "UUID do engajamento (opcional) — vincula os achados a um scan.",
                "asset_id":      "UUID do asset (opcional) — vincula os achados a um ativo.",
            },
        },
    }


# ─── POST /semgrep ────────────────────────────────────────────────────────────

@router.post(
    "/semgrep",
    status_code=status.HTTP_201_CREATED,
    summary="Ingerir resultados do Semgrep",
    response_description="Achados importados e métricas de ingestão.",
)
async def ingest_semgrep(
    body: dict | list | None = None,
    file: Optional[UploadFile] = File(default=None, description="Arquivo JSON do Semgrep (--json output)"),
    engagement_id: Optional[str] = Query(None, description="UUID do engajamento"),
    asset_id:      Optional[str] = Query(None, description="UUID do asset"),
):
    """
    Ingere o JSON bruto gerado pelo **Semgrep** e persiste os achados normalizados.

    ### Modos de entrada
    - **Upload de arquivo** (`multipart/form-data`, campo `file`): ideal para CI/CD pipelines.
    - **Body JSON** (`application/json`): ideal para integrações programáticas.

    ### Formato suportado
    O parser detecta automaticamente entre:
    - **SAST** (`"results"`): saída de `semgrep --json`
    - **SCA** (`"vulns"`): saída de `semgrep ci --json` (Supply Chain)

    ### Campos extraídos
    `check_id` · `severity` · `message` · `file_path` · `line` · `CWE` · `fingerprint` · `fix`

    ### Exemplo CLI
    ```bash
    semgrep --json --config=auto src/ > semgrep-output.json
    curl -X POST http://localhost:8000/api/v1/integrations/parsers/semgrep \\
         -H 'Content-Type: application/json' \\
         -d @semgrep-output.json
    ```
    """
    if file is not None:
        content = await file.read()
        raw = content
    elif body is not None:
        raw = body
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Forneça o JSON via body (application/json) ou via upload de arquivo (multipart/form-data).",
        )

    return await _ingest(raw, parse_semgrep, "semgrep", engagement_id, asset_id)


# ─── POST /gitleaks ───────────────────────────────────────────────────────────

@router.post(
    "/gitleaks",
    status_code=status.HTTP_201_CREATED,
    summary="Ingerir resultados do Gitleaks",
    response_description="Achados importados e métricas de ingestão.",
)
async def ingest_gitleaks(
    body: dict | list | None = None,
    file: Optional[UploadFile] = File(default=None, description="Arquivo JSON do Gitleaks (--report-format json)"),
    engagement_id: Optional[str] = Query(None, description="UUID do engajamento"),
    asset_id:      Optional[str] = Query(None, description="UUID do asset"),
):
    """
    Ingere o JSON bruto gerado pelo **Gitleaks** e persiste os achados normalizados.

    ### Modos de entrada
    - **Upload de arquivo** (`multipart/form-data`, campo `file`)
    - **Body JSON** (`application/json`)

    ### Formato suportado
    O parser detecta automaticamente entre:
    - **Legado** (< v8): campo `"rule"` nos objetos
    - **Atual** (v8+): campo `"Description"` nos objetos

    > ⚠️ Segredos são **REDACTED** na descrição. Autor/email omitidos (GDPR).

    ### Campos extraídos
    `rule/Description` · `file_path` · `line` · `commit_hash` · `date` · `CWE-798`

    ### Exemplo CLI
    ```bash
    gitleaks detect --source . --report-format json --report-path gitleaks.json
    curl -X POST http://localhost:8000/api/v1/integrations/parsers/gitleaks \\
         -H 'Content-Type: application/json' \\
         -d @gitleaks.json
    ```
    """
    if file is not None:
        content = await file.read()
        raw = content
    elif body is not None:
        raw = body
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Forneça o JSON via body (application/json) ou via upload de arquivo (multipart/form-data).",
        )

    return await _ingest(raw, parse_gitleaks, "gitleaks", engagement_id, asset_id)


# ─── POST /checkov ────────────────────────────────────────────────────────────

@router.post(
    "/checkov",
    status_code=status.HTTP_201_CREATED,
    summary="Ingerir resultados do Checkov",
    response_description="Achados importados e métricas de ingestão.",
)
async def ingest_checkov(
    body: dict | list | None = None,
    file: Optional[UploadFile] = File(default=None, description="Arquivo JSON do Checkov (-o json)"),
    engagement_id: Optional[str] = Query(None, description="UUID do engajamento"),
    asset_id:      Optional[str] = Query(None, description="UUID do asset"),
):
    """
    Ingere o JSON bruto gerado pelo **Checkov** e persiste os achados normalizados.

    ### Modos de entrada
    - **Upload de arquivo** (`multipart/form-data`, campo `file`)
    - **Body JSON** (`application/json`)

    ### Formato suportado
    O parser detecta automaticamente entre:
    - **Single check_type**: objeto JSON único
    - **Multi check_type**: array de objetos JSON (ex: terraform + kubernetes)

    > ✅ Apenas `failed_checks` são importados. `passed_checks` são ignorados.

    ### Campos extraídos
    `check_id` · `check_name` · `check_type` · `file_path` · `line_range` · `resource` · `severity` · `benchmarks`

    ### Exemplo CLI
    ```bash
    checkov -d ./terraform -o json > checkov-results.json
    curl -X POST http://localhost:8000/api/v1/integrations/parsers/checkov \\
         -H 'Content-Type: application/json' \\
         -d @checkov-results.json
    ```
    """
    if file is not None:
        content = await file.read()
        raw = content
    elif body is not None:
        raw = body
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Forneça o JSON via body (application/json) ou via upload de arquivo (multipart/form-data).",
        )

    return await _ingest(raw, parse_checkov, "checkov", engagement_id, asset_id)
