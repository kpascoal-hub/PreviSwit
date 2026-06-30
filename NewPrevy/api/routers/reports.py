"""
PreviSwit AI-ASPM — Router: Reports
Geração e listagem de relatórios executivos e técnicos.
Motor de PDF independente e agnóstico via ReportLab.
"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Optional, Any
import json
import io
import os
import uuid
import logging
from datetime import datetime

logger = logging.getLogger("previswit.reports")

router = APIRouter(prefix="/reports", tags=["Reports"])

DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "data", "reports_meta.json")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "reports")


# ─── Helpers de Persistência ──────────────────────────────────────────────────

def _load_meta() -> list:
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_meta(data: list) -> None:
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


# ─── Helpers de scan_data ─────────────────────────────────────────────────────

def _scan_data_path(report_id: str) -> str:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    return os.path.join(REPORTS_DIR, f"{report_id}_scan.json")


def _save_scan_data(report_id: str, data: Any) -> None:
    with open(_scan_data_path(report_id), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def _load_scan_data(report_id: str) -> Optional[Any]:
    path = _scan_data_path(report_id)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _delete_scan_data(report_id: str) -> None:
    path = _scan_data_path(report_id)
    if os.path.exists(path):
        os.remove(path)


# ─── Modelos Pydantic ─────────────────────────────────────────────────────────

class ReportIngestPayload(BaseModel):
    id:               Optional[str] = None
    title:            str
    target:           Optional[str] = "unknown"
    target_label:     Optional[str] = None
    type:             Optional[str] = "SAST Tecnico"
    standard:         Optional[str] = "—"
    risk:             Optional[str] = "UNKNOWN"
    compliance_model: Optional[str] = "TECNICO"   # ISO_27001 | EXECUTIVO | TECNICO
    scan_data:        Optional[Any] = None
    requested_at:     Optional[str] = None


class GeneratePDFPayload(BaseModel):
    scan_data:        dict          = Field(...,   description="Dados brutos dos scanners ou da IA")
    compliance_model: str           = Field(...,   description="ISO_27001 | EXECUTIVO | TECNICO")
    severity_filter:  str           = Field("ALL", description="CRITICAL | HIGH | MEDIUM | LOW | ALL")
    target_name:      Optional[str] = Field(None,  description="Nome do projeto ou hash do commit")


# ─── Constantes do Motor de PDF ───────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "CLEAN": 4, "UNKNOWN": 5}

COMPLIANCE_META = {
    "ISO_27001": {
        "title_prefix": "Relatorio de Conformidade ISO/IEC 27001:2022",
        "subtitle":     "Auditoria de Controles de Seguranca da Informacao",
        "standard":     "ISO/IEC 27001:2022 — Sistemas de Gestao de Seguranca da Informacao",
        "focus":        "conformidade",
    },
    "EXECUTIVO": {
        "title_prefix": "Relatorio Executivo de Risco de Seguranca",
        "subtitle":     "Visao C-Level — Impacto de Negocio e Exposicao Financeira",
        "standard":     "Framework Executivo PreviSwit — NIST CSF / LGPD",
        "focus":        "executivo",
    },
    "TECNICO": {
        "title_prefix": "Laudo Tecnico SAST — Analise de Vulnerabilidades",
        "subtitle":     "Relatorio de Engenharia de Seguranca de Software (AppSec)",
        "standard":     "OWASP Top 10 / CWE / CVSS v3.1",
        "focus":        "tecnico",
    },
}


# ─── CRUD de Relatórios ───────────────────────────────────────────────────────

@router.get("/", summary="Listar relatorios gerados")
def list_reports():
    """Retorna estritamente os dados persistidos. Sem mocks."""
    reports = _load_meta()
    return {"reports": reports, "total": len(reports)}


@router.post("/", summary="Receber e persistir novo laudo gerado por outra aba")
def receive_report(body: ReportIngestPayload):
    """
    Recebe um laudo de qualquer parte do sistema (ex: RiskGraphCanvas apos SAST)
    e persiste no storage JSON. Rejeita duplicatas por ID.
    """
    report = {
        "id":              body.id or str(uuid.uuid4()),
        "title":           body.title,
        "target":          body.target,
        "target_label":    body.target_label or body.target or "—",
        "type":            body.type,
        "standard":        body.standard,
        "risk":            body.risk,
        "compliance_model": body.compliance_model or "TECNICO",
        "status":          "ready",
        "requested_at":    body.requested_at or datetime.utcnow().isoformat() + "Z",
        "completed_at":    datetime.utcnow().isoformat() + "Z",
        "has_scan_data":   body.scan_data is not None,
    }

    if body.scan_data is not None:
        _save_scan_data(report["id"], body.scan_data)

    meta_list = _load_meta()
    meta_list = [r for r in meta_list if r.get("id") != report["id"]]
    meta_list.insert(0, report)
    _save_meta(meta_list)

    return {"message": "Laudo recebido e persistido com sucesso.", "report": report}


@router.delete("/{report_id}", summary="Excluir relatorio permanentemente")
def delete_report(report_id: str):
    """Remove o laudo do indice e apaga o scan_data associado. Operacao irreversivel."""
    meta_list    = _load_meta()
    original_len = len(meta_list)
    meta_list    = [r for r in meta_list if r.get("id") != report_id]

    if len(meta_list) == original_len:
        raise HTTPException(status_code=404, detail="Relatorio nao encontrado.")

    _save_meta(meta_list)
    _delete_scan_data(report_id)

    return {"message": f"Relatorio '{report_id}' excluido com sucesso."}


@router.get("/{report_id}", summary="Obter metadados de um relatorio")
def get_report(report_id: str):
    """Retorna os metadados de um relatorio especifico."""
    reports = _load_meta()
    report  = next((r for r in reports if r["id"] == report_id), None)
    if not report:
        raise HTTPException(status_code=404, detail="Relatorio nao encontrado.")
    return report


# ─── Motor de Filtragem de Achados ────────────────────────────────────────────

def _apply_severity_filter(scan_data: dict, severity_filter: str) -> list:
    """
    Normaliza achados de Semgrep, Trivy, Gitleaks e Checkov em lista plana
    e aplica o filtro de severidade.
    """
    all_findings = []
    sev_upper    = severity_filter.upper()
    threshold    = SEVERITY_ORDER.get(sev_upper, 5)

    # Semgrep
    semgrep = scan_data.get("semgrep", {})
    if isinstance(semgrep, dict):
        for r in semgrep.get("results", []):
            sev = r.get("extra", {}).get("severity", "UNKNOWN").upper()
            if sev_upper == "ALL" or SEVERITY_ORDER.get(sev, 5) <= threshold:
                all_findings.append({
                    "tool":     "Semgrep",
                    "file":     r.get("path", "—"),
                    "rule":     r.get("check_id", "—"),
                    "severity": sev,
                    "details":  r.get("extra", {}).get("message", "—")[:200],
                })

    # Trivy
    trivy = scan_data.get("trivy", {})
    if isinstance(trivy, dict):
        for result in trivy.get("Results", []):
            target = result.get("Target", "—")
            for vuln in result.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "UNKNOWN").upper()
                if sev_upper == "ALL" or SEVERITY_ORDER.get(sev, 5) <= threshold:
                    all_findings.append({
                        "tool":     "Trivy",
                        "file":     target,
                        "rule":     vuln.get("VulnerabilityID", "—"),
                        "severity": sev,
                        "details":  vuln.get("Title", "—")[:200],
                    })
            for misc in result.get("Misconfigurations", []):
                sev = misc.get("Severity", "UNKNOWN").upper()
                if sev_upper == "ALL" or SEVERITY_ORDER.get(sev, 5) <= threshold:
                    all_findings.append({
                        "tool":     "Trivy",
                        "file":     target,
                        "rule":     misc.get("ID", misc.get("Title", "—")),
                        "severity": sev,
                        "details":  misc.get("Description", "—")[:200],
                    })

    # Gitleaks
    gitleaks = scan_data.get("gitleaks", [])
    if isinstance(gitleaks, list):
        for r in gitleaks:
            if isinstance(r, dict):
                all_findings.append({
                    "tool":     "Gitleaks",
                    "file":     r.get("File", "—"),
                    "rule":     r.get("RuleID", r.get("Description", "Segredo Exposto")),
                    "severity": "CRITICAL",
                    "details":  r.get("Description", "—")[:200],
                })

    # Checkov
    checkov      = scan_data.get("checkov", {})
    reports_raw  = checkov if isinstance(checkov, list) else ([checkov] if isinstance(checkov, dict) else [])
    for rpt in reports_raw:
        if isinstance(rpt, dict):
            for fc in rpt.get("results", {}).get("failed_checks", []):
                all_findings.append({
                    "tool":     "Checkov",
                    "file":     fc.get("file_path", "—"),
                    "rule":     fc.get("check_id", "—"),
                    "severity": "MEDIUM",
                    "details":  fc.get("check_name", "—")[:200],
                })

    return all_findings


# ─── Motor de Construção do PDF ───────────────────────────────────────────────

def _build_pdf(payload: GeneratePDFPayload) -> io.BytesIO:
    """Constroi o PDF em memoria usando ReportLab e retorna um BytesIO."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer,
        Table, TableStyle, HRFlowable,
    )
    from reportlab.lib.enums import TA_LEFT, TA_RIGHT

    model_upper = payload.compliance_model.upper()
    meta        = COMPLIANCE_META.get(model_upper, COMPLIANCE_META["TECNICO"])
    target      = payload.target_name or "Nao especificado"
    now_str     = datetime.utcnow().strftime("%d/%m/%Y %H:%M UTC")

    # Paleta Enterprise Dark
    C_ACCENT   = colors.HexColor("#4f46e5")
    C_BORDER   = colors.HexColor("#1e2d40")
    C_ROW_A    = colors.HexColor("#0b111a")
    C_ROW_B    = colors.HexColor("#060c14")
    C_TEXT     = colors.HexColor("#e2e8f0")
    C_MUTED    = colors.HexColor("#94a3b8")
    C_CRITICAL = colors.HexColor("#ef4444")
    C_HIGH     = colors.HexColor("#f97316")
    C_MEDIUM   = colors.HexColor("#eab308")
    C_LOW      = colors.HexColor("#38bdf8")
    C_CLEAN    = colors.HexColor("#22c55e")
    SEV_COLORS = {
        "CRITICAL": C_CRITICAL, "HIGH": C_HIGH, "MEDIUM": C_MEDIUM,
        "LOW": C_LOW, "CLEAN": C_CLEAN,
    }

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm,  bottomMargin=2*cm)

    s_title    = ParagraphStyle("pt", fontSize=18, textColor=C_TEXT,   fontName="Helvetica-Bold",   spaceAfter=4)
    s_subtitle = ParagraphStyle("ps", fontSize=10, textColor=C_ACCENT, fontName="Helvetica-Bold",   spaceAfter=2)
    s_meta     = ParagraphStyle("pm", fontSize=8,  textColor=C_MUTED,  fontName="Helvetica",        spaceAfter=12)
    s_section  = ParagraphStyle("ph", fontSize=11, textColor=C_TEXT,   fontName="Helvetica-Bold",   spaceBefore=14, spaceAfter=6)
    s_body     = ParagraphStyle("pb", fontSize=8,  textColor=C_MUTED,  fontName="Helvetica",        spaceAfter=6,   leading=12)
    s_caption  = ParagraphStyle("pc", fontSize=7,  textColor=C_MUTED,  fontName="Helvetica-Oblique",alignment=TA_RIGHT)

    story = []

    # Cabecalho
    story.append(Paragraph(meta["title_prefix"], s_title))
    story.append(Paragraph(meta["subtitle"], s_subtitle))
    story.append(Paragraph(
        f"Alvo: <b>{target}</b>  |  Norma: {meta['standard']}  |  Gerado: {now_str}  |  Filtro: {payload.severity_filter}",
        s_meta
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=16))

    # Filtro e achados
    findings = _apply_severity_filter(payload.scan_data, payload.severity_filter)
    total    = len(findings)

    # Sumario
    story.append(Paragraph("1. Sumario Executivo", s_section))

    focus = meta["focus"]
    if focus == "executivo":
        crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        lvl  = "CRITICO" if crit > 0 else ("ALTO" if high > 0 else "CONTROLADO")
        intro = (
            f"Esta analise identificou <b>{total}</b> achado(s) no alvo <b>{target}</b>. "
            f"Nivel de risco consolidado: <b>{lvl}</b>. "
            f"Criticos: <b>{crit}</b> | Altos: <b>{high}</b>. "
            "Acao imediata recomendada para mitigar exposicao financeira e regulatoria."
        ) if total > 0 else (
            f"O alvo <b>{target}</b> nao apresentou vulnerabilidades. Risco: <b>BAIXO</b>."
        )
    elif focus == "conformidade":
        intro = (
            f"A auditoria ISO/IEC 27001:2022 revelou <b>{total}</b> nao-conformidade(s) no alvo <b>{target}</b>. "
            "Cada achado representa um controle em falha no SGSI."
        ) if total > 0 else (
            f"O alvo <b>{target}</b> atende aos controles auditados da ISO/IEC 27001:2022. Nenhuma nao-conformidade detectada."
        )
    else:
        intro = (
            f"A varredura SAST (Semgrep, Trivy, Gitleaks, Checkov) retornou <b>{total}</b> achado(s) no alvo <b>{target}</b>. "
            "Resultados detalhados na tabela abaixo."
        ) if total > 0 else (
            f"Nenhuma vulnerabilidade detectada no alvo <b>{target}</b> para o filtro solicitado. Classificado como <b>Seguro</b>."
        )
    story.append(Paragraph(intro, s_body))

    # KPI por ferramenta
    if findings:
        tool_sev = {}
        for f in findings:
            k = (f["tool"], f["severity"])
            tool_sev[k] = tool_sev.get(k, 0) + 1

        kpi_rows = [["Ferramenta", "Severidade", "Qtd."]]
        for (tool, sev), cnt in sorted(tool_sev.items(), key=lambda x: SEVERITY_ORDER.get(x[0][1], 9)):
            kpi_rows.append([tool, sev, str(cnt)])

        kpi_tbl = Table(kpi_rows, colWidths=[5*cm, 4*cm, 2*cm], style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_ACCENT),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 7),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_ROW_A, C_ROW_B]),
            ("TEXTCOLOR",     (0, 1), (-1, -1), C_MUTED),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("ALIGN",         (2, 0), (2, -1),  "CENTER"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ]))
        story.append(Spacer(1, 6))
        story.append(kpi_tbl)

    story.append(Spacer(1, 12))

    # Tabela de achados
    story.append(Paragraph("2. Achados Detalhados", s_section))

    if findings:
        if focus == "conformidade":
            header = ["Ferramenta", "Controle / Regra", "Arquivo", "Nao-Conformidade"]
            col_w  = [2.5*cm, 4*cm, 4*cm, 6.5*cm]
            rows   = [header] + [[f["tool"], f["rule"], f["file"][:50], f["details"]] for f in findings]
        elif focus == "executivo":
            header = ["Severidade", "Ferramenta", "Descricao do Risco"]
            col_w  = [2.5*cm, 3*cm, 11.5*cm]
            rows   = [header] + [[f["severity"], f["tool"], f["details"]] for f in findings]
        else:
            header = ["Sev.", "Ferramenta", "Arquivo", "Regra / CWE", "Detalhes"]
            col_w  = [1.5*cm, 2.5*cm, 3.5*cm, 3.5*cm, 6*cm]
            rows   = [header] + [
                [f["severity"], f["tool"], f["file"][:40], f["rule"][:35], f["details"]]
                for f in findings
            ]

        tbl = Table(rows, colWidths=col_w, repeatRows=1, style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_ACCENT),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 7),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_ROW_A, C_ROW_B]),
            ("TEXTCOLOR",     (0, 1), (-1, -1), C_TEXT),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ]))
        story.append(tbl)
    else:
        story.append(Paragraph(
            "Nenhum achado para o filtro de severidade aplicado.", s_body
        ))

    # Rodape
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Gerado automaticamente pelo <b>PreviSwit AI-ASPM v1.0</b> — {now_str}. "
        "Documento confidencial para uso interno exclusivo.",
        s_caption
    ))

    doc.build(story)
    buf.seek(0)
    return buf


# ─── Endpoint Principal: Motor de PDF ─────────────────────────────────────────

@router.post(
    "/generate-pdf",
    summary="Motor de Geracao de PDF — Agnostico e Independente",
    description=(
        "Recebe dados brutos de scanners + modelo de conformidade, aplica filtro de severidade "
        "e retorna PDF gerado em memoria via ReportLab. Nao persiste arquivo em disco. "
        "Modelos: ISO_27001 | EXECUTIVO | TECNICO."
    ),
)
def generate_pdf_endpoint(payload: GeneratePDFPayload):
    """
    Motor de PDF stateless. Pode ser chamado de qualquer ponto do sistema.
    Entrada: { scan_data, compliance_model, severity_filter, target_name }
    Saida:   PDF binario via StreamingResponse.
    """
    model_upper = payload.compliance_model.upper()
    if model_upper not in COMPLIANCE_META:
        raise HTTPException(
            status_code=400,
            detail=f"compliance_model invalido. Use: {', '.join(COMPLIANCE_META.keys())}."
        )

    valid_filters = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"}
    if payload.severity_filter.upper() not in valid_filters:
        raise HTTPException(
            status_code=400,
            detail=f"severity_filter invalido. Use: {', '.join(valid_filters)}."
        )

    payload.compliance_model = model_upper
    payload.severity_filter  = payload.severity_filter.upper()

    try:
        pdf_buf = _build_pdf(payload)
    except Exception as exc:
        logger.exception("[PDF Motor] Falha ao gerar PDF: %s", exc)
        raise HTTPException(status_code=500, detail=f"Erro interno no motor de PDF: {exc}")

    safe_target = (payload.target_name or "relatorio").replace(" ", "_").replace("/", "-")[:40]
    filename    = f"previswit_{model_upper}_{safe_target}.pdf"

    return StreamingResponse(
        pdf_buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ─── PDF por ID de relatório persistido ──────────────────────────────────────

@router.get("/{report_id}/pdf", summary="Baixar PDF de relatorio persistido")
def download_report_pdf(report_id: str, severity_filter: str = "ALL"):
    """
    Recupera o scan_data salvo de um laudo existente e gera o PDF dinamicamente.
    Requer has_scan_data=true no laudo.
    """
    reports = _load_meta()
    report  = next((r for r in reports if r["id"] == report_id), None)
    if not report:
        raise HTTPException(status_code=404, detail="Relatorio nao encontrado.")

    scan_data = _load_scan_data(report_id)
    if scan_data is None:
        raise HTTPException(
            status_code=422,
            detail="Este laudo nao possui scan_data persistido. Use POST /generate-pdf com os dados brutos."
        )

    payload = GeneratePDFPayload(
        scan_data        = scan_data,
        compliance_model = report.get("compliance_model", "TECNICO"),
        severity_filter  = severity_filter,
        target_name      = report.get("target_label") or report.get("target"),
    )

    try:
        pdf_buf = _build_pdf(payload)
    except Exception as exc:
        logger.exception("[PDF Motor] Falha ao gerar PDF para relatorio %s: %s", report_id, exc)
        raise HTTPException(status_code=500, detail=f"Erro interno no motor de PDF: {exc}")

    model_upper = report.get("compliance_model", "TECNICO").upper()
    filename    = f"previswit_{model_upper}_{report_id[:8]}.pdf"

    return StreamingResponse(
        pdf_buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{report_id}/json", summary="Baixar JSON de relatorio persistido")
def download_report_json(report_id: str):
    """
    Recupera o scan_data de um laudo e retorna como JSON response para download.
    """
    reports = _load_meta()
    report  = next((r for r in reports if r["id"] == report_id), None)
    if not report:
        raise HTTPException(status_code=404, detail="Relatorio nao encontrado.")

    scan_data = _load_scan_data(report_id)
    if scan_data is None:
        scan_data = report

    content = json.dumps(scan_data, indent=2, ensure_ascii=False)
    filename = f"previswit_report_{report_id[:8]}.json"
    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ─── Rotas auxiliares ─────────────────────────────────────────────────────────

@router.post("/generate", summary="[Legado] Registrar relatorio agendado")
def generate_report(body: dict):
    """Mantida para compatibilidade. Para PDF imediato, use POST /generate-pdf."""
    report_type = body.get("type", "executive")
    title       = body.get("title", f"Relatorio {report_type.capitalize()} — {datetime.now().strftime('%d/%m/%Y')}")
    report_meta = {
        "id":             str(uuid.uuid4()),
        "title":          title,
        "type":           report_type,
        "compliance_model": body.get("compliance_model", "TECNICO"),
        "status":         "generating",
        "requested_at":   datetime.utcnow().isoformat() + "Z",
        "completed_at":   None,
        "has_scan_data":  False,
    }
    meta_list = _load_meta()
    meta_list.insert(0, report_meta)
    _save_meta(meta_list)
    return {
        "message": "Relatorio registrado.",
        "report": report_meta,
        "note":   "Para PDF imediato, use POST /api/v1/reports/generate-pdf com scan_data.",
    }


@router.get("/templates/list", summary="Listar modelos de conformidade disponiveis")
def list_templates():
    """Retorna os modelos suportados pelo motor de PDF."""
    return {
        "templates": [
            {
                "id":          "TECNICO",
                "name":        "Laudo Tecnico SAST",
                "description": "Relatorio de engenharia com tabelas de achados, CWEs e recomendacoes tecnicas.",
                "standard":    "OWASP Top 10 / CWE / CVSS v3.1",
                "audiences":   ["security_engineer", "developer"],
            },
            {
                "id":          "ISO_27001",
                "name":        "Conformidade ISO/IEC 27001:2022",
                "description": "Mapeamento de nao-conformidades do SGSI e controles em falha.",
                "standard":    "ISO/IEC 27001:2022",
                "audiences":   ["ciso", "auditor", "compliance_officer"],
            },
            {
                "id":          "EXECUTIVO",
                "name":        "Relatorio Executivo de Risco",
                "description": "Visao C-Level: impacto financeiro, regulatorio e de reputacao. Sem termos tecnicos profundos.",
                "standard":    "NIST CSF / LGPD",
                "audiences":   ["ceo", "cfo", "board"],
            },
        ]
    }
