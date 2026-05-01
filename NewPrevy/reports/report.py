"""
Report Generator — PDF profissional + HTML Dashboard interativo.
Chamado ao final dos 3 pipelines com o full_results consolidado.
"""
import json, datetime, os
from config import Config

# ─── PDF ──────────────────────────────────────────────────────────────────────
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF

C_RED    = colors.HexColor("#e63946")
C_ORANGE = colors.HexColor("#f4a261")
C_YELLOW = colors.HexColor("#e9c46a")
C_GREEN  = colors.HexColor("#2a9d8f")
C_BLUE   = colors.HexColor("#457b9d")
C_DARK   = colors.HexColor("#1a1a2e")
C_GRAY   = colors.HexColor("#adb5bd")

SEV_COLORS = {"CRITICAL":C_RED,"HIGH":C_ORANGE,"MEDIUM":C_YELLOW,"LOW":C_GREEN,"INFO":C_BLUE}

CVSS_MAP  = {
    "SQLi Error-Based":9.8,"SQLi":9.8,"SQLi (HTTP 500)":7.5,
    "XSS Refletido":6.1,"XSS em Form":6.1,"XSS":6.1,
    "Possível SSRF":8.6,"SSRF":8.6,"Path Traversal":7.5,
    "Secret exposto":9.0,"CORS":6.5,"Open Redirect":6.1,
    "CRITICAL":9.0,"HIGH":7.5,"MEDIUM":5.0,"LOW":2.5,
}
IMPACT_MAP = {
    "sqli":      "Acesso completo ao banco. Possível escalada para RCE.",
    "xss":       "Roubo de sessão, defacement, phishing direcionado.",
    "ssrf":      "Acesso a serviços internos e metadata de cloud.",
    "secret":    "Comprometimento de APIs, infraestrutura e autenticação.",
    "traversal": "Leitura de arquivos arbitrários no servidor.",
    "cors":      "Leitura cross-origin de dados autenticados.",
    "redirect":  "Phishing e bypass de controles de acesso.",
    "default":   "Avaliar impacto conforme contexto da aplicação.",
}
REC_MAP = {
    "sqli":      "Usar prepared statements. Nunca concatenar inputs em queries.",
    "xss":       "Sanitizar outputs. Implementar CSP restritiva.",
    "ssrf":      "Whitelist de URLs permitidas. Bloquear ranges privados.",
    "secret":    "Remover do código. Usar variáveis de ambiente e secret managers.",
    "traversal": "Validar e sanitizar caminhos. Usar chroot/jail quando possível.",
    "cors":      "Restringir Access-Control-Allow-Origin a origens confiáveis.",
    "redirect":  "Validar destinos de redirecionamento contra whitelist.",
    "default":   "Revisar e corrigir conforme contexto.",
}

def _style(size=9, color=colors.black, bold=False, align=TA_CENTER, font=None):
    return ParagraphStyle("s", fontSize=size, textColor=color,
                          alignment=align, fontName=font or ("Helvetica-Bold" if bold else "Helvetica"))

def _badge(sev):
    c = {"CRITICAL":"#e63946","HIGH":"#f4a261","MEDIUM":"#e9c46a","LOW":"#2a9d8f","INFO":"#457b9d"}
    return f'<font color="{c.get(sev.upper(),"#999")}"><b>[{sev.upper()}]</b></font>'

def _score(report):
    s = 10.0
    for f in report.get("findings_prioritized",[]):
        s -= {"CRITICAL":2.5,"HIGH":1.5,"MEDIUM":0.7,"LOW":0.2}.get(f.get("severity","").upper(),0)
    if report.get("secrets"): s -= 2.0
    return round(max(s,0),1)

def _counts(report):
    c = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for f in report.get("findings_prioritized",[]):
        c[f.get("severity","INFO").upper()] = c.get(f.get("severity","INFO").upper(),0)+1
    for _ in report.get("secrets",[]): c["CRITICAL"]+=1
    return c

def _pie(counts):
    labels = [k for k,v in counts.items() if v>0]
    vals   = [counts[k] for k in labels]
    if not vals:
        d = Drawing(200,150)
        d.add(String(100,75,"Sem findings",textAnchor="middle",fontSize=10,fillColor=C_GRAY))
        return d
    d   = Drawing(220,160)
    pie = Pie()
    pie.x=10; pie.y=10; pie.width=140; pie.height=140
    pie.data=vals; pie.labels=[f"{l}({v})" for l,v in zip(labels,vals)]
    pie.sideLabels=True; pie.slices.strokeWidth=0.5
    for i,l in enumerate(labels):
        pie.slices[i].fillColor = SEV_COLORS.get(l,C_BLUE)
    d.add(pie)
    return d

def _scorebar(score):
    d = Drawing(400,40)
    fill = C_RED if score<4 else (C_ORANGE if score<7 else C_GREEN)
    d.add(Rect(0,10,360,20,fillColor=colors.HexColor("#dddddd"),strokeColor=None))
    if score>0: d.add(Rect(0,10,int(360*score/10),20,fillColor=fill,strokeColor=None))
    d.add(String(368,18,f"{score}/10",fontSize=11,fontName="Helvetica-Bold",fillColor=fill))
    return d

def _impact(f):
    text = (f.get("issue","") + f.get("type","")).lower()
    for k,v in IMPACT_MAP.items():
        if k in text: return v
    return IMPACT_MAP["default"]

def _rec(f):
    text = (f.get("issue","") + f.get("type","")).lower()
    for k,v in REC_MAP.items():
        if k in text: return v
    return REC_MAP["default"]

def generate_pdf(report, filename="report.pdf"):
    doc = SimpleDocTemplate(filename, pagesize=(21*cm,29.7*cm),
                            rightMargin=1.8*cm,leftMargin=1.8*cm,
                            topMargin=1.5*cm,bottomMargin=1.5*cm)
    now    = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    target = report.get("target","N/A")
    score  = _score(report)
    counts = _counts(report)
    total  = sum(counts.values())
    C = []

    # CAPA
    C.append(Spacer(1,1.2*cm))
    C.append(Paragraph("👁  PREVISWIT", _style(26,C_RED,True,TA_CENTER)))
    C.append(Paragraph("Relatório Técnico de Segurança — AI-Powered Pentest", _style(11,C_GRAY,align=TA_CENTER)))
    C.append(HRFlowable(width="100%",thickness=2,color=C_RED,spaceAfter=10))
    C.append(Paragraph(f"<b>Alvo:</b> {target}",_style(10)))
    C.append(Paragraph(f"<b>Data:</b> {now}",_style(10)))
    C.append(Paragraph(f"<b>Total de findings:</b> {total}",_style(10)))
    C.append(Spacer(1,.5*cm))
    C.append(Paragraph("Security Score",_style(13,C_RED,True)))
    C.append(renderPDF.GraphicsFlowable(_scorebar(score)))
    lbl = ("CRÍTICO — Ação imediata" if score<4 else
           "ATENÇÃO — Vulnerabilidades significativas" if score<7 else "BOM — Poucos problemas")
    C.append(Paragraph(lbl,_style(9,C_GRAY)))
    C.append(Spacer(1,.6*cm))

    # RESUMO
    C.append(Paragraph("Resumo Executivo",_style(14,C_RED,True)))
    rows = [["Severidade","Qtd","Prazo"]]
    for sev,prazo in [("CRITICAL","Imediato"),("HIGH","≤ 7 dias"),("MEDIUM","≤ 30 dias"),("LOW","Próx. ciclo")]:
        if counts[sev]>0:
            rows.append([Paragraph(_badge(sev),_style(9)),str(counts[sev]),prazo])
    if len(rows)>1:
        t=Table(rows,colWidths=[5*cm,3*cm,5*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),C_DARK),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),
            ("GRID",(0,0),(-1,-1),.5,C_GRAY),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f8f9fa")]),
        ]))
        C.append(t)
    C.append(Spacer(1,.5*cm))
    C.append(Paragraph("Distribuição por Severidade",_style(13,C_RED,True)))
    C.append(renderPDF.GraphicsFlowable(_pie(counts)))
    C.append(PageBreak())

    # AI INSIGHTS
    insights = report.get("ai_insights",[])
    if insights:
        C.append(Paragraph("🤖 Insights da IA",_style(14,C_RED,True)))
        for ins in insights:
            C.append(Paragraph(f"▸ {ins}",_style(9)))
        C.append(Spacer(1,.5*cm))

    # TOP ISSUES HISTÓRICOS
    top = report.get("ai_top_issues",[])
    if top:
        C.append(Paragraph("Issues mais recorrentes (memória histórica)",_style(12,C_RED,True)))
        rows=[["Issue","Ocorrências"]]
        for item in top[:8]:
            rows.append([item.get("issue",""),str(item.get("count",0))])
        t=Table(rows,colWidths=[11*cm,3*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),C_DARK),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),
            ("GRID",(0,0),(-1,-1),.5,C_GRAY),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f8f9fa")]),
        ]))
        C.append(t)
        C.append(Spacer(1,.5*cm))

    # FINDINGS CRÍTICOS DETALHADOS
    prioritized = report.get("findings_prioritized",[])
    crit_high   = [f for f in prioritized if f.get("severity","").upper() in ("CRITICAL","HIGH")]
    if crit_high:
        C.append(Paragraph("🔴 Vulnerabilidades Críticas e Altas",_style(14,C_RED,True)))
        for i,f in enumerate(crit_high[:25],1):
            sev   = f.get("severity","INFO").upper()
            issue = f.get("issue") or f.get("type","Desconhecido")
            url   = f.get("url",target)
            cvss  = CVSS_MAP.get(issue, CVSS_MAP.get(sev,5.0))
            ev    = f.get("evidence","") or f.get("payload","") or f.get("value","")
            block=[
                Paragraph(f"{i}. {_badge(sev)} {issue}",_style(10,bold=True)),
                Paragraph(f"<b>URL:</b> {url[:90]}",_style(9)),
                Paragraph(f"<b>CVSS estimado:</b> {cvss}",_style(9)),
                Paragraph(f"<b>Impacto:</b> {_impact(f)}",_style(9)),
                Paragraph(f"<b>Recomendação:</b> {_rec(f)}",_style(9)),
            ]
            if ev:
                block.append(Paragraph(f"<b>Evidência:</b> {str(ev)[:120]}",
                                       _style(8,colors.HexColor("#2d6a4f"),font="Courier")))
            block.append(HRFlowable(width="100%",thickness=.5,color=C_GRAY,spaceAfter=4))
            C.append(KeepTogether(block))
    C.append(PageBreak())

    # SECRETS
    secrets = report.get("secrets",[])
    if secrets:
        C.append(Paragraph("🔑 Secrets e Credenciais Expostos",_style(14,C_RED,True)))
        rows=[["Tipo","Valor (truncado)","URL"]]
        for s in secrets[:30]:
            rows.append([s.get("type",""),str(s.get("value",""))[:40]+"…",s.get("url","")[:55]])
        t=Table(rows,colWidths=[4.5*cm,5.5*cm,7.5*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),C_RED),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
            ("GRID",(0,0),(-1,-1),.5,C_GRAY),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#fff5f5"),colors.white]),
        ]))
        C.append(t)
        C.append(Spacer(1,.5*cm))

    # TECNOLOGIAS + CVEs
    techs = report.get("technologies",[])
    cves  = report.get("cve_matches",[])
    if techs:
        C.append(Paragraph("🧩 Stack Tecnológico e CVEs",_style(14,C_RED,True)))
        C.append(Paragraph("  •  ".join(techs),_style(9)))
        if cves:
            C.append(Spacer(1,.3*cm))
            rows=[["CVE","Tech","Severidade","Descrição"]]
            for cv in (cves or [])[:15]:
                rows.append([cv.get("cve",""),cv.get("tech",""),
                             cv.get("severity",""),cv.get("desc","")[:50]])
            t=Table(rows,colWidths=[3*cm,3*cm,2.5*cm,9*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),C_DARK),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
                ("GRID",(0,0),(-1,-1),.5,C_GRAY),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f8f9fa")]),
            ]))
            C.append(t)
        C.append(Spacer(1,.5*cm))

    # ATAQUE — resultados do Pipeline 4
    attack = report.get("attack", {})
    attack_summary = attack.get("summary", report.get("attack_summary", {}))
    attack_insights = attack.get("insights", report.get("attack_insights", []))
    if attack_summary or attack_insights:
        C.append(Paragraph("\u2694\ufe0f Pipeline 4 — Resultados do Ataque", _style(14,C_RED,True)))
        C.append(Spacer(1,.2*cm))
        if attack_insights:
            for ins in attack_insights:
                C.append(Paragraph(f"  \u25b8  {ins}", _style(9)))
            C.append(Spacer(1,.3*cm))
        if attack_summary:
            rows = [["M\u00e9trica", "Resultado"]]
            metrics = [
                ("Vers\u00e3o do banco extraida",  str(attack_summary.get("db_version") or "—")),
                ("Tabelas enumeradas",          str(attack_summary.get("tables_found", 0))),
                ("Registros vazados",            str(attack_summary.get("records_dumped", 0))),
                ("Auth bypass por SQLi",         str(attack_summary.get("auth_bypassed", 0))),
                ("XSS confirmados",              str(attack_summary.get("xss_confirmed", 0))),
                ("DOM XSS potencial",            str(attack_summary.get("dom_xss", 0))),
                ("Arquivos lidos via LFI",       str(attack_summary.get("files_read", 0))),
                ("Configs expostos",             str(attack_summary.get("configs_exposed", 0))),
                ("Log Poisoning",                "SIM" if attack_summary.get("log_poison") else "N\u00e3o"),
                ("Credenciais v\u00e1lidas",         str(attack_summary.get("valid_creds", 0))),
                ("Usu\u00e1rios enumerados",          str(attack_summary.get("users_enumerated", 0))),
            ]
            for label, val in metrics:
                rows.append([label, val])
            t = Table(rows, colWidths=[8*cm, 6*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),C_DARK),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),
                ("GRID",(0,0),(-1,-1),.5,C_GRAY),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#fff5f5"),colors.white]),
            ]))
            C.append(t)
        C.append(Spacer(1,.5*cm))

    # RECOMENDA\u00c7\u00d5ES GERAIS
    C.append(Paragraph("\U0001f4cb Recomenda\u00e7\u00f5es Gerais",_style(14,C_RED,True)))
    recs=[
        "Implementar WAF na frente da aplica\u00e7\u00e3o.",
        "Habilitar todos os security headers (CSP, HSTS, X-Frame-Options, etc.).",
        "Remover secrets do frontend. Usar vari\u00e1veis de ambiente e secret managers.",
        "Adotar prepared statements em todas as queries SQL.",
        "Implementar rate limiting em endpoints de autentica\u00e7\u00e3o.",
        "Manter depend\u00eancias atualizadas com patches de seguran\u00e7a.",
        "Configurar monitoramento de logs com alertas para padr\u00f5es de ataque.",
        "Realizar pentest manual focado nos findings cr\u00edticos deste relat\u00f3rio.",
    ]
    for r in recs:
        C.append(Paragraph(f"  \u25b8  {r}",_style(9)))

    C.append(Spacer(1,1*cm))
    C.append(HRFlowable(width="100%",thickness=1,color=C_RED))
    C.append(Spacer(1,.3*cm))
    C.append(Paragraph(f"Gerado por <b>PreviSwit v3</b> \u2014 PreviSwit | {now}",
                       _style(8,C_GRAY,align=TA_CENTER)))
    doc.build(C)


# ─── HTML DASHBOARD ──────────────────────────────────────────────────────────
def generate_dashboard(report, filename="dashboard.html"):
    now    = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    target = report.get("target","N/A")
    score  = _score(report)
    counts = _counts(report)

    findings_prioritized = report.get("findings_prioritized",[])
    secrets   = report.get("secrets",[])
    techs     = report.get("technologies",[])
    insights  = report.get("ai_insights",[])
    top_issues= report.get("ai_top_issues",[])
    cves      = report.get("cve_matches",[])

    score_color = "#e63946" if score<4 else ("#f4a261" if score<7 else "#2a9d8f")
    score_label = "CRITICO" if score<4 else ("ATENCAO" if score<7 else "BOM")

    def badge(sev):
        c = {"CRITICAL":"#e63946","HIGH":"#f4a261","MEDIUM":"#e9c46a","LOW":"#2a9d8f","INFO":"#457b9d"}
        return f'<span class="badge" style="background:{c.get(sev.upper(),"#666")}">{sev}</span>'

    def cvss_val(f):
        issue = f.get("issue","") or f.get("type","")
        sev   = f.get("severity","LOW").upper()
        for k,v in CVSS_MAP.items():
            if k.lower() in issue.lower(): return v
        return CVSS_MAP.get(sev,5.0)

    finding_rows = ""
    for f in findings_prioritized[:60]:
        sev   = f.get("severity","INFO").upper()
        issue = f.get("issue") or f.get("type","")
        url   = f.get("url","")
        ev    = str(f.get("evidence","") or f.get("payload","") or f.get("value",""))[:80]
        src   = f.get("source","")
        cvss  = cvss_val(f)
        finding_rows += (
            f'<tr class="finding-row" data-sev="{sev}">'
            f'<td>{badge(sev)}</td><td>{issue}</td>'
            f'<td><a href="{url}" target="_blank">{url[:60]}...</a></td>'
            f'<td>{cvss}</td><td class="ev">{ev}</td>'
            f'<td><span class="source">{src}</span></td></tr>'
        )

    secret_rows = ""
    for s in secrets[:30]:
        secret_rows += (
            f'<tr><td><span class="badge" style="background:#e63946">{s.get("type","")}</span></td>'
            f'<td class="ev">{str(s.get("value",""))[:60]}...</td>'
            f'<td><a href="{s.get("url","")}" target="_blank">{s.get("url","")[:60]}</a></td></tr>'
        )

    insight_items = "".join(f"<li>{i}</li>" for i in insights)
    top_items     = "".join(
        f"<div class='top-item'><span>{i['issue']}</span><b>{i['count']}x</b></div>"
        for i in top_issues
    )
    tech_badges = "".join(f"<span class='tech-badge'>{t}</span>" for t in techs)

    cve_rows = ""
    for cv in (cves or [])[:15]:
        sc = {"CRITICAL":"#e63946","HIGH":"#f4a261","MEDIUM":"#e9c46a"}.get(cv.get("severity",""), "#adb5bd")
        cve_rows += (
            f'<tr><td><a href="https://nvd.nist.gov/vuln/detail/{cv.get("cve","")}" target="_blank">'
            f'{cv.get("cve","")}</a></td><td>{cv.get("tech","")}</td>'
            f'<td><span class="badge" style="background:{sc}">{cv.get("severity","")}</span></td>'
            f'<td>{cv.get("desc","")}</td></tr>'
        )

    # ── Attack (Pipeline 4) ─────────────────────────────────────────────────
    attack_data   = report.get("attack", {})
    atk_summary   = attack_data.get("summary", report.get("attack_summary", {}))
    atk_insights  = attack_data.get("insights", report.get("attack_insights", []))
    valid_creds   = attack_data.get("auth",{}).get("valid_credentials",[])
    files_read    = (attack_data.get("path",{}).get("files_read",[]) +
                     attack_data.get("path",{}).get("app_configs",[]))
    confirmed_xss = (attack_data.get("xss",{}).get("confirmed_xss",[]) +
                     attack_data.get("xss",{}).get("bypass_xss",[]))
    dumped_data   = attack_data.get("sqli",{}).get("dumped_data",[])

    atk_insight_items = "".join(f"<li>{i}</li>" for i in atk_insights)

    cred_rows = ""
    for c in valid_creds[:20]:
        cred_rows += (
            f'<tr><td><span class="badge" style="background:#e63946">CRITICAL</span></td>'
            f'<td><code class="ev">{c.get("username","")}</code></td>'
            f'<td><code class="ev">{c.get("password","")}</code></td>'
            f'<td><a href="{c.get("url","")}" target="_blank">{c.get("url","")[:55]}</a></td></tr>'
        )

    file_rows = ""
    for f2 in files_read[:15]:
        file_rows += (
            f'<tr><td><code class="ev">{f2.get("file","")}</code></td>'
            f'<td class="ev">{str(f2.get("excerpt",""))[:100]}</td>'
            f'<td><a href="{f2.get("url","")}" target="_blank">{f2.get("url","")[:50]}</a></td></tr>'
        )

    xss_atk_rows = ""
    for x in confirmed_xss[:15]:
        xss_atk_rows += (
            f'<tr><td><span class="badge" style="background:#f4a261">{x.get("type","XSS")}</span></td>'
            f'<td><code>{x.get("param","")}</code></td>'
            f'<td class="ev">{x.get("payload","")[:80]}</td>'
            f'<td><a href="{x.get("url","")}" target="_blank">{x.get("url","")[:55]}</a></td></tr>'
        )

    dump_rows = ""
    for d in dumped_data[:10]:
        sample = ", ".join(str(s) for s in d.get("sample",[])[:3])
        dump_rows += (
            f'<tr><td><code>{d.get("table","")}</code></td>'
            f'<td><code>{d.get("columns","")}</code></td>'
            f'<td>{d.get("total",0)}</td>'
            f'<td class="ev">{sample[:80]}</td></tr>'
        )

    atk_summary_cards = ""
    if atk_summary:
        s = atk_summary
        for label, val, col in [
            ("Credenciais",  s.get("valid_creds",0),    "#e63946"),
            ("XSS confirm.", s.get("xss_confirmed",0),  "#f4a261"),
            ("Arq. lidos",   s.get("files_read",0),     "#e63946"),
            ("Tabelas",      s.get("tables_found",0),   "#f4a261"),
            ("Reg. vazados", s.get("records_dumped",0), "#e63946"),
            ("Log Poison",   "SIM" if s.get("log_poison") else "Nao", "#adb5bd"),
        ]:
            atk_summary_cards += (
                f"<div class='card' style='border-color:{col}'>"
                f"<div class='num' style='color:{col}'>{val}</div>"
                f"<div class='lbl'>{label}</div></div>"
            )

    has_attack = bool(atk_summary or atk_insights)

    # Build conditional HTML blocks as plain strings (avoids f-string nesting issues)
    attack_block = ""
    if has_attack:
        attack_block = (
            f'<div class="box" style="border-color:#e63946">'
            f'<h3 style="color:#e63946">Pipeline 4 -- Resultados do Ataque</h3>'
            f'<div class="cards" style="margin-bottom:14px">{atk_summary_cards}</div>'
            + (f'<div class="insights"><ul>{atk_insight_items}</ul></div>' if atk_insight_items else "") +
            f'</div>'
        )

    cred_block = ""
    if valid_creds:
        cred_block = (
            f'<div class="box"><h3 style="color:#e63946">Credenciais Validas Encontradas</h3>'
            f'<table><thead><tr><th>Sev</th><th>Usuario</th><th>Senha</th><th>Endpoint</th></tr></thead>'
            f'<tbody>{cred_rows}</tbody></table></div>'
        )

    xss_atk_block = ""
    if confirmed_xss:
        xss_atk_block = (
            f'<div class="box"><h3 style="color:#f4a261">XSS Confirmados (Attack)</h3>'
            f'<table><thead><tr><th>Tipo</th><th>Param</th><th>Payload</th><th>URL</th></tr></thead>'
            f'<tbody>{xss_atk_rows}</tbody></table></div>'
        )

    file_block = ""
    if files_read:
        file_block = (
            f'<div class="box"><h3>Arquivos Lidos via LFI</h3>'
            f'<table><thead><tr><th>Arquivo</th><th>Conteudo (preview)</th><th>URL</th></tr></thead>'
            f'<tbody>{file_rows}</tbody></table></div>'
        )

    dump_block = ""
    if dumped_data:
        dump_block = (
            f'<div class="box"><h3 style="color:#e63946">Dump de Dados (SQLi)</h3>'
            f'<table><thead><tr><th>Tabela</th><th>Colunas</th><th>Registros</th><th>Amostra</th></tr></thead>'
            f'<tbody>{dump_rows}</tbody></table></div>'
        )

    secrets_block = ""
    if secrets:
        secrets_block = (
            f'<div class="box"><h3>Secrets e Credenciais Expostos</h3>'
            f'<table><thead><tr><th>Tipo</th><th>Valor</th><th>URL</th></tr></thead>'
            f'<tbody>{secret_rows}</tbody></table></div>'
        )

    cve_block = ""
    if cves:
        cve_block = (
            f'<div class="box"><h3>CVEs por Tecnologia Detectada</h3>'
            f'<table><thead><tr><th>CVE</th><th>Tecnologia</th><th>Severidade</th><th>Descricao</th></tr></thead>'
            f'<tbody>{cve_rows}</tbody></table></div>'
        )

    tech_block = ""
    if techs:
        tech_block = f'<div class="box"><h3>Stack Tecnologico</h3><div style="margin-top:8px">{tech_badges}</div></div>'

    pie_data   = json.dumps([counts[k] for k in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]])
    top_labels = json.dumps([i["issue"][:30] for i in top_issues])
    top_vals   = json.dumps([i["count"] for i in top_issues])

    html = (
        "<!DOCTYPE html>\n"
        '<html lang="pt-BR">\n'
        "<head>\n"
        '<meta charset="UTF-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        "<title>PreviSwit -- Dashboard</title>\n"
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>\n'
        "<style>\n"
        "  :root {\n"
        "    --bg:#0d0d1a; --panel:#12122a; --border:#1e1e3a;\n"
        "    --red:#e63946; --orange:#f4a261; --yellow:#e9c46a;\n"
        "    --green:#2a9d8f; --blue:#457b9d; --gray:#adb5bd; --white:#f1faee;\n"
        "  }\n"
        "  *{box-sizing:border-box;margin:0;padding:0}\n"
        "  body{background:var(--bg);color:var(--white);font-family:'Segoe UI',sans-serif;font-size:14px}\n"
        "  header{background:var(--panel);border-bottom:2px solid var(--red);padding:18px 32px;display:flex;align-items:center;gap:16px}\n"
        "  header h1{font-size:22px;color:var(--red);letter-spacing:2px}\n"
        "  header span{color:var(--gray);font-size:13px}\n"
        "  .meta{margin-left:auto;text-align:right;font-size:12px;color:var(--gray)}\n"
        "  main{padding:24px 32px;display:grid;gap:20px}\n"
        "  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px}\n"
        "  .card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:18px;text-align:center}\n"
        "  .card .num{font-size:36px;font-weight:700;line-height:1}\n"
        "  .card .lbl{font-size:11px;color:var(--gray);margin-top:4px;text-transform:uppercase;letter-spacing:1px}\n"
        "  .card.crit{border-color:var(--red)} .card.crit .num{color:var(--red)}\n"
        "  .card.high{border-color:var(--orange)} .card.high .num{color:var(--orange)}\n"
        "  .card.med{border-color:var(--yellow)} .card.med .num{color:var(--yellow)}\n"
        "  .card.low{border-color:var(--green)} .card.low .num{color:var(--green)}\n"
        f"  .card.score .num{{color:{score_color}}}\n"
        "  .charts{display:grid;grid-template-columns:1fr 1fr;gap:20px}\n"
        "  .box{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:20px}\n"
        "  .box h3{color:var(--red);font-size:13px;letter-spacing:1px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid var(--border);padding-bottom:8px}\n"
        "  canvas{max-height:260px}\n"
        "  .insights ul{list-style:none;display:grid;gap:8px}\n"
        "  .insights li{background:#1a1a2e;border-left:3px solid var(--red);padding:10px 14px;border-radius:4px;font-size:13px}\n"
        "  .filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}\n"
        "  .filter-btn{background:var(--panel);border:1px solid var(--border);color:var(--gray);\n"
        "               padding:5px 14px;border-radius:20px;cursor:pointer;font-size:12px;transition:.2s}\n"
        "  .filter-btn.active,.filter-btn:hover{border-color:var(--red);color:var(--white)}\n"
        "  table{width:100%;border-collapse:collapse;font-size:12px}\n"
        "  th{background:#1a1a2e;color:var(--gray);padding:8px 10px;text-align:left;font-size:11px;letter-spacing:.5px;text-transform:uppercase}\n"
        "  td{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}\n"
        "  tr:hover td{background:#14142a}\n"
        '  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;color:#fff}\n'
        "  .source{font-size:10px;color:var(--gray);background:#1a1a2e;padding:2px 6px;border-radius:3px}\n"
        "  .ev{font-family:monospace;font-size:11px;color:#7ec8a0;word-break:break-all}\n"
        "  a{color:var(--blue);text-decoration:none} a:hover{text-decoration:underline}\n"
        "  .tech-badge{background:#1a1a2e;border:1px solid var(--border);padding:4px 10px;border-radius:12px;font-size:12px;margin:3px;display:inline-block}\n"
        "  .top-item{display:flex;justify-content:space-between;padding:8px 12px;background:#1a1a2e;border-radius:6px;margin-bottom:6px;font-size:12px}\n"
        "  .top-item b{color:var(--red)}\n"
        "  .score-bar-wrap{margin:8px 0 4px}\n"
        "  .score-bar{height:16px;border-radius:8px;background:#1e1e3a;overflow:hidden}\n"
        f"  .score-fill{{height:100%;background:{score_color};border-radius:8px;width:{score*10}%;transition:width .8s}}\n"
        f"  .score-label{{font-size:28px;font-weight:700;color:{score_color}}}\n"
        "  @media(max-width:700px){.charts{grid-template-columns:1fr}main{padding:14px}}\n"
        "  .hidden{display:none}\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "<header>\n"
        "  <div>\n"
        "    <h1>PREVISWIT</h1>\n"
        "    <span>AI-Powered Pentest Dashboard</span>\n"
        "  </div>\n"
        '  <div class="meta">\n'
        f"    <div><b>Alvo:</b> {target}</div>\n"
        f"    <div><b>Data:</b> {now}</div>\n"
        "  </div>\n"
        "</header>\n"
        "<main>\n"
        '\n<!-- CARDS -->\n'
        '<div class="cards">\n'
        '  <div class="card score">\n'
        f'    <div class="num">{score}</div>\n'
        '    <div class="lbl">Security Score</div>\n'
        '    <div class="score-bar-wrap"><div class="score-bar"><div class="score-fill"></div></div></div>\n'
        f'    <div style="font-size:11px;color:{score_color};margin-top:4px">{score_label}</div>\n'
        "  </div>\n"
        f'  <div class="card crit"><div class="num">{counts["CRITICAL"]}</div><div class="lbl">Critico</div></div>\n'
        f'  <div class="card high"><div class="num">{counts["HIGH"]}</div><div class="lbl">Alto</div></div>\n'
        f'  <div class="card med"><div class="num">{counts["MEDIUM"]}</div><div class="lbl">Medio</div></div>\n'
        f'  <div class="card low"><div class="num">{counts["LOW"]}</div><div class="lbl">Baixo</div></div>\n'
        f'  <div class="card"><div class="num">{len(secrets)}</div><div class="lbl">Secrets</div></div>\n'
        f'  <div class="card"><div class="num">{len(techs)}</div><div class="lbl">Tecnologias</div></div>\n'
        "</div>\n"
        "\n<!-- CHARTS -->\n"
        '<div class="charts">\n'
        '  <div class="box"><h3>Distribuicao de Severidade</h3><canvas id="pieChart"></canvas></div>\n'
        '  <div class="box"><h3>Top Issues Recorrentes</h3><canvas id="barChart"></canvas></div>\n'
        "</div>\n"
        + (f'\n<div class="box insights"><h3>Insights da IA</h3><ul>{insight_items}</ul></div>\n' if insights else "")
        + (f'\n<div class="box"><h3>Memoria Historica da IA</h3>{top_items}</div>\n' if top_items else "")
        +
        "\n<!-- FINDINGS -->\n"
        '<div class="box">\n'
        "  <h3>Findings Priorizados</h3>\n"
        '  <div class="filters">\n'
        '    <button class="filter-btn active" onclick="filterFindings(\'ALL\')">Todos</button>\n'
        '    <button class="filter-btn" onclick="filterFindings(\'CRITICAL\')" style="color:#e63946">Critico</button>\n'
        '    <button class="filter-btn" onclick="filterFindings(\'HIGH\')" style="color:#f4a261">Alto</button>\n'
        '    <button class="filter-btn" onclick="filterFindings(\'MEDIUM\')" style="color:#e9c46a">Medio</button>\n'
        '    <button class="filter-btn" onclick="filterFindings(\'LOW\')" style="color:#2a9d8f">Baixo</button>\n'
        "  </div>\n"
        "  <table>\n"
        "    <thead><tr><th>Sev</th><th>Issue</th><th>URL</th><th>CVSS</th><th>Evidencia</th><th>Fonte</th></tr></thead>\n"
        f'    <tbody id="findingsBody">{finding_rows}</tbody>\n'
        "  </table>\n"
        "</div>\n"
        + secrets_block
        + cve_block
        + tech_block
        + "\n<!-- PIPELINE 4: ATAQUE -->\n"
        + attack_block
        + cred_block
        + xss_atk_block
        + file_block
        + dump_block
        +
        "\n</main>\n"
        "<script>\n"
        "new Chart(document.getElementById('pieChart'), {\n"
        "  type:'doughnut',\n"
        "  data:{\n"
        "    labels:['Critical','High','Medium','Low','Info'],\n"
        "    datasets:[{\n"
        f"      data:{pie_data},\n"
        "      backgroundColor:['#e63946','#f4a261','#e9c46a','#2a9d8f','#457b9d'],\n"
        "      borderWidth:2, borderColor:'#0d0d1a'\n"
        "    }]\n"
        "  },\n"
        "  options:{plugins:{legend:{labels:{color:'#adb5bd',font:{size:12}}}}}\n"
        "});\n"
        "new Chart(document.getElementById('barChart'), {\n"
        "  type:'bar',\n"
        "  data:{\n"
        f"    labels:{top_labels},\n"
        "    datasets:[{\n"
        "      label:'Ocorrencias',\n"
        f"      data:{top_vals},\n"
        "      backgroundColor:'#e63946cc',\n"
        "      borderRadius:4\n"
        "    }]\n"
        "  },\n"
        "  options:{\n"
        "    indexAxis:'y',\n"
        "    plugins:{legend:{display:false}},\n"
        "    scales:{\n"
        "      x:{ticks:{color:'#adb5bd'},grid:{color:'#1e1e3a'}},\n"
        "      y:{ticks:{color:'#adb5bd',font:{size:10}},grid:{display:false}}\n"
        "    }\n"
        "  }\n"
        "});\n"
        "function filterFindings(sev) {\n"
        "  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));\n"
        "  event.target.classList.add('active');\n"
        "  document.querySelectorAll('.finding-row').forEach(row=>{\n"
        "    row.classList.toggle('hidden', sev!=='ALL' && row.dataset.sev!==sev);\n"
        "  });\n"
        "}\n"
        "</script>\n"
        "</body></html>"
    )

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

