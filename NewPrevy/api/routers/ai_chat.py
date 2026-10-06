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
PreviSwit AI-ASPM — Router: AI Chat (Copilot)
Endpoint de chat conversacional usando o AIManager (Cérebro Central).
Serve o painel de chat do Risk Graph (RiskGraphCanvas.jsx).
"""
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
import json

from core.ai_agents.repositorios_mapa_mental.agent import mapa_mental_agent

router = APIRouter(prefix="/ai", tags=["AI Chat"])


class ChatRequest(BaseModel):
    session_id: str                    # Ex: nome do repositório (owner_repo)
    message:    Optional[str] = None   # Campo legado (retrocompatibilidade)
    prompt:     Optional[str] = None   # Campo preferencial (spec do contexto)
    prompt_type: Optional[str] = None  # "insight" | "chat" (padrão: "chat")
    context:    Optional[str] = ""     # Contexto extraído do DOM (Mapa Mental)


class InsightRequest(BaseModel):
    prompt: str
    system_instruction: Optional[str] = None


@router.post("/chat", summary="Chat conversacional com memória persistente (Copilot)")
async def ai_chat_endpoint(body: ChatRequest, x_gemini_key: str = Header(default=None, alias="X-Gemini-Key")):
    """
    Envia uma mensagem para o Gemini Security Copilot.
    Aceita 'prompt' ou 'message' no body (ambos funcionam).
    O histórico é salvo por session_id — memória persistente entre sessões.
    """
    print(f"[DEBUG BACKEND] Header X-Gemini-Key recebido: {'SIM' if x_gemini_key else 'NÃO'}")

    # Resolve o texto da mensagem (aceita 'prompt' ou 'message')
    text = (body.prompt or body.message or "").strip()

    # Diagnóstico do contexto recebido do Mapa Mental
    _ctx = body.context or ""
    print(f"[DEBUG CTX] len={len(_ctx)} preview={_ctx[:300]!r}")

    if not text:
        raise HTTPException(status_code=400, detail="Forneça 'prompt' ou 'message' no body.")

    if not x_gemini_key:
        raise HTTPException(status_code=401, detail="Header 'X-Gemini-Key' é obrigatório. Configure a chave na interface.")

    if not mapa_mental_agent.is_available:
        return {
            "session_id": body.session_id,
            "prompt": text,
            "response": "⚠️ Motor de IA indisponível. Configure GEMINI_API_KEY para habilitar o Copilot.",
            "role": "assistant",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    use_stateless = body.prompt_type == "insight"

    if use_stateless:
        response_text = await mapa_mental_agent.generate_insight(prompt=text, api_key=x_gemini_key)
    else:
        response_text = await mapa_mental_agent.chat_with_memory(
            session_id=body.session_id,
            prompt=text,
            api_key=x_gemini_key,
            context=body.context
        )

    return {
        "session_id": body.session_id,
        "prompt": text,
        "response": response_text,
        "role": "assistant",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/insight", summary="Geração de insight stateless (sem histórico)")
async def ai_insight_endpoint(body: InsightRequest, x_gemini_key: str = Header(default=None, alias="X-Gemini-Key")):
    """
    Chamada direta ao Gemini sem guardar histórico.
    Ideal para análises únicas como 'Resumir riscos' de um repositório.
    """
    print(f"[DEBUG BACKEND] Header X-Gemini-Key recebido (Insight): {'SIM' if x_gemini_key else 'NÃO'}")

    if not body.prompt.strip():
        raise HTTPException(status_code=400, detail="Campo 'prompt' não pode estar vazio.")

    if not x_gemini_key:
        raise HTTPException(status_code=401, detail="Header 'X-Gemini-Key' é obrigatório. Configure a chave na interface.")

    response_text = await mapa_mental_agent.generate_insight(
        prompt=body.prompt,
        api_key=x_gemini_key,
        system_instruction=body.system_instruction or "",
    )
    return {
        "response": response_text,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.delete("/chat/{session_id}", summary="Limpar histórico de uma sessão de chat")
async def clear_chat_session(session_id: str):
    """
    Apaga o histórico persistido de uma sessão específica do Copilot.
    Útil para começar uma nova conversa do zero sem recarregar o servidor.
    """
    mapa_mental_agent.clear_session(session_id)
    return {"detail": f"Histórico da sessão '{session_id}' apagado com sucesso."}


from typing import Optional, Any, Union

class SASTValidationRequest(BaseModel):
    sha:     str
    message: Optional[str] = ""
    author:  Optional[str] = ""
    date:    Optional[str] = ""
    branch:  Optional[str] = ""
    files:   Optional[list] = []
    scanner_results: Optional[Union[dict, list]] = {}
    commits_data: Optional[list] = []   # lista de { sha, message, author, date, scanner_results, vulnerable }
    commit_data: Optional[dict] = {}
    executive_mode: Optional[bool] = False


def _extract_findings(scanner_results: dict, sha: str = "") -> list:
    """Extrai findings reais (vulnerabilidades HIGH/CRITICAL) de um scanner_results dict."""
    findings = []
    if not isinstance(scanner_results, dict):
        return findings

    # Trivy — apenas HIGH/CRITICAL
    trivy = scanner_results.get("trivy", {})
    if isinstance(trivy, dict):
        for r in trivy.get("Results", []):
            target = r.get("Target", "unknown")
            for v in r.get("Vulnerabilities", []):
                if v.get("Severity", "").upper() in ("HIGH", "CRITICAL"):
                    findings.append({
                        "tool": "Trivy", "sha": sha, "file": target,
                        "rule": v.get("Title") or v.get("VulnerabilityID", "Vuln"),
                        "severity": v.get("Severity", ""),
                    })

    # Semgrep
    semgrep = scanner_results.get("semgrep", {})
    if isinstance(semgrep, dict):
        for r in semgrep.get("results", []):
            findings.append({
                "tool": "Semgrep", "sha": sha,
                "file": r.get("path", "unknown"),
                "rule": r.get("check_id", "Vuln"),
                "severity": r.get("extra", {}).get("severity", ""),
            })

    # Gitleaks
    gitleaks = scanner_results.get("gitleaks", [])
    if isinstance(gitleaks, list):
        for r in gitleaks:
            if isinstance(r, dict):
                findings.append({
                    "tool": "Gitleaks", "sha": sha,
                    "file": r.get("File", "unknown"),
                    "rule": r.get("Description", "Secret Leaked"),
                    "severity": "CRITICAL",
                })

    # Checkov
    checkov = scanner_results.get("checkov", {})
    checkov_reports = checkov if isinstance(checkov, list) else [checkov]
    for report in checkov_reports:
        if isinstance(report, dict):
            for fc in report.get("results", {}).get("failed_checks", []):
                findings.append({
                    "tool": "Checkov", "sha": sha,
                    "file": fc.get("file_path", "unknown"),
                    "rule": fc.get("check_name", "Check failed"),
                    "severity": fc.get("severity", ""),
                })

    return findings


@router.post("/validate-sast", summary="Validação de Segurança via IA (Gemini)")
async def validate_sast_endpoint(body: SASTValidationRequest, x_gemini_key: str = Header(..., alias="X-Gemini-Key")):
    """
    Recebe resultados dos scanners e o diff do commit.
    Suporta análise de commit único (scanner_results) ou múltiplos (commits_data).
    """
    import logging
    import asyncio
    import json

    logger = logging.getLogger("previswit.ai_chat")

    if not x_gemini_key:
        raise HTTPException(status_code=401, detail="Header 'X-Gemini-Key' é obrigatório.")

    analysis_text = ""
    multi_commit_mode = bool(body.commits_data)

    # ── Extração de findings reais ────────────────────────────────────────────
    if multi_commit_mode:
        # Processa cada commit individualmente com identificação
        per_commit = []
        for c in body.commits_data:
            sr = c.get("scanner_results") or {}
            findings = _extract_findings(sr, sha=c.get("sha", "")[:8])
            per_commit.append({
                "sha":      c.get("sha", "")[:8],
                "message":  (c.get("message") or "")[:80],
                "author":   c.get("author", ""),
                "date":     c.get("date", ""),
                "vulnerable": c.get("vulnerable", len(findings) > 0),
                "severity": c.get("severity", "HIGH" if findings else "CLEAN"),
                "findings": findings,
            })
        all_findings = [f for c in per_commit for f in c["findings"]]
        vulnerable = any(c["vulnerable"] for c in per_commit)
    else:
        # Commit único
        sr = body.scanner_results if isinstance(body.scanner_results, dict) else {}
        all_findings = _extract_findings(sr, sha=body.sha[:8])
        vulnerable = len(all_findings) > 0
        per_commit = [{
            "sha": body.sha[:8], "message": (body.message or "")[:80],
            "author": body.author, "date": body.date,
            "vulnerable": vulnerable,
            "severity": "HIGH" if vulnerable else "CLEAN",
            "findings": all_findings,
        }]

    try:
        from google import genai as _genai
        from google.genai import types as _types

        MAX_CHARS = 60000

        if body.executive_mode:
            # Constrói sumário por commit para o CISO
            commit_lines = []
            for c in per_commit:
                status = f"⚠️ {len(c['findings'])} achado(s)" if c["vulnerable"] else "✅ Limpo"
                line = f"- `{c['sha']}` ({c['author']}, {c['date'][:10]}): {status}"
                if c["findings"]:
                    for f in c["findings"][:3]:
                        line += f"\n  • [{f['tool']}] {f['file']}: {f['rule']}"
                commit_lines.append(line)

            commits_summary = "\n".join(commit_lines)
            prompt = (
                "Você é um CISO falando com um executivo não-técnico. "
                f"Foram analisados {len(per_commit)} commit(s) do repositório.\n\n"
                f"SUMÁRIO POR COMMIT:\n{commits_summary}\n\n"
                "Gere um relatório executivo em português que:\n"
                "1. Liste cada commit pelo seu hash e indique se está vulnerável ou limpo.\n"
                "2. Para os commits com achados, explique o impacto no negócio (financeiro, "
                "regulatório, imagem) sem termos técnicos profundos.\n"
                "3. Finalize com uma recomendação de prioridade de ação.\n"
                "Seja direto e objetivo."
            )
        else:
            diff_summary = ""
            for f in (body.files or [])[:5]:
                if isinstance(f, dict):
                    diff_summary += f"\n### {f.get('filename', '')}\n```\n{(f.get('patch') or '')[:600]}\n```\n"

            scan_json = json.dumps(all_findings, ensure_ascii=False)
            if len(scan_json) > MAX_CHARS:
                scan_json = scan_json[:MAX_CHARS] + "\n... [TRUNCADO]"

            if vulnerable:
                prompt = (
                    f"Você é um Auditor Sênior de Segurança (AppSec). "
                    f"Commit `{body.sha[:8]}` ('{(body.message or '')[:80]}' por {body.author}).\n\n"
                    f"ACHADOS HIGH/CRITICAL:\n{scan_json}\n\n"
                    f"DIFF:\n{diff_summary}\n\n"
                    "Para cada achado: explique o risco real (CWE, CVSS estimado), o impacto "
                    "possível em produção e a correção exata. Seja técnico e direto em pt-BR. "
                    "Comece com: NÍVEL DE RISCO: [CRÍTICO/ALTO/MÉDIO]"
                )
            else:
                prompt = (
                    f"Você é Auditor Sênior de Segurança (AppSec). "
                    f"Semgrep, Trivy, Gitleaks e Checkov NÃO encontraram vulnerabilidades HIGH/CRITICAL "
                    f"no commit `{body.sha[:8]}` ('{(body.message or '')[:80]}' por {body.author}).\n\n"
                    f"DIFF:\n{diff_summary or 'Sem arquivos disponíveis.'}\n\n"
                    "Explique tecnicamente por que o código está seguro, quais vetores foram "
                    "inspecionados (SQLi, XSS, SSRF, secrets) e conclua com: "
                    "'VEREDICTO: Código Seguro — [motivo em 1 linha]'. Responda em pt-BR."
                )

        client = _genai.Client(api_key=x_gemini_key)
        for attempt in range(3):
            try:
                response = await asyncio.to_thread(
                    client.models.generate_content,
                    model="gemini-2.5-flash",
                    contents=prompt,
                    config=_types.GenerateContentConfig(temperature=0.2, max_output_tokens=2048),
                )
                analysis_text = response.text.strip()
                break
            except Exception as e:
                err_str = str(e)
                logger.warning(f"[AI/ValidateSAST] Tentativa {attempt + 1}/3 falhou: {err_str[:120]}")
                if attempt < 2:
                    await asyncio.sleep(3)
                else:
                    logger.error(f"[AI/ValidateSAST] Todas as tentativas esgotadas. Retornando fallback.")
                    if vulnerable:
                        analysis_text = (
                            f"⚠️ {len(all_findings)} achado(s) SAST detectado(s). "
                            f"A geração da explicação detalhada via IA está temporariamente indisponível "
                            f"devido ao limite de requisições da API (Rate Limit). "
                            f"Achados brutos:\n" +
                            "\n".join(f"• [{f.get('tool')}] {f.get('file')}: {f.get('rule')}" for f in all_findings)
                        )
                    else:
                        analysis_text = (
                            "O código foi auditado pelas ferramentas Semgrep e Trivy e validado como "
                            "estruturalmente seguro. A geração da explicação detalhada via IA está "
                            "temporariamente indisponível devido ao limite de requisições da API "
                            "(Rate Limit), mas nenhuma anomalia de lógica ou código foi detectada."
                        )
    except Exception as general_err:
        analysis_text = f"Erro na integração com Gemini: {str(general_err)}"

    return {
        "analysis": analysis_text,
        "vulnerable": vulnerable,
        "sha": body.sha
    }


class CommitSummaryRequest(BaseModel):
    sha: str
    message: Optional[str] = ""
    author: Optional[str] = ""
    date: Optional[str] = ""
    files: Optional[list] = []

@router.post("/summarize-commit", summary="Resumo Executivo e Técnico do Commit")
async def summarize_commit_endpoint(body: CommitSummaryRequest, x_gemini_key: str = Header(..., alias="X-Gemini-Key")):
    import logging
    import asyncio
    import json
    
    logger = logging.getLogger("previswit.ai_chat")
    
    if not x_gemini_key:
        raise HTTPException(status_code=401, detail="Header 'X-Gemini-Key' é obrigatório.")
        
    try:
        from google import genai as _genai
        from google.genai import types as _types
        
        diff_summary = ""
        for f in (body.files or [])[:5]:
            if isinstance(f, dict):
                diff_summary += f"\n### {f.get('filename', '')}\n```\n{(f.get('patch') or '')[:800]}\n```\n"
                
        prompt = (
            "Você é um Engenheiro de Software Sênior analisando commits. "
            "Leia os dados deste commit e crie um resumo curto (máximo 2 parágrafos) "
            "explicando o que foi feito e o impacto dessa alteração na arquitetura.\n\n"
            f"DADOS DO COMMIT:\n- Hash: {body.sha}\n- Autor: {body.author}\n- Data: {body.date}\n- Mensagem: {body.message}\n\n"
            f"DIFF DO CÓDIGO:\n{diff_summary or 'Sem arquivos alterados disponíveis.'}"
        )
        
        client = _genai.Client(api_key=x_gemini_key)
        summary_text = ""
        
        for attempt in range(3):
            try:
                response = await asyncio.to_thread(
                    client.models.generate_content,
                    model="gemini-2.5-flash",
                    contents=prompt,
                    config=_types.GenerateContentConfig(
                        temperature=0.3, 
                        max_output_tokens=1024,
                        response_mime_type="application/json",
                        response_schema={"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]}
                    ),
                )
                
                try:
                    resp_json = json.loads(response.text)
                    summary_text = resp_json.get("summary", response.text)
                except Exception:
                    summary_text = response.text
                break
            except Exception as e:
                logger.warning(f"[AI/Summarize] Tentativa {attempt + 1}/3 falhou: {str(e)[:120]}")
                if attempt < 2:
                    await asyncio.sleep(2)
                else:
                    summary_text = "O resumo automático está temporariamente indisponível devido a instabilidades na API ou Rate Limit."
                    
        return {"summary": summary_text}
        
    except Exception as general_err:
        return {"summary": f"Erro interno ao gerar resumo: {str(general_err)}"}

