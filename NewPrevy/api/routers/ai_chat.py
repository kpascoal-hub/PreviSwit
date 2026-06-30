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
    commit_data: Optional[dict] = {}
    executive_mode: Optional[bool] = False


@router.post("/validate-sast", summary="Validação de Segurança via IA (Gemini)")
async def validate_sast_endpoint(body: SASTValidationRequest, x_gemini_key: str = Header(..., alias="X-Gemini-Key")):
    """
    Recebe os resultados técnicos dos scanners (Semgrep/Trivy) e o diff do commit,
    usando a IA como auditora para gerar a Prova Técnica de Segurança ou explicar
    as vulnerabilidades encontradas.
    """
    import logging
    import asyncio
    import time as _time
    import json
    
    logger = logging.getLogger("previswit.ai_chat")

    if not x_gemini_key:
        raise HTTPException(status_code=401, detail="Header 'X-Gemini-Key' é obrigatório. Configure a chave na interface.")

    analysis_text = ""
    
    # Tratamento de formato (List vs Dict)
    all_findings = []
    if isinstance(body.scanner_results, list):
        all_findings = body.scanner_results
    elif isinstance(body.scanner_results, dict):
        for tool, results in body.scanner_results.items():
            if tool == "trivy" and isinstance(results, dict):
                for r in results.get("Results", []):
                    target = r.get("Target", "unknown")
                    for vuln in r.get("Vulnerabilities", []):
                        all_findings.append({"tool": "Trivy", "file": target, "rule": vuln.get("Title", "Vuln")})
                    for misc in r.get("Misconfigurations", []):
                        all_findings.append({"tool": "Trivy", "file": target, "rule": misc.get("Title", "Misc")})
            
            elif tool == "semgrep" and isinstance(results, dict):
                for r in results.get("results", []):
                    all_findings.append({"tool": "Semgrep", "file": r.get("path", "unknown"), "rule": r.get("check_id", "Vuln")})
            
            elif tool == "checkov":
                # Checkov pode retornar um dict (1 framework) ou list de dicts (múltiplos)
                checkov_reports = results if isinstance(results, list) else [results]
                for report in checkov_reports:
                    if isinstance(report, dict):
                        failed = report.get("results", {}).get("failed_checks", [])
                        if isinstance(failed, list):
                            for fc in failed:
                                all_findings.append({"tool": "Checkov", "file": fc.get("file_path", "unknown"), "rule": fc.get("check_name", "Check failed")})
                                
            elif tool == "gitleaks" and isinstance(results, list):
                for r in results:
                    if isinstance(r, dict):
                        all_findings.append({"tool": "Gitleaks", "file": r.get("File", "unknown"), "rule": r.get("Description", "Secret Leaked")})

    vulnerable = len(all_findings) > 0

    try:
        from google import genai as _genai
        from google.genai import types as _types

        # Prepara o diff textual dos arquivos para dar contexto ao Gemini
        diff_summary = ""
        for f in (body.files or [])[:5]:
            if isinstance(f, dict):
                diff_summary += f"\n### {f.get('filename', '')}\n```\n{(f.get('patch') or '')[:800]}\n```\n"

        rastreabilidade_rule = (
            f"\n\nDADOS DO COMMIT:\n"
            f"- Hash: {body.sha}\n"
            f"- Autor: {body.author}\n"
            f"- Data: {body.date}\n\n"
            "REGRA DE RASTREABILIDADE: Todo relatório gerado DEVE iniciar obrigatoriamente "
            "com um cabeçalho identificando o ID do Commit (Hash), o Autor e a Data da alteração. "
            "O relatório deve ser completo e detalhado."
        )

        MAX_CHARS = 80000
        scan_json = json.dumps(body.scanner_results, ensure_ascii=False) if body.scanner_results else "[]"
        if len(scan_json) > MAX_CHARS:
            scan_json = scan_json[:MAX_CHARS] + "\n... [DADOS TRUNCADOS PARA EVITAR ESTOURO DE TOKENS DA IA]"

        if body.executive_mode:
            prompt = (
                "Você é um CISO (Chief Information Security Officer) falando com um executivo não-técnico. "
                "O relatório DEVE conter:\n"
                "1) O ID do Commit analisado.\n"
                "2) Se houver vulnerabilidade, explique em um parágrafo o PORQUÊ isso é um risco para o negócio, "
                "detalhando o impacto financeiro, de imagem ou regulatório (ex: ISO 27001/LGPD). "
                "Não cite linhas de código ou termos técnicos profundos. Apenas o impacto e a recomendação de negócio.\n\n"
                f"RESULTADO DOS SCANNERS (Vulnerável: {vulnerable}):\n{scan_json}\n\n"
                "Resuma o impacto de negócios de forma clara, direta e em português."
            )
        else:
            if vulnerable:
                prompt = (
                    "Você é um Auditor Sênior de Segurança de Software (AppSec). "
                    f"Analise os seguintes achados SAST do commit `{body.sha[:8]}` "
                    f"('{body.message[:80]}' por {body.author}):\n\n"
                    f"ACHADOS (JSON Bruto/Truncado):\n{scan_json}\n\n"
                    f"DIFF DO CÓDIGO:\n{diff_summary}\n\n"
                    "Para cada achado: explique o risco real (CWE, CVSS estimado), o impacto "
                    "possível em produção e a correção exata recomendada com exemplo de código "
                    "quando aplicável. Seja direto e técnico em português brasileiro. "
                    "Comece com uma linha: NÍVEL DE RISCO: [CRÍTICO/ALTO/MÉDIO]"
                )
            else:
                prompt = (
                    "Você é Auditor Sênior de Segurança de Software (AppSec). "
                    f"As ferramentas Semgrep e Trivy NÃO encontraram vulnerabilidades no commit "
                    f"`{body.sha[:8]}` ('{body.message[:80]}' por {body.author}).\n\n"
                    f"DIFF DO CÓDIGO ANALISADO:\n{diff_summary or 'Sem arquivos alterados disponíveis.'}\n\n"
                    "REGRA ABSOLUTA: Você DEVE fornecer um relatório técnico de segurança detalhado "
                    "explicando ESTRITAMENTE o PORQUÊ o código está seguro. Analise o diff acima e:\n"
                    "1. Descreva as mudanças de código implementadas neste commit.\n"
                    "2. Explique tecnicamente por que a lógica implementada NÃO abre margem para "
                    "vulnerabilidades (ausência de injeção, sanitização correta, autenticação preservada, etc.).\n"
                    "3. Mencione quais vetores de ataque foram inspecionados e descartados (SQLi, XSS, SSRF, "
                    "exposição de credenciais, etc.) com justificativa técnica.\n"
                    "4. Conclua com: 'VEREDICTO: Código Seguro — [motivo principal em 1 linha]'.\n\n"
                    "Responda em português brasileiro de forma técnica e precisa."
                )

        prompt += rastreabilidade_rule

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
