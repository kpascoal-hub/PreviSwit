"""
PreviSwit AI-ASPM — Router: AI Chat (Copilot)
Endpoint de chat conversacional usando o AIManager (Cérebro Central).
Serve o painel de chat do Risk Graph (RiskGraphCanvas.jsx).
"""
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone

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
