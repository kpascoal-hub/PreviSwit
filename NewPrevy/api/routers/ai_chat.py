"""
PreviSwit AI-ASPM — Router: AI Chat (Copilot)
Endpoint de chat conversacional usando o AIManager (Cérebro Central).
Serve o painel de chat do Risk Graph (RiskGraphCanvas.jsx).
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone

from core.ai_manager import ai_core

router = APIRouter(prefix="/ai", tags=["AI Chat"])


class ChatRequest(BaseModel):
    session_id: str                   # Ex: "owner_repo" ou nome do repositório
    message: str                      # Mensagem do usuário
    prompt_type: Optional[str] = None  # "insight" | "chat" (padrão: "chat")


class InsightRequest(BaseModel):
    prompt: str
    system_instruction: Optional[str] = None


@router.post("/chat", summary="Chat conversacional com memória persistente (Copilot)")
async def ai_chat_endpoint(body: ChatRequest):
    """
    Envia uma mensagem para o Gemini Security Copilot.
    O histórico é automaticamente salvo e recuperado por session_id,
    garantindo memória persistente entre sessões do browser.
    """
    if not body.message.strip():
        raise HTTPException(status_code=400, detail="Campo 'message' não pode estar vazio.")

    if not ai_core.is_available:
        return {
            "session_id": body.session_id,
            "response": "⚠️ Motor de IA indisponível. Configure GEMINI_API_KEY para habilitar o Copilot.",
            "role": "assistant",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    use_stateless = body.prompt_type == "insight"

    if use_stateless:
        response_text = await ai_core.generate_insight(prompt=body.message)
    else:
        response_text = await ai_core.chat_with_memory(
            session_id=body.session_id,
            prompt=body.message,
        )

    return {
        "session_id": body.session_id,
        "message": body.message,
        "response": response_text,
        "role": "assistant",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/insight", summary="Geração de insight stateless (sem histórico)")
async def ai_insight_endpoint(body: InsightRequest):
    """
    Chamada direta ao Gemini sem guardar histórico.
    Ideal para análises únicas como 'Resumir riscos' de um repositório.
    """
    if not body.prompt.strip():
        raise HTTPException(status_code=400, detail="Campo 'prompt' não pode estar vazio.")

    response_text = await ai_core.generate_insight(
        prompt=body.prompt,
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
    ai_core.clear_session(session_id)
    return {"detail": f"Histórico da sessão '{session_id}' apagado com sucesso."}
