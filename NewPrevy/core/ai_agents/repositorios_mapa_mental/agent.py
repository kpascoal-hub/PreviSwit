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
PreviSwit AI-ASPM — Core: AI Manager (Cérebro Central)
Gerenciador unificado do Gemini via novo SDK google-genai.
Suporta chamadas stateless (generate_insight) e chats com memória
persistente por session_id (chat_with_memory).
"""
import os
import re
import json
import logging
import asyncio
from pathlib import Path
from typing import Optional

logger = logging.getLogger("previswit.ai_manager")

try:
    from google import genai
    from google.genai import types
    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False
    logger.warning("SDK google-genai não instalado. Funcionalidades de IA desabilitadas.")

# Caminho raiz para armazenar memórias de sessão
_MEMORY_DIR = Path(__file__).parent.parent / "data"
_MEMORY_DIR.mkdir(parents=True, exist_ok=True)

# Mensagens puramente sociais — as únicas que dispensam o contexto do Mapa Mental.
_SOCIAL_RE = re.compile(
    r"^\s*(oi+|ol[áa]|e a[íi]|hey|hi|bom dia|boa tarde|boa noite|tudo bem|tudo certo|"
    r"obrigad[oa]|valeu|vlw|tchau|at[ée] mais|ok|okay|blz|beleza|legal|show|entendi|"
    r"perfeito|top|massa)\s*[.!?…]*\s*$",
    re.I,
)

_SYSTEM_INSTRUCTION = (
    "Você é o Gemini Security Copilot da plataforma PreviSwit AI-ASPM — "
    "um assistente especialista em Application Security Posture Management (ASPM), "
    "segurança de software, análise de commits e revisão de código. "
    "Responda sempre em português brasileiro. "
    "Seja técnico, preciso e direto ao ponto. "
    "Quando analisar código ou commits, foque em vulnerabilidades reais, "
    "problemas de qualidade e boas práticas de segurança. "
    "REGRA ABSOLUTA: Você NÃO é um scanner de código. NUNCA deduza ou invente "
    "falhas de segurança baseando-se apenas em títulos de commits ou mensagens de texto. "
    "PORÉM: quando o contexto trouxer commits com `scan_executado: true` e uma lista "
    "`achados[]`, esses são resultados SAST REAIS já produzidos por Semgrep/Trivy/Gitleaks/"
    "Checkov — use-os com confiança, cite ferramenta, arquivo, regra e severidade, e NÃO "
    "peça para o usuário rodar a análise novamente. Só oriente rodar a Análise SAST nas "
    "Ações Rápidas para os commits que estiverem com `scan_executado: false`."
)


class MapaMentalAgent:
    """
    Cérebro Central de IA para o PreviSwit.
    
    - generate_insight(): Chamada stateless para análises pontuais.
    - chat_with_memory(): Chat com memória persistente por session_id.
    """

    def __init__(self):
        self._model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        # Cache em memória dos históricos de sessão carregados do disco
        self._session_cache: dict[str, list] = {}

        if not _SDK_AVAILABLE:
            logger.error("SDK google-genai não disponível. Instale: pip install google-genai")

    @property
    def is_available(self) -> bool:
        return _SDK_AVAILABLE

    def _unavailable_msg(self) -> str:
        if not _SDK_AVAILABLE:
            return "⚠️ SDK google-genai não instalado no servidor."
        return "⚠️ Cliente de IA indisponível. Tente novamente em instantes."

    # ── Método 1: Stateless ───────────────────────────────────────────────────

    async def generate_insight(
        self,
        prompt: str,
        api_key: str,
        system_instruction: str = ""
    ) -> str:
        """
        Gera um insight único sem guardar histórico.
        Ideal para resumos de repositórios e análises pontuais de commits.
        Tenta até 3 vezes em caso de 503 (Gemini temporariamente indisponível).
        """
        if not self.is_available:
            return self._unavailable_msg()

        if not api_key:
            return "⚠️ Chave do Gemini não fornecida. Configure em Integrações."

        sys_instr = system_instruction or _SYSTEM_INSTRUCTION
        client = genai.Client(api_key=api_key)

        for attempt in range(3):
            try:
                response = await asyncio.to_thread(
                    client.models.generate_content,
                    model=self._model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=sys_instr,
                        temperature=0.3,
                        max_output_tokens=4096,
                    ),
                )
                return response.text.strip()
            except Exception as e:
                err = str(e)
                is_503 = "503" in err or "UNAVAILABLE" in err
                is_429 = "429" in err or "RESOURCE_EXHAUSTED" in err

                if is_503 and attempt < 2:
                    wait = 2 ** attempt  # 1s, 2s
                    logger.warning(f"generate_insight 503 (tentativa {attempt+1}/3) — aguardando {wait}s")
                    await asyncio.sleep(wait)
                    continue

                logger.error(f"generate_insight falhou: {err}")
                if is_429:
                    return "⚠️ Limite de requisições atingido. Aguarde alguns segundos e tente novamente."
                if is_503:
                    return "⚠️ Serviço Gemini temporariamente indisponível. Tente novamente em instantes."
                return f"⚠️ Erro ao consultar IA: {err}"

    # ── Método 2: Stateful com memória persistente ────────────────────────────

    def _memory_path(self, session_id: str) -> Path:
        # Sanitiza o session_id para ser um nome de arquivo seguro
        safe_id = "".join(c if c.isalnum() or c in "-_." else "_" for c in session_id)
        return _MEMORY_DIR / f"ai_memory_{safe_id}.json"

    def _load_history(self, session_id: str) -> list:
        """Carrega histórico de mensagens do disco (formato google-genai)."""
        if session_id in self._session_cache:
            return self._session_cache[session_id]
        path = self._memory_path(session_id)
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                self._session_cache[session_id] = data
                return data
            except Exception as e:
                logger.warning(f"Falha ao carregar histórico de {session_id}: {e}")
        return []

    def _save_history(self, session_id: str, history: list) -> None:
        """Persiste histórico de mensagens no disco."""
        self._session_cache[session_id] = history
        path = self._memory_path(session_id)
        try:
            path.write_text(json.dumps(history, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning(f"Falha ao salvar histórico de {session_id}: {e}")

    async def chat_with_memory(self, session_id: str, prompt: str, api_key: str, context: str = "") -> str:
        """
        Envia uma mensagem para o Gemini mantendo histórico persistente
        por session_id. Cada session_id tem seu próprio arquivo de memória
        em data/ai_memory_{session_id}.json.
        """
        if not self.is_available:
            return self._unavailable_msg()
            
        if not api_key:
            return "⚠️ Chave do Gemini não fornecida. Configure em Integrações."

        # Carrega histórico anterior
        history = self._load_history(session_id)

        # Constrói o conteúdo completo: contexto do sistema + histórico + nova mensagem
        contents: list[dict] = []
        for msg in history:
            contents.append(msg)
            
        # Roteamento de Intenção (Intent Routing).
        # Antes usava allowlist de keywords + len(prompt) < 10, o que descartava o
        # contexto em perguntas de acompanhamento ("e esse aí?", "quais?") e fazia a
        # IA negar ter acesso aos dados. Agora só mensagens puramente sociais
        # dispensam o contexto — qualquer pergunta real recebe o snapshot completo.
        needs_context = bool(context and context.strip()) and not _SOCIAL_RE.match(prompt)

        final_prompt = prompt
        current_system_instruction = _SYSTEM_INSTRUCTION

        if needs_context and context.strip():
            # Cache Efêmero: salva o contexto JSON na pasta do agente
            cache_file = os.path.join(os.path.dirname(__file__), "commits_context.json")
            try:
                with open(cache_file, 'w', encoding='utf-8') as f:
                    f.write(context)
                logger.info(f"[Cache Efêmero] commits_context.json atualizado para session '{session_id}'.")
            except Exception as cache_err:
                logger.warning(f"[Cache Efêmero] Falha ao salvar cache: {cache_err}")

            final_prompt = (
                "REGRA ABSOLUTA: O snapshot atual do Mapa Mental do repositório está no JSON abaixo. "
                "Ele é a sua ÚNICA fonte de verdade e você TEM acesso completo a ele.\n\n"
                "Estrutura do JSON:\n"
                "- `resumo`: contagens agregadas (commits no mapa, quantos têm scan SAST, quantos são "
                "vulneráveis, total de achados).\n"
                "- `commits[]`: cada commit com `hash`, `hash_curto`, `autor`, `data`, `mensagem`, "
                "`branch`, `tipo` (main/pr).\n"
                "- `commits[].scan_executado`: se `true`, esse commit JÁ passou pelos scanners reais "
                "(Semgrep, Trivy, Gitleaks, Checkov).\n"
                "- `commits[].achados[]`: os RESULTADOS SAST REAIS — `tool`, `arquivo`, `regra`, "
                "`severidade`, `pacote`, `linha`. Estes são achados verificados por ferramenta, "
                "NÃO deduções. Trate-os como fato e cite-os livremente.\n"
                "- `commits[].vulneravel`, `severidade`, `total_achados`, `analise_ia`.\n\n"
                "COMO RESPONDER:\n"
                "1. Se o commit perguntado tem `scan_executado: true`, use os `achados[]` para responder "
                "com precisão (ferramenta, arquivo, regra, severidade). NÃO peça para rodar a análise "
                "de novo — ela já foi executada.\n"
                "2. Se `scan_executado: false`, aí sim diga que aquele commit ainda não foi escaneado e "
                "oriente a rodar a Análise SAST nas Ações Rápidas.\n"
                "3. NUNCA invente vulnerabilidades a partir da mensagem do commit — use apenas `achados[]`.\n"
                "4. NUNCA sugira acessar o GitHub ou outras ferramentas externas.\n"
                "5. Se a informação realmente não estiver no JSON, diga que não está visível no mapa atual.\n\n"
                f"[SNAPSHOT DO MAPA MENTAL — JSON]\n{context}\n\n"
                f"Pergunta do usuário: {prompt}"
            )
        elif not needs_context:
            current_system_instruction = (
                "Você é o PreviSwit AI, um assistente de cibersegurança. O usuário mandou uma mensagem "
                "social/curta. Responda de forma breve, educada e conversacional, e ofereça ajuda com "
                "análise de commits, vulnerabilidades ou postura de segurança."
            )

        contents.append({"role": "user", "parts": [{"text": final_prompt}]})


        client = genai.Client(api_key=api_key)
        
        # Armadura de Resiliência: 3 Tentativas em caso de 503 / Falhas de Demanda
        for attempt in range(3):
            try:
                response = await asyncio.to_thread(
                    client.models.generate_content,
                    model=self._model,
                    contents=contents,
                    config=types.GenerateContentConfig(
                        system_instruction=current_system_instruction,
                        temperature=0.4,
                        max_output_tokens=3072,
                    ),
                )
                answer = response.text.strip()
                
                # Salva a nova dupla de mensagens no histórico (salva o prompt real sem a trava pesada pra não poluir)
                history.append({"role": "user", "parts": [{"text": prompt}]})
                history.append({"role": "model", "parts": [{"text": answer}]})

                # Mantém no máximo 40 mensagens (20 turnos) para evitar context overflow
                if len(history) > 40:
                    history = history[-40:]

                self._save_history(session_id, history)
                return answer

            except Exception as e:
                err = str(e)
                logger.warning(f"[WARN] API sobrecarregada ou falha (Tentativa {attempt + 1}/3): {err}")
                if attempt < 2:
                    await asyncio.sleep(5)
                else:
                    logger.error(f"chat_with_memory falhou definitivamente após 3 tentativas: {err}")
                    return "⚠️ O servidor da IA está com alta demanda no momento (Erro 503). Por favor, aguarde alguns segundos e tente novamente."

    def clear_session(self, session_id: str) -> None:
        """Apaga o histórico de uma sessão do cache e do disco."""
        self._session_cache.pop(session_id, None)
        path = self._memory_path(session_id)
        if path.exists():
            path.unlink()
            logger.info(f"Memória de sessão '{session_id}' apagada.")


# ── Instância Global ──────────────────────────────────────────────────────────
# Importe esta instância em qualquer router: from core.ai_manager import ai_core
mapa_mental_agent = MapaMentalAgent()
