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
PreviSwit AI-ASPM — Core: AI Engine
Orquestrador centralizado de chamadas ao Gemini.
Usado pelos routers de AI Insights para manter lógica consistente.
"""
import os
import json
import logging
from typing import Optional

logger = logging.getLogger("previswit.ai_engine")

try:
    import google.generativeai as genai
    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False
    logger.warning("google-generativeai não instalado. Funcionalidades de IA desabilitadas.")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
_model = None


def _get_model():
    """Inicializa o modelo Gemini de forma lazy e thread-safe."""
    global _model
    if _model is None and _SDK_AVAILABLE and GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
        _model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            generation_config={
                "temperature": 0.3,
                "top_p": 0.95,
                "max_output_tokens": 2048,
            },
        )
    return _model


def generate(prompt: str, json_mode: bool = False) -> str:
    """
    Gera texto a partir de um prompt usando o Gemini.

    Args:
        prompt: O prompt completo a enviar ao modelo.
        json_mode: Se True, o prompt deve solicitar resposta em JSON.

    Returns:
        String com a resposta do modelo, ou mensagem de erro/fallback.
    """
    model = _get_model()
    if model is None:
        if not _SDK_AVAILABLE:
            return '{"error": "SDK google-generativeai não instalado"}'
        if not GEMINI_API_KEY:
            return '{"error": "GEMINI_API_KEY não configurada"}'
        return '{"error": "Modelo IA indisponível"}'

    try:
        response = model.generate_content(prompt)
        text = response.text.strip()
        # Se json_mode, tenta remover markdown code fences
        if json_mode and text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1])
        return text
    except Exception as e:
        logger.error(f"Erro ao chamar Gemini: {e}")
        if json_mode:
            return json.dumps({"error": str(e)})
        return f"Erro ao consultar IA: {str(e)}"


def generate_json(prompt: str) -> dict:
    """
    Gera e parseia uma resposta JSON do Gemini.

    Returns:
        Dict com o JSON parseado, ou dict com chave 'error' em caso de falha.
    """
    raw = generate(prompt, json_mode=True)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.warning(f"Resposta do Gemini não é JSON válido: {raw[:200]}")
        return {"error": "Resposta não é JSON válido", "raw": raw}


def is_available() -> bool:
    """Verifica se o motor IA está disponível e configurado."""
    return _SDK_AVAILABLE and bool(GEMINI_API_KEY)
