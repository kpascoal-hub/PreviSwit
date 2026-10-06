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
PreviSwit AI-ASPM — Router: AI Insights (Command Center)
Recomendações de remediação, Threat Intelligence e Chat Gemini.
"""
from fastapi import APIRouter, HTTPException, Header
import json
from datetime import datetime

router = APIRouter(prefix="/ai", tags=["AI & Insights"])

try:
    from google import genai
    from google.genai import types
    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False


def _call_gemini(prompt: str, api_key: str) -> str:
    """Chama o Gemini dinamicamente e retorna a resposta em texto."""
    if not _SDK_AVAILABLE:
        return "⚠️ Motor IA indisponível. SDK google-genai não instalado."
    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(model="gemini-2.5-flash", contents=prompt)
        return response.text
    except Exception as e:
        return f"Erro ao consultar IA: {str(e)}"


# ── Remediação Guiada ──────────────────────────────────────────────────────────

@router.post("/remediation", summary="Gerar recomendação de correção para um finding")
def generate_remediation(body: dict, x_gemini_key: str = Header(default=None, alias="X-Gemini-Key")):
    """
    Recebe os dados de um finding e retorna um playbook de remediação
    personalizado gerado pelo Gemini, incluindo código corrigido quando aplicável.
    """
    if not x_gemini_key:
        raise HTTPException(status_code=401, detail="⚠️ Motor IA indisponível. Configure a chave do Gemini na interface.")

    title = body.get("title", "vulnerabilidade desconhecida")
    severity = body.get("severity", "MEDIUM")
    description = body.get("description", "")
    cve_id = body.get("cve_id", "N/A")
    technology = body.get("technology", "Não especificada")
    raw_output = body.get("raw_output", "")

    prompt = f"""Você é um especialista em segurança de aplicações (AppSec) da plataforma PreviSwit.
Analise a vulnerabilidade abaixo e gere um playbook de remediação detalhado em português.

## Vulnerabilidade
- **Título**: {title}
- **Severidade**: {severity}
- **CVE**: {cve_id}
- **Tecnologia afetada**: {technology}
- **Descrição**: {description}
- **Output bruto da ferramenta**: {raw_output[:500] if raw_output else 'N/A'}

## Gere um playbook com:
1. **Resumo Executivo** (2-3 linhas para o CISO)
2. **Análise Técnica** (causa raiz e vetor de ataque)
3. **Passos de Remediação** (numerados, com comandos/código quando aplicável)
4. **Verificação** (como confirmar que a correção funcionou)
5. **Referências** (CVE, OWASP, CWE relevantes)

Seja específico, prático e direto ao ponto."""

    ai_response = _call_gemini(prompt, api_key=x_gemini_key)
    return {
        "finding_title": title,
        "severity": severity,
        "cve_id": cve_id,
        "remediation_playbook": ai_response,
        "generated_at": datetime.utcnow().isoformat(),
        "model": "gemini-2.5-flash",
    }


# ── Threat Intelligence ────────────────────────────────────────────────────────

@router.post("/threat-intel", summary="Análise de Threat Intelligence para um CVE ou finding")
def threat_intelligence(body: dict, x_gemini_key: str = Header(default=None, alias="X-Gemini-Key")):
    """
    Correlaciona um CVE ou finding com MITRE ATT&CK, OWASP Top 10 e
    tendências de exploração em campo.
    """
    if not x_gemini_key:
        raise HTTPException(status_code=401, detail="⚠️ Motor IA indisponível. Configure a chave do Gemini na interface.")

    cve_id = body.get("cve_id", "")
    title = body.get("title", "")
    description = body.get("description", "")

    prompt = f"""Você é um analista de Threat Intelligence da plataforma PreviSwit.
Analise o seguinte CVE/vulnerabilidade e forneça inteligência de ameaças detalhada.

## Vulnerabilidade
- **CVE**: {cve_id if cve_id else 'N/A'}
- **Título**: {title}
- **Descrição**: {description}

## Forneça análise estruturada em JSON com os campos:
{{
  "mitre_attack": {{
    "tactics": ["lista de táticas MITRE ATT&CK relevantes"],
    "techniques": ["lista de técnicas T-XXXX relevantes"]
  }},
  "owasp_category": "categoria OWASP Top 10 2021 (ex: A03:2021)",
  "cwe_ids": ["lista de CWE IDs relevantes"],
  "exploitation_likelihood": "LOW | MEDIUM | HIGH | CRITICAL",
  "known_exploits_in_wild": true | false,
  "threat_actors": ["grupos APT conhecidos que exploram esta vuln, se houver"],
  "business_impact": "descrição do impacto de negócio em 2-3 linhas",
  "priority_score": número de 1 a 10
}}

Responda APENAS com o JSON válido, sem texto adicional."""

    ai_response = _call_gemini(prompt, api_key=x_gemini_key)

    # Tenta parsear como JSON; se falhar, retorna como string
    try:
        intel_data = json.loads(ai_response)
    except json.JSONDecodeError:
        intel_data = {"raw_analysis": ai_response}

    return {
        "cve_id": cve_id,
        "title": title,
        "threat_intel": intel_data,
        "generated_at": datetime.utcnow().isoformat(),
    }


# ── Chat Conversacional ────────────────────────────────────────────────────────

@router.post("/chat", summary="Chat conversacional sobre postura de segurança")
def ai_chat(body: dict, x_gemini_key: str = Header(default=None, alias="X-Gemini-Key")):
    """
    Interface conversacional com o Gemini para perguntas sobre o estado
    de segurança da organização. Contexto de findings pode ser injetado.
    """
    if not x_gemini_key:
        raise HTTPException(status_code=401, detail="⚠️ Motor IA indisponível. Configure a chave do Gemini na interface.")

    user_message = body.get("message", "")
    context_findings = body.get("context_findings", [])
    conversation_history = body.get("history", [])

    if not user_message:
        raise HTTPException(status_code=400, detail="Campo 'message' é obrigatório")

    # Monta contexto de findings para o modelo
    findings_context = ""
    if context_findings:
        findings_context = "\n## Contexto atual da plataforma:\n"
        for f in context_findings[:10]:  # Limite de 10 findings no contexto
            findings_context += f"- [{f.get('severity','?')}] {f.get('title','?')}\n"

    system_prompt = f"""Você é o assistente IA da plataforma PreviSwit AI-ASPM, especializado em segurança de aplicações.
Sua função é responder perguntas sobre o posture de segurança da organização, 
vulnerabilidades, remediações e melhores práticas de AppSec.
Seja claro, técnico mas acessível, e sempre em português.
{findings_context}"""

    # Constrói histórico da conversa
    full_prompt = system_prompt + "\n\n"
    for msg in conversation_history[-10:]:  # Últimas 10 mensagens
        role = "Usuário" if msg.get("role") == "user" else "Assistente"
        full_prompt += f"{role}: {msg.get('content', '')}\n"
    full_prompt += f"Usuário: {user_message}\nAssistente:"

    ai_response = _call_gemini(full_prompt, api_key=x_gemini_key)

    return {
        "message": user_message,
        "response": ai_response,
        "role": "assistant",
        "timestamp": datetime.utcnow().isoformat(),
    }


# ── Análise de Risco por IA ────────────────────────────────────────────────────

@router.post("/risk-analysis", summary="Análise de risco global por IA")
def risk_analysis(body: dict, x_gemini_key: str = Header(default=None, alias="X-Gemini-Key")):
    """
    Analisa o conjunto de findings de um ativo e gera um score de risco
    com justificativa e recomendações prioritárias.
    """
    if not x_gemini_key:
        raise HTTPException(status_code=401, detail="⚠️ Motor IA indisponível. Configure a chave do Gemini na interface.")

    asset_name = body.get("asset_name", "ativo não identificado")
    findings = body.get("findings", [])

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if sev in counts:
            counts[sev] += 1

    prompt = f"""Você é um arquiteto de segurança da plataforma PreviSwit.
Analise o perfil de risco do ativo "{asset_name}" com os seguintes findings:
- Críticos: {counts['CRITICAL']}
- Altos: {counts['HIGH']}
- Médios: {counts['MEDIUM']}
- Baixos: {counts['LOW']}
Total: {len(findings)} vulnerabilidades

Calcule e retorne em JSON:
{{
  "risk_score": número de 0 a 100 (100 = máximo risco),
  "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
  "executive_summary": "resumo executivo em 3 linhas",
  "top_priorities": ["lista das 3 ações mais urgentes"],
  "security_posture": "descrição geral da postura de segurança"
}}

Responda APENAS com JSON válido."""

    ai_response = _call_gemini(prompt, api_key=x_gemini_key)

    try:
        risk_data = json.loads(ai_response)
    except json.JSONDecodeError:
        # Fallback: cálculo simples de score
        score = min(100, counts["CRITICAL"] * 25 + counts["HIGH"] * 10 + counts["MEDIUM"] * 3 + counts["LOW"] * 1)
        risk_data = {
            "risk_score": score,
            "risk_level": "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW",
            "executive_summary": ai_response,
        }

    return {
        "asset_name": asset_name,
        "findings_analyzed": len(findings),
        "counts": counts,
        "risk_analysis": risk_data,
        "generated_at": datetime.utcnow().isoformat(),
    }
