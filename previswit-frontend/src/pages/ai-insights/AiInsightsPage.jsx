/*
 * PreviSwit AI-ASPM
 * Copyright (C) 2026 PreviSwit Team
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
/**
 * PreviSwit AI-ASPM — IA & Insights
 * ====================================
 * Layout em duas colunas:
 *   Esquerda (60%): Seletor de vuln + Threat Intel + Remediação (Auto-Fix)
 *   Direita  (40%): Chat Gemini (mock UI — pronto para integração real)
 *
 * Coleta vulnerabilidades dos mesmos prefixos do localStorage que a Central
 * de Findings, evitando qualquer dependência entre módulos.
 *
 * Design: Cyber Dark Enterprise (#060b13 / glass cards / neon accents).
 */

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import {
  BrainCircuit, ShieldAlert, Code2, Copy, Check,
  ChevronDown, Send, Bot, User, AlertTriangle,
  DollarSign, FileText, TrendingUp, Sparkles,
  Loader2, ChevronRight, Trash2, RefreshCw,
} from 'lucide-react';


// ── Severidade helpers ─────────────────────────────────────────────────────────

function sevStyle(sev) {
  switch (sev) {
    case 'CRITICAL': return { text: 'text-rose-400',  border: 'border-rose-500/30',  bg: 'bg-rose-500/10' };
    case 'HIGH':     return { text: 'text-red-400',   border: 'border-red-500/30',   bg: 'bg-red-500/10' };
    case 'MEDIUM':   return { text: 'text-amber-400', border: 'border-amber-500/30', bg: 'bg-amber-500/10' };
    default:         return { text: 'text-blue-400',  border: 'border-blue-500/30',  bg: 'bg-blue-500/10' };
  }
}

// ── Mocked Threat Intel data (estrutura pronta para substituir por API) ────────

function buildThreatIntel(vuln) {
  if (!vuln) return null;
  const sev = vuln.severity;
  return {
    financialImpact: sev === 'CRITICAL' ? 'R$ 2M – R$ 15M (estimativa de breach + LGPD)'
                   : sev === 'HIGH'     ? 'R$ 200K – R$ 2M (vazamento de dados + multas)'
                   :                      'R$ 10K – R$ 200K (incidentes operacionais)',
    standards: sev === 'CRITICAL'       ? ['ISO 27001 – A.12.6', 'SOC 2 – CC7.1', 'LGPD – Art. 46', 'PCI DSS – 6.3']
             : sev === 'HIGH'           ? ['ISO 27001 – A.14.2', 'SOC 2 – CC6.1', 'LGPD – Art. 48']
             :                           ['ISO 27001 – A.12.2', 'SOC 2 – CC7.2'],
    businessRisk:    sev === 'CRITICAL' ? 'Risco CATASTRÓFICO — Exploração ativa documentada. Probabilidade de breach: 87%. Requer remediação imediata (< 24h).'
                   : sev === 'HIGH'     ? 'Risco ALTO — Vetor de exploração conhecido. Probabilidade de comprometimento: 60%. Janela de remediação: 7 dias.'
                   :                      'Risco MODERADO — Exploração requer condições específicas. Janela de remediação: 30 dias.',
    attackVectors:   sev === 'CRITICAL' ? ['RCE Remota', 'Privilege Escalation', 'Data Exfiltration']
                   : sev === 'HIGH'     ? ['Injection', 'Auth Bypass', 'SSRF']
                   :                     ['Information Disclosure', 'DoS Parcial'],
  };
}

function buildPatch(vuln) {
  if (!vuln) return '';
  if (vuln.source === 'SAST' || vuln.source === 'Code') {
    return `# Patch sugerido — ${vuln.title}
# Origem: ${vuln.source} | Alvo: ${vuln.target}
# NOTA: Revise e adapte ao seu contexto antes de aplicar.

# ❌ Código vulnerável (exemplo):
# query = "SELECT * FROM users WHERE id=" + user_input

# ✅ Código corrigido (parameterizado):
import sqlite3

def get_user(user_id: str) -> dict:
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    # Use sempre placeholders (?) — nunca concatene strings
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

# Validação adicional recomendada:
from pydantic import BaseModel, validator

class UserQuery(BaseModel):
    user_id: str

    @validator("user_id")
    def must_be_numeric(cls, v):
        if not v.isdigit():
            raise ValueError("ID inválido")
        return v`;
  }
  if (vuln.source === 'Container') {
    return `# Patch sugerido — ${vuln.title}
# Origem: ${vuln.source} | Alvo: ${vuln.target}

# ❌ Imagem com vulnerabilidade conhecida:
# FROM ubuntu:20.04   (CVE conhecidas não patchadas)

# ✅ Imagem atualizada e hardened:
FROM ubuntu:22.04

# Atualiza pacotes e remove cache
RUN apt-get update && apt-get upgrade -y \\
    && apt-get install -y --no-install-recommends \\
       ca-certificates curl \\
    && rm -rf /var/lib/apt/lists/*

# Execute como usuário não-root
RUN useradd -m -u 1000 appuser
USER appuser

WORKDIR /app
COPY --chown=appuser:appuser . .`;
  }
  return `# Remediação recomendada — ${vuln.title}
# Origem: ${vuln.source} | Alvo: ${vuln.target}
# CVE: ${vuln.cve || 'N/A'}
#
# 1. Atualize a dependência para a versão patchada:
#    pip install --upgrade <pacote>  (ou npm update / apt upgrade)
#
# 2. Adicione validação de entrada:
#    - Sanitize todos os parâmetros recebidos via API.
#    - Implemente rate-limiting e WAF rules.
#
# 3. Implemente monitoramento:
#    - Alertas para tentativas de exploração no SIEM.
#    - Revisão trimestral dos controles.
#
# Referência: ${vuln.cve ? 'https://nvd.nist.gov/vuln/detail/' + vuln.cve : 'Consulte a documentação da ferramenta'}`;
}



// ── Componente: Threat Intel Card ─────────────────────────────────────────────

function ThreatIntelCard({ intel }) {
  if (!intel) return null;
  return (
    <div className="flex flex-col gap-4">
      {/* Impacto Financeiro */}
      <div className="flex items-start gap-3 p-4 rounded-xl bg-rose-500/5 border border-rose-500/15">
        <div className="w-8 h-8 rounded-lg bg-rose-500/15 flex items-center justify-center shrink-0 mt-0.5">
          <DollarSign className="w-4 h-4 text-rose-400" />
        </div>
        <div>
          <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold mb-1">Impacto Financeiro Estimado</p>
          <p className="text-sm text-rose-300 font-semibold leading-relaxed">{intel.financialImpact}</p>
        </div>
      </div>

      {/* Normas Afetadas */}
      <div className="flex items-start gap-3 p-4 rounded-xl bg-amber-500/5 border border-amber-500/15">
        <div className="w-8 h-8 rounded-lg bg-amber-500/15 flex items-center justify-center shrink-0 mt-0.5">
          <FileText className="w-4 h-4 text-amber-400" />
        </div>
        <div className="flex-1">
          <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold mb-2">Normas Afetadas</p>
          <div className="flex flex-wrap gap-1.5">
            {intel.standards.map(s => (
              <span key={s} className="text-[10px] px-2 py-1 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 font-mono font-bold">{s}</span>
            ))}
          </div>
        </div>
      </div>

      {/* Risco de Negócio */}
      <div className="flex items-start gap-3 p-4 rounded-xl bg-purple-500/5 border border-purple-500/15">
        <div className="w-8 h-8 rounded-lg bg-purple-500/15 flex items-center justify-center shrink-0 mt-0.5">
          <TrendingUp className="w-4 h-4 text-purple-400" />
        </div>
        <div>
          <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold mb-1">Risco de Negócio</p>
          <p className="text-sm text-purple-300 leading-relaxed">{intel.businessRisk}</p>
        </div>
      </div>

      {/* Vetores de Ataque */}
      <div className="flex items-start gap-3 p-4 rounded-xl bg-white/[0.03] border border-white/[0.06]">
        <div className="w-8 h-8 rounded-lg bg-white/[0.06] flex items-center justify-center shrink-0 mt-0.5">
          <AlertTriangle className="w-4 h-4 text-gray-400" />
        </div>
        <div>
          <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold mb-2">Vetores de Ataque Documentados</p>
          <div className="flex flex-wrap gap-1.5">
            {intel.attackVectors.map(v => (
              <span key={v} className="text-[10px] px-2 py-1 rounded-lg bg-white/[0.04] border border-white/[0.08] text-gray-300 font-semibold">{v}</span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Componente: Patch Code Block ──────────────────────────────────────────────

function PatchBlock({ code }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="rounded-xl border border-white/[0.08] overflow-hidden">
      {/* Code editor topbar */}
      <div className="flex items-center justify-between px-4 py-2 bg-[#030710]/90 border-b border-white/[0.05]">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500/60" />
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/60" />
          </div>
          <Code2 className="w-3 h-3 text-gray-600" />
          <span className="text-[10px] text-gray-500 font-mono">auto-fix.patch</span>
        </div>
        <button
          onClick={handleCopy}
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10px] font-bold transition-all
                      ${copied
                        ? 'bg-emerald-500/15 border border-emerald-500/30 text-emerald-400'
                        : 'bg-white/[0.04] border border-white/[0.08] text-gray-400 hover:text-white hover:bg-white/[0.08]'}`}
        >
          {copied ? <><Check className="w-3 h-3" /> Copiado!</> : <><Copy className="w-3 h-3" /> Copiar Código</>}
        </button>
      </div>
      <pre className="p-4 text-[11px] font-mono text-gray-300 bg-[#060b13] overflow-x-auto leading-relaxed whitespace-pre max-h-72 overflow-y-auto">
        {code}
      </pre>
    </div>
  );
}

// ── Componente: MarkdownText ──────────────────────────────────────────────────

function parseInline(line) {
  const parts = [];
  const regex = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0, m;
  while ((m = regex.exec(line)) !== null) {
    if (m.index > last) parts.push(line.slice(last, m.index));
    const token = m[0];
    if (token.startsWith('**')) {
      parts.push(<strong key={m.index} className="font-bold text-white">{token.slice(2, -2)}</strong>);
    } else {
      parts.push(<code key={m.index} className="px-1 py-0.5 rounded bg-white/[0.08] font-mono text-[10px] text-cyan-300">{token.slice(1, -1)}</code>);
    }
    last = m.index + token.length;
  }
  if (last < line.length) parts.push(line.slice(last));
  return parts.length > 1 ? parts : line;
}

function MarkdownText({ text }) {
  if (!text) return null;
  const lines = text.split('\n');
  const elements = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.startsWith('```')) {
      const lang = line.slice(3).trim();
      const codeLines = [];
      i++;
      while (i < lines.length && !lines[i].startsWith('```')) { codeLines.push(lines[i]); i++; }
      elements.push(
        <div key={`cb-${i}`} className="my-2 rounded-lg overflow-hidden border border-white/[0.08]">
          {lang && <div className="px-3 py-1 text-[9px] font-mono text-gray-500 bg-[#030710]/80 border-b border-white/[0.05]">{lang}</div>}
          <pre className="p-3 text-[10px] font-mono text-gray-300 bg-[#060b13] overflow-x-auto whitespace-pre">{codeLines.join('\n')}</pre>
        </div>
      );
      i++; continue;
    }
    if (/^---+$/.test(line.trim())) {
      elements.push(<hr key={i} className="border-white/[0.06] my-2" />);
      i++; continue;
    }
    if (/^#{1,3} /.test(line)) {
      const lvl = line.match(/^(#+)/)[1].length;
      const content = line.replace(/^#+\s*/, '');
      const cls = lvl === 1 ? 'text-sm font-bold text-white mt-2 mb-0.5' : lvl === 2 ? 'text-xs font-bold text-white mt-2 mb-0.5' : 'text-[11px] font-semibold text-gray-300 mt-1.5';
      elements.push(<p key={i} className={cls}>{parseInline(content)}</p>);
      i++; continue;
    }
    if (line.trim() === '') {
      elements.push(<div key={i} className="h-1.5" />);
      i++; continue;
    }
    const bulletMatch = line.match(/^[-*] (.+)/);
    const numMatch = line.match(/^\d+\. (.+)/);
    if (bulletMatch) {
      elements.push(<div key={i} className="flex gap-1.5 text-xs text-gray-300"><span className="text-gray-600 shrink-0">•</span><span>{parseInline(bulletMatch[1])}</span></div>);
      i++; continue;
    }
    if (numMatch) {
      const num = line.match(/^(\d+)\./)[1];
      elements.push(<div key={i} className="flex gap-1.5 text-xs text-gray-300"><span className="text-gray-600 shrink-0 w-4">{num}.</span><span>{parseInline(numMatch[1])}</span></div>);
      i++; continue;
    }
    elements.push(<p key={i} className="text-xs leading-relaxed text-gray-300">{parseInline(line)}</p>);
    i++;
  }
  return <div className="space-y-0.5">{elements}</div>;
}

// ── Componente: Chat Bubble ───────────────────────────────────────────────────

function ChatBubble({ msg }) {
  const isUser = msg.role === 'user';
  return (
    <div className={`flex items-end gap-2 ${isUser ? 'flex-row-reverse' : 'flex-row'}`}>
      {/* Avatar */}
      <div className={`w-6 h-6 rounded-full flex items-center justify-center shrink-0 mb-0.5
                       ${isUser ? 'bg-blue-600/30 border border-blue-500/30' : 'bg-purple-600/30 border border-purple-500/30'}`}>
        {isUser
          ? <User className="w-3 h-3 text-blue-400" />
          : <Bot  className="w-3 h-3 text-purple-400" />
        }
      </div>
      {/* Bubble */}
      <div className={`max-w-[80%] px-3.5 py-2.5 rounded-2xl text-xs leading-relaxed
                       ${isUser
                         ? 'bg-blue-600/20 border border-blue-500/20 text-blue-100 rounded-br-sm'
                         : 'bg-white/[0.05] border border-white/[0.08] text-gray-200 rounded-bl-sm'}`}>
        {isUser ? msg.content : <MarkdownText text={msg.content} />}
        <p className={`text-[9px] mt-1 ${isUser ? 'text-blue-400/60 text-right' : 'text-gray-600'}`}>
          {msg.time}
        </p>
      </div>
    </div>
  );
}

// ── Componente Principal ──────────────────────────────────────────────────────

export default function AiInsightsPage() {
  const [vulns,        setVulns]        = useState([]);
  const [selectedId,   setSelectedId]   = useState('');
  const [messages,     setMessages]     = useState([
    {
      id: 0, role: 'ai',
      content: 'Olá! Sou o Copiloto de Segurança do PreviSwit. Selecione uma vulnerabilidade na coluna ao lado para análise contextualizada, ou me faça qualquer pergunta sobre o risco da sua aplicação.',
      time: new Date().toLocaleTimeString('pt-BR', { hour12: false }),
    }
  ]);
  const [input,        setInput]        = useState('');
  const [isTyping,     setIsTyping]     = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const messagesEndRef = useRef(null);
  const inputRef       = useRef(null);

  const fetchVulns = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const res = await fetch('/api/v1/findings/?page_size=500');
      if (!res.ok) return;
      const json = await res.json();
      const list = (json.findings || []).map(f => ({
        id:          f.id,
        title:       f.title || '—',
        severity:    f.severity || 'LOW',
        source:      f.tags?.[0] || f.tool || 'Agent',
        target:      f.asset_id || f.endpoint || '—',
        description: f.description || '',
        cve:         f.cve_id || '',
        endpoint:    f.endpoint || '',
      }));
      setVulns(list);
      setSelectedId(prev => {
        if (prev && list.find(v => v.id === prev)) return prev;
        return list.length > 0 ? list[0].id : '';
      });
    } catch (_) {}
    finally { setIsRefreshing(false); }
  }, []);

  useEffect(() => { fetchVulns(); }, [fetchVulns]);

  // Auto-scroll do chat
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  // Vuln selecionada
  const selected = useMemo(() => vulns.find(v => v.id === selectedId) || null, [vulns, selectedId]);
  const intel     = useMemo(() => buildThreatIntel(selected), [selected]);
  const patchCode = useMemo(() => selected ? buildPatch(selected) : '', [selected]);
  const sC        = selected ? sevStyle(selected.severity) : null;

  // Envia mensagem no chat (Real API Call)
  const handleSend = useCallback(async () => {
    const text = input.trim();
    if (!text) return;

    const time = new Date().toLocaleTimeString('pt-BR', { hour12: false });
    const userMsg = { id: Date.now(), role: 'user', content: text, time };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setIsTyping(true);

    try {
      const geminiKey = sessionStorage.getItem('gemini_api_key') || localStorage.getItem('previswit_gemini_key') || '';

      const res = await fetch('/api/v1/ai/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Gemini-Key': geminiKey
        },
        body: JSON.stringify({
          session_id: `ai_insights_${selectedId || 'general'}`,
          message: text,
          context: selected
            ? `Vulnerabilidade: ${selected.title} (${selected.severity})\nAlvo: ${selected.target}\nDescrição: ${selected.description}`
            : '',
        })
      });

      if (!res.ok) {
        let errStr = 'Erro na comunicação com a API Gemini.';
        try { const errData = await res.json(); errStr = errData.detail || errStr; } catch(e){}
        throw new Error(errStr);
      }

      const data = await res.json();
      const aiMsg = { 
        id: Date.now() + 1, 
        role: 'ai', 
        content: data.response || 'Sem resposta do modelo.', 
        time: new Date().toLocaleTimeString('pt-BR', { hour12: false }) 
      };
      setMessages(prev => [...prev, aiMsg]);
    } catch (err) {
      const errMsg = { 
        id: Date.now() + 1, 
        role: 'ai', 
        content: `⚠️ Falha: ${err.message}`, 
        time: new Date().toLocaleTimeString('pt-BR', { hour12: false }) 
      };
      setMessages(prev => [...prev, errMsg]);
    } finally {
      setIsTyping(false);
    }
  }, [input, selected, selectedId]);

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend(); }
  };

  const handleSelectVuln = (id) => {
    setSelectedId(id);
    const vuln = vulns.find(v => v.id === id);
    if (!vuln) return;
    const time = new Date().toLocaleTimeString('pt-BR', { hour12: false });
    setMessages(prev => [
      ...prev,
      { id: Date.now(), role: 'ai', time,
        content: `Carregando análise de Threat Intel para: "${vuln.title}" (${vuln.severity} · ${vuln.source}). Verifique os cards ao lado para impacto financeiro, normas afetadas e o patch de remediação automático.` }
    ]);
  };

  const handleClearChat = () => {
    setMessages([{
      id: 0, role: 'ai',
      content: 'Olá! Sou o Copiloto de Segurança do PreviSwit. Selecione uma vulnerabilidade na coluna ao lado para análise contextualizada, ou me faça qualquer pergunta sobre o risco da sua aplicação.',
      time: new Date().toLocaleTimeString('pt-BR', { hour12: false }),
    }]);
  };

  return (
    <div className="flex flex-col gap-5 w-full">

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
            <BrainCircuit className="w-5 h-5 text-purple-400" />
            IA & Insights
          </h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Threat Intel · Remediação guiada · Copiloto de Segurança Gemini
          </p>
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-purple-500/20 bg-purple-500/10">
          <Sparkles className="w-3.5 h-3.5 text-purple-400" />
          <span className="text-[10px] text-purple-400 font-bold">Gemini AI</span>
        </div>
      </div>

      {/* ── Two-column layout ────────────────────────────────────────────── */}
      <div className="flex flex-col lg:flex-row gap-5 min-h-[700px]">

        {/* ═══════════════════════════════════════════════
            COLUNA ESQUERDA — Threat Intel + Remediação
            ═══════════════════════════════════════════════ */}
        <div className="flex flex-col gap-5 lg:w-[60%]">

          {/* Seletor de Vulnerabilidade */}
          <div className="rounded-2xl border border-white/[0.06] bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/60 p-5">
            <div className="flex items-center justify-between mb-3">
              <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold">
                Selecionar Vulnerabilidade para Análise
              </p>
              <button
                onClick={fetchVulns}
                disabled={isRefreshing}
                title="Atualizar dados"
                className="flex items-center gap-1 px-2 py-1 rounded-lg bg-white/[0.04] border border-white/[0.08] text-gray-500 hover:text-gray-300 hover:bg-white/[0.08] disabled:opacity-40 transition-all text-[9px]"
              >
                <RefreshCw className={`w-3 h-3 ${isRefreshing ? 'animate-spin' : ''}`} />
                Atualizar
              </button>
            </div>

            {vulns.length === 0 ? (
              <div className="flex items-center gap-3 p-4 rounded-xl bg-white/[0.02] border border-dashed border-white/[0.06]">
                <ShieldAlert className="w-4 h-4 text-gray-600 shrink-0" />
                <p className="text-xs text-gray-600">
                  Nenhum laudo no cache. Execute scans nas abas SAST, Cloud, Containers ou Pentest.
                </p>
              </div>
            ) : (
              <div className="relative">
                <select
                  value={selectedId}
                  onChange={e => handleSelectVuln(e.target.value)}
                  className="w-full appearance-none bg-[#111827] border border-white/[0.08] rounded-xl px-4 py-3 text-sm text-white
                             focus:outline-none focus:border-purple-500/40 focus:ring-1 focus:ring-purple-500/20
                             transition-all pr-10"
                >
                  {vulns.map(v => (
                    <option key={v.id} value={v.id}>
                      [{v.severity}] {v.title} — {v.target}
                    </option>
                  ))}
                </select>
                <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500 pointer-events-none" />
              </div>
            )}

            {/* Badge da vuln selecionada */}
            {selected && (
              <div className={`mt-3 flex items-center gap-3 px-3 py-2 rounded-xl border ${sC.bg} ${sC.border}`}>
                <span className={`text-[10px] font-bold ${sC.text} uppercase`}>{selected.severity}</span>
                <span className="text-gray-600">·</span>
                <span className="text-[10px] text-gray-400 truncate">{selected.title}</span>
                {selected.cve && <span className="text-[9px] font-mono text-cyan-500 shrink-0">{selected.cve}</span>}
              </div>
            )}
          </div>

          {/* Threat Intel Card */}
          <div className="rounded-2xl border border-white/[0.06] bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/60 overflow-hidden">
            <div className="flex items-center gap-2 px-5 py-3.5 border-b border-white/[0.05] bg-[#030710]/60">
              <TrendingUp className="w-4 h-4 text-rose-400" />
              <span className="text-sm font-bold text-white">Threat Intelligence</span>
              <span className="ml-auto text-[10px] text-gray-600">Tradução de Risco de Negócios</span>
            </div>
            <div className="p-5">
              {intel
                ? <ThreatIntelCard intel={intel} />
                : (
                  <div className="flex flex-col items-center justify-center py-10 gap-3">
                    <ShieldAlert className="w-8 h-8 text-gray-700" />
                    <p className="text-xs text-gray-600 text-center">Selecione uma vulnerabilidade acima para gerar o relatório de Threat Intel.</p>
                  </div>
                )
              }
            </div>
          </div>

          {/* Auto-Fix Patch */}
          <div className="rounded-2xl border border-white/[0.06] bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/60 overflow-hidden">
            <div className="flex items-center gap-2 px-5 py-3.5 border-b border-white/[0.05] bg-[#030710]/60">
              <Code2 className="w-4 h-4 text-emerald-400" />
              <span className="text-sm font-bold text-white">Remediação — Auto-Fix</span>
              <span className="ml-auto text-[10px] text-gray-600">Patch gerado por IA</span>
            </div>
            <div className="p-5">
              {patchCode
                ? <PatchBlock code={patchCode} />
                : (
                  <div className="flex flex-col items-center justify-center py-10 gap-3">
                    <Code2 className="w-8 h-8 text-gray-700" />
                    <p className="text-xs text-gray-600 text-center">Selecione uma vulnerabilidade para gerar o patch de remediação.</p>
                  </div>
                )
              }
            </div>
          </div>

        </div>

        {/* ═══════════════════════════════════════════════
            COLUNA DIREITA — Chat Gemini
            ═══════════════════════════════════════════════ */}
        <div className="flex flex-col lg:w-[40%] rounded-2xl border border-purple-500/15 bg-gradient-to-b from-[#0d1421]/90 to-[#060b13]/80 overflow-hidden h-[700px]">

          {/* Chat header */}
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-purple-500/10 bg-[#030710]/70 shrink-0">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-xl bg-purple-600/20 border border-purple-500/30 flex items-center justify-center">
                <Bot className="w-4 h-4 text-purple-400" />
              </div>
              <div>
                <p className="text-sm font-bold text-white">Copiloto de Segurança</p>
                <div className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-[10px] text-emerald-400">Gemini AI · Online</span>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1 px-2 py-1 rounded-lg bg-purple-500/10 border border-purple-500/15">
                <Sparkles className="w-3 h-3 text-purple-400" />
                <span className="text-[10px] text-purple-400 font-bold">Pro</span>
              </div>
              <button
                onClick={handleClearChat}
                title="Limpar Conversa"
                className="w-7 h-7 rounded-lg bg-white/[0.04] border border-white/[0.08] flex items-center justify-center text-gray-500 hover:text-rose-400 hover:bg-rose-500/10 hover:border-rose-500/20 transition-all"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Messages area */}
          <div className="flex-1 overflow-y-auto min-h-0 p-4 space-y-4">
            {messages.map(msg => <ChatBubble key={msg.id} msg={msg} />)}

            {/* Typing indicator */}
            {isTyping && (
              <div className="flex items-end gap-2">
                <div className="w-6 h-6 rounded-full bg-purple-600/30 border border-purple-500/30 flex items-center justify-center shrink-0 mb-0.5">
                  <Bot className="w-3 h-3 text-purple-400" />
                </div>
                <div className="px-3.5 py-2.5 rounded-2xl rounded-bl-sm bg-white/[0.05] border border-white/[0.08]">
                  <Loader2 className="w-4 h-4 text-purple-400 animate-spin" />
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Input area */}
          <div className="shrink-0 p-4 border-t border-purple-500/10 bg-[#030710]/50">
            {/* Quick prompts */}
            <div className="flex flex-wrap gap-1.5 mb-3">
              {[
                'Qual o impacto desta vuln?',
                'Como priorizar a remediação?',
                'Explique o risco para o negócio',
              ].map(q => (
                <button
                  key={q}
                  onClick={() => { setInput(q); inputRef.current?.focus(); }}
                  className="text-[9px] px-2 py-1 rounded-full bg-white/[0.03] border border-white/[0.06] text-gray-500 hover:text-gray-300 hover:border-white/[0.12] transition-all"
                >
                  {q}
                </button>
              ))}
            </div>

            <div className="flex items-end gap-2">
              <textarea
                ref={inputRef}
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                rows={1}
                placeholder="Pergunte sobre vulnerabilidades, compliance, remediação..."
                className="flex-1 bg-[#111827] border border-white/[0.08] rounded-xl px-4 py-3 text-sm text-white
                           placeholder:text-gray-600 focus:outline-none focus:border-purple-500/40
                           focus:ring-1 focus:ring-purple-500/20 transition-all resize-none max-h-32"
                style={{ overflowY: 'auto' }}
              />
              <button
                onClick={handleSend}
                disabled={!input.trim() || isTyping}
                className="w-10 h-10 rounded-xl bg-purple-600 hover:bg-purple-500 disabled:bg-gray-800 disabled:opacity-50
                           flex items-center justify-center transition-all shadow-lg shadow-purple-500/20 shrink-0"
              >
                {isTyping
                  ? <Loader2 className="w-4 h-4 text-white animate-spin" />
                  : <Send className="w-4 h-4 text-white" />
                }
              </button>
            </div>
            <p className="text-[9px] text-gray-700 mt-2 text-center">
              Enter para enviar · Shift+Enter para nova linha
            </p>
          </div>
        </div>

      </div>
    </div>
  );
}
