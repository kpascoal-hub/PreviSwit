
# 🛡️ PreviSwit
### AI-Powered ASPM

![Python](https://img.shields.io/badge/Python-3.10%2B-orange?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-red?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-1.0-blue?style=for-the-badge)

**Framework de pentest automatizado com IA integrada, 3 pipelines independentes e relatório profissional.**  
Desenvolvido por **PreviSwit Team** — Engenharia de Software & Cybersecurity.

> ⚠️ **USO EXCLUSIVO EM ALVOS COM AUTORIZAÇÃO ESCRITA,**
> **QUAISQUER ATAQUES REALIZADOS SEM O CONSENTIMENTO PRÉVIO DO PROPRIETÁRIO DO SISTEMA SÃO ILEGAIS E SUJEITOS ÀS PENALIDADES DA LEI**


---

## Preview

  
```
                                          _
                                        ª$$$a_
                                  .  u%   V$$$Ru:,_ 
                             ,´º$$" i$$i   T$$$$$$$$$UU}      
                             |u, T_4$$$$   B$$$$$$$$$$$|      
                             !$$, ª$$$$'   A$$$$$$$$$$$!  
                             :$$! a,¨7¨  .s$$$$$$$$$$$$;
                             º$$' $P"   j$$$$$$$$$$$$$$'
                              5" .uUl,  '$$$$$?j$$$$$$7
                               g !$$$$;   $$" a$$$$$$$"
                               " l$$$$$      4$$$$$$$j
                                 __ ¨¨ª    .4$$$$$$$P
                                 $$$l"    a$$$$$$$$$'
                                 ¨P" 8  ,_¨ª$$$$$$$'
                                       s$$$$nY$$$" 
                                      $$$$$$${ ª¨
                                       ¨$$$$$"
                                         ¨^¨
                                                
 ooooooooo.                                  o8o   .M"""bgd                  db   mm     
`$$$   `Y$$.                                 º"º  ,MI    "Y                  ¨¨   MM    
 $$$   .d$$$' oooo d8b  .ooooo.  oooo    ooo oooo  `MMb.  `7M'    ,A    `MF'`7MM mmMMmm  
 $$$ooo$$P'  `$$$""8P d$$' `$$b  `$$.  .8'  `$$$    `YMMNq.VA   ,VAA   ,V    MM   MM     
 $$$          $$$     $$$ooo$$$   `$$..8'    $$$  .     `MM VA ,V  VA ,V     MM   MM   
 $$$          $$$     $$$    .o    `$$$'     $$$  Mb     dM  VVV    VVV      MM   MM   
o$$$o        d$$$b    `Y8bod8P'     `8'     o$$$o P"Ybmmd"    W      W     .JMML. `Mbmo   
      
   ┌────────────────────────────────────────────────────────────────────────────────┐
   │   # PreviSwit v1.0 - ASPM and AI-powered security management tools             │ 
   │   # Developed by: PreviSwit Team                                               │                      
   └────────────────────────────────────────────────────────────────────────────────┘
    
```

---

## O que é?

O **PreviSwit** é um framework de pentest automatizado construído do zero em Python, com foco em:

- **Cobertura ampla** — do recon passivo até exploração de vulnerabilidades
- **IA integrada** — priorização inteligente, memória histórica e insights automáticos
- **Relatório profissional** — PDF com gráficos, CVSS scores e dashboard HTML interativo
- **Arquitetura modular** — plugins extensíveis, 3 pipelines independentes
- **Sem dependência de licença** — 100% open source, sem pagar Burp Pro

---

## 🏗️ Arquitetura — 3 Pipelines

```
main.py
 │
 ├── P1 — RECON PASSIVO (OSINT)
 │     WHOIS · DNS · Shodan · InternetDB · VirusTotal · Google Dorks
 │
 ├── P2 — RECON ATIVO (INFRA)
 │     Nmap Stealth Scan · Enumeração de Subdomínios · SSL/TLS Analyzer
 │
 ├── P3 — SCANNER WEB & API
 │     WAF Fingerprint · JWT (alg:none/secrets) · GraphQL Introspection
 │     IDOR Tester · Clickjacking · Rate Limit · Security Headers
 │
 ├── P4 — AGRESSIVO (CRAWLER)
 │     Deep Crawler · JS Endpoint Extraction · Sensitive Paths · Sitemap
 │
 ├── P5 — ATTACK ENGINE (DAST)
 │     Validação de XSS/SQLi · Path Traversal Real · Auth Attacker
 │
 ├── P6 — AI LOGIC ENGINE
 │     Risk Engine (Severidade) · Learning Engine (JSON Persistence)
 │
 └── P7 — GEMINI OVERWATCH
       Master Correlation · Redução de Falsos Positivos · Business Insights
```

---

## 🔧 Módulos

| Módulo | O que faz |
|--------|-----------|
| `recon/recon.py` | WHOIS, DNS (A/MX/NS/TXT), SSL, Google Dorks |
| `recon/active.py` | Nmap `-sV`, Gobuster dir brute, análise de cookies |
| `recon/subdomain_enum.py` | DNS brute + crt.sh (Certificate Transparency) + Takeover check |
| `scanner/waf_detector.py` | Fingerprinting de 8 WAFs + hints de bypass |
| `scanner/ssl_analyzer.py` | Protocolos fracos, ciphers inseguros, cert expirado |
| `scanner/jwt_analyzer.py` | `alg:none`, segredo fraco (wordlist), sem expiração, claims admin |
| `scanner/graphql_tester.py` | Introspection exposta, queries sem auth, DoS por nested query |
| `scanner/idor_tester.py` | Extrai endpoints com IDs do crawl, testa acesso cruzado |
| `scanner/api_fuzzer.py` | Endpoints em JS minificado, verb tampering, APIs expostas |
| `scanner/osint_enricher.py` | Shodan, InternetDB (sem key), urlscan.io, VirusTotal |
| `scanner/rate_limit_tester.py` | Endpoints de login sem proteção contra força bruta |
| `scanner/clickjacking.py` | X-Frame-Options + CSP frame-ancestors |
| `aggressive/crawler.py` | Crawler com robots.txt, sitemap.xml, JS files, forms |
| `aggressive/aggressive_engine.py` | Path traversal, paths sensíveis, extração de endpoints JS |
| `ai/ai_engine.py` | Secret scanner, XSS/SQLi/SSRF, priorização, insights |
| `ai/risk_engine.py` | Score multi-critério por severidade + palavras-chave |
| `ai/learning_engine.py` | Memória histórica persistida em JSON entre sessões |
| `plugins/` | Headers check, cookie flags, CSP — extensível |
| `reports/report.py` | PDF profissional (ReportLab) + Dashboard HTML (Chart.js) |
| `api/api.py` | API REST via FastAPI para integração externa |

---

## 🚀 Instalação

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/PreviSwit.git
cd PreviSwit

# Instale as dependências
pip install -r requirements.txt

# Dependências externas (opcionais mas recomendadas)
# Nmap:     https://nmap.org/download.html
# Gobuster: https://github.com/OJ/gobuster/releases
```

---

## ⚙️ Uso

```bash
# Scan completo — todos os pipelines
python main.py http://target.com

# Apenas pipeline 1 (recon tradicional)
python main.py http://target.com --pipeline 1

# Apenas pipeline 2 (agressivo)
python main.py http://target.com --pipeline 2

# Apenas pipeline 3 (IA)
python main.py http://target.com --pipeline 3

# Com API keys para OSINT enriquecido
python main.py http://target.com --shodan SUA_KEY --vt SUA_KEY

# Sem pipeline agressivo (recon + IA apenas)
python main.py http://target.com --no-aggressive
```

---

## 📊 Outputs

Todos os relatórios são salvos em `reports/`:

| Arquivo | Descrição |
|---------|-----------|
| `<target>_report.pdf` | Relatório técnico profissional com gráfico de severidade, score de segurança, CVSS por finding, impacto e recomendações |
| `<target>_dashboard.html` | Dashboard interativo com Chart.js, filtros por severidade, tabela de findings, secrets, CVEs e stack tecnológico |
| `<target>_report.json` | Dados completos em JSON para integração com outras ferramentas |
| `data/results.db` | Histórico de findings em SQLite |
| `data/ai_memory.json` | Memória da IA — aprende com cada scan |

---

## 🧩 Criando Plugins

Crie um arquivo em `modules/plugins/` herdando `BasePlugin`:

```python
from modules.plugins.base_plugin import BasePlugin

class MeuPlugin(BasePlugin):
    name     = "meu_plugin"
    severity = "MEDIUM"

    def run(self, url: str, response) -> dict | None:
        if "algo_suspeito" in response.text:
            return {
                "url":      url,
                "issue":    "Algo suspeito encontrado",
                "severity": self.severity,
                "source":   f"Plugin:{self.name}",
            }
```

O loader detecta automaticamente. Sem configuração extra.

---

## 🔑 API Keys (opcionais)

| Serviço | Sem key | Com key |
|---------|---------|---------|
| Shodan | InternetDB público (ports + CVEs básico) | Full host info, vulns, banners |
| VirusTotal | urlscan.io (reputação básica) | Análise completa de 70+ engines |

---

## 📦 Dependências principais

```
requests · beautifulsoup4 · lxml · dnspython
python-whois · python-nmap · googlesearch-python
colorama · reportlab · fastapi · uvicorn
```

---

## ⚠️ Aviso Legal

Este projeto foi desenvolvido para fins educacionais e uso em ambientes autorizados.  
**Utilizar esta ferramenta em alvos sem autorização escrita é crime** (Lei 12.737/2012 — Brasil).  
O autor não se responsabiliza pelo uso indevido.

---

## 👤 Autor

**PreviSwit Team**  
Engenharia de Software · Cybersecurity  

---

<div align="center">
  <sub>Se essa ferramenta te ajudou, deixa uma ⭐ no repositório.</sub>
</div>
