import json
from core.ai_offensive.ai_engine import validate_vuln

def run_test():
    print("🤖 Iniciando teste da IA Ofensiva (Llama 3.3 70B via OpenRouter)...")
    print("⏳ Aguardando resposta (Lembre-se: a API gratuita pode levar até 30s)...\n")

    # Simulando um achado crítico do scanner
    mock_vuln = {
        "scanner": "nuclei",
        "severity": "critical",
        "name": "SQL Injection in Login Panel",
        "url": "http://localhost:3000/rest/user/login",
        "matched_at": "email=admin' OR 1=1--"
    }

    # Chamando nossa função com a Armadura de resiliência
    resultado = validate_vuln(mock_vuln)

    print("✅ Resposta recebida da IA:\n")
    print(json.dumps(resultado, indent=4, ensure_ascii=False))

if __name__ == "__main__":
    run_test()