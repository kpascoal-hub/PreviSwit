import asyncio
import json
from core.scanners.nmap_runner import run_nmap
from core.scanners.nuclei_runner import run_nuclei
from core.scanners.trivy_runner import run_trivy

# Alvos de teste seguros
TARGET_IP = "scanme.nmap.org"
TARGET_URL = "http://scanme.nmap.org"
TARGET_DIR = "." # Testa os arquivos da própria pasta do seu projeto

async def main():
    print("========================================")
    print("🔍 INICIANDO O EXÉRCITO DE VARREDURA...")
    print("========================================")

    # 1. Testando Nmap (O Batedor)
    print("\n🟢 1. Disparando NMAP...")
    nmap_result = run_nmap(TARGET_IP)
    print(f"Status Nmap: {'MOCK (Falso)' if nmap_result.get('mock') else 'REAL'}")
    
    # 2. Testando Nuclei (O Sniper Web)
    print("\n🟢 2. Disparando NUCLEI...")
    nuclei_result = run_nuclei(TARGET_URL)
    print(f"Status Nuclei: {'MOCK (Falso)' if nuclei_result.get('mock') else 'REAL'}")

    # 3. Testando Trivy (O Inspecionador de Código)
    print("\n🟢 3. Disparando TRIVY...")
    trivy_result = run_trivy(TARGET_DIR)
    print(f"Status Trivy: {'MOCK (Falso)' if trivy_result.get('mock') else 'REAL'}")

    print("\n========================================")
    print("🏁 TESTE CONCLUÍDO!")
    print("========================================")

if __name__ == "__main__":
    asyncio.run(main())