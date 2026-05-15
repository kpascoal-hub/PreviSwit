import sys
from colorama import Fore, Style, init
init()

# Força UTF-8 no terminal do Windows para suportar emojis e caracteres especiais
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

def show_banner():
    try:
        print(f"""{Fore.CYAN}
        
{Fore.RED}
        [*] PREVISWIT  v3.0  --  AI-Powered Pentest Framework
{Fore.WHITE}        Pipeline: Tradicional  |  Agressivo  |  IA
        Autor  : PreviSwit  |  Uso exclusivo em alvos autorizados
{Style.RESET_ALL}""")
    except UnicodeEncodeError:
        print("=== PREVISWIT v3.0 — AI-Powered Pentest Framework ===")
