# PreviSwit ASPM Parsers
# Módulo de parsers para ferramentas SAST, Secrets e IaC
from .semgrep_parser import parse_semgrep
from .gitleaks_parser import parse_gitleaks
from .checkov_parser import parse_checkov

__all__ = ["parse_semgrep", "parse_gitleaks", "parse_checkov"]
