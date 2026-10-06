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
"""Smoke tests para os parsers ASPM do PreviSwit."""
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from semgrep_parser import parse_semgrep
from gitleaks_parser import parse_gitleaks
from checkov_parser import parse_checkov


async def main():
    # ── Semgrep SAST ──────────────────────────────────────────────────────
    semgrep_sast = {
        "results": [{
            "check_id": "python.lang.security.audit.hardcoded-password",
            "path": "src/app.py",
            "start": {"line": 42},
            "extra": {
                "severity": "ERROR",
                "message": "Hardcoded password detected.",
                "lines": "password = 's3cr3t'",
                "metadata": {
                    "cwe": ["CWE-259: Use of Hard-coded Password"],
                    "references": ["https://cwe.mitre.org/data/definitions/259.html"]
                },
                "fingerprint": "abc123def456"
            }
        }]
    }

    findings = await parse_semgrep(semgrep_sast)
    assert len(findings) == 1, f"Semgrep esperava 1, obteve {len(findings)}"
    f = findings[0]
    assert f["cwe"] == 259, f"CWE esperado 259, obteve {f['cwe']}"
    assert f["severity"] == "High", f"Severidade esperada High, obteve {f['severity']}"
    assert f["tool"] == "semgrep"
    print(f"[OK] Semgrep SAST: {f['title']} | {f['severity']} | CWE-{f['cwe']}")

    # ── Semgrep SCA (vulns) ───────────────────────────────────────────────
    semgrep_sca = {
        "vulns": [{
            "title": "Remote Code Execution in requests",
            "repositoryId": "GHSA-j8r2-6x86-q33q",
            "dependencyFileLocation": {"path": "requirements.txt", "startLine": 5},
            "advisory": {
                "severity": "HIGH",
                "description": "requests library vulnerable to RCE.",
                "references": {
                    "cweIds": ["CWE-94: Improper Control of Code Generation"]
                }
            }
        }]
    }

    findings = await parse_semgrep(semgrep_sca)
    assert len(findings) == 1
    f = findings[0]
    assert f["scan_type"] == "sca"
    assert f["cwe"] == 94
    print(f"[OK] Semgrep SCA: {f['title']} | {f['severity']} | CWE-{f['cwe']}")

    # ── Gitleaks v8+ ──────────────────────────────────────────────────────
    gitleaks_data = [{
        "Description": "AWS Access Key",
        "StartLine": 10,
        "Match": "AKIAIOSFODNN7EXAMPLE",
        "Secret": "AKIAIOSFODNN7EXAMPLE",
        "File": "config/deploy.yaml",
        "Commit": "deadbeef",
        "Date": "2024-01-15T12:00:00Z",
        "Message": "chore: update deployment config",
        "RuleID": "aws-access-key-id",
        "Tags": ["aws", "credentials"]
    }]

    findings = await parse_gitleaks(gitleaks_data)
    assert len(findings) == 1, f"Gitleaks esperava 1, obteve {len(findings)}"
    f = findings[0]
    assert f["cwe"] == 798, f"CWE esperado 798, obteve {f['cwe']}"
    assert f["severity"] == "High"
    assert f["tool"] == "gitleaks"
    print(f"[OK] Gitleaks v8+: {f['title'][:55]}... | {f['severity']} | CWE-{f['cwe']}")

    # ── Gitleaks legado ───────────────────────────────────────────────────
    gitleaks_legacy = [{
        "rule": "Github Personal Access Token",
        "commit": "abc123",
        "file": ".env",
        "commitMessage": "fix credentials",
        "author": "dev",
        "email": "dev@company.com",
        "date": "2024-01-10",
        "line": "GITHUB_TOKEN=ghp_xxxxxxxxxxxx",
        "offender": "ghp_xxxxxxxxxxxx",
        "lineNumber": 3,
        "tags": "secret, github"
    }]

    findings = await parse_gitleaks(gitleaks_legacy)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "Critical"  # "Github" eleva para Critical
    assert f["format"] == "legacy"
    print(f"[OK] Gitleaks legacy: {f['title']} | {f['severity']}")

    # ── Gitleaks JSON nulo ────────────────────────────────────────────────
    findings = await parse_gitleaks("null")
    assert findings == []
    print("[OK] Gitleaks null: retornou lista vazia")

    # ── Checkov IaC single ────────────────────────────────────────────────
    checkov_single = {
        "check_type": "terraform",
        "results": {
            "passed_checks": [],
            "failed_checks": [{
                "check_id": "CKV_AWS_18",
                "check_name": "Ensure the S3 bucket has access logging enabled",
                "file_path": "/terraform/main.tf",
                "file_line_range": [12, 25],
                "resource": "aws_s3_bucket.my_bucket",
                "severity": "MEDIUM",
                "guideline": "https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html",
                "benchmarks": {
                    "CIS AWS Foundations v1.4.0": [
                        {"name": "2.1.2", "description": "S3 logging enabled"}
                    ]
                }
            }]
        }
    }

    findings = await parse_checkov(checkov_single)
    assert len(findings) == 1, f"Checkov esperava 1, obteve {len(findings)}"
    f = findings[0]
    assert f["check_type"] == "terraform"
    assert f["severity"] == "Medium"
    assert f["line"] == 12
    assert f["component_name"] == "aws_s3_bucket.my_bucket"
    assert f["tool"] == "checkov"
    print(f"[OK] Checkov IaC (single): {f['check_id']} | {f['severity']} | {f['component_name']}")

    # ── Checkov IaC multi check_type ─────────────────────────────────────
    checkov_multi = [
        {
            "check_type": "terraform",
            "results": {
                "failed_checks": [{
                    "check_id": "CKV_AWS_18",
                    "check_name": "S3 access logging",
                    "file_path": "/terraform/s3.tf",
                    "file_line_range": [1, 10],
                    "resource": "aws_s3_bucket.data",
                    "severity": "HIGH"
                }]
            }
        },
        {
            "check_type": "kubernetes",
            "results": {
                "failed_checks": [{
                    "check_id": "CKV_K8S_28",
                    "check_name": "Do not admit containers wishing to share the host IPC namespace",
                    "file_path": "/k8s/deployment.yaml",
                    "file_line_range": [5, 30],
                    "resource": "Deployment.default.my-app",
                    "severity": "CRITICAL"
                }]
            }
        }
    ]

    findings = await parse_checkov(checkov_multi)
    assert len(findings) == 2, f"Checkov multi esperava 2, obteve {len(findings)}"
    types = {f["check_type"] for f in findings}
    assert types == {"terraform", "kubernetes"}
    print(f"[OK] Checkov IaC (multi): {len(findings)} achados em {types}")

    print()
    print("=" * 50)
    print("  TODOS OS TESTES PASSARAM COM SUCESSO!")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
