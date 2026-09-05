"""
OXHUNTER - owasp_mapping.py
OWASP Top 10 (2021) Mapping + Compliance Report
"""

from typing import Dict, List

# ─────────────────────────────────────────────
#  OWASP TOP 10 — 2021
# ─────────────────────────────────────────────
OWASP_TOP10 = {
    "A01": {"title": "Broken Access Control",        "vulns": ["idor","csrf","open_redirect","directory_listing"]},
    "A02": {"title": "Cryptographic Failures",        "vulns": ["ssl_issues","sensitive_files","info_disclosure"]},
    "A03": {"title": "Injection",                     "vulns": ["sqli","command_injection","xxe","ssti","xss"]},
    "A04": {"title": "Insecure Design",               "vulns": ["business_logic","race_condition"]},
    "A05": {"title": "Security Misconfiguration",     "vulns": ["cors","header_missing","git_exposure","sensitive_files"]},
    "A06": {"title": "Vulnerable Components",         "vulns": ["cve_found","outdated_software"]},
    "A07": {"title": "Auth Failures",                 "vulns": ["jwt_attacks","session_fixation","password_policy"]},
    "A08": {"title": "Software & Data Integrity",     "vulns": ["prototype_pollution","supply_chain"]},
    "A09": {"title": "Logging & Monitoring Failures", "vulns": ["no_logging"]},
    "A10": {"title": "SSRF",                          "vulns": ["ssrf"]},
}

# Remediation advice per category
REMEDIATION = {
    "A01": "Implement proper access controls, deny by default, log access failures.",
    "A02": "Use strong encryption (TLS 1.2+), never store sensitive data in plaintext.",
    "A03": "Use parameterized queries, validate all input, encode output.",
    "A04": "Threat model during design, implement rate limiting and anti-automation.",
    "A05": "Harden configurations, disable unnecessary features, review cloud permissions.",
    "A06": "Keep dependencies updated, use SCA tools, monitor CVE feeds.",
    "A07": "Use MFA, rotate tokens, enforce strong session management.",
    "A08": "Verify integrity of updates/CI pipelines, use signed packages.",
    "A09": "Implement centralized logging, alerting, and incident response plan.",
    "A10": "Validate/sanitize all URLs, use allowlists, block internal IP ranges.",
}


class OWASPMapper:

    @staticmethod
    def map_finding(vuln_type: str) -> List[str]:
        """Return OWASP category IDs for a vuln type."""
        return [k for k, v in OWASP_TOP10.items() if vuln_type in v["vulns"]]

    @staticmethod
    def map_findings(findings: List[Dict]) -> Dict:
        """Map all findings to OWASP categories."""
        report = {k: {"title": v["title"], "findings": [], "remediation": REMEDIATION[k]}
                  for k, v in OWASP_TOP10.items()}

        for f in findings:
            cats = OWASPMapper.map_finding(f.get("vuln_type",""))
            for cat in cats:
                report[cat]["findings"].append(f)

        return report

    @staticmethod
    def compliance_score(findings: List[Dict]) -> Dict:
        """Calculate OWASP compliance score (0-100)."""
        mapped  = OWASPMapper.map_findings(findings)
        failed  = sum(1 for v in mapped.values() if v["findings"])
        total   = len(OWASP_TOP10)
        passed  = total - failed
        score   = round((passed / total) * 100)
        return {
            "score"  : score,
            "passed" : passed,
            "failed" : failed,
            "total"  : total,
            "status" : "PASS" if score >= 70 else "FAIL",
            "detail" : mapped,
        }

    @staticmethod
    def markdown_report(findings: List[Dict], target: str = "") -> str:
        """Generate markdown OWASP compliance report."""
        result = OWASPMapper.compliance_score(findings)
        lines  = [
            "# OWASP Top 10 Compliance Report",  # BUG-012 FIX: removed unnecessary f-string
            f"**Target:** {target}  **Score:** {result['score']}/100 ({result['status']})\n",
            "| ID | Category | Status | Findings |",
            "|---|---|---|---|",
        ]
        for k, v in result["detail"].items():
            status = "❌ FAIL" if v["findings"] else "✅ PASS"
            lines.append(f"| {k} | {v['title']} | {status} | {len(v['findings'])} |")

        lines.append("\n## Remediation")
        for k, v in result["detail"].items():
            if v["findings"]:
                lines.append(f"\n### {k} — {v['title']}\n{v['remediation']}")

        return "\n".join(lines)
