"""
OXHUNTER - pci_iso_report.py
PCI-DSS v4.0 + ISO 27001:2022 Compliance Reports
"""

from typing import Dict, List
from datetime import datetime

# ─────────────────────────────────────────────
#  PCI-DSS v4.0 REQUIREMENTS
# ─────────────────────────────────────────────
PCI_REQUIREMENTS = {
    "1": {"title": "Network Security Controls",       "vulns": ["cors","header_missing","open_redirect"]},
    "2": {"title": "Secure Configurations",           "vulns": ["ssl_issues","sensitive_files","git_exposure"]},
    "3": {"title": "Protect Stored Data",             "vulns": ["info_disclosure","sensitive_files"]},
    "4": {"title": "Encrypt Transmission",            "vulns": ["ssl_issues","http_smuggling"]},
    "5": {"title": "Protect Against Malware",         "vulns": ["xss","ssti"]},
    "6": {"title": "Secure Systems & Software",       "vulns": ["sqli","xxe","ssrf","command_injection","idor","csrf"]},
    "7": {"title": "Restrict Access",                 "vulns": ["idor","jwt_attacks","session_fixation"]},
    "8": {"title": "Identify & Authenticate",         "vulns": ["jwt_attacks","session_fixation","password_policy"]},
    "9": {"title": "Restrict Physical Access",        "vulns": []},
    "10": {"title": "Log & Monitor",                  "vulns": ["no_logging"]},
    "11": {"title": "Test Security Regularly",        "vulns": ["xss","sqli","ssrf"]},
    "12": {"title": "Information Security Policy",    "vulns": []},
}

# ─────────────────────────────────────────────
#  ISO 27001:2022 CONTROLS
# ─────────────────────────────────────────────
ISO_CONTROLS = {
    "A.5":  {"title": "Organizational Controls",     "vulns": ["no_logging","info_disclosure"]},
    "A.6":  {"title": "People Controls",             "vulns": ["password_policy","session_fixation"]},
    "A.7":  {"title": "Physical Controls",           "vulns": []},
    "A.8":  {"title": "Technological Controls",      "vulns": [
        "xss","sqli","ssrf","xxe","command_injection","csrf","cors",
        "jwt_attacks","idor","ssl_issues","open_redirect","prototype_pollution",
        "header_missing","sensitive_files","git_exposure","http_smuggling",
    ]},
}


class ComplianceReporter:

    def __init__(self, findings: List[Dict], target: str = "", company: str = ""):
        self.findings = findings
        self.target   = target
        self.company  = company
        self.date     = datetime.now().strftime("%Y-%m-%d")
        self._vuln_types = [f.get("vuln_type","") for f in findings]

    def _failed(self, vuln_list: List[str]) -> List[str]:
        return [v for v in vuln_list if v in self._vuln_types]

    def _score(self, requirements: Dict) -> Dict:
        total  = len(requirements)
        failed = sum(1 for v in requirements.values() if self._failed(v["vulns"]))
        passed = total - failed
        return {
            "passed" : passed,
            "failed" : failed,
            "total"  : total,
            "score"  : round(passed / total * 100),
            "status" : "PASS" if failed == 0 else "FAIL",
        }

    # ── PCI-DSS Report ────────────────────────

    def pci_report(self) -> Dict:
        detail = {}
        for req, data in PCI_REQUIREMENTS.items():
            failed = self._failed(data["vulns"])
            detail[f"Req {req}"] = {
                "title"   : data["title"],
                "status"  : "FAIL" if failed else "PASS",
                "failures": failed,
            }
        return {
            "standard": "PCI-DSS v4.0",
            "target"  : self.target,
            "date"    : self.date,
            **self._score(PCI_REQUIREMENTS),
            "detail"  : detail,
        }

    # ── ISO 27001 Report ──────────────────────

    def iso_report(self) -> Dict:
        detail = {}
        for ctrl, data in ISO_CONTROLS.items():
            failed = self._failed(data["vulns"])
            detail[ctrl] = {
                "title"   : data["title"],
                "status"  : "FAIL" if failed else "PASS",
                "failures": failed,
            }
        return {
            "standard": "ISO 27001:2022",
            "target"  : self.target,
            "date"    : self.date,
            **self._score(ISO_CONTROLS),
            "detail"  : detail,
        }

    # ── Markdown Reports ──────────────────────

    def pci_markdown(self) -> str:
        r     = self.pci_report()
        rows  = "\n".join(
            f"| {k} | {v['title']} | {'❌' if v['status']=='FAIL' else '✅'} {v['status']} | {', '.join(v['failures']) or '-'} |"
            for k, v in r["detail"].items()
        )
        return (
            f"# PCI-DSS v4.0 Compliance Report\n"
            f"**Target:** {self.target}  **Date:** {self.date}  "
            f"**Score:** {r['score']}/100 ({r['status']})\n\n"
            f"| Requirement | Title | Status | Failed Vulns |\n|---|---|---|---|\n{rows}\n"
        )

    def iso_markdown(self) -> str:
        r     = self.iso_report()
        rows  = "\n".join(
            f"| {k} | {v['title']} | {'❌' if v['status']=='FAIL' else '✅'} {v['status']} | {', '.join(v['failures']) or '-'} |"
            for k, v in r["detail"].items()
        )
        return (
            f"# ISO 27001:2022 Compliance Report\n"
            f"**Target:** {self.target}  **Date:** {self.date}  "
            f"**Score:** {r['score']}/100 ({r['status']})\n\n"
            f"| Control | Title | Status | Failed Vulns |\n|---|---|---|---|\n{rows}\n"
        )

    def full_report(self) -> Dict:
        """Both PCI + ISO in one call."""
        return {
            "pci_dss"  : self.pci_report(),
            "iso_27001": self.iso_report(),
            "summary"  : {
                "target"     : self.target,
                "date"       : self.date,
                "total_vulns": len(self.findings),
                "pci_status" : self.pci_report()["status"],
                "iso_status" : self.iso_report()["status"],
            }
        }
