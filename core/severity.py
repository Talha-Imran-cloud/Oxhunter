"""
OXHUNTER - severity.py
CVSS Scoring + Severity Rating (Critical/High/Medium/Low/Info)
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field


# ─────────────────────────────────────────────
#  SEVERITY LEVELS
# ─────────────────────────────────────────────
LEVELS = {
    "CRITICAL": {"min": 9.0, "color": "\033[91m", "emoji": "🔴"},
    "HIGH"    : {"min": 7.0, "color": "\033[91m", "emoji": "🟠"},
    "MEDIUM"  : {"min": 4.0, "color": "\033[93m", "emoji": "🟡"},
    "LOW"     : {"min": 1.0, "color": "\033[94m", "emoji": "🔵"},
    "INFO"    : {"min": 0.0, "color": "\033[92m", "emoji": "⚪"},
}

# Default CVSS scores per vuln type
VULN_SCORES = {
    "sqli"              : ("CRITICAL", 9.8),
    "xss"               : ("HIGH",     7.2),
    "xxe"               : ("CRITICAL", 9.1),
    "ssrf"              : ("CRITICAL", 9.3),
    "command_injection" : ("CRITICAL", 9.8),
    "open_redirect"     : ("MEDIUM",   6.1),
    "csrf"              : ("MEDIUM",   5.4),
    "cors"              : ("HIGH",     7.5),
    "lfi"               : ("HIGH",     7.8),
    "idor"              : ("HIGH",     7.5),
    "jwt_attacks"       : ("CRITICAL", 9.1),
    "session_fixation"  : ("HIGH",     7.3),
    "prototype_pollution": ("HIGH",    7.3),
    "ssti"              : ("CRITICAL", 9.8),
    "http_smuggling"    : ("HIGH",     8.1),
    "race_condition"    : ("MEDIUM",   5.9),
    "subdomain_takeover": ("HIGH",     8.0),
    "git_exposure"      : ("HIGH",     7.5),
    "sensitive_files"   : ("MEDIUM",   5.3),
    "ssl_issues"        : ("MEDIUM",   5.9),
    "header_missing"    : ("LOW",      3.1),
    "directory_listing" : ("MEDIUM",   5.3),
    "info_disclosure"   : ("LOW",      2.7),
}


# ─────────────────────────────────────────────
#  FINDING DATACLASS
# ─────────────────────────────────────────────
@dataclass
class Finding:
    vuln_type  : str
    url        : str
    severity   : str         = "INFO"
    cvss_score : float        = 0.0
    detail     : str          = ""
    payload    : str          = ""
    evidence   : str          = ""
    remediation: str          = ""
    cve        : Optional[str]= None
    owasp      : str          = ""
    extra      : Dict         = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "vuln_type"  : self.vuln_type,
            "url"        : self.url,
            "severity"   : self.severity,
            "cvss_score" : self.cvss_score,
            "detail"     : self.detail,
            "payload"    : self.payload,
            "evidence"   : self.evidence,
            "remediation": self.remediation,
            "cve"        : self.cve,
            "owasp"      : self.owasp,
        }

    def colored(self) -> str:
        c   = LEVELS.get(self.severity, {}).get("color", "")
        rst = "\033[0m"
        em  = LEVELS.get(self.severity, {}).get("emoji", "")
        return (f"{em} {c}[{self.severity}]{rst} {self.vuln_type} "
                f"| CVSS:{self.cvss_score} | {self.url}")


# ─────────────────────────────────────────────
#  SEVERITY MANAGER
# ─────────────────────────────────────────────
class SeverityManager:

    # ── Score from CVSS vector ────────────────

    @staticmethod
    def from_cvss_score(score: float) -> str:
        """Convert numeric CVSS score to severity label."""
        for level, data in LEVELS.items():
            if score >= data["min"]:
                return level
        return "INFO"

    @staticmethod
    def get_default(vuln_type: str) -> tuple:
        """Return (severity, cvss_score) for known vuln type."""
        return VULN_SCORES.get(vuln_type.lower(), ("MEDIUM", 5.0))

    # ── CVSS v3.1 Base Score Calculator ───────

    @staticmethod
    def calculate_cvss(
        AV: str = "N",   # Attack Vector:    N=Network, A=Adjacent, L=Local, P=Physical
        AC: str = "L",   # Attack Complexity: L=Low, H=High
        PR: str = "N",   # Privileges Required: N=None, L=Low, H=High
        UI: str = "N",   # User Interaction:  N=None, R=Required
        S : str = "U",   # Scope:             U=Unchanged, C=Changed
        C : str = "H",   # Confidentiality:   N=None, L=Low, H=High
        I : str = "H",   # Integrity:         N=None, L=Low, H=High
        A : str = "H",   # Availability:      N=None, L=Low, H=High
    ) -> Dict:
        av  = {"N":0.85,"A":0.62,"L":0.55,"P":0.2}.get(AV,0.85)
        ac  = {"L":0.77,"H":0.44}.get(AC,0.77)
        pr  = {"N":0.85,"L":0.62,"H":0.27}.get(PR,0.85) if S=="U" else {"N":0.85,"L":0.68,"H":0.5}.get(PR,0.85)
        ui  = {"N":0.85,"R":0.62}.get(UI,0.85)
        isc = {"N":0.0,"L":0.22,"H":0.56}
        ci,ii,ai = isc.get(C,0.56), isc.get(I,0.56), isc.get(A,0.56)

        isc_base = 1 - (1-ci)*(1-ii)*(1-ai)
        impact   = (7.52*(isc_base-0.029) - 3.25*((isc_base-0.02)**15)) if S=="U" \
                   else (7.52*(isc_base-0.029) - 3.25*((isc_base-0.02)**15))*1.08 if isc_base else 0
        exploit  = 8.22 * av * ac * pr * ui

        if isc_base <= 0:
            score = 0.0
        else:
            raw   = min(impact + exploit, 10)
            score = round(raw * 10) / 10

        return {"score": score, "severity": SeverityManager.from_cvss_score(score),
                "vector": f"CVSS:3.1/AV:{AV}/AC:{AC}/PR:{PR}/UI:{UI}/S:{S}/C:{C}/I:{I}/A:{A}"}

    # ── Build Finding ─────────────────────────

    @staticmethod
    def make_finding(vuln_type: str, url: str, **kwargs) -> Finding:
        """Create a Finding with auto severity + CVSS."""
        severity, score = SeverityManager.get_default(vuln_type)
        return Finding(
            vuln_type  = vuln_type,
            url        = url,
            severity   = kwargs.get("severity", severity),
            cvss_score = kwargs.get("cvss_score", score),
            detail     = kwargs.get("detail", ""),
            payload    = kwargs.get("payload", ""),
            evidence   = kwargs.get("evidence", ""),
            remediation= kwargs.get("remediation", ""),
            owasp      = kwargs.get("owasp", ""),
        )

    # ── Filter & Sort ─────────────────────────

    @staticmethod
    def filter(findings: List[Finding], min_severity: str = "LOW") -> List[Finding]:
        order = list(LEVELS.keys())
        min_i = order.index(min_severity) if min_severity in order else 4
        return [f for f in findings if order.index(f.severity) <= min_i]

    @staticmethod
    def sort(findings: List[Finding]) -> List[Finding]:
        order = list(LEVELS.keys())
        return sorted(findings, key=lambda f: order.index(f.severity))

    @staticmethod
    def summary(findings: List[Finding]) -> Dict:
        counts = {l: 0 for l in LEVELS}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {"total": len(findings), "by_severity": counts}
