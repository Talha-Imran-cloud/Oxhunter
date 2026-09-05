"""
OXHUNTER - bug_bounty.py
Bug Bounty Mode — In-scope / Out-of-scope Filter
"""

from urllib.parse import urlparse
from typing import Dict, List
from dataclasses import dataclass, field


@dataclass
class BugBountyScope:
    in_scope    : List[str] = field(default_factory=list)   # "*.example.com", "api.example.com"
    out_of_scope: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list) # "/logout", "/admin"
    severity_min: str       = "LOW"
    platform    : str       = ""   # HackerOne, Bugcrowd, etc.
    notes       : str       = ""


class BugBountyMode:

    def __init__(self, scope: BugBountyScope):
        self.scope = scope

    # ── Scope Check ───────────────────────────

    def _matches(self, host: str, pattern: str) -> bool:
        """Check if host matches pattern (supports wildcards)."""
        pattern = pattern.lstrip("*.")
        return host == pattern or host.endswith(f".{pattern}")

    def is_in_scope(self, url: str) -> bool:
        host = urlparse(url).netloc.split(":")[0]
        path = urlparse(url).path

        # Check out-of-scope first
        for oos in self.scope.out_of_scope:
            if self._matches(host, oos):
                return False

        # Check excluded paths
        for ep in self.scope.excluded_paths:
            if path.startswith(ep):
                return False

        # Check in-scope
        if not self.scope.in_scope:
            return True   # No scope defined = all allowed
        return any(self._matches(host, s) for s in self.scope.in_scope)

    def filter_urls(self, urls: List[str]) -> Dict:
        """Split URLs into in/out of scope."""
        result = {"in_scope": [], "out_of_scope": [], "excluded": []}
        for url in urls:
            host = urlparse(url).netloc.split(":")[0]
            path = urlparse(url).path

            if any(path.startswith(ep) for ep in self.scope.excluded_paths):
                result["excluded"].append(url)
            elif self.is_in_scope(url):
                result["in_scope"].append(url)
            else:
                result["out_of_scope"].append(url)
        return result

    def filter_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove out-of-scope findings."""
        order   = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
        # FIX: normalize severity_min to uppercase so case mismatch doesn't crash
        min_sev = self.scope.severity_min.upper()
        min_i   = order.index(min_sev) if min_sev in order else 4
        result  = []
        for f in findings:
            if not self.is_in_scope(f.get("url", "")):
                continue
            # FIX: normalize finding severity to uppercase before index lookup
            sev = f.get("severity", "INFO").upper()
            if sev not in order:
                sev = "INFO"
            if order.index(sev) <= min_i:
                result.append(f)
        return result

    # ── Report ────────────────────────────────

    def bounty_report(self, findings: List[Dict], target: str = "") -> Dict:
        """Generate bug bounty ready report."""
        valid = self.filter_findings(findings)
        return {
            "platform"      : self.scope.platform,
            "target"        : target,
            "total_valid"   : len(valid),
            "in_scope_only" : True,
            "min_severity"  : self.scope.severity_min,
            "findings"      : [self._format(f) for f in valid],
        }

    @staticmethod
    def _format(f: Dict) -> Dict:
        """Format finding for bug bounty submission."""
        return {
            "title"      : f"{f.get('vuln_type','').upper()} in {f.get('url','')}",
            "severity"   : f.get("severity"),
            "cvss"       : f.get("cvss_score"),
            "url"        : f.get("url"),
            "description": f.get("detail",""),
            "steps"      : f"1. Visit {f.get('url')}\n2. Payload: {f.get('payload','N/A')}",
            "impact"     : f.get("detail",""),
            "remediation": f.get("remediation",""),
            "evidence"   : f.get("evidence",""),
        }

    def markdown_submission(self, finding: Dict) -> str:
        """Generate single finding markdown for platform submission."""
        f = self._format(finding)
        return (
            f"## {f['title']}\n\n"
            f"**Severity:** {f['severity']} (CVSS: {f['cvss']})\n\n"
            f"### Description\n{f['description']}\n\n"
            f"### Steps to Reproduce\n{f['steps']}\n\n"
            f"### Impact\n{f['impact']}\n\n"
            f"### Remediation\n{f['remediation']}\n\n"
            "*Found by OXHUNTER Security Scanner*"
        )


# ── Quick Setup ───────────────────────────────
def setup(in_scope: List[str], out_of_scope: List[str] = None,
          platform: str = "", severity_min: str = "LOW") -> BugBountyMode:
    return BugBountyMode(BugBountyScope(
        in_scope     = in_scope,
        out_of_scope = out_of_scope or [],
        platform     = platform,
        severity_min = severity_min,
    ))
