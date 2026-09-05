"""
OXHUNTER - ai/attack_chaining.py
Smart Attack Chaining — SSRF→RCE, XSS→CSRF→Account Takeover, etc.
Uses Groq API (Free)
"""

import os
import json
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = "llama-3.3-70b-versatile"


# ─────────────────────────────────────────────
#  KNOWN ATTACK CHAINS
# ─────────────────────────────────────────────
KNOWN_CHAINS = {
    ("ssrf", "rce"): {
        "name"  : "SSRF → RCE",
        "steps" : [
            "SSRF se internal services access karo (Redis, Memcache)",
            "Redis SLAVEOF command inject karo via gopher://",
            "Malicious .so file upload karo",
            "MODULE LOAD se RCE achieve karo",
        ],
        "severity": "CRITICAL",
        "cvss"    : 9.8,
    },
    ("xss", "csrf"): {
        "name"  : "XSS → CSRF → Account Takeover",
        "steps" : [
            "XSS payload inject karo victim page mein",
            "JS se admin CSRF-protected endpoint call karo",
            "Admin password ya email change karo",
            "Account takeover complete",
        ],
        "severity": "CRITICAL",
        "cvss"    : 9.3,
    },
    ("xss", "session_fixation"): {
        "name"  : "XSS → Session Hijacking",
        "steps" : [
            "XSS se document.cookie steal karo",
            "Cookie attacker server pe send karo",
            "Stolen session use karke login karo",
        ],
        "severity": "HIGH",
        "cvss"    : 8.8,
    },
    ("open_redirect", "xss"): {
        "name"  : "Open Redirect → XSS",
        "steps" : [
            "Open redirect pe javascript: URI inject karo",
            "Victim redirect pe XSS trigger ho",
            "Session/credentials steal karo",
        ],
        "severity": "HIGH",
        "cvss"    : 7.5,
    },
    ("lfi", "rce"): {
        "name"  : "LFI → Log Poisoning → RCE",
        "steps" : [
            "LFI se /var/log/apache2/access.log read karo",
            "User-Agent mein PHP code inject karo",
            "LFI se poisoned log include karo",
            "RCE achieve karo",
        ],
        "severity": "CRITICAL",
        "cvss"    : 9.8,
    },
    ("sqli", "rce"): {
        "name"  : "SQLi → File Write → RCE",
        "steps" : [
            "SQLi se FILE privilege check karo",
            "INTO OUTFILE se webshell likho",
            "Webshell access karke RCE karo",
        ],
        "severity": "CRITICAL",
        "cvss"    : 9.8,
    },
    ("xxe", "ssrf"): {
        "name"  : "XXE → SSRF → Cloud Metadata",
        "steps" : [
            "XXE payload se http:// entity define karo",
            "AWS/GCP metadata endpoint target karo",
            "IAM credentials steal karo",
            "Cloud infrastructure access karo",
        ],
        "severity": "CRITICAL",
        "cvss"    : 9.1,
    },
    ("cors", "csrf"): {
        "name"  : "CORS → Cross-Origin Data Theft",
        "steps" : [
            "CORS misconfiguration se cross-origin request karo",
            "Authenticated user ke private data read karo",
            "Sensitive API endpoints call karo",
        ],
        "severity": "HIGH",
        "cvss"    : 8.1,
    },
    ("jwt_attacks", "privilege_escalation"): {
        "name"  : "JWT Attack → Admin Access",
        "steps" : [
            "JWT token intercept karo",
            "alg:none attack ya weak secret brute-force karo",
            "role/isAdmin claim modify karo",
            "Admin endpoints access karo",
        ],
        "severity": "CRITICAL",
        "cvss"    : 9.8,
    },
    ("prototype_pollution", "xss"): {
        "name"  : "Prototype Pollution → XSS",
        "steps" : [
            "Object prototype pollute karo",
            "innerHTML ya eval-based sink trigger karo",
            "XSS execute karo",
        ],
        "severity": "HIGH",
        "cvss"    : 8.0,
    },
    ("idor", "privilege_escalation"): {
        "name"  : "IDOR → Privilege Escalation",
        "steps" : [
            "IDOR se admin user ID access karo",
            "Admin profile data modify karo",
            "Privilege escalation complete",
        ],
        "severity": "HIGH",
        "cvss"    : 8.5,
    },
}


# ─────────────────────────────────────────────
#  DATACLASS
# ─────────────────────────────────────────────
@dataclass
class AttackChain:
    name        : str
    vulns       : List[str]
    steps       : List[str]
    severity    : str
    cvss        : float
    target_url  : str
    ai_analysis : str       = ""
    poc_outline : str       = ""
    impact      : str       = ""


# ─────────────────────────────────────────────
#  SMART ATTACK CHAINER
# ─────────────────────────────────────────────
class SmartAttackChainer:
    """
    Automatically identifies and chains vulnerabilities
    for maximum impact exploitation paths.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GROQ_API_KEY", "")
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type" : "application/json",
        }

    def _groq(self, prompt: str, max_tokens: int = 800) -> str:
        if not self.api_key:
            return ""
        try:
            r = requests.post(
                GROQ_API_URL,
                headers=self.headers,
                json={
                    "model"      : GROQ_MODEL,
                    "messages"   : [{"role": "user", "content": prompt}],
                    "max_tokens" : max_tokens,
                    "temperature": 0.2,
                },
                timeout=30
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"].strip()
        except Exception:
            pass
        return ""

    # ── Local Chaining ────────────────────────

    def find_chains(self, findings: List[Dict]) -> List[AttackChain]:
        """
        Find attack chains from scan findings (no API needed).
        Uses built-in KNOWN_CHAINS database.
        """
        vuln_types = list(set(
            f.get("type", f.get("vuln_type", "")).lower()
            for f in findings
        ))
        target_url = findings[0].get("url", "") if findings else ""
        chains     = []

        for (v1, v2), chain_data in KNOWN_CHAINS.items():
            if v1 in vuln_types and (v2 in vuln_types or v2 in ["rce","privilege_escalation"]):
                chain = AttackChain(
                    name      = chain_data["name"],
                    vulns     = [v1, v2],
                    steps     = chain_data["steps"],
                    severity  = chain_data["severity"],
                    cvss      = chain_data["cvss"],
                    target_url= target_url,
                    impact    = f"Chain: {v1.upper()} → {v2.upper()} can lead to full compromise",
                )
                chains.append(chain)

        # Sort by CVSS score
        chains.sort(key=lambda c: c.cvss, reverse=True)
        return chains

    # ── AI-Enhanced Chaining ──────────────────

    def ai_chain_analysis(self, findings: List[Dict]) -> List[AttackChain]:
        """
        Use Groq AI to find creative attack chains
        beyond the known patterns.
        """
        chains = self.find_chains(findings)

        if not self.api_key or not findings:
            return chains

        vuln_summary = ", ".join(set(
            f.get("type", f.get("vuln_type","")).upper()
            for f in findings
        ))
        target = findings[0].get("url","") if findings else ""

        prompt = f"""You are a senior penetration tester analyzing vulnerabilities.

Target: {target}
Vulnerabilities found: {vuln_summary}

Identify attack chains that combine these vulnerabilities for maximum impact.
Return as JSON array with this exact format:
[
  {{
    "name": "Chain Name",
    "vulns": ["vuln1", "vuln2"],
    "steps": ["step1", "step2", "step3"],
    "severity": "CRITICAL",
    "cvss": 9.8,
    "impact": "What attacker can achieve"
  }}
]

Return ONLY the JSON array, nothing else."""

        raw = self._groq(prompt, max_tokens=1000)
        if not raw:
            return chains

        try:
            start = raw.find("[")
            end   = raw.rfind("]") + 1
            if start == -1:
                return chains

            ai_chains = json.loads(raw[start:end])
            for ac in ai_chains:
                # Check for duplicates
                if ac.get("name") not in [c.name for c in chains]:
                    chains.append(AttackChain(
                        name      = ac.get("name", "Unknown Chain"),
                        vulns     = ac.get("vulns", []),
                        steps     = ac.get("steps", []),
                        severity  = ac.get("severity", "HIGH"),
                        cvss      = float(ac.get("cvss", 7.0)),
                        target_url= target,
                        impact    = ac.get("impact", ""),
                        ai_analysis = "AI-discovered chain",
                    ))
        except Exception:
            pass

        chains.sort(key=lambda c: c.cvss, reverse=True)
        return chains

    def generate_poc_outline(self, chain: AttackChain) -> str:
        """Generate attack PoC outline for a chain."""
        if not self.api_key:
            return "\n".join(f"{i+1}. {s}" for i, s in enumerate(chain.steps))

        prompt = f"""Write a brief PoC outline for this attack chain (authorized testing only):

Chain: {chain.name}
Target: {chain.target_url}
Vulnerabilities: {' → '.join(chain.vulns)}

Steps:
{chr(10).join(f'{i+1}. {s}' for i,s in enumerate(chain.steps))}

Write 5-8 lines of pseudocode or commands showing how to execute this chain.
Keep it concise and technical."""

        return self._groq(prompt, max_tokens=400)

    # ── Report ────────────────────────────────

    def summary(self, chains: List[AttackChain]) -> Dict:
        return {
            "total_chains"   : len(chains),
            "critical_chains": sum(1 for c in chains if c.severity == "CRITICAL"),
            "highest_cvss"   : max((c.cvss for c in chains), default=0),
            "chains"         : [
                {
                    "name"    : c.name,
                    "severity": c.severity,
                    "cvss"    : c.cvss,
                    "vulns"   : c.vulns,
                    "steps"   : c.steps,
                    "impact"  : c.impact,
                }
                for c in chains
            ],
        }

    def html_report(self, chains: List[AttackChain], target: str = "") -> str:
        """Generate HTML attack chain report."""
        if not chains:
            return "<p>No attack chains identified.</p>"

        cards = ""
        for i, c in enumerate(chains, 1):
            color = {
                "CRITICAL": "#dc2626", "HIGH": "#ea580c",
                "MEDIUM"  : "#d97706", "LOW" : "#2563eb"
            }.get(c.severity, "#6b7280")

            steps_html = "".join(f"<li style='color:#94a3b8'>{s}</li>" for s in c.steps)
            vulns_html = " → ".join(
                f"<span style='background:{color};color:white;padding:2px 6px;border-radius:3px;font-size:11px'>{v.upper()}</span>"
                for v in c.vulns
            )

            cards += f"""
<div style="background:#1e293b;border-radius:8px;margin:16px 0;border-left:4px solid {color};padding:16px">
    <div style="margin-bottom:10px">
        <span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{c.severity} | CVSS:{c.cvss}</span>
        <strong style="color:white;margin-left:10px">#{i} {c.name}</strong>
    </div>
    <div style="margin-bottom:10px">{vulns_html}</div>
    <p style="color:#94a3b8;margin:0 0 8px"><strong style="color:#e2e8f0">Impact:</strong> {c.impact}</p>
    <p style="color:#e2e8f0;margin:0 0 8px"><strong>Attack Steps:</strong></p>
    <ol style="margin:0">{steps_html}</ol>
</div>"""

        return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Attack Chains</title>
<style>body{{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;padding:20px;max-width:1000px;margin:0 auto}}</style>
</head><body>
<h1 style="color:#f87171">⛓️ OXHUNTER — Attack Chain Analysis</h1>
<p style="color:#94a3b8">Target: {target} | Chains Found: {len(chains)}</p>
<p style="color:#ef4444;border:1px solid #ef4444;padding:8px;border-radius:4px">⚠️ FOR AUTHORIZED TESTING ONLY</p>
{cards}
</body></html>"""
