"""
OXHUNTER - ai/vuln_chaining.py
Smart Vulnerability Chaining using Groq AI
"""

import os
import json
import requests
from typing import List, Dict, Optional

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = "llama-3.3-70b-versatile"


class VulnChainer:
    """
    Smart Vulnerability Chaining
    Uses AI to find how vulnerabilities can be chained
    to achieve higher impact attacks.
    Example: SSRF + IDOR → Full account takeover
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GROQ_API_KEY", "")
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type":  "application/json",
        }

    def _call(self, prompt: str, system: str = "") -> str:
        """Call Groq API"""
        if not self.api_key:
            return ""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            r = requests.post(
                GROQ_API_URL,
                headers=self.headers,
                json={
                    "model":       GROQ_MODEL,
                    "messages":    messages,
                    "max_tokens":  1000,
                    "temperature": 0.5,
                },
                timeout=30
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"].strip()
            return ""
        except Exception:
            return ""

    def analyze_chains(self, findings: List[Dict]) -> List[Dict]:
        """
        Analyze findings and suggest vulnerability chains.
        Returns list of chain scenarios with impact.
        """
        if not findings:
            return []

        # Build vulnerability summary
        vuln_list = []
        for f in findings:
            vuln_list.append({
                "type":     f.get("vuln_type", f.get("type", "")),
                "severity": f.get("severity", ""),
                "url":      f.get("url", "")[:60],
            })

        system = (
            "You are a senior penetration tester analyzing vulnerability chains. "
            "Identify how vulnerabilities can be combined for higher impact. "
            "Return ONLY valid JSON. No markdown, no explanation."
        )

        prompt = f"""Analyze these vulnerabilities found on a target:
{json.dumps(vuln_list, indent=2)}

Identify vulnerability chains. Return JSON:
{{
  "chains": [
    {{
      "name": "Chain name",
      "vulns_used": ["vuln1", "vuln2"],
      "attack_steps": ["Step 1", "Step 2", "Step 3"],
      "impact": "What attacker can achieve",
      "severity": "CRITICAL/HIGH/MEDIUM",
      "likelihood": "HIGH/MEDIUM/LOW"
    }}
  ],
  "highest_impact": "Overall highest impact scenario"
}}"""

        response = self._call(prompt, system)
        return self._parse_chains(response)

    def suggest_next_steps(self, finding: Dict,
                            all_findings: List[Dict]) -> Dict:
        """
        Given one finding, suggest what to test next
        to chain it with other vulnerabilities.
        """
        system = (
            "You are a penetration tester. Suggest next attack steps "
            "to chain vulnerabilities for higher impact. Be concise and practical."
        )

        prompt = f"""Found vulnerability:
Type: {finding.get('type', finding.get('vuln_type', ''))}
URL: {finding.get('url', '')}
Severity: {finding.get('severity', '')}

Other vulnerabilities on target:
{json.dumps([f.get('type', f.get('vuln_type', '')) for f in all_findings[:10]], indent=2)}

Suggest 3-5 specific next steps to chain this vulnerability.
Return JSON: {{"next_steps": ["step1", "step2"], "goal": "end goal", "combined_severity": "CRITICAL/HIGH"}}"""

        response = self._call(prompt, system)
        try:
            clean = response.strip()
            start = clean.find("{")
            end   = clean.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(clean[start:end])
        except Exception:
            pass
        return {"next_steps": [], "goal": "", "combined_severity": ""}

    def generate_attack_path(self, findings: List[Dict],
                              target: str = "") -> Dict:
        """
        Generate complete attack path from initial access
        to full compromise.
        """
        vuln_types = list(set([
            f.get("vuln_type", f.get("type", ""))
            for f in findings if f.get("vuln_type") or f.get("type")
        ]))

        system = (
            "You are a red team expert. Create a realistic attack path "
            "using the discovered vulnerabilities. Return ONLY valid JSON."
        )

        prompt = f"""Target: {target}
Vulnerabilities found: {json.dumps(vuln_types, indent=2)}

Create a complete attack path. Return JSON:
{{
  "attack_path": [
    {{"phase": "Initial Access", "action": "...", "vuln_used": "..."}},
    {{"phase": "Privilege Escalation", "action": "...", "vuln_used": "..."}},
    {{"phase": "Data Exfiltration", "action": "...", "vuln_used": "..."}}
  ],
  "final_impact": "...",
  "difficulty": "EASY/MEDIUM/HARD",
  "estimated_time": "..."
}}"""

        response = self._call(prompt, system)
        try:
            clean = response.strip()
            if "```" in clean:
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            start = clean.find("{")
            end   = clean.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(clean[start:end])
        except Exception:
            pass
        return {"attack_path": [], "final_impact": "", "difficulty": ""}

    def _parse_chains(self, response: str) -> List[Dict]:
        """Parse chains from AI response"""
        if not response:
            return []
        try:
            clean = response.strip()
            if "```" in clean:
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            start = clean.find("{")
            end   = clean.rfind("}") + 1
            if start != -1 and end > start:
                data = json.loads(clean[start:end])
                return data.get("chains", [])
        except Exception:
            pass
        return []
