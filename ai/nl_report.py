"""
OXHUNTER - ai/nl_report.py
Natural Language Report Generator — English & Urdu
Using Groq AI (Free)
"""

import os
import json
import requests
from typing import Dict, Optional

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = "llama-3.3-70b-versatile"


class NLReportGenerator:
    """
    Natural Language Report Generator.
    Generates human-readable security reports in:
    - English (professional)
    - Urdu (Roman Urdu + Urdu script)
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GROQ_API_KEY", "")
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type":  "application/json",
        }

    def _call(self, prompt: str, system: str = "",
              max_tokens: int = 1500) -> str:
        """Call Groq API"""
        if not self.api_key:
            return "AI features require GROQ_API_KEY in .env file"

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        fallback_models = [GROQ_MODEL, "llama-3.1-8b-instant", "mixtral-8x7b-32768"]
        for model in fallback_models:
            try:
                r = requests.post(
                    GROQ_API_URL,
                    headers=self.headers,
                    json={
                        "model":       model,
                        "messages":    messages,
                        "max_tokens":  max_tokens,
                        "temperature": 0.6,
                    },
                    timeout=45
                )
                if r.status_code == 200:
                    return r.json()["choices"][0]["message"]["content"].strip()
            except Exception:
                continue
        return "AI report unavailable — check GROQ_API_KEY"

    # ── English Reports ───────────────────────

    def executive_summary_en(self, scan_data: Dict) -> str:
        """Generate executive summary in English"""
        findings  = scan_data.get("findings", [])
        target    = scan_data.get("target", "")
        summary   = scan_data.get("summary", {})

        system = (
            "You are a senior security consultant writing an executive summary "
            "for a non-technical audience. Be professional, clear, and concise. "
            "Focus on business risk and impact."
        )

        prompt = f"""Write an executive summary for a security assessment:

Target: {target}
Total Findings: {len(findings)}
Critical: {summary.get('Critical', 0)}
High: {summary.get('High', 0)}
Medium: {summary.get('Medium', 0)}
Low: {summary.get('Low', 0)}

Top findings:
{json.dumps([{
    'type': f.get('type', ''),
    'severity': f.get('severity', ''),
    'url': f.get('url', '')[:60]
} for f in findings[:5]], indent=2)}

Write a 3-paragraph executive summary:
1. Overall security posture
2. Key risks found
3. Recommended actions

Keep it professional and non-technical."""

        return self._call(prompt, system)

    def technical_report_en(self, scan_data: Dict) -> str:
        """Generate technical report in English"""
        findings = scan_data.get("findings", [])
        target   = scan_data.get("target", "")

        system = (
            "You are a senior penetration tester writing a technical security report. "
            "Be detailed, accurate, and include actionable remediation steps."
        )

        prompt = f"""Write a technical security report for:
Target: {target}
Findings: {json.dumps([{
    'type': f.get('type', ''),
    'severity': f.get('severity', ''),
    'url': f.get('url', '')[:60],
    'evidence': f.get('evidence', '')[:100]
} for f in findings[:10]], indent=2)}

Include:
1. Assessment scope and methodology
2. Technical findings with severity ratings
3. Proof of concept descriptions
4. Detailed remediation recommendations
5. Risk ratings and priorities

Write a comprehensive technical report."""

        return self._call(prompt, system, max_tokens=2000)

    # ── Urdu Reports ─────────────────────────

    def executive_summary_ur(self, scan_data: Dict) -> str:
        """Generate executive summary in Urdu"""
        findings = scan_data.get("findings", [])
        target   = scan_data.get("target", "")
        summary  = scan_data.get("summary", {})

        system = (
            "Aap ek senior security consultant hain jo Urdu mein executive summary likh rahe hain. "
            "Roman Urdu aur Urdu script dono use karein. Simple aur clear language use karein."
        )

        prompt = f"""Is security assessment ki executive summary Urdu mein likhein:

Target: {target}
Total Issues: {len(findings)}
Critical: {summary.get('Critical', 0)}
High: {summary.get('High', 0)}
Medium: {summary.get('Medium', 0)}
Low: {summary.get('Low', 0)}

Top problems:
{json.dumps([{
    'type': f.get('type', ''),
    'severity': f.get('severity', '')
} for f in findings[:5]], indent=2)}

3 paragraphs mein likhein:
1. Overall security ki halat
2. Important risks jo mile
3. Kya karna chahiye

Urdu mein likhein (Roman Urdu + Urdu script)."""

        return self._call(prompt, system, max_tokens=1500)

    def finding_description_ur(self, finding: Dict) -> str:
        """Describe a single finding in Urdu"""
        system = (
            "Aap ek security expert hain. Vulnerability ko simple Urdu mein explain karein. "
            "Non-technical log bhi samajh sakein."
        )

        prompt = f"""Is vulnerability ko Urdu mein explain karein:

Type: {finding.get('type', '')}
Severity: {finding.get('severity', '')}
URL: {finding.get('url', '')}
Evidence: {finding.get('evidence', '')[:200]}

Explain karein:
1. Ye kya problem hai (simple words mein)
2. Attacker kya kar sakta hai
3. Isko kaise fix karein

Roman Urdu + Urdu script use karein."""

        return self._call(prompt, system, max_tokens=600)

    # ── Combined Report ───────────────────────

    def generate_full_report(self, scan_data: Dict,
                              language: str = "en") -> Dict:
        """
        Generate complete NL report.
        language: 'en' | 'ur' | 'both'
        """
        result = {}

        if language in ["en", "both"]:
            result["executive_summary_en"] = self.executive_summary_en(scan_data)
            result["technical_report_en"]  = self.technical_report_en(scan_data)

        if language in ["ur", "both"]:
            result["executive_summary_ur"] = self.executive_summary_ur(scan_data)

            # Urdu descriptions for top findings
            findings = scan_data.get("findings", [])[:5]
            ur_findings = []
            for f in findings:
                ur_findings.append({
                    **f,
                    "description_ur": self.finding_description_ur(f)
                })
            result["findings_ur"] = ur_findings

        result["language"]  = language
        result["target"]    = scan_data.get("target", "")
        result["generated"] = "Groq AI (LLaMA 3.1 70B)"

        return result

    def save_report(self, scan_data: Dict,
                    language: str = "en",
                    output_path: str = "reports/nl_report.txt") -> str:
        """Generate and save NL report to file"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)  # BUG-011 FIX: removed redundant 'import os'

        report = self.generate_full_report(scan_data, language)

        content = f"""
{'='*60}
OXHUNTER — NATURAL LANGUAGE SECURITY REPORT
Target: {report.get('target', '')}
Generated by: {report.get('generated', '')}
{'='*60}

"""
        if "executive_summary_en" in report:
            content += f"## EXECUTIVE SUMMARY (English)\n\n{report['executive_summary_en']}\n\n"

        if "technical_report_en" in report:
            content += f"## TECHNICAL REPORT (English)\n\n{report['technical_report_en']}\n\n"

        if "executive_summary_ur" in report:
            content += f"## EXECUTIVE SUMMARY (Urdu)\n\n{report['executive_summary_ur']}\n\n"

        if "findings_ur" in report:
            content += "## FINDINGS (Urdu)\n\n"
            for f in report.get("findings_ur", []):
                content += f"### {f.get('type', '')}\n{f.get('description_ur', '')}\n\n"

        with open(output_path, "w", encoding="utf-8") as file:
            file.write(content)

        return output_path
