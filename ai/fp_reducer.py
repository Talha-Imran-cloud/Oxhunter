"""
OXHUNTER - ai/fp_reducer.py
False Positive Reducer using Groq AI
"""

import os
import json
import requests
from typing import List, Dict, Optional, Tuple

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = "llama-3.3-70b-versatile"


class FalsePositiveReducer:
    """
    AI-powered False Positive Reducer.
    Analyzes scan findings and filters out likely false positives
    based on evidence, context, and response analysis.
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
                    "max_tokens":  800,
                    "temperature": 0.2,
                },
                timeout=30
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"].strip()
            return ""
        except Exception:
            return ""

    def analyze_finding(self, finding: Dict) -> Tuple[bool, float, str]:
        """
        Analyze single finding for false positive.
        Returns (is_false_positive, confidence, reason)
        """
        system = (
            "You are a senior security analyst validating vulnerability findings. "
            "Determine if a finding is a false positive. Return ONLY valid JSON."
        )

        prompt = f"""Analyze this security finding:
Type: {finding.get('type', finding.get('vuln_type', ''))}
URL: {finding.get('url', '')}
Evidence: {finding.get('evidence', '')[:300]}
Payload: {finding.get('payload', '')}
Response: {finding.get('response_preview', '')}[:200]
Severity: {finding.get('severity', '')}

Is this a false positive?
Return JSON: {{
  "is_false_positive": true/false,
  "confidence": 0.0-1.0,
  "reason": "explanation",
  "recommendation": "verify by..."
}}"""

        response = self._call(prompt, system)

        try:
            clean = response.strip()
            start = clean.find("{")
            end   = clean.rfind("}") + 1
            if start != -1 and end > start:
                data = json.loads(clean[start:end])
                return (
                    data.get("is_false_positive", False),
                    data.get("confidence", 0.5),
                    data.get("reason", "")
                )
        except Exception:
            pass

        return False, 0.5, "Could not analyze"

    def filter_findings(self, findings: List[Dict],
                         fp_threshold: float = 0.7) -> Dict:
        """
        Filter findings — remove likely false positives.
        fp_threshold: confidence level above which to mark as FP
        """
        confirmed  = []
        false_pos  = []
        uncertain  = []

        for finding in findings:
            is_fp, confidence, reason = self.analyze_finding(finding)

            enriched = {
                **finding,
                "fp_analysis": {
                    "is_false_positive": is_fp,
                    "confidence":        confidence,
                    "reason":            reason,
                }
            }

            if is_fp and confidence >= fp_threshold:
                false_pos.append(enriched)
            elif confidence < 0.5:
                uncertain.append(enriched)
            else:
                confirmed.append(enriched)

        return {
            "confirmed":   confirmed,
            "false_positive": false_pos,
            "uncertain":   uncertain,
            "summary": {
                "total":         len(findings),
                "confirmed":     len(confirmed),
                "false_positive":len(false_pos),
                "uncertain":     len(uncertain),
                "fp_rate":       round(len(false_pos) / max(len(findings), 1) * 100, 1),
            }
        }

    def bulk_analyze(self, findings: List[Dict]) -> Dict:
        """
        Bulk analyze all findings at once (faster, 1 API call).
        """
        if not findings:
            return {"confirmed": [], "false_positive": [], "summary": {}}

        system = (
            "You are a senior security analyst. Analyze multiple findings for false positives. "
            "Return ONLY valid JSON array."
        )

        finding_list = []
        for i, f in enumerate(findings):
            finding_list.append({
                "index":    i,
                "type":     f.get("type", f.get("vuln_type", "")),
                "evidence": f.get("evidence", "")[:150],
                "payload":  f.get("payload", "")[:80],
            })

        prompt = f"""Analyze these {len(findings)} security findings for false positives:
{json.dumps(finding_list, indent=2)}

Return JSON array with one entry per finding:
[{{"index": 0, "is_fp": false, "confidence": 0.9, "reason": "..."}}]"""

        response = self._call(prompt, system)

        try:
            clean = response.strip()
            if "```" in clean:
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            start = clean.find("[")
            end   = clean.rfind("]") + 1
            if start != -1 and end > start:
                analyses = json.loads(clean[start:end])

                confirmed  = []
                false_pos  = []

                for analysis in analyses:
                    idx = analysis.get("index", 0)
                    if idx < len(findings):
                        enriched = {
                            **findings[idx],
                            "fp_analysis": {
                                "is_false_positive": analysis.get("is_fp", False),
                                "confidence":        analysis.get("confidence", 0.5),
                                "reason":            analysis.get("reason", ""),
                            }
                        }
                        if analysis.get("is_fp") and analysis.get("confidence", 0) > 0.7:
                            false_pos.append(enriched)
                        else:
                            confirmed.append(enriched)

                return {
                    "confirmed":      confirmed,
                    "false_positive": false_pos,
                    "summary": {
                        "total":          len(findings),
                        "confirmed":      len(confirmed),
                        "false_positive": len(false_pos),
                        "fp_rate":        round(len(false_pos) / max(len(findings), 1) * 100, 1),
                    }
                }
        except Exception:
            pass

        return {
            "confirmed":      findings,
            "false_positive": [],
            "summary":        {"total": len(findings), "confirmed": len(findings), "fp_rate": 0}
        }
