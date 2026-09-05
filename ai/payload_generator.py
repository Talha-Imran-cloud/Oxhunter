"""
OXHUNTER - ai/payload_generator.py
AI-Powered Payload Generator using Groq API (Free)
"""

import os
import json
import requests
from typing import List, Dict, Optional

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = "llama-3.3-70b-versatile"


class AIPayloadGenerator:
    """
    AI-Powered Payload Generator
    Uses Groq API (Free) with LLaMA 3.1 70B
    Generates context-aware payloads based on:
    - Target technology stack
    - WAF detected
    - Vulnerability type
    - Previous failed payloads
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GROQ_API_KEY", "")
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type":  "application/json",
        }
        self.history: List[Dict] = []

    def _call(self, prompt: str, system: str = "", max_tokens: int = 800) -> str:
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
                    "max_tokens":  max_tokens,
                    "temperature": 0.7,
                },
                timeout=30
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"].strip()
            return ""
        except Exception as e:
            print(f"[!] Groq API error: {e}")
            return ""

    def generate_xss_payloads(self, context: Dict) -> List[str]:
        """Generate XSS payloads based on target context"""
        tech  = context.get("technology", "unknown")
        waf   = context.get("waf", "none")
        param = context.get("parameter", "q")

        system = (
            "You are a security researcher generating XSS payloads for authorized pen testing. "
            "Return ONLY a JSON array of payload strings. No explanation, no markdown."
        )

        prompt = f"""Generate 10 XSS payloads for:
- Technology: {tech}
- WAF: {waf}
- Parameter: {param}
- Make payloads bypass the WAF if detected
- Include reflected, DOM-based variations
Return ONLY JSON array: ["payload1", "payload2", ...]"""

        response = self._call(prompt, system)
        return self._parse_list(response)

    def generate_sqli_payloads(self, context: Dict) -> List[str]:
        """Generate SQLi payloads based on DB type"""
        db    = context.get("database", "MySQL")
        waf   = context.get("waf", "none")
        blind = context.get("blind", False)

        system = (
            "You are a security researcher generating SQL injection payloads for authorized pen testing. "
            "Return ONLY a JSON array of payload strings. No explanation."
        )

        prompt = f"""Generate 10 SQL injection payloads for:
- Database: {db}
- WAF: {waf}
- Blind injection: {blind}
- Include error-based, time-based if blind=True
Return ONLY JSON array: ["payload1", "payload2", ...]"""

        response = self._call(prompt, system)
        return self._parse_list(response)

    def generate_ssrf_payloads(self, context: Dict) -> List[str]:
        """Generate SSRF payloads"""
        cloud = context.get("cloud", "AWS")

        system = (
            "You are a security researcher generating SSRF payloads for authorized pen testing. "
            "Return ONLY a JSON array. No explanation."
        )

        prompt = f"""Generate 10 SSRF payloads targeting:
- Cloud: {cloud}
- Include metadata endpoints, internal services
Return ONLY JSON array: ["payload1", "payload2", ...]"""

        response = self._call(prompt, system)
        return self._parse_list(response)

    def generate_bypass_payloads(self, vuln_type: str,
                                  waf_name: str,
                                  failed_payloads: List[str]) -> List[str]:
        """Generate WAF bypass payloads based on failed attempts"""
        system = (
            "You are a WAF bypass expert generating payloads for authorized security testing. "
            "Return ONLY a JSON array. No explanation."
        )

        prompt = f"""Generate 10 WAF bypass payloads:
- Vulnerability: {vuln_type}
- WAF: {waf_name}
- These payloads FAILED (avoid same patterns):
{json.dumps(failed_payloads[:5], indent=2)}
- Use encoding, case variation, comment injection
Return ONLY JSON array: ["payload1", "payload2", ...]"""

        response = self._call(prompt, system)
        return self._parse_list(response)

    def generate_custom(self, vuln_type: str,
                         target_info: Dict,
                         count: int = 10) -> List[str]:
        """Generate custom payloads for any vulnerability type"""
        system = (
            "You are a security researcher generating vulnerability payloads for authorized pen testing. "
            "Return ONLY a JSON array of payload strings."
        )

        prompt = f"""Generate {count} {vuln_type} payloads for:
Target info: {json.dumps(target_info, indent=2)}
Return ONLY JSON array: ["payload1", "payload2", ...]"""

        response = self._call(prompt, system)
        return self._parse_list(response)

    def _parse_list(self, response: str) -> List[str]:
        """Parse JSON array from AI response"""
        if not response:
            return []
        try:
            # Clean markdown if present
            clean = response.strip()
            if "```" in clean:
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            # Find JSON array
            start = clean.find("[")
            end   = clean.rfind("]") + 1
            if start != -1 and end > start:
                return json.loads(clean[start:end])
        except Exception:
            pass
        return []
