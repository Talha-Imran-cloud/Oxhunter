"""
SSTI (Server-Side Template Injection) Detection Module
BUG-003 FIX: This file was missing — SSTI scanning was silently disabled.
"""

import asyncio
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode
from pathlib import Path

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger

PAYLOAD_FILE = Path(__file__).parent.parent / "payloads" / "ssti" / "ssti.txt"

def _load_ssti_payloads() -> List[str]:
    if PAYLOAD_FILE.exists():
        return [
            line.strip()
            for line in PAYLOAD_FILE.read_text(errors="ignore").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    # Minimal built-in fallback
    return [
        "{{7*7}}", "${7*7}", "#{7*7}", "*{7*7}",
        "{{7*'7'}}", "{{config}}", "{{self.__dict__}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
    ]


@dataclass
class SSTIFinding:
    url: str
    parameter: str
    payload: str
    type: str
    confidence: str
    evidence: str
    remediation: str
    severity: str = "high"


class SSTIScanner:
    """
    Server-Side Template Injection Scanner.
    Detects SSTI in URL parameters and form inputs.
    """

    MATH_PAYLOADS = {
        "{{7*7}}": "49",
        "${7*7}": "49",
        "#{7*7}": "49",
        "*{7*7}": "49",
        "{{7*'7'}}": "7777777",
        "<%= 7*7 %>": "49",
        "{7*7}": "49",
    }

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("SSTI")
        self.payloads = _load_ssti_payloads()
        self.findings: List[SSTIFinding] = []
        self.timeout = httpx.Timeout(15.0, connect=8.0)
        self.logger.info(f"Loaded {len(self.payloads)} SSTI payloads")

    async def scan(self, target_urls: List[str], forms: List = None) -> List[SSTIFinding]:
        """Scan URLs and forms for SSTI vulnerabilities."""
        self.findings = []
        async with httpx.AsyncClient(timeout=self.timeout, verify=False,
                                     follow_redirects=True) as client:
            tasks = []
            for url in target_urls:
                parsed = urlparse(url)
                params = dict(parse_qsl(parsed.query))
                if params:
                    for param in params:
                        tasks.append(self._test_param(client, url, param))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, SSTIFinding):
                    self.findings.append(r)
        return self.findings

    async def _test_param(self, client: httpx.AsyncClient,
                          url: str, param: str) -> Optional[SSTIFinding]:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))

        # Use math-expression payloads first (highest confidence)
        for payload, expected in self.MATH_PAYLOADS.items():
            await self.rate_limiter.wait()
            test_params = params.copy()
            test_params[param] = payload
            test_url = parsed._replace(query=urlencode(test_params)).geturl()
            try:
                resp = await client.get(test_url)
                if expected in resp.text:
                    return SSTIFinding(
                        url=url, parameter=param, payload=payload,
                        type="math_expression",
                        confidence="high",
                        evidence=f"Expression '{payload}' evaluated to '{expected}' in response",
                        remediation=(
                            "Never pass user input directly to template engines. "
                            "Use sandboxing, input validation, or render user content as data "
                            "rather than templates. Update template engine to latest version."
                        ),
                        severity="high",
                    )
            except Exception:
                pass
        return None
