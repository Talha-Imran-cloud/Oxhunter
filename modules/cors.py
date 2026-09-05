"""
CORS (Cross-Origin Resource Sharing) Misconfiguration Detection Module
Tests for insecure CORS policies that allow unauthorized cross-origin access
"""

import asyncio
from urllib.parse import urlparse
from typing import List, Optional
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class CORSFinding:
    """Represents a CORS misconfiguration finding"""
    url: str
    type: str        # 'wildcard', 'origin_reflection', 'null_origin', 'trusted_subdomain', 'http_allowed'
    severity: str
    confidence: str
    origin_sent: str
    acao_header: str
    acac_header: str
    evidence: str
    remediation: str


class CORSScanner:
    """
    CORS Misconfiguration Detection Module
    Detects:
    - Wildcard origin with credentials
    - Reflected origin (any origin allowed)
    - Null origin allowed
    - Trusted subdomain bypass
    - HTTP downgrade allowed
    - Pre-domain bypass (evildomain.com matches victim.com)
    """

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("CORS")
        self.findings: List[CORSFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(15.0, connect=10.0)

    def _get_test_origins(self, target_url: str) -> List[tuple]:
        """
        Generate test origins based on target URL.
        Returns list of (origin, test_type, description)
        """
        parsed = urlparse(target_url)
        host = parsed.netloc
        scheme = parsed.scheme
        domain_parts = host.split('.')

        origins = []

        # 1. Arbitrary external origin
        origins.append(("https://evil.com",                    "origin_reflection",    "Arbitrary external origin"))
        origins.append(("https://attacker.com",                "origin_reflection",    "Attacker origin"))

        # 2. Null origin
        origins.append(("null",                                "null_origin",          "Null origin"))

        # 3. HTTP version of target (downgrade)
        if scheme == "https":
            origins.append((f"http://{host}",                  "http_allowed",         "HTTP downgrade of target"))

        # 4. Pre-domain bypass (evilexample.com)
        if len(domain_parts) >= 2:
            base = '.'.join(domain_parts[-2:])
            origins.append((f"https://evil{base}",             "pre_domain_bypass",    f"Pre-domain bypass: evil{base}"))
            origins.append((f"https://evil.{base}",            "subdomain_bypass",     f"Subdomain bypass: evil.{base}"))

        # 5. Post-domain bypass (example.com.evil.com)
        origins.append((f"https://{host}.evil.com",            "post_domain_bypass",   f"Post-domain bypass"))

        # 6. Trusted subdomain
        if len(domain_parts) >= 2:
            base = '.'.join(domain_parts[-2:])
            origins.append((f"https://sub.{base}",             "subdomain",            f"Subdomain: sub.{base}"))
            origins.append((f"https://test.{base}",            "subdomain",            f"Subdomain: test.{base}"))

        # 7. Special bypass tricks
        origins.append((f"https://{host}@evil.com",            "at_bypass",            "@ bypass"))
        origins.append(("https://evil.com#" + host,            "fragment_bypass",      "Fragment bypass"))

        return origins

    async def _send_cors_request(self, url: str, origin: str) -> Optional[httpx.Response]:
        """Send request with custom Origin header"""
        try:
            async def _do_request():
                return await self.client.get(
                    url,
                    headers={
                        'Origin': origin,
                        'Accept': '*/*',
                    },
                    follow_redirects=True
                )
            return await self.rate_limiter.execute_with_retry(_do_request)
        except Exception as e:
            self.logger.debug(f"CORS request failed {url}: {e}")
            return None

    async def _send_preflight(self, url: str, origin: str) -> Optional[httpx.Response]:
        """Send OPTIONS preflight request"""
        try:
            async def _do_request():
                return await self.client.options(
                    url,
                    headers={
                        'Origin': origin,
                        'Access-Control-Request-Method': 'GET',
                        'Access-Control-Request-Headers': 'Authorization, Content-Type',
                    },
                    follow_redirects=True
                )
            return await self.rate_limiter.execute_with_retry(_do_request)
        except Exception as e:
            self.logger.debug(f"Preflight failed {url}: {e}")
            return None

    def _analyze_cors_headers(self, response: httpx.Response,
                               origin_sent: str, test_type: str) -> Optional[tuple]:
        """
        Analyze CORS response headers.
        Returns (is_vulnerable, severity, confidence, evidence) or None
        """
        acao = response.headers.get('access-control-allow-origin', '')
        acac = response.headers.get('access-control-allow-credentials', '')
        acam = response.headers.get('access-control-allow-methods', '')
        acah = response.headers.get('access-control-allow-headers', '')

        if not acao:
            return None

        is_credentials = acac.lower() == 'true'

        # 1. Wildcard with credentials (impossible combo but still check)
        if acao == '*' and is_credentials:
            return (
                "critical",
                "high",
                "ACAO: * with ACAC: true — browsers block this but config is dangerously wrong"
            )

        # 2. Wildcard without credentials (medium risk)
        if acao == '*':
            return (
                "medium",
                "high",
                "ACAO: * — any origin can read responses (no credentials, but data may be sensitive)"
            )

        # 3. Origin reflected with credentials (Critical)
        if acao == origin_sent and is_credentials:
            return (
                "critical",
                "high",
                f"Origin '{origin_sent}' is reflected in ACAO with credentials=true. "
                "Attacker can make authenticated cross-origin requests."
            )

        # 4. Origin reflected without credentials (High)
        if acao == origin_sent:
            return (
                "high",
                "high",
                f"Origin '{origin_sent}' is reflected in ACAO (no credentials). "
                "Attacker can read responses from this origin."
            )

        # 5. Null origin allowed with credentials (Critical)
        if acao == 'null' and is_credentials:
            return (
                "critical",
                "high",
                "Null origin allowed with credentials=true. "
                "Sandbox iframe attacks possible."
            )

        # 6. Null origin without credentials (Medium)
        if acao == 'null':
            return (
                "medium",
                "medium",
                "Null origin allowed. Sandboxed iframes can read responses."
            )

        return None

    async def test_url(self, url: str) -> List[CORSFinding]:
        """Test a single URL for CORS misconfigurations"""
        findings = []
        test_origins = self._get_test_origins(url)
        seen_types = set()

        for origin, test_type, description in test_origins:
            # Regular request
            response = await self._send_cors_request(url, origin)
            if not response:
                continue

            result = self._analyze_cors_headers(response, origin, test_type)
            if result:
                severity, confidence, evidence = result
                type_key = f"{test_type}:{severity}"

                if type_key not in seen_types:
                    seen_types.add(type_key)
                    acao = response.headers.get('access-control-allow-origin', '')
                    acac = response.headers.get('access-control-allow-credentials', '')

                    findings.append(CORSFinding(
                        url=url,
                        type=test_type,
                        severity=severity,
                        confidence=confidence,
                        origin_sent=origin,
                        acao_header=acao,
                        acac_header=acac,
                        evidence=f"[{description}] {evidence}",
                        remediation=self._get_remediation(test_type)
                    ))
                    self.logger.warning(
                        f"CORS [{severity.upper()}]: {url} | "
                        f"Type: {test_type} | Origin: {origin} | ACAO: {acao}"
                    )

            # Also test preflight
            preflight = await self._send_preflight(url, origin)
            if preflight:
                result = self._analyze_cors_headers(preflight, origin, test_type)
                if result:
                    severity, confidence, evidence = result
                    type_key = f"preflight:{test_type}:{severity}"
                    if type_key not in seen_types:
                        seen_types.add(type_key)
                        acao = preflight.headers.get('access-control-allow-origin', '')
                        acac = preflight.headers.get('access-control-allow-credentials', '')
                        findings.append(CORSFinding(
                            url=url,
                            type=f"preflight_{test_type}",
                            severity=severity,
                            confidence=confidence,
                            origin_sent=origin,
                            acao_header=acao,
                            acac_header=acac,
                            evidence=f"[Preflight/{description}] {evidence}",
                            remediation=self._get_remediation(test_type)
                        ))

        return findings

    def _get_remediation(self, test_type: str) -> str:
        base = (
            "1. Define an explicit allowlist of trusted origins — never reflect Origin header blindly.\n"
            "2. Do not use wildcard '*' with Access-Control-Allow-Credentials: true.\n"
            "3. Never allow 'null' origin in production.\n"
        )
        specific = {
            "origin_reflection":  "4. Validate Origin against a strict server-side allowlist before reflecting.\n",
            "null_origin":        "4. Explicitly reject 'null' origin in your CORS policy.\n",
            "http_allowed":       "4. Only allow HTTPS origins; reject HTTP origins to prevent downgrade attacks.\n",
            "pre_domain_bypass":  "4. Use exact domain matching, not suffix matching (e.g., avoid endsWith check).\n",
            "subdomain_bypass":   "4. Audit all subdomains — a compromised subdomain can bypass CORS allowlist.\n",
            "post_domain_bypass": "4. Use exact origin matching, not contains/prefix matching.\n",
        }
        return base + specific.get(test_type, "4. Review and harden your CORS configuration.\n") + \
               "5. Set Vary: Origin header when CORS responses vary by origin."

    async def scan(self, target_urls: List[str], forms: List = None) -> List[CORSFinding]:  # NEW-BUG-001 FIX
        forms = forms or []  # NEW-BUG-001 FIX
        """Main CORS scan method"""
        # Deduplicate URLs (test unique base URLs only)
        unique_urls = list({urlparse(u).scheme + "://" + urlparse(u).netloc + urlparse(u).path
                           for u in target_urls})
        self.logger.info(f"Starting CORS scan on {len(unique_urls)} unique endpoints")

        headers = {
            'User-Agent': '0xHunter Security Scanner (Authorized Testing)',
        }

        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=True,
            verify=False
        ) as client:
            self.client = client
            tasks = [self.test_url(url) for url in unique_urls[:50]]  # cap at 50

            self.logger.info(f"Running CORS tests on {len(tasks)} endpoints...")
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    self.logger.debug(f"CORS test error: {result}")
                    continue
                if isinstance(result, list):
                    self.findings.extend(result)

        self.logger.info(f"CORS scan complete. Found {len(self.findings)} misconfigurations")
        return self.findings
