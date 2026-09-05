"""
Security Headers Detection Module
Checks for missing or misconfigured security headers
"""

from typing import List, Optional
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class HeaderFinding:
    """Represents a security header issue"""
    url: str
    header_name: str
    type: str  # 'missing', 'weak', 'misconfigured'
    confidence: str
    evidence: str
    remediation: str
    severity: str = "medium"


class HeadersScanner:
    """
    Security Headers Scanner
    Checks for important security headers in HTTP responses.
    """

    # Security headers that should be present
    REQUIRED_HEADERS = {
        'Strict-Transport-Security': {
            'description': 'HSTS - Forces HTTPS connections',
            'severity': 'medium',
            'remediation': "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        },
        'X-Content-Type-Options': {
            'description': 'Prevents MIME-type sniffing',
            'severity': 'medium',
            'remediation': "Add: X-Content-Type-Options: nosniff"
        },
        'X-Frame-Options': {
            'description': 'Clickjacking protection',
            'severity': 'high',  # BUG-002 FIX: was 'High' (capital) causing mismatch
            'remediation': "Add: X-Frame-Options: DENY or SAMEORIGIN. Prefer Content-Security-Policy: frame-ancestors."
        },
        'Content-Security-Policy': {
            'description': 'XSS and data injection protection',
            'severity': 'high',  # BUG-002 FIX: was 'High' (capital) causing mismatch
            'remediation': "Add a strict Content-Security-Policy header. Start with: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        },
        'Referrer-Policy': {
            'description': 'Controls referrer information leakage',
            'severity': 'low',  # BUG-002 FIX: lowercase for consistent normalisation
            'remediation': "Add: Referrer-Policy: strict-origin-when-cross-origin or no-referrer"
        },
        'Permissions-Policy': {
            'description': 'Controls browser features/APIs',
            'severity': 'low',  # BUG-002 FIX: lowercase for consistent normalisation
            'remediation': "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"
        },
    }

    # Headers that should NOT be present (information disclosure)
    BAD_HEADERS = {
        'X-Powered-By': {
            'description': 'Reveals server technology',
            'severity': 'low',
            'remediation': "Remove X-Powered-By header from server configuration"
        },
        'Server': {
            'description': 'Reveals server software/version',
            'severity': 'info',
            'remediation': "Configure server to suppress or genericize Server header"
        },
        'X-AspNet-Version': {
            'description': 'Reveals ASP.NET version',
            'severity': 'low',
            'remediation': "Remove X-AspNet-Version header from web.config"
        },
        'X-AspNetMvc-Version': {
            'description': 'Reveals ASP.NET MVC version',
            'severity': 'low',
            'remediation': "Remove X-AspNetMvc-Version header"
        },
    }

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("Headers")
        self.findings: List[HeaderFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(8.0, connect=5.0)

    async def _fetch(self, url: str) -> Optional[httpx.Response]:
        """Make HTTP request with rate limiting"""
        try:
            async def _do_request():
                return await self.client.get(url, follow_redirects=True)
            return await self.rate_limiter.execute_with_retry(_do_request)
        except Exception as e:
            self.logger.warning(f"Request failed {url}: {e}")
            return None

    def _check_header_value(self, header_name: str, header_value: str) -> Optional[str]:
        """Check if a header value is weak or misconfigured"""
        header_lower = header_name.lower()
        value_lower = header_value.lower()

        if header_lower == 'x-frame-options':
            if value_lower not in ['deny', 'sameorigin']:
                return f"Weak X-Frame-Options value: {header_value}"

        if header_lower == 'content-security-policy':
            if "unsafe-inline" in value_lower and "nonce" not in value_lower:
                return "CSP allows unsafe-inline without nonce"
            if "* " in value_lower or value_lower.endswith("*"):
                return "CSP contains wildcard (*) source"

        if header_lower == 'strict-transport-security':
            if 'max-age=' in value_lower:
                try:
                    max_age = int(value_lower.split('max-age=')[1].split(';')[0].strip())
                    if max_age < 31536000:  # Less than 1 year
                        return f"HSTS max-age is too short: {max_age} seconds"
                except Exception:
                    pass

        return None

    async def scan(self, target_urls: List[str]) -> List[HeaderFinding]:
        """
        Scan target URLs for security header issues.
        Checks unique domains only to avoid redundant checks.
        """
        # Reset findings list on each scan call to prevent duplicate accumulation
        self.findings = []
        if not target_urls:
            return self.findings

        # Check only unique domains
        urls_to_check = []
        seen_domains = set()

        from urllib.parse import urlparse
        for url in target_urls[:10]:  # Check first 10 URLs max
            domain = urlparse(url).netloc
            if domain not in seen_domains:
                seen_domains.add(domain)
                urls_to_check.append(url)

        self.logger.info(f"Starting Headers scan on {len(urls_to_check)} URLs")

        headers = {
            'User-Agent': '0xHunter Security Scanner (Authorized Testing)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }

        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=True,
            verify=False
        ) as client:
            self.client = client

            for url in urls_to_check:
                response = await self._fetch(url)
                if not response:
                    continue

                resp_headers = {k.lower(): v for k, v in response.headers.items()}

                # Check for missing required headers
                for header_name, info in self.REQUIRED_HEADERS.items():
                    header_lower = header_name.lower()

                    if header_lower not in resp_headers:
                        # BUG-002 FIX: pass per-header severity from REQUIRED_HEADERS dict
                        # Previously severity was always hardcoded 'medium' on the dataclass default,
                        # ignoring the 'high'/'low' values defined above (CSP and X-Frame-Options were
                        # reported as Medium instead of High).
                        self.findings.append(HeaderFinding(
                            url=url,
                            header_name=header_name,
                            type="missing",
                            confidence="high",
                            evidence=f"Missing header: {header_name} - {info['description']}",
                            remediation=info['remediation'],
                            severity=info['severity'],  # ← FIX: was missing, now uses per-header value
                        ))
                        self.logger.warning(f"Headers: Missing {header_name} on {url}")
                    else:
                        # Check if present header is weak/misconfigured
                        weak = self._check_header_value(header_name, resp_headers[header_lower])
                        if weak:
                            self.findings.append(HeaderFinding(
                                url=url,
                                header_name=header_name,
                                type="weak",
                                confidence="medium",
                                evidence=f"Weak {header_name}: {weak}",
                                remediation=info['remediation'],
                                severity=info['severity'],  # ← FIX: same fix for weak findings
                            ))

                # Check for bad headers (information disclosure)
                for header_name, info in self.BAD_HEADERS.items():
                    header_lower = header_name.lower()
                    if header_lower in resp_headers:
                        self.findings.append(HeaderFinding(
                            url=url,
                            header_name=header_name,
                            type="information_disclosure",
                            confidence="low",
                            evidence=f"Information disclosure: {header_name}: {resp_headers[header_lower]}",
                            remediation=info['remediation'],
                            severity=info['severity'],  # ← FIX: same fix for bad headers
                        ))
                        self.logger.warning(f"Headers: {header_name} reveals info on {url}")

        self.logger.info(f"Headers scan complete. Found {len(self.findings)} issues")
        return self.findings
