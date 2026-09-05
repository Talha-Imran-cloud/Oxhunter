"""
SSRF (Server-Side Request Forgery) Detection Module
Tests for SSRF vulnerabilities in URL parameters and form inputs
"""

import asyncio
from urllib.parse import urlparse, parse_qsl, urlencode
from typing import List, Dict, Optional
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from core.paths import PAYLOADS_DIR
from utils.logger import setup_logger


@dataclass
class SSRFFinding:
    """Represents a confirmed or potential SSRF vulnerability"""
    url: str
    parameter: str
    payload: str
    type: str  # 'internal_access', 'cloud_metadata', 'blind_ssrf'
    severity: str  # 'critical', 'high', 'medium', 'low'
    confidence: str
    evidence: str
    remediation: str


class SSRFScanner:
    """
    SSRF Detection Module
    Tests URL parameters and form inputs for SSRF vulnerabilities.
    Checks for internal network access, cloud metadata, and blind SSRF.
    """

    def __init__(self, rate_limiter: RateLimiter, payload_file: str = None):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("SSRF")
        resolved = str(PAYLOADS_DIR / "ssrf/ssrf.txt") if payload_file is None else payload_file
        self.payloads = self._load_payloads(resolved)
        self.findings: List[SSRFFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(8.0, connect=5.0)

        # SSRF-prone parameter names
        self.ssrf_params = [
            'url', 'uri', 'path', 'dest', 'destination', 'redirect',
            'redirect_url', 'redirect_uri', 'return', 'return_url',
            'next', 'next_url', 'target', 'link', 'src', 'source',
            'callback', 'webhook', 'api', 'endpoint', 'host', 'domain',
            'site', 'file', 'load', 'fetch', 'proxy', 'forward',
            'image', 'img', 'picture', 'avatar', 'icon', 'feed',
            'rss', 'xml', 'data', 'resource', 'service', 'server'
        ]

        # Cloud metadata indicators in response
        self.metadata_indicators = [
            'ami-id', 'instance-id', 'security-credentials',
            'computeMetadata', 'metadata.google.internal',
            'iam/security-credentials', 'latest/meta-data',
            'metadata/instance', 'MANAGED_IDENTITY_TOKEN'
        ]

        # Internal network response indicators
        self.internal_indicators = [
            'Connection refused', 'Connection timed out',
            'root:x:0:0', 'localhost', '127.0.0.1',
            'internal server error', 'nginx', 'apache',
            'IIS', 'X-Powered-By', 'Server:', 'redis',
            'mongodb', 'postgresql', 'mysql'
        ]

    def _load_payloads(self, filepath: str) -> List[str]:
        """Load SSRF payloads from file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            self.logger.info(f"Loaded {len(payloads)} SSRF payloads")
            return payloads
        except FileNotFoundError:
            self.logger.warning(f"Payload file not found: {filepath}. Using defaults.")
            return self._default_payloads()

    def _default_payloads(self) -> List[str]:
        """Default SSRF payloads"""
        return [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://localhost/",
            "http://127.0.0.1/",
            "http://0.0.0.0/",
            "http://localhost:8080/",
            "http://localhost:3000/",
            "http://localhost:9200/",
            "http://localhost:6379/",
            "http://kubernetes.default.svc/",
            "file:///etc/passwd",
        ]

    async def _fetch(self, url: str, method: str = "GET", data: Optional[Dict] = None) -> Optional[httpx.Response]:
        """Make HTTP request with rate limiting"""
        try:
            async def _do_request():
                if method.upper() == "POST" and data:
                    return await self.client.post(url, data=data, follow_redirects=False)
                return await self.client.get(url, follow_redirects=False)
            return await self.rate_limiter.execute_with_retry(_do_request)
        except Exception as e:
            self.logger.debug(f"Request failed {url}: {e}")
            return None

    def _check_ssrf_response(self, response: httpx.Response, payload: str) -> tuple:
        """
        Analyze response for SSRF indicators.
        Returns (is_vulnerable, ssrf_type, severity, evidence)
        """
        response_text = response.text.lower()
        headers_str = str(response.headers).lower()

        # Check for cloud metadata leak (Critical)
        for indicator in self.metadata_indicators:
            if indicator.lower() in response_text:
                return True, "cloud_metadata", "critical", f"Cloud metadata leaked: '{indicator}' found in response"

        # Check file read via SSRF (Critical)
        if "root:x:0:0" in response.text or "daemon:x:" in response.text:
            return True, "file_read", "critical", "Local file /etc/passwd content detected in response"

        # Check internal service response (High)
        if response.status_code in [200, 301, 302, 403]:
            for indicator in self.internal_indicators:
                if indicator.lower() in response_text or indicator.lower() in headers_str:
                    return True, "internal_access", "high", f"Internal service indicator found: '{indicator}'"

        # Check redirect to internal (High)
        location = response.headers.get('location', '')
        if location and any(internal in location for internal in ['127.0.0.1', 'localhost', '169.254', '10.', '192.168.', '172.16.']):
            return True, "internal_redirect", "high", f"Redirect to internal address: {location}"

        # Response time difference check for blind SSRF (Medium)
        if response.status_code == 200 and len(response.text) > 100:
            if any(kw in payload.lower() for kw in ['localhost', '127.0.0.1', '169.254', 'metadata']):
                return True, "blind_ssrf", "medium", f"Possible blind SSRF - server fetched internal URL (status: {response.status_code})"

        return False, None, None, None

    def _is_ssrf_param(self, param: str) -> bool:
        """Check if parameter name suggests SSRF potential"""
        param_lower = param.lower()
        return any(ssrf_param in param_lower for ssrf_param in self.ssrf_params)

    async def test_url_parameter(self, url: str, param: str, payload: str) -> Optional[SSRFFinding]:
        """Test a single URL parameter with SSRF payload"""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))

        if param not in params:
            return None

        # Inject SSRF payload
        test_params = params.copy()
        test_params[param] = payload
        test_query = urlencode(test_params)
        test_url = parsed._replace(query=test_query).geturl()

        response = await self._fetch(test_url)
        if not response:
            return None

        is_vuln, ssrf_type, severity, evidence = self._check_ssrf_response(response, payload)

        if is_vuln:
            return SSRFFinding(
                url=url,
                parameter=param,
                payload=payload,
                type=ssrf_type,
                severity=severity,
                confidence="high" if ssrf_type == "cloud_metadata" else "medium",
                evidence=evidence,
                remediation=(
                    "1. Validate and whitelist allowed URLs/domains.\n"
                    "2. Block requests to private IP ranges (RFC 1918).\n"
                    "3. Disable unnecessary URL schemes (file://, gopher://, dict://).\n"
                    "4. Use a firewall to block outbound requests from server.\n"
                    "5. Never trust user-supplied URLs for server-side requests."
                )
            )
        return None

    async def test_form(self, form_action: str, form_method: str,
                        inputs: List[Dict], payload: str) -> Optional[SSRFFinding]:
        """Test form inputs for SSRF"""
        data = {}
        target_input = None

        for inp in inputs:
            name = inp.get('name', '')
            if name:
                if self._is_ssrf_param(name) or inp.get('type') in ['url', 'text']:
                    data[name] = payload
                    target_input = name
                else:
                    data[name] = inp.get('value', 'test')

        if not target_input:
            return None

        if form_method.upper() == "POST":
            response = await self._fetch(form_action, method="POST", data=data)
        else:
            test_url = f"{form_action}?{urlencode(data)}"
            response = await self._fetch(test_url)

        if not response:
            return None

        is_vuln, ssrf_type, severity, evidence = self._check_ssrf_response(response, payload)

        if is_vuln:
            return SSRFFinding(
                url=form_action,
                parameter=target_input,
                payload=payload,
                type=ssrf_type,
                severity=severity,
                confidence="medium",
                evidence=f"Form SSRF: {evidence}",
                remediation=(
                    "1. Validate and whitelist allowed URLs/domains.\n"
                    "2. Block requests to private IP ranges.\n"
                    "3. Disable file:// and other dangerous URL schemes.\n"
                    "4. Implement network-level egress filtering."
                )
            )
        return None

    async def scan(self, target_urls: List[str], forms: List) -> List[SSRFFinding]:
        """
        Main SSRF scan method.
        target_urls: List of URLs with parameters
        forms: List of Form objects from crawler
        """
        self.logger.info(f"Starting SSRF scan on {len(target_urls)} URLs and {len(forms)} forms")

        headers = {
            'User-Agent': '0xHunter Security Scanner (Authorized Testing)',
            'Accept': '*/*',
        }

        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=False,
            verify=False
        ) as client:
            self.client = client
            tasks = []

            # Test URL parameters (focus on SSRF-prone ones)
            for url in target_urls:
                parsed = urlparse(url)
                params = dict(parse_qsl(parsed.query))
                for param in params.keys():
                    # Prioritize SSRF-prone parameter names
                    if self._is_ssrf_param(param):
                        for payload in self.payloads[:8]:
                            tasks.append(self.test_url_parameter(url, param, payload))
                    else:
                        # Test all params with top cloud metadata payloads
                        for payload in self.payloads[:3]:
                            tasks.append(self.test_url_parameter(url, param, payload))

            # Test forms
            for form in forms:
                for payload in self.payloads[:5]:
                    tasks.append(self.test_form(
                        form.action, form.method, form.inputs, payload
                    ))

            self.logger.info(f"Running {len(tasks)} SSRF tests...")
            results = await asyncio.gather(*tasks, return_exceptions=True)

            seen = set()
            for result in results:
                if isinstance(result, Exception):
                    self.logger.debug(f"SSRF test error: {result}")
                    continue
                if result:
                    key = f"{result.url}:{result.parameter}:{result.type}"
                    if key not in seen:
                        seen.add(key)
                        self.findings.append(result)
                        self.logger.warning(
                            f"SSRF Found [{result.severity.upper()}]: {result.url} | "
                            f"Param: {result.parameter} | Type: {result.type}"
                        )

        self.logger.info(f"SSRF scan complete. Found {len(self.findings)} issues")
        return self.findings
