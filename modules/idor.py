"""
IDOR (Insecure Direct Object Reference) Detection Module
Tests for unauthorized access to objects by manipulating IDs
"""

import asyncio
import re
from urllib.parse import urlparse, parse_qsl, urlencode
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from core.paths import PAYLOADS_DIR
from utils.logger import setup_logger


@dataclass
class IDORFinding:
    """Represents a confirmed or potential IDOR vulnerability"""
    url: str
    parameter: str
    original_value: str
    tested_value: str
    type: str        # 'horizontal', 'vertical', 'guid_idor', 'json_idor'
    severity: str    # 'critical', 'high', 'medium'
    confidence: str
    evidence: str
    remediation: str


class IDORScanner:
    """
    IDOR Detection Module
    Detects Insecure Direct Object References via:
    - Numeric ID manipulation (increment/decrement)
    - GUID/UUID substitution
    - Horizontal privilege escalation
    - Vertical privilege escalation
    - JSON body parameter tampering
    - Path parameter manipulation
    """

    def __init__(self, rate_limiter: RateLimiter, payload_file: str = None):  # BUG-014 NOTE: payload_file reserved for future use
        self.rate_limiter = rate_limiter
        _ = payload_file  # BUG-014 FIX: explicitly discard unused arg to suppress lint warnings
        self.logger = setup_logger("IDOR")
        self.findings: List[IDORFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(20.0, connect=10.0)

        # ID-like parameter names
        self.id_params = [
            'id', 'user_id', 'userid', 'account_id', 'accountid',
            'profile_id', 'profileid', 'order_id', 'orderid',
            'invoice_id', 'invoiceid', 'document_id', 'documentid',
            'file_id', 'fileid', 'record_id', 'recordid',
            'item_id', 'itemid', 'product_id', 'productid',
            'ticket_id', 'ticketid', 'message_id', 'messageid',
            'report_id', 'reportid', 'uid', 'pid', 'rid',
            'oid', 'aid', 'bid', 'cid', 'mid', 'tid',
            'customer_id', 'employee_id', 'member_id', 'group_id',
            'session_id', 'token', 'key', 'ref', 'reference',
            'uuid', 'guid', 'hash', 'slug', 'username', 'email'
        ]

        # UUID pattern
        self.uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            re.IGNORECASE
        )

        # Numeric pattern
        self.numeric_pattern = re.compile(r'^\d+$')

    def _is_id_param(self, param: str) -> bool:
        """Check if parameter name looks like an ID"""
        return param.lower() in self.id_params or param.lower().endswith('_id') or param.lower().endswith('id')

    def _is_numeric(self, value: str) -> bool:
        return bool(self.numeric_pattern.match(value))

    def _is_uuid(self, value: str) -> bool:
        return bool(self.uuid_pattern.match(value))

    def _generate_test_values(self, value: str) -> List[Tuple[str, str]]:
        """
        Generate test values based on original value type.
        Returns list of (test_value, description) tuples.
        """
        tests = []

        if self._is_numeric(value):
            num = int(value)
            # Increment/decrement
            if num > 1:
                tests.append((str(num - 1), "decrement"))
            tests.append((str(num + 1), "increment"))
            tests.append(("1",           "set to 1"))
            tests.append(("0",           "set to 0"))
            tests.append(("99999",       "large number"))
            tests.append((f"{num}%00",   "null byte append"))
            tests.append((f"{num} OR 1=1", "SQLi-style"))

        elif self._is_uuid(value):
            # Predictable UUIDs
            tests.append(("00000000-0000-0000-0000-000000000001", "zero UUID +1"))
            tests.append(("00000000-0000-0000-0000-000000000002", "zero UUID +2"))
            tests.append(("ffffffff-ffff-ffff-ffff-ffffffffffff", "max UUID"))

        else:
            # String-based IDs
            tests.append(("admin",        "admin substitution"))
            tests.append(("administrator","administrator substitution"))
            tests.append(("root",         "root substitution"))
            tests.append(("1",            "numeric substitution"))
            tests.append((value + "_test","append test"))

        return tests

    def _compare_responses(self, original: httpx.Response,
                            test: httpx.Response,
                            original_value: str) -> Tuple[bool, str]:
        """
        Compare original and test responses to detect IDOR.
        Returns (is_vulnerable, evidence)
        """
        orig_len  = len(original.text)
        test_len  = len(test.text)
        orig_code = original.status_code
        test_code = test.status_code

        # Both return 200 with different non-empty content = IDOR
        if orig_code == 200 and test_code == 200:
            if abs(orig_len - test_len) > 50 and test_len > 100:
                return True, (
                    f"Both requests returned 200. Original size: {orig_len}B, "
                    f"Test size: {test_len}B. Different content may indicate IDOR."
                )

        # Original 403/401 but test returns 200 = Vertical IDOR
        if orig_code in [401, 403] and test_code == 200 and test_len > 50:
            return True, (
                f"Original returned {orig_code} but test value returned 200 "
                f"with {test_len}B content. Possible vertical IDOR."
            )

        # Check for sensitive data patterns in test response
        sensitive_patterns = [
            r'"email"\s*:\s*"[^"]+"',
            r'"password"\s*:\s*"[^"]+"',
            r'"token"\s*:\s*"[^"]+"',
            r'"ssn"\s*:\s*"[^"]+"',
            r'"credit_card"\s*:\s*"[^"]+"',
            r'"phone"\s*:\s*"[^"]+"',
            r'"address"\s*:\s*"[^"]+"',
            r'"role"\s*:\s*"admin"',
            r'"is_admin"\s*:\s*true',
            r'"balance"\s*:\s*\d+',
        ]
        for pattern in sensitive_patterns:
            match = re.search(pattern, test.text, re.IGNORECASE)
            if match:
                return True, f"Sensitive data exposed: '{match.group(0)[:60]}'"

        # JSON response with different user data
        try:
            orig_json = original.json()
            test_json = test.json()
            if orig_json != test_json and test_json:
                if isinstance(test_json, dict) and any(
                    k in test_json for k in ['id', 'user', 'email', 'name', 'username', 'account']
                ):
                    return True, (  # BUG-012 FIX: removed unnecessary f-strings
                        "Different JSON objects returned. "
                        "Test response contains user data fields."
                    )
        except Exception:
            pass

        return False, ""

    async def _fetch(self, url: str, method: str = "GET",
                     data: Optional[Dict] = None) -> Optional[httpx.Response]:
        """Make HTTP request with rate limiting"""
        try:
            async def _do_request():
                if method.upper() == "POST" and data:
                    return await self.client.post(url, json=data, follow_redirects=True)
                return await self.client.get(url, follow_redirects=True)
            return await self.rate_limiter.execute_with_retry(_do_request)
        except Exception as e:
            self.logger.debug(f"Request failed {url}: {e}")
            return None

    async def test_url_parameter(self, url: str, param: str) -> Optional[IDORFinding]:
        """Test a URL parameter for IDOR"""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))

        if param not in params:
            return None

        original_value = params[param]
        if not original_value or len(original_value) > 100:
            return None

        # Get baseline response
        original_response = await self._fetch(url)
        if not original_response:
            return None

        test_values = self._generate_test_values(original_value)

        for test_value, description in test_values:
            test_params = params.copy()
            test_params[param] = test_value
            test_url = parsed._replace(query=urlencode(test_params)).geturl()

            test_response = await self._fetch(test_url)
            if not test_response:
                continue

            is_vuln, evidence = self._compare_responses(
                original_response, test_response, original_value
            )

            if is_vuln:
                idor_type = "horizontal" if test_response.status_code == 200 else "vertical"
                if self._is_uuid(original_value):
                    idor_type = "guid_idor"

                return IDORFinding(
                    url=url,
                    parameter=param,
                    original_value=original_value,
                    tested_value=test_value,
                    type=idor_type,
                    severity="high",
                    confidence="medium",
                    evidence=f"[{description}] {evidence}",
                    remediation=self._get_remediation()
                )

        return None

    async def test_path_parameter(self, url: str) -> Optional[IDORFinding]:
        """Test numeric/UUID values in URL path for IDOR"""
        parsed = urlparse(url)
        path = parsed.path

        # Find numeric segments in path
        segments = path.split('/')
        for i, segment in enumerate(segments):
            if not segment:
                continue

            if self._is_numeric(segment) and int(segment) > 0:
                original_value = segment
                test_values = self._generate_test_values(original_value)

                original_response = await self._fetch(url)
                if not original_response:
                    continue

                for test_value, description in test_values[:4]:
                    new_segments = segments.copy()
                    new_segments[i] = test_value
                    new_path = '/'.join(new_segments)
                    test_url = parsed._replace(path=new_path).geturl()

                    test_response = await self._fetch(test_url)
                    if not test_response:
                        continue

                    is_vuln, evidence = self._compare_responses(
                        original_response, test_response, original_value
                    )

                    if is_vuln:
                        return IDORFinding(
                            url=url,
                            parameter=f"path:{segment}",
                            original_value=original_value,
                            tested_value=test_value,
                            type="horizontal",
                            severity="high",
                            confidence="medium",
                            evidence=f"[Path param {description}] {evidence}",
                            remediation=self._get_remediation()
                        )

            elif self._is_uuid(segment):
                original_response = await self._fetch(url)
                if not original_response:
                    continue

                test_uuid = "00000000-0000-0000-0000-000000000001"
                new_segments = segments.copy()
                new_segments[i] = test_uuid
                new_path = '/'.join(new_segments)
                test_url = parsed._replace(path=new_path).geturl()

                test_response = await self._fetch(test_url)
                if not test_response:
                    continue

                is_vuln, evidence = self._compare_responses(
                    original_response, test_response, segment
                )
                if is_vuln:
                    return IDORFinding(
                        url=url,
                        parameter=f"path:{segment}",
                        original_value=segment,
                        tested_value=test_uuid,
                        type="guid_idor",
                        severity="high",
                        confidence="medium",
                        evidence=f"[UUID path substitution] {evidence}",
                        remediation=self._get_remediation()
                    )

        return None

    def _get_remediation(self) -> str:
        return (
            "1. Implement server-side authorization checks for every object access.\n"
            "2. Use indirect object references (map internal IDs to random tokens).\n"
            "3. Verify the authenticated user owns/has permission for the requested object.\n"
            "4. Never rely solely on obscurity (UUIDs are not authorization).\n"
            "5. Log and alert on unauthorized access attempts.\n"
            "6. Implement proper RBAC (Role-Based Access Control)."
        )

    async def scan(self, target_urls: List[str], forms: List) -> List[IDORFinding]:
        """
        Main IDOR scan method.
        target_urls: List of URLs with parameters
        forms: List of Form objects from crawler
        """
        self.logger.info(f"Starting IDOR scan on {len(target_urls)} URLs")

        headers = {
            'User-Agent': '0xHunter Security Scanner (Authorized Testing)',
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
                # Test path parameters
                tasks.append(self.test_path_parameter(url))

                # Test query parameters
                parsed = urlparse(url)
                params = dict(parse_qsl(parsed.query))
                for param in params.keys():
                    if self._is_id_param(param) or self._is_numeric(params[param]) or self._is_uuid(params[param]):
                        tasks.append(self.test_url_parameter(url, param))

            self.logger.info(f"Running {len(tasks)} IDOR tests...")
            results = await asyncio.gather(*tasks, return_exceptions=True)

            seen = set()
            for result in results:
                if isinstance(result, Exception):
                    self.logger.debug(f"IDOR test error: {result}")
                    continue
                if result:
                    key = f"{result.url}:{result.parameter}:{result.type}"
                    if key not in seen:
                        seen.add(key)
                        self.findings.append(result)
                        self.logger.warning(
                            f"IDOR [{result.severity.upper()}]: {result.url} | "
                            f"Param: {result.parameter} | "
                            f"{result.original_value} -> {result.tested_value}"
                        )

        self.logger.info(f"IDOR scan complete. Found {len(self.findings)} issues")
        return self.findings
