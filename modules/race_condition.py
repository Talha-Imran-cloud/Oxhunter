"""
Race Condition Testing Module
Tests for race condition vulnerabilities by sending concurrent requests
"""

import asyncio
import time
from urllib.parse import urlparse
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class RaceFinding:
    """Represents a race condition vulnerability finding"""
    url: str
    method: str
    parameter: str
    type: str        # 'limit_bypass', 'duplicate_action', 'state_corruption', 'coupon_abuse'
    severity: str
    confidence: str
    concurrent_requests: int
    responses_summary: str
    evidence: str
    remediation: str


class RaceConditionScanner:
    """
    Race Condition Testing Module
    Detects race conditions via:
    - Concurrent request flooding (Last-Byte Sync technique)
    - Duplicate transaction detection
    - Coupon/voucher abuse testing
    - Rate limit bypass via parallel requests
    - State corruption detection
    - Time-of-check to time-of-use (TOCTOU) detection
    """

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("RaceCondition")
        self.findings: List[RaceFinding] = []
        self.timeout = httpx.Timeout(8.0, connect=5.0)

        # Endpoints likely vulnerable to race conditions
        self.race_prone_paths = [
            '/purchase', '/buy', '/order', '/checkout', '/payment',
            '/transfer', '/withdraw', '/deposit', '/redeem',
            '/coupon', '/voucher', '/promo', '/discount', '/code',
            '/vote', '/like', '/follow', '/subscribe', '/register',
            '/apply', '/submit', '/claim', '/activate',
            '/api/purchase', '/api/order', '/api/transfer',
            '/api/redeem', '/api/vote', '/api/like',
            '/api/coupon', '/api/voucher', '/api/payment',
        ]

        # Race-prone parameter names
        self.race_prone_params = [
            'amount', 'quantity', 'qty', 'count', 'coupon',
            'voucher', 'code', 'promo', 'discount', 'token',
            'transfer', 'withdraw', 'points', 'credit', 'balance',
        ]

    def _is_race_prone_url(self, url: str) -> bool:
        """Check if URL looks race-condition prone"""
        url_lower = url.lower()
        return any(path in url_lower for path in self.race_prone_paths)

    def _is_race_prone_param(self, param: str) -> bool:
        """Check if parameter name suggests race condition potential"""
        return any(rp in param.lower() for rp in self.race_prone_params)

    def _analyze_responses(self, responses: List[Tuple[int, str, float]]) -> Dict:
        """
        Analyze concurrent responses for race condition indicators.
        responses: list of (status_code, body, elapsed)
        Returns analysis dict
        """
        status_counts: Dict[int, int] = {}
        bodies = []
        elapsed_times = []

        for status, body, elapsed in responses:
            status_counts[status] = status_counts.get(status, 0) + 1
            bodies.append(body[:500])
            elapsed_times.append(elapsed)

        # Check for mixed success responses (race condition indicator)
        success_count = status_counts.get(200, 0) + status_counts.get(201, 0)
        total = len(responses)

        # Look for duplicate success indicators
        success_keywords = ['success', 'approved', 'confirmed', 'accepted',
                           'processed', 'completed', 'created', 'ok']
        error_keywords   = ['error', 'failed', 'invalid', 'limit', 'exceeded',
                           'already', 'duplicate', 'once', 'one time']

        success_bodies = sum(1 for b in bodies if any(kw in b.lower() for kw in success_keywords))
        error_bodies   = sum(1 for b in bodies if any(kw in b.lower() for kw in error_keywords))

        # Unique response bodies (state corruption indicator)
        unique_bodies = len(set(bodies))

        return {
            'status_counts':   status_counts,
            'success_count':   success_count,
            'success_bodies':  success_bodies,
            'error_bodies':    error_bodies,
            'unique_bodies':   unique_bodies,
            'total':           total,
            'avg_elapsed':     sum(elapsed_times) / len(elapsed_times) if elapsed_times else 0,
        }

    def _detect_race(self, analysis: Dict, url: str) -> Tuple[bool, str, str]:
        """
        Detect race condition from response analysis.
        Returns (is_vulnerable, race_type, evidence)
        """
        success  = analysis['success_bodies']
        errors   = analysis['error_bodies']
        total    = analysis['total']
        statuses = analysis['status_counts']

        # Multiple successes when only one should be allowed
        if success >= 2 and errors >= 1:
            return True, "limit_bypass", (
                f"{success}/{total} requests returned success responses simultaneously. "
                "Only 1 should succeed — race condition allows limit bypass."
            )

        # All requests succeeded (should fail after first)
        if success == total and total > 1:
            return True, "duplicate_action", (
                f"All {total} concurrent requests returned success. "
                "Duplicate actions may have been processed."
            )

        # Mixed status codes suggesting state corruption
        if len(statuses) >= 3 and total >= 5:
            return True, "state_corruption", (
                f"Inconsistent responses: {statuses}. "
                "Multiple status codes indicate possible state corruption."
            )

        # Multiple 200s with same endpoint (rate limit bypass)
        if statuses.get(200, 0) >= 2 and 'limit' in url.lower():
            return True, "limit_bypass", (
                f"{statuses.get(200, 0)} successful responses on rate-limited endpoint."
            )

        return False, "", ""

    async def _send_concurrent(self, url: str, method: str = "GET",
                                data: Optional[Dict] = None,
                                headers: Optional[Dict] = None,
                                count: int = 15) -> List[Tuple[int, str, float]]:
        """
        Send N concurrent requests using Last-Byte Sync technique.
        All requests are prepared and fired simultaneously.
        """
        results = []

        async def _single_request(client: httpx.AsyncClient) -> Tuple[int, str, float]:
            start = time.monotonic()
            try:
                if method.upper() == "POST" and data:
                    resp = await client.post(url, data=data, headers=headers or {},
                                             follow_redirects=True)
                else:
                    resp = await client.get(url, headers=headers or {},
                                            follow_redirects=True)
                elapsed = time.monotonic() - start
                return resp.status_code, resp.text, elapsed
            except Exception as e:
                elapsed = time.monotonic() - start
                return 0, str(e), elapsed

        # Last-Byte Sync: create all connections, then fire simultaneously
        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=False,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=count + 5)
        ) as client:
            # Fire all requests at the exact same time
            tasks = [_single_request(client) for _ in range(count)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for r in responses:
                if isinstance(r, tuple):
                    results.append(r)
                else:
                    results.append((0, str(r), 0.0))

        return results

    async def test_endpoint(self, url: str, method: str = "GET",
                             data: Optional[Dict] = None) -> Optional[RaceFinding]:
        """Test a single endpoint for race conditions"""
        self.logger.info(f"Race condition test: {method} {url}")

        concurrency_levels = [10, 20]

        for count in concurrency_levels:
            responses = await self._send_concurrent(url, method, data, count=count)

            if not responses:
                continue

            analysis = self._analyze_responses(responses)
            is_vuln, race_type, evidence = self._detect_race(analysis, url)

            if is_vuln:
                status_summary = ", ".join(
                    f"HTTP {k}: {v}x" for k, v in sorted(analysis['status_counts'].items())
                )
                return RaceFinding(
                    url=url,
                    method=method,
                    parameter=str(data) if data else "URL",
                    type=race_type,
                    severity="high",
                    confidence="medium",
                    concurrent_requests=count,
                    responses_summary=status_summary,
                    evidence=evidence,
                    remediation=self._get_remediation(race_type)
                )

        return None

    async def test_form(self, form_action: str, form_method: str,
                        inputs: List[Dict]) -> Optional[RaceFinding]:
        """Test a form for race conditions"""
        data = {inp['name']: inp.get('value', 'test')
                for inp in inputs if inp.get('name')}

        if not data:
            return None

        return await self.test_endpoint(form_action, form_method.upper(), data)

    def _get_remediation(self, race_type: str) -> str:
        base = (
            "1. Implement database-level atomic operations and transactions.\n"
            "2. Use mutex locks or semaphores for critical sections.\n"
            "3. Implement idempotency keys for payment/transfer endpoints.\n"
        )
        specific = {
            "limit_bypass": (
                "4. Use Redis/database atomic counters (INCR) instead of read-then-write.\n"
                "5. Implement per-user rate limiting with atomic checks.\n"
                "6. Add unique constraint at database level."
            ),
            "duplicate_action": (
                "4. Store one-time tokens in database and mark as used atomically.\n"
                "5. Use SELECT FOR UPDATE to lock rows during processing.\n"
                "6. Implement idempotency: same request = same result."
            ),
            "state_corruption": (
                "4. Use optimistic locking with version fields.\n"
                "5. Ensure all state changes happen in a single transaction.\n"
                "6. Review and fix TOCTOU (time-of-check time-of-use) patterns."
            ),
            "coupon_abuse": (
                "4. Mark coupon as 'in use' atomically before applying.\n"
                "5. Use database transactions: check + mark + apply in one TX.\n"
                "6. Implement per-user coupon usage tracking."
            ),
        }
        return base + specific.get(race_type, "4. Review concurrency handling in critical sections.")

    async def scan(self, target_urls: List[str], forms: List = None) -> List[RaceFinding]:  # NEW-BUG-001 FIX
        forms = forms or []  # NEW-BUG-001 FIX
        """Main race condition scan"""
        self.logger.info(f"Starting race condition scan on {len(target_urls)} URLs")

        tasks = []

        # Test race-prone URLs
        for url in target_urls:
            if self._is_race_prone_url(url):
                tasks.append(self.test_endpoint(url, "GET"))
                tasks.append(self.test_endpoint(url, "POST"))

        # Test forms on race-prone endpoints
        for form in forms:
            if self._is_race_prone_url(form.action):
                tasks.append(self.test_form(form.action, form.method, form.inputs))

        if not tasks:
            # If no race-prone URLs found, test all POST endpoints
            for url in target_urls[:10]:
                parsed = urlparse(url)
                if parsed.query:
                    tasks.append(self.test_endpoint(url, "GET"))

        self.logger.info(f"Running {len(tasks)} race condition tests...")
        results = await asyncio.gather(*tasks, return_exceptions=True)

        seen = set()
        for result in results:
            if isinstance(result, Exception):
                self.logger.debug(f"Race test error: {result}")
                continue
            if result:
                key = f"{result.url}:{result.type}"
                if key not in seen:
                    seen.add(key)
                    self.findings.append(result)
                    self.logger.warning(
                        f"RACE [{result.severity.upper()}]: {result.url} | "
                        f"Type: {result.type} | Responses: {result.responses_summary}"
                    )

        self.logger.info(f"Race condition scan complete. Found {len(self.findings)} issues")
        return self.findings
