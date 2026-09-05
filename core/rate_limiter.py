"""
Rate Limiter - Smart concurrent rate limiting with token bucket algorithm
UPGRADE: True concurrency via Semaphore + Token Bucket + Adaptive throttling
"""

import asyncio
import time
import yaml
from core.paths import resolve_config_path


class RateLimiter:
    """
    Token Bucket Rate Limiter — supports TRUE concurrent requests.
    
    OLD (broken): asyncio.Lock serialized every request → 1 req at a time
    NEW: asyncio.Semaphore → 'threads' concurrent requests, token bucket controls rate
    """

    def __init__(self, config_path: str = "config.yaml", concurrency: int = None):
        config_file = resolve_config_path(config_path)
        with config_file.open('r', encoding='utf-8') as f:
            config = yaml.safe_load(f) or {}

        rl = config.get('rate_limit', {})
        self.requests_per_second = rl.get('requests_per_second', 10)
        self.delay               = rl.get('delay_between_requests', 0.1)
        self.max_retries         = rl.get('max_retries', 3)
        self.retry_delay         = rl.get('retry_delay', 2)

        # ── Token Bucket ──────────────────────────────────────
        self._tokens      = float(self.requests_per_second)
        self._max_tokens  = float(self.requests_per_second)
        self._refill_rate = float(self.requests_per_second)   # tokens/sec
        self._last_refill = time.monotonic()
        self._bucket_lock = asyncio.Lock()

        # ── Concurrency Semaphore ─────────────────────────────
        # Allows N requests truly in parallel instead of serializing them
        _concurrency = concurrency or max(1, int(self.requests_per_second))
        self._semaphore = asyncio.Semaphore(_concurrency)

        # ── Adaptive throttle stats ───────────────────────────
        self._error_count    = 0
        self._success_count  = 0
        self._throttle_until = 0.0   # epoch time — back-off deadline

    # ──────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────

    def _refill_tokens(self):
        """Add tokens based on elapsed time (token-bucket refill)."""
        now   = time.monotonic()
        delta = now - self._last_refill
        self._tokens = min(
            self._max_tokens,
            self._tokens + delta * self._refill_rate
        )
        self._last_refill = now

    async def _wait_for_token(self):
        """Block until a token is available (non-serializing for callers)."""
        async with self._bucket_lock:
            self._refill_tokens()
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self._refill_rate
                await asyncio.sleep(wait)
                self._refill_tokens()
            self._tokens -= 1.0

    async def acquire(self):
        """
        Acquire permission to send a request.
        - Waits for any global back-off (adaptive throttle)
        - Waits for a token (rate limit)
        Semaphore is handled by execute_with_retry for true concurrency.
        """
        # Adaptive back-off (triggered after repeated errors)
        now = time.monotonic()
        if self._throttle_until > now:
            await asyncio.sleep(self._throttle_until - now)

        await self._wait_for_token()

        # Legacy delay support (--delay CLI flag)
        if self.delay > 0:
            await asyncio.sleep(self.delay)

    # ──────────────────────────────────────────────────────────
    # Adaptive throttle control
    # ──────────────────────────────────────────────────────────

    def report_success(self):
        """Call after a successful request to ease throttling."""
        self._success_count += 1
        self._error_count = max(0, self._error_count - 1)

    def report_error(self, status_code: int = 0):
        """
        Call after an error.  On 429 / 503 we back off aggressively.
        """
        self._error_count += 1

        if status_code in (429, 503):
            # Hard back-off: 10s + 5s per consecutive error
            back_off = min(60, 10 + self._error_count * 5)
            self._throttle_until = time.monotonic() + back_off
            # Also halve the token refill rate temporarily
            self._refill_rate = max(1.0, self._refill_rate * 0.5)
        elif self._error_count > 5:
            # Soft back-off for repeated non-429 errors
            self._throttle_until = time.monotonic() + 2.0

    def reset_throttle(self):
        """Restore full speed after back-off clears."""
        self._throttle_until = 0.0
        self._error_count    = 0
        self._refill_rate    = float(self.requests_per_second)

    # ──────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────

    async def execute_with_retry(self, coro_func, *args, retries=None, **kwargs):
        """
        Execute a coroutine with:
          - Semaphore (true concurrency limit)
          - Token-bucket rate limiting
          - Configurable retry with exponential back-off
          - Adaptive throttling on 429/503
        """
        attempts = self.max_retries if retries is None else max(0, retries)

        async with self._semaphore:          # <── true concurrency gate
            for attempt in range(attempts + 1):
                await self.acquire()
                try:
                    result = await coro_func(*args, **kwargs)
                    self.report_success()
                    return result
                except Exception as exc:
                    # Detect HTTP 429 / 503 from exception message
                    msg = str(exc)
                    if "429" in msg:
                        self.report_error(429)
                    elif "503" in msg:
                        self.report_error(503)
                    else:
                        self.report_error()

                    if attempt >= attempts:
                        raise exc

                    wait = self.retry_delay * (attempt + 1)
                    await asyncio.sleep(wait)

        return None

    # ──────────────────────────────────────────────────────────
    # Bulk parallel executor (NEW — for modules)
    # ──────────────────────────────────────────────────────────

    async def run_tasks(self, tasks: list, chunk_size: int = 50) -> list:
        """
        Run a list of coroutines in parallel chunks.
        Better than asyncio.gather(all) which floods memory on huge task lists.
        
        Usage:
            results = await rate_limiter.run_tasks([coro1, coro2, ...])
        """
        results = []
        for i in range(0, len(tasks), chunk_size):
            chunk   = tasks[i: i + chunk_size]
            batch   = await asyncio.gather(*chunk, return_exceptions=True)
            results.extend(batch)
        return results

