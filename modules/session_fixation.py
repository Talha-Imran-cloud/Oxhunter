"""
Session Fixation & Session Security Testing Module
Tests for session fixation, session hijacking, and weak session management
"""

import asyncio
import re
from urllib.parse import urlparse
from typing import List, Optional, Dict, Set
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class SessionFinding:
    """Represents a session security finding"""
    url: str
    type: str        # 'fixation', 'weak_id', 'no_regeneration', 'insecure_cookie',
                     # 'long_expiry', 'no_httponly', 'no_secure', 'no_samesite', 'predictable'
    severity: str
    confidence: str
    session_cookie: str
    evidence: str
    remediation: str


class SessionFixationScanner:
    """
    Session Security Testing Module
    Tests for:
    - Session Fixation (pre-auth session reused after login)
    - Weak/predictable session IDs
    - Missing HttpOnly flag
    - Missing Secure flag
    - Missing SameSite attribute
    - Session ID in URL
    - Long session expiry
    - No session invalidation on logout
    - Concurrent session issues
    - Session ID length/entropy
    """

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("SessionSecurity")
        self.findings: List[SessionFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(15.0, connect=8.0)

        # Common session cookie names
        self.session_cookie_names = [
            'sessionid', 'session', 'sess', 'sid', 'session_id',
            'PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId', 'ASPSESSIONID',
            'laravel_session', 'ci_session', 'django_session',
            'connect.sid', 'express.sid', 'rack.session',
            'auth', 'token', 'access_token', 'jwt', 'user_session',
            'remember_token', 'login_token', '_session', 'user_id',
        ]

        # Login form indicators
        self.login_indicators = [
            'login', 'signin', 'sign-in', 'sign_in', 'auth',
            'authenticate', 'logon', 'log-in', 'log_in'
        ]

        # Logout indicators
        self.logout_indicators = [
            'logout', 'signout', 'sign-out', 'sign_out',
            'logoff', 'log-out', 'log_out', 'exit'
        ]

    def _find_session_cookies(self, response: httpx.Response) -> Dict[str, str]:
        """Extract session cookies from response"""
        session_cookies = {}
        all_cookies = dict(response.cookies)

        for name, value in all_cookies.items():
            if any(sc in name.lower() for sc in self.session_cookie_names):
                session_cookies[name] = value

        # Also check Set-Cookie headers for flags
        return session_cookies

    def _analyze_cookie_flags(self, response: httpx.Response) -> List[SessionFinding]:
        """Analyze cookie security flags from Set-Cookie headers"""
        findings = []
        url = str(response.url)
        parsed = urlparse(url)
        is_https = parsed.scheme == 'https'

        set_cookie_headers = response.headers.get_list('set-cookie') \
            if hasattr(response.headers, 'get_list') \
            else [v for k, v in response.headers.items() if k.lower() == 'set-cookie']

        for cookie_header in set_cookie_headers:
            cookie_name = cookie_header.split('=')[0].strip()

            # Check if this is a session cookie
            is_session = any(sc in cookie_name.lower() for sc in self.session_cookie_names)
            if not is_session:
                continue

            cookie_lower = cookie_header.lower()

            # Check HttpOnly
            if 'httponly' not in cookie_lower:
                findings.append(SessionFinding(
                    url=url,
                    type="no_httponly",
                    severity="medium",
                    confidence="high",
                    session_cookie=cookie_name,
                    evidence=f"Session cookie '{cookie_name}' missing HttpOnly flag — accessible via JavaScript (XSS risk)",
                    remediation=(
                        "1. Add HttpOnly flag to all session cookies.\n"
                        "2. PHP: session.cookie_httponly = 1\n"
                        "3. Express: cookie: { httpOnly: true }\n"
                        "4. Django: SESSION_COOKIE_HTTPONLY = True"
                    )
                ))

            # Check Secure flag (only warn for HTTPS sites)
            if is_https and 'secure' not in cookie_lower:
                findings.append(SessionFinding(
                    url=url,
                    type="no_secure",
                    severity="high",
                    confidence="high",
                    session_cookie=cookie_name,
                    evidence=f"Session cookie '{cookie_name}' missing Secure flag on HTTPS site — cookie sent over HTTP",
                    remediation=(
                        "1. Add Secure flag to all session cookies.\n"
                        "2. PHP: session.cookie_secure = 1\n"
                        "3. Express: cookie: { secure: true }\n"
                        "4. Django: SESSION_COOKIE_SECURE = True"
                    )
                ))

            # Check SameSite
            if 'samesite' not in cookie_lower:
                findings.append(SessionFinding(
                    url=url,
                    type="no_samesite",
                    severity="medium",
                    confidence="high",
                    session_cookie=cookie_name,
                    evidence=f"Session cookie '{cookie_name}' missing SameSite attribute — CSRF risk",
                    remediation=(
                        "1. Add SameSite=Strict or SameSite=Lax to session cookies.\n"
                        "2. PHP: session.cookie_samesite = 'Strict'\n"
                        "3. Express: cookie: { sameSite: 'strict' }\n"
                        "4. Django: SESSION_COOKIE_SAMESITE = 'Strict'"
                    )
                ))
            elif 'samesite=none' in cookie_lower and 'secure' not in cookie_lower:
                findings.append(SessionFinding(
                    url=url,
                    type="samesite_none_no_secure",
                    severity="high",
                    confidence="high",
                    session_cookie=cookie_name,
                    evidence=f"Cookie '{cookie_name}' has SameSite=None without Secure — browsers will reject",
                    remediation="Add Secure flag when using SameSite=None."
                ))

            # Check for long/no expiry (session vs persistent)
            if 'max-age=' in cookie_lower:
                max_age_match = re.search(r'max-age=(\d+)', cookie_lower)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age > 86400 * 30:  # 30 days
                        findings.append(SessionFinding(
                            url=url,
                            type="long_expiry",
                            severity="low",
                            confidence="high",
                            session_cookie=cookie_name,
                            evidence=f"Session cookie '{cookie_name}' has very long expiry: {max_age}s ({max_age//86400} days)",
                            remediation=(
                                "1. Use short session expiry (15-60 minutes for sensitive apps).\n"
                                "2. Implement sliding session expiry.\n"
                                "3. Force re-authentication for sensitive actions."
                            )
                        ))

        return findings

    def _analyze_session_id_strength(self, session_id: str, cookie_name: str,
                                      url: str) -> List[SessionFinding]:
        """Analyze session ID for weakness/predictability"""
        findings = []

        # Check length
        if len(session_id) < 16:
            findings.append(SessionFinding(
                url=url,
                type="weak_id",
                severity="high",
                confidence="high",
                session_cookie=cookie_name,
                evidence=f"Session ID too short: {len(session_id)} chars (minimum 32 recommended)",
                remediation=(
                    "1. Use cryptographically random session IDs of at least 128 bits (32 hex chars).\n"
                    "2. Use os.urandom() or secrets.token_hex(32) in Python.\n"
                    "3. Use crypto.randomBytes(32) in Node.js."
                )
            ))

        # Check if purely numeric (very weak)
        if session_id.isdigit():
            findings.append(SessionFinding(
                url=url,
                type="predictable",
                severity="critical",
                confidence="high",
                session_cookie=cookie_name,
                evidence=f"Session ID is purely numeric: '{session_id[:20]}' — highly predictable",
                remediation=(
                    "1. Use cryptographically random alphanumeric session IDs.\n"
                    "2. Never use sequential or timestamp-based session IDs."
                )
            ))

        # Check if looks like MD5/SHA1 (may be predictable)
        if re.match(r'^[a-f0-9]{32}$', session_id):
            findings.append(SessionFinding(
                url=url,
                type="weak_id",
                severity="medium",
                confidence="medium",
                session_cookie=cookie_name,
                evidence="Session ID looks like MD5 hash — may be derived from predictable input",
                remediation=(
                    "1. Use CSPRNG (cryptographically secure pseudo-random number generator).\n"
                    "2. Do not derive session IDs from user data or timestamps."
                )
            ))

        # Check if base64 encoded (may expose structure)
        try:
            import base64
            decoded = base64.b64decode(session_id + '==').decode('utf-8', errors='ignore')
            if '{' in decoded or ':' in decoded or 'user' in decoded.lower():
                findings.append(SessionFinding(
                    url=url,
                    type="weak_id",
                    severity="high",
                    confidence="medium",
                    session_cookie=cookie_name,
                    evidence="Session ID appears to be base64-encoded structured data — may contain user info",
                    remediation=(
                        "1. Never encode user data in session IDs.\n"
                        "2. Store session data server-side, use random opaque token."
                    )
                ))
        except Exception:
            pass

        return findings

    async def _fetch(self, url: str, cookies: Optional[Dict] = None,
                     follow_redirects: bool = True) -> Optional[httpx.Response]:
        """Make HTTP request"""
        try:
            async def _do_request():
                return await self.client.get(
                    url,
                    cookies=cookies or {},
                    follow_redirects=follow_redirects
                )
            return await self.rate_limiter.execute_with_retry(_do_request)
        except Exception as e:
            self.logger.debug(f"Request failed {url}: {e}")
            return None

    async def _find_login_page(self, base_url: str) -> Optional[str]:
        """Try to find login page"""
        common_login_paths = [
            '/login', '/signin', '/sign-in', '/auth/login',
            '/user/login', '/users/login', '/account/login',
            '/admin/login', '/wp-login.php', '/api/auth/login',
        ]
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in common_login_paths:
            url = base + path
            try:
                async def _do_req(u=url):
                    return await self.client.get(u, follow_redirects=True)
                response = await self.rate_limiter.execute_with_retry(_do_req)
                if response and response.status_code == 200:
                    body_lower = response.text.lower()
                    if any(ind in body_lower for ind in ['password', 'login', 'signin']):
                        return url
            except Exception:
                continue
        return None

    async def test_session_fixation(self, url: str) -> Optional[SessionFinding]:
        """
        Test for session fixation:
        1. Get session ID before login
        2. Login (if possible)
        3. Check if session ID changed after login
        """
        # Step 1: Get pre-auth session
        response = await self._fetch(url)
        if not response:
            return None

        pre_auth_cookies = self._find_session_cookies(response)
        if not pre_auth_cookies:
            return None

        pre_auth_id = list(pre_auth_cookies.values())[0]
        cookie_name = list(pre_auth_cookies.keys())[0]

        # Step 2: Try to find login endpoint
        login_url = await self._find_login_page(url)
        if not login_url:
            return None

        # Step 3: Simulate login attempt with fixed session
        try:
            async def _do_login():
                return await self.client.post(
                    login_url,
                    data={
                        'username': 'test_user_0xhunter',
                        'password': 'test_pass_0xhunter',
                        'email': 'test@0xhunter.test'
                    },
                    cookies={cookie_name: pre_auth_id},
                    follow_redirects=True
                )
            post_login = await self.rate_limiter.execute_with_retry(_do_login)

            if not post_login:
                return None

            post_auth_cookies = self._find_session_cookies(post_login)

            # If session ID didn't change after login attempt = fixation risk
            if post_auth_cookies:
                post_auth_id = post_auth_cookies.get(cookie_name, '')
                if post_auth_id and post_auth_id == pre_auth_id:
                    return SessionFinding(
                        url=login_url,
                        type="fixation",
                        severity="high",
                        confidence="medium",
                        session_cookie=cookie_name,
                        evidence=(
                            f"Session ID '{pre_auth_id[:20]}...' did not change after login attempt. "
                            "Possible session fixation — attacker can set victim's session ID pre-auth."
                        ),
                        remediation=(
                            "1. Always regenerate session ID after successful login.\n"
                            "2. PHP: session_regenerate_id(true) after login.\n"
                            "3. Express: req.session.regenerate() after login.\n"
                            "4. Django: request.session.cycle_key() after login.\n"
                            "5. Invalidate old session, create new one on authentication."
                        )
                    )
        except Exception as e:
            self.logger.debug(f"Session fixation test error: {e}")

        return None

    async def test_session_in_url(self, url: str) -> Optional[SessionFinding]:
        """Check if session ID appears in URL"""
        session_url_patterns = [
            re.compile(r'[?&](sessionid|session|sid|PHPSESSID|jsessionid)=([a-zA-Z0-9_\-]+)', re.I),
            re.compile(r';jsessionid=([a-zA-Z0-9_\-]+)', re.I),
        ]

        for pattern in session_url_patterns:
            match = pattern.search(url)
            if match:
                return SessionFinding(
                    url=url,
                    type="session_in_url",
                    severity="high",
                    confidence="high",
                    session_cookie=match.group(0)[:50],
                    evidence=f"Session ID found in URL: '{match.group(0)}' — exposed in logs, referrer headers, browser history",
                    remediation=(
                        "1. Never put session IDs in URLs.\n"
                        "2. Use cookies exclusively for session management.\n"
                        "3. Disable URL-based session tracking in framework config.\n"
                        "4. PHP: session.use_only_cookies = 1"
                    )
                )
        return None

    async def test_logout_invalidation(self, base_url: str) -> Optional[SessionFinding]:
        """Test if session is properly invalidated on logout"""
        # Get session
        response = await self._fetch(base_url)
        if not response:
            return None

        session_cookies = self._find_session_cookies(response)
        if not session_cookies:
            return None

        session_id   = list(session_cookies.values())[0]
        cookie_name  = list(session_cookies.keys())[0]

        # Try logout
        parsed = urlparse(base_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        for logout_path in ['/logout', '/signout', '/sign-out', '/api/logout']:
            logout_url = base + logout_path
            try:
                async def _do_logout(u=logout_url):
                    return await self.client.get(
                        u, cookies={cookie_name: session_id},
                        follow_redirects=True
                    )
                logout_resp = await self.rate_limiter.execute_with_retry(_do_logout)
                if not logout_resp or logout_resp.status_code not in [200, 302]:
                    continue

                # Try using old session after logout
                await asyncio.sleep(0.5)
                old_session_resp = await self._fetch(base_url, cookies={cookie_name: session_id})
                if not old_session_resp:
                    continue

                # If old session still works (returns 200 with content)
                if old_session_resp.status_code == 200 and len(old_session_resp.text) > 500:
                    body_lower = old_session_resp.text.lower()
                    # Check if we're still logged in (not redirected to login page)
                    if not any(ind in body_lower for ind in ['login', 'signin', 'sign in', 'log in']):
                        return SessionFinding(
                            url=logout_url,
                            type="no_logout_invalidation",
                            severity="high",
                            confidence="medium",
                            session_cookie=cookie_name,
                            evidence=(
                                f"Session cookie '{cookie_name}' still valid after logout. "
                                "Session not invalidated server-side — old session can be reused."
                            ),
                            remediation=(
                                "1. Invalidate session server-side on logout (not just client-side).\n"
                                "2. PHP: session_destroy() on logout.\n"
                                "3. Express: req.session.destroy() on logout.\n"
                                "4. Django: request.session.flush() on logout.\n"
                                "5. Maintain server-side session blacklist."
                            )
                        )
            except Exception:
                continue

        return None

    async def scan(self, target_urls: List[str], forms: List = None) -> List[SessionFinding]:  # NEW-BUG-001 FIX
        forms = forms or []  # NEW-BUG-001 FIX
        """Main session security scan"""
        seen_bases: Set[str] = set()

        self.logger.info(f"Starting session security scan on {len(target_urls)} URLs")

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,*/*',
        }

        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=True,
            verify=False
        ) as client:
            self.client = client

            for url in target_urls:
                parsed  = urlparse(url)
                base    = f"{parsed.scheme}://{parsed.netloc}"

                # Session in URL check (all URLs)
                finding = await self.test_session_in_url(url)
                if finding:
                    self.findings.append(finding)

                if base in seen_bases:
                    continue
                seen_bases.add(base)

                # Fetch base URL and analyze cookies
                response = await self._fetch(base)
                if response:
                    # Cookie flag analysis
                    cookie_findings = self._analyze_cookie_flags(response)
                    self.findings.extend(cookie_findings)

                    # Session ID strength
                    session_cookies = self._find_session_cookies(response)
                    for name, value in session_cookies.items():
                        strength_findings = self._analyze_session_id_strength(value, name, base)
                        self.findings.extend(strength_findings)

                # Session fixation test
                fixation = await self.test_session_fixation(base)
                if fixation:
                    self.findings.append(fixation)

                # Logout invalidation test
                logout = await self.test_logout_invalidation(base)
                if logout:
                    self.findings.append(logout)

            # Log all findings
            for f in self.findings:
                self.logger.warning(
                    f"SESSION [{f.severity.upper()}]: {f.url} | "
                    f"Type: {f.type} | Cookie: {f.session_cookie}"
                )

        self.logger.info(f"Session scan complete. Found {len(self.findings)} issues")
        return self.findings
