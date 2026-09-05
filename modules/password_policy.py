"""
Password Policy Tester Module
Tests for weak password policies, account lockout, and brute-force protection
"""

import asyncio
import re
import time
from urllib.parse import urljoin
from typing import List, Optional, Dict, Set
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class PasswordFinding:
    """Represents a password policy finding"""
    url: str
    type: str        # 'weak_password_accepted', 'no_lockout', 'no_captcha',
                     # 'no_rate_limit', 'username_enum', 'default_creds', 'password_in_response'
    severity: str
    confidence: str
    evidence: str
    remediation: str


class PasswordPolicyTester:
    """
    Password Policy Testing Module
    Tests for:
    - Weak passwords accepted (123456, password, etc.)
    - No account lockout after failed attempts
    - Username enumeration via different error messages
    - No rate limiting on login endpoint
    - Default credentials accepted
    - Password returned in response
    - No CAPTCHA after multiple failures
    - Brute-force protection bypass
    """

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("PasswordPolicy")
        self.findings: List[PasswordFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(15.0, connect=8.0)

        # Weak passwords to test
        self.weak_passwords = [
            "123456", "password", "12345678", "qwerty", "123456789",
            "12345", "1234", "111111", "1234567", "dragon",
            "123123", "baseball", "iloveyou", "monkey", "letmein",
            "shadow", "master", "666666", "qwertyuiop", "123321",
            "mustang", "1234567890", "michael", "654321", "superman",
            "1qaz2wsx", "7777777", "121212", "000000", "qazwsx",
            "123qwe", "password1", "password123", "admin", "admin123",
            "root", "test", "guest", "user", "pass",
        ]

        # Default credentials to test
        self.default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "admin123"),
            ("admin", "123456"),
            ("admin", ""),
            ("root", "root"),
            ("root", "toor"),
            ("root", "password"),
            ("test", "test"),
            ("guest", "guest"),
            ("user", "user"),
            ("administrator", "administrator"),
            ("administrator", "password"),
            ("demo", "demo"),
            ("info", "info"),
        ]

        # Common login form field names
        self.username_fields = [
            'username', 'user', 'email', 'login', 'name',
            'user_name', 'user_email', 'userid', 'uname',
            'log', 'usr', 'account', 'identifier'
        ]
        self.password_fields = [
            'password', 'pass', 'passwd', 'pwd', 'secret',
            'user_password', 'login_password', 'passwrd', 'psw'
        ]

    def _find_login_forms(self, html: str, base_url: str) -> List[Dict]:
        """Extract login forms from HTML"""
        forms = []
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        input_pattern = re.compile(r'<input([^>]*)>', re.IGNORECASE)
        action_pattern = re.compile(r'action=[\'"]([^\'"]*)[\'"]', re.IGNORECASE)
        method_pattern = re.compile(r'method=[\'"]([^\'"]*)[\'"]', re.IGNORECASE)
        name_pattern   = re.compile(r'name=[\'"]([^\'"]*)[\'"]', re.IGNORECASE)
        type_pattern   = re.compile(r'type=[\'"]([^\'"]*)[\'"]', re.IGNORECASE)

        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            form_body = form_match.group(1)

            action_m = action_pattern.search(form_html)
            method_m = method_pattern.search(form_html)
            action = urljoin(base_url, action_m.group(1)) if action_m else base_url
            method = method_m.group(1).upper() if method_m else "POST"

            inputs = []
            has_password = False
            has_username = False

            for input_match in input_pattern.finditer(form_body):
                attrs = input_match.group(1)
                name_m = name_pattern.search(attrs)
                type_m = type_pattern.search(attrs)
                name = name_m.group(1).lower() if name_m else ''
                itype = type_m.group(1).lower() if type_m else 'text'

                if itype == 'password':
                    has_password = True
                if any(uf in name for uf in self.username_fields):
                    has_username = True

                inputs.append({'name': name_m.group(1) if name_m else '', 'type': itype})

            if has_password:
                forms.append({
                    'action': action,
                    'method': method,
                    'inputs': inputs,
                    'has_username': has_username,
                })

        return forms

    def _build_form_data(self, form: Dict, username: str, password: str) -> Dict:
        """Build form submission data"""
        data = {}
        for inp in form['inputs']:
            name = inp['name']
            if not name:
                continue
            name_lower = name.lower()
            if any(pf in name_lower for pf in self.password_fields) or inp['type'] == 'password':
                data[name] = password
            elif any(uf in name_lower for uf in self.username_fields) or inp['type'] == 'email':
                data[name] = username
            elif inp['type'] not in ['submit', 'button', 'hidden', 'checkbox', 'radio']:
                data[name] = 'test'
        return data

    def _is_login_success(self, response: httpx.Response, prev_response: httpx.Response) -> bool:
        """Detect successful login from response"""
        # Status code change
        if prev_response.status_code in [200] and response.status_code in [302, 301]:
            location = response.headers.get('location', '')
            if not any(ind in location.lower() for ind in ['login', 'signin', 'error', 'fail']):
                return True

        body_lower = response.text.lower()

        # Success indicators
        success_keywords = [
            'dashboard', 'welcome', 'logout', 'sign out', 'profile',
            'my account', 'admin panel', 'control panel', 'logged in'
        ]
        if any(kw in body_lower for kw in success_keywords):
            return True

        # Failure indicators (if present = not logged in)
        fail_keywords = [
            'invalid', 'incorrect', 'wrong', 'failed', 'error',
            'try again', 'not found', 'does not match'
        ]
        if all(kw not in body_lower for kw in fail_keywords):
            # No failure message = might be success
            if len(response.text) > 2000:
                return True

        return False

    def _is_login_failure(self, response: httpx.Response) -> bool:
        """Detect login failure"""
        body_lower = response.text.lower()
        fail_keywords = [
            'invalid', 'incorrect', 'wrong', 'failed', 'error',
            'try again', 'not found', 'does not match', 'unauthorized',
            'bad credentials', 'login failed', 'authentication failed'
        ]
        return any(kw in body_lower for kw in fail_keywords)

    async def _submit_form(self, form: Dict, username: str,
                            password: str) -> Optional[httpx.Response]:
        """Submit login form"""
        try:
            data = self._build_form_data(form, username, password)
            if not data:
                return None

            async def _do_request():
                if form['method'] == 'POST':
                    return await self.client.post(
                        form['action'], data=data, follow_redirects=True
                    )
                else:
                    return await self.client.get(
                        form['action'], params=data, follow_redirects=True
                    )
            return await self.rate_limiter.execute_with_retry(_do_request)
        except Exception as e:
            self.logger.debug(f"Form submit failed: {e}")
            return None

    async def test_weak_passwords(self, url: str, form: Dict) -> List[PasswordFinding]:
        """Test if weak passwords are accepted"""
        findings = []

        # Get baseline failure response
        baseline = await self._submit_form(form, "validuser@test.com", "INVALID_PASS_xyz987")
        if not baseline:
            return []

        for weak_pass in self.weak_passwords[:15]:
            response = await self._submit_form(form, "admin", weak_pass)
            if not response:
                continue

            if self._is_login_success(response, baseline):
                findings.append(PasswordFinding(
                    url=url,
                    type="weak_password_accepted",
                    severity="critical",
                    confidence="high",
                    evidence=f"Login succeeded with weak password: '{weak_pass}'",
                    remediation=(
                        "1. Enforce minimum password length of 12+ characters.\n"
                        "2. Require uppercase, lowercase, numbers, and special chars.\n"
                        "3. Block common passwords using a password blocklist.\n"
                        "4. Use zxcvbn library for password strength estimation.\n"
                        "5. Implement HIBP (Have I Been Pwned) API check."
                    )
                ))
                break

        return findings

    async def test_account_lockout(self, url: str, form: Dict) -> Optional[PasswordFinding]:
        """Test if account lockout exists after multiple failures"""
        failed_attempts = 0
        locked = False

        for i in range(12):
            response = await self._submit_form(
                form, "admin@test.com", f"wrong_password_{i}_xyz"
            )
            if not response:
                continue

            # Check for lockout indicators
            body_lower = response.text.lower()
            lockout_keywords = [
                'locked', 'too many', 'attempts', 'blocked',
                'temporarily', 'wait', 'suspended', 'captcha'
            ]
            if any(kw in body_lower for kw in lockout_keywords):
                locked = True
                self.logger.info(f"Account lockout triggered after {i+1} attempts")
                break

            if response.status_code == 429:
                locked = True
                break

            failed_attempts += 1
            await asyncio.sleep(0.3)

        if not locked and failed_attempts >= 10:
            return PasswordFinding(
                url=url,
                type="no_lockout",
                severity="high",
                confidence="high",
                evidence=f"No account lockout after {failed_attempts} failed login attempts — brute-force possible",
                remediation=(
                    "1. Implement account lockout after 5-10 failed attempts.\n"
                    "2. Use progressive delays (exponential backoff).\n"
                    "3. Implement CAPTCHA after 3-5 failures.\n"
                    "4. Send email alert on multiple failures.\n"
                    "5. Consider IP-based rate limiting with Redis."
                )
            )
        return None

    async def test_no_rate_limit(self, url: str, form: Dict) -> Optional[PasswordFinding]:
        """Test if login endpoint has rate limiting"""
        start = time.monotonic()
        tasks = []

        # Send 20 concurrent requests
        async def _send_one(i):
            return await self._submit_form(form, "test@test.com", f"pass{i}")

        tasks = [_send_one(i) for i in range(20)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.monotonic() - start

        valid_responses = [r for r in responses if isinstance(r, httpx.Response)]
        status_429 = sum(1 for r in valid_responses if r.status_code == 429)

        if len(valid_responses) >= 15 and status_429 == 0:
            return PasswordFinding(
                url=url,
                type="no_rate_limit",
                severity="high",
                confidence="high",
                evidence=(
                    f"{len(valid_responses)}/20 concurrent requests accepted with no rate limiting "
                    f"(completed in {elapsed:.1f}s, 0 got HTTP 429)"
                ),
                remediation=(
                    "1. Implement rate limiting: max 5 requests/minute per IP.\n"
                    "2. Use Redis-based rate limiter (express-rate-limit, django-ratelimit).\n"
                    "3. Return HTTP 429 with Retry-After header.\n"
                    "4. Implement per-account attempt tracking."
                )
            )
        return None

    async def test_username_enumeration(self, url: str, form: Dict) -> Optional[PasswordFinding]:
        """Test for username enumeration via different error messages"""
        # Test with likely-invalid username
        resp_invalid = await self._submit_form(form, "xyz_nonexistent_user_12345@fake.com", "wrongpass")
        # Test with common username
        resp_common  = await self._submit_form(form, "admin", "wrongpass")

        if not resp_invalid or not resp_common:
            return None

        # Compare response lengths and content
        len_diff = abs(len(resp_invalid.text) - len(resp_common.text))

        if len_diff > 100:
            return PasswordFinding(
                url=url,
                type="username_enum",
                severity="medium",
                confidence="medium",
                evidence=(
                    "Different response sizes for valid vs invalid username: "  # NEW-BUG-003 FIX: removed unnecessary f-prefix
                    f"invalid={len(resp_invalid.text)}B, common={len(resp_common.text)}B "
                    f"(diff: {len_diff}B) — username enumeration possible"
                ),
                remediation=(
                    "1. Return identical error messages for wrong username AND wrong password.\n"
                    "2. Use generic: 'Invalid username or password'.\n"
                    "3. Ensure response time is same for both cases.\n"
                    "4. Use constant-time comparison functions."
                )
            )

        # Check for different error messages
        invalid_lower = resp_invalid.text.lower()
        common_lower  = resp_common.text.lower()

        user_not_found = any(kw in invalid_lower for kw in ['user not found', 'no account', 'not registered', 'does not exist'])
        wrong_pass     = any(kw in common_lower  for kw in ['wrong password', 'incorrect password', 'invalid password'])

        if user_not_found and wrong_pass:
            return PasswordFinding(
                url=url,
                type="username_enum",
                severity="medium",
                confidence="high",
                evidence="Different error messages: 'user not found' vs 'wrong password' — username enumeration confirmed",
                remediation=(
                    "1. Always use generic error: 'Invalid username or password'.\n"
                    "2. Never reveal if username exists.\n"
                    "3. Apply same logic to password reset flow."
                )
            )

        return None

    async def test_default_credentials(self, url: str, form: Dict) -> List[PasswordFinding]:
        """Test for default credentials"""
        findings = []
        baseline = await self._submit_form(form, "INVALID_USER_xyz", "INVALID_PASS_xyz")
        if not baseline:
            return []

        for username, password in self.default_creds:
            response = await self._submit_form(form, username, password)
            if not response:
                continue

            if self._is_login_success(response, baseline):
                findings.append(PasswordFinding(
                    url=url,
                    type="default_creds",
                    severity="critical",
                    confidence="high",
                    evidence=f"Default credentials accepted: '{username}' / '{password}'",
                    remediation=(
                        "1. Change all default credentials immediately.\n"
                        "2. Force password change on first login.\n"
                        "3. Remove or disable default accounts.\n"
                        "4. Implement strong password policy for all accounts."
                    )
                ))
                break

        return findings

    async def test_password_in_response(self, url: str, form: Dict) -> Optional[PasswordFinding]:
        """Test if password is returned in response"""
        test_pass = "TestPass_0xHunter_123"
        response  = await self._submit_form(form, "admin", test_pass)
        if not response:
            return None

        if test_pass in response.text:
            return PasswordFinding(
                url=url,
                type="password_in_response",
                severity="high",
                confidence="high",
                evidence=f"Submitted password '{test_pass}' found reflected in response — password disclosure",
                remediation=(
                    "1. Never return passwords in HTTP responses.\n"
                    "2. Never log passwords.\n"
                    "3. Always hash passwords before storage (bcrypt, argon2)."
                )
            )
        return None

    async def scan(self, target_urls: List[str], forms: List = None) -> List[PasswordFinding]:  # BUG-003 FIX
        """Main password policy scan"""
        forms = forms or []  # BUG-003 FIX: avoid mutable default argument
        self.logger.info(f"Starting password policy scan on {len(target_urls)} URLs")

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
            seen_forms: Set[str] = set()

            for url in target_urls:
                try:
                    async def _do_get(u=url):
                        return await client.get(u, follow_redirects=True)
                    response = await self.rate_limiter.execute_with_retry(_do_get)
                    if not response or response.status_code != 200:
                        continue

                    login_forms = self._find_login_forms(response.text, url)

                    for form in login_forms:
                        form_key = form['action']
                        if form_key in seen_forms:
                            continue
                        seen_forms.add(form_key)

                        self.logger.info(f"Testing login form: {form['action']}")

                        # Run all tests
                        tasks = [
                            self.test_weak_passwords(url, form),
                            self.test_account_lockout(url, form),
                            self.test_no_rate_limit(url, form),
                            self.test_username_enumeration(url, form),
                            self.test_default_credentials(url, form),
                            self.test_password_in_response(url, form),
                        ]

                        results = await asyncio.gather(*tasks, return_exceptions=True)

                        for result in results:
                            if isinstance(result, Exception):
                                self.logger.debug(f"Password test error: {result}")
                                continue
                            items = result if isinstance(result, list) else ([result] if result else [])
                            for finding in items:
                                if finding:
                                    self.findings.append(finding)
                                    self.logger.warning(
                                        f"PASSWORD [{finding.severity.upper()}]: "
                                        f"{finding.type} | {finding.evidence[:80]}"
                                    )

                except Exception as e:
                    self.logger.debug(f"Password policy scan error {url}: {e}")

        self.logger.info(f"Password policy scan complete. Found {len(self.findings)} issues")
        return self.findings
