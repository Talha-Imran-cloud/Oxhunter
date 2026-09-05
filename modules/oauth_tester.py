"""
OXHUNTER - modules/oauth_tester.py
OAuth 2.0 / OIDC Security Tester
Token leakage, PKCE bypass, state fixation, open redirect abuse
"""

import re
import requests
import urllib.parse
import urllib3
from typing import Dict, List, Optional
from dataclasses import dataclass
from utils.logger import setup_logger

urllib3.disable_warnings()


@dataclass
class OAuthFinding:
    type        : str
    severity    : str
    url         : str
    detail      : str
    evidence    : str  = ""
    remediation : str  = ""
    payload     : str  = ""
    confidence  : str  = "medium"


class OAuthTester:
    """
    OAuth 2.0 / OIDC Security Tester.
    Tests for: token leakage, PKCE bypass, state fixation,
    open redirect in redirect_uri, implicit flow abuse,
    token substitution, scope escalation.
    """

    OAUTH_ENDPOINTS = [
        "/oauth/authorize", "/oauth2/authorize", "/auth/authorize",
        "/connect/authorize", "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/oauth/token", "/oauth2/token", "/auth/token",
        "/oauth/userinfo", "/oauth2/userinfo",
        "/oauth/introspect", "/oauth2/introspect",
        "/oauth/revoke", "/oauth2/revoke",
        "/api/oauth/authorize", "/api/v1/oauth/authorize",
    ]

    COMMON_CLIENT_IDS = [
        "client", "test", "demo", "app", "mobile",
        "web", "default", "admin", "public", "oauth",
    ]

    def __init__(self, rate_limiter=None, timeout: int = 10,
                 proxy: Optional[str] = None):
        self.timeout  = timeout
        self.logger   = setup_logger("OAuthTester")
        self.session  = requests.Session()
        self.session.verify = False
        self.session.headers["User-Agent"] = "Mozilla/5.0 OXHUNTER/2.0"
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def _get(self, url: str, **kw) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=self.timeout,
                                    allow_redirects=False, **kw)
        except Exception:
            return None

    def _post(self, url: str, **kw) -> Optional[requests.Response]:
        try:
            return self.session.post(url, timeout=self.timeout, **kw)
        except Exception:
            return None

    # ── Discover OAuth Endpoints ──────────────

    def discover(self, base_url: str) -> Dict:
        """Discover OAuth/OIDC endpoints on target."""
        base     = base_url.rstrip("/")
        found    = []
        oidc_cfg = {}

        # Check OIDC well-known
        for path in ["/.well-known/openid-configuration",
                     "/.well-known/oauth-authorization-server"]:
            r = self._get(base + path)
            if r and r.status_code == 200:
                try:
                    oidc_cfg = r.json()
                    found.append(base + path)
                    self.logger.info(f"OIDC config found: {base+path}")
                except Exception:
                    pass

        # Check common OAuth paths
        for path in self.OAUTH_ENDPOINTS:
            r = self._get(base + path)
            if r and r.status_code in [200, 302, 400, 401]:
                if base + path not in found:
                    found.append(base + path)

        return {"endpoints": found, "oidc_config": oidc_cfg}

    # ── Test 1: Token in URL (Referrer Leakage) ──

    def test_token_in_url(self, authorize_url: str,
                           client_id: str = "test") -> List[OAuthFinding]:
        """Check if access tokens appear in URLs (referrer leakage)."""
        findings = []
        url = (f"{authorize_url}?response_type=token&client_id={client_id}"
               "&redirect_uri=https://evil.com&scope=openid")
        r = self._get(url)
        if r and r.status_code == 302:
            location = r.headers.get("Location", "")
            if "access_token" in location or "#token" in location:
                findings.append(OAuthFinding(
                    type="oauth_token_in_url", severity="HIGH",
                    url=url,
                    detail="Access token exposed in URL via implicit flow",
                    evidence=f"Location: {location[:100]}",
                    remediation="Use authorization code flow with PKCE instead of implicit flow",
                ))
        return findings

    # ── Test 2: Missing State Parameter ──────────

    def test_missing_state(self, authorize_url: str,
                            client_id: str = "test") -> List[OAuthFinding]:
        """Test CSRF via missing state parameter."""
        findings = []
        url = (f"{authorize_url}?response_type=code&client_id={client_id}"
               "&redirect_uri=https://example.com")
        r = self._get(url)
        if r and r.status_code in [200, 302]:
            location = r.headers.get("Location", "")
            body     = r.text.lower()
            if "state" not in location and "state" not in body:
                findings.append(OAuthFinding(
                    type="oauth_missing_state", severity="MEDIUM",
                    url=url,
                    detail="OAuth flow missing CSRF state parameter",
                    remediation="Always include and validate state parameter in OAuth requests",
                ))
        return findings

    # ── Test 3: Open Redirect in redirect_uri ────

    def test_redirect_uri_bypass(self, authorize_url: str,
                                  client_id: str = "test") -> List[OAuthFinding]:
        """Test for open redirect / redirect_uri bypass."""
        findings = []
        evil_uris = [
            "https://evil.com",
            "https://evil.com/callback",
            "https://evil.com@legit.com",
            "https://legit.com.evil.com",
            "//evil.com",
            "https://evil%2Ecom",
            "javascript:alert(1)",
        ]
        for uri in evil_uris:
            url = (f"{authorize_url}?response_type=code&client_id={client_id}"
                   f"&redirect_uri={urllib.parse.quote(uri)}&state=test123")
            r = self._get(url)
            if r and r.status_code == 302:
                location = r.headers.get("Location", "")
                if "evil.com" in location or "javascript" in location:
                    findings.append(OAuthFinding(
                        type="oauth_redirect_uri_bypass", severity="HIGH",
                        url=url, payload=uri,
                        detail=f"redirect_uri not validated — redirected to: {location[:80]}",
                        remediation="Validate redirect_uri against exact whitelist",
                    ))
                    break
        return findings

    # ── Test 4: PKCE Bypass ───────────────────────

    def test_pkce_bypass(self, token_url: str,
                          code: str = "test_code",
                          client_id: str = "test") -> List[OAuthFinding]:
        """Test if PKCE code_verifier is properly validated."""
        findings = []

        # Try without code_verifier
        r = self._post(token_url, data={
            "grant_type"  : "authorization_code",
            "code"        : code,
            "client_id"   : client_id,
            "redirect_uri": "https://example.com",
        })
        if r and r.status_code == 200:
            try:
                data = r.json()
                if "access_token" in data:
                    findings.append(OAuthFinding(
                        type="oauth_pkce_bypass", severity="HIGH",
                        url=token_url,
                        detail="Token issued without code_verifier — PKCE not enforced",
                        remediation="Enforce PKCE for all public clients",
                    ))
            except Exception:
                pass

        return findings

    # ── Test 5: Client Secret Exposed ────────────

    def test_client_secret_exposure(self, base_url: str) -> List[OAuthFinding]:
        """Check for client secrets in JS files or source."""
        findings = []
        r = self._get(base_url)
        if not r:
            return findings

        # Find JS files
        js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', r.text)
        for js_path in js_urls[:5]:
            js_url = urllib.parse.urljoin(base_url, js_path)
            jr = self._get(js_url)
            if not jr:
                continue

            patterns = [
                (r'client_secret["\s:=]+["\']([a-zA-Z0-9_\-]{10,})["\']', "client_secret"),
                (r'clientSecret["\s:=]+["\']([a-zA-Z0-9_\-]{10,})["\']',  "clientSecret"),
                (r'oauth_secret["\s:=]+["\']([a-zA-Z0-9_\-]{10,})["\']',  "oauth_secret"),
            ]
            for pattern, key in patterns:
                match = re.search(pattern, jr.text, re.IGNORECASE)
                if match:
                    findings.append(OAuthFinding(
                        type="oauth_secret_exposed", severity="CRITICAL",
                        url=js_url,
                        detail=f"OAuth client secret found in JS: {key}",
                        evidence=f"{key}={match.group(1)[:10]}...",
                        remediation="Never expose client secrets in frontend code",
                    ))
        return findings

    # ── Test 6: Scope Escalation ──────────────────

    def test_scope_escalation(self, authorize_url: str,
                               client_id: str = "test") -> List[OAuthFinding]:
        """Test if server accepts unauthorized scopes."""
        findings = []
        admin_scopes = [
            "admin", "admin:read", "admin:write",
            "user:admin", "root", "superuser",
            "openid profile email admin",
        ]
        for scope in admin_scopes:
            url = (f"{authorize_url}?response_type=code&client_id={client_id}"
                   f"&redirect_uri=https://example.com&scope={scope}&state=xyz")
            r = self._get(url)
            if r and r.status_code not in [400, 401, 403]:
                body = r.text.lower()
                if "invalid_scope" not in body and "error" not in body[:100]:
                    findings.append(OAuthFinding(
                        type="oauth_scope_escalation", severity="HIGH",
                        url=url, payload=scope,
                        detail=f"Server accepted unauthorized scope: {scope}",
                        remediation="Validate and restrict allowed scopes per client",
                    ))
                    break
        return findings

    # ── Test 7: Token Substitution ────────────────

    def test_token_substitution(self, userinfo_url: str,
                                 token: str = "test.invalid.token") -> List[OAuthFinding]:
        """Test if userinfo endpoint validates token properly."""
        findings = []
        r = self._get(userinfo_url, headers={"Authorization": f"Bearer {token}"})
        if r and r.status_code == 200:
            try:
                data = r.json()
                if data and "error" not in data:
                    findings.append(OAuthFinding(
                        type="oauth_token_not_validated", severity="CRITICAL",
                        url=userinfo_url,
                        detail="Userinfo endpoint returned data for invalid token",
                        evidence=str(data)[:100],
                        remediation="Properly validate access tokens before returning userinfo",
                    ))
            except Exception:
                pass
        return findings

    # ── Full Scan ──────────────────────────────────

    async def scan(self, urls: List[str]) -> List[OAuthFinding]:
        """Run all OAuth tests on discovered endpoints."""
        findings = []
        if not urls:
            return findings

        base_url = urls[0].split("/")[0] + "//" + urls[0].split("/")[2] if len(urls[0].split("/")) > 2 else urls[0]
        self.logger.info(f"Starting OAuth/OIDC scan on {base_url}")

        # Discover endpoints
        discovery = self.discover(base_url)
        endpoints = discovery.get("endpoints", [])
        oidc_cfg  = discovery.get("oidc_config", {})

        if not endpoints:
            self.logger.info("No OAuth endpoints found")
            return findings

        self.logger.info(f"Found {len(endpoints)} OAuth endpoints")

        # Get specific endpoint URLs
        auth_url  = oidc_cfg.get("authorization_endpoint", "")
        token_url = oidc_cfg.get("token_endpoint", "")
        info_url  = oidc_cfg.get("userinfo_endpoint", "")

        if not auth_url:
            for ep in endpoints:
                if "authorize" in ep:
                    auth_url = ep
                    break
        if not token_url:
            for ep in endpoints:
                if "token" in ep:
                    token_url = ep
                    break

        for client_id in self.COMMON_CLIENT_IDS[:3]:
            if auth_url:
                findings.extend(self.test_token_in_url(auth_url, client_id))
                findings.extend(self.test_missing_state(auth_url, client_id))
                findings.extend(self.test_redirect_uri_bypass(auth_url, client_id))
                findings.extend(self.test_scope_escalation(auth_url, client_id))

        if token_url:
            findings.extend(self.test_pkce_bypass(token_url))

        if info_url:
            findings.extend(self.test_token_substitution(info_url))

        findings.extend(self.test_client_secret_exposure(base_url))

        self.logger.info(f"OAuth scan complete. Found {len(findings)} issues")
        return findings
