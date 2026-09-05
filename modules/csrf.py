"""
CSRF (Cross-Site Request Forgery) Detection Module
Checks for missing CSRF tokens in forms
"""

from typing import List, Optional
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class CSRFinding:
    """Represents a potential CSRF vulnerability"""
    url: str
    form_action: str
    form_method: str
    type: str  # 'missing_token', 'weak_token'
    confidence: str
    evidence: str
    remediation: str


class CSRFScanner:
    """
    CSRF Detection Module
    Checks forms for missing or weak CSRF protection.
    """
    
    # Common CSRF token field names
    CSRF_FIELD_NAMES = [
        'csrf', 'csrf_token', 'csrfmiddlewaretoken', '_token',
        'authenticity_token', 'token', 'xsrf_token', 'requesttoken',
        'nonce', 'auth_token', 'verification_token', 'security_token',
        'csrf_token_id', 'form_token', 'page_token', 'session_token'
    ]
    
    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("CSRF")
        self.findings: List[CSRFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(8.0, connect=5.0)
    
    def _has_csrf_token(self, inputs: List[dict]) -> bool:
        """Check if form has a CSRF token field"""
        for inp in inputs:
            name = inp.get('name', '').lower()
            if any(csrf_name in name for csrf_name in self.CSRF_FIELD_NAMES):
                return True
        return False
    
    def _check_same_origin(self, form_action: str, base_url: str) -> bool:
        """Check if form action is same-origin"""
        from urllib.parse import urlparse
        base_domain = urlparse(base_url).netloc
        action_domain = urlparse(form_action).netloc
        
        # If action_domain is empty, it's relative (same-origin)
        if not action_domain:
            return True
        return base_domain == action_domain
    
    async def _fetch(self, url: str) -> Optional[httpx.Response]:
        """Make HTTP request with rate limiting"""
        try:
            async def _do_request():
                return await self.client.get(url, follow_redirects=True)
            return await self.rate_limiter.execute_with_retry(_do_request)
        except Exception as e:
            self.logger.warning(f"Request failed {url}: {e}")
            return None
    
    async def scan(self, forms: List, base_url: str) -> List[CSRFinding]:
        """
        Scan forms for CSRF vulnerabilities.
        forms: List of Form objects from crawler
        base_url: The base target URL
        """
        self.findings = []  # FIX: reset on each call to prevent duplicates
        self.logger.info(f"Starting CSRF scan on {len(forms)} forms")
        
        headers = {
            'User-Agent': '0xHunter Security Scanner (Authorized Testing)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        
        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=True,
            verify=False
        ) as client:
            self.client = client
            
            for form in forms:
                # Skip GET forms (CSRF not applicable for safe methods)
                if form.method.upper() == 'GET':
                    continue
                
                # Check for CSRF token
                has_token = self._has_csrf_token(form.inputs)
                
                if not has_token:
                    # Check if form action is same-origin
                    is_same_origin = self._check_same_origin(form.action, base_url)
                    
                    if is_same_origin:
                        self.findings.append(CSRFinding(
                            url=base_url,
                            form_action=form.action,
                            form_method=form.method,
                            type="missing_token",
                            confidence="high",
                            evidence=f"POST form at {form.action} has no CSRF token field",
                            remediation="Add CSRF tokens to all state-changing forms. Use synchronizer token pattern or double-submit cookie. Implement SameSite cookies."
                        ))
                        self.logger.warning(f"CSRF: Missing token in form at {form.action}")
                    else:
                        # Cross-origin POST form - even more dangerous
                        self.findings.append(CSRFinding(
                            url=base_url,
                            form_action=form.action,
                            form_method=form.method,
                            type="missing_token_cross_origin",
                            confidence="high",
                            evidence=f"POST form submits to external domain {form.action} without CSRF protection",
                            remediation="Remove cross-origin form submissions. If necessary, implement strict CORS and CSRF protection."
                        ))
                        self.logger.warning(f"CSRF: Cross-origin form without token at {form.action}")
        
        self.logger.info(f"CSRF scan complete. Found {len(self.findings)} potential issues")
        return self.findings