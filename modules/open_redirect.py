"""
Open Redirect Detection Module
Tests for unvalidated redirect/forwards vulnerabilities
"""

import asyncio
import re
from urllib.parse import urlparse, parse_qsl, urlencode
from typing import List, Optional
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class OpenRedirectFinding:
    """Represents an open redirect vulnerability"""
    url: str
    parameter: str
    payload: str
    type: str  # 'open_redirect', 'url_manipulation'
    confidence: str
    evidence: str
    remediation: str


class OpenRedirectScanner:
    """
    Open Redirect Detection Module
    Tests URL parameters for unvalidated redirects.
    """
    
    # Common redirect parameter names
    REDIRECT_PARAMS = [
        'redirect', 'redirect_to', 'redirect_url', 'return', 'return_url',
        'return_to', 'url', 'next', 'target', 'destination', 'dest',
        'goto', 'go', 'link', 'href', 'path', 'site', 'uri', 'forward',
        'returnUrl', 'redirectUrl', 'callback', 'cb', 'redir', 'to',
        'login_return', 'logout_return', 'continue', 'return_path'
    ]
    
    # Test payloads - external domains to test redirect
    TEST_PAYLOADS = [
        'https://evil.com',
        'http://evil.com',
        '//evil.com',
        'https://attacker.example.com',
        'http://attacker.example.com',
        '//attacker.example.com',
    ]
    
    def __init__(self, rate_limiter: RateLimiter, payload_file: str = None):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("OpenRedirect")
        self.findings: List[OpenRedirectFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(8.0, connect=5.0)
    
    async def _fetch(self, url: str, allow_redirects: bool = False) -> Optional[httpx.Response]:
        """Make HTTP request with rate limiting, don't follow redirects"""
        try:
            async def _do_request():
                return await self.client.get(url, follow_redirects=allow_redirects)
            return await self.rate_limiter.execute_with_retry(_do_request)
        except Exception as e:
            self.logger.warning(f"Request failed {url}: {e}")
            return None
    
    def _is_redirect_param(self, param_name: str) -> bool:
        """Check if parameter name suggests it's used for redirects"""
        param_lower = param_name.lower()
        return any(redirect in param_lower for redirect in self.REDIRECT_PARAMS)
    
    def _detect_redirect(self, response: httpx.Response, payload: str) -> bool:
        """Detect if response contains a redirect to our payload"""
        # Check Location header
        location = response.headers.get('location', '')
        if location and payload in location:
            return True
        
        # Check Refresh header
        refresh = response.headers.get('refresh', '')
        if payload in refresh:
            return True
        
        # Check for meta refresh in body
        if payload in response.text and 'meta' in response.text.lower():
            pattern = "<meta[^>]*http-equiv=" + '"' + "refresh" + '"'
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        # Check for JavaScript redirects
        if 'window.location' in response.text or 'document.location' in response.text:
            if payload in response.text:
                return True
        
        return False
    
    async def _test_parameter(self, url: str, param: str, payload: str) -> Optional[OpenRedirectFinding]:
        """Test a single URL parameter for open redirect"""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        
        if param not in params:
            return None
        
        # Create test URL with payload
        test_params = params.copy()
        test_params[param] = payload
        test_query = urlencode(test_params)
        test_url = parsed._replace(query=test_query).geturl()
        
        # Make request without following redirects
        response = await self._fetch(test_url, allow_redirects=False)
        if not response:
            return None
        
        # Check for redirect indicators
        if self._detect_redirect(response, payload):
            return OpenRedirectFinding(
                url=url,
                parameter=param,
                payload=payload,
                type="open_redirect",
                confidence="high",
                evidence=f"Redirect detected to external domain via {param} parameter",
                remediation="Validate and whitelist redirect destinations. Use internal mapping (ID-to-URL) instead of direct URLs. Never trust user input for redirect targets."
            )
        
        # Also check if response is 3xx status
        if 300 <= response.status_code < 400:
            location = response.headers.get('location', '')
            if location:
                # Check if redirect goes to external domain
                parsed_loc = urlparse(location)
                parsed_base = urlparse(url)
                
                if parsed_loc.netloc and parsed_loc.netloc != parsed_base.netloc:
                    if payload in location or 'evil.com' in location or 'attacker' in location:
                        return OpenRedirectFinding(
                            url=url,
                            parameter=param,
                            payload=payload,
                            type="open_redirect",
                            confidence="high",
                            evidence=f"HTTP {response.status_code} redirect to external domain: {location}",
                            remediation="Implement strict redirect validation. Use allow-list of permitted domains. Consider using path-only redirects."
                        )
        
        return None
    
    async def scan(self, target_urls: List[str]) -> List[OpenRedirectFinding]:
        """
        Main scan method.
        target_urls: List of URLs with parameters
        """
        self.logger.info(f"Starting Open Redirect scan on {len(target_urls)} URLs")
        
        headers = {
            'User-Agent': '0xHunter Security Scanner (Authorized Testing)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        
        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=False,  # Important: don't follow redirects
            verify=False
        ) as client:
            self.client = client
            
            tasks = []
            tested_params = set()
            
            for url in target_urls:
                parsed = urlparse(url)
                params = dict(parse_qsl(parsed.query))
                
                for param in params.keys():
                    # Only test parameters that look like redirect params
                    if self._is_redirect_param(param):
                        param_key = f"{url}:{param}"
                        if param_key not in tested_params:
                            tested_params.add(param_key)
                            for payload in self.TEST_PAYLOADS:
                                tasks.append(self._test_parameter(url, param, payload))
            
            if not tasks:
                self.logger.info("No redirect-like parameters found to test")
                return self.findings
            
            self.logger.info(f"Running {len(tasks)} Open Redirect tests...")
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    self.logger.error(f"Open Redirect test error: {result}")
                    continue
                if result:
                    self.findings.append(result)
                    self.logger.warning(f"Open Redirect Found: {result.url} | Param: {result.parameter}")
        
        self.logger.info(f"Open Redirect scan complete. Found {len(self.findings)} potential issues")
        return self.findings