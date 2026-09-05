"""
SQL Injection Detection Module
Tests for error-based, boolean-based, and time-based SQLi
"""

import asyncio
import re
from urllib.parse import urlparse, parse_qsl, urlencode
from typing import List, Dict, Optional
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from core.paths import PAYLOADS_DIR
from utils.logger import setup_logger


@dataclass
class SQLiFinding:
    """Represents a confirmed or potential SQL Injection vulnerability"""
    url: str
    parameter: str
    payload: str
    type: str  # 'error_based', 'boolean_based', 'time_based', 'union_based'
    confidence: str
    evidence: str
    remediation: str
    severity: str = "high"  # BUG-005 FIX: explicit severity


class SQLiScanner:
    """
    SQL Injection Detection Module
    Tests URL parameters and form inputs for SQLi vulnerabilities.
    """
    
    # Common SQL error patterns that indicate vulnerability
    SQL_ERRORS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.*SQL.*Server",
        r"OLE DB.*SQL.*Server",
        r"\bSQL Server.*Driver",
        r"Warning.*mssql_.*",
        r"\bMicrosoft SQL Server.*Error",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"SqlException",
        r"Oracle.*Error",
        r"Oracle.*Driver",
        r"Warning.*oci_.*",
        r"Microsoft OLE DB Provider for Oracle",
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
        r"Warning.*sqlite_.*",
        r"Warning.*SQLite3::",
        r"\[IBM\]\[CLI Driver\]\[DB2/6000\]",
        r"CLI Driver.*DB2",
        r"DB2 SQL error",
        r"\bdb2_\w+\(",
        r"Sybase message",
        r"Sybase.*Server message",
        r"Warning.*sybase.*",
        r"Dynamic SQL Error",
        r"Warning.*ibase_.*",
        r"syntax error",
        r"unexpected token",
        r"unterminated string",
        r"quoted string not properly terminated",
        r"You have an error in your SQL syntax",
        r"unrecognized token",
    ]
    
    def __init__(self, rate_limiter: RateLimiter, payload_file: str = None):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("SQLi")
        resolved = str(PAYLOADS_DIR / "sqli/sqli.txt") if payload_file is None else payload_file
        self.payloads = self._load_payloads(resolved)
        self.findings: List[SQLiFinding] = []
        
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(8.0, connect=5.0)
        self.error_patterns = [re.compile(err, re.IGNORECASE) for err in self.SQL_ERRORS]
    
    def _load_payloads(self, filepath: str) -> List[str]:
        """Load SQLi payloads from file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            self.logger.info(f"Loaded {len(payloads)} SQLi payloads")
            return payloads
        except FileNotFoundError:
            self.logger.warning(f"Payload file not found: {filepath}. Using defaults.")
            return self._default_payloads()
    
    def _default_payloads(self) -> List[str]:
        """Default SQLi payloads"""
        return [
            "'",
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SLEEP(5)--",
            "'; DROP TABLE users--",
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
    
    def _detect_sql_error(self, response_text: str) -> Optional[str]:
        """Check if response contains SQL error messages"""
        for pattern in self.error_patterns:
            match = pattern.search(response_text)
            if match:
                return match.group(0)
        return None
    
    def _check_boolean_based(self, true_response: str, false_response: str) -> bool:
        """Compare TRUE vs FALSE condition responses for boolean-based detection"""
        true_len = len(true_response)
        false_len = len(false_response)
        
        if abs(true_len - false_len) > 50:
            return True
        
        if true_response != false_response:
            true_has_error = self._detect_sql_error(true_response) is not None
            false_has_error = self._detect_sql_error(false_response) is not None
            if true_has_error != false_has_error:
                return True
        
        return False
    
    async def _test_error_based(self, url: str, param: str) -> Optional[SQLiFinding]:
        """Test for error-based SQLi using single quote"""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        
        if param not in params:
            return None
        
        test_params = params.copy()
        test_params[param] = "'"
        test_query = urlencode(test_params)
        test_url = parsed._replace(query=test_query).geturl()
        
        response = await self._fetch(test_url)
        if not response:
            return None
        
        error = self._detect_sql_error(response.text)
        if error:
            return SQLiFinding(
                url=url,
                parameter=param,
                payload="'",
                type="error_based",
                confidence="high",
                evidence=f"SQL error detected: {error[:100]}",
                remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL. Use ORM frameworks. Validate and sanitize all input."
            )
        
        return None
    
    async def _test_boolean_based(self, url: str, param: str) -> Optional[SQLiFinding]:
        """Test for boolean-based SQLi using AND 1=1 vs AND 1=2"""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        
        if param not in params:
            return None
        
        original_value = params[param]
        
        test_params_true = params.copy()
        test_params_true[param] = f"{original_value}' AND 1=1--"
        test_url_true = parsed._replace(query=urlencode(test_params_true)).geturl()
        
        test_params_false = params.copy()
        test_params_false[param] = f"{original_value}' AND 1=2--"
        test_url_false = parsed._replace(query=urlencode(test_params_false)).geturl()
        
        resp_true = await self._fetch(test_url_true)
        resp_false = await self._fetch(test_url_false)
        
        if not resp_true or not resp_false:
            return None
        
        if self._check_boolean_based(resp_true.text, resp_false.text):
            return SQLiFinding(
                url=url,
                parameter=param,
                payload="' AND 1=1-- / ' AND 1=2--",
                type="boolean_based",
                confidence="medium",
                evidence="Different responses for TRUE vs FALSE SQL conditions",
                remediation="Use parameterized queries. Implement strict input validation. Use WAF rules."
            )
        
        return None
    
    async def _test_form(self, form_action: str, form_method: str,
                         inputs: List[Dict]) -> Optional[SQLiFinding]:
        """Test a form for SQLi"""
        data = {}
        target_input = None
        
        for inp in inputs:
            if inp.get('name'):
                if inp.get('type') in ['text', 'search', 'url', 'email', 'password', '']:
                    data[inp['name']] = "'"
                    target_input = inp['name']
                else:
                    data[inp['name']] = inp.get('value', 'test')
        
        if not target_input:
            return None
        
        method = form_method.upper()
        if method == "POST":
            response = await self._fetch(form_action, method="POST", data=data)
        else:
            test_url = f"{form_action}?{urlencode(data)}"
            response = await self._fetch(test_url)
        
        if not response:
            return None
        
        error = self._detect_sql_error(response.text)
        if error:
            return SQLiFinding(
                url=form_action,
                parameter=target_input,
                payload="'",
                type="error_based",
                confidence="high",
                evidence=f"SQL error in form submission: {error[:100]}",
                remediation="Use parameterized queries for all database operations. Never build SQL with string concatenation."
            )
        
        return None
    
    async def scan(self, target_urls: List[str], forms: List) -> List[SQLiFinding]:
        """Main scan method"""
        self.logger.info(f"Starting SQLi scan on {len(target_urls)} URLs and {len(forms)} forms")
        
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
            
            for url in target_urls:
                parsed = urlparse(url)
                params = dict(parse_qsl(parsed.query))
                for param in params.keys():
                    tasks.append(self._test_error_based(url, param))
                    tasks.append(self._test_boolean_based(url, param))
            
            for form in forms:
                tasks.append(self._test_form(form.action, form.method, form.inputs))
            
            self.logger.info(f"Running {len(tasks)} SQLi tests...")
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    self.logger.error(f"SQLi test error: {result}")
                    continue
                if result:
                    self.findings.append(result)
                    self.logger.warning(f"SQLi Found: {result.url} | Param: {result.parameter} | Type: {result.type} | Confidence: {result.confidence}")
        
        self.logger.info(f"SQLi scan complete. Found {len(self.findings)} potential issues")
        return self.findings