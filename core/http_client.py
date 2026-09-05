"""
OXHUNTER - http_client.py
Base HTTP Session Manager - Proxy, Headers, Timeout, Retry, Fingerprinting
"""

import time
import random
import requests
import urllib3
from collections import Counter  # BUG-009 FIX
from typing import Optional, Dict, List, Tuple, Any
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Disable SSL warnings (we're a security tool)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─────────────────────────────────────────────
#  USER AGENT POOL (rotation)
# ─────────────────────────────────────────────
USER_AGENTS = [
    # Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    # Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    # Security Scanner (for transparent testing)
    "OXHUNTER/1.0 Security Scanner",
]


# ─────────────────────────────────────────────
#  RESPONSE WRAPPER
# ─────────────────────────────────────────────
class OXResponse:
    """
    Wrapper around requests.Response with extra metadata.
    """
    def __init__(self, response: requests.Response, elapsed: float, error: Optional[str] = None):
        self.response       = response
        self.elapsed        = elapsed          # seconds
        self.error          = error
        self.status_code    = response.status_code if response else 0
        self.headers        = dict(response.headers) if response else {}
        self.text           = response.text if response else ""
        self.content        = response.content if response else b""
        self.url            = response.url if response else ""
        self.history        = response.history if response else []
        self.redirected     = len(response.history) > 0 if response else False
        self.final_url      = response.url if response else ""

    def json(self) -> Any:
        try:
            return self.response.json()
        except Exception:
            return None

    def contains(self, keyword: str, case_sensitive: bool = False) -> bool:
        text = self.text if case_sensitive else self.text.lower()
        kw   = keyword if case_sensitive else keyword.lower()
        return kw in text

    def has_header(self, header: str) -> bool:
        return header.lower() in {k.lower() for k in self.headers}

    def get_header(self, header: str) -> Optional[str]:
        for k, v in self.headers.items():
            if k.lower() == header.lower():
                return v
        return None

    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    def is_error(self) -> bool:
        return self.status_code >= 400

    def size(self) -> int:
        return len(self.content)

    def __repr__(self):
        return f"<OXResponse [{self.status_code}] {self.url} ({self.elapsed:.2f}s)>"


# ─────────────────────────────────────────────
#  HTTP CLIENT
# ─────────────────────────────────────────────
class HTTPClient:
    """
    Central HTTP client for OXHUNTER.
    Handles sessions, proxies, retries, rate limiting, UA rotation.
    """

    def __init__(
        self,
        timeout         : int              = 10,
        max_retries     : int              = 3,
        delay           : float            = 0.0,
        proxy           : Optional[str]    = None,
        verify_ssl      : bool             = False,
        follow_redirects: bool             = True,
        rotate_ua       : bool             = False,
        headers         : Optional[Dict]   = None,
        cookies         : Optional[Dict]   = None,
        auth_headers    : Optional[Dict]   = None,
    ):
        self.timeout          = timeout
        self.delay            = delay
        self.verify_ssl       = verify_ssl
        self.follow_redirects = follow_redirects
        self.rotate_ua        = rotate_ua
        self.proxy            = proxy
        self._request_count   = 0
        self._error_count     = 0
        self._response_times  : List[float] = []

        # Build session
        self.session = requests.Session()

        # Retry strategy
        retry = Retry(
            total             = max_retries,
            backoff_factor    = 0.5,
            status_forcelist  = [429, 500, 502, 503, 504],
            allowed_methods   = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://",  adapter)
        self.session.mount("https://", adapter)

        # Set proxy
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        # Default headers
        default_headers = {
            "User-Agent"     : USER_AGENTS[0],
            "Accept"         : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection"     : "close",
        }
        if headers:
            default_headers.update(headers)
        if auth_headers:
            default_headers.update(auth_headers)
        self.session.headers.update(default_headers)

        # Cookies
        if cookies:
            self.session.cookies.update(cookies)

    # ── Core Request ──────────────────────────

    def request(
        self,
        method  : str,
        url     : str,
        params  : Optional[Dict]   = None,
        data    : Optional[Any]    = None,
        json    : Optional[Dict]   = None,
        headers : Optional[Dict]   = None,
        cookies : Optional[Dict]   = None,
        timeout : Optional[int]    = None,
        allow_redirects: Optional[bool] = None,
    ) -> OXResponse:
        """Make an HTTP request and return OXResponse."""

        # Rate limiting delay
        if self.delay > 0:
            time.sleep(self.delay)

        # Rotate user agent
        if self.rotate_ua:
            self.session.headers["User-Agent"] = random.choice(USER_AGENTS)

        _timeout          = timeout          or self.timeout
        _allow_redirects  = allow_redirects  if allow_redirects is not None else self.follow_redirects

        start = time.time()
        try:
            resp = self.session.request(
                method          = method.upper(),
                url             = url,
                params          = params,
                data            = data,
                json            = json,
                headers         = headers,
                cookies         = cookies,
                timeout         = _timeout,
                verify          = self.verify_ssl,
                allow_redirects = _allow_redirects,
            )
            elapsed = time.time() - start
            self._request_count  += 1
            self._response_times.append(elapsed)
            return OXResponse(resp, elapsed)

        except requests.exceptions.Timeout:
            self._error_count += 1
            return OXResponse(None, time.time() - start, error="Timeout")
        except requests.exceptions.ConnectionError as e:
            self._error_count += 1
            return OXResponse(None, time.time() - start, error=f"ConnectionError: {e}")
        except Exception as e:
            self._error_count += 1
            return OXResponse(None, time.time() - start, error=str(e))

    # ── Convenience Methods ───────────────────

    def get(self, url: str, **kwargs) -> OXResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> OXResponse:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> OXResponse:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> OXResponse:
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs) -> OXResponse:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> OXResponse:
        return self.request("OPTIONS", url, **kwargs)

    def patch(self, url: str, **kwargs) -> OXResponse:
        return self.request("PATCH", url, **kwargs)

    # ── Bulk Requests ─────────────────────────

    def get_many(self, urls: List[str], **kwargs) -> List[OXResponse]:
        """Send GET request to multiple URLs sequentially."""
        return [self.get(url, **kwargs) for url in urls]

    def fuzz(self, base_url: str, payloads: List[str],
             param: str = "q", method: str = "GET") -> List[Tuple[str, OXResponse]]:
        """
        Send requests with multiple payloads.
        Returns list of (payload, response) tuples.
        """
        results = []
        for payload in payloads:
            if method.upper() == "GET":
                resp = self.get(base_url, params={param: payload})
            else:
                resp = self.post(base_url, data={param: payload})
            results.append((payload, resp))
        return results

    # ── Response Analysis ─────────────────────

    def baseline(self, url: str, count: int = 3) -> Dict:
        """
        Get baseline response data (for differential analysis).
        Used in blind injection detection.
        """
        responses = [self.get(url) for _ in range(count)]
        valid     = [r for r in responses if r.response]

        if not valid:
            return {}

        return {
            "avg_status"  : sum(r.status_code for r in valid) / len(valid),
            "avg_time"    : sum(r.elapsed for r in valid) / len(valid),
            "avg_size"    : sum(r.size() for r in valid) / len(valid),
            "common_status": Counter(r.status_code for r in valid).most_common(1)[0][0],  # BUG-009 FIX: O(n) instead of O(n²)
        }

    def time_based_check(self, url: str, payload_url: str,
                         threshold: float = 5.0) -> bool:
        """
        Check if payload caused significant response delay.
        Used in time-based blind SQLi / Command Injection.
        """
        base    = self.baseline(url)
        resp    = self.get(payload_url)
        base_t  = base.get("avg_time", 1.0)
        return resp.elapsed >= base_t + threshold

    # ── Technology Fingerprinting ─────────────

    def fingerprint(self, url: str) -> Dict:
        """
        Basic technology fingerprinting from response headers and body.
        """
        resp = self.get(url)
        if not resp.response:
            return {}

        tech = {
            "server"     : resp.get_header("Server"),
            "powered_by" : resp.get_header("X-Powered-By"),
            "framework"  : None,
            "language"   : None,
            "cms"        : None,
            "cdn"        : None,
            "waf"        : None,
        }

        body   = resp.text.lower()
        headers_str = str(resp.headers).lower()

        # CMS Detection
        cms_signatures = {
            "WordPress" : ["wp-content", "wp-includes", "wordpress"],
            "Joomla"    : ["joomla", "/components/com_"],
            "Drupal"    : ["drupal", "sites/default/files"],
            "Magento"   : ["magento", "mage/cookies"],
            "Laravel"   : ["laravel_session", "laravel"],
            "Django"    : ["csrfmiddlewaretoken", "django"],
        }
        for name, sigs in cms_signatures.items():
            if any(s in body or s in headers_str for s in sigs):
                tech["cms"] = name
                break

        # Language Detection
        lang_sigs = {
            "PHP"    : [".php", "x-powered-by: php", "phpsessid"],
            "Python" : ["python", "django", "flask", "wsgi"],
            "Java"   : ["java", "jsessionid", "j_session"],
            "Node.js": ["express", "node.js", "x-powered-by: express"],
            "Ruby"   : ["ruby", "rails", "_session_id"],
            "ASP.NET": ["asp.net", "aspxauth", "__viewstate"],
        }
        for lang, sigs in lang_sigs.items():
            if any(s in body or s in headers_str for s in sigs):
                tech["language"] = lang
                break

        # CDN Detection
        cdn_sigs = {
            "Cloudflare" : ["cf-ray", "cloudflare"],
            "Akamai"     : ["akamai", "x-akamai"],
            "Fastly"     : ["fastly", "x-fastly"],
            "AWS CloudFront": ["cloudfront", "x-amz-cf"],
        }
        for cdn, sigs in cdn_sigs.items():
            if any(s in headers_str for s in sigs):
                tech["cdn"] = cdn
                break

        return {k: v for k, v in tech.items() if v}

    # ── Stats ─────────────────────────────────

    def stats(self) -> Dict:
        """Return request statistics."""
        avg_time = (
            sum(self._response_times) / len(self._response_times)
            if self._response_times else 0
        )
        return {
            "total_requests" : self._request_count,
            "errors"         : self._error_count,
            "avg_response_ms": round(avg_time * 1000, 2),
            "success_rate"   : round(
                (self._request_count - self._error_count) / max(self._request_count, 1) * 100, 1
            ),
        }

    def reset_stats(self):
        self._request_count  = 0
        self._error_count    = 0
        self._response_times = []

    def close(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self):
        return (
            f"<HTTPClient timeout={self.timeout}s delay={self.delay}s "
            f"proxy={self.proxy} requests={self._request_count}>"
        )


# ─────────────────────────────────────────────
#  QUICK FACTORY
# ─────────────────────────────────────────────
def make_client(
    proxy       : Optional[str]  = None,
    delay       : float          = 0.5,
    timeout     : int            = 10,
    rotate_ua   : bool           = False,
    headers     : Optional[Dict] = None,
    cookies     : Optional[Dict] = None,
    auth_headers: Optional[Dict] = None,
) -> HTTPClient:
    """Quick factory to create an HTTPClient."""
    return HTTPClient(
        proxy        = proxy,
        delay        = delay,
        timeout      = timeout,
        rotate_ua    = rotate_ua,
        headers      = headers,
        cookies      = cookies,
        auth_headers = auth_headers,
    )


def quick_get(url: str, **kwargs) -> OXResponse:
    """One-shot GET request without managing a session."""
    with HTTPClient() as client:
        return client.get(url, **kwargs)


def quick_post(url: str, **kwargs) -> OXResponse:
    """One-shot POST request without managing a session."""
    with HTTPClient() as client:
        return client.post(url, **kwargs)
