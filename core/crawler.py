"""
Web Crawler - Discovers URLs, forms, and inputs on the target
"""

import asyncio
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field

from core.validator import ScopeValidator
from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class Form:
    """Represents a discovered HTML form"""
    action: str
    method: str
    inputs: List[Dict[str, str]] = field(default_factory=list)
    
    def __repr__(self):
        return f"Form(action={self.action}, method={self.method}, inputs={len(self.inputs)})"


@dataclass  
class CrawlResult:
    """Results from crawling a URL"""
    url: str
    status_code: int
    title: str = ""
    links: List[str] = field(default_factory=list)
    forms: List[Form] = field(default_factory=list)
    parameters: Dict[str, List[str]] = field(default_factory=dict)  # BUG-001 FIX


class WebCrawler:
    """
    Async web crawler that discovers URLs, forms, and parameters
    while respecting scope and rate limits.
    """
    
    def __init__(self, target_url: str, validator: ScopeValidator, 
                 rate_limiter: RateLimiter, max_depth: int = 3, 
                 max_urls: int = 500):
        self.target_url = target_url.rstrip('/')
        self.validator = validator
        self.rate_limiter = rate_limiter
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.logger = setup_logger("Crawler")
        
        self.visited: Set[str] = set()
        self.results: List[CrawlResult] = []
        self.all_urls: Set[str] = set()
        self.all_forms: List[Form] = []
        
        # HTTP client settings
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(8.0, connect=5.0)
    
    async def _fetch(self, url: str) -> Optional[httpx.Response]:
        """Fetch a URL with rate limiting and retry logic"""
        try:
            async def _do_request():
                return await self.client.get(url, follow_redirects=True)
            
            response = await self.rate_limiter.execute_with_retry(_do_request)
            return response
        except Exception as e:
            self.logger.warning(f"Failed to fetch {url}: {e}")
            return None
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract all links from a page"""
        links = []
        for tag in soup.find_all(['a', 'link'], href=True):
            href = tag['href']
            full_url = urljoin(base_url, href)
            normalized = self.validator.normalize_url(full_url)
            if normalized and normalized not in self.visited:
                links.append(normalized)
        return links
    
    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Form]:
        """Extract all forms from a page"""
        forms = []
        for form_tag in soup.find_all('form'):
            action = urljoin(base_url, form_tag.get('action', ''))
            method = form_tag.get('method', 'GET').upper()
            
            inputs = []
            for inp in form_tag.find_all(['input', 'textarea', 'select']):
                inp_info = {
                    'name': inp.get('name', ''),
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', ''),
                    'tag': inp.name
                }
                if inp_info['name']:
                    inputs.append(inp_info)
            
            forms.append(Form(action=action, method=method, inputs=inputs))
        return forms
    
    def _extract_parameters(self, url: str) -> Dict[str, List[str]]:
        """Extract URL parameters"""
        parsed = urlparse(url)
        return parse_qs(parsed.query)
    
    async def _crawl_url(self, url: str, depth: int = 0) -> Optional[CrawlResult]:
        """Crawl a single URL"""
        if depth > self.max_depth or len(self.visited) >= self.max_urls:
            return None
        
        if url in self.visited:
            return None
        
        self.visited.add(url)
        self.logger.info(f"Crawling [{depth}]: {url}")
        
        response = await self._fetch(url)
        if not response:
            return None

        # Skip 4xx / 5xx error pages
        if response.status_code in [404, 403, 401, 410, 500, 502, 503]:
            self.logger.debug(f"Skipping {response.status_code} page: {url}")
            return CrawlResult(url=url, status_code=response.status_code)

        # Skip non-HTML responses
        content_type = response.headers.get('content-type', '')
        if 'text/html' not in content_type:
            return CrawlResult(url=url, status_code=response.status_code)
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract data
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        links = self._extract_links(soup, url)
        forms = self._extract_forms(soup, url)
        parameters = self._extract_parameters(url)
        
        result = CrawlResult(
            url=url,
            status_code=response.status_code,
            title=title,
            links=links,
            forms=forms,
            parameters=parameters
        )
        
        # Store discovered items
        self.all_urls.update(links)
        self.all_forms.extend(forms)
        
        return result
    
    async def crawl(self) -> List[CrawlResult]:
        """
        Main crawl method. Starts from target URL and discovers
        all in-scope pages up to max_depth.
        """
        self.logger.info(f"Starting crawl of {self.target_url}")
        
        headers = {
            'User-Agent': '0xHunter Security Scanner (Authorized Testing)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=True,
            verify=False
        ) as client:
            self.client = client
            
            # BFS crawl
            queue = [(self.target_url, 0)]
            
            while queue and len(self.visited) < self.max_urls:
                current_batch = []
                
                # SPEED-003: larger batch = faster crawl (was 5)
                while queue and len(current_batch) < 20:
                    url, depth = queue.pop(0)
                    if url not in self.visited:
                        current_batch.append((url, depth))
                
                if not current_batch:
                    break
                
                # Crawl batch concurrently
                tasks = [self._crawl_url(url, depth) for url, depth in current_batch]
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, Exception):
                        self.logger.error(f"Crawl error: {result}")
                        continue
                    if result:
                        self.results.append(result)
                        # Add new links to queue
                        for link in result.links:
                            if link not in self.visited:
                                queue.append((link, depth + 1))
        
        self.logger.info(f"Crawl complete. Discovered {len(self.visited)} URLs, {len(self.all_forms)} forms")
        return self.results
    
    def get_injectable_urls(self) -> List[str]:
        """
        Return only URLs that have at least one real query parameter with a value.
        
        FIX: Old code used ('?' in url or '=' in url) which incorrectly included:
          - URLs with '=' inside the path  e.g. /intl/en=GB/about
          - URLs with '?' but no params    e.g. /search?
          - Static assets                  e.g. /style.min.css?v=2
        """
        STATIC_EXTENSIONS = {
            '.css', '.js', '.png', '.jpg', '.jpeg', '.gif',
            '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot',
            '.pdf', '.zip', '.map', '.webp',
        }

        injectable = []
        seen = set()

        for url in self.all_urls:
            if url in seen:
                continue
            seen.add(url)

            try:
                parsed = urlparse(url)
            except Exception:
                continue

            # Skip static assets — they are never injectable
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in STATIC_EXTENSIONS):
                continue

            # Must have a query string with at least one key=value pair
            if not parsed.query:
                continue

            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue

            injectable.append(url)

        return injectable
    
    def get_all_forms(self) -> List[Form]:
        """Get all discovered forms"""
        return self.all_forms