"""
Subdomain Enumeration Module
Discovers subdomains via wordlist brute-force, DNS resolution, and certificate transparency
"""

import asyncio
import socket
from urllib.parse import urlparse
from typing import List, Optional, Set
from dataclasses import dataclass, field

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class SubdomainFinding:
    """Represents a discovered subdomain"""
    subdomain: str
    ip_address: str
    status_code: int
    title: str
    server: str
    is_alive: bool
    technologies: List[str] = field(default_factory=list)
    notes: str = ""


class SubdomainEnumerator:
    """
    Subdomain Enumeration Module
    Discovers subdomains via:
    - Wordlist brute-force (DNS resolution)
    - Certificate Transparency logs (crt.sh)
    - Common subdomain patterns
    - HTTP probing for alive subdomains
    """

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("Subdomain")
        self.findings: List[SubdomainFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(10.0, connect=5.0)

        # Built-in wordlist (common subdomains)
        self.wordlist = [
            # Most common
            "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
            "blog", "shop", "store", "app", "mobile", "m", "cdn", "static",
            "media", "img", "images", "assets", "upload", "uploads", "files",
            # Infrastructure
            "vpn", "ssh", "remote", "rdp", "citrix", "portal", "gateway",
            "proxy", "firewall", "router", "switch", "dns", "ns1", "ns2",
            "mx", "smtp", "pop", "imap", "webmail", "owa", "exchange",
            # Services
            "api", "api2", "apiv2", "api-dev", "api-test", "api-staging",
            "v1", "v2", "v3", "rest", "graphql", "grpc", "websocket",
            # Dev environments
            "dev", "dev1", "dev2", "development", "develop",
            "test", "test1", "test2", "testing", "qa", "uat",
            "staging", "stage", "preprod", "pre-prod", "preview",
            "sandbox", "demo", "beta", "alpha", "experimental",
            # Admin panels
            "admin", "administrator", "panel", "dashboard", "control",
            "manage", "manager", "management", "cpanel", "whm",
            "phpmyadmin", "adminer", "webadmin",
            # Databases
            "db", "database", "mysql", "postgres", "mongo", "redis",
            "elastic", "elasticsearch", "kibana", "grafana", "influx",
            # Monitoring
            "monitor", "monitoring", "metrics", "status", "health",
            "nagios", "zabbix", "prometheus", "alert", "alerts",
            # CI/CD
            "jenkins", "gitlab", "github", "bitbucket", "ci", "cd",
            "build", "deploy", "jira", "confluence", "sonar",
            # Cloud
            "aws", "azure", "gcp", "cloud", "s3", "storage",
            # Auth
            "auth", "login", "sso", "oauth", "id", "identity",
            "account", "accounts", "user", "users", "profile",
            # Misc
            "help", "support", "docs", "documentation", "wiki",
            "forum", "community", "chat", "meet", "video",
            "old", "new", "backup", "bak", "archive", "legacy",
            "internal", "intranet", "corp", "office", "hr",
            "git", "svn", "repo", "registry", "docker", "k8s",
        ]

    async def _resolve_subdomain(self, subdomain: str) -> Optional[str]:
        """DNS resolve a subdomain, return IP if exists"""
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None, socket.gethostbyname, subdomain
            )
            return result
        except (socket.gaierror, socket.herror):
            return None

    async def _probe_http(self, subdomain: str, ip: str) -> SubdomainFinding:
        """Probe subdomain over HTTP/HTTPS to get status, title, server"""
        status_code = 0
        title = ""
        server = ""
        technologies = []
        is_alive = False

        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{subdomain}/"
                async def _do_request(u=url):
                    return await self.client.get(u, follow_redirects=True)
                response = await self.rate_limiter.execute_with_retry(_do_request)

                if response:
                    is_alive = True
                    status_code = response.status_code
                    server = response.headers.get('server', '')

                    # Extract title
                    import re
                    title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
                    if title_match:
                        title = title_match.group(1).strip()[:100]

                    # Detect technologies from headers
                    powered_by = response.headers.get('x-powered-by', '')
                    if powered_by:
                        technologies.append(powered_by)
                    if 'wordpress' in response.text.lower():
                        technologies.append('WordPress')
                    if 'drupal' in response.text.lower():
                        technologies.append('Drupal')
                    if 'joomla' in response.text.lower():
                        technologies.append('Joomla')
                    if 'laravel' in response.headers.get('set-cookie', '').lower():
                        technologies.append('Laravel')
                    if server:
                        technologies.append(server)

                    break
            except Exception:
                continue

        return SubdomainFinding(
            subdomain=subdomain,
            ip_address=ip,
            status_code=status_code,
            title=title,
            server=server,
            is_alive=is_alive,
            technologies=list(set(technologies)),
            notes=""
        )

    async def _fetch_crtsh(self, domain: str) -> Set[str]:
        """Fetch subdomains from certificate transparency logs (crt.sh)"""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async def _do_request():
                return await self.client.get(url, follow_redirects=True)
            response = await self.rate_limiter.execute_with_retry(_do_request)

            if response and response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(f'.{domain}') and '*' not in sub:
                            subdomains.add(sub)
                self.logger.info(f"crt.sh found {len(subdomains)} subdomains for {domain}")
        except Exception as e:
            self.logger.debug(f"crt.sh lookup failed: {e}")

        return subdomains

    async def _fetch_hackertarget(self, domain: str) -> Set[str]:
        """Fetch subdomains from HackerTarget API"""
        subdomains = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            async def _do_request():
                return await self.client.get(url, follow_redirects=True)
            response = await self.rate_limiter.execute_with_retry(_do_request)

            if response and response.status_code == 200 and 'error' not in response.text.lower():
                for line in response.text.strip().split('\n'):
                    if ',' in line:
                        sub = line.split(',')[0].strip().lower()
                        if sub.endswith(f'.{domain}'):
                            subdomains.add(sub)
                self.logger.info(f"HackerTarget found {len(subdomains)} subdomains for {domain}")
        except Exception as e:
            self.logger.debug(f"HackerTarget lookup failed: {e}")

        return subdomains

    async def enumerate(self, domain: str) -> List[SubdomainFinding]:
        """
        Full subdomain enumeration for a domain.
        Combines: wordlist brute-force + crt.sh + HackerTarget
        """
        self.logger.info(f"Starting subdomain enumeration for {domain}")
        all_subdomains: Set[str] = set()

        headers = {
            'User-Agent': '0xHunter Security Scanner (Authorized Testing)',
        }

        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=True,
            verify=False
        ) as client:
            self.client = client

            # 1. Certificate transparency logs
            crt_subs = await self._fetch_crtsh(domain)
            all_subdomains.update(crt_subs)

            # 2. HackerTarget
            ht_subs = await self._fetch_hackertarget(domain)
            all_subdomains.update(ht_subs)

            # 3. Wordlist brute-force
            wordlist_subs = {f"{word}.{domain}" for word in self.wordlist}
            all_subdomains.update(wordlist_subs)

            self.logger.info(f"Total unique subdomains to probe: {len(all_subdomains)}")

            # 4. DNS resolve all subdomains concurrently
            resolve_tasks = [self._resolve_subdomain(sub) for sub in all_subdomains]
            resolved = await asyncio.gather(*resolve_tasks, return_exceptions=True)

            # 5. Probe alive subdomains over HTTP
            alive_targets = []
            for subdomain, ip in zip(all_subdomains, resolved):
                if isinstance(ip, str) and ip:
                    alive_targets.append((subdomain, ip))

            self.logger.info(f"DNS resolved {len(alive_targets)} alive subdomains — probing HTTP...")

            probe_tasks = [self._probe_http(sub, ip) for sub, ip in alive_targets]
            probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

            for result in probe_results:
                if isinstance(result, SubdomainFinding) and result.is_alive:
                    self.findings.append(result)
                    self.logger.info(
                        f"ALIVE: {result.subdomain} [{result.ip_address}] "
                        f"Status: {result.status_code} | Title: {result.title[:50]}"
                    )

        self.logger.info(f"Subdomain enumeration complete. Found {len(self.findings)} alive subdomains")
        return self.findings

    async def scan(self, target_urls: List[str], forms: List = None) -> List[SubdomainFinding]:  # NEW-BUG-001 FIX
        forms = forms or []  # NEW-BUG-001 FIX
        """Main scan entry point — extracts domain and enumerates"""
        domains_seen = set()
        for url in target_urls:
            parsed = urlparse(url)
            host = parsed.hostname or ''
            # Get base domain (last two parts)
            parts = host.split('.')
            if len(parts) >= 2:
                domain = '.'.join(parts[-2:])
                if domain not in domains_seen:
                    domains_seen.add(domain)
                    await self.enumerate(domain)

        return self.findings
