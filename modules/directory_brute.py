"""
Directory & File Bruteforcing Module
Discovers hidden files, directories, admin panels, backup files, and sensitive endpoints
"""

import asyncio
import re
from urllib.parse import urlparse
from typing import List, Optional, Set
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class DirFinding:
    """Represents a discovered directory or file"""
    url: str
    status_code: int
    content_length: int
    content_type: str
    title: str
    severity: str
    category: str   # 'admin', 'backup', 'config', 'sensitive', 'directory', 'api', 'misc'
    evidence: str
    remediation: str


class DirectoryBruteforcer:
    """
    Directory & File Bruteforcing Module
    Discovers:
    - Admin panels (/admin, /dashboard, /cpanel)
    - Backup files (.bak, .old, .zip, .tar.gz)
    - Config files (.env, config.php, web.config)
    - Sensitive files (.git, .svn, robots.txt, sitemap)
    - API endpoints (/api/v1, /swagger, /graphql)
    - Common CMS paths (WordPress, Drupal, Joomla)
    """

    def __init__(self, rate_limiter: RateLimiter, wordlist_file: Optional[str] = None,
                 max_paths: int = 250, concurrency: int = 32,
                 probe_retries: int = 0, timeout_seconds: float = 5.0):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("DirBrute")
        self.findings: List[DirFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(timeout_seconds, connect=min(3.0, timeout_seconds))
        self.found_urls: Set[str] = set()
        self.concurrency = max(1, min(concurrency, 50))
        self.probe_retries = max(0, min(probe_retries, 1))

        # Deduplicate normalized paths and cap work for predictable runtime.
        entries = self._build_wordlist()
        unique = {}
        for path, category, severity in entries:
            unique.setdefault(path.rstrip('/') or '/', (path, category, severity))
        self.wordlist = list(unique.values())[:max(1, max_paths)]

    def _build_wordlist(self) -> List[tuple]:
        """
        Build categorized wordlist.
        Returns list of (path, category, severity)
        """
        entries = []

        # Admin panels - Critical
        admin_paths = [
            "/admin", "/admin/", "/administrator", "/admin/login",
            "/admin/index.php", "/admin/dashboard", "/admin/panel",
            "/adminpanel", "/admin_panel", "/admin-panel",
            "/dashboard", "/dashboard/", "/cpanel", "/whm",
            "/manager", "/management", "/control", "/controlpanel",
            "/backend", "/back-end", "/backoffice", "/back-office",
            "/staff", "/staff/login", "/superadmin", "/superuser",
            "/root", "/webmaster", "/wp-admin", "/wp-login.php",
            "/wp-admin/admin-ajax.php", "/administrator/index.php",
            "/joomla/administrator", "/drupal/admin",
            "/phpmyadmin", "/phpmyadmin/", "/pma", "/myadmin",
            "/adminer", "/adminer.php", "/db", "/database",
            "/panel", "/panel/", "/user/login", "/users/login",
            "/login", "/signin", "/auth/login", "/auth/admin",
        ]
        for p in admin_paths:
            entries.append((p, "admin", "high"))

        # Sensitive config files - Critical
        config_paths = [
            "/.env", "/.env.local", "/.env.production", "/.env.backup",
            "/.env.old", "/.env.example", "/.env.dev", "/.env.staging",
            "/config.php", "/config.yml", "/config.yaml", "/config.json",
            "/configuration.php", "/settings.php", "/settings.py",
            "/web.config", "/app.config", "/appsettings.json",
            "/database.yml", "/database.php", "/db.php", "/db.yml",
            "/wp-config.php", "/wp-config.php.bak", "/wp-config.old",
            "/config/database.yml", "/config/application.yml",
            "/config/secrets.yml", "/config/master.key",
            "/.htpasswd", "/.htaccess", "/server.xml",
            "/application.properties", "/application.yml",
            "/credentials", "/credentials.json", "/secrets.json",
            "/key.pem", "/private.key", "/server.key",
        ]
        for p in config_paths:
            entries.append((p, "config", "critical"))

        # Git/SVN exposure - Critical
        vcs_paths = [
            "/.git", "/.git/", "/.git/HEAD", "/.git/config",
            "/.git/COMMIT_EDITMSG", "/.git/index", "/.git/packed-refs",
            "/.git/refs/heads/master", "/.git/logs/HEAD",
            "/.svn", "/.svn/", "/.svn/entries", "/.svn/wc.db",
            "/.hg", "/.hg/", "/.hg/manifest",
            "/.bzr", "/.bzr/README",
            "/CVS", "/CVS/Root", "/CVS/Entries",
        ]
        for p in vcs_paths:
            entries.append((p, "sensitive", "critical"))

        # Backup files - High
        backup_paths = [
            "/backup", "/backup/", "/backups", "/bak",
            "/backup.zip", "/backup.tar.gz", "/backup.sql",
            "/backup.php", "/backup.old", "/backup.bak",
            "/db_backup.sql", "/database_backup.sql",
            "/site_backup.zip", "/www.zip", "/html.zip",
            "/public_html.zip", "/web.zip",
            "/index.php.bak", "/index.html.bak",
            "/old", "/old/", "/archive", "/archived",
            "/.backup", "/.bak",
        ]
        for p in backup_paths:
            entries.append((p, "backup", "high"))

        # Sensitive files - High
        sensitive_paths = [
            "/robots.txt", "/sitemap.xml", "/sitemap.txt",
            "/.well-known/security.txt", "/.well-known/",
            "/security.txt", "/humans.txt", "/crossdomain.xml",
            "/clientaccesspolicy.xml", "/browserconfig.xml",
            "/manifest.json", "/package.json", "/composer.json",
            "/composer.lock", "/yarn.lock", "/package-lock.json",
            "/Gemfile", "/Gemfile.lock", "/requirements.txt",
            "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
            "/.dockerignore", "/.gitignore", "/.npmrc", "/.pypirc",
            "/phpinfo.php", "/info.php", "/test.php", "/php.php",
            "/server-status", "/server-info",
            "/elmah.axd", "/trace.axd", "/webresource.axd",
        ]
        for p in sensitive_paths:
            entries.append((p, "sensitive", "medium"))

        # API endpoints - Medium
        api_paths = [
            "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
            "/api/v1/", "/api/v2/", "/api/v3/",
            "/api/users", "/api/user", "/api/admin",
            "/api/login", "/api/auth", "/api/token",
            "/api/swagger", "/api/docs", "/api/redoc",
            "/swagger", "/swagger/", "/swagger-ui.html",
            "/swagger-ui/", "/swagger.json", "/swagger.yaml",
            "/api-docs", "/api-docs/", "/openapi.json",
            "/openapi.yaml", "/redoc", "/redoc/",
            "/graphql", "/graphql/", "/graphiql", "/graphiql/",
            "/v1", "/v2", "/v3", "/v1/", "/v2/", "/v3/",
            "/rest", "/rest/", "/restapi", "/restapi/",
        ]
        for p in api_paths:
            entries.append((p, "api", "medium"))

        # Common directories - Low/Info
        common_dirs = [
            "/uploads", "/upload", "/files", "/file",
            "/images", "/image", "/img", "/static",
            "/assets", "/media", "/css", "/js",
            "/download", "/downloads", "/temp", "/tmp",
            "/log", "/logs", "/error", "/errors",
            "/test", "/tests", "/debug", "/dev",
            "/cache", "/cached", "/session", "/sessions",
            "/include", "/includes", "/lib", "/libs",
            "/src", "/source", "/app", "/application",
            "/scripts", "/cgi-bin", "/cgi", "/bin",
            "/vendor", "/node_modules", "/bower_components",
        ]
        for p in common_dirs:
            entries.append((p, "directory", "info"))

        # Monitoring & DevOps - High
        devops_paths = [
            "/actuator", "/actuator/", "/actuator/health",
            "/actuator/env", "/actuator/beans", "/actuator/mappings",
            "/actuator/info", "/actuator/metrics", "/actuator/dump",
            "/health", "/health/", "/healthz", "/ready", "/readyz",
            "/metrics", "/metrics/", "/prometheus", "/prometheus/metrics",
            "/status", "/status/", "/ping", "/alive",
            "/jenkins", "/jenkins/", "/gitlab", "/sonar",
            "/kibana", "/grafana", "/portainer",
            "/.well-known/acme-challenge/",
        ]
        for p in devops_paths:
            entries.append((p, "sensitive", "high"))

        return entries

    def _get_title(self, html: str) -> str:
        """Extract page title from HTML"""
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip()[:80] if match else ""

    def _assess_finding(self, path: str, response: httpx.Response,
                        category: str, severity: str) -> Optional[DirFinding]:
        """Assess if a response indicates a real finding"""
        status = response.status_code
        content_length = len(response.content)
        content_type = response.headers.get('content-type', '')
        title = self._get_title(response.text) if 'html' in content_type else ""

        # Skip obvious 404 pages with low content
        if status == 404 and content_length < 500:
            return None

        # Skip redirects to login (not interesting unless admin path)
        if status in [301, 302] and category not in ['admin', 'config', 'sensitive']:
            return None

        # 200 OK - definitely interesting
        if status == 200 and content_length > 0:
            # Determine severity upgrades
            final_severity = severity

            # Upgrade severity for sensitive content detected in body
            body_lower = response.text.lower()
            if any(kw in body_lower for kw in ['password', 'secret', 'api_key', 'token', 'private']):
                final_severity = "critical"
            elif any(kw in body_lower for kw in ['admin', 'dashboard', 'panel', 'configuration']):
                if final_severity == "info":
                    final_severity = "medium"

            return DirFinding(
                url=path,
                status_code=status,
                content_length=content_length,
                content_type=content_type,
                title=title,
                severity=final_severity,
                category=category,
                evidence=f"HTTP {status} | Size: {content_length}B | Type: {content_type[:40]}",
                remediation=self._get_remediation(category, path)
            )

        # 403 Forbidden - NOT a vulnerability, skip (false positive)
        if status == 403:
            return None  # FIX: 403 = blocked, not a real finding

        # 401 Unauthorized - auth required
        if status == 401:
            return DirFinding(
                url=path,
                status_code=status,
                content_length=content_length,
                content_type=content_type,
                title=title,
                severity=severity,
                category=category,
                evidence="HTTP 401 Unauthorized — resource exists, authentication required",
                remediation=self._get_remediation(category, path)
            )

        return None

    def _get_remediation(self, category: str, path: str) -> str:
        remediations = {
            "admin": (
                "1. Restrict admin panel access by IP allowlist.\n"
                "2. Implement strong authentication (MFA).\n"
                "3. Use non-default admin URL paths.\n"
                "4. Add rate limiting on login endpoints."
            ),
            "config": (
                "1. Remove configuration files from web root immediately.\n"
                "2. Add these paths to .htaccess or nginx deny rules.\n"
                "3. Store configs outside web root.\n"
                "4. Use environment variables instead of config files."
            ),
            "sensitive": (
                "1. Remove or restrict access to this sensitive file/directory.\n"
                "2. Add deny rules in web server configuration.\n"
                "3. Review what data is exposed and rotate any leaked credentials.\n"
                "4. Add this path to robots.txt (security through obscurity only)."
            ),
            "backup": (
                "1. Delete backup files from web root immediately.\n"
                "2. Store backups outside web root or on separate secure storage.\n"
                "3. Audit what data is in backup files.\n"
                "4. Implement proper backup policies."
            ),
            "api": (
                "1. Disable API documentation in production (Swagger, GraphiQL).\n"
                "2. Require authentication for all API endpoints.\n"
                "3. Implement API rate limiting.\n"
                "4. Review exposed API endpoints for sensitive data."
            ),
            "directory": (
                "1. Disable directory listing in web server config.\n"
                "2. Remove unnecessary files from web root.\n"
                "3. Nginx: autoindex off; Apache: Options -Indexes"
            ),
        }
        return remediations.get(category, "Restrict access to this resource.")

    async def _probe_path(self, base_url: str, path: str,
                          category: str, severity: str) -> Optional[DirFinding]:
        """Probe a single path"""
        url = base_url.rstrip('/') + path
        try:
            async def _do_request():
                return await self.client.get(url, follow_redirects=False)
            response = await self.rate_limiter.execute_with_retry(
                _do_request, retries=self.probe_retries)
            if not response:
                return None

            finding = self._assess_finding(path, response, category, severity)
            if finding:
                finding.url = url  # store full URL
                return finding
        except Exception as e:
            self.logger.debug(f"Probe failed {url}: {e}")
        return None

    async def scan(self, target_urls: List[str], forms: List = None) -> List[DirFinding]:  # NEW-BUG-001 FIX
        forms = forms or []  # NEW-BUG-001 FIX
        """Main directory brute-force scan"""
        # Get unique base URLs
        base_urls: Set[str] = set()
        for url in target_urls:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            base_urls.add(base)

        if not base_urls:
            return []

        self.logger.info(f"Starting directory bruteforce on {len(base_urls)} base URL(s) "
                         f"with {len(self.wordlist)} paths")

        headers = {
            'User-Agent': '0xHunter Security Scanner (Authorized Testing)',
            'Accept': 'text/html,application/json,*/*',
        }

        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=False,
            verify=False
        ) as client:
            self.client = client

            for base_url in base_urls:
                self.logger.info(f"Scanning: {base_url}")
                # Bounded batches avoid unbounded task creation while allowing
                # useful concurrency. The shared rate limiter remains authoritative.
                tasks = [
                    self._probe_path(base_url, path, category, severity)
                    for path, category, severity in self.wordlist
                ]
                batch_size = self.concurrency
                for i in range(0, len(tasks), batch_size):
                    batch = tasks[i:i + batch_size]
                    results = await asyncio.gather(*batch, return_exceptions=True)

                    for result in results:
                        if isinstance(result, DirFinding):
                            key = result.url
                            if key not in self.found_urls:
                                self.found_urls.add(key)
                                self.findings.append(result)
                                self.logger.warning(
                                    f"FOUND [{result.severity.upper()}]: "
                                    f"{result.url} | {result.status_code} | "
                                    f"{result.category} | {result.title[:40]}"
                                )

        self.logger.info(f"Directory bruteforce complete. Found {len(self.findings)} paths")
        return self.findings
