"""
Git Exposure Check Module
Detects exposed .git folders, sensitive files, and version control data
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
class GitFinding:
    """Represents a Git/VCS exposure finding"""
    url: str
    type: str        # 'git_folder', 'git_file', 'svn', 'env_file', 'sensitive_file', 'backup'
    severity: str
    confidence: str
    file_path: str
    content_preview: str
    evidence: str
    remediation: str


class GitExposureScanner:
    """
    Git Exposure & Sensitive File Detection Module
    Detects:
    - Exposed .git/ directory and files
    - .svn, .hg, .bzr version control
    - .env, config files with credentials
    - Backup files (.bak, .old, .zip)
    - Log files with sensitive data
    - Source code exposure
    - Database dumps
    """

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("GitExposure")
        self.findings: List[GitFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(15.0, connect=8.0)

        # All paths to check with (category, severity)
        self.check_paths = self._build_check_paths()

    def _build_check_paths(self) -> List[tuple]:
        """Build comprehensive list of paths to check"""
        paths = []

        # Git core files — Critical
        git_files = [
            ("/.git/HEAD",                  "git_file",     "critical"),
            ("/.git/config",                "git_file",     "critical"),
            ("/.git/index",                 "git_file",     "critical"),
            ("/.git/COMMIT_EDITMSG",        "git_file",     "critical"),
            ("/.git/packed-refs",           "git_file",     "critical"),
            ("/.git/FETCH_HEAD",            "git_file",     "critical"),
            ("/.git/logs/HEAD",             "git_file",     "critical"),
            ("/.git/refs/heads/master",     "git_file",     "critical"),
            ("/.git/refs/heads/main",       "git_file",     "critical"),
            ("/.git/objects/info/packs",    "git_file",     "critical"),
            ("/.git/info/exclude",          "git_file",     "high"),
            ("/.git/description",           "git_file",     "medium"),
            ("/.gitignore",                 "git_file",     "medium"),
            ("/.git-credentials",           "git_file",     "critical"),
        ]
        paths.extend(git_files)

        # SVN / Mercurial / Bazaar — Critical
        vcs_files = [
            ("/.svn/entries",               "svn",          "critical"),
            ("/.svn/wc.db",                 "svn",          "critical"),
            ("/.svn/all-wcprops",           "svn",          "critical"),
            ("/.hg/manifest",               "hg",           "critical"),
            ("/.hg/store/00manifest.i",     "hg",           "critical"),
            ("/.bzr/README",                "bzr",          "high"),
            ("/CVS/Root",                   "cvs",          "high"),
            ("/CVS/Entries",                "cvs",          "high"),
        ]
        paths.extend(vcs_files)

        # Environment & Config files — Critical
        env_files = [
            ("/.env",                       "env_file",     "critical"),
            ("/.env.local",                 "env_file",     "critical"),
            ("/.env.production",            "env_file",     "critical"),
            ("/.env.prod",                  "env_file",     "critical"),
            ("/.env.staging",               "env_file",     "critical"),
            ("/.env.development",           "env_file",     "critical"),
            ("/.env.dev",                   "env_file",     "critical"),
            ("/.env.backup",                "env_file",     "critical"),
            ("/.env.old",                   "env_file",     "critical"),
            ("/.env.example",               "env_file",     "medium"),
            ("/config.php",                 "env_file",     "critical"),
            ("/configuration.php",          "env_file",     "critical"),
            ("/wp-config.php",              "env_file",     "critical"),
            ("/wp-config.php.bak",          "env_file",     "critical"),
            ("/settings.py",                "env_file",     "critical"),
            ("/settings.php",               "env_file",     "critical"),
            ("/database.yml",               "env_file",     "critical"),
            ("/config/database.yml",        "env_file",     "critical"),
            ("/config/secrets.yml",         "env_file",     "critical"),
            ("/config/master.key",          "env_file",     "critical"),
            ("/application.properties",     "env_file",     "critical"),
            ("/appsettings.json",           "env_file",     "critical"),
            ("/web.config",                 "env_file",     "high"),
            ("/.htpasswd",                  "env_file",     "critical"),
            ("/credentials.json",           "env_file",     "critical"),
            ("/secrets.json",               "env_file",     "critical"),
            ("/key.pem",                    "env_file",     "critical"),
            ("/private.key",                "env_file",     "critical"),
            ("/server.key",                 "env_file",     "critical"),
            ("/id_rsa",                     "env_file",     "critical"),
            ("/.ssh/id_rsa",                "env_file",     "critical"),
            ("/aws_credentials",            "env_file",     "critical"),
            ("/.aws/credentials",           "env_file",     "critical"),
        ]
        paths.extend(env_files)

        # Backup files — High
        backup_files = [
            ("/backup.sql",                 "backup",       "high"),
            ("/backup.zip",                 "backup",       "high"),
            ("/backup.tar.gz",              "backup",       "high"),
            ("/db_backup.sql",              "backup",       "high"),
            ("/database.sql",               "backup",       "high"),
            ("/dump.sql",                   "backup",       "high"),
            ("/site.sql",                   "backup",       "high"),
            ("/index.php.bak",              "backup",       "high"),
            ("/index.bak",                  "backup",       "high"),
            ("/index.php.old",              "backup",       "high"),
            ("/config.bak",                 "backup",       "high"),
            ("/config.old",                 "backup",       "high"),
            ("/web.zip",                    "backup",       "high"),
            ("/www.zip",                    "backup",       "high"),
            ("/public_html.zip",            "backup",       "high"),
            ("/site_backup.zip",            "backup",       "high"),
        ]
        paths.extend(backup_files)

        # Log files — Medium/High
        log_files = [
            ("/error.log",                  "log_file",     "medium"),
            ("/error_log",                  "log_file",     "medium"),
            ("/access.log",                 "log_file",     "medium"),
            ("/debug.log",                  "log_file",     "medium"),
            ("/app.log",                    "log_file",     "medium"),
            ("/application.log",            "log_file",     "medium"),
            ("/server.log",                 "log_file",     "medium"),
            ("/logs/error.log",             "log_file",     "medium"),
            ("/logs/access.log",            "log_file",     "medium"),
            ("/storage/logs/laravel.log",   "log_file",     "high"),
            ("/var/log/nginx/error.log",    "log_file",     "high"),
        ]
        paths.extend(log_files)

        # Dev/Build files — Medium
        dev_files = [
            ("/package.json",               "dev_file",     "low"),
            ("/package-lock.json",          "dev_file",     "low"),
            ("/composer.json",              "dev_file",     "low"),
            ("/composer.lock",              "dev_file",     "medium"),
            ("/yarn.lock",                  "dev_file",     "low"),
            ("/Gemfile",                    "dev_file",     "low"),
            ("/Gemfile.lock",               "dev_file",     "low"),
            ("/requirements.txt",           "dev_file",     "low"),
            ("/Dockerfile",                 "dev_file",     "medium"),
            ("/docker-compose.yml",         "dev_file",     "medium"),
            ("/docker-compose.yaml",        "dev_file",     "medium"),
            ("/.dockerignore",              "dev_file",     "low"),
            ("/Makefile",                   "dev_file",     "low"),
            ("/README.md",                  "dev_file",     "low"),
            ("/phpinfo.php",                "sensitive_file","high"),
            ("/info.php",                   "sensitive_file","high"),
            ("/test.php",                   "sensitive_file","medium"),
            ("/robots.txt",                 "sensitive_file","info"),
            ("/sitemap.xml",                "sensitive_file","info"),
            ("/crossdomain.xml",            "sensitive_file","low"),
        ]
        paths.extend(dev_files)

        return paths

    # Patterns that indicate sensitive data in file content
    SENSITIVE_PATTERNS = {
        'aws_key':       re.compile(r'AKIA[0-9A-Z]{16}'),
        'aws_secret':    re.compile(r'aws_secret_access_key\s*=\s*\S+', re.I),
        'db_password':   re.compile(r'(DB_PASSWORD|db_pass|database_password)\s*[=:]\s*\S+', re.I),
        'api_key':       re.compile(r'(api_key|apikey|api_secret)\s*[=:]\s*[\'"]?\w{16,}', re.I),
        'private_key':   re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
        'jwt_secret':    re.compile(r'(JWT_SECRET|jwt_secret|SECRET_KEY)\s*[=:]\s*\S+', re.I),
        'password':      re.compile(r'(PASSWORD|PASSWD|PWD)\s*[=:]\s*\S+', re.I),
        'token':         re.compile(r'(access_token|auth_token|bearer_token)\s*[=:]\s*[\'"]?\S+', re.I),
        'git_branch':    re.compile(r'ref:\s*refs/heads/\w+'),
        'db_url':        re.compile(r'(mysql|postgres|mongodb|redis)://[^\s]+', re.I),
        'smtp_pass':     re.compile(r'(MAIL_PASSWORD|SMTP_PASS)\s*[=:]\s*\S+', re.I),
    }

    def _analyze_content(self, content: str, file_type: str) -> tuple:
        """
        Analyze file content for sensitive data.
        Returns (severity_upgrade, sensitive_matches, preview)
        """
        matches = []
        severity_upgrade = False

        for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
            match = pattern.search(content)
            if match:
                matched_text = match.group(0)[:60]
                matches.append(f"{pattern_name}: {matched_text}")
                severity_upgrade = True

        preview = content[:300].replace('\n', ' | ').strip()
        return severity_upgrade, matches, preview

    async def _check_path(self, base_url: str, path: str,
                           file_type: str, severity: str) -> Optional[GitFinding]:
        """Check a single path for exposure"""
        url = base_url.rstrip('/') + path
        try:
            async def _do_request():
                return await self.client.get(url, follow_redirects=False)
            response = await self.rate_limiter.execute_with_retry(_do_request)

            if not response:
                return None

            # Skip obvious not-found responses
            if response.status_code == 404:
                # Check if it's a real 404 or soft 404
                if len(response.text) < 1000 or 'not found' in response.text.lower():
                    return None

            if response.status_code not in [200, 206, 301, 302, 403]:
                return None

            content = response.text
            content_length = len(response.content)

            # For 403, just report existence
            if response.status_code == 403:
                return GitFinding(
                    url=url,
                    type=file_type,
                    severity="medium",
                    confidence="medium",
                    file_path=path,
                    content_preview="Access forbidden — resource exists but access denied",
                    evidence=f"HTTP 403 on {path} — resource exists",
                    remediation=self._get_remediation(file_type)
                )

            if response.status_code in [301, 302]:
                location = response.headers.get('location', '')
                if path in location or path.rstrip('/') in location:
                    return GitFinding(
                        url=url,
                        type=file_type,
                        severity=severity,
                        confidence="medium",
                        file_path=path,
                        content_preview=f"Redirects to: {location}",
                        evidence=f"HTTP {response.status_code} redirect — {path} exists",
                        remediation=self._get_remediation(file_type)
                    )
                return None

            # 200 OK — analyze content
            if content_length == 0:
                return None

            severity_upgrade, sensitive_matches, preview = self._analyze_content(content, file_type)

            # Upgrade severity if sensitive data found
            final_severity = "critical" if severity_upgrade else severity

            evidence_parts = [f"HTTP 200 | Size: {content_length}B | Path: {path}"]
            if sensitive_matches:
                evidence_parts.append(f"Sensitive data: {'; '.join(sensitive_matches[:3])}")

            # Special checks for git HEAD file
            if path == "/.git/HEAD" and "ref:" in content:
                branch = content.strip()
                evidence_parts.append(f"Git branch exposed: {branch}")
                final_severity = "critical"

            return GitFinding(
                url=url,
                type=file_type,
                severity=final_severity,
                confidence="high",
                file_path=path,
                content_preview=preview[:200],
                evidence=" | ".join(evidence_parts),
                remediation=self._get_remediation(file_type)
            )

        except Exception as e:
            self.logger.debug(f"Check failed {url}: {e}")
            return None

    def _get_remediation(self, file_type: str) -> str:
        remediations = {
            "git_file": (
                "1. Remove .git directory from web root immediately.\n"
                "2. Add to nginx: location ~* /\\.git { deny all; return 404; }\n"
                "3. Apache: RedirectMatch 404 /\\.git\n"
                "4. Rotate all credentials found in git history.\n"
                "5. Use 'git filter-branch' or BFG to remove secrets from history."
            ),
            "env_file": (
                "1. Move .env file outside web root immediately.\n"
                "2. Rotate ALL credentials/secrets found in the file.\n"
                "3. Add deny rule: location ~* \\.env { deny all; }\n"
                "4. Use environment variables or secrets manager instead.\n"
                "5. Add .env to .gitignore to prevent future commits."
            ),
            "backup": (
                "1. Delete backup files from web root immediately.\n"
                "2. Store backups in secure, non-web-accessible location.\n"
                "3. Encrypt backups if they must be stored on server.\n"
                "4. Audit backup contents for exposed credentials."
            ),
            "log_file": (
                "1. Move logs outside web root.\n"
                "2. Add deny rules for /logs/ directory.\n"
                "3. Review log contents for sensitive data exposure.\n"
                "4. Configure log rotation and retention policies."
            ),
            "sensitive_file": (
                "1. Remove or restrict access to this file.\n"
                "2. Disable phpinfo() in production.\n"
                "3. Add deny rules in web server configuration."
            ),
            "dev_file": (
                "1. Review if this file needs to be publicly accessible.\n"
                "2. Block access to build/dependency files in production.\n"
                "3. Avoid exposing internal project structure."
            ),
        }
        return remediations.get(file_type, "Restrict access to this sensitive resource.")

    async def scan(self, target_urls: List[str], forms: List = None) -> List[GitFinding]:  # NEW-BUG-001 FIX
        forms = forms or []  # NEW-BUG-001 FIX
        """Main Git exposure scan"""
        # Get unique base URLs
        base_urls: Set[str] = set()
        for url in target_urls:
            parsed = urlparse(url)
            base_urls.add(f"{parsed.scheme}://{parsed.netloc}")

        self.logger.info(
            f"Starting Git/sensitive file scan on {len(base_urls)} host(s) "
            f"with {len(self.check_paths)} paths"
        )

        headers = {
            'User-Agent': '0xHunter Security Scanner (Authorized Testing)',
            'Accept': '*/*',
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
                tasks = [
                    self._check_path(base_url, path, ftype, severity)
                    for path, ftype, severity in self.check_paths
                ]

                # Batch processing
                batch_size = 25
                for i in range(0, len(tasks), batch_size):
                    batch = tasks[i:i + batch_size]
                    results = await asyncio.gather(*batch, return_exceptions=True)

                    for result in results:
                        if isinstance(result, GitFinding):
                            self.findings.append(result)
                            self.logger.warning(
                                f"EXPOSED [{result.severity.upper()}]: "
                                f"{result.url} | {result.type} | {result.evidence[:80]}"
                            )

        self.logger.info(f"Git exposure scan complete. Found {len(self.findings)} exposed files")
        return self.findings
