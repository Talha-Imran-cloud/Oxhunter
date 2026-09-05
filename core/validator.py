"""
URL Validation & Scope Control
Ensures we ONLY scan authorized targets
"""

from urllib.parse import urlparse, urljoin
import re
from typing import Optional
import yaml
from core.paths import resolve_config_path


class ScopeValidator:
    def __init__(self, target_url: str, config_path: str = "config.yaml"):
        self.target_url = target_url.rstrip('/')
        self.target_domain = urlparse(self.target_url).netloc
        
        config_file = resolve_config_path(config_path)
        with config_file.open('r', encoding='utf-8') as f:
            config = yaml.safe_load(f) or {}

        self.scope = config.get('scope', {})
        self.max_depth = config.get('scanner', {}).get('max_depth', 3)
        self.block_external = config.get('safety', {}).get('block_external_domains', True)
    
    def is_in_scope(self, url: str) -> bool:
        """Check if URL is within allowed scope"""
        parsed = urlparse(url)
        
        # Block external domains if enabled
        if self.block_external and parsed.netloc != self.target_domain:
            return False
        
        # Check excluded patterns
        for pattern in self.scope.get('exclude', []):
            if pattern in url:
                return False
        
        # Check included patterns (if specified)
        includes = self.scope.get('include', [])
        if includes:
            matched = any(re.match(inc.replace('*', '.*'), parsed.netloc) for inc in includes)
            if not matched:
                return False
        
        return True
    
    def normalize_url(self, url: str, base: Optional[str] = None) -> Optional[str]:
        """Normalize and validate URL"""
        if base:
            url = urljoin(base, url)
        
        # Remove fragments
        url = url.split('#')[0]
        
        # Must be HTTP/HTTPS
        if not url.startswith(('http://', 'https://')):
            return None
        
        if not self.is_in_scope(url):
            return None
        
        return url
    
    def get_target_domain(self) -> str:
        return self.target_domain


class AuthorizationChecker:
    """Ensures user has explicit authorization"""
    
    DISCLAIMER = """
    +--------------------------------------------------------------+
    |  ETHICAL USE DISCLAIMER                                      |
    |                                                              |
    |  This tool is for AUTHORIZED security testing ONLY.          |
    |  You MUST have written permission to scan the target.        |
    |  Unauthorized scanning is ILLEGAL in most jurisdictions.     |
    |                                                              |
    |  By proceeding, you confirm you have proper authorization.   |
    +--------------------------------------------------------------+
    """
    
    @classmethod
    def confirm(cls) -> bool:
        print(cls.DISCLAIMER)
        response = input("Do you have written authorization to scan this target? (yes/no): ")
        return response.strip().lower() in ['yes', 'y']