"""
Utility functions and classes for BoltVulnScanner
"""
import re
import time
import logging
import requests
import yaml
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse, urlunparse
from dataclasses import dataclass, asdict, field
import socket
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ScanConfig:
    """Configuration for scanner modules"""
    target_url: str
    max_depth: int = 3
    max_pages: int = 100
    same_domain_only: bool = True
    exclude_regex: List[str] = field(default_factory=list)
    delay: float = 1.0
    max_requests_per_sec: int = 5
    concurrency: int = 10
    timeout: int = 30
    enable_active: bool = False
    include_poc: bool = False
    
@dataclass
class Finding:
    """Represents a security finding"""
    finding_id: str
    title: str
    module: str
    url: str
    parameter: str
    severity: str  # low, medium, high, critical
    cvss_vector: str
    poc: str
    reproduction_steps: str
    impact: str
    recommended_fix: str
    suggested_bounty: str
    references: List[str]
    confirmed: bool = False

class RateLimiter:
    """Simple rate limiter to control request frequency"""
    
    def __init__(self, max_requests_per_sec: int):
        self.max_requests_per_sec = max_requests_per_sec
        self.requests = []
        
    def wait_if_needed(self):
        """Wait if we've exceeded our rate limit"""
        now = time.time()
        # Remove requests older than 1 second
        self.requests = [req_time for req_time in self.requests if now - req_time < 1]
        
        if len(self.requests) >= self.max_requests_per_sec:
            # Wait until we can make another request
            oldest = min(self.requests)
            sleep_time = 1 - (now - oldest)
            if sleep_time > 0:
                time.sleep(sleep_time)
                
        self.requests.append(now)

def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning(f"Config file {config_path} not found, using defaults")
        return {}

def normalize_url(url: str) -> str:
    """Normalize URL to ensure it has a scheme and trailing slash"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    # Ensure path ends with /
    path = parsed.path if parsed.path.endswith('/') else parsed.path + '/'
    normalized = parsed._replace(path=path)
    return urlunparse(normalized)

def is_same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs are from the same domain"""
    domain1 = urlparse(url1).netloc.lower()
    domain2 = urlparse(url2).netloc.lower()
    return domain1 == domain2

def is_valid_url(url: str) -> bool:
    """Validate that the URL has http/https scheme and a valid hostname"""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False

def safe_request(url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
    """Make a safe HTTP request with error handling"""
    try:
       if "timeout" not in kwargs:
        kwargs["timeout"] = 30
        response = requests.request(method, url, **kwargs)

        return response
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed for {url}: {e}")
        return None

def check_port(host: str, port: int, timeout: int = 3) -> bool:
    """Check if a port is open on a host"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def requires_consent(func):
    """Decorator to ensure active tests only run with consent"""
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not getattr(self, 'enable_active', False):
            logger.warning(f"Active test {func.__name__} requires consent. Skipping.")
            return []
        return func(self, *args, **kwargs)
    return wrapper