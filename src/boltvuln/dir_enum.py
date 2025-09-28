"""
Directory enumeration module for BoltVulnScanner
"""
import logging
import requests
from typing import List
from urllib.parse import urljoin
import os

from .utils import ScanConfig, Finding, safe_request, RateLimiter

logger = logging.getLogger(__name__)

class DirectoryEnumerator:
    """Enumerate directories and files on the target server"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.rate_limiter = RateLimiter(config.max_requests_per_sec)
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'BoltVulnScanner/0.1.0'})
        
    def enumerate(self) -> List[Finding]:
        """
        Enumerate directories and files using wordlist
        
        Returns:
            List of directory enumeration findings
        """
        logger.info("Starting directory enumeration")
        findings = []
        
        # Load wordlist
        wordlist = self._load_wordlist()
        if not wordlist:
            logger.error("Failed to load wordlist")
            return findings
            
        logger.info(f"Loaded {len(wordlist)} entries from wordlist")
        
        # Parse target base URL
        from urllib.parse import urlparse
        parsed = urlparse(self.config.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Try each word in the wordlist
        for word in wordlist:
            # Respect rate limiting
            self.rate_limiter.wait_if_needed()
            
            # Construct URL to test
            test_url = urljoin(base_url + "/", word)
            
            # Make request
            response = safe_request(test_url, timeout=self.config.timeout)
            if not response:
                continue
                
            # Check if we found something interesting
            if response.status_code == 200:
                # Check content type for interesting files
                content_type = response.headers.get('Content-Type', '').lower()
                content_length = len(response.content)
                
                # Flag interesting findings
                if self._is_interesting_response(content_type, content_length):
                    finding = self._create_finding(
                        url=test_url,
                        status_code=response.status_code,
                        content_type=content_type,
                        content_length=content_length
                    )
                    findings.append(finding)
                    
            # Also check for redirects that might indicate something interesting
            elif response.status_code in [301, 302, 307, 308]:
                finding = self._create_redirect_finding(
                    url=test_url,
                    status_code=response.status_code,
                    redirect_location=response.headers.get('Location', '')
                )
                findings.append(finding)
                
        logger.info(f"Directory enumeration completed. Found {len(findings)} potential issues")
        return findings
    
    def _load_wordlist(self) -> List[str]:
        """Load wordlist for directory enumeration"""
        wordlist = []
        
        # Try to load from config first
        config_data = self._load_dir_config()
        wordlist_path = config_data.get('wordlist', '')
        
        # If wordlist path is specified and exists, load it
        if wordlist_path and os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except Exception as e:
                logger.error(f"Error loading wordlist from {wordlist_path}: {e}")
                
        # If no wordlist loaded, use default from config
        if not wordlist:
            wordlist = config_data.get('default_wordlist', [
                "admin",
                "login",
                "backup",
                "config",
                "test",
                "dev",
                "api",
                "dashboard",
                "upload",
                "downloads",
                "images",
                "css",
                "js",
                "tmp",
                "temp"
            ])
            
        # Add common extensions if in active mode
        if self.config.enable_active:
            extensions = config_data.get('extensions', ['.bak', '.old', '.backup', '.txt', '.log'])
            extended_wordlist = []
            for word in wordlist:
                extended_wordlist.append(word)
                for ext in extensions:
                    extended_wordlist.append(word + ext)
            wordlist = extended_wordlist
            
        return wordlist
    
    def _load_dir_config(self) -> dict:
        """Load directory enumeration configuration"""
        # Default configuration
        config = {
            'wordlist': 'default_wordlist.txt',
            'extensions': ['.bak', '.old', '.backup', '.txt', '.log'],
            'default_wordlist': [
                "admin",
                "login",
                "backup",
                "config",
                "test",
                "dev",
                "api",
                "dashboard",
                "upload",
                "downloads",
                "images",
                "css",
                "js",
                "tmp",
                "temp"
            ]
        }
        
        return config
    
    def _is_interesting_response(self, content_type: str, content_length: int) -> bool:
        """Determine if a response is interesting enough to report"""
        # Skip empty responses
        if content_length == 0:
            return False
            
        # Flag certain content types as interesting
        interesting_types = [
            'text/html',
            'application/json',
            'application/xml',
            'text/xml',
            'application/javascript',
            'text/plain'
        ]
        
        # Flag large responses as interesting
        is_large = content_length > 10000  # 10KB
        
        # Flag common sensitive file types
        sensitive_extensions = [
            '.env', '.config', '.conf', '.ini', '.log', '.bak', '.backup', '.old',
            '.sql', '.db', '.sqlite', '.key', '.pem', '.crt', '.cert'
        ]
        
        # For demo purposes, we'll flag everything as interesting
        # In a real scanner, this would be more sophisticated
        return True
    
    def _create_finding(self, url: str, status_code: int, content_type: str, content_length: int) -> Finding:
        """Create a directory enumeration finding"""
        # Determine severity based on content type and size
        if '.env' in url or '.config' in url or '.key' in url:
            severity = "high"
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        elif content_length > 100000:  # 100KB
            severity = "medium"
            cvss_vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
        else:
            severity = "low"
            cvss_vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"
            
        poc_content = f"Found accessible resource at {url} (Status: {status_code}, Type: {content_type}, Size: {content_length} bytes)" if self.config.include_poc else "[REDACTED]"
        
        finding = Finding(
            finding_id=f"DIR-ENUM-{hash(url) % 10000}",
            title=f"Accessible Directory/File Found: {url}",
            module="dir_enum",
            url=url,
            parameter="path",
            severity=severity,
            cvss_vector=cvss_vector,
            poc=poc_content,
            reproduction_steps=f"1. Navigate to {url}\n2. Observe the response\n3. Note that the resource is accessible",
            impact="Exposed directories or files may contain sensitive information or reveal internal structure.",
            recommended_fix="Restrict access to sensitive directories and files. Use proper authentication and authorization controls.",
            suggested_bounty="$100-$500" if severity == "high" else "$50-$200" if severity == "medium" else "$25-$100",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/assets/archive/4.2/WSTG-v42-08-03-Directory_Brute_Forcing.html",
                "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"
            ]
        )
        
        return finding
    
    def _create_redirect_finding(self, url: str, status_code: int, redirect_location: str) -> Finding:
        """Create a redirect finding"""
        poc_content = f"Found redirect at {url} (Status: {status_code}) -> {redirect_location}" if self.config.include_poc else "[REDACTED]"
        
        finding = Finding(
            finding_id=f"DIR-REDIR-{hash(url) % 10000}",
            title=f"Directory Redirect Found: {url}",
            module="dir_enum",
            url=url,
            parameter="path",
            severity="low",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
            poc=poc_content,
            reproduction_steps=f"1. Navigate to {url}\n2. Observe the {status_code} redirect to {redirect_location}",
            impact="Redirects may reveal information about the application structure or internal paths.",
            recommended_fix="Ensure redirects do not expose internal paths or sensitive locations.",
            suggested_bounty="$25-$100",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/assets/archive/4.2/WSTG-v42-08-03-Directory_Brute_Forcing.html"
            ]
        )
        
        return finding