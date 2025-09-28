"""
Directory traversal scanner module for BoltVulnScanner
"""
import logging
import requests
from typing import List
from urllib.parse import urlencode
import time

from .utils import ScanConfig, Finding, safe_request, requires_consent

logger = logging.getLogger(__name__)

class TraversalScanner:
    """Detect directory traversal vulnerabilities"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'BoltVulnScanner/0.1.0'})
        self.traversal_payloads = [
            '../etc/passwd',
            '..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini',
            '../../../../../../../../../../../../etc/passwd',
            '..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\system.ini',
            '../../../etc/passwd%00',
            '..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini%00',
            '....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd',
            '..\\..\\..\\..\\\\..\\..\\..\\..\\\\..\\..\\..\\..\\\\..\\..\\..\\..\\\\windows\\\\win.ini'
        ]
        
    @requires_consent
    def scan(self) -> List[Finding]:
        """
        Scan for directory traversal vulnerabilities (requires consent)
        
        Returns:
            List of directory traversal findings
        """
        logger.info("Starting directory traversal scan")
        findings = []
        
        # Parse target base URL
        from urllib.parse import urlparse
        parsed = urlparse(self.config.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Common parameters that might be vulnerable to traversal
        traversal_params = [
            'file', 'filename', 'path', 'filepath', 'document', 'doc', 'page',
            'template', 'theme', 'lang', 'locale', 'resource', 'include',
            'src', 'source', 'dir', 'directory', 'folder', 'config', 'conf'
        ]
        
        # Test each parameter with each payload
        for param in traversal_params:
            for payload in self.traversal_payloads:
                # Create test URL
                test_params = {param: payload}
                test_url = base_url + '?' + urlencode(test_params)
                
                # Make request
                response = safe_request(test_url, timeout=self.config.timeout)
                if not response:
                    continue
                    
                # Check if we got a sensitive file
                if self._contains_sensitive_content(response.text, payload):
                    finding = self._create_finding(
                        url=test_url,
                        parameter=param,
                        payload=payload
                    )
                    findings.append(finding)
                    
        logger.info(f"Directory traversal scan completed. Found {len(findings)} potential issues")
        return findings
    
    def _contains_sensitive_content(self, response_text: str, payload: str) -> bool:
        """Check if response contains sensitive file content"""
        # Check for Linux /etc/passwd signature
        if 'etc/passwd' in payload and ':/bin/' in response_text:
            return True
            
        # Check for Windows win.ini signature
        if 'win.ini' in payload and ('[fonts]' in response_text or '[extensions]' in response_text):
            return True
            
        # Check for Windows system.ini signature
        if 'system.ini' in payload and ('[boot]' in response_text or '[386Enh]' in response_text):
            return True
            
        return False
    
    def _create_finding(self, url: str, parameter: str, payload: str) -> Finding:
        """Create a directory traversal finding"""
        poc_content = f"Parameter '{parameter}' with payload '{payload}' returned sensitive file content" if self.config.include_poc else "[REDACTED]"
        
        finding = Finding(
            finding_id=f"TRAVERSAL-{int(time.time() * 1000)}",
            title="Directory Traversal Vulnerability",
            module="traversal",
            url=url,
            parameter=parameter,
            severity="high",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            poc=poc_content,
            reproduction_steps=f"1. Navigate to {url}\n2. Observe that the response contains sensitive file content\n3. Note that this indicates a directory traversal vulnerability",
            impact="An attacker could read arbitrary files from the server filesystem, potentially exposing sensitive information like passwords or configuration files.",
            recommended_fix="Validate and sanitize all user input used in file paths. Use secure file access methods that prevent directory traversal. Implement proper access controls.",
            suggested_bounty="$500-$1500",
            references=[
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
            ],
            confirmed=True
        )
        
        return finding