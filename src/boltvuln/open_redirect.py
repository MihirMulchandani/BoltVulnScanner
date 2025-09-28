"""
Open redirect scanner module for BoltVulnScanner
"""
import logging
import requests
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

from .utils import ScanConfig, Finding, safe_request, requires_consent
from .crawler import WebPage

logger = logging.getLogger(__name__)

class OpenRedirectScanner:
    """Detect open redirect vulnerabilities"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'BoltVulnScanner/0.1.0'})
        self.redirect_payloads = [
            'https://evil.com',
            '//evil.com',
            'https://evil.com/path',
            '//evil.com/path',
            'data:text/html,<script>alert("XSS")</script>',
            'javascript:alert("XSS")'
        ]
        
    @requires_consent
    def scan(self) -> List[Finding]:
        """
        Scan for open redirect vulnerabilities (requires consent)
        
        Returns:
            List of open redirect findings
        """
        logger.info("Starting open redirect scan")
        findings = []
        
        # Parse target base URL
        parsed = urlparse(self.config.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Test common redirect parameters with payloads
        redirect_params = [
            'redirect', 'redirect_to', 'redirect_url', 'url', 'uri', 'next',
            'continue', 'return', 'rurl', 'dest', 'destination', 'redir',
            'go', 'goto', 'forward', 'follow', 'clickurl', 'callback'
        ]
        
        # Test each parameter with each payload
        for param in redirect_params:
            for payload in self.redirect_payloads:
                # Create test URL
                test_params = {param: payload}
                test_url = base_url + '?' + urlencode(test_params)
                
                # Make request
                response = safe_request(test_url, timeout=self.config.timeout)
                if not response:
                    continue
                    
                # Check if redirect occurred to our payload
                if self._is_redirect_to_payload(response, payload):
                    finding = self._create_finding(
                        url=test_url,
                        parameter=param,
                        payload=payload,
                        redirect_location=response.headers.get('Location', '')
                    )
                    findings.append(finding)
                    
        logger.info(f"Open redirect scan completed. Found {len(findings)} potential issues")
        return findings
    
    def _is_redirect_to_payload(self, response: requests.Response, payload: str) -> bool:
        """Check if response redirects to our payload"""
        if response.status_code not in [301, 302, 303, 307, 308]:
            return False
            
        location = response.headers.get('Location', '')
        if not location:
            return False
            
        # Check if location matches our payload
        # This is a simplified check - in practice, we'd need to be more careful
        # about URL parsing and matching
        return payload in location
    
    def _create_finding(self, url: str, parameter: str, payload: str, redirect_location: str) -> Finding:
        """Create an open redirect finding"""
        poc_content = f"Parameter '{parameter}' redirects to '{redirect_location}' when provided payload '{payload}'" if self.config.include_poc else "[REDACTED]"
        
        finding = Finding(
            finding_id=f"OPEN-REDIRECT-{int(time.time() * 1000)}",
            title="Open Redirect Vulnerability",
            module="open_redirect",
            url=url,
            parameter=parameter,
            severity="medium",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
            poc=poc_content,
            reproduction_steps=f"1. Navigate to {url}\n2. Observe that the response redirects to {redirect_location}\n3. Note that this redirect can be controlled by user input",
            impact="An attacker could redirect users to malicious sites, leading to phishing attacks or malware distribution.",
            recommended_fix="Validate all redirect destinations against a whitelist of allowed URLs. Avoid allowing user input to control redirects directly.",
            suggested_bounty="$200-$800",
            references=[
                "https://owasp.org/www-community/attacks/Open_redirect",
                "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
            ],
            confirmed=True
        )
        
        return finding