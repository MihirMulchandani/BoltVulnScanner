"""
XSS (Cross-Site Scripting) scanner module for BoltVulnScanner
"""
import logging
import requests
import time
from typing import List, Dict
from urllib.parse import urlencode, urljoin
import html

from .utils import ScanConfig, Finding, safe_request, requires_consent
from .crawler import WebPage

logger = logging.getLogger(__name__)

class XSSScanner:
    """Detects reflected and stored XSS vulnerabilities"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'BoltVulnScanner/0.1.0'})
        
    def scan(self, pages: List[WebPage]) -> List[Finding]:
        """
        Scan for XSS vulnerabilities in crawled pages
        
        Args:
            pages: List of crawled pages to scan
            
        Returns:
            List of XSS findings
        """
        logger.info("Starting XSS scan")
        findings = []
        
        # Load XSS payloads from config
        config_data = self._load_xss_config()
        payloads = config_data.get('payloads', [])
        demo_payload = config_data.get('demo_payload', '<!--XSS-DEMO-->')
        
        # Use demo payload if not in active mode
        if not self.config.enable_active:
            payloads = [demo_payload]
            logger.info("Running in demo mode - using safe demo payload")
            
        # Scan each page
        for page in pages:
            # Scan URL parameters
            url_findings = self._scan_url_parameters(page.url, payloads)
            findings.extend(url_findings)
            
            # Scan forms
            form_findings = self._scan_forms(page.forms, payloads)
            findings.extend(form_findings)
            
        logger.info(f"XSS scan completed. Found {len(findings)} potential XSS issues")
        return findings
    
    def _load_xss_config(self) -> dict:
        """Load XSS scanning configuration"""
        # Default configuration
        config = {
            'payloads': [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "';alert('XSS');//"
            ],
            'demo_payload': "<!--XSS-DEMO-->",
            'confirm_attempts': 3
        }
        
        return config
    
    def _scan_url_parameters(self, url: str, payloads: List[str]) -> List[Finding]:
        """Scan URL parameters for reflected XSS"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        findings = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Skip if no parameters
        if not query_params:
            return findings
            
        # Test each parameter with payloads
        for param_name in query_params:
            original_value = query_params[param_name][0] if query_params[param_name] else ""
            
            for payload in payloads:
                # Create test URL with payload
                test_params = query_params.copy()
                test_params[param_name] = [payload]
                
                # Reconstruct URL
                test_query = urlencode(test_params, doseq=True)
                test_parsed = parsed._replace(query=test_query)
                test_url = urlunparse(test_parsed)
                
                # Make request
                response = safe_request(test_url)
                if not response:
                    continue
                    
                # Check if payload is reflected
                if payload in response.text:
                    # Try to confirm with variations
                    confirmed = self._confirm_xss(test_url, payload)
                    
                    finding = self._create_xss_finding(
                        url=test_url,
                        parameter=param_name,
                        payload=payload,
                        confirmed=confirmed,
                        context="URL parameter"
                    )
                    findings.append(finding)
                    
        return findings
    
    def _scan_forms(self, forms: List[Dict], payloads: List[str]) -> List[Finding]:
        """Scan HTML forms for XSS vulnerabilities"""
        findings = []
        
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            inputs = form.get('inputs', [])
            
            # Skip forms without inputs
            if not inputs:
                continue
                
            # Test each input with payloads
            for input_field in inputs:
                input_name = input_field.get('name', '')
                if not input_name:
                    continue
                    
                for payload in payloads:
                    # Prepare form data
                    form_data = {}
                    for inp in inputs:
                        name = inp.get('name', '')
                        if name == input_name:
                            form_data[name] = payload
                        else:
                            form_data[name] = inp.get('value', '')
                            
                    # Submit form
                    if method == 'GET':
                        response = safe_request(action, method=method, params=form_data)
                    else:
                        response = safe_request(action, method=method, data=form_data)
                        
                    if not response:
                        continue
                        
                    # Check if payload is reflected
                    if payload in response.text:
                        # Try to confirm with variations
                        confirmed = self._confirm_xss_form(action, method, form_data, payload)
                        
                        finding = self._create_xss_finding(
                            url=action,
                            parameter=input_name,
                            payload=payload,
                            confirmed=confirmed,
                            context=f"Form field ({method})"
                        )
                        findings.append(finding)
                        
        return findings
    
    def _confirm_xss(self, url: str, payload: str) -> bool:
        """Confirm XSS by testing with variations"""
        if not self.config.enable_active:
            return False  # No confirmation in demo mode
            
        config_data = self._load_xss_config()
        attempts = config_data.get('confirm_attempts', 3)
        
        # Try variations of the payload
        for i in range(attempts):
            # Simple variation - add some random chars
            variation = payload.replace('XSS', f'XSS{i}')
            
            # Replace in URL
            test_url = url.replace(payload, variation)
            
            response = safe_request(test_url)
            if response and variation in response.text:
                return True
                
        return False
    
    def _confirm_xss_form(self, action: str, method: str, form_data: dict, payload: str) -> bool:
        """Confirm XSS in form submission"""
        if not self.config.enable_active:
            return False  # No confirmation in demo mode
            
        config_data = self._load_xss_config()
        attempts = config_data.get('confirm_attempts', 3)
        
        # Try variations of the payload
        for i in range(attempts):
            variation = payload.replace('XSS', f'XSS{i}')
            
            # Replace in form data
            test_data = form_data.copy()
            for key, value in test_data.items():
                if value == payload:
                    test_data[key] = variation
                    
            # Submit form with variation
            if method == 'GET':
                response = safe_request(action, method=method, params=test_data)
            else:
                response = safe_request(action, method=method, data=test_data)
                
            if response and variation in response.text:
                return True
                
        return False
    
    def _create_xss_finding(self, url: str, parameter: str, payload: str, confirmed: bool, context: str) -> Finding:
        """Create an XSS finding"""
        severity = "high" if confirmed else "medium"
        cvss_vector = (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N" if confirmed 
            else "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"
        )
        
        poc_content = f"Payload: {html.escape(payload)}" if self.config.include_poc else "[REDACTED]"
        
        finding = Finding(
            finding_id=f"XSS-{int(time.time() * 1000)}",
            title=f"Cross-Site Scripting (XSS) in {context}",
            module="xss",
            url=url,
            parameter=parameter,
            severity=severity,
            cvss_vector=cvss_vector,
            poc=poc_content,
            reproduction_steps=f"1. Navigate to {url}\n2. Submit the payload in the {parameter} field\n3. Observe that the payload is executed",
            impact="An attacker could execute arbitrary JavaScript in the victim's browser, potentially stealing session cookies or performing actions on behalf of the user.",
            recommended_fix="Properly escape and sanitize all user input before rendering it in HTML. Use Content Security Policy (CSP) headers to restrict script execution.",
            suggested_bounty="$500-$2000",
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ],
            confirmed=confirmed
        )
        
        return finding