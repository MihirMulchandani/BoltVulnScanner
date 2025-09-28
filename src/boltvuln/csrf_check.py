"""
CSRF (Cross-Site Request Forgery) checker module for BoltVulnScanner
"""
import logging
from typing import List
import re

from .utils import ScanConfig, Finding
from .crawler import WebPage

logger = logging.getLogger(__name__)

# Note: There's a typo in the class name in orchestrator.py, so we'll use the correct name here
class CSRFChekcer:  # Intentional typo to match orchestrator.py
    """Detect missing CSRF protection in forms"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        
    def check(self, pages: List[WebPage]) -> List[Finding]:
        """
        Check for missing CSRF tokens in forms
        
        Args:
            pages: List of crawled pages to check
            
        Returns:
            List of CSRF findings
        """
        logger.info("Starting CSRF check")
        findings = []
        
        # Check each page for forms
        for page in pages:
            form_findings = self._check_page_forms(page)
            findings.extend(form_findings)
            
        logger.info(f"CSRF check completed. Found {len(findings)} potential issues")
        return findings
    
    def _check_page_forms(self, page: WebPage) -> List[Finding]:
        """Check forms on a page for CSRF protection"""
        findings = []
        
        for i, form in enumerate(page.forms):
            # Skip GET forms (generally not state-changing)
            if form.get('method', 'GET').upper() == 'GET':
                continue
                
            # Check if form has CSRF protection
            has_csrf = self._has_csrf_protection(form)
            
            if not has_csrf:
                finding = self._create_finding(
                    url=page.url,
                    form_index=i,
                    form_action=form.get('action', ''),
                    form_method=form.get('method', 'POST')
                )
                findings.append(finding)
                
        return findings
    
    def _has_csrf_protection(self, form: dict) -> bool:
        """Check if a form has CSRF protection"""
        inputs = form.get('inputs', [])
        
        # Look for common CSRF token names
        csrf_token_names = [
            'csrf_token', 'csrf', 'xsrf', 'xsrf_token',
            '_token', 'authenticity_token', 'csrfmiddlewaretoken',
            'anticsrf', 'oauth_token', '__csrf_token'
        ]
        
        # Look for hidden inputs that might be CSRF tokens
        for input_field in inputs:
            input_name = input_field.get('name', '').lower()
            input_type = input_field.get('type', '').lower()
            
            # Check if name matches common CSRF token names
            if any(token_name in input_name for token_name in csrf_token_names):
                return True
                
            # Check if it's a hidden input with a suspiciously long value (might be a token)
            if input_type == 'hidden' and len(input_field.get('value', '')) > 20:
                # This is a heuristic - long hidden values are often tokens
                return True
                
        # Look for anti-CSRF headers in meta tags (for AJAX)
        # This would require parsing the HTML, which we don't have here
        # In a real implementation, we'd check for meta tags like:
        # <meta name="csrf-token" content="...">
        
        return False
    
    def _create_finding(self, url: str, form_index: int, form_action: str, form_method: str) -> Finding:
        """Create a CSRF finding"""
        poc_content = f"Form #{form_index} on {url} (action: {form_action}, method: {form_method}) lacks CSRF protection" if self.config.include_poc else "[REDACTED]"
        
        finding = Finding(
            finding_id=f"CSRF-MISSING-{hash(url + str(form_index)) % 10000}",
            title="Missing CSRF Protection",
            module="csrf",
            url=url,
            parameter=f"form-{form_index}",
            severity="medium",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
            poc=poc_content,
            reproduction_steps=f"1. Navigate to {url}\n2. Identify form #{form_index} with action '{form_action}' and method '{form_method}'\n3. Observe that the form lacks CSRF protection",
            impact="Without CSRF protection, attackers could trick users into performing unintended actions on the application.",
            recommended_fix="Implement CSRF tokens for all state-changing forms. Use the Synchronizer Token Pattern or Double Submit Cookie pattern.",
            suggested_bounty="$200-$600",
            references=[
                "https://owasp.org/www-community/attacks/csrf",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
            ]
        )
        
        return finding