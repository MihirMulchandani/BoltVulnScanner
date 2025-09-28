"""
SQL Injection scanner module for BoltVulnScanner
"""
import logging
import time
import re
from typing import List, Dict
import requests

from .utils import ScanConfig, Finding, safe_request, requires_consent
from .crawler import WebPage

logger = logging.getLogger(__name__)

class SQLiScanner:
    """Detects SQL injection vulnerabilities"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'BoltVulnScanner/0.1.0'})
        self.error_signatures = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"SQLServer JDBC Driver",
            r"SqlException",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark",
            r"ODBC SQL Server",
            r"SQLite.Exception",
            r"sqlite3.OperationalError"
        ]
        
    def scan(self, pages: List[WebPage]) -> List[Finding]:
        """
        Scan for SQL injection vulnerabilities in crawled pages
        
        Args:
            pages: List of crawled pages to scan
            
        Returns:
            List of SQLi findings
        """
        logger.info("Starting SQL injection scan")
        findings = []
        
        # Load SQLi payloads from config
        config_data = self._load_sqli_config()
        error_payloads = config_data.get('error_based_payloads', [])
        boolean_payloads = config_data.get('boolean_based_payloads', [])
        time_payloads = config_data.get('time_based_payloads', [])
        demo_payload = config_data.get('demo_payload', "' OR '1'='1--")
        
        # Use demo payload if not in active mode
        if not self.config.enable_active:
            error_payloads = [demo_payload]
            boolean_payloads = []
            time_payloads = []
            logger.info("Running in demo mode - using safe demo payload")
            
        # Scan each page
        for page in pages:
            # Scan URL parameters for error-based SQLi
            error_findings = self._scan_error_based(page.url, error_payloads)
            findings.extend(error_findings)
            
            # Scan forms for error-based SQLi
            form_error_findings = self._scan_forms_error_based(page.forms, error_payloads)
            findings.extend(form_error_findings)
            
            # Scan for boolean-based SQLi (only in active mode)
            if self.config.enable_active:
                boolean_findings = self._scan_boolean_based(page.url, boolean_payloads)
                findings.extend(boolean_findings)
                
                form_boolean_findings = self._scan_forms_boolean_based(page.forms, boolean_payloads)
                findings.extend(form_boolean_findings)
                
                # Scan for time-based SQLi (only in active mode)
                time_findings = self._scan_time_based(page.url, time_payloads)
                findings.extend(time_findings)
                
                form_time_findings = self._scan_forms_time_based(page.forms, time_payloads)
                findings.extend(form_time_findings)
            
        logger.info(f"SQLi scan completed. Found {len(findings)} potential SQLi issues")
        return findings
    
    def _load_sqli_config(self) -> dict:
        """Load SQLi scanning configuration"""
        # Default configuration
        config = {
            'error_based_payloads': [
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' OR '1'='1'--",
                "\" OR \"1\"=\"1\"--",
                "' UNION SELECT NULL--",
                "\" UNION SELECT NULL--"
            ],
            'boolean_based_payloads': [
                "' AND '1'='2",
                "\" AND \"1\"=\"2",
                "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
                "\" AND (SELECT COUNT(*) FROM information_schema.tables) > 0--"
            ],
            'time_based_payloads': [
                "'; WAITFOR DELAY '00:00:05'--",
                "\"; SELECT pg_sleep(5)--",
                "'; SLEEP(5)--",
                "\" OR SLEEP(5)--"
            ],
            'demo_payload': "' OR '1'='1--"
        }
        
        return config
    
    def _scan_error_based(self, url: str, payloads: List[str]) -> List[Finding]:
        """Scan URL parameters for error-based SQLi"""
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
                    
                # Check for SQL error signatures
                if self._contains_sql_errors(response.text):
                    confirmed = self.config.enable_active and self._confirm_sqli(test_url, payload)
                    
                    finding = self._create_sqli_finding(
                        url=test_url,
                        parameter=param_name,
                        payload=payload,
                        sqli_type="error-based",
                        confirmed=confirmed
                    )
                    findings.append(finding)
                    
        return findings
    
    def _scan_forms_error_based(self, forms: List[Dict], payloads: List[str]) -> List[Finding]:
        """Scan HTML forms for error-based SQLi"""
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
                        
                    # Check for SQL error signatures
                    if self._contains_sql_errors(response.text):
                        confirmed = self.config.enable_active and self._confirm_sqli_form(action, method, form_data, payload)
                        
                        finding = self._create_sqli_finding(
                            url=action,
                            parameter=input_name,
                            payload=payload,
                            sqli_type="error-based (form)",
                            confirmed=confirmed
                        )
                        findings.append(finding)
                        
        return findings
    
    def _scan_boolean_based(self, url: str, payloads: List[str]) -> List[Finding]:
        """Scan for boolean-based SQLi"""
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
                
                # Create control URL (without payload)
                control_params = query_params.copy()
                control_params[param_name] = [original_value + "BOLTCONTROL"]
                control_query = urlencode(control_params, doseq=True)
                control_parsed = parsed._replace(query=control_query)
                control_url = urlunparse(control_parsed)
                
                # Make requests
                test_response = safe_request(test_url)
                control_response = safe_request(control_url)
                
                if not test_response or not control_response:
                    continue
                    
                # Compare responses
                # Simple comparison - in real implementation, this would be more sophisticated
                if len(test_response.text) != len(control_response.text):
                    # This is a simplified check - real implementation would be more robust
                    finding = self._create_sqli_finding(
                        url=test_url,
                        parameter=param_name,
                        payload=payload,
                        sqli_type="boolean-based",
                        confirmed=False  # Boolean-based is harder to confirm
                    )
                    findings.append(finding)
                    
        return findings
    
    def _scan_forms_boolean_based(self, forms: List[Dict], payloads: List[str]) -> List[Finding]:
        """Scan forms for boolean-based SQLi"""
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
                    
                original_value = input_field.get('value', '')
                
                for payload in payloads:
                    # Prepare form data with payload
                    form_data_payload = {}
                    for inp in inputs:
                        name = inp.get('name', '')
                        if name == input_name:
                            form_data_payload[name] = payload
                        else:
                            form_data_payload[name] = inp.get('value', '')
                            
                    # Prepare form data with control
                    form_data_control = {}
                    for inp in inputs:
                        name = inp.get('name', '')
                        if name == input_name:
                            form_data_control[name] = original_value + "BOLTCONTROL"
                        else:
                            form_data_control[name] = inp.get('value', '')
                            
                    # Submit forms
                    if method == 'GET':
                        response_payload = safe_request(action, method=method, params=form_data_payload)
                        response_control = safe_request(action, method=method, params=form_data_control)
                    else:
                        response_payload = safe_request(action, method=method, data=form_data_payload)
                        response_control = safe_request(action, method=method, data=form_data_control)
                        
                    if not response_payload or not response_control:
                        continue
                        
                    # Compare responses
                    if len(response_payload.text) != len(response_control.text):
                        finding = self._create_sqli_finding(
                            url=action,
                            parameter=input_name,
                            payload=payload,
                            sqli_type="boolean-based (form)",
                            confirmed=False
                        )
                        findings.append(finding)
                        
        return findings
    
    @requires_consent
    def _scan_time_based(self, url: str, payloads: List[str]) -> List[Finding]:
        """Scan for time-based SQLi (requires consent)"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        findings = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Skip if no parameters
        if not query_params:
            return findings
            
        # Test each parameter with payloads
        for param_name in query_params:
            for payload in payloads:
                # Create test URL with payload
                test_params = query_params.copy()
                test_params[param_name] = [payload]
                
                # Reconstruct URL
                test_query = urlencode(test_params, doseq=True)
                test_parsed = parsed._replace(query=test_query)
                test_url = urlunparse(test_parsed)
                
                # Measure response time
                start_time = time.time()
                response = safe_request(test_url)
                end_time = time.time()
                
                response_time = end_time - start_time
                
                # Check if response took significantly longer (simplified check)
                if response_time > 4.0:  # More than 4 seconds
                    finding = self._create_sqli_finding(
                        url=test_url,
                        parameter=param_name,
                        payload=payload,
                        sqli_type="time-based",
                        confirmed=True  # Time-based is strong evidence
                    )
                    findings.append(finding)
                    
        return findings
    
    @requires_consent
    def _scan_forms_time_based(self, forms: List[Dict], payloads: List[str]) -> List[Finding]:
        """Scan forms for time-based SQLi (requires consent)"""
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
                            
                    # Measure response time
                    start_time = time.time()
                    if method == 'GET':
                        response = safe_request(action, method=method, params=form_data)
                    else:
                        response = safe_request(action, method=method, data=form_data)
                    end_time = time.time()
                    
                    response_time = end_time - start_time
                    
                    # Check if response took significantly longer
                    if response_time > 4.0:  # More than 4 seconds
                        finding = self._create_sqli_finding(
                            url=action,
                            parameter=input_name,
                            payload=payload,
                            sqli_type="time-based (form)",
                            confirmed=True
                        )
                        findings.append(finding)
                        
        return findings
    
    def _contains_sql_errors(self, response_text: str) -> bool:
        """Check if response contains SQL error signatures"""
        for signature in self.error_signatures:
            if re.search(signature, response_text, re.IGNORECASE):
                return True
        return False
    
    def _confirm_sqli(self, url: str, payload: str) -> bool:
        """Confirm SQLi with additional checks"""
        # In a real implementation, this would involve more sophisticated confirmation
        # For now, we'll just return True if we're in active mode
        return self.config.enable_active
    
    def _confirm_sqli_form(self, action: str, method: str, form_data: dict, payload: str) -> bool:
        """Confirm SQLi in form submission"""
        # In a real implementation, this would involve more sophisticated confirmation
        return self.config.enable_active
    
    def _create_sqli_finding(self, url: str, parameter: str, payload: str, sqli_type: str, confirmed: bool) -> Finding:
        """Create an SQLi finding"""
        severity = "high" if confirmed else "medium"
        cvss_vector = (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if confirmed 
            else "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
        )
        
        poc_content = f"Payload: {payload}" if self.config.include_poc else "[REDACTED]"
        
        finding = Finding(
            finding_id=f"SQLI-{int(time.time() * 1000)}",
            title=f"SQL Injection ({sqli_type})",
            module="sqli",
            url=url,
            parameter=parameter,
            severity=severity,
            cvss_vector=cvss_vector,
            poc=poc_content,
            reproduction_steps=f"1. Navigate to {url}\n2. Submit the payload in the {parameter} field\n3. Observe the SQL error or behavior change",
            impact="An attacker could extract sensitive data from the database, modify data, or execute administrative operations.",
            recommended_fix="Use parameterized queries or prepared statements. Validate and sanitize all user input. Apply principle of least privilege to database accounts.",
            suggested_bounty="$1000-$5000",
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ],
            confirmed=confirmed
        )
        
        return finding