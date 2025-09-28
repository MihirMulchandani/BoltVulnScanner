"""
Port scanner module for BoltVulnScanner
"""
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple
import time

from .utils import ScanConfig, Finding, check_port

logger = logging.getLogger(__name__)

class PortScanner:
    """TCP port scanner using socket and ThreadPoolExecutor"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.findings: List[Finding] = []
        
    def scan(self) -> List[Finding]:
        """
        Scan ports on the target host
        
        Returns:
            List of findings for open ports
        """
        logger.info(f"Starting port scan for {self.config.target_url}")
        
        # Parse target host
        from urllib.parse import urlparse
        parsed = urlparse(self.config.target_url)
        host = parsed.hostname or parsed.path
        
        if not host:
            logger.error("Could not determine target host")
            return []
            
        # Get port range from config or use defaults
        config_data = self._load_port_config()
        ports_to_scan = config_data.get('top_ports', list(range(1, 1001)))
        
        # Limit to top 10 ports for demo mode
        if not self.config.enable_active:
            ports_to_scan = ports_to_scan[:10]
            logger.info("Running in demo mode - scanning only top 10 ports")
            
        logger.info(f"Scanning {len(ports_to_scan)} ports on {host}")
        
        # Scan ports concurrently
        open_ports = self._scan_ports_concurrent(host, ports_to_scan)
        
        # Convert to findings
        findings = self._generate_findings(host, open_ports)
        
        logger.info(f"Port scan completed. Found {len(findings)} open ports")
        return findings
    
    def _load_port_config(self) -> dict:
        """Load port scanning configuration"""
        # Default configuration
        config = {
            'top_ports': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443],
            'concurrency': 100,
            'timeout': 3
        }
        
        return config
    
    def _scan_ports_concurrent(self, host: str, ports: List[int]) -> List[Tuple[int, str]]:
        """Scan ports concurrently using ThreadPoolExecutor"""
        open_ports = []
        concurrency = min(self._load_port_config().get('concurrency', 100), len(ports))
        
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            # Submit all port scan tasks
            future_to_port = {
                executor.submit(check_port, host, port, self._load_port_config().get('timeout', 3)): port 
                for port in ports
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open = future.result()
                    if is_open:
                        # Try to get service name
                        try:
                            service = socket.getservbyport(port)
                        except OSError:
                            service = "unknown"
                            
                        open_ports.append((port, service))
                        logger.debug(f"Found open port: {port} ({service})")
                except Exception as e:
                    logger.error(f"Error scanning port {port}: {e}")
                    
        return open_ports
    
    def _generate_findings(self, host: str, open_ports: List[Tuple[int, str]]) -> List[Finding]:
        """Generate findings from open ports"""
        findings = []
        
        for port, service in open_ports:
            # Determine severity based on port
            if port in [21, 22, 23, 25, 110, 143]:  # Common service ports
                severity = "medium"
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
            elif port in [135, 139, 445, 3389]:  # Windows services
                severity = "high"
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
            else:
                severity = "low"
                cvss_vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"
                
            finding = Finding(
                finding_id=f"PORT-{port}",
                title=f"Open Port Detected: {port} ({service})",
                module="ports",
                url=f"{self.config.target_url}:{port}",
                parameter="port",
                severity=severity,
                cvss_vector=cvss_vector,
                poc=f"Port {port} is open on {host}" if self.config.include_poc else "[REDACTED]",
                reproduction_steps=f"1. Use nmap or similar tool to scan {host}\n2. Observe that port {port} is open",
                impact=f"Service '{service}' is exposed on port {port}. This may increase attack surface.",
                recommended_fix=f"Close port {port} if the service is not needed. If needed, ensure it is properly secured.",
                suggested_bounty="$50-$200",
                references=[
                    "https://owasp.org/www-project-top-ten/",
                    "https://nmap.org/book/man-port-scanning-techniques.html"
                ]
            )
            
            findings.append(finding)
            
        return findings