"""
Orchestrator for BoltVulnScanner - coordinates all scanning modules
"""
import logging
import time
from typing import List, Dict, Any, Optional
from dataclasses import asdict

from .utils import ScanConfig, Finding
from .crawler import Crawler
from .ports import PortScanner
from .xss import XSSScanner
from .sqli import SQLiScanner
from .tls_check import TLSChecker
from .headers_check import HeadersChecker
from .dir_enum import DirectoryEnumerator
from .open_redirect import OpenRedirectScanner
from .csrf_check import CSRFChekcer
from .traversal import TraversalScanner
from .subdomain_enum import SubdomainEnumerator
from .cmd_injection import CommandInjectionScanner

logger = logging.getLogger(__name__)

class ScannerOrchestrator:
    """Coordinates all scanning modules and manages the scanning pipeline"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.findings: List[Finding] = []
        self.modules_enabled: List[str] = []
        self.progress_callback = None
        
    def set_progress_callback(self, callback):
        """Set callback function for progress updates"""
        self.progress_callback = callback
        
    def _update_progress(self, module: str, status: str, progress: float = None):
        """Update progress if callback is set"""
        if self.progress_callback:
            self.progress_callback(module, status, progress)
            
    def run_scan(self, modules: List[str]) -> List[Finding]:
        """
        Run selected scanning modules in order
        
        Args:
            modules: List of module names to run
            
        Returns:
            List of findings from all modules
        """
        logger.info(f"Starting scan for {self.config.target_url}")
        logger.info(f"Enabled modules: {modules}")
        
        start_time = time.time()
        all_findings = []
        
        try:
            # Step 1: Crawl the target (if enabled)
            crawled_pages = []
            if 'crawler' in modules:
                self._update_progress('crawler', 'starting')
                crawler = Crawler(self.config)
                crawled_pages = crawler.crawl()
                self._update_progress('crawler', 'completed', 100)
                logger.info(f"Crawled {len(crawled_pages)} pages")
            
            # Step 2: Port scanning (if enabled)
            if 'ports' in modules:
                self._update_progress('ports', 'starting')
                port_scanner = PortScanner(self.config)
                port_findings = port_scanner.scan()
                all_findings.extend(port_findings)
                self._update_progress('ports', 'completed', 100)
            
            # Step 3: XSS scanning (if enabled)
            if 'xss' in modules:
                self._update_progress('xss', 'starting')
                xss_scanner = XSSScanner(self.config)
                xss_findings = xss_scanner.scan(crawled_pages)
                all_findings.extend(xss_findings)
                self._update_progress('xss', 'completed', 100)
            
            # Step 4: SQLi scanning (if enabled)
            if 'sqli' in modules:
                self._update_progress('sqli', 'starting')
                sqli_scanner = SQLiScanner(self.config)
                sqli_findings = sqli_scanner.scan(crawled_pages)
                all_findings.extend(sqli_findings)
                self._update_progress('sqli', 'completed', 100)
            
            # Step 5: TLS checking (if enabled)
            if 'tls' in modules:
                self._update_progress('tls', 'starting')
                tls_checker = TLSChecker(self.config)
                tls_findings = tls_checker.check()
                all_findings.extend(tls_findings)
                self._update_progress('tls', 'completed', 100)
            
            # Step 6: Headers checking (if enabled)
            if 'headers' in modules:
                self._update_progress('headers', 'starting')
                headers_checker = HeadersChecker(self.config)
                headers_findings = headers_checker.check()
                all_findings.extend(headers_findings)
                self._update_progress('headers', 'completed', 100)
            
            # Step 7: Directory enumeration (if enabled)
            if 'dir_enum' in modules:
                self._update_progress('dir_enum', 'starting')
                dir_enum = DirectoryEnumerator(self.config)
                dir_findings = dir_enum.enumerate()
                all_findings.extend(dir_findings)
                self._update_progress('dir_enum', 'completed', 100)
            
            # Step 8: Open redirect scanning (if enabled and consent given)
            if 'open_redirect' in modules and self.config.enable_active:
                self._update_progress('open_redirect', 'starting')
                open_redirect_scanner = OpenRedirectScanner(self.config)
                open_redirect_findings = open_redirect_scanner.scan()
                all_findings.extend(open_redirect_findings)
                self._update_progress('open_redirect', 'completed', 100)
            
            # Step 9: CSRF checking (if enabled)
            if 'csrf' in modules:
                self._update_progress('csrf', 'starting')
                csrf_checker = CSRFChekcer(self.config)
                csrf_findings = csrf_checker.check(crawled_pages)
                all_findings.extend(csrf_findings)
                self._update_progress('csrf', 'completed', 100)
            
            # Step 10: Directory traversal scanning (if enabled and consent given)
            if 'traversal' in modules and self.config.enable_active:
                self._update_progress('traversal', 'starting')
                traversal_scanner = TraversalScanner(self.config)
                traversal_findings = traversal_scanner.scan()
                all_findings.extend(traversal_findings)
                self._update_progress('traversal', 'completed', 100)
            
            # Step 11: Subdomain enumeration (if enabled)
            if 'subdomain' in modules:
                self._update_progress('subdomain', 'starting')
                subdomain_enum = SubdomainEnumerator(self.config)
                subdomain_findings = subdomain_enum.enumerate()
                all_findings.extend(subdomain_findings)
                self._update_progress('subdomain', 'completed', 100)
            
            # Step 12: Command injection scanning (if enabled and consent given)
            if 'cmd_injection' in modules and self.config.enable_active:
                self._update_progress('cmd_injection', 'starting')
                cmd_injection_scanner = CommandInjectionScanner(self.config)
                cmd_injection_findings = cmd_injection_scanner.scan()
                all_findings.extend(cmd_injection_findings)
                self._update_progress('cmd_injection', 'completed', 100)
                
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            raise
            
        end_time = time.time()
        logger.info(f"Scan completed in {end_time - start_time:.2f} seconds")
        logger.info(f"Total findings: {len(all_findings)}")
        
        return all_findings