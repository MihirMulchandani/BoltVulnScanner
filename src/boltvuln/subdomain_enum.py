"""
Subdomain enumeration module for BoltVulnScanner
"""
import logging
import socket
from typing import List
import time

from .utils import ScanConfig, Finding

logger = logging.getLogger(__name__)

class SubdomainEnumerator:
    """Enumerate subdomains of the target domain"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'ns3', 'ns4', 'blog', 'm', 'shop', 'api', 'dev', 'test', 'admin', 'portal',
            'beta', 'support', 'secure', 'wiki', 'help', 'stage', 'cdn', 'assets',
            'files', 'images', 'img', 'cloud', 'database', 'db', 'mysql', 'sql',
            'ldap', 'dns', 'search', 'login', 'auth', 'portal', 'gateway', 'proxy',
            'vpn', 'intranet', 'extranet', 'backup', 'old', 'new', 'staging', 'demo',
            'monitor', 'status', 'stats', 'metrics', 'alert', 'chat', 'im', 'cms',
            'erp', 'crm', 'pos', 'atm', 'ads', 'ad', 'adsense', 'analytics', 'static',
            'mobile', 'mobil', 'mobi', 'video', 'vod', 'stream', 'live', 'radio',
            'music', 'photo', 'photos', 'games', 'game', 'casino', 'poker', 'news',
            'rss', 'xml', 'feed', 'forum', 'board', 'boards', 'store', 'buy', 'shop',
            'career', 'jobs', 'job', 'hr', 'recruit', 'recruitment', 'survey', 'forms',
            'form', 'event', 'events', 'calendar', 'ical', 'icalendar', 'travel',
            'booking', 'reservation', 'reservations', 'ticket', 'tickets', 'finance',
            'money', 'bank', 'invest', 'investment', 'investor', 'stocks', 'stock',
            'insurance', 'insure', 'quote', 'quotes', 'health', 'medical', 'med',
            'doctor', 'hospital', 'education', 'school', 'university', 'college',
            'library', 'lib', 'gov', 'government', 'mil', 'military', 'defence',
            'defense', 'energy', 'power', 'electric', 'electricity', 'water', 'gas',
            'oil', 'petrol', 'auto', 'car', 'cars', 'truck', 'trucks', 'bus', 'buses',
            'bike', 'bikes', 'motor', 'motorcycle', 'food', 'restaurant', 'resto',
            'hotel', 'hotels', 'booking', 'reserve', 'reservations', 'realty', 'real',
            'estate', 'property', 'properties', 'realestate', 'sport', 'sports',
            'fitness', 'fit', 'gym', 'weather', 'forecast', 'map', 'maps', 'gps',
            'navigation', 'nav', 'drive', 'driving', 'taxi', 'cab', 'uber', 'lyft'
        ]
        
    def enumerate(self) -> List[Finding]:
        """
        Enumerate subdomains of the target domain
        
        Returns:
            List of subdomain enumeration findings
        """
        logger.info("Starting subdomain enumeration")
        findings = []
        
        # Parse target domain
        from urllib.parse import urlparse
        parsed = urlparse(self.config.target_url)
        domain = parsed.hostname
        
        if not domain:
            logger.error("Could not determine target domain")
            return findings
            
        # Skip IP addresses
        try:
            socket.inet_aton(domain)
            logger.info("Target is an IP address, skipping subdomain enumeration")
            return findings
        except socket.error:
            pass  # Not an IP address, continue
            
        # Try to resolve common subdomains
        resolved_subdomains = []
        
        for subdomain in self.common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            
            # Add a small delay to avoid overwhelming DNS servers
            time.sleep(0.1)
            
            try:
                # Try to resolve the subdomain
                socket.gethostbyname(full_domain)
                resolved_subdomains.append(full_domain)
                logger.debug(f"Found subdomain: {full_domain}")
            except socket.gaierror:
                # Subdomain doesn't exist or doesn't resolve
                pass
            except Exception as e:
                logger.error(f"Error resolving {full_domain}: {e}")
                
        # Create findings for resolved subdomains
        for subdomain in resolved_subdomains:
            finding = self._create_finding(subdomain)
            findings.append(finding)
            
        logger.info(f"Subdomain enumeration completed. Found {len(findings)} subdomains")
        return findings
    
    def _create_finding(self, subdomain: str) -> Finding:
        """Create a subdomain enumeration finding"""
        poc_content = f"Subdomain found: {subdomain}" if self.config.include_poc else "[REDACTED]"
        
        finding = Finding(
            finding_id=f"SUBDOMAIN-{hash(subdomain) % 10000}",
            title="Subdomain Found",
            module="subdomain",
            url=f"https://{subdomain}",
            parameter="subdomain",
            severity="info",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            poc=poc_content,
            reproduction_steps=f"1. Run DNS lookup for {subdomain}\n2. Observe that it resolves to an IP address",
            impact="Additional subdomains may expose more attack surface or reveal internal services.",
            recommended_fix="Review all subdomains for proper security configurations. Remove or secure any unnecessary subdomains.",
            suggested_bounty="N/A",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/assets/archive/4.2/WSTG-v42-02-01-Subdomain_Enumeration.html",
                "https://en.wikipedia.org/wiki/Domain_Name_System"
            ]
        )
        
        return finding