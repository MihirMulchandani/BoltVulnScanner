"""
Web crawler module for BoltVulnScanner
"""
import logging
import time
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
from typing import List, Dict, Set
from dataclasses import dataclass, field

from .utils import ScanConfig, RateLimiter, is_same_domain, safe_request

logger = logging.getLogger(__name__)

@dataclass
class WebPage:
    """Represents a crawled web page"""
    url: str
    title: str
    forms: List[Dict] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    depth: int = 0

@dataclass
class Form:
    """Represents an HTML form"""
    action: str
    method: str
    inputs: List[Dict] = field(default_factory=list)

class Crawler:
    """Domain-limited web crawler respecting robots.txt"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.visited_urls: Set[str] = set()
        self.pages: List[WebPage] = []
        self.rate_limiter = RateLimiter(config.max_requests_per_sec)
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'BoltVulnScanner/0.1.0'})
        
    def crawl(self) -> List[WebPage]:
        """
        Crawl the target website up to max_depth and max_pages
        
        Returns:
            List of crawled pages with their forms and links
        """
        logger.info(f"Starting crawl of {self.config.target_url}")
        
        # Normalize the target URL
        target_url = self.config.target_url.rstrip('/')
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
            
        # Start crawling from the target URL
        self._crawl_page(target_url, depth=0)
        
        logger.info(f"Crawling completed. Found {len(self.pages)} pages")
        return self.pages
    
    def _crawl_page(self, url: str, depth: int):
        """Recursively crawl a page and its links"""
        # Check limits
        if depth > self.config.max_depth:
            return
            
        if len(self.pages) >= self.config.max_pages:
            return
            
        # Skip if already visited
        if url in self.visited_urls:
            return
            
        # Skip if excluded by regex
        for pattern in self.config.exclude_regex:
            if re.search(pattern, url):
                logger.debug(f"Skipping excluded URL: {url}")
                return
                
        # Skip if not same domain (when required)
        if self.config.same_domain_only and not is_same_domain(self.config.target_url, url):
            logger.debug(f"Skipping external URL: {url}")
            return
            
        # Respect rate limiting
        self.rate_limiter.wait_if_needed()
        
        # Mark as visited
        self.visited_urls.add(url)
        
        # Fetch the page
        logger.debug(f"Crawling: {url}")
        response = safe_request(url, timeout=self.config.timeout)
        
        if not response:
            return
            
        # Parse the page
        try:
            soup = BeautifulSoup(response.content, 'html.parser')
        except Exception as e:
            logger.error(f"Failed to parse HTML from {url}: {e}")
            return
            
        # Extract page information
        title = soup.title.string if soup.title else ""
        
        # Extract forms
        forms = self._extract_forms(soup, url)
        
        # Extract links
        links = self._extract_links(soup, url)
        
        # Create page object
        page = WebPage(
            url=url,
            title=title,
            forms=forms,
            links=links,
            depth=depth
        )
        
        self.pages.append(page)
        
        # Crawl links if we haven't reached max depth
        if depth < self.config.max_depth:
            for link in links:
                # Add delay between requests
                time.sleep(self.config.delay)
                self._crawl_page(link, depth + 1)
    
    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Extract forms from a parsed HTML page"""
        forms = []
        
        for form_elem in soup.find_all('form'):
            form_data = {
                'action': form_elem.get('action', ''),
                'method': form_elem.get('method', 'GET').upper(),
                'inputs': []
            }
            
            # Resolve form action URL
            if form_data['action']:
                form_data['action'] = urljoin(base_url, form_data['action'])
            else:
                form_data['action'] = base_url
                
            # Extract input fields
            for input_elem in form_elem.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_elem.get('name', ''),
                    'type': input_elem.get('type', 'text'),
                    'value': input_elem.get('value', '')
                }
                form_data['inputs'].append(input_data)
                
            forms.append(form_data)
            
        return forms
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract links from a parsed HTML page"""
        links = []
        
        for link_elem in soup.find_all('a', href=True):
            href = link_elem['href']
            
            # Skip empty links
            if not href or href.startswith('#') or href.startswith('mailto:'):
                continue
                
            # Resolve relative URLs
            absolute_url = urljoin(base_url, href)
            
            # Validate URL
            parsed = urlparse(absolute_url)
            if parsed.scheme in ['http', 'https']:
                links.append(absolute_url)
                
        return links