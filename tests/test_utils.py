"""
Unit tests for BoltVulnScanner utils module
"""
import sys
import os
import unittest
from unittest.mock import Mock, patch

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from boltvuln.utils import ScanConfig, normalize_url, is_same_domain, is_valid_url

class TestUtils(unittest.TestCase):
    
    def test_scan_config_creation(self):
        """Test ScanConfig creation with default values"""
        config = ScanConfig(target_url="http://example.com")
        
        self.assertEqual(config.target_url, "http://example.com")
        self.assertEqual(config.max_depth, 3)
        self.assertEqual(config.max_pages, 100)
        self.assertEqual(config.same_domain_only, True)
        self.assertEqual(config.exclude_regex, [])
        self.assertEqual(config.delay, 1.0)
        self.assertEqual(config.max_requests_per_sec, 5)
        self.assertEqual(config.concurrency, 10)
        self.assertEqual(config.timeout, 30)
        self.assertEqual(config.enable_active, False)
        self.assertEqual(config.include_poc, False)
        
    def test_scan_config_custom_values(self):
        """Test ScanConfig creation with custom values"""
        config = ScanConfig(
            target_url="http://example.com",
            max_depth=5,
            max_pages=200,
            same_domain_only=False,
            delay=2.0,
            max_requests_per_sec=10,
            concurrency=20,
            timeout=60,
            enable_active=True,
            include_poc=True
        )
        
        self.assertEqual(config.max_depth, 5)
        self.assertEqual(config.max_pages, 200)
        self.assertEqual(config.same_domain_only, False)
        self.assertEqual(config.delay, 2.0)
        self.assertEqual(config.max_requests_per_sec, 10)
        self.assertEqual(config.concurrency, 20)
        self.assertEqual(config.timeout, 60)
        self.assertEqual(config.enable_active, True)
        self.assertEqual(config.include_poc, True)
        
    def test_normalize_url(self):
        """Test URL normalization"""
        from boltvuln.utils import normalize_url
        
        # Test adding scheme
        self.assertEqual(normalize_url("example.com"), "http://example.com/")
        
        # Test adding trailing slash
        self.assertEqual(normalize_url("http://example.com"), "http://example.com/")
        
        # Test already normalized URL
        self.assertEqual(normalize_url("https://example.com/"), "https://example.com/")
        
        # Test URL with path
        self.assertEqual(normalize_url("http://example.com/path"), "http://example.com/path/")
        
    def test_is_same_domain(self):
        """Test domain comparison"""
        from boltvuln.utils import is_same_domain
        
        self.assertTrue(is_same_domain("http://example.com", "http://example.com"))
        self.assertTrue(is_same_domain("http://example.com", "https://example.com"))
        self.assertTrue(is_same_domain("http://example.com/path", "http://example.com/other"))
        self.assertFalse(is_same_domain("http://example.com", "http://other.com"))
        self.assertFalse(is_same_domain("http://example.com", "http://sub.example.com"))
        
    def test_is_valid_url(self):
        """Test URL validation"""
        from boltvuln.utils import is_valid_url
        
        self.assertTrue(is_valid_url("http://example.com"))
        self.assertTrue(is_valid_url("https://example.com"))
        self.assertTrue(is_valid_url("http://example.com/path?query=value"))
        self.assertFalse(is_valid_url("not-a-url"))
        self.assertFalse(is_valid_url("ftp://example.com"))
        self.assertFalse(is_valid_url(""))

if __name__ == '__main__':
    unittest.main()