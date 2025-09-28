"""
Unit tests for BoltVulnScanner orchestrator module
"""
import sys
import os
import unittest
from unittest.mock import Mock, patch

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from boltvuln.utils import ScanConfig
from boltvuln.orchestrator import ScannerOrchestrator

class TestOrchestrator(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.config = ScanConfig(target_url="http://example.com")
        self.orchestrator = ScannerOrchestrator(self.config)
        
    def test_orchestrator_initialization(self):
        """Test ScannerOrchestrator initialization"""
        self.assertIsInstance(self.orchestrator, ScannerOrchestrator)
        self.assertEqual(self.orchestrator.config, self.config)
        self.assertEqual(self.orchestrator.findings, [])
        self.assertEqual(self.orchestrator.modules_enabled, [])
        
    def test_set_progress_callback(self):
        """Test setting progress callback"""
        callback = Mock()
        self.orchestrator.set_progress_callback(callback)
        self.assertEqual(self.orchestrator.progress_callback, callback)
        
    @patch('boltvuln.orchestrator.Crawler')
    def test_run_scan_crawler_only(self, mock_crawler):
        """Test running scan with only crawler module"""
        # Mock the crawler to return some pages
        mock_crawler_instance = Mock()
        mock_crawler_instance.crawl.return_value = []
        mock_crawler.return_value = mock_crawler_instance
        
        findings = self.orchestrator.run_scan(['crawler'])
        
        # Verify the crawler was called
        mock_crawler.assert_called_once_with(self.config)
        mock_crawler_instance.crawl.assert_called_once()
        
        # Verify findings are returned (empty in this case)
        self.assertIsInstance(findings, list)
        
    def test_empty_module_list(self):
        """Test running scan with no modules"""
        with patch.object(self.orchestrator, '_update_progress') as mock_update:
            findings = self.orchestrator.run_scan([])
            self.assertEqual(findings, [])
            mock_update.assert_not_called()

if __name__ == '__main__':
    unittest.main()