"""
BoltVulnScanner - Automated Web Vulnerability Scanner

A comprehensive security scanning tool for detecting common web vulnerabilities
including XSS, SQLi, directory traversal, and more.
"""

__version__ = "0.1.0"
__author__ = "Security Engineer"
__email__ = "security@example.com"

# Import core modules for easier access
from .orchestrator import ScannerOrchestrator
from .reporter import Reporter
from .utils import ScanConfig

__all__ = [
    "ScannerOrchestrator",
    "Reporter",
    "ScanConfig"
]