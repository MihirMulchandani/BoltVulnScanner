#!/usr/bin/env python3
"""
Test runner for BoltVulnScanner
"""
import sys
import os
import unittest

def run_tests():
    """Discover and run all tests"""
    # Add src and tests to path
    project_root = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(project_root, 'src'))
    sys.path.insert(0, project_root)
    
    # Discover and run tests
    loader = unittest.TestLoader()
    start_dir = os.path.join(project_root, 'tests')
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)