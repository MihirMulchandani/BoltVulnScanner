#!/usr/bin/env python3
"""
Test script to verify BoltVulnScanner imports work correctly
"""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_imports():
    """Test that all modules can be imported"""
    modules_to_test = [
        'boltvuln.utils',
        'boltvuln.cli',
        'boltvuln.orchestrator',
        'boltvuln.crawler',
        'boltvuln.ports',
        'boltvuln.xss',
        'boltvuln.sqli',
        'boltvuln.tls_check',
        'boltvuln.headers_check',
        'boltvuln.dir_enum',
        'boltvuln.open_redirect',
        'boltvuln.csrf_check',
        'boltvuln.traversal',
        'boltvuln.subdomain_enum',
        'boltvuln.cmd_injection',
        'boltvuln.reporter'
    ]
    
    failed_imports = []
    
    for module in modules_to_test:
        try:
            __import__(module)
            print(f"✓ {module}")
        except ImportError as e:
            failed_imports.append((module, str(e)))
            print(f"✗ {module}: {e}")
            
    if failed_imports:
        print(f"\n{len(failed_imports)} modules failed to import:")
        for module, error in failed_imports:
            print(f"  {module}: {error}")
        return False
    else:
        print(f"\nAll {len(modules_to_test)} modules imported successfully!")
        return True

if __name__ == "__main__":
    print("Testing BoltVulnScanner imports...")
    success = test_imports()
    sys.exit(0 if success else 1)