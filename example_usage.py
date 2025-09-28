#!/usr/bin/env python3
"""
Example usage of BoltVulnScanner
"""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from boltvuln.utils import ScanConfig
from boltvuln.orchestrator import ScannerOrchestrator
from boltvuln.reporter import Reporter

def demo_scan():
    """Run a demo scan"""
    print("BoltVulnScanner Demo")
    print("=" * 30)
    
    # Create scan configuration
    config = ScanConfig(
        target_url="http://example.com",
        max_depth=2,
        max_pages=10,
        concurrency=5,
        timeout=10
    )
    
    # Create orchestrator
    orchestrator = ScannerOrchestrator(config)
    
    # Set up progress callback
    def progress_callback(module, status, progress=None):
        print(f"[{module}] {status} ({progress if progress else 'N/A'}%)")
        
    orchestrator.set_progress_callback(progress_callback)
    
    # Run scan with selected modules
    modules = ['crawler', 'headers', 'ports']
    print(f"Running scan with modules: {', '.join(modules)}")
    
    try:
        findings = orchestrator.run_scan(modules)
        print(f"\nScan completed! Found {len(findings)} findings.")
        
        # Generate report
        reporter = Reporter()
        scan_config = {
            "target_url": config.target_url,
            "modules": modules,
            "depth": config.max_depth,
            "concurrency": config.concurrency,
            "rate_limit": config.max_requests_per_sec,
            "enable_active": config.enable_active,
            "include_poc": config.include_poc
        }
        
        report_files = reporter.generate_reports(findings, scan_config)
        print(f"Reports generated: {', '.join(report_files)}")
        
    except Exception as e:
        print(f"Scan failed: {e}")
        return False
        
    return True

if __name__ == "__main__":
    success = demo_scan()
    sys.exit(0 if success else 1)