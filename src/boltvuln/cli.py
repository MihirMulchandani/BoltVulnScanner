"""
CLI interface for BoltVulnScanner
"""
import argparse
import sys
import os
import logging
from typing import List
import json
import subprocess

from .utils import ScanConfig, Finding
from .orchestrator import ScannerOrchestrator
from .reporter import Reporter

logger = logging.getLogger(__name__)

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="BoltVulnScanner - Automated Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  boltvulnscan scan --target http://example.com --checks xss,sqli
  boltvulnscan scan --target http://example.com --enable-active --confirm-legal "I CONSENT TO ACTIVE TESTS"
  boltvulnscan report --input report.json --format md,pdf
  boltvulnscan ui
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run a security scan')
    scan_parser.add_argument('--target', required=True, help='Target URL to scan')
    scan_parser.add_argument('--checks', help='Comma-separated list of checks to run (default: all)')
    scan_parser.add_argument('--depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
    scan_parser.add_argument('--concurrency', type=int, default=10, help='Concurrency level (default: 10)')
    scan_parser.add_argument('--rate-limit', type=int, default=5, help='Requests per second limit (default: 5)')
    scan_parser.add_argument('--enable-active', action='store_true', help='Enable active tests (requires consent)')
    scan_parser.add_argument('--include-poc', action='store_true', help='Include proof of concept in reports')
    scan_parser.add_argument('--out', default='reports/', help='Output directory for reports (default: reports/)')
    scan_parser.add_argument('--confirm-legal', help='Legal consent phrase for active tests')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate reports from scan results')
    report_parser.add_argument('--input', required=True, help='Input JSON scan results file')
    report_parser.add_argument('--format', default='md,json', help='Output formats (md,json,pdf) (default: md,json)')
    report_parser.add_argument('--out', default='reports/', help='Output directory (default: reports/)')
    
    # UI command
    ui_parser = subparsers.add_parser('ui', help='Launch Streamlit web UI')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        _run_scan(args)
    elif args.command == 'report':
        _generate_report(args)
    elif args.command == 'ui':
        _launch_ui()
    else:
        parser.print_help()

def _run_scan(args):
    """Run a security scan"""
    # Validate legal consent for active tests
    if args.enable_active:
        if not args.confirm_legal or args.confirm_legal != "I CONSENT TO ACTIVE TESTS":
            print("ERROR: Active tests require legal consent.")
            print("Please add: --confirm-legal \"I CONSENT TO ACTIVE TESTS\"")
            sys.exit(1)
            
    # Parse checks
    if args.checks:
        modules = args.checks.split(',')
    else:
        # Default to all modules
        modules = [
            'crawler', 'ports', 'xss', 'sqli', 'tls', 'headers', 
            'dir_enum', 'open_redirect', 'csrf', 'traversal', 
            'subdomain', 'cmd_injection'
        ]
        
    # Create scan configuration
    config = ScanConfig(
        target_url=args.target,
        max_depth=args.depth,
        concurrency=args.concurrency,
        max_requests_per_sec=args.rate_limit,
        enable_active=args.enable_active,
        include_poc=args.include_poc
    )
    
    # Run scan
    print(f"Starting scan of {args.target}")
    print(f"Modules: {', '.join(modules)}")
    
    orchestrator = ScannerOrchestrator(config)
    findings = orchestrator.run_scan(modules)
    
    # Generate reports
    reporter = Reporter(args.out)
    scan_config = {
        "target_url": args.target,
        "modules": modules,
        "depth": args.depth,
        "concurrency": args.concurrency,
        "rate_limit": args.rate_limit,
        "enable_active": args.enable_active,
        "include_poc": args.include_poc
    }
    
    report_files = reporter.generate_reports(findings, scan_config)
    
    print(f"\nScan completed successfully!")
    print(f"Findings: {len(findings)}")
    print(f"Reports generated:")
    for report_file in report_files:
        print(f"  - {report_file}")

def _generate_report(args):
    """Generate reports from scan results"""
    # Load scan results
    if not os.path.exists(args.input):
        print(f"ERROR: Input file {args.input} not found")
        sys.exit(1)
        
    with open(args.input, 'r') as f:
        scan_data = json.load(f)
        
    findings_data = scan_data.get('findings', [])
    scan_config = scan_data.get('scan_info', {})
    
    # Convert findings data to Finding objects
    findings = []
    for finding_data in findings_data:
        finding = Finding(
            finding_id=finding_data.get('finding_id', ''),
            title=finding_data.get('title', ''),
            module=finding_data.get('module', ''),
            url=finding_data.get('url', ''),
            parameter=finding_data.get('parameter', ''),
            severity=finding_data.get('severity', ''),
            cvss_vector=finding_data.get('cvss_vector', ''),
            poc=finding_data.get('poc', ''),
            reproduction_steps=finding_data.get('reproduction_steps', ''),
            impact=finding_data.get('impact', ''),
            recommended_fix=finding_data.get('recommended_fix', ''),
            suggested_bounty=finding_data.get('suggested_bounty', ''),
            references=finding_data.get('references', []),
            confirmed=finding_data.get('confirmed', False)
        )
        findings.append(finding)
        
    # Parse formats
    formats = args.format.split(',')
    
    # Generate reports
    reporter = Reporter(args.out)
    report_files = reporter.generate_reports(findings, scan_config, formats)
    
    print(f"Reports generated:")
    for report_file in report_files:
        print(f"  - {report_file}")

def _launch_ui():
    """Launch Streamlit web UI"""
    try:
        # Try to import streamlit
        import importlib
        importlib.import_module('streamlit')
        
        # Get the path to streamlit_app.py
        ui_path = os.path.join(os.path.dirname(__file__), 'streamlit_app.py')
        
        # Launch Streamlit
        subprocess.run([
            sys.executable, '-m', 'streamlit', 'run', ui_path
        ])
    except ImportError:
        print("ERROR: Streamlit not installed. Install with: pip install streamlit")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to launch UI: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()