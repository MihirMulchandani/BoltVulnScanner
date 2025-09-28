"""
Streamlit web UI for BoltVulnScanner
"""
import sys
import os
import logging
import time
import json
from typing import List

# Import our modules
from boltvuln.utils import ScanConfig
from boltvuln.orchestrator import ScannerOrchestrator
from boltvuln.reporter import Reporter

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    # Check if streamlit is available
    try:
        import streamlit as st
    except ImportError:
        print("Streamlit is not installed. Please install it with: pip install streamlit")
        return
        
    st.set_page_config(
        page_title="BoltVulnScanner",
        page_icon="⚡",
        layout="wide"
    )
    
    # Custom CSS for better styling
    st.markdown("""
        <style>
        .stProgress > div > div > div > div {
            background-color: #4CAF50;
        }
        .finding-critical { 
            border-left: 5px solid #f44336; 
            padding: 10px; 
            margin: 10px 0; 
        }
        .finding-high { 
            border-left: 5px solid #ff9800; 
            padding: 10px; 
            margin: 10px 0; 
        }
        .finding-medium { 
            border-left: 5px solid #ffc107; 
            padding: 10px; 
            margin: 10px 0; 
        }
        .finding-low { 
            border-left: 5px solid #4caf50; 
            padding: 10px; 
            margin: 10px 0; 
        }
        .log-info { color: #2196F3; }
        .log-warning { color: #FF9800; }
        .log-error { color: #f44336; }
        .log-critical { color: #9C27B0; }
        </style>
    """, unsafe_allow_html=True)
    
    st.title("⚡ BoltVulnScanner")
    st.markdown("#### Automated Web Vulnerability Scanner")
    st.markdown("Safe-by-default, single-user, demo/production-aware pentesting suite")
    
    # Initialize session state
    if 'scan_running' not in st.session_state:
        st.session_state.scan_running = False
    if 'findings' not in st.session_state:
        st.session_state.findings = []
    if 'logs' not in st.session_state:
        st.session_state.logs = []
    if 'progress' not in st.session_state:
        st.session_state.progress = {}
        
    # Sidebar controls
    with st.sidebar:
        st.header("Scan Configuration")
        
        # Target URL
        target_url = st.text_input("Target Website URL", placeholder="https://example.com")
        
        # Module selection
        st.subheader("Modules to Scan")
        modules = {
            'crawler': st.checkbox('Crawler', value=True),
            'ports': st.checkbox('Ports', value=True),
            'xss': st.checkbox('XSS', value=True),
            'sqli': st.checkbox('SQLi', value=True),
            'tls': st.checkbox('TLS/SSL', value=True),
            'headers': st.checkbox('Security Headers', value=True),
            'dir_enum': st.checkbox('Directory Enumeration', value=True),
            'open_redirect': st.checkbox('Open Redirect', value=True),
            'csrf': st.checkbox('CSRF Token Detection', value=True),
            'traversal': st.checkbox('Directory Traversal', value=True),
            'subdomain': st.checkbox('Subdomain Enumeration', value=True),
            'cmd_injection': st.checkbox('Command Injection', value=True)
        }
        
        # Advanced options
        st.subheader("Advanced Options")
        max_depth = st.slider("Max Crawl Depth", 1, 10, 3)
        concurrency = st.slider("Concurrency", 1, 50, 10)
        rate_limit = st.slider("Rate Limit (req/sec)", 1, 20, 5)
        
        # Optional wordlist upload
        wordlist_file = st.file_uploader("Upload Wordlist (optional)", type=['txt'])
        
        # Optional integrations
        st.subheader("Optional Integrations")
        enable_playwright = st.checkbox("Enable Playwright (headless browser)")
        enable_sslyze = st.checkbox("Enable sslyze (TLS scanning)")
        
        # Safety confirmation
        st.subheader("Safety & Consent")
        consent = st.checkbox("I understand this scan can be active")
        
        # PoC inclusion
        include_poc = st.checkbox("Include Proof of Concept in Report", value=False)
        
        # Buttons
        col1, col2 = st.columns(2)
        with col1:
            demo_scan = st.button("Run Demo Scan", key="demo_scan")
        with col2:
            active_scan = st.button("Run Active Scan", key="active_scan", 
                                  disabled=not consent or not target_url)
        
        # Legal disclaimer
        st.markdown("---")
        st.warning("""
        **Legal Disclaimer**: 
        - Active scans require user responsibility
        - Demo scans are safe and fully local
        - Always obtain proper authorization before scanning
        """)
        
    # Initialize variables
    selected_modules = []
    enable_active = False
    
    # Main content area
    if demo_scan or active_scan:
        # Validate target URL
        if not target_url:
            st.error("Please enter a target URL")
            st.stop()
            
        # Validate modules selection
        selected_modules = [module for module, selected in modules.items() if selected]
        if not selected_modules:
            st.error("Please select at least one module to scan")
            st.stop()
            
        # Configure scan
        enable_active = active_scan and consent
        config = ScanConfig(
            target_url=target_url,
            max_depth=max_depth,
            concurrency=concurrency,
            max_requests_per_sec=rate_limit,
            enable_active=enable_active,
            include_poc=include_poc
        )
        
        # Run scan
        with st.spinner("Running scan..."):
            orchestrator = ScannerOrchestrator(config)
            
            # Set up progress callback
            def progress_callback(module, status, progress=None):
                st.session_state.progress[module] = {
                    'status': status,
                    'progress': progress or 0
                }
                st.session_state.logs.append(f"[{module}] {status}")
                
            orchestrator.set_progress_callback(progress_callback)
            
            try:
                findings = orchestrator.run_scan(selected_modules)
                st.session_state.findings = findings
                st.session_state.logs.append("Scan completed successfully!")
                st.success("Scan completed!")
            except Exception as e:
                st.session_state.logs.append(f"Error: {str(e)}")
                st.error(f"Scan failed: {str(e)}")
                
    # Display progress
    if st.session_state.progress:
        st.subheader("Scan Progress")
        progress_cols = st.columns(len(st.session_state.progress))
        for i, (module, progress_info) in enumerate(st.session_state.progress.items()):
            with progress_cols[i]:
                st.markdown(f"**{module}**")
                st.progress(progress_info['progress'] / 100)
                st.caption(progress_info['status'])
                
    # Display logs
    if st.session_state.logs:
        st.subheader("Scan Logs")
        log_container = st.container()
        with log_container:
            for log in st.session_state.logs[-20:]:  # Show last 20 logs
                if "ERROR" in log:
                    st.markdown(f"<div class='log-error'>{log}</div>", unsafe_allow_html=True)
                elif "WARNING" in log:
                    st.markdown(f"<div class='log-warning'>{log}</div>", unsafe_allow_html=True)
                elif "completed" in log:
                    st.markdown(f"<div class='log-info'>{log}</div>", unsafe_allow_html=True)
                else:
                    st.markdown(f"<div class='log-info'>{log}</div>", unsafe_allow_html=True)
                    
    # Display findings
    if st.session_state.findings:
        st.subheader(f"Findings ({len(st.session_state.findings)} issues found)")
        
        # Summary
        severity_counts = {}
        for finding in st.session_state.findings:
            severity = finding.severity
            if severity not in severity_counts:
                severity_counts[severity] = 0
            severity_counts[severity] += 1
            
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Critical", severity_counts.get('critical', 0))
        col2.metric("High", severity_counts.get('high', 0))
        col3.metric("Medium", severity_counts.get('medium', 0))
        col4.metric("Low", severity_counts.get('low', 0))
        col5.metric("Info", severity_counts.get('info', 0))
        
        # Filter by severity
        severity_filter = st.selectbox(
            "Filter by Severity",
            ["All", "Critical", "High", "Medium", "Low", "Info"]
        )
        
        # Display findings
        filtered_findings = st.session_state.findings
        if severity_filter != "All":
            filtered_findings = [f for f in st.session_state.findings if f.severity == severity_filter.lower()]
            
        for finding in filtered_findings:
            severity_class = f"finding-{finding.severity}"
            with st.expander(f"**{finding.title}** - {finding.severity.upper()}", expanded=False):
                st.markdown(f"<div class='{severity_class}'>", unsafe_allow_html=True)
                st.markdown(f"**ID**: {finding.finding_id}")
                st.markdown(f"**Module**: {finding.module}")
                st.markdown(f"**URL**: {finding.url}")
                st.markdown(f"**Parameter**: {finding.parameter}")
                st.markdown(f"**CVSS Vector**: {finding.cvss_vector}")
                st.markdown(f"**Confirmed**: {'Yes' if finding.confirmed else 'No'}")
                
                st.markdown("#### Proof of Concept")
                st.code(finding.poc, language="text")
                
                st.markdown("#### Reproduction Steps")
                st.markdown(finding.reproduction_steps)
                
                st.markdown("#### Impact")
                st.markdown(finding.impact)
                
                st.markdown("#### Recommended Fix")
                st.markdown(finding.recommended_fix)
                
                st.markdown("#### Suggested Bounty")
                st.markdown(finding.suggested_bounty)
                
                st.markdown("#### References")
                for ref in finding.references:
                    st.markdown(f"- {ref}")
                    
                st.markdown("</div>", unsafe_allow_html=True)
                
        # Report generation
        st.subheader("Generate Report")
        report_formats = st.multiselect(
            "Select Report Formats",
            ["JSON", "Markdown", "PDF", "ZIP"],
            ["JSON", "Markdown"]
        )
        
        if st.button("Generate Report"):
            with st.spinner("Generating report..."):
                try:
                    reporter = Reporter()
                    scan_config = {
                        "target_url": target_url,
                        "modules": selected_modules,
                        "depth": max_depth,
                        "concurrency": concurrency,
                        "rate_limit": rate_limit,
                        "enable_active": enable_active,
                        "include_poc": include_poc
                    }
                    
                    formats = [f.lower() for f in report_formats]
                    report_files = reporter.generate_reports(st.session_state.findings, scan_config, formats)
                    
                    st.success("Reports generated successfully!")
                    for report_file in report_files:
                        with open(report_file, "rb") as file:
                            st.download_button(
                                label=f"Download {os.path.basename(report_file)}",
                                data=file,
                                file_name=os.path.basename(report_file),
                                mime="application/octet-stream"
                            )
                except Exception as e:
                    st.error(f"Failed to generate report: {str(e)}")
                    
    # Footer
    st.markdown("---")
    st.markdown("""
    **BoltVulnScanner** is an automated web vulnerability scanner for educational purposes.
    
    ⚠️ **Disclaimer**: This tool is for authorized security testing only. 
    The scores and CVSS vectors are approximations and should not be used for production assessments.
    """)

if __name__ == "__main__":
    main()