"""
Report generator module for BoltVulnScanner
"""
import logging
import json
import os
import zipfile
from typing import List, Dict, Any, Optional
from datetime import datetime
import markdown

from .utils import Finding

logger = logging.getLogger(__name__)

class Reporter:
    """Generate security scan reports in various formats"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
    def generate_reports(self, findings: List[Finding], scan_config: Dict[str, Any], format_types: Optional[List[str]] = None) -> List[str]:
        """
        Generate reports in specified formats
        
        Args:
            findings: List of security findings
            scan_config: Scan configuration
            format_types: List of format types to generate (json, markdown, pdf)
            
        Returns:
            List of generated report file paths
        """
        if format_types is None:
            format_types = ['json', 'markdown']
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_dir = os.path.join(self.output_dir, f"scan_{timestamp}")
        os.makedirs(scan_dir, exist_ok=True)
        
        report_files = []
        
        # Generate JSON report
        if 'json' in format_types:
            json_file = self._generate_json_report(findings, scan_config, scan_dir, timestamp)
            report_files.append(json_file)
            
        # Generate Markdown report
        if 'markdown' in format_types:
            md_file = self._generate_markdown_report(findings, scan_config, scan_dir, timestamp)
            report_files.append(md_file)
            
        # Generate PDF report (if dependencies are available)
        if 'pdf' in format_types:
            try:
                pdf_file = self._generate_pdf_report(findings, scan_config, scan_dir, timestamp)
                report_files.append(pdf_file)
            except ImportError:
                logger.warning("PDF generation dependencies not available. Install weasyprint for PDF reports.")
            except Exception as e:
                logger.error(f"Error generating PDF report: {e}")
                
        # Create ZIP archive with all reports and evidence
        zip_file = self._create_zip_archive(report_files, scan_dir, timestamp)
        report_files.append(zip_file)
        
        return report_files
    
    def _generate_json_report(self, findings: List[Finding], scan_config: Dict[str, Any], scan_dir: str, timestamp: str) -> str:
        """Generate JSON report"""
        report_data = {
            "scan_info": {
                "timestamp": timestamp,
                "target": scan_config.get("target_url", ""),
                "modules": scan_config.get("modules", []),
                "total_findings": len(findings)
            },
            "summary": self._generate_summary(findings),
            "findings": [self._finding_to_dict(f) for f in findings]
        }
        
        json_file = os.path.join(scan_dir, f"report_{timestamp}.json")
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2)
            
        logger.info(f"JSON report generated: {json_file}")
        return json_file
    
    def _generate_markdown_report(self, findings: List[Finding], scan_config: Dict[str, Any], scan_dir: str, timestamp: str) -> str:
        """Generate Markdown report"""
        # Group findings by severity
        findings_by_severity = {}
        for finding in findings:
            severity = finding.severity
            if severity not in findings_by_severity:
                findings_by_severity[severity] = []
            findings_by_severity[severity].append(finding)
            
        # Sort severities by criticality
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        sorted_findings = []
        for severity in severity_order:
            if severity in findings_by_severity:
                # Sort findings by confirmed status and title
                sorted_findings.extend(sorted(findings_by_severity[severity], 
                                            key=lambda x: (not x.confirmed, x.title)))
                
        # Create markdown content
        md_content = f"""# BoltVulnScanner Security Report

## Scan Information
- **Timestamp**: {timestamp}
- **Target**: {scan_config.get("target_url", "N/A")}
- **Modules Scanned**: {', '.join(scan_config.get("modules", []))}
- **Total Findings**: {len(findings)}

## Executive Summary
{self._generate_summary_markdown(findings)}

## Findings Details

"""
        
        for finding in sorted_findings:
            md_content += f"""### {finding.title}
- **ID**: {finding.finding_id}
- **Module**: {finding.module}
- **URL**: {finding.url}
- **Parameter**: {finding.parameter}
- **Severity**: {finding.severity.upper()}
- **CVSS Vector**: {finding.cvss_vector}
- **Confirmed**: {"Yes" if finding.confirmed else "No"}

#### Proof of Concept
```
{finding.poc}
```

#### Reproduction Steps
{finding.reproduction_steps}

#### Impact
{finding.impact}

#### Recommended Fix
{finding.recommended_fix}

#### Suggested Bounty
{finding.suggested_bounty}

#### References
"""
            for ref in finding.references:
                md_content += f"- {ref}\n"
            md_content += "\n---\n\n"
            
        md_content += f"""## Disclaimer
This report is for educational and demonstration purposes only. The scores and CVSS vectors are approximations and should not be used for production security assessments. Always conduct proper penetration testing with professional tools and expertise.

## About BoltVulnScanner
BoltVulnScanner is an automated web vulnerability scanner designed for educational purposes. It detects common web vulnerabilities and generates bug bounty style reports.
"""
        
        md_file = os.path.join(scan_dir, f"report_{timestamp}.md")
        with open(md_file, 'w') as f:
            f.write(md_content)
            
        logger.info(f"Markdown report generated: {md_file}")
        return md_file
    
    def _generate_pdf_report(self, findings: List[Finding], scan_config: Dict[str, Any], scan_dir: str, timestamp: str) -> str:
        """Generate PDF report using weasyprint"""
        # Convert markdown to HTML first
        md_file = self._generate_markdown_report(findings, scan_config, scan_dir, timestamp)
        
        with open(md_file, 'r') as f:
            md_content = f.read()
            
        html_content = markdown.markdown(md_content)
        
        # Add basic styling
        html_with_style = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #d32f2f; border-bottom: 2px solid #d32f2f; padding-bottom: 10px; }}
                h2 {{ color: #303f9f; margin-top: 30px; }}
                h3 {{ color: #388e3c; margin-top: 25px; }}
                pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }}
                code {{ font-family: 'Courier New', monospace; }}
                .finding {{ border: 1px solid #e0e0e0; margin: 20px 0; padding: 15px; border-radius: 5px; }}
                .severity-critical {{ border-left: 5px solid #d32f2f; }}
                .severity-high {{ border-left: 5px solid #f57c00; }}
                .severity-medium {{ border-left: 5px solid #fbc02d; }}
                .severity-low {{ border-left: 5px solid #388e3c; }}
                .severity-info {{ border-left: 5px solid #1976d2; }}
            </style>
        </head>
        <body>
            {html_content}
        </body>
        </html>
        """
        
        # Generate PDF
        try:
            # Try to import weasyprint
            import importlib
            weasyprint = importlib.import_module('weasyprint')
            HTML = weasyprint.HTML
            
            pdf_file = os.path.join(scan_dir, f"report_{timestamp}.pdf")
            HTML(string=html_with_style).write_pdf(pdf_file)
            logger.info(f"PDF report generated: {pdf_file}")
            return pdf_file
        except ImportError:
            logger.warning("weasyprint not installed, cannot generate PDF")
            raise
        except Exception as e:
            logger.error(f"Error generating PDF: {e}")
            raise
    
    def _generate_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate scan summary statistics"""
        severity_counts = {}
        confirmed_count = 0
        
        for finding in findings:
            severity = finding.severity
            if severity not in severity_counts:
                severity_counts[severity] = 0
            severity_counts[severity] += 1
            
            if finding.confirmed:
                confirmed_count += 1
                
        # Determine highest severity
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        highest_severity = 'info'
        for severity in severity_order:
            if severity in severity_counts and severity_counts[severity] > 0:
                highest_severity = severity
                break
                
        return {
            "total_findings": len(findings),
            "confirmed_findings": confirmed_count,
            "severity_breakdown": severity_counts,
            "highest_severity": highest_severity
        }
    
    def _generate_summary_markdown(self, findings: List[Finding]) -> str:
        """Generate markdown summary"""
        summary = self._generate_summary(findings)
        
        md_summary = f"""This scan identified **{summary['total_findings']}** potential security issues, with **{summary['confirmed_findings']}** confirmed findings.

### Severity Breakdown
"""
        for severity, count in summary['severity_breakdown'].items():
            md_summary += f"- **{severity.upper()}**: {count}\n"
            
        md_summary += f"""

### Highest Severity
**{summary['highest_severity'].upper()}**

### Educational Note
The severity scores and CVSS vectors in this report are for educational purposes only. They are approximations and should not be used for production security assessments.
"""
        
        return md_summary
    
    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Convert Finding to dictionary"""
        return {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "module": finding.module,
            "url": finding.url,
            "parameter": finding.parameter,
            "severity": finding.severity,
            "cvss_vector": finding.cvss_vector,
            "poc": finding.poc,
            "reproduction_steps": finding.reproduction_steps,
            "impact": finding.impact,
            "recommended_fix": finding.recommended_fix,
            "suggested_bounty": finding.suggested_bounty,
            "references": finding.references,
            "confirmed": finding.confirmed
        }
    
    def _create_zip_archive(self, report_files: List[str], scan_dir: str, timestamp: str) -> str:
        """Create ZIP archive containing all reports and evidence"""
        zip_file = os.path.join(scan_dir, f"report_{timestamp}.zip")
        
        with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in report_files:
                if os.path.exists(file_path):
                    # Add file to zip with relative path
                    arc_name = os.path.basename(file_path)
                    zipf.write(file_path, arc_name)
                    
        logger.info(f"ZIP archive created: {zip_file}")
        return zip_file