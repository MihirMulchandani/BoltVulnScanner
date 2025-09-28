"""
Security headers checker module for BoltVulnScanner
"""
import logging
import requests
from typing import List, Dict, Any
from urllib.parse import urlparse

from .utils import ScanConfig, Finding, safe_request

logger = logging.getLogger(__name__)

class HeadersChecker:
    """Check for security-related HTTP headers"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        
    def check(self) -> List[Finding]:
        """
        Check for missing or misconfigured security headers
        
        Returns:
            List of header-related findings
        """
        logger.info("Starting security headers check")
        findings = []
        
        # Make request to target
        response = safe_request(self.config.target_url, timeout=self.config.timeout)
        if not response:
            logger.error("Failed to fetch target URL")
            return findings
            
        headers: Dict[str, Any] = dict(response.headers)
        
        # Check for missing security headers
        missing_headers_findings = self._check_missing_headers(headers)
        findings.extend(missing_headers_findings)
        
        # Check for misconfigured headers
        misconfigured_findings = self._check_misconfigured_headers(headers)
        findings.extend(misconfigured_findings)
        
        logger.info(f"Headers check completed. Found {len(findings)} issues")
        return findings
    
    def _check_missing_headers(self, headers: Dict[str, Any]) -> List[Finding]:
        """Check for missing security headers"""
        findings = []
        
        # Define expected security headers
        expected_headers = {
            'strict-transport-security': {
                'title': 'Missing Strict-Transport-Security Header',
                'description': 'The Strict-Transport-Security header enforces the use of HTTPS.',
                'severity': 'medium',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N',
                'fix': 'Add the Strict-Transport-Security header with a max-age of at least 31536000 seconds (1 year). Example: Strict-Transport-Security: max-age=31536000; includeSubDomains'
            },
            'content-security-policy': {
                'title': 'Missing Content-Security-Policy Header',
                'description': 'The Content-Security-Policy header helps prevent XSS and other injection attacks.',
                'severity': 'high',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N',
                'fix': 'Implement a Content Security Policy that restricts sources for scripts, styles, and other content. Example: Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\''
            },
            'x-frame-options': {
                'title': 'Missing X-Frame-Options Header',
                'description': 'The X-Frame-Options header prevents clickjacking attacks by controlling whether the page can be embedded in frames.',
                'severity': 'medium',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N',
                'fix': 'Add the X-Frame-Options header. Example: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN'
            },
            'x-content-type-options': {
                'title': 'Missing X-Content-Type-Options Header',
                'description': 'The X-Content-Type-Options header prevents MIME type sniffing.',
                'severity': 'low',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N',
                'fix': 'Add the X-Content-Type-Options header. Example: X-Content-Type-Options: nosniff'
            },
            'referrer-policy': {
                'title': 'Missing Referrer-Policy Header',
                'description': 'The Referrer-Policy header controls how much referrer information is included with requests.',
                'severity': 'low',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
                'fix': 'Add the Referrer-Policy header. Example: Referrer-Policy: strict-origin-when-cross-origin'
            },
            'permissions-policy': {
                'title': 'Missing Permissions-Policy Header',
                'description': 'The Permissions-Policy header controls which features and APIs can be used in the browser.',
                'severity': 'low',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
                'fix': 'Add the Permissions-Policy header to restrict browser features. Example: Permissions-Policy: geolocation=(), camera=()'
            }
        }
        
        # Check each expected header
        for header_name, header_info in expected_headers.items():
            if header_name not in [h.lower() for h in headers.keys()]:
                finding = Finding(
                    finding_id=f"HEADER-MISSING-{header_name.upper().replace('-', '')}",
                    title=header_info['title'],
                    module="headers",
                    url=self.config.target_url,
                    parameter=header_name,
                    severity=header_info['severity'],
                    cvss_vector=header_info['cvss_vector'],
                    poc=f"Header '{header_name}' is missing from the response" if self.config.include_poc else "[REDACTED]",
                    reproduction_steps=f"1. Send a request to {self.config.target_url}\n2. Check the response headers\n3. Observe that the '{header_name}' header is missing",
                    impact=header_info['description'],
                    recommended_fix=header_info['fix'],
                    suggested_bounty="$100-$500" if header_info['severity'] == 'high' else "$50-$200" if header_info['severity'] == 'medium' else "$25-$100",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
                    ]
                )
                findings.append(finding)
                
        return findings
    
    def _check_misconfigured_headers(self, headers: Dict[str, Any]) -> List[Finding]:
        """Check for misconfigured security headers"""
        findings = []
        
        # Check HSTS configuration
        hsts_header = headers.get('Strict-Transport-Security')
        if hsts_header:
            hsts_findings = self._check_hsts_config(hsts_header)
            findings.extend(hsts_findings)
            
        # Check CSP configuration
        csp_header = headers.get('Content-Security-Policy')
        if csp_header:
            csp_findings = self._check_csp_config(csp_header)
            findings.extend(csp_findings)
            
        # Check X-Frame-Options
        xfo_header = headers.get('X-Frame-Options')
        if xfo_header:
            xfo_findings = self._check_xfo_config(xfo_header)
            findings.extend(xfo_findings)
            
        # Check for insecure headers
        insecure_findings = self._check_insecure_headers(headers)
        findings.extend(insecure_findings)
        
        return findings
    
    def _check_hsts_config(self, hsts_header: str) -> List[Finding]:
        """Check HSTS header configuration"""
        findings = []
        
        # Check max-age
        if 'max-age=' not in hsts_header:
            finding = Finding(
                finding_id="HEADER-HSTS-NO-MAXAGE",
                title="HSTS Header Missing max-age Directive",
                module="headers",
                url=self.config.target_url,
                parameter="strict-transport-security",
                severity="medium",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                poc=f"HSTS header missing max-age: {hsts_header}" if self.config.include_poc else "[REDACTED]",
                reproduction_steps=f"1. Send a request to {self.config.target_url}\n2. Check the Strict-Transport-Security header\n3. Observe that it's missing the max-age directive",
                impact="Without max-age, browsers won't know how long to enforce HTTPS-only connections.",
                recommended_fix="Add a max-age directive to the HSTS header. Example: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                suggested_bounty="$100-$300",
                references=[
                    "https://owasp.org/www-project-secure-headers/#strict-transport-security",
                    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
                ]
            )
            findings.append(finding)
        else:
            # Extract max-age value
            try:
                max_age_part = [part for part in hsts_header.split(';') if 'max-age=' in part][0]
                max_age = int(max_age_part.split('=')[1])
                if max_age < 31536000:  # Less than 1 year
                    finding = Finding(
                        finding_id="HEADER-HSTS-SHORT-MAXAGE",
                        title="HSTS Header max-age Too Short",
                        module="headers",
                        url=self.config.target_url,
                        parameter="strict-transport-security",
                        severity="low",
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                        poc=f"HSTS max-age is only {max_age} seconds" if self.config.include_poc else "[REDACTED]",
                        reproduction_steps=f"1. Send a request to {self.config.target_url}\n2. Check the Strict-Transport-Security header\n3. Observe that max-age is less than 31536000 seconds (1 year)",
                        impact="A short max-age value reduces the effectiveness of HSTS protection.",
                        recommended_fix="Set max-age to at least 31536000 seconds (1 year). Example: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                        suggested_bounty="$50-$150",
                        references=[
                            "https://owasp.org/www-project-secure-headers/#strict-transport-security"
                        ]
                    )
                    findings.append(finding)
            except (ValueError, IndexError):
                finding = Finding(
                    finding_id="HEADER-HSTS-INVALID-MAXAGE",
                    title="HSTS Header Invalid max-age Value",
                    module="headers",
                    url=self.config.target_url,
                    parameter="strict-transport-security",
                    severity="medium",
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    poc=f"HSTS header has invalid max-age: {hsts_header}" if self.config.include_poc else "[REDACTED]",
                    reproduction_steps=f"1. Send a request to {self.config.target_url}\n2. Check the Strict-Transport-Security header\n3. Observe that the max-age value is invalid",
                    impact="Invalid max-age value means HSTS protection may not work correctly.",
                    recommended_fix="Fix the max-age value in the HSTS header. Example: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    suggested_bounty="$100-$300",
                    references=[
                        "https://owasp.org/www-project-secure-headers/#strict-transport-security"
                    ]
                )
                findings.append(finding)
                
        return findings
    
    def _check_csp_config(self, csp_header: str) -> List[Finding]:
        """Check CSP header configuration"""
        findings = []
        
        # Check for unsafe-inline in script-src
        if "'unsafe-inline'" in csp_header and "script-src" in csp_header:
            finding = Finding(
                finding_id="HEADER-CSP-UNSAFE-INLINE",
                title="CSP Header Allows unsafe-inline for Scripts",
                module="headers",
                url=self.config.target_url,
                parameter="content-security-policy",
                severity="high",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
                poc=f"CSP allows unsafe-inline: {csp_header}" if self.config.include_poc else "[REDACTED]",
                reproduction_steps=f"1. Send a request to {self.config.target_url}\n2. Check the Content-Security-Policy header\n3. Observe that it allows 'unsafe-inline' for scripts",
                impact="Allowing 'unsafe-inline' makes the application vulnerable to XSS attacks.",
                recommended_fix="Remove 'unsafe-inline' from script-src and use nonce or hash-based policies instead.",
                suggested_bounty="$300-$800",
                references=[
                    "https://owasp.org/www-project-secure-headers/#content-security-policy",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
                ]
            )
            findings.append(finding)
            
        # Check for unsafe-eval
        if "'unsafe-eval'" in csp_header:
            finding = Finding(
                finding_id="HEADER-CSP-UNSAFE-EVAL",
                title="CSP Header Allows unsafe-eval",
                module="headers",
                url=self.config.target_url,
                parameter="content-security-policy",
                severity="medium",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
                poc=f"CSP allows unsafe-eval: {csp_header}" if self.config.include_poc else "[REDACTED]",
                reproduction_steps=f"1. Send a request to {self.config.target_url}\n2. Check the Content-Security-Policy header\n3. Observe that it allows 'unsafe-eval'",
                impact="Allowing 'unsafe-eval' can lead to code injection vulnerabilities.",
                recommended_fix="Remove 'unsafe-eval' from the CSP policy and use safer alternatives.",
                suggested_bounty="$200-$500",
                references=[
                    "https://owasp.org/www-project-secure-headers/#content-security-policy"
                ]
            )
            findings.append(finding)
            
        return findings
    
    def _check_xfo_config(self, xfo_header: str) -> List[Finding]:
        """Check X-Frame-Options header configuration"""
        findings = []
        
        # Normalize the header value
        xfo_value = xfo_header.strip().upper()
        
        # Check for insecure values
        if xfo_value == 'ALLOW-FROM':
            finding = Finding(
                finding_id="HEADER-XFO-ALLOW-FROM",
                title="X-Frame-Options Header Uses ALLOW-FROM",
                module="headers",
                url=self.config.target_url,
                parameter="x-frame-options",
                severity="low",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
                poc=f"X-Frame-Options uses deprecated ALLOW-FROM: {xfo_header}" if self.config.include_poc else "[REDACTED]",
                reproduction_steps=f"1. Send a request to {self.config.target_url}\n2. Check the X-Frame-Options header\n3. Observe that it uses the deprecated ALLOW-FROM directive",
                impact="ALLOW-FROM is deprecated and not supported by all browsers.",
                recommended_fix="Use DENY or SAMEORIGIN instead of ALLOW-FROM. Example: X-Frame-Options: SAMEORIGIN",
                suggested_bounty="$50-$150",
                references=[
                    "https://owasp.org/www-project-secure-headers/#x-frame-options"
                ]
            )
            findings.append(finding)
            
        return findings
    
    def _check_insecure_headers(self, headers: Dict[str, Any]) -> List[Finding]:
        """Check for insecure headers that should not be present"""
        findings = []
        
        # Check for deprecated or insecure headers
        insecure_headers = {
            'x-powered-by': {
                'title': 'Server Information Disclosure via x-powered-by Header',
                'description': 'The x-powered-by header reveals server technology information that can be used by attackers.',
                'severity': 'low',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N'
            },
            'server': {
                'title': 'Server Information Disclosure via Server Header',
                'description': 'The Server header reveals server software information that can be used by attackers.',
                'severity': 'low',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N'
            },
            'x-aspnet-version': {
                'title': 'Server Information Disclosure via x-aspnet-version Header',
                'description': 'The x-aspnet-version header reveals ASP.NET version information.',
                'severity': 'low',
                'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N'
            }
        }
        
        for header_name, header_info in insecure_headers.items():
            if header_name in [h.lower() for h in headers.keys()]:
                header_value = headers.get(header_name.title()) or headers.get(header_name.upper()) or headers.get(header_name)
                finding = Finding(
                    finding_id=f"HEADER-INSECURE-{header_name.upper().replace('-', '')}",
                    title=header_info['title'],
                    module="headers",
                    url=self.config.target_url,
                    parameter=header_name,
                    severity=header_info['severity'],
                    cvss_vector=header_info['cvss_vector'],
                    poc=f"Header '{header_name}' reveals: {header_value}" if self.config.include_poc else "[REDACTED]",
                    reproduction_steps=f"1. Send a request to {self.config.target_url}\n2. Check the response headers\n3. Observe that the '{header_name}' header reveals server information",
                    impact=header_info['description'],
                    recommended_fix=f"Remove the {header_name} header from server responses.",
                    suggested_bounty="$25-$100",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://owasp.org/www-community/attacks/Server_side_infrastructure_disclosure"
                    ]
                )
                findings.append(finding)
                
        return findings