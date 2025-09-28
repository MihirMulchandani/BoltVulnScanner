"""
TLS/SSL certificate checker module for BoltVulnScanner
"""
import logging
import ssl
import socket
from urllib.parse import urlparse
from typing import List, Dict, Optional
import datetime

from .utils import ScanConfig, Finding

logger = logging.getLogger(__name__)

class TLSChecker:
    """Check TLS certificates and configurations"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        
    def check(self) -> List[Finding]:
        """
        Check TLS certificate and configuration
        
        Returns:
            List of TLS-related findings
        """
        logger.info("Starting TLS check")
        findings = []
        
        # Parse target host
        parsed = urlparse(self.config.target_url)
        host = parsed.hostname or parsed.path
        
        if not host:
            logger.error("Could not determine target host")
            return findings
            
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        # Skip if not HTTPS
        if parsed.scheme != 'https':
            logger.info("Target is not using HTTPS, skipping TLS check")
            return findings
            
        try:
            # Get certificate
            cert = self._get_certificate(host, port)
            if not cert:
                finding = Finding(
                    finding_id="TLS-NO-CERT",
                    title="No SSL/TLS Certificate Found",
                    module="tls",
                    url=self.config.target_url,
                    parameter="certificate",
                    severity="high",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    poc="No SSL/TLS certificate found on the server" if self.config.include_poc else "[REDACTED]",
                    reproduction_steps=f"1. Connect to {host}:{port} using SSL/TLS\n2. Observe that no certificate is presented",
                    impact="The connection is not encrypted, making it vulnerable to eavesdropping and man-in-the-middle attacks.",
                    recommended_fix="Configure a valid SSL/TLS certificate for the server.",
                    suggested_bounty="$200-$500",
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
                    ]
                )
                findings.append(finding)
                return findings
                
            # Check certificate expiration
            expiration_findings = self._check_certificate_expiration(cert, host)
            findings.extend(expiration_findings)
            
            # Check certificate validity (CN/SAN)
            validity_findings = self._check_certificate_validity(cert, host)
            findings.extend(validity_findings)
            
            # Check for weak protocols and ciphers
            protocol_findings = self._check_weak_protocols(host, port)
            findings.extend(protocol_findings)
            
        except Exception as e:
            logger.error(f"Error during TLS check: {e}")
            finding = Finding(
                finding_id="TLS-ERROR",
                title="TLS Check Error",
                module="tls",
                url=self.config.target_url,
                parameter="tls",
                severity="medium",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
                poc=f"Error during TLS check: {str(e)}" if self.config.include_poc else "[REDACTED]",
                reproduction_steps=f"1. Attempt to connect to {host}:{port} using SSL/TLS\n2. Observe the error",
                impact="Unable to verify TLS configuration, potential security issues may exist.",
                recommended_fix="Ensure the server is properly configured with valid TLS certificates and secure protocols.",
                suggested_bounty="$100-$300",
                references=[
                    "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
                ]
            )
            findings.append(finding)
            
        logger.info(f"TLS check completed. Found {len(findings)} issues")
        return findings
    
    def _get_certificate(self, host: str, port: int) -> Optional[Dict]:
        """Get SSL certificate information"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((host, port), timeout=self.config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_bin = ssock.getpeercert(True)
                    if cert_bin is None:
                        return None
                        
                    cert = ssl.DER_cert_to_PEM_cert(cert_bin)
                    
                    # Parse certificate with built-in ssl module
                    cert_dict = ssock.getpeercert()
                    
                    if not cert_dict:
                        return None
                        
                    cert_info = {
                        'subject': cert_dict.get('subject', []),
                        'issuer': cert_dict.get('issuer', []),
                        'version': cert_dict.get('version', 0),
                        'serialNumber': cert_dict.get('serialNumber', ''),
                        'notBefore': cert_dict.get('notBefore', ''),
                        'notAfter': cert_dict.get('notAfter', ''),
                        'subjectAltName': cert_dict.get('subjectAltName', [])
                    }
                    
                    # Parse dates
                    if cert_info['notBefore']:
                        cert_info['not_before'] = datetime.datetime.strptime(
                            cert_info['notBefore'], '%b %d %H:%M:%S %Y %Z'
                        )
                    if cert_info['notAfter']:
                        cert_info['not_after'] = datetime.datetime.strptime(
                            cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z'
                        )
                        
                    return cert_info
                    
        except Exception as e:
            logger.error(f"Error getting certificate for {host}:{port} - {e}")
            return None
    
    def _check_certificate_expiration(self, cert: Dict, host: str) -> List[Finding]:
        """Check certificate expiration"""
        findings = []
        
        not_before = cert.get('not_before')
        not_after = cert.get('not_after')
        
        if not not_before or not not_after:
            return findings
            
        now = datetime.datetime.utcnow()
        
        # Check if certificate is expired
        if not_after < now:
            days_expired = (now - not_after).days
            finding = Finding(
                finding_id="TLS-EXPIRED",
                title="SSL/TLS Certificate Expired",
                module="tls",
                url=self.config.target_url,
                parameter="certificate",
                severity="high",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                poc=f"Certificate expired {days_expired} days ago" if self.config.include_poc else "[REDACTED]",
                reproduction_steps=f"1. Connect to {host} using SSL/TLS\n2. Check certificate expiration date\n3. Observe that it expired on {not_after}",
                impact="Expired certificates cannot be trusted and may expose users to man-in-the-middle attacks.",
                recommended_fix="Renew the SSL/TLS certificate immediately.",
                suggested_bounty="$300-$800",
                references=[
                    "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
                ]
            )
            findings.append(finding)
            
        # Check if certificate is about to expire (within 30 days)
        elif (not_after - now).days <= 30:
            days_until_expiry = (not_after - now).days
            finding = Finding(
                finding_id="TLS-EXPIRING",
                title="SSL/TLS Certificate Expiring Soon",
                module="tls",
                url=self.config.target_url,
                parameter="certificate",
                severity="medium",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
                poc=f"Certificate expires in {days_until_expiry} days" if self.config.include_poc else "[REDACTED]",
                reproduction_steps=f"1. Connect to {host} using SSL/TLS\n2. Check certificate expiration date\n3. Observe that it expires on {not_after}",
                impact="The certificate will expire soon, potentially causing service disruption.",
                recommended_fix="Renew the SSL/TLS certificate before it expires.",
                suggested_bounty="$100-$300",
                references=[
                    "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
                ]
            )
            findings.append(finding)
            
        return findings
    
    def _check_certificate_validity(self, cert: Dict, host: str) -> List[Finding]:
        """Check certificate validity (CN/SAN)"""
        findings = []
        
        # Get subject information
        subject = cert.get('subject', [])
        common_name = None
        
        # Extract common name from subject
        for item in subject:
            for sub_item in item:
                if sub_item[0] == 'commonName':
                    common_name = sub_item[1]
                    break
            if common_name:
                break
                
        # Check subject alternative names
        subject_alt_names = cert.get('subjectAltName', [])
        
        # Check if host matches CN or SAN
        host_matches = False
        
        if common_name:
            # Simple wildcard matching
            if common_name.startswith('*.'):
                domain = common_name[2:]
                if host.endswith(domain) or host == domain:
                    host_matches = True
            elif common_name == host:
                host_matches = True
                
        # Check SAN
        if not host_matches:
            for san_type, san_value in subject_alt_names:
                if san_type == 'DNS':
                    # Simple wildcard matching
                    if san_value.startswith('*.'):
                        domain = san_value[2:]
                        if host.endswith(domain) or host == domain:
                            host_matches = True
                            break
                    elif san_value == host:
                        host_matches = True
                        break
                        
        if not host_matches:
            finding = Finding(
                finding_id="TLS-HOST-MISMATCH",
                title="SSL/TLS Certificate Hostname Mismatch",
                module="tls",
                url=self.config.target_url,
                parameter="certificate",
                severity="high",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                poc=f"Certificate issued for {common_name}, accessed as {host}" if self.config.include_poc else "[REDACTED]",
                reproduction_steps=f"1. Connect to {host} using SSL/TLS\n2. Check certificate subject\n3. Observe mismatch between certificate and accessed hostname",
                impact="Users may receive certificate warnings, and the connection may be vulnerable to man-in-the-middle attacks.",
                recommended_fix="Obtain a certificate that matches the hostname or configure the server to use the correct certificate.",
                suggested_bounty="$300-$800",
                references=[
                    "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
                ]
            )
            findings.append(finding)
            
        return findings
    
    def _check_weak_protocols(self, host: str, port: int) -> List[Finding]:
        """Check for weak SSL/TLS protocols and ciphers"""
        findings = []
        
        # Try to connect with weak protocols if supported
        try:
            # Try TLS 1.0
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # If we can connect, it means TLS 1.0 is supported
                    finding = Finding(
                        finding_id="TLS-WEAK-PROTOCOL-TLS10",
                        title="Weak SSL/TLS Protocol Supported: TLS 1.0",
                        module="tls",
                        url=self.config.target_url,
                        parameter="protocol",
                        severity="medium",
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        poc="Server supports deprecated TLS 1.0" if self.config.include_poc else "[REDACTED]",
                        reproduction_steps=f"1. Connect to {host}:{port} using TLS 1.0\n2. Observe successful connection",
                        impact="Using deprecated TLS 1.0 makes the connection vulnerable to known attacks.",
                        recommended_fix="Disable TLS 1.0 and use only TLS 1.2 or higher.",
                        suggested_bounty="$200-$500",
                        references=[
                            "https://www.schneier.com/academic/paperfiles/paper-ssl.pdf",
                            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
                        ]
                    )
                    findings.append(finding)
                    
        except Exception:
            # TLS 1.0 not supported, which is good
            pass
            
        try:
            # Try TLS 1.1
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # If we can connect, it means TLS 1.1 is supported
                    finding = Finding(
                        finding_id="TLS-WEAK-PROTOCOL-TLS11",
                        title="Weak SSL/TLS Protocol Supported: TLS 1.1",
                        module="tls",
                        url=self.config.target_url,
                        parameter="protocol",
                        severity="medium",
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        poc="Server supports deprecated TLS 1.1" if self.config.include_poc else "[REDACTED]",
                        reproduction_steps=f"1. Connect to {host}:{port} using TLS 1.1\n2. Observe successful connection",
                        impact="Using deprecated TLS 1.1 makes the connection vulnerable to known attacks.",
                        recommended_fix="Disable TLS 1.1 and use only TLS 1.2 or higher.",
                        suggested_bounty="$200-$500",
                        references=[
                            "https://www.schneier.com/academic/paperfiles/paper-ssl.pdf",
                            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
                        ]
                    )
                    findings.append(finding)
                    
        except Exception:
            # TLS 1.1 not supported, which is good
            pass
                
        return findings