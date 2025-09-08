#!/usr/bin/env python3
"""
Odoo Security Test Suite
========================

A comprehensive automated security testing framework for Odoo web servers.
Designed for DevOps engineers to identify and mitigate common security vulnerabilities
in Odoo deployments with PostgreSQL backend and Nginx reverse proxy.

Author: AI Security Engineer
Version: 1.0
Target: Odoo Web Server Security Assessment
Environment: Linux-based server with administrative privileges

Dependencies:
    pip install requests psutil

Usage:
    python3 security_tests_odoo.py --target http://your-odoo-server.com
    python3 security_tests_odoo.py --target https://odoo.example.com --auto-remediate
"""

import unittest
import requests
import ssl
import socket
import subprocess
import logging
import json
import time
import os
import shutil
import argparse
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Tuple, Optional
import http.client
import re

# Configure logging for DevOps auditing
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_test_odoo.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class OdooSecurityConfig:
    """Configuration class for Odoo security testing parameters"""
    
    def __init__(self, base_url: str = "http://example.com"):
        self.base_url = base_url.rstrip('/')
        self.login_endpoint = "/web/login"
        self.database_endpoint = "/web/database/selector"
        self.session_endpoint = "/web/session/authenticate"
        self.admin_endpoint = "/web"
        
        # Common Odoo endpoints for testing
        self.test_endpoints = [
            "/web/login",
            "/web/database/selector", 
            "/web/session/authenticate",
            "/web/webclient/version_info",
            "/web/static/src/js/boot.js",
            "/web/dataset/call_kw"
        ]
        
        # Nginx configuration paths (common Odoo deployment patterns)
        self.nginx_config_paths = [
            "/etc/nginx/sites-available/odoo",
            "/etc/nginx/sites-enabled/odoo",
            "/etc/nginx/conf.d/odoo.conf"
        ]
        
        # Backup directory for configuration changes
        self.backup_dir = Path("/tmp/odoo_security_backups")
        self.backup_dir.mkdir(exist_ok=True)

class OdooSecurityTestSuite(unittest.TestCase):
    """Main test suite for Odoo security vulnerabilities"""
    
    @classmethod
    def setUpClass(cls):
        """Initialize test suite with configuration"""
        cls.config = OdooSecurityConfig(getattr(cls, 'target_url', 'http://example.com'))
        cls.session = requests.Session()
        cls.session.timeout = 10
        cls.remediation_actions = []
        
        logger.info(f"Starting Odoo Security Test Suite for: {cls.config.base_url}")
        logger.info(f"Test endpoints: {cls.config.test_endpoints}")
    
    def setUp(self):
        """Setup for each individual test"""
        self.test_results = {}
        
    def test_01_server_information_disclosure(self):
        """Test for sensitive server information exposure in Odoo"""
        logger.info("Testing for server information disclosure...")
        
        vulnerabilities = []
        
        try:
            # Test version info endpoint
            version_url = urljoin(self.config.base_url, "/web/webclient/version_info")
            response = self.session.get(version_url)
            
            if response.status_code == 200:
                try:
                    version_data = response.json()
                    if 'server_version' in version_data:
                        vulnerabilities.append({
                            'type': 'Version Disclosure',
                            'endpoint': version_url,
                            'details': f"Server version exposed: {version_data.get('server_version')}",
                            'severity': 'Medium'
                        })
                except json.JSONDecodeError:
                    pass
            
            # Check HTTP headers for information disclosure
            for endpoint in self.config.test_endpoints:
                url = urljoin(self.config.base_url, endpoint)
                try:
                    response = self.session.head(url)
                    headers_to_check = ['Server', 'X-Powered-By', 'X-AspNet-Version']
                    
                    for header in headers_to_check:
                        if header in response.headers:
                            vulnerabilities.append({
                                'type': 'Header Information Disclosure',
                                'endpoint': url,
                                'details': f"{header}: {response.headers[header]}",
                                'severity': 'Low'
                            })
                except requests.RequestException:
                    continue
            
            self.test_results['information_disclosure'] = vulnerabilities
            
            if vulnerabilities:
                logger.warning(f"Found {len(vulnerabilities)} information disclosure issues")
                for vuln in vulnerabilities:
                    logger.warning(f"  - {vuln['type']}: {vuln['details']}")
            else:
                logger.info("No information disclosure vulnerabilities found")
                
        except Exception as e:
            logger.error(f"Error testing information disclosure: {e}")
            self.fail(f"Information disclosure test failed: {e}")
    
    def test_02_sql_injection_detection(self):
        """Test for SQL injection vulnerabilities in Odoo endpoints"""
        logger.info("Testing for SQL injection vulnerabilities...")
        
        vulnerabilities = []
        
        # SQL injection payloads specific to PostgreSQL (Odoo's database)
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE res_users; --",
            "' UNION SELECT version(); --",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
            "' OR 1=1 LIMIT 1 OFFSET 1 --"
        ]
        
        # Test login endpoint for SQL injection
        login_url = urljoin(self.config.base_url, self.config.login_endpoint)
        
        for payload in sql_payloads:
            try:
                # Test in login form
                login_data = {
                    'login': payload,
                    'password': 'test',
                    'db': payload
                }
                
                response = self.session.post(login_url, data=login_data, allow_redirects=False)
                
                # Check for SQL error indicators
                sql_errors = [
                    'postgresql',
                    'syntax error',
                    'unterminated quoted string',
                    'pg_',
                    'psycopg2',
                    'relation does not exist'
                ]
                
                response_text = response.text.lower()
                for error in sql_errors:
                    if error in response_text:
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'endpoint': login_url,
                            'payload': payload,
                            'details': f"SQL error detected with payload: {payload}",
                            'severity': 'Critical'
                        })
                        break
                        
            except requests.RequestException as e:
                logger.debug(f"Request failed for payload {payload}: {e}")
                continue
        
        # Test database selector endpoint
        db_url = urljoin(self.config.base_url, self.config.database_endpoint)
        for payload in sql_payloads[:3]:  # Test fewer payloads for performance
            try:
                params = {'db': payload}
                response = self.session.get(db_url, params=params)
                
                if any(error in response.text.lower() for error in ['postgresql', 'syntax error', 'pg_']):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'endpoint': db_url,
                        'payload': payload,
                        'details': f"Database selector vulnerable to SQL injection",
                        'severity': 'Critical'
                    })
                    
            except requests.RequestException:
                continue
        
        self.test_results['sql_injection'] = vulnerabilities
        
        if vulnerabilities:
            logger.error(f"CRITICAL: Found {len(vulnerabilities)} SQL injection vulnerabilities!")
            for vuln in vulnerabilities:
                logger.error(f"  - {vuln['endpoint']}: {vuln['details']}")
        else:
            logger.info("No SQL injection vulnerabilities detected")
    
    def test_03_xss_detection(self):
        """Test for Cross-Site Scripting (XSS) vulnerabilities"""
        logger.info("Testing for XSS vulnerabilities...")
        
        vulnerabilities = []
        
        # XSS payloads for testing
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert('XSS');//",
            "<svg onload=alert('XSS')>"
        ]
        
        # Test login form for reflected XSS
        login_url = urljoin(self.config.base_url, self.config.login_endpoint)
        
        for payload in xss_payloads:
            try:
                # Test in various form fields
                test_data = {
                    'login': payload,
                    'password': 'test',
                    'redirect': payload
                }
                
                response = self.session.post(login_url, data=test_data)
                
                # Check if payload is reflected in response
                if payload in response.text and 'text/html' in response.headers.get('content-type', ''):
                    vulnerabilities.append({
                        'type': 'Reflected XSS',
                        'endpoint': login_url,
                        'payload': payload,
                        'details': f"XSS payload reflected in response",
                        'severity': 'High'
                    })
                    
            except requests.RequestException:
                continue
        
        # Test error pages for XSS
        error_endpoints = [
            "/web/nonexistent",
            "/web/database/nonexistent"
        ]
        
        for endpoint in error_endpoints:
            url = urljoin(self.config.base_url, endpoint)
            for payload in xss_payloads[:2]:  # Test fewer for performance
                try:
                    response = self.session.get(f"{url}?error={payload}")
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'Reflected XSS',
                            'endpoint': url,
                            'payload': payload,
                            'details': f"XSS in error page",
                            'severity': 'High'
                        })
                except requests.RequestException:
                    continue
        
        self.test_results['xss'] = vulnerabilities
        
        if vulnerabilities:
            logger.warning(f"Found {len(vulnerabilities)} XSS vulnerabilities")
            for vuln in vulnerabilities:
                logger.warning(f"  - {vuln['type']} at {vuln['endpoint']}")
        else:
            logger.info("No XSS vulnerabilities detected")
    
    def test_04_insecure_http_headers(self):
        """Test for missing or insecure HTTP security headers"""
        logger.info("Testing HTTP security headers...")
        
        missing_headers = []
        insecure_headers = []
        
        # Required security headers for Odoo
        required_headers = {
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-Content-Type-Options': ['nosniff'],
            'X-XSS-Protection': ['1; mode=block'],
            'Strict-Transport-Security': None,  # For HTTPS only
            'Content-Security-Policy': None,
            'Referrer-Policy': ['strict-origin-when-cross-origin', 'strict-origin']
        }
        
        try:
            response = self.session.get(urljoin(self.config.base_url, self.config.login_endpoint))
            headers = response.headers
            
            for header, expected_values in required_headers.items():
                if header not in headers:
                    missing_headers.append({
                        'header': header,
                        'severity': 'Medium',
                        'recommendation': f"Add {header} header to Nginx configuration"
                    })
                elif expected_values and headers[header] not in expected_values:
                    insecure_headers.append({
                        'header': header,
                        'current_value': headers[header],
                        'expected_values': expected_values,
                        'severity': 'Medium'
                    })
            
            # Check for insecure cookie attributes
            set_cookie_headers = response.headers.get_list('Set-Cookie') if hasattr(response.headers, 'get_list') else []
            if 'Set-Cookie' in response.headers:
                set_cookie_headers = [response.headers['Set-Cookie']]
            
            for cookie in set_cookie_headers:
                if 'Secure' not in cookie and self.config.base_url.startswith('https'):
                    insecure_headers.append({
                        'header': 'Set-Cookie',
                        'issue': 'Missing Secure flag',
                        'severity': 'Medium'
                    })
                if 'HttpOnly' not in cookie:
                    insecure_headers.append({
                        'header': 'Set-Cookie', 
                        'issue': 'Missing HttpOnly flag',
                        'severity': 'Medium'
                    })
                if 'SameSite' not in cookie:
                    insecure_headers.append({
                        'header': 'Set-Cookie',
                        'issue': 'Missing SameSite attribute',
                        'severity': 'Low'
                    })
            
        except requests.RequestException as e:
            logger.error(f"Failed to test HTTP headers: {e}")
            self.fail(f"HTTP headers test failed: {e}")
        
        self.test_results['missing_headers'] = missing_headers
        self.test_results['insecure_headers'] = insecure_headers
        
        total_issues = len(missing_headers) + len(insecure_headers)
        if total_issues > 0:
            logger.warning(f"Found {total_issues} HTTP header security issues")
            for header in missing_headers:
                logger.warning(f"  - Missing: {header['header']}")
            for header in insecure_headers:
                logger.warning(f"  - Insecure: {header['header']}")
        else:
            logger.info("All HTTP security headers are properly configured")
    
    def test_05_ssl_tls_configuration(self):
        """Test SSL/TLS configuration security"""
        logger.info("Testing SSL/TLS configuration...")
        
        if not self.config.base_url.startswith('https'):
            logger.info("Skipping SSL/TLS tests - HTTP endpoint detected")
            self.test_results['ssl_tls'] = {'skipped': 'HTTP endpoint'}
            return
        
        vulnerabilities = []
        parsed_url = urlparse(self.config.base_url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        
        try:
            # Test SSL/TLS connection
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate info
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check TLS version
                    if version in ['TLSv1', 'TLSv1.1']:
                        vulnerabilities.append({
                            'type': 'Weak TLS Version',
                            'details': f"Using {version} - should use TLSv1.2 or higher",
                            'severity': 'High'
                        })
                    
                    # Check cipher strength
                    if cipher and len(cipher) >= 3:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name.upper() for weak in ['RC4', 'DES', 'MD5', 'NULL']):
                            vulnerabilities.append({
                                'type': 'Weak Cipher',
                                'details': f"Weak cipher detected: {cipher_name}",
                                'severity': 'High'
                            })
                    
                    # Check certificate validity
                    if cert:
                        import datetime
                        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (not_after - datetime.datetime.now()).days
                        
                        if days_until_expiry < 30:
                            vulnerabilities.append({
                                'type': 'Certificate Expiry',
                                'details': f"Certificate expires in {days_until_expiry} days",
                                'severity': 'Medium' if days_until_expiry > 7 else 'High'
                            })
            
            # Test for SSL/TLS vulnerabilities using external check
            try:
                # Simple check for common SSL issues
                weak_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                weak_context.set_ciphers('ALL:@SECLEVEL=0')
                weak_context.check_hostname = False
                weak_context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with weak_context.wrap_socket(sock) as ssock:
                        if ssock.version() in ['TLSv1', 'TLSv1.1']:
                            vulnerabilities.append({
                                'type': 'SSL/TLS Misconfiguration',
                                'details': 'Server accepts weak TLS versions',
                                'severity': 'High'
                            })
            except:
                pass  # Expected if server properly rejects weak connections
                
        except Exception as e:
            logger.error(f"SSL/TLS testing failed: {e}")
            vulnerabilities.append({
                'type': 'SSL/TLS Test Error',
                'details': str(e),
                'severity': 'Unknown'
            })
        
        self.test_results['ssl_tls'] = vulnerabilities
        
        if vulnerabilities:
            logger.warning(f"Found {len(vulnerabilities)} SSL/TLS issues")
            for vuln in vulnerabilities:
                logger.warning(f"  - {vuln['type']}: {vuln['details']}")
        else:
            logger.info("SSL/TLS configuration appears secure")
    
    def test_06_authentication_security(self):
        """Test authentication mechanisms and security"""
        logger.info("Testing authentication security...")
        
        vulnerabilities = []
        login_url = urljoin(self.config.base_url, self.config.login_endpoint)
        
        try:
            # Test for account lockout mechanism
            failed_attempts = 0
            for i in range(10):  # Try 10 failed login attempts
                login_data = {
                    'login': 'admin',
                    'password': f'wrongpassword{i}',
                    'db': 'test'
                }
                
                response = self.session.post(login_url, data=login_data)
                
                if 'locked' in response.text.lower() or 'blocked' in response.text.lower():
                    logger.info(f"Account lockout detected after {i+1} attempts")
                    break
                elif response.status_code == 200:
                    failed_attempts += 1
            
            if failed_attempts >= 10:
                vulnerabilities.append({
                    'type': 'No Account Lockout',
                    'details': 'No account lockout mechanism detected after 10 failed attempts',
                    'severity': 'Medium'
                })
            
            # Test for weak password policy (if we can create accounts)
            # This would require admin access, so we'll check for common indicators
            
            # Test session management
            initial_response = self.session.get(login_url)
            cookies_before = self.session.cookies.copy()
            
            # Make another request
            second_response = self.session.get(login_url)
            cookies_after = self.session.cookies.copy()
            
            # Check if session ID changes (good practice)
            session_cookies = [c for c in cookies_before if 'session' in c.name.lower()]
            if session_cookies:
                session_cookie = session_cookies[0]
                if session_cookie.name in cookies_after and cookies_before[session_cookie.name] == cookies_after[session_cookie.name]:
                    vulnerabilities.append({
                        'type': 'Static Session ID',
                        'details': 'Session ID does not change between requests',
                        'severity': 'Low'
                    })
            
            # Test for session fixation
            # This is complex to test automatically, so we'll check for basic indicators
            
        except Exception as e:
            logger.error(f"Authentication testing failed: {e}")
            vulnerabilities.append({
                'type': 'Authentication Test Error',
                'details': str(e),
                'severity': 'Unknown'
            })
        
        self.test_results['authentication'] = vulnerabilities
        
        if vulnerabilities:
            logger.warning(f"Found {len(vulnerabilities)} authentication security issues")
            for vuln in vulnerabilities:
                logger.warning(f"  - {vuln['type']}: {vuln['details']}")
        else:
            logger.info("Authentication security appears adequate")
    
    def remediate_http_headers(self):
        """Automatically remediate HTTP header security issues"""
        logger.info("Starting automated HTTP header remediation...")
        
        if 'missing_headers' not in self.test_results and 'insecure_headers' not in self.test_results:
            logger.info("No HTTP header issues to remediate")
            return
        
        # Find Nginx configuration file
        nginx_config_path = None
        for path in self.config.nginx_config_paths:
            if os.path.exists(path):
                nginx_config_path = path
                break
        
        if not nginx_config_path:
            logger.error("Could not find Nginx configuration file for Odoo")
            return
        
        try:
            # Create backup
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.config.backup_dir / f"nginx_odoo_backup_{timestamp}.conf"
            shutil.copy2(nginx_config_path, backup_path)
            logger.info(f"Created backup: {backup_path}")
            
            # Read current configuration
            with open(nginx_config_path, 'r') as f:
                config_content = f.read()
            
            # Add security headers
            security_headers = """
    # Security headers added by Odoo Security Test Suite
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'self';" always;
"""
            
            # Add HSTS for HTTPS
            if self.config.base_url.startswith('https'):
                security_headers += '    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n'
            
            # Find the server block and add headers
            if 'add_header X-Frame-Options' not in config_content:
                # Look for the location / block or server block
                if 'location / {' in config_content:
                    config_content = config_content.replace(
                        'location / {',
                        f'location / {{\n{security_headers}'
                    )
                elif 'server {' in config_content:
                    # Add after server { line
                    config_content = config_content.replace(
                        'server {',
                        f'server {{\n{security_headers}'
                    )
                
                # Write updated configuration
                with open(nginx_config_path, 'w') as f:
                    f.write(config_content)
                
                # Test Nginx configuration
                test_result = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
                if test_result.returncode == 0:
                    # Reload Nginx
                    reload_result = subprocess.run(['systemctl', 'reload', 'nginx'], capture_output=True, text=True)
                    if reload_result.returncode == 0:
                        logger.info("Successfully applied HTTP security headers")
                        self.remediation_actions.append({
                            'action': 'HTTP Headers Remediation',
                            'status': 'Success',
                            'backup': str(backup_path)
                        })
                    else:
                        logger.error(f"Failed to reload Nginx: {reload_result.stderr}")
                        # Restore backup
                        shutil.copy2(backup_path, nginx_config_path)
                else:
                    logger.error(f"Nginx configuration test failed: {test_result.stderr}")
                    # Restore backup
                    shutil.copy2(backup_path, nginx_config_path)
            else:
                logger.info("Security headers already present in Nginx configuration")
                
        except Exception as e:
            logger.error(f"Failed to remediate HTTP headers: {e}")
            # Restore backup if it exists
            if 'backup_path' in locals() and backup_path.exists():
                shutil.copy2(backup_path, nginx_config_path)
    
    @classmethod
    def tearDownClass(cls):
        """Generate final security report"""
        logger.info("Generating security assessment report...")
        
        # Compile all test results
        all_results = {}
        for test_instance in cls._get_test_instances():
            if hasattr(test_instance, 'test_results'):
                all_results.update(test_instance.test_results)
        
        # Generate report
        report = {
            'timestamp': datetime.now().isoformat(),
            'target': cls.config.base_url,
            'test_results': all_results,
            'remediation_actions': getattr(cls, 'remediation_actions', []),
            'summary': cls._generate_summary(all_results)
        }
        
        # Save report to file
        report_file = f"odoo_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Security report saved to: {report_file}")
        
        # Print summary
        cls._print_summary(report['summary'])
    
    @classmethod
    def _get_test_instances(cls):
        """Helper to get test instances (simplified for this implementation)"""
        return [cls()]
    
    @classmethod
    def _generate_summary(cls, results: Dict) -> Dict:
        """Generate summary statistics"""
        summary = {
            'total_vulnerabilities': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'categories': {}
        }
        
        for category, issues in results.items():
            if isinstance(issues, list):
                summary['categories'][category] = len(issues)
                summary['total_vulnerabilities'] += len(issues)
                
                for issue in issues:
                    severity = issue.get('severity', 'Unknown').lower()
                    if severity in summary:
                        summary[severity] += 1
        
        return summary
    
    @classmethod
    def _print_summary(cls, summary: Dict):
        """Print formatted summary to console"""
        print("\n" + "="*60)
        print("ODOO SECURITY ASSESSMENT SUMMARY")
        print("="*60)
        print(f"Total Vulnerabilities Found: {summary['total_vulnerabilities']}")
        print(f"Critical: {summary['critical']}")
        print(f"High: {summary['high']}")
        print(f"Medium: {summary['medium']}")
        print(f"Low: {summary['low']}")
        print("\nVulnerabilities by Category:")
        for category, count in summary['categories'].items():
            print(f"  {category}: {count}")
        print("="*60)

def main():
    """Main execution function with command line argument parsing"""
    parser = argparse.ArgumentParser(description='Odoo Security Test Suite')
    parser.add_argument('--target', default='http://example.com', 
                       help='Target Odoo server URL (default: http://example.com)')
    parser.add_argument('--auto-remediate', action='store_true',
                       help='Automatically remediate fixable security issues')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Set target URL for test suite
    OdooSecurityTestSuite.target_url = args.target
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(OdooSecurityTestSuite)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)
    
    # Perform auto-remediation if requested
    if args.auto_remediate:
        logger.info("Starting automated remediation...")
        test_instance = OdooSecurityTestSuite()
        test_instance.config = OdooSecurityConfig(args.target)
        test_instance.remediate_http_headers()
    
    # Print recommendations
    print_recommendations()
    
    return 0 if result.wasSuccessful() else 1

def print_recommendations():
    """Print actionable security recommendations for DevOps engineers"""
    print("\n" + "="*60)
    print("SECURITY RECOMMENDATIONS FOR ODOO DEVOPS")
    print("="*60)
    
    recommendations = [
        {
            'category': 'SQL Injection Prevention',
            'actions': [
                'Ensure Odoo is updated to the latest version',
                'Review custom modules for SQL injection vulnerabilities',
                'Implement input validation in custom code',
                'Use Odoo ORM methods instead of raw SQL queries',
                'Configure PostgreSQL with restricted user permissions'
            ]
        },
        {
            'category': 'XSS Prevention',
            'actions': [
                'Sanitize user inputs in custom modules',
                'Use Odoo\'s built-in templating security features',
                'Implement Content Security Policy headers',
                'Validate and escape output in custom views'
            ]
        },
        {
            'category': 'HTTP Security Headers',
            'actions': [
                'Configure Nginx with security headers (automated by this script)',
                'Enable HSTS for HTTPS deployments',
                'Set secure cookie attributes',
                'Implement proper CORS policies'
            ]
        },
        {
            'category': 'SSL/TLS Security',
            'actions': [
                'Use TLS 1.2 or higher',
                'Disable weak ciphers and protocols',
                'Implement certificate monitoring',
                'Use strong cipher suites'
            ]
        },
        {
            'category': 'Authentication Security',
            'actions': [
                'Implement account lockout policies',
                'Enforce strong password requirements',
                'Enable two-factor authentication',
                'Monitor failed login attempts',
                'Implement session timeout policies'
            ]
        },
        {
            'category': 'General Odoo Security',
            'actions': [
                'Regularly update Odoo and modules',
                'Restrict database access to localhost only',
                'Disable unnecessary Odoo modules',
                'Implement proper backup encryption',
                'Monitor system logs for suspicious activity',
                'Use fail2ban for brute force protection'
            ]
        }
    ]
    
    for rec in recommendations:
        print(f"\n{rec['category']}:")
        for action in rec['actions']:
            print(f"  • {action}")
    
    print("\n" + "="*60)
    print("For more information, refer to:")
    print("• OWASP Top 10: https://owasp.org/www-project-top-ten/")
    print("• Odoo Security Guide: https://www.odoo.com/documentation/security")
    print("• Nginx Security: https://nginx.org/en/docs/http/securing_http.html")
    print("="*60)

if __name__ == '__main__':
    sys.exit(main())
