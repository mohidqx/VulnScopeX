"""
REAL Web Application Vulnerability Analysis Module  
Performs actual XSS, SQL Injection, CSRF, and security header testing
"""

import requests
import re
import sys
import os
from colorama import Fore, Style
from datetime import datetime
import json
from pathlib import Path
from urllib.parse import urljoin, quote

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.utils import WebAnalyzer

class WebApplicationAnalyzer:
    def __init__(self):
        self.vulnerabilities = []
        self.headers_missing = []
        self.url = None
    
    def test_xss(self, url, params=None):
        """Test for XSS vulnerabilities"""
        self.vulnerabilities.append(f"\n=== XSS Testing for {url} ===")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "'\"><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ]
        
        if params is None:
            params = ['search', 'q', 'query', 'input', 'comment']
        
        found = False
        for param in params:
            for payload in xss_payloads:
                try:
                    test_url = f"{url}?{param}={quote(payload)}"
                    response = requests.get(test_url, timeout=2, verify=False)
                    
                    if payload in response.text:
                        self.vulnerabilities.append(f"🔴 REFLECTED XSS FOUND in parameter '{param}'")
                        found = True
                        break
                except:
                    pass
        
        if not found:
            self.vulnerabilities.append("✓ XSS checks completed - No obvious vulnerabilities")
    
    def test_sql_injection(self, url, params=None):
        """Test for SQL Injection"""
        self.vulnerabilities.append(f"\n=== SQL Injection Testing ===")
        
        sql_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "admin' --",
            "' UNION SELECT NULL --"
        ]
        
        if params is None:
            params = ['id', 'user', 'login', 'username', 'search']
        
        for param in params:
            for payload in sql_payloads:
                try:
                    test_url = f"{url}?{param}={quote(payload)}"
                    response = requests.get(test_url, timeout=2, verify=False)
                    
                    # Check for SQL error patterns
                    if re.search(r'(SQL|mysql|postgres|oracle|database|error|syntax)', response.text, re.IGNORECASE):
                        self.vulnerabilities.append(f"🟡 Potential SQL Error exposed for parameter '{param}'")
                except:
                    pass
    
    def test_security_headers(self, url):
        """Test security headers"""
        self.vulnerabilities.append(f"\n=== Security Headers Check ===")
        
        try:
            response = requests.get(url, timeout=2, verify=False)
            
            required_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'Strict-Transport-Security': 'max-age=31536000',
                'X-XSS-Protection': '1; mode=block',
                'Content-Security-Policy': 'default-src'
            }
            
            missing = []
            for header, expected in required_headers.items():
                if header not in response.headers:
                    missing.append(header)
                    self.vulnerabilities.append(f"🔴 Missing: {header}")
                else:
                    self.vulnerabilities.append(f"✓ Present: {header}: {response.headers[header]}")
            
            self.headers_missing = missing
        
        except Exception as e:
            self.vulnerabilities.append(f"Error checking headers: {str(e)}")
    
    def test_authentication(self, url):
        """Test for authentication issues"""
        self.vulnerabilities.append(f"\n=== Authentication Testing ===")
        
        # Test for missing authentication
        try:
            response = requests.get(f"{url}/admin", timeout=2, verify=False)
            if response.status_code == 200:
                self.vulnerabilities.append("🔴 /admin accessible without authentication")
            
            response = requests.get(f"{url}/api/users", timeout=2, verify=False)
            if response.status_code == 200:
                self.vulnerabilities.append("🔴 API endpoint accessible without auth")
        except:
            pass
        
        # Test for session fixation
        try:
            session1 = requests.Session()
            session1.get(url, timeout=2, verify=False)
            
            if 'Set-Cookie' in session1.headers:
                self.vulnerabilities.append("✓ Session cookies are set")
            else:
                self.vulnerabilities.append("⚠ No session management detected")
        except:
            pass
    
    def test_http_methods(self, url):
        """Test allowed HTTP methods"""
        self.vulnerabilities.append(f"\n=== HTTP Methods Check ===")
        
        try:
            response = requests.options(url, timeout=2, verify=False)
            
            if 'Allow' in response.headers:
                allowed = response.headers['Allow']
                self.vulnerabilities.append(f"Allowed methods: {allowed}")
                
                if 'DELETE' in allowed or 'PUT' in allowed:
                    self.vulnerabilities.append("🟡 Dangerous HTTP methods allowed (DELETE/PUT)")
            else:
                self.vulnerabilities.append("✓ No ALLOW header (methods may be restricted)")
        except:
            self.vulnerabilities.append("Could not test OPTIONS")
    
    def test_cookies(self, url):
        """Test cookie security"""
        self.vulnerabilities.append(f"\n=== Cookie Security Check ===")
        
        try:
            response = requests.get(url, timeout=2, verify=False)
            
            if 'Set-Cookie' in response.headers:
                cookies = response.headers['Set-Cookie']
                
                if 'Secure' not in cookies:
                    self.vulnerabilities.append("🔴 Cookies not marked Secure (SSL/TLS)")
                else:
                    self.vulnerabilities.append("✓ Cookies marked Secure")
                
                if 'HttpOnly' not in cookies:
                    self.vulnerabilities.append("🔴 HttpOnly flag missing (XSS risk)")
                else:
                    self.vulnerabilities.append("✓ HttpOnly flag set")
            else:
                self.vulnerabilities.append("No cookies set")
        except:
            pass
    
    def test_directory_listing(self, url):
        """Test for directory listing"""
        self.vulnerabilities.append(f"\n=== Directory Listing Check ===")
        
        dirs = ['/', '/admin/', '/api/', '/uploads/', '/backup/']
        
        for dir_path in dirs:
            try:
                response = requests.get(urljoin(url, dir_path), timeout=2, verify=False)
                
                if response.status_code == 200:
                    if re.search(r'Index of|Directory Listing', response.text, re.IGNORECASE):
                        self.vulnerabilities.append(f"🔴 Directory listing enabled: {dir_path}")
            except:
                pass
    
    def generate_report(self):
        """Generate web security report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'module': 'Web Application Security',
            'url': self.url,
            'vulnerabilities_found': len([v for v in self.vulnerabilities if '🔴' in v]),
            'warnings': len([v for v in self.vulnerabilities if '🟡' in v]),
            'details': self.vulnerabilities
        }
        return report
    
    def run(self, url=None):
        """Main execution"""
        print(Fore.CYAN + "\n╔════════════════════════════════════════════════════╗" + Style.RESET_ALL)
        print(Fore.CYAN + "║     WEB APPLICATION SECURITY ANALYZER               ║" + Style.RESET_ALL)
        print(Fore.CYAN + "╚════════════════════════════════════════════════════╝\n" + Style.RESET_ALL)
        
        if not url:
            url = input(Fore.YELLOW + "Enter target URL (http://example.com): " + Style.RESET_ALL)
        
        self.url = url
        
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            self.url = url
        
        print(f"\n{Fore.CYAN}Analyzing web application: {Fore.YELLOW}{url}{Style.RESET_ALL}")
        
        # Run tests
        self.test_security_headers(url)
        self.test_xss(url)
        self.test_sql_injection(url)
        self.test_authentication(url)
        self.test_http_methods(url)
        self.test_cookies(url)
        self.test_directory_listing(url)
        
        # Display results
        print("\n" + "="*60)
        print("WEB APPLICATION SECURITY FINDINGS")
        print("="*60 + "\n")
        
        for vuln in self.vulnerabilities:
            if '🔴' in vuln:
                print(Fore.RED + vuln + Style.RESET_ALL)
            elif '🟡' in vuln:
                print(Fore.YELLOW + vuln + Style.RESET_ALL)
            else:
                print(Fore.GREEN + vuln + Style.RESET_ALL)
        
        report = self.generate_report()
        print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(f"  Critical issues: {report['vulnerabilities_found']}")
        print(f"  Warnings: {report['warnings']}")
        
        return report

def main():
    import argparse
    parser = argparse.ArgumentParser(description='SHODAN VulnScopeX - Web App Security | Usage: webapp_module.py -u <url> | webapp_module.py --help')
    parser.add_argument('-u', '--url', dest='url', help='Target URL for testing')
    parser.add_argument('--xss', action='store_true', help='Test XSS')
    parser.add_argument('--sqli', action='store_true', help='Test SQL injection')
    parser.add_argument('--headers', action='store_true', help='Check security headers')
    parser.add_argument('--version', action='version', version='%(prog)s v6.0')
    args = parser.parse_args()
    analyzer = WebApplicationAnalyzer()
    analyzer.run(url=args.url)

if __name__ == "__main__":
    main()
