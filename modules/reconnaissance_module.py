"""
REAL Advanced Reconnaissance Module
Performs actual DNS lookups, port scanning, service detection, banner grabbing
"""

import socket
import dns.resolver
import dns.name
import dns.reversename
from colorama import Fore, Style
import sys
import os
import json
from pathlib import Path
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.utils import VulnerabilityAnalyzer

class ReconnaissanceModule:
    def __init__(self):
        self.findings = []
        self.subdomains = []
        self.open_ports = []
    
    def dns_lookup(self, domain):
        """Perform actual DNS lookups"""
        self.findings.append(f"\n=== DNS Lookups for {domain} ===")
        
        try:
            # A Records
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                ips = [str(rdata) for rdata in a_records]
                self.findings.append(f"A Records: {', '.join(ips)}")
            except:
                self.findings.append("A Records: Not found")
            
            # MX Records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                mxs = [str(rdata.exchange) for rdata in mx_records]
                self.findings.append(f"MX Records: {len(mxs)} mail servers")
            except:
                self.findings.append("MX Records: Not found")
            
            # NS Records
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                nss = [str(rdata) for rdata in ns_records]
                self.findings.append(f"NS Records: {', '.join(nss[:3])}")
            except:
                self.findings.append("NS Records: Not found")
            
            # TXT Records
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                for rdata in txt_records:
                    txt_content = str(rdata).replace('"', '')
                    self.findings.append(f"TXT: {txt_content[:60]}")
            except:
                pass
        
        except Exception as e:
            self.findings.append(f"DNS lookup error: {str(e)}")
    
    def port_scan(self, host, ports=None):
        """Perform actual port scanning"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 27017]
        
        self.findings.append(f"\n=== Port Scanning {host} ===")
        
        for port in ports:
            if VulnerabilityAnalyzer.check_port_open(host, port, timeout=1):
                service = VulnerabilityAnalyzer.detect_service(host, port)
                banner = VulnerabilityAnalyzer.banner_grab(host, port)
                
                self.open_ports.append({'port': port, 'service': service, 'banner': banner})
                self.findings.append(f"✓ {port}/tcp: {service} OPEN")
                if banner:
                    self.findings.append(f"  Banner: {banner[:60]}")
    
    def subdomain_enum(self, domain):
        """Enumerate common subdomains"""
        self.findings.append(f"\n=== Subdomain Enumeration for {domain} ===")
        
        common_subdomains = [
            'www', 'mail', 'ftp', 'api', 'admin', 'staging', 'dev', 'test',
            'cdn', 'db', 'server', 'app', 'blog', 'shop', 'support', 'example'
        ]
        
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                self.subdomains.append({'name': subdomain, 'ip': ip})
                self.findings.append(f"✓ {subdomain}: {ip}")
            except socket.gaierror:
                pass
    
    def reverse_dns(self, ip):
        """Perform reverse DNS lookup"""
        self.findings.append(f"\n=== Reverse DNS for {ip} ===")
        
        try:
            reverse_name = dns.reversename.from_address(ip)
            hostname = dns.resolver.resolve(reverse_name, "PTR")
            self.findings.append(f"Hostname: {hostname[0]}")
        except:
            self.findings.append("Reverse DNS: Not available")
    
    def check_http_methods(self, host, port=80):
        """Check allowed HTTP methods"""
        import requests
        
        self.findings.append(f"\n=== HTTP Methods Analysis {host}:{port} ===")
        
        try:
            url = f"http://{host}:{port}/"
            response = requests.options(url, timeout=2, verify=False)
            allowed = response.headers.get('Allow', 'Unknown')
            self.findings.append(f"Allowed methods: {allowed}")
        except:
            self.findings.append("Could not determine allowed methods")
    
    def technology_detection(self, host, port=80):
        """Detect web technologies"""
        import requests
        
        self.findings.append(f"\n=== Technology Detection {host}:{port} ===")
        
        try:
            url = f"http://{host}:{port}/"
            response = requests.get(url, timeout=2, verify=False)
            
            server = response.headers.get('Server', 'Unknown')
            self.findings.append(f"Server: {server}")
            
            # Check for common technologies
            if 'X-Powered-By' in response.headers:
                self.findings.append(f"Powered by: {response.headers['X-Powered-By']}")
            
            if 'wordpress' in response.text.lower():
                self.findings.append("Technology: WordPress detected")
            if 'joomla' in response.text.lower():
                self.findings.append("Technology: Joomla detected")
        
        except:
            pass
    
    def generate_report(self):
        """Generate reconnaissance report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'module': 'Advanced Reconnaissance',
            'findings': len(self.findings),
            'subdomains_found': len(self.subdomains),
            'ports_open': len(self.open_ports),
            'details': self.findings
        }
        
        return report
    
    def run(self, host=None):
        """Main execution"""
        print(Fore.CYAN + "\n╔════════════════════════════════════════════════════╗" + Style.RESET_ALL)
        print(Fore.CYAN + "║     ADVANCED RECONNAISSANCE MODULE                   ║" + Style.RESET_ALL)
        print(Fore.CYAN + "╚════════════════════════════════════════════════════╝\n" + Style.RESET_ALL)
        
        if not host:
            host = input(Fore.YELLOW + "Enter target domain/host: " + Style.RESET_ALL)
        
        print(f"\n{Fore.CYAN}Starting reconnaissance on: {Fore.YELLOW}{host}{Style.RESET_ALL}")
        
        # Check if it's a domain or IP
        try:
            socket.inet_aton(host)
            ip = host
        except socket.error:
            try:
                ip = socket.gethostbyname(host)
                self.findings.append(f"Resolved {host} to {ip}")
            except:
                ip = None
        
        # Perform reconnaissance
        if host and '.' in host and not host[0].isdigit():
            self.dns_lookup(host)
            self.subdomain_enum(host)
        
        if ip:
            self.port_scan(ip)
            self.reverse_dns(ip)
            self.check_http_methods(ip)
            self.technology_detection(ip)
        
        # Display findings
        report = self.generate_report()
        
        print("\n" + "="*60)
        print("RECONNAISSANCE FINDINGS")
        print("="*60 + "\n")
        
        for finding in self.findings:
            print(Fore.GREEN + finding + Style.RESET_ALL)
        
        print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(f"  Total findings: {report['findings']}")
        print(f"  Subdomains found: {report['subdomains_found']}")
        print(f"  Open ports: {report['ports_open']}")
        
        return report

def main():
    import argparse
    parser = argparse.ArgumentParser(description='SHODAN VulnScopeX - Reconnaissance | Usage: reconnaissance_module.py -t <host> | reconnaissance_module.py --help')
    parser.add_argument('-t', '--target', '--host', dest='target', help='Target domain or IP')
    parser.add_argument('--dns', action='store_true', help='DNS lookups only')
    parser.add_argument('--ports', action='store_true', help='Port scan only')
    parser.add_argument('--version', action='version', version='%(prog)s v6.0')
    args = parser.parse_args()
    module = ReconnaissanceModule()
    module.run(host=args.target)

if __name__ == "__main__":
    main()
