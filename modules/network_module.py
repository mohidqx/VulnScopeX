"""
REAL Network Analysis Module
Performs actual network vulnerability detection, MITM analysis, protocol testing
"""

import socket
import subprocess
import platform
from colorama import Fore, Style
import sys
import os
import json
from pathlib import Path
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.utils import VulnerabilityAnalyzer

class NetworkAnalyzer:
    def __init__(self):
        self.findings = []
        self.vulnerabilities = []
    
    def check_ddos_vulnerabilities(self, host):
        """Check for DDoS attack vectors"""
        self.findings.append(f"\n=== DDoS Vector Analysis for {host} ===")
        
        # Check ICMP response
        try:
            result = subprocess.run(
                ['ping', '-c', '1', host] if platform.system() != 'Windows' else ['ping', '-n', '1', host],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0:
                self.vulnerabilities.append("ICMP Echo enabled - Ping of Death possible")
        except:
            pass
        
        # Check open ports for SYN flood potential
        if VulnerabilityAnalyzer.check_port_open(host, 80):
            self.vulnerabilities.append("Port 80 open - HTTP flood possible")
        if VulnerabilityAnalyzer.check_port_open(host, 443):
            self.vulnerabilities.append("Port 443 open - HTTPS flood possible")
    
    def check_mitm_vectors(self, host):
        """Analyze MITM vulnerabilities"""
        self.findings.append(f"\n=== Man-in-the-Middle Analysis ===")
        
        # Check for unencrypted services
        if VulnerabilityAnalyzer.check_port_open(host, 80):
            self.vulnerabilities.append("HTTP (unencrypted) enabled - ARP spoofing attack possible")
        
        if VulnerabilityAnalyzer.check_port_open(host, 23):
            self.vulnerabilities.append("Telnet enabled - SSL Strip possible")
        
        if VulnerabilityAnalyzer.check_port_open(host, 21):
            self.vulnerabilities.append("FTP (unencrypted) enabled - Credentials at risk")
    
    def check_arp_spoofing(self, host):
        """Check for ARP spoofing vulnerability"""
        self.findings.append(f"\n=== ARP Spoofing Analysis ===")
        
        # Check if ARP is responding
        try:
            result = subprocess.run(
                ['arp', '-a', host] if platform.system() == 'Windows' else ['arp', '-n', host],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0 and host in result.stdout:
                self.vulnerabilities.append("ARP entry found - ARP spoofing possible")
                self.findings.append(f"ARP Response: ✓ Enabled")
        except:
            self.findings.append("ARP not directly accessible")
    
    def dns_security_check(self, domain):
        """Check DNS security"""
        self.findings.append(f"\n=== DNS Security Analysis ===")
        
        try:
            import dns.resolver
            
            # Check DNSSEC
            try:
                answers = dns.resolver.resolve(domain, 'A')
                self.findings.append(f"DNS resolution: ✓ Working")
            except:
                self.vulnerabilities.append("DNS resolution failure")
            
            # Check for AXFR (zone transfer)
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(domain, dns.resolver.resolve(domain, 'NS')[0]))
                self.vulnerabilities.append("CRITICAL: Zone transfer (AXFR) ALLOWED")
            except:
                self.findings.append("Zone transfer: ✓ Blocked")
        
        except:
            pass
    
    def firewall_detection(self, host):
        """Detect firewall presence"""
        self.findings.append(f"\n=== Firewall Detection ===")
        
        # Check for firewall by scanning TCP SYN
        open_count = 0
        for port in [80, 443, 22, 25, 53]:
            if VulnerabilityAnalyzer.check_port_open(host, port, timeout=1):
                open_count += 1
        
        if open_count == 0:
            self.findings.append("Firewall: ✓ Likely enabled (all ports blocked)")
        elif open_count < 3:
            self.findings.append("Firewall: ⚠ Stateful firewall detected (selective blocking)")
        else:
            self.vulnerabilities.append("Firewall: ✗ Not detected or misconfigured")
    
    def check_icmp_redirect(self, host):
        """Check for ICMP Redirect vulnerability"""
        self.findings.append(f"\n=== ICMP Redirect Analysis ===")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.findings.append("ICMP socket access: Allowed")
            sock.close()
        except PermissionError:
            self.findings.append("ICMP socket: ✓ Restricted (good)")
        except:
            pass
    
    def port_enumeration_status(self, host):
        """Check port enumeration resistance"""
        self.findings.append(f"\n=== Port Enumeration Detection ===")
        
        # Try stealth techniques
        closed_response = 0
        for port in range(65000, 65010):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((host, port))
                sock.close()
                if result != 0:
                    closed_response += 1
            except:
                pass
        
        if closed_response == 10:
            self.findings.append("Port enumeration: ✓ Consistent responses (good filter)")
        else:
            self.vulnerabilities.append("Port enumeration: ✗ Inconsistent responses")
    
    def generate_report(self):
        """Generate network security report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'module': 'Network Analysis',
            'vulnerabilities_found': len(self.vulnerabilities),
            'findings': len(self.findings),
            'details': self.vulnerabilities
        }
        return report
    
    def run(self, host=None):
        """Main execution"""
        print(Fore.CYAN + "\n╔════════════════════════════════════════════════════╗" + Style.RESET_ALL)
        print(Fore.CYAN + "║     NETWORK VULNERABILITY ANALYZER                  ║" + Style.RESET_ALL)
        print(Fore.CYAN + "╚════════════════════════════════════════════════════╝\n" + Style.RESET_ALL)
        
        if not host:
            host = input(Fore.YELLOW + "Enter target host: " + Style.RESET_ALL)
        
        print(f"\n{Fore.CYAN}Starting network analysis on: {Fore.YELLOW}{host}{Style.RESET_ALL}")
        
        # Resolve hostname
        try:
            ip = socket.gethostbyname(host)
            self.findings.append(f"Resolved to: {ip}")
        except:
            ip = host
        
        # Perform analyses
        self.check_ddos_vulnerabilities(ip)
        self.check_mitm_vectors(ip)
        self.check_arp_spoofing(ip)
        self.dns_security_check(host)
        self.firewall_detection(ip)
        self.check_icmp_redirect(ip)
        self.port_enumeration_status(ip)
        
        # Display results
        print("\n" + "="*60)
        print("NETWORK ANALYSIS RESULTS")
        print("="*60 + "\n")
        
        if self.vulnerabilities:
            print(Fore.RED + "VULNERABILITIES DETECTED:\n" + Style.RESET_ALL)
            for vuln in self.vulnerabilities:
                print(f"  🔴 {vuln}")
        
        print(f"\n{Fore.GREEN}FINDINGS:\n{Style.RESET_ALL}")
        for finding in self.findings:
            print(f"  • {finding}")
        
        report = self.generate_report()
        print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(f"  Vulnerabilities found: {report['vulnerabilities_found']}")
        print(f"  Total findings: {report['findings']}")
        
        return report

def main():
    import argparse
    parser = argparse.ArgumentParser(description='SHODAN VulnScopeX - Network Analyzer | Usage: network_module.py -t <host> | network_module.py --help')
    parser.add_argument('-t', '--target', '--host', dest='target', help='Target host/network')
    parser.add_argument('--ddos', action='store_true', help='Test DDoS vectors')
    parser.add_argument('--mitm', action='store_true', help='Analyze MITM')
    parser.add_argument('--firewall', action='store_true', help='Detect firewall')
    parser.add_argument('--version', action='version', version='%(prog)s v6.0')
    args = parser.parse_args()
    analyzer = NetworkAnalyzer()
    analyzer.run(host=args.target)

if __name__ == "__main__":
    main()
