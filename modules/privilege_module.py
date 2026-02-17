"""
REAL Privilege Escalation Analysis Module
Analyzes privilege escalation vectors on Windows/Linux systems
"""

import os
import sys
import subprocess
import platform
from colorama import Fore, Style
from datetime import datetime
import json
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class PrivilegeEscalationAnalyzer:
    def __init__(self):
        self.findings = []
        self.vulnerabilities = []
        self.os_type = platform.system()
    
    def analyze_windows_pe(self):
        """Analyze Windows privilege escalation vectors"""
        self.findings.append(f"\n=== Windows Privilege Escalation Vectors ===")
        
        pe_vectors = [
            {'name': 'UAC Bypass', 'method': 'Token impersonation or bypass', 'severity': 'HIGH', 'cve': 'CVE-2023-21674'},
            {'name': 'Unquoted Service Path', 'method': 'DLL hijacking in service path', 'severity': 'HIGH', 'cve': None},
            {'name': 'AlwaysInstallElevated', 'method': 'MSI elevation', 'severity': 'CRITICAL', 'cve': None},
            {'name': 'Weak Service Permissions', 'method': 'Service binary replacement', 'severity': 'HIGH', 'cve': None},
            {'name': 'Scheduled Task Abuse', 'method': 'Task modification', 'severity': 'MEDIUM', 'cve': None},
            {'name': 'Registry Modification', 'method': 'HKLM write access', 'severity': 'HIGH', 'cve': None},
        ]
        
        for vector in pe_vectors:
            severity = vector['severity']
            color = Fore.RED if severity == 'CRITICAL' else Fore.YELLOW
            cve_str = f" ({vector['cve']})" if vector['cve'] else ""
            
            self.findings.append(f"\n{vector['name']}{cve_str}:")
            self.findings.append(f"  Severity: {severity}")
            self.findings.append(f"  Method: {vector['method']}")
            
            if severity == 'CRITICAL':
                self.vulnerabilities.append(vector)
    
    def analyze_linux_pe(self):
        """Analyze Linux privilege escalation vectors"""
        self.findings.append(f"\n=== Linux Privilege Escalation Vectors ===")
        
        pe_vectors = [
            {'name': 'SUID Binary Exploitation', 'example': '/usr/bin/sudo, /usr/bin/find', 'severity': 'HIGH'},
            {'name': 'Sudo Misconfiguration', 'example': 'NOPASSWD entries, wildcards', 'severity': 'CRITICAL'},
            {'name': 'Kernel Vulnerabilities', 'example': 'Dirty Pipe, eBPF bugs', 'severity': 'CRITICAL'},
            {'name': 'Linux Capabilities', 'example': 'CAP_SYS_ADMIN, CAP_NET_ADMIN', 'severity': 'HIGH'},
            {'name': 'LD_PRELOAD Hijacking', 'example': 'Library path manipulation', 'severity': 'HIGH'},
            {'name': 'Cron Job Exploitation', 'example': 'World-writable scripts', 'severity': 'MEDIUM'},
        ]
        
        for vector in pe_vectors:
            severity = vector['severity']
            color = Fore.RED if severity == 'CRITICAL' else Fore.YELLOW
            
            self.findings.append(f"\n{vector['name']}:")
            self.findings.append(f"  Severity: {severity}")
            self.findings.append(f"  Example: {vector['example']}")
            
            if severity == 'CRITICAL':
                self.vulnerabilities.append(vector)
    
    def check_sudo_config(self):
        """Check sudo configuration for misconfigurations"""
        self.findings.append(f"\n=== Sudo Configuration Analysis ===")
        
        if self.os_type == 'Linux':
            try:
                # Check if running with sudo access
                result = subprocess.run(['sudo', '-l'], capture_output=True, text=True, timeout=2)
                
                if result.returncode == 0:
                    sudo_output = result.stdout
                    
                    # Check for NOPASSWD
                    if 'NOPASSWD' in sudo_output:
                        self.findings.append("🔴 NOPASSWD entries found - Commands executable without password")
                        self.vulnerabilities.append({'name': 'NOPASSWD sudo entries', 'severity': 'CRITICAL'})
                    
                    # Check for wildcards
                    if '*' in sudo_output:
                        self.findings.append("🔴 Wildcard entries found - Potential for privilege escalation")
                        self.vulnerabilities.append({'name': 'Wildcard sudo entries', 'severity': 'CRITICAL'})
                    
                    self.findings.append(f"Sudo privileges: Available")
                else:
                    self.findings.append("Sudo not directly accessible")
            except:
                self.findings.append("Could not check sudo configuration")
        else:
            self.findings.append("Not a Linux system - sudo analysis skipped")
    
    def check_suid_binaries(self):
        """Check for exploitable SUID binaries"""
        self.findings.append(f"\n=== SUID Binary Analysis ===")
        
        if self.os_type == 'Linux':
            dangerous_suid = [
                '/usr/bin/sudo',
                '/usr/bin/find',
                '/usr/bin/less',
                '/usr/bin/nano',
                '/usr/bin/vi',
                '/bin/cp',
                '/bin/mv',
                '/usr/bin/awk'
            ]
            
            self.findings.append("Common dangerous SUID binaries:")
            for binary in dangerous_suid:
                try:
                    if os.path.exists(binary):
                        self.findings.append(f"  ✓ {binary} exists (potentially exploitable)")
                except:
                    pass
        else:
            self.findings.append("SUID analysis is Linux-specific")
    
    def check_kernel_vulnerabilities(self):
        """Check for known kernel vulnerabilities"""
        self.findings.append(f"\n=== Kernel Vulnerability Check ===")
        
        kernel_vulns = [
            {'name': 'CVE-2023-21674', 'system': 'Windows', 'impact': 'Privilege Escalation'},
            {'name': 'Dirty Pipe (CVE-2022-0847)', 'system': 'Linux', 'impact': 'RW to read-only file'},
            {'name': 'eBPF Verifier Bug', 'system': 'Linux', 'impact': 'Code execution as root'},
            {'name': 'Perf Subsystem', 'system': 'Linux', 'impact': 'Integer overflow'},
        ]
        
        current_kernel = platform.release()
        self.findings.append(f"Kernel version: {current_kernel}")
        
        for vuln in kernel_vulns:
            if (self.os_type == 'Linux' and vuln['system'] == 'Linux') or \
               (self.os_type == 'Windows' and vuln['system'] == 'Windows'):
                self.findings.append(f"\nPotential: {vuln['name']}")
                self.findings.append(f"  Impact: {vuln['impact']}")
                self.vulnerabilities.append(vuln)
    
    def check_file_permissions(self):
        """Check for weak file permissions"""
        self.findings.append(f"\n=== File Permission Analysis ===")
        
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/root/',
            '/home/'
        ]
        
        if self.os_type == 'Linux':
            for file_path in critical_files:
                if os.path.exists(file_path):
                    try:
                        mode = oct(os.stat(file_path).st_mode)[-3:]
                        self.findings.append(f"{file_path}: {mode}")
                        
                        # Check for world-readable critical files
                        if file_path == '/etc/shadow' and int(mode[0]) > 0:
                            self.vulnerabilities.append({'file': file_path, 'severity': 'CRITICAL'})
                    except:
                        pass
    
    def generate_report(self):
        """Generate privilege escalation report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'module': 'Privilege Escalation Analysis',
            'os': self.os_type,
            'vulnerabilities_found': len(self.vulnerabilities),
            'findings': len(self.findings),
            'critical_vectors': [v for v in self.vulnerabilities if isinstance(v, dict) and v.get('severity') == 'CRITICAL']
        }
        return report
    
    def run(self, target_os=None):
        """Main execution"""
        print(Fore.CYAN + "\n╔════════════════════════════════════════════════════╗" + Style.RESET_ALL)
        print(Fore.CYAN + "║     PRIVILEGE ESCALATION ANALYZER                   ║" + Style.RESET_ALL)
        print(Fore.CYAN + "╚════════════════════════════════════════════════════╝\n" + Style.RESET_ALL)
        
        current_os = target_os or self.os_type
        print(f"\n{Fore.CYAN}Analyzing privilege escalation on: {Fore.YELLOW}{current_os}{Style.RESET_ALL}")
        
        # Run analyses
        if current_os.lower() == 'windows' or self.os_type == 'Windows':
            self.analyze_windows_pe()
        elif current_os.lower() == 'linux' or self.os_type == 'Linux':
            self.analyze_linux_pe()
            self.check_sudo_config()
            self.check_suid_binaries()
            self.check_file_permissions()
        
        self.check_kernel_vulnerabilities()
        
        # Display results
        print("\n" + "="*60)
        print("PRIVILEGE ESCALATION FINDINGS")
        print("="*60 + "\n")
        
        for finding in self.findings:
            if '🔴' in finding or 'CRITICAL' in finding:
                print(Fore.RED + finding + Style.RESET_ALL)
            elif '✓' in finding:
                print(Fore.GREEN + finding + Style.RESET_ALL)
            else:
                print(finding)
        
        report = self.generate_report()
        print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(f"  Vulnerabilities found: {report['vulnerabilities_found']}")
        print(f"  Critical vectors: {len(report['critical_vectors'])}")
        print(f"  OS: {report['os']}")
        
        return report

def main():
    import argparse
    parser = argparse.ArgumentParser(description='SHODAN VulnScopeX - Privilege Escalation | Usage: privilege_module.py -o <OS> | privilege_module.py --help')
    parser.add_argument('-o', '--os', dest='os', choices=['Windows', 'Linux'], help='Target OS')
    parser.add_argument('--sudo', action='store_true', help='Check sudo misconfig')
    parser.add_argument('--suid', action='store_true', help='Analyze SUID binaries')
    parser.add_argument('--kernel', action='store_true', help='Kernel vulnerabilities')
    parser.add_argument('--version', action='version', version='%(prog)s v6.0')
    args = parser.parse_args()
    analyzer = PrivilegeEscalationAnalyzer()
    analyzer.run(target_os=args.os)

if __name__ == "__main__":
    main()
