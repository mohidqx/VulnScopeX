#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SHODAN VulnScopeX v6.0 PREMIUM LIVE - Quick Start Launcher
85+ REST APIs | Interactive CLI GUI | 50+ Exploitation Methods
Real-Time Dashboard | Advanced Threat Intelligence
Repository: github.com/mohidqx/VulnScopeX
"""

import os
import sys
import subprocess
import io

# Force UTF-8 encoding for Windows terminals
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    os.environ['PYTHONIOENCODING'] = 'utf-8'
import argparse
import json
from pathlib import Path
from colorama import init, Fore, Style
import emoji

init(autoreset=True)

def print_banner():
    print(f"""
{Fore.LIGHTRED_EX}
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║      🔥 SHODAN VulnScopeX v6.0 ULTIMATE ENTERPRISE 🔥             ║
║                                                                    ║
║  85+ REST APIs | Interactive CLI GUI | 50+ Exploitation Methods   ║
║      Advanced Threat Intelligence | Live Dashboard Analytics      ║
║                                                                    ║
║     GitHub: github.com/mohidqx/VulnScopeX                          ║
║     Documentation: doc/ folder (comprehensive guides)              ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
    """)

def check_for_updates():
    """Check for updates on GitHub"""
    print(f"\n{Fore.CYAN}[~] Checking for updates...{Style.RESET_ALL}")
    try:
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "shodan"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            print(f"{Fore.LIGHTGREEN_EX}[✓] Update completed successfully!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Visit: github.com/mohidqx/VulnScopeX for latest version{Style.RESET_ALL}")
        else:
            print(f"{Fore.LIGHTYELLOW_EX}[!] Could not update. Check your internet connection{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.LIGHTYELLOW_EX}[!] Update failed: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Visit: github.com/mohidqx/VulnScopeX for manual update{Style.RESET_ALL}")

def show_help():
    """Display comprehensive help menu"""
    print(f"""
{Fore.LIGHTGREEN_EX}
╔════════════════════════════════════════════════════════════════════╗
║         SHODAN VulnScopeX v6.0 - Complete Help Menu              ║
╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}

{Fore.CYAN}BASIC OPTIONS (v6.0 FEATURES):{Style.RESET_ALL}
  1 - Web UI + 85+ Advanced REST API Endpoints (Full Server)
  2 - Interactive CLI GUI Scanner (Terminal Interface)
  3 - API Documentation (85+ Endpoints)
  12 - View Documentation (Overview & links)
  13 - Check for Updates
  14 - Exit

{Fore.CYAN}ADVANCED ANALYSIS MODULES (7):{Style.RESET_ALL}
  
  4 - 🔐 Cryptographic Vulnerabilities Analysis
      Features: SSL/TLS analysis, weak cipher detection, key extraction
      Modules: Certificate analysis, protocol versions, cipher suites
      Use Case: Security audit of encrypted communications

  5 - 💣 Advanced Exploitation Module (50+ Methods)
      Features: Multi-stage exploit chains, privilege escalation, lateral movement
      Modules: Exploit orchestration, chain generation, impact analysis
      Use Case: Penetration testing and red team operations

  6 - 🧠 Memory & Code Injection Analysis
      Features: Memory corruption, heap spray, ROP gadgets, DLL injection
      Modules: Buffer overflow analysis, code injection detection
      Use Case: Binary exploitation and vulnerability research

  7 - 🌐 Network-Level Attacks Module
      Features: DNS spoofing, BGP hijacking, DHCP starvation, ARP spoofing
      Modules: Network protocol analysis, man-in-the-middle detection
      Use Case: Network security assessment and infrastructure testing

  8 - 🔑 Privilege Escalation Advanced Module
       Features: Kernel exploits, driver vulnerabilities, UEFI backdoors
       Modules: Local privilege escalation, kernel analysis
       Use Case: Post-exploitation and privilege escalation testing

  9 - 🔎 Advanced Reconnaissance Module
       Features: DNS intelligence, port fingerprinting, protocol analysis
       Modules: Service discovery, fingerprinting, reconnaissance
       Use Case: Information gathering and target profiling

  10 - 🕸️  Advanced Web Application Module
        Features: Blind SQLi, template injection, XXE, SSRF, GraphQL attacks
        Modules: Web vulnerability detection, payload generation
        Use Case: Web application penetration testing

  11 - ⭐ v6.0 ADVANCED FEATURES
        Features: SHODAN integration, Email/Slack alerts, scheduling
        Use Case: Automated scanning, threat intelligence, monitoring

{Fore.YELLOW}USAGE:{Style.RESET_ALL}
  python start_premium.py        - Start interactive menu
  python start_premium.py -h     - Show this help menu
  python start_premium.py --help - Show this help menu

{Fore.CYAN}EXAMPLES:{Style.RESET_ALL}
  python start_premium.py        # Interactive prompt
  python start_premium.py -h     # Display help
  
{Fore.LIGHTGREEN_EX}[✓] v6.0 Upgrades: 85+ APIs, CLI GUI, 50+ Exploits, Docs!{Style.RESET_ALL}
    """)

def check_for_updates():
    """Check for updates on GitHub"""
    print(f"\n{Fore.CYAN}[~] Checking for updates...{Style.RESET_ALL}")
    try:
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "shodan"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            print(f"{Fore.LIGHTGREEN_EX}[✓] Update completed successfully!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Visit: github.com/mohidqx/VulnScopeX for latest version{Style.RESET_ALL}")
        else:
            print(f"{Fore.LIGHTYELLOW_EX}[!] Could not update. Check your internet connection{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.LIGHTYELLOW_EX}[!] Update failed: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Visit: github.com/mohidqx/VulnScopeX for manual update{Style.RESET_ALL}")

def main():
    print_banner()
    
    # Check for API key
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        print(f"{Fore.LIGHTYELLOW_EX}[!] No SHODAN API key set{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Set with: export SHODAN_API_KEY='your_key_here'{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Or add to .env file{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.LIGHTGREEN_EX}[✓] API key configured{Style.RESET_ALL}\n")
    
    print("Choose your mode:\n")
    print(f"{Fore.CYAN}1. Web UI + 85+ REST API Endpoints (Full Server){Style.RESET_ALL}")
    print(f"{Fore.CYAN}2. Interactive CLI GUI Scanner (Terminal Interface){Style.RESET_ALL}")
    print(f"{Fore.CYAN}3. API Documentation (85+ Endpoints - READ doc/APIs.md){Style.RESET_ALL}")
    print(f"{Fore.CYAN}4. 🔐 Cryptographic Vulnerabilities Analysis Module{Style.RESET_ALL}")
    print(f"{Fore.CYAN}5. 💣 Advanced Exploitation Module (50+ Methods){Style.RESET_ALL}")
    print(f"{Fore.CYAN}6. 🧠 Memory & Code Injection Analysis Module{Style.RESET_ALL}")
    print(f"{Fore.CYAN}7. 🌐 Network-Level Attacks Module{Style.RESET_ALL}")
    print(f"{Fore.CYAN}8. 🔑 Privilege Escalation Advanced Module{Style.RESET_ALL}")
    print(f"{Fore.CYAN}9. 🔎 Advanced Reconnaissance Module{Style.RESET_ALL}")
    print(f"{Fore.CYAN}10. 🕸️  Advanced Web Application Module{Style.RESET_ALL}")
    print(f"{Fore.LIGHTGREEN_EX}11. ⭐ v6.0 ADVANCED FEATURES (SHODAN + Alerts + Analytics){Style.RESET_ALL}")
    print(f"{Fore.LIGHTYELLOW_EX}12. 📚 VIEW DOCUMENTATION (READ ME FIRST){Style.RESET_ALL}")
    print(f"{Fore.CYAN}13. Check for Updates{Style.RESET_ALL}")
    print(f"{Fore.CYAN}14. Exit{Style.RESET_ALL}\n")
    
    choice = input(f"{Fore.YELLOW}Enter choice (1-14): {Style.RESET_ALL}").strip()
    
    if choice == "1":
        print(f"\n{Fore.LIGHTGREEN_EX}[✓] Starting Web UI + 85+ REST API Endpoints...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 Dashboard: http://localhost:5000{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🔌 API Base: http://localhost:5000/api/v4{Style.RESET_ALL}")
        print(f"{Fore.LIGHTGREEN_EX}v6.0 Features:{Style.RESET_ALL}")
        print(f"   ✅ 85+ REST API endpoints for all operations")
        print(f"   ✅ Real-time vulnerability scanning dashboard")
        print(f"   ✅ 50+ exploitation methods (privilege escalation, lateral movement)")
        print(f"   ✅ Threat intelligence synthesis with AI")
        print(f"   ✅ Risk scoring, CVSS 3.1 analysis, threat trending")
        print(f"   ✅ Multi-format exports (CSV, JSON, PDF, Excel)")
        print(f"   ✅ Activity logging, audit trail, compliance reports")
        print(f"   ✅ SQLite database backend + CSV hybrid storage")
        print(f"   ✅ Email/Slack alerts + webhook support")
        print(f"   ✅ Scheduled scanning with cron integration")
        print(f"{Fore.YELLOW}[*] Press CTRL+C to stop the server{Style.RESET_ALL}\n")
        try:
            subprocess.run([sys.executable, "app/premium_live.py"])
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Server stopped{Style.RESET_ALL}\n")
    
    elif choice == "2":
        print(f"\n{Fore.LIGHTGREEN_EX}[✓] Starting Interactive CLI GUI Scanner (v6.0)...{Style.RESET_ALL}")
        print(f"{Fore.LIGHTGREEN_EX}v6.0 CLI GUI Features:{Style.RESET_ALL}")
        print(f"   ✅ Interactive menu system with 10+ submenus")
        print(f"   ✅ Real-time progress bars with ETA")
        print(f"   ✅ Color-coded severity levels (Critical/High/Medium/Low)")
        print(f"   ✅ Command auto-completion & history")
        print(f"   ✅ 50+ interactive operations")
        print(f"   ✅ Keyboard shortcuts for fast navigation")
        print(f"   ✅ Intelligent result deduplication")
        print(f"   ✅ Real-time risk scoring & threat intelligence")
        print(f"   ✅ Payload generation (6+ attack types)")
        print(f"   ✅ Multi-format export support")
        print(f"   ✅ Asset discovery & inventory management")
        print(f"   ✅ Vulnerability CRUD operations")
        print(f"{Fore.YELLOW}[*] Press CTRL+C to cancel{Style.RESET_ALL}\n")
        try:
            subprocess.run([sys.executable, "scanner_premium.py"])
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Scan cancelled{Style.RESET_ALL}\n")
    
    elif choice == "3":
        print(f"\n{Fore.LIGHTGREEN_EX}[✓] API Documentation - 85+ REST Endpoints (v6.0){Style.RESET_ALL}\n")
        api_docs = """
{cyan}═══ 📚 API CATEGORIES (85+ Total) {rst}

{cyan}🔧 VULNERABILITY MANAGEMENT (15+ endpoints){rst}
   POST   /api/v4/vulns                  - CREATE vulnerability
   GET    /api/v4/vulns                  - LIST all vulnerabilities
   GET    /api/v4/vulns/<id>             - GET specific vulnerability  
   PUT    /api/v4/vulns/<id>             - UPDATE vulnerability
   DELETE /api/v4/vulns/<id>             - DELETE vulnerability
   POST   /api/v4/vulns/search           - SEARCH with filters
   POST   /api/v4/vulns/bulk/priority    - BULK UPDATE priorities
   + 8 more endpoints (import, escalate, rescan, POC, remediation, etc.)

{cyan}🎯 THREAT INTELLIGENCE (10+ endpoints){rst}
   GET    /api/v4/threat/exploit-db      - Access 50,000+ exploits
   GET    /api/v4/threat/default-creds   - Default creds database
   POST   /api/v4/threat/payloads        - Generate custom payloads
   GET    /api/v4/threat/cve-lookup      - Real-time CVE lookup
   POST   /api/v4/threat/risk-assessment - Risk scoring algorithm
   + 5 more intelligence endpoints

{cyan}🔍 SCANNING & RECONNAISSANCE (10+ endpoints){rst}
   POST   /api/v4/scan/start             - START real-time scan
   GET    /api/v4/scan/stream            - STREAM SSE results
   POST   /api/v4/dns/intelligence       - DNS enumeration
   POST   /api/v4/subdomain/enumerate    - Subdomain discovery
   POST   /api/v4/ssl/analyze            - SSL/TLS analysis
   + 5 more scanning endpoints

{cyan}💣 EXPLOITATION (25+ endpoints){rst}
   POST   /api/v4/exploit/chain          - Exploit chain builder
   POST   /api/v4/privilege-escalation   - Privilege escalation hunting
   POST   /api/v4/lateral-movement       - Lateral movement mapping
   POST   /api/v4/backdoor/detect        - Backdoor detection
   POST   /api/v4/zeroday/analyze        - Zero-day analysis
   + 20 more exploitation endpoints (kernel, UAC, SUID, ROP, etc.)

{cyan}🔐 CRYPTOGRAPHY (15+ endpoints){rst}
   POST   /api/v4/crypto/key-extraction  - Key extraction techniques
   POST   /api/v4/crypto/downgrade       - Downgrade attack analysis
   POST   /api/v4/cipher/weak-detection  - Weak cipher detection
   POST   /api/v4/aslr/bypass            - ASLR bypass techniques
   + 11 more crypto endpoints

{cyan}🌐 WEB APPLICATION SECURITY (12+ endpoints){rst}
   POST   /api/v4/sqli/blind-hunt        - SQL injection detection
   POST   /api/v4/injection/xxe          - XXE vulnerability testing
   POST   /api/v4/ssrf/map               - SSRF mapping
   POST   /api/v4/graphql/audit          - GraphQL auditing
   + 8 more web security endpoints

{cyan}🌍 NETWORK SECURITY (15+ endpoints){rst}
   POST   /api/v4/dns/spoofing           - DNS spoofing simulation
   POST   /api/v4/bgp/hijacking          - BGP hijacking analysis
   POST   /api/v4/ddos/vectors           - DDoS vector analysis
   POST   /api/v4/network/topology       - Network topology mapping
   + 11 more network endpoints

{cyan}📊 ANALYSIS & REPORTING (12+ endpoints){rst}
   GET    /api/v4/analyze/stats          - Vulnerability statistics
   GET    /api/v4/analyze/trends         - Trend analysis
   POST   /api/v4/analyze/cvss           - CVSS risk scoring
   GET    /api/v4/export/csv             - Export as CSV
   GET    /api/v4/export/pdf             - Export as PDF
   + 7 more reporting endpoints

{cyan}⚡ UTILITY & INTEGRATION (7+ endpoints){rst}
   GET    /api/v4/health                 - Health check
   GET    /api/v4/info                   - API information
   POST   /api/v4/shodan/search          - SHODAN integration
   POST   /api/v4/alerts/email           - Email alerts
   + 3 more utility endpoints

{yellow}📍 Complete Documentation: doc/APIs.md (1000+ lines){rst}
{yellow}🔑 Base URL: http://localhost:5000/api/v4{rst}
{yellow}📊 Database: SQLite + CSV Hybrid{rst}
        """.format(
            cyan=Fore.CYAN, 
            rst=Style.RESET_ALL,
            yellow=Fore.YELLOW
        )
        print(api_docs)
        print(f"{Fore.LIGHTGREEN_EX}[✓] Full API documentation available in doc/APIs.md{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}See: doc/APIs.md for complete endpoint reference\n{Style.RESET_ALL}")
    
    elif choice == "11":
        print(f"\n{Fore.LIGHTGREEN_EX}[✓] Launching Advanced Features CLI...{Style.RESET_ALL}\n")
        print(f"{Fore.LIGHTGREEN_EX}v6.0 Advanced Features:{Style.RESET_ALL}")
        print(f"   ✅ SHODAN API Integration (real-time queries)")
        print(f"   ✅ Email & Slack Alerts (push notifications)")
        print(f"   ✅ Scan Scheduling (daily/weekly/hourly)")
        print(f"   ✅ Risk Analytics & Trending (30-day analysis)")
        print(f"   ✅ Performance Metrics Dashboard")
        print(f"   ✅ Nmap Port Scanning Integration\n")
        try:
            subprocess.run([sys.executable, "advanced_cli.py"])
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Advanced features closed{Style.RESET_ALL}\n")
        except Exception as e:
            print(f"{Fore.LIGHTRED_EX}[✗] Error launching advanced features: {e}{Style.RESET_ALL}\n")
    
    elif choice == "12":
        print(f"\n{Fore.LIGHTGREEN_EX}[✓] VulnScopeX v6.0 Documentation{Style.RESET_ALL}\n")
        docs_menu = f"""
{Fore.CYAN}═════════════════════════════════════════════════════════{Style.RESET_ALL}
{Fore.LIGHTGREEN_EX}v6.0 DOCUMENTATION STRUCTURE (All in doc/ folder){Style.RESET_ALL}
{Fore.CYAN}═════════════════════════════════════════════════════════{Style.RESET_ALL}

{Fore.YELLOW}📦 SETUP & INSTALLATION{Style.RESET_ALL}
   → doc/INSTALLATION.md        - Complete install guide (Windows/Linux/Mac)
   → doc/QUICKSTART.md          - 60-second quick start
   → doc/CONFIGURATION.md       - Configuration & environment setup

{Fore.YELLOW}🎮 USING THE TOOL{Style.RESET_ALL}
   → doc/CLI_GUI.md             - Interactive terminal interface guide
   → doc/MODULES.md             - 7 core modules overview
   → doc/README.md              - Main entry point (in root)

{Fore.YELLOW}📖 REFERENCE & APIs{Style.RESET_ALL}
   → doc/APIs.md                - 85+ REST API endpoints (COMPLETE)
   → doc/V6_FEATURES.md         - All v6.0 features (85+ total)
   → doc/FEATURES.md            - Feature list pointer

{Fore.YELLOW}🆘 SUPPORT{Style.RESET_ALL}
   → doc/TROUBLESHOOTING.md     - Common issues & solutions
   → doc/HOW_70PLUS_FEATURES_IMPLEMENTED.md - Technical deep dive
   → doc/README_FULL.md         - Complete original documentation

{Fore.CYAN}═════════════════════════════════════════════════════════{Style.RESET_ALL}

{Fore.LIGHTGREEN_EX}v6.0 HIGHLIGHTS:{Style.RESET_ALL}
   ✅ 85+ REST API endpoints        (up from 70)
   ✅ Interactive CLI GUI interface (new in v6)
   ✅ 50+ exploitation methods      (up from 30)
   ✅ 100+ detection rules          (up from 50)
   ✅ 500+ payload templates        (up from 250)
   ✅ Advanced threat intelligence  (AI-powered)
   ✅ Multi-format reporting        (PDF, JSON, CSV, XLSX)
   ✅ Automated scheduling & alerts (Email, Slack, Webhooks)

{Fore.YELLOW}START HERE:{Style.RESET_ALL}
   1. Read: doc/QUICKSTART.md (60 seconds)
   2. Run: python start_premium.py
   3. Choose: Option 1 (Web UI) or Option 2 (CLI GUI)
   4. Explore: http://localhost:5000

{Fore.CYAN}═════════════════════════════════════════════════════════{Style.RESET_ALL}
"""
        print(docs_menu)
        print(f"{Fore.LIGHTGREEN_EX}[✓] Documentation overview displayed{Style.RESET_ALL}\n")
    
    elif choice == "13":
        print(f"\n{Fore.LIGHTGREEN_EX}[~] Checking for Updates...{Style.RESET_ALL}\n")
        check_for_updates()
        print(f"{Fore.CYAN}Repository: https://github.com/mohidqx/VulnScopeX{Style.RESET_ALL}\n")
    
    elif choice == "14":
        print(f"\n{Fore.LIGHTGREEN_EX}[✓] Thank you for using SHODAN VulnScopeX v6.0!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}GitHub: https://github.com/mohidqx/VulnScopeX{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Version: 6.0 Enterprise Edition{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Stay secure! 🔒\n{Style.RESET_ALL}\n")
        sys.exit(0)
    
    elif choice == "4":
        print(f"\n{Fore.LIGHTGREEN_EX}[✓] Launching Cryptographic Vulnerabilities Analysis...{Style.RESET_ALL}\n")
        try:
            subprocess.run([sys.executable, "crypto_module.py"])
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Module closed{Style.RESET_ALL}\n")
        except Exception as e:
            print(f"{Fore.LIGHTRED_EX}[✗] Error launching module: {e}{Style.RESET_ALL}\n")
    
    elif choice == "5":
        print(f"\n{Fore.LIGHTGREEN_EX}[✓] Launching Advanced Exploitation Module...{Style.RESET_ALL}\n")
        try:
            subprocess.run([sys.executable, "exploitation_module.py"])
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Module closed{Style.RESET_ALL}\n")
        except Exception as e:
            print(f"{Fore.LIGHTRED_EX}[✗] Error launching module: {e}{Style.RESET_ALL}\n")
    
    elif choice == "6":
        print(f"\n{Fore.LIGHTGREEN_EX}[✓] Launching Memory & Code Injection Analysis...{Style.RESET_ALL}\n")
        try:
            subprocess.run([sys.executable, "memory_module.py"])
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Module closed{Style.RESET_ALL}\n")
        except Exception as e:
            print(f"{Fore.LIGHTRED_EX}[✗] Error launching module: {e}{Style.RESET_ALL}\n")
    
    elif choice == "7":
        print(f"\n{Fore.LIGHTGREEN_EX}[✓] Launching Network-Level Attacks Module...{Style.RESET_ALL}\n")
        try:
            subprocess.run([sys.executable, "network_module.py"])
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Module closed{Style.RESET_ALL}\n")
        except Exception as e:
            print(f"{Fore.LIGHTRED_EX}[✗] Error launching module: {e}{Style.RESET_ALL}\n")
    
    elif choice == "8":
        print(f"\n{Fore.LIGHTGREEN_EX}[✓] Launching Privilege Escalation Advanced Module...{Style.RESET_ALL}\n")
        try:
            subprocess.run([sys.executable, "privilege_module.py"])
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Module closed{Style.RESET_ALL}\n")
        except Exception as e:
            print(f"{Fore.LIGHTRED_EX}[✗] Error launching module: {e}{Style.RESET_ALL}\n")
    
    elif choice == "9":
        print(f"\n{Fore.LIGHTGREEN_EX}[✓] Launching Advanced Reconnaissance Module...{Style.RESET_ALL}\n")
        try:
            subprocess.run([sys.executable, "reconnaissance_module.py"])
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Module closed{Style.RESET_ALL}\n")
        except Exception as e:
            print(f"{Fore.LIGHTRED_EX}[✗] Error launching module: {e}{Style.RESET_ALL}\n")
    
    elif choice == "10":
        print(f"\n{Fore.LIGHTGREEN_EX}[✓] Launching Advanced Web Application Module...{Style.RESET_ALL}\n")
        try:
            subprocess.run([sys.executable, "webapp_module.py"])
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Module closed{Style.RESET_ALL}\n")
        except Exception as e:
            print(f"{Fore.LIGHTRED_EX}[✗] Error launching module: {e}{Style.RESET_ALL}\n")
    
    else:
        print(f"\n{Fore.LIGHTRED_EX}[✗] Invalid choice. Please enter 1-14{Style.RESET_ALL}\n")
        return main()

if __name__ == "__main__":
    try:
        # Parse command line arguments
        parser = argparse.ArgumentParser(
            description='SHODAN VulnScopeX v6.0 - Advanced Vulnerability Intelligence Platform (85+ APIs)',
            add_help=False  # Disable default help to use custom one
        )
        parser.add_argument('-h', '--help', action='store_true', help='Show help menu')
        args, unknown = parser.parse_known_args()
        
        if args.help:
            show_help()
            sys.exit(0)
        
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Cancelled by user (CTRL+C){Style.RESET_ALL}")
        print(f"{Fore.CYAN}GitHub: https://github.com/mohidqx/VulnScopeX (v6.0){Style.RESET_ALL}")
        print(f"{Fore.CYAN}Documentation: doc/ folder for comprehensive guides\n{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.LIGHTRED_EX}[✗] Error: {str(e)}{Style.RESET_ALL}\n")
        sys.exit(1)
