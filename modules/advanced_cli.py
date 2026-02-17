#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced CLI Module - All-in-one Advanced Features CLI
SHODAN VulnScopeX v6.0 - Advanced Features Command Line Interface (85+ APIs)
"""

import os
import sys
import json
from colorama import init, Fore, Style
from datetime import datetime
from pathlib import Path

# Force UTF-8 encoding for Windows terminals
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# Import advanced features
try:
    from app.advanced_features import (
        shodan_client, alert_system, scan_scheduler, 
        risk_analyzer, performance_metrics, nmap_integration
    )
except ImportError:
    print(f"{Fore.LIGHTYELLOW_EX}[!] Advanced features module not available{Style.RESET_ALL}")
    sys.exit(1)

init(autoreset=True)

RESULTS_DIR = Path("scan_results")
RESULTS_DIR.mkdir(exist_ok=True)


def print_header(title):
    """Print section header"""
    print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║{Fore.WHITE} {title:<62}{Fore.CYAN}║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")


def shodan_cli():
    """SHODAN API Interactive Menu"""
    print_header("SHODAN API Integration")
    
    while True:
        print(f"{Fore.YELLOW}SHODAN API Commands:{Style.RESET_ALL}")
        print(f"  1. Search SHODAN")
        print(f"  2. Get Host Details")
        print(f"  3. Get Account Info")
        print(f"  0. Back\n")
        
        choice = input(f"{Fore.YELLOW}Select option: {Style.RESET_ALL}").strip()
        
        if choice == "1":
            query = input(f"{Fore.CYAN}Enter search query (default: mongodb): {Style.RESET_ALL}").strip() or "mongodb"
            limit = input(f"{Fore.CYAN}Enter result limit (default: 50): {Style.RESET_ALL}").strip() or "50"
            
            print(f"\n{Fore.YELLOW}[~] Searching SHODAN for: {query}...{Style.RESET_ALL}\n")
            result = shodan_client.search(query, int(limit))
            
            print(f"{Fore.LIGHTGREEN_EX}Result:{Style.RESET_ALL}")
            print(json.dumps(result, indent=2))
            
            # Save to file
            filename = RESULTS_DIR / f"shodan_search_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"\n{Fore.LIGHTGREEN_EX}[✓] Saved to: {filename}{Style.RESET_ALL}\n")
            
        elif choice == "2":
            ip = input(f"{Fore.CYAN}Enter IP address: {Style.RESET_ALL}").strip()
            if not ip:
                print(f"{Fore.LIGHTRED_EX}[✗] IP address required{Style.RESET_ALL}\n")
                continue
            
            print(f"\n{Fore.YELLOW}[~] Getting details for {ip}...{Style.RESET_ALL}\n")
            result = shodan_client.get_host_details(ip)
            
            print(f"{Fore.LIGHTGREEN_EX}Result:{Style.RESET_ALL}")
            print(json.dumps(result, indent=2))
            
            filename = RESULTS_DIR / f"shodan_host_{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"\n{Fore.LIGHTGREEN_EX}[✓] Saved to: {filename}{Style.RESET_ALL}\n")
            
        elif choice == "3":
            result = shodan_client.get_account_info()
            print(f"\n{Fore.LIGHTGREEN_EX}Account Info:{Style.RESET_ALL}")
            print(json.dumps(result, indent=2))
            print()
            
        elif choice == "0":
            break
        else:
            print(f"{Fore.LIGHTRED_EX}[✗] Invalid option{Style.RESET_ALL}\n")


def alerts_cli():
    """Alerts & Notifications Menu"""
    print_header("Alerts & Notifications")
    
    while True:
        print(f"{Fore.YELLOW}Alert Options:{Style.RESET_ALL}")
        print(f"  1. Send Email Alert")
        print(f"  2. Send Slack Alert")
        print(f"  3. View Alert History")
        print(f"  0. Back\n")
        
        choice = input(f"{Fore.YELLOW}Select option: {Style.RESET_ALL}").strip()
        
        if choice == "1":
            subject = input(f"{Fore.CYAN}Email Subject: {Style.RESET_ALL}").strip() or "Security Alert"
            body = input(f"{Fore.CYAN}Email Body (plain text): {Style.RESET_ALL}").strip() or "New vulnerability detected"
            
            print(f"\n{Fore.YELLOW}[~] Sending email alert...{Style.RESET_ALL}\n")
            result = alert_system.send_email_alert(subject, body)
            print(f"{Fore.LIGHTGREEN_EX}Result: {json.dumps(result, indent=2)}{Style.RESET_ALL}\n")
            
        elif choice == "2":
            title = input(f"{Fore.CYAN}Alert Title: {Style.RESET_ALL}").strip() or "Security Alert"
            message = input(f"{Fore.CYAN}Alert Message: {Style.RESET_ALL}").strip() or "New finding detected"
            severity = input(f"{Fore.CYAN}Severity (CRITICAL/HIGH/MEDIUM/LOW/INFO): {Style.RESET_ALL}").strip() or "INFO"
            
            print(f"\n{Fore.YELLOW}[~] Sending Slack alert...{Style.RESET_ALL}\n")
            result = alert_system.send_slack_alert(title, message, severity)
            print(f"{Fore.LIGHTGREEN_EX}Result: {json.dumps(result, indent=2)}{Style.RESET_ALL}\n")
            
        elif choice == "3":
            limit = input(f"{Fore.CYAN}Number of alerts to show (default: 20): {Style.RESET_ALL}").strip() or "20"
            alerts = alert_system.get_alert_history(int(limit))
            
            print(f"\n{Fore.LIGHTGREEN_EX}Alert History (Last {len(alerts)}):{Style.RESET_ALL}")
            for alert in alerts:
                print(f"  • {alert.get('type')} - {alert.get('status')} @ {alert.get('timestamp')}")
            print()
            
        elif choice == "0":
            break
        else:
            print(f"{Fore.LIGHTRED_EX}[✗] Invalid option{Style.RESET_ALL}\n")


def scheduler_cli():
    """Scan Scheduler Menu"""
    print_header("Scan Scheduling")
    
    while True:
        print(f"{Fore.YELLOW}Scheduler Options:{Style.RESET_ALL}")
        print(f"  1. Schedule New Scan")
        print(f"  2. List Scheduled Jobs")
        print(f"  3. Start Scheduler")
        print(f"  4. Stop Scheduler")
        print(f"  0. Back\n")
        
        choice = input(f"{Fore.YELLOW}Select option: {Style.RESET_ALL}").strip()
        
        if choice == "1":
            scan_id = input(f"{Fore.CYAN}Scan ID (auto if empty): {Style.RESET_ALL}").strip() or f"auto_{datetime.now().timestamp()}"
            frequency = input(f"{Fore.CYAN}Frequency (daily/weekly/hourly): {Style.RESET_ALL}").strip() or "daily"
            target = input(f"{Fore.CYAN}Target network: {Style.RESET_ALL}").strip() or "0.0.0.0/0"
            queries = input(f"{Fore.CYAN}Queries (comma-separated, default: mongodb,redis): {Style.RESET_ALL}").strip().split(",") or ["mongodb", "redis"]
            
            result = scan_scheduler.schedule_scan(scan_id, frequency, target, queries)
            print(f"\n{Fore.LIGHTGREEN_EX}Scheduled: {json.dumps(result, indent=2)}{Style.RESET_ALL}\n")
            
        elif choice == "2":
            jobs = scan_scheduler.get_scheduled_jobs()
            print(f"\n{Fore.LIGHTGREEN_EX}Scheduled Jobs ({len(jobs)}):{Style.RESET_ALL}")
            for job in jobs:
                print(f"  • {job.get('scan_id')} - {job.get('frequency')} - {job.get('status')}")
            print()
            
        elif choice == "3":
            result = scan_scheduler.start_scheduler()
            print(f"\n{Fore.LIGHTGREEN_EX}[✓] {result.get('status')}{Style.RESET_ALL}\n")
            
        elif choice == "4":
            result = scan_scheduler.stop_scheduler()
            print(f"\n{Fore.LIGHTGREEN_EX}[✓] {result.get('status')}{Style.RESET_ALL}\n")
            
        elif choice == "0":
            break
        else:
            print(f"{Fore.LIGHTRED_EX}[✗] Invalid option{Style.RESET_ALL}\n")


def analytics_cli():
    """Risk Analytics & Trending Menu"""
    print_header("Risk Analytics & Trending")
    
    while True:
        print(f"{Fore.YELLOW}Analytics Options:{Style.RESET_ALL}")
        print(f"  1. Vulnerability Trends")
        print(f"  2. Risk Score Trending")
        print(f"  3. Vulnerability Forecast")
        print(f"  0. Back\n")
        
        choice = input(f"{Fore.YELLOW}Select option: {Style.RESET_ALL}").strip()
        
        if choice == "1":
            days = input(f"{Fore.CYAN}Number of days to analyze (default: 30): {Style.RESET_ALL}").strip() or "30"
            result = risk_analyzer.get_vulnerability_trends(int(days))
            print(f"\n{Fore.LIGHTGREEN_EX}Trends:{Style.RESET_ALL}")
            print(json.dumps(result, indent=2))
            print()
            
        elif choice == "2":
            days = input(f"{Fore.CYAN}Number of days (default: 30): {Style.RESET_ALL}").strip() or "30"
            result = risk_analyzer.get_risk_score_trend(int(days))
            print(f"\n{Fore.LIGHTGREEN_EX}Risk Score Trend:{Style.RESET_ALL}")
            print(json.dumps(result, indent=2))
            print()
            
        elif choice == "3":
            days = input(f"{Fore.CYAN}Forecast days (default: 7): {Style.RESET_ALL}").strip() or "7"
            result = risk_analyzer.get_vulnerability_forecast(int(days))
            print(f"\n{Fore.LIGHTGREEN_EX}Forecast:{Style.RESET_ALL}")
            print(json.dumps(result, indent=2))
            print()
            
        elif choice == "0":
            break
        else:
            print(f"{Fore.LIGHTRED_EX}[✗] Invalid option{Style.RESET_ALL}\n")


def metrics_cli():
    """Performance Metrics Menu"""
    print_header("Performance Metrics")
    
    while True:
        print(f"{Fore.YELLOW}Metrics Options:{Style.RESET_ALL}")
        print(f"  1. Scan Performance Metrics")
        print(f"  2. Performance Statistics")
        print(f"  0. Back\n")
        
        choice = input(f"{Fore.YELLOW}Select option: {Style.RESET_ALL}").strip()
        
        if choice == "1":
            result = performance_metrics.get_scan_performance()
            print(f"\n{Fore.LIGHTGREEN_EX}Performance Metrics:{Style.RESET_ALL}")
            print(json.dumps(result, indent=2))
            print()
            
        elif choice == "2":
            result = performance_metrics.get_performance_stats()
            print(f"\n{Fore.LIGHTGREEN_EX}Performance Stats:{Style.RESET_ALL}")
            print(json.dumps(result, indent=2))
            print()
            
        elif choice == "0":
            break
        else:
            print(f"{Fore.LIGHTRED_EX}[✗] Invalid option{Style.RESET_ALL}\n")


def nmap_cli():
    """Nmap Integration Menu"""
    print_header("Nmap Port Scanning")
    
    while True:
        print(f"{Fore.YELLOW}Nmap Options:{Style.RESET_ALL}")
        print(f"  1. Run Port Scan")
        print(f"  2. View Recent Scans")
        print(f"  0. Back\n")
        
        choice = input(f"{Fore.YELLOW}Select option: {Style.RESET_ALL}").strip()
        
        if choice == "1":
            target = input(f"{Fore.CYAN}Target IP or domain: {Style.RESET_ALL}").strip()
            if not target:
                print(f"{Fore.LIGHTRED_EX}[✗] Target required{Style.RESET_ALL}\n")
                continue
            
            ports = input(f"{Fore.CYAN}Port range (default: 1-1000): {Style.RESET_ALL}").strip() or "1-1000"
            aggressive = input(f"{Fore.CYAN}Aggressive scan? (y/n): {Style.RESET_ALL}").strip().lower() == "y"
            
            print(f"\n{Fore.YELLOW}[~] Starting Nmap scan...{Style.RESET_ALL}\n")
            result = nmap_integration.scan_ports(target, ports, aggressive)
            print(f"{Fore.LIGHTGREEN_EX}Scan Result:{Style.RESET_ALL}")
            print(result.get("output", "No output"))
            print()
            
        elif choice == "2":
            limit = input(f"{Fore.CYAN}Number of recent scans (default: 5): {Style.RESET_ALL}").strip() or "5"
            results = nmap_integration.get_scan_results(int(limit))
            print(f"\n{Fore.LIGHTGREEN_EX}Recent Scans ({len(results)}):{Style.RESET_ALL}")
            for r in results:
                print(f"  • {r.get('target')} - {r.get('status')} @ {r.get('timestamp')}")
            print()
            
        elif choice == "0":
            break
        else:
            print(f"{Fore.LIGHTRED_EX}[✗] Invalid option{Style.RESET_ALL}\n")


def main_menu():
    """Main Advanced Features Menu"""
    print(f"""
{Fore.LIGHTGREEN_EX}
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║   🚀 SHODAN VulnScopeX v6.0 - ADVANCED FEATURES CLI 🚀            ║
║                                                                    ║
║   All-in-One: 85+ APIs + Alerts + Analytics + CLI GUI + Nmap      ║
║                    50+ Exploits + Interactive Interface            ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
""")
    
    while True:
        print(f"\n{Fore.CYAN}Advanced Features:{Style.RESET_ALL}")
        print(f"  1. SHODAN API Integration")
        print(f"  2. Alerts & Notifications (Email/Slack)")
        print(f"  3. Scan Scheduling")
        print(f"  4. Risk Analytics & Trending")
        print(f"  5. Performance Metrics")
        print(f"  6. Nmap Port Scanning")
        print(f"  0. Exit\n")
        
        choice = input(f"{Fore.YELLOW}Select feature (0-6): {Style.RESET_ALL}").strip()
        
        if choice == "1":
            shodan_cli()
        elif choice == "2":
            alerts_cli()
        elif choice == "3":
            scheduler_cli()
        elif choice == "4":
            analytics_cli()
        elif choice == "5":
            metrics_cli()
        elif choice == "6":
            nmap_cli()
        elif choice == "0":
            print(f"\n{Fore.LIGHTGREEN_EX}[✓] Goodbye!{Style.RESET_ALL}\n")
            break
        else:
            print(f"{Fore.LIGHTRED_EX}[✗] Invalid option{Style.RESET_ALL}\n")


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Cancelled by user{Style.RESET_ALL}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.LIGHTRED_EX}[✗] Error: {e}{Style.RESET_ALL}\n")
        sys.exit(1)
