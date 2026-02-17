#!/usr/bin/env python3
"""
SHODAN VulnScopeX v6.0 - Complete Setup & Installation Script
Installs dependencies, initializes database, validates all components + v6.0 enhancements
"""

import os
import sys
import subprocess
import sqlite3
from pathlib import Path
from colorama import init, Fore, Style

init(autoreset=True)

def print_header(text):
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}{Style.RESET_ALL}\n")

def print_success(text):
    print(f"{Fore.LIGHTGREEN_EX}✓ {text}{Style.RESET_ALL}")

def print_error(text):
    print(f"{Fore.LIGHTRED_EX}✗ {text}{Style.RESET_ALL}")

def print_warning(text):
    print(f"{Fore.LIGHTYELLOW_EX}⚠ {text}{Style.RESET_ALL}")

def print_info(text):
    print(f"{Fore.LIGHTBLUE_EX}ℹ {text}{Style.RESET_ALL}")

def check_python_version():
    """Ensure Python 3.8+ is installed"""
    print_info(f"Python version: {sys.version.split()[0]}")
    if sys.version_info < (3, 8):
        print_error("Python 3.8+ required")
        sys.exit(1)
    print_success("Python version check passed")

def install_dependencies():
    """Install required packages from requirements.txt"""
    print_header("INSTALLING DEPENDENCIES")
    
    req_file = Path("requirements.txt")
    if not req_file.exists():
        print_error("requirements.txt not found")
        return False
    
    try:
        print_info("Installing packages from requirements.txt...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "-q", "--break-system-packages"],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode == 0:
            print_success("All dependencies installed successfully")
            return True
        else:
            print_error(f"Installation failed: {result.stderr}")
            return False
    except Exception as e:
        print_error(f"Error installing dependencies: {e}")
        return False

def verify_imports():
    """Verify all required imports work"""
    print_header("VERIFYING IMPORTS")
    
    required_modules = {
        'shodan': 'SHODAN API',
        'flask': 'Flask Web Framework',
        'flask_cors': 'CORS Support',
        'requests': 'HTTP Requests',
        'colorama': 'Terminal Colors',
        'emoji': 'Emoji Support',
        'sqlite3': 'Database'
    }
    
    all_ok = True
    for module, description in required_modules.items():
        try:
            __import__(module)
            print_success(f"{description} ({module})")
        except ImportError as e:
            print_error(f"{description} ({module}): {e}")
            all_ok = False
    
    return all_ok

def initialize_database():
    """Initialize SQLite database with required tables"""
    print_header("INITIALIZING DATABASE")
    
    scan_results_dir = Path("scan_results")
    scan_results_dir.mkdir(exist_ok=True)
    
    db_file = scan_results_dir / "vulnerabilities.db"
    
    try:
        conn = sqlite3.connect(str(db_file))
        cursor = conn.cursor()
        
        # Create vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip TEXT UNIQUE,
                port INTEGER,
                organization TEXT,
                country TEXT,
                city TEXT,
                service TEXT,
                version TEXT,
                cve_ids TEXT,
                vulnerabilities_count INTEGER DEFAULT 0,
                risk_level TEXT,
                risk_score REAL,
                os TEXT,
                hostname TEXT,
                isp TEXT,
                asn TEXT,
                http_code INTEGER,
                ssl_cert TEXT,
                tags TEXT
            )
        ''')
        
        # Create assets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                name TEXT UNIQUE,
                type TEXT,
                status TEXT,
                risk_score REAL,
                owner TEXT,
                description TEXT
            )
        ''')
        
        # Create scan_history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                query TEXT,
                total_results INTEGER,
                vulnerabilities_found INTEGER,
                scan_duration REAL
            )
        ''')
        
        # Create threat_intelligence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source TEXT,
                threat_type TEXT,
                severity TEXT,
                description TEXT,
                mitigation TEXT
            )
        ''')
        
        # Create api_usage table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                endpoint TEXT,
                status_code INTEGER,
                response_time REAL
            )
        ''')
        
        # Create audit_log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user TEXT,
                action TEXT,
                resource TEXT,
                details TEXT
            )
        ''')
        
        # Create exports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS exports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                export_type TEXT,
                file_path TEXT,
                record_count INTEGER,
                status TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        
        print_success(f"Database initialized: {db_file}")
        return True
    except Exception as e:
        print_error(f"Database initialization failed: {e}")
        return False

def verify_file_structure():
    """Verify all required files and directories exist"""
    print_header("VERIFYING FILE STRUCTURE")
    
    required_files = {
        'start_premium.py': 'CLI Launcher',
        'scanner_premium.py': 'CLI Scanner',
        'requirements.txt': 'Dependencies',
        'README.md': 'Documentation',
        'app/premium_live.py': 'Flask Server',
        'app/config.py': 'Configuration',
        'app/templates/premium_dashboard.html': 'Dashboard Template',
        'app/static/script.js': 'JavaScript Handler',
        'app/static/style.css': 'CSS Styling',
    }
    
    all_exist = True
    for filepath, description in required_files.items():
        path = Path(filepath)
        if path.exists():
            print_success(f"{description}: {filepath}")
        else:
            print_error(f"{description} missing: {filepath}")
            all_exist = False
    
    # Check directories
    required_dirs = ['app', 'app/templates', 'app/static', 'scan_results']
    for dirname in required_dirs:
        Path(dirname).mkdir(exist_ok=True)
    
    return all_exist

def test_shodan_api():
    """Test SHODAN API key"""
    print_header("TESTING SHODAN API")
    
    try:
        import shodan
        api_key = os.getenv("SHODAN_API_KEY", "test_api_key_demo_mode")
        api = shodan.Shodan(api_key)
        
        try:
            account_info = api.info()
            print_success("SHODAN API connection successful")
            print_info(f"Account Credits: {account_info.get('credits', 'N/A')}")
            return True
        except shodan.exception.APIError as e:
            if "Invalid" in str(e):
                print_warning(f"API key may be invalid: {e}")
                print_info("Using demo mode - replace SHODAN_API_KEY environment variable for full access")
                return True
            else:
                print_error(f"API Error: {e}")
                return False
    except Exception as e:
        print_error(f"SHODAN API test failed: {e}")
        return False

def create_env_file():
    """Create .env file with configuration"""
    print_header("CREATING ENVIRONMENT FILE")
    
    env_content = """# SHODAN VulnScopeX v5.0 Configuration
# Set your SHODAN API key here (TEST MODE - Replace with your actual API key)
SHODAN_API_KEY=test_api_key_demo_mode_replace_with_yours

# Flask Configuration
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_DEBUG=False

# Scanner Configuration
SCANNER_THREADS=10
SCANNER_TIMEOUT=30
SCANNER_RETRIES=3

# Database
DB_PATH=scan_results/vulnerabilities.db
CACHE_PATH=scan_results/cache.json

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/app.log
"""
    
    try:
        env_file = Path(".env")
        env_file.write_text(env_content)
        print_success(".env file created")
        return True
    except Exception as e:
        print_error(f"Failed to create .env file: {e}")
        return False

def create_run_script():
    """Create convenient run scripts"""
    print_header("CREATING RUN SCRIPTS")
    
    # Windows batch script
    batch_content = """@echo off
REM SHODAN VulnScopeX v5.0 - Windows Launcher
cd /d "%~dp0"
python start_premium.py %*
pause
"""
    
    # Unix/Linux shell script
    shell_content = """#!/bin/bash
# SHODAN VulnScopeX v5.0 - Unix/Linux Launcher
cd "$(dirname "$0")"
python3 start_premium.py "$@"
"""
    
    try:
        # Create batch file
        Path("run.bat").write_text(batch_content)
        print_success("Created run.bat (Windows launcher)")
        
        # Create shell script
        Path("run.sh").write_text(shell_content)
        os.chmod("run.sh", 0o755)
        print_success("Created run.sh (Unix/Linux launcher)")
        
        return True
    except Exception as e:
        print_error(f"Failed to create run scripts: {e}")
        return False

def show_next_steps():
    """Display next steps for the user"""
    print_header("SETUP COMPLETE")
    
    print(f"""
{Fore.LIGHTGREEN_EX}✓ Installation completed successfully!{Style.RESET_ALL}

{Fore.LIGHTCYAN_EX}NEXT STEPS:{Style.RESET_ALL}

1. {Fore.YELLOW}Start the Web UI + REST API Server:{Style.RESET_ALL}
   python start_premium.py
   → Select option 1 (Web UI + REST API Server)
   → Open browser to http://localhost:5000

2. {Fore.YELLOW}Run CLI Scanner:{Style.RESET_ALL}
   python start_premium.py
   → Select option 2 (CLI Scanner)
   → Enter search query and start scanning

3. {Fore.YELLOW}View API Documentation:{Style.RESET_ALL}
   python start_premium.py
   → Select option 3 (API Documentation)

{Fore.LIGHTBLUE_EX}QUICK START COMMANDS:{Style.RESET_ALL}
   • Windows: run.bat
   • Unix/Linux: ./run.sh
   • Direct: python start_premium.py

{Fore.LIGHTBLUE_EX}CONFIGURATION:{Style.RESET_ALL}
   • Edit .env file to customize settings
   • Set SHODAN_API_KEY for full API access
   • Configure Flask host/port for web server

{Fore.LIGHTBLUE_EX}DOCUMENTATION:{Style.RESET_ALL}
   • See README.md for detailed features
   • Visit github.com/mohidqx/VulnScopeX for updates

{Fore.LIGHTYELLOW_EX}Enjoy VulnScopeX! 🚀{Style.RESET_ALL}
""")

def main():
    print(f"\n{Fore.LIGHTCYAN_EX}")
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║                 SHODAN VulnScopeX v5.0 Setup Wizard                ║")
    print("║              Complete Installation & Configuration                 ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print(f"{Style.RESET_ALL}")
    
    steps = [
        ("Checking Python Version", check_python_version),
        ("Verifying File Structure", verify_file_structure),
        ("Installing Dependencies", install_dependencies),
        ("Verifying Imports", verify_imports),
        ("Initializing Database", initialize_database),
        ("Testing SHODAN API", test_shodan_api),
        ("Creating Configuration", create_env_file),
        ("Creating Run Scripts", create_run_script),
    ]
    
    failed = []
    
    for step_name, step_func in steps:
        try:
            if not step_func():
                failed.append(step_name)
        except Exception as e:
            print_error(f"{step_name} failed: {e}")
            failed.append(step_name)
    
    print_header("SETUP SUMMARY")
    
    if failed:
        print_warning(f"Setup completed with {len(failed)} issue(s):")
        for step in failed:
            print(f"  • {step}")
        print_info("Please review the errors above and try again")
    else:
        print_success("All setup steps completed successfully!")
        show_next_steps()
    
    return 0 if not failed else 1

if __name__ == "__main__":
    sys.exit(main())
