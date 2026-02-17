#!/usr/bin/env python3
"""
SHODAN VulnScopeX v6.0 - Advanced Modules Launcher
Master controller for all 7 advanced analysis modules + v6.0 enhancements
"""

import os
import sys
import subprocess
from pathlib import Path
from colorama import init, Fore, Style

init(autoreset=True)

def print_banner():
    print(f"""
{Fore.LIGHTCYAN_EX}
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║     🚀 SHODAN VulnScopeX v6.0 - ADVANCED MODULES LAUNCHER 🚀       ║
║                                                                    ║
║           Choose Your Advanced Security Analysis Tool              ║
║              v6.0 with 85+ APIs + 50+ Exploits + CLI GUI           ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
    """)

def check_module(module_name, file_path):
    """Check if module file exists"""
    return Path(file_path).exists()

def launch_module(module_name, file_path):
    """Launch a specific module"""
    if not check_module(module_name, file_path):
        print(f"{Fore.RED}[✗] Module not found: {file_path}{Style.RESET_ALL}\n")
        return
    
    print(f"{Fore.LIGHTGREEN_EX}[✓] Launching {module_name}...{Style.RESET_ALL}\n")
    
    try:
        subprocess.run([sys.executable, file_path], check=False)
    except Exception as e:
        print(f"{Fore.RED}[✗] Error launching module: {e}{Style.RESET_ALL}\n")

def show_modules():
    """Show available modules"""
    modules = [
        ("🔐 Cryptographic Vulnerabilities Analysis", "crypto_module.py"),
        ("💣 Advanced Exploitation Module", "exploitation_module.py"),
        ("🧠 Memory & Code Injection Analysis", "memory_module.py"),
        ("🌐 Network-Level Attacks Module", "network_module.py"),
        ("🔑 Privilege Escalation Advanced Module", "privilege_module.py"),
        ("🔎 Advanced Reconnaissance Module", "reconnaissance_module.py"),
        ("🕸️  Advanced Web Applications Module", "webapp_module.py")
    ]
    
    return modules

def main():
    print_banner()
    
    modules = show_modules()
    
    print(f"{Fore.CYAN}Available Advanced Modules:\n{Style.RESET_ALL}")
    
    for i, (name, _) in enumerate(modules, 1):
        print(f"  {i}. {name}")
    
    print(f"\n  {Fore.YELLOW}0. Exit{Style.RESET_ALL}\n")
    
    while True:
        try:
            choice = input(f"{Fore.YELLOW}Select module [0-7]: {Style.RESET_ALL}").strip()
            
            if choice == "0":
                print(f"\n{Fore.LIGHTGREEN_EX}[✓] Goodbye!{Style.RESET_ALL}\n")
                break
            elif choice in [str(i) for i in range(1, 8)]:
                idx = int(choice) - 1
                module_name, module_file = modules[idx]
                launch_module(module_name, module_file)
                
                # Show menu again after module closes
                print_banner()
                print(f"{Fore.CYAN}Available Advanced Modules:\n{Style.RESET_ALL}")
                for i, (name, _) in enumerate(modules, 1):
                    print(f"  {i}. {name}")
                print(f"\n  {Fore.YELLOW}0. Exit{Style.RESET_ALL}\n")
            else:
                print(f"{Fore.RED}[!] Invalid option. Please try again.{Style.RESET_ALL}\n")
                
        except KeyboardInterrupt:
            print(f"\n\n{Fore.LIGHTYELLOW_EX}[!] Launcher interrupted by user{Style.RESET_ALL}\n")
            break
        except Exception as e:
            print(f"{Fore.RED}[✗] Error: {e}{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
