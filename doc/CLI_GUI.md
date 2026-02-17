# 🖥️ CLI GUI INTERFACE GUIDE (v6.0)

**Interactive Terminal User Interface for VulnScopeX**

---

## 🎯 OVERVIEW

The v6.0 CLI GUI provides an interactive, user-friendly terminal interface for security researchers and penetration testers. Features a modern menu system, real-time progress visualization, and color-coded severity levels.

---

## 🚀 LAUNCHING CLI GUI

### Method 1: Direct Launch
```bash
python scanner_premium.py
```

### Method 2: Start Premium (with dashboard)
```bash
python start_premium.py
```

### Method 3: CLI-Only Mode
```bash
python scanner_premium.py --cli-only
```

### Method 4: Interactive Mode
```bash
python scanner_premium.py --interactive
```

---

## 📋 MAIN MENU

```
╔═══════════════════════════════════════════════════════════╗
║         VulnScopeX v6.0 - Security Scanner              ║
║              CLI GUI Terminal Interface                   ║
╚═══════════════════════════════════════════════════════════╝

[1] 🔍 SCANNER
    ├─ Start New Scan
    ├─ Resume Previous Scan
    ├─ View Scan History
    └─ Scan Settings

[2] 🎯 VULNERABILITY MANAGEMENT
    ├─ List Vulnerabilities
    ├─ Create Vulnerability
    ├─ Update Vulnerability
    ├─ Delete Vulnerability
    ├─ Search/Filter
    └─ Bulk Operations

[3] 📊 ANALYSIS & REPORTING
    ├─ Generate Reports
    ├─ View Statistics
    ├─ Trend Analysis
    ├─ CVSS Analysis
    └─ Risk Assessment

[4] 🏢 ASSET MANAGEMENT
    ├─ View Assets
    ├─ Add Asset
    ├─ Update Asset
    ├─ Asset Discovery
    └─ Asset Inventory

[5] ⚙️ DETECTION RULES
    ├─ List Rules
    ├─ Create Rule
    ├─ Edit Rule
    ├─ Delete Rule
    └─ Rule Templates

[6] 💣 PAYLOADS
    ├─ View Payloads
    ├─ Generate Payload
    ├─ Payload Templates
    ├─ Test Payload
    └─ Payload Encoding

[7] 🔗 INTEGRATIONS
    ├─ SHODAN Integration
    ├─ Email Alerts
    ├─ Slack Notifications
    ├─ Webhook Setup
    └─ API Configuration

[8] 📤 EXPORT & IMPORT
    ├─ Export as CSV
    ├─ Export as JSON
    ├─ Export as PDF
    ├─ Export as Excel
    ├─ Import Vulnerabilities
    └─ Batch Import

[9] ⚡ ADVANCED FEATURES
    ├─ Exploit Chaining
    ├─ Privilege Escalation
    ├─ Lateral Movement
    ├─ Zero-Day Detection
    └─ Memory Analysis

[0] 🚪 EXIT

Choose option (0-9):
```

---

## 🔍 SCANNER MENU

### Start New Scan
```
╔════════════════════════════════════╗
║       Start New Vulnerability     ║
║              Scan                  ║
╚════════════════════════════════════╝

Target (IP/Domain/Range): 192.168.1.0/24
Scan Type [network/web/all]: network
Number of Threads [1-100]: 50
Timeout (seconds) [10-3600]: 300
Include Deep Scan [y/n]: y

Scanning: 192.168.1.0/24 [████████░░] 45% | ETA: 2m 15s
Found: 23 vulnerabilities | 45 ports scanned | 8 services detected

Status:
  ✓ Network sweep completed
  ✓ Port scanning in progress
  ✓ Service detection: 8/10
  ○ Vulnerability analysis: pending

Continue scanning [y/n]? y
```

### Scan History
```
╔══════════════════════════════════════════════════╗
║        Recent Scan History (Last 10)             ║
╚══════════════════════════════════════════════════╝

[1] scan_20260217_120000 | 192.168.1.0/24 | 45 vulns | ▼ 3 CRITICAL
[2] scan_20260216_180000 | 10.0.0.0/8    | 127 vulns | ▼ 8 CRITICAL
[3] scan_20260216_090000 | example.com   | 12 vulns  | ▼ 1 CRITICAL
[4] scan_20260215_150000 | api.local     | 5 vulns   | ▲ 0 CRITICAL
[5] scan_20260214_220000 | db.local      | 18 vulns  | ▼ 2 CRITICAL

View details [1-5] or [0] back: 1

────────────────────────────────────────
Scan Details: scan_20260217_120000
────────────────────────────────────────
Target:         192.168.1.0/24
Type:           Network
Start Time:     2024-02-17 12:00:00
End Time:       2024-02-17 12:45:30
Duration:       45m 30s
Threads:        50

Results:
  ✓ Total Vulnerabilities: 45
  ✓ Critical (CVSS 9+): 3
  ✓ High (CVSS 7-8.9): 8
  ✓ Medium (CVSS 4-6.9): 22
  ✓ Low (CVSS 0-3.9): 12

View details [y/n]? y
```

---

## 🎯 VULNERABILITY MANAGEMENT

### List Vulnerabilities
```
╔═══════════════════════════════════════════════════════════╗
║         Vulnerabilities (Showing 10 of 180)               ║
╚═══════════════════════════════════════════════════════════╝

ID  | Title                          | Severity  | Status
────┼────────────────────────────────┼───────────┼──────────
1   | Remote Code Execution          | 🔴 CRITIC | unverified
2   | SQL Injection in Login          | 🔴 CRITIC | verified
3   | XSS in Search Form              | 🟠 HIGH   | verified
4   | Weak Cipher Suites              | 🟠 HIGH   | unverified
5   | Missing Security Headers        | 🟡 MEDIUM | verified
6   | Exposed API Keys                | 🟠 HIGH   | critical
7   | Default Credentials Found       | 🔴 CRITIC | verified
8   | Privilege Escalation            | 🟠 HIGH   | unverified
9   | Insecure Deserialization        | 🟠 HIGH   | verified
10  | Directory Traversal             | 🟡 MEDIUM | unverified

More results [y/n]? y
Filter by severity [C/H/M/L/all]: C

Filtered: 5 CRITICAL vulnerabilities
Priority Sort [newest/highest-severity/unverified]: highest-severity
```

### Create Vulnerability
```
╔════════════════════════════════════╗
║   Create New Vulnerability Entry   ║
╚════════════════════════════════════╝

Title: Remote Code Execution via Command Injection
Description: User input not sanitized in /admin/execute endpoint
CVE ID (optional): CVE-2024-5678
Severity [C/H/M/L]: C
Target (IP/Domain): 192.168.1.100:8080
CWE ID (optional): CWE-78
CVSS Score (optional): 9.8
Status [unverified/verified/critical]: verified
Tags (comma-separated): rce,command-injection,web

Proof of Concept (POC):
curl -X GET "http://192.168.1.100:8080/admin/execute?cmd=$(whoami)"
```

---

## 📊 ANALYSIS & REPORTING

### Generate Report
```
╔════════════════════════════════════╗
║      Generate Security Report      ║
╚════════════════════════════════════╝

Report Type:
[1] Executive Summary
[2] Detailed Technical Report
[3] Risk Assessment
[4] Compliance Report (PCI/HIPAA/SOC2)
[5] Custom Report

Selection [1-5]: 1

Export Format:
[1] PDF (with charts)
[2] DOCX (editable)
[3] HTML (interactive)
[4] JSON (structured)

Selection [1-4]: 1

Report Title: Security Audit - Q1 2024
Include Assets [y/n]: y
Include Trends [y/n]: y
Sensitive Data [y/n]: n

Generating report... ████████████████ 100%

Report saved to: scan_results/Security_Audit_Q1_2024.pdf
```

### Vulnerability Statistics
```
╔═══════════════════════════════════════╗
║    Vulnerability Statistics          ║
╚═══════════════════════════════════════╝

Total Vulnerabilities:            180
├─ Critical (CVSS 9-10):          12  🔴 6.7%
├─ High (CVSS 7-8.9):             45  🟠 25%
├─ Medium (CVSS 4-6.9):           78  🟡 43.3%
└─ Low (CVSS 0-3.9):              45  🟢 25%

Status Breakdown:
├─ Verified:                     145 (80.6%)
├─ Unverified:                    28 (15.6%)
└─ Critical/Ongoing:               7 (3.9%)

Most Common Weaknesses:
1. Weak Cryptography           (23)
2. SQL Injection                (18)
3. XSS Vulnerabilities          (15)
4. Privilege Escalation         (12)
5. Default Credentials          (11)

Severity Trend (Last 30 days):
Date        | Critical | High | Medium | Low
────────────┼──────────┼──────┼────────┼─────
2024-02-17  |    12    |  45  |   78   |  45
2024-02-10  |    10    |  42  |   75   |  48
2024-02-03  |     8    |  38  |   70   |  50
Trend:      |    ↑     |  ↑   |   ↑    |  ↓
```

---

## 🏢 ASSET MANAGEMENT

### Asset Discovery
```
╔════════════════════════════════════╗
║      Asset Discovery Scan          ║
╚════════════════════════════════════╝

Network Range: 192.168.0.0/16
Scan Type [quick/thorough/aggressive]: thorough
Include Services [y/n]: y
Include OS Detection [y/n]: y
Include Geolocation [y/n]: y

Scanning... ████████████████░░ 80% | Found: 142 assets | ETA: 1m 30s

Assets Discovered:
─────────────────────────────────────────────
IP Address      | OS              | Services
─────────────────────────────────────────────
192.168.1.1     | Cisco IOS       | SSH, HTTP
192.168.1.10    | Windows 2019    | SMB, WinRM, RDP
192.168.1.20    | Ubuntu 20.04    | SSH, HTTP(S)
192.168.1.25    | CentOS 8        | SSH, MySQL
192.168.1.30    | macOS 11        | SSH, HTTP
192.168.2.100   | Nginx           | HTTP(S)
192.168.2.101   | Apache          | HTTP(S)
...

Save assets to inventory [y/n]? y
Saved 142 assets to database
```

---

## ⚡ ADVANCED FEATURES

### Exploit Chaining
```
╔════════════════════════════════════╗
║     Exploit Chain Builder          ║
╚════════════════════════════════════╝

Target: 192.168.1.100
Discovered Vulnerabilities:
  [1] SQL Injection (CVSS 9.1)
  [2] Weak Session Management (CVSS 7.5)
  [3] Insufficient Logging (CVSS 6.5)

Chain Path Analysis:
  Step 1: SQL Injection
    └─→ Extract credentials
         └─→ Step 2: Weak Sessions
              └─→ Session hijacking
                   └─→ Step 3: RCE
                        └─→ Full compromise

Viability: ✓ LIKELY (87% confidence)
Impact: 🔴 CRITICAL
Estimated Time: 2-4 hours

Execute chain [y/n]? n
```

### Privilege Escalation Hunting
```
╔════════════════════════════════════╗
║ Privilege Escalation Hunter        ║
╚════════════════════════════════════╝

Target: 192.168.1.50 (Linux)
Current Access: www-data

Scanning for escalation vectors...
████████████████░░ 75% | Found: 8 paths

Escalation Paths Found:
────────────────────────────────
[1] SUID Binary Misconfiguration
    /usr/bin/sudo - privilege escalation possible
    Confidence: ✓✓✓ HIGH

[2] Sudo Rules Misconfig
    www-data can run /usr/bin/find without password
    Confidence: ✓✓✓ HIGH

[3] Capabilities Abuse
    cap_setuid+ep on /usr/bin/ping
    Confidence: ✓✓ MEDIUM

[4] Kernel Exploit
    CVE-2021-22555 (eBPF overflow)
    Confidence: ✓✓ MEDIUM

[5] Cron Job Insecurity
    /var/spool/cron/crontabs/root - world writable
    Confidence: ✓✓✓ HIGH

Recommended: [1] (easiest, fastest)
Execute [1-5] or [0] skip? 1

Escalating privileges... ████████░░ 60%
Root shell obtained! ✓
```

---

## 📤 EXPORT/IMPORT

### Export Vulnerabilities
```
╔════════════════════════════════════╗
║   Export Vulnerabilities           ║
╚════════════════════════════════════╝

Format:
[1] CSV (Excel compatible)
[2] JSON (API integration)
[3] PDF (Report format)
[4] XLSX (Advanced Excel)
[5] XML (Enterprise systems)

Selection [1-5]: 1

Include fields:
  ✓ Title
  ✓ Severity
  ✓ CVE
  ✓ Description
  ✓ Remediation
  ○ POC
  ○ Internal Notes

Filter:
  Severity: ALL
  Status: All
  Date Range: Last 30 days

Exporting 180 vulnerabilities...
████████████████ 100%

File saved: scan_results/vulns_export_20240217.csv (245 KB)
```

### Batch Import
```
╔════════════════════════════════════╗
║   Batch Import Vulnerabilities     ║
╚════════════════════════════════════╝

Import file: vulns_from_nessus.csv
File type: CSV
File size: 1.2 MB
Rows: 456

Preview (first 5):
  1. Heartbleed (OpenSSL)
  2. Shellshock (Bash)
  3. Weak SSL Ciphers
  4. Missing Patches
  5. Default Credentials

Validation:
  ✓ All rows valid
  ✓ 0 duplicates detected
  ✓ 0 missing required fields

Import options:
  [1] Add all (merge duplicates)
  [2] Update existing (latest wins)
  [3] Skip duplicates

Selection [1-3]: 1

Importing... ████████████████ 100%
Successfully imported 456 vulnerabilities
```

---

## 🎨 COLORS & SYMBOLS

### Severity Indicators
```
🔴 CRITICAL    (CVSS 9-10)   - Immediate action required
🟠 HIGH        (CVSS 7-8.9)  - High priority
🟡 MEDIUM      (CVSS 4-6.9)  - Medium priority
🟢 LOW         (CVSS 0-3.9)  - Low priority
⚪ INFO        (No score)    - Informational
```

### Status Indicators
```
✓  Verified       - Confirmed vulnerability
✗  Unverified    - Needs confirmation
⚠  Critical      - Active exploitation
○  Pending       - In progress
```

### Progress Bars
```
████████████████░░ 80%  - In progress
████████████████████ 100% - Complete
```

---

## ⌨️ KEYBOARD SHORTCUTS

| Shortcut | Action |
|----------|--------|
| `Ctrl+C` | Cancel current operation |
| `Ctrl+S` | Save/Export results |
| `Ctrl+F` | Search/Filter |
| `Ctrl+H` | Show history |
| `Ctrl+Q` | Quit application |
| `Up/Down` | Navigate menu |
| `Page Up/Dn` | Scroll results |
| `Home/End` | First/Last result |

---

## 🔧 ADVANCED OPTIONS

### Command-Line Flags
```bash
# CLI-only mode (no web interface)
python scanner_premium.py --cli-only

# Interactive mode
python scanner_premium.py --interactive

# Quiet mode
python scanner_premium.py --quiet

# Verbose/Debug output
python scanner_premium.py --verbose

# Specific scan type
python scanner_premium.py --scan-type network

# Define target
python scanner_premium.py --target 192.168.1.0/24

# Number of threads
python scanner_premium.py --threads 50

# Output to file
python scanner_premium.py --output results.csv

# Load config file
python scanner_premium.py --config config.json
```

---

## 🐛 TROUBLESHOOTING CLI

### Issue: Colors not showing
```bash
# Enable ANSI colors
export FORCE_COLOR=1
python scanner_premium.py

# Or use:
python scanner_premium.py --force-color
```

### Issue: Menu not displaying correctly
```bash
# Resize terminal to minimum 80x24
# Or use:
python scanner_premium.py --simple-ui
```

### Issue: Slow performance
```bash
# Reduce threads
python scanner_premium.py --threads 10

# Or use:
python scanner_premium.py --lite-mode
```

---

## 📚 Related Documentation

- [APIs Reference](APIs.md)
- [Installation Guide](INSTALLATION.md)
- [Quick Start](QUICKSTART.md)
- [Configuration](CONFIGURATION.md)
