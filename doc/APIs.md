# 📡 COMPLETE API REFERENCE (85+ ENDPOINTS)

**VulnScopeX v6.0 - Enterprise REST API**

---

## 🌐 BASE URL

```
http://localhost:5000/api/v4/
```

**Authentication:** Include API key in headers or environment

---

## 📊 API STATISTICS

| Category | Endpoints | Key Features |
|----------|-----------|--------------|
| **CRUD Operations** | 15+ | Create, Read, Update, Delete vulnerabilities, assets, rules |
| **Threat Intelligence** | 10+ | CVE lookup, exploit database, payloads, trending threats |
| **Analysis & Reporting** | 12+ | Stats, CVSS analysis, trends, report generation |
| **Scanning Operations** | 8+ | Start, stop, pause, resume, stream results |
| **Export Formats** | 4+ | CSV, JSON, PDF, Excel |
| **Advanced Exploitation** | 25+ | Exploit chains, privilege escalation, lateral movement |
| **Cryptography** | 15+ | SSL analysis, weak ciphers, key extraction, side-channel |
| **Web Application Security** | 12+ | SQLI, injection attacks, SSRF, GraphQL, API keys |
| **Network Security** | 15+ | DNS spoofing, BGP hijacking, DDoS, fragmentation |
| **System Exploitation** | 15+ | Kernel exploits, driver analysis, UAC bypass, SUID |
| **Reconnaissance** | 10+ | DNS intelligence, fingerprinting, web crawling, subdomains |
| **SHODAN Integration** | 5+ | Direct SHODAN queries, host details, account info |
| **Alerts & Notifications** | 4+ | Email, Slack alerts, history |
| **Scheduler** | 4+ | Schedule scans, manage jobs |
| **Analytics & Monitoring** | 5+ | Trends, risk scoring, performance metrics |

**Total: 85+ endpoints covering all security research needs**

---

## 🔧 CRUD OPERATIONS (15+ ENDPOINTS)

### Vulnerabilities

#### Create Vulnerability
```http
POST /vulns
Content-Type: application/json

{
  "title": "XSS in Login Form",
  "description": "Reflected XSS vulnerability",
  "cve": "CVE-2024-1234",
  "severity": "HIGH",
  "target": "example.com"
}
```

#### List All Vulnerabilities
```http
GET /vulns
```

#### Get Specific Vulnerability
```http
GET /vulns/<vuln_id>
```

#### Search Vulnerabilities
```http
GET /vulns/search?query=XSS&limit=50
```

#### Filter Vulnerabilities
```http
POST /vulns/filter
{
  "severity": "CRITICAL",
  "status": "open",
  "tags": ["web", "xss"]
}
```

#### Update Vulnerability
```http
PUT /vulns/<vuln_id>
{
  "severity": "MEDIUM",
  "status": "verified"
}
```

#### Update Priority
```http
PATCH /vulns/<vuln_id>/priority
{
  "priority": 1
}
```

#### Update Tags
```http
PUT /vulns/<vuln_id>/tags
{
  "tags": ["critical", "network", "rce"]
}
```

#### Mark as Duplicate
```http
POST /vulns/duplicate
{
  "original_id": 123,
  "duplicate_id": 124
}
```

#### Escalate Vulnerability
```http
POST /vulns/escalate
{
  "vuln_id": 123,
  "new_severity": "CRITICAL"
}
```

#### Add POC (Proof of Concept)
```http
PUT /vulns/<vuln_id>/POC
{
  "poc": "curl http://target.com/?search=<script>alert(1)</script>"
}
```

#### Add Remediation
```http
PUT /vulns/<vuln_id>/remediation
{
  "steps": ["Update to version 2.5.1", "Restart service"]
}
```

#### Delete Vulnerability
```http
DELETE /vulns/<vuln_id>
```

#### Bulk Delete
```http
POST /vulns/batch/delete
{
  "ids": [1, 2, 3, 4, 5]
}
```

#### Delete by Priority
```http
DELETE /vulns/delete-by-priority?priority=LOW
```

#### Rescan Vulnerability
```http
POST /vulns/rescan
{
  "vuln_id": 123
}
```

---

## 🏢 ASSET MANAGEMENT (5+ ENDPOINTS)

#### Add Asset
```http
POST /assets/add
{
  "ip": "192.168.1.1",
  "hostname": "server1.local",
  "os": "Windows Server 2019"
}
```

#### List All Assets
```http
GET /assets
```

#### Get Asset Details
```http
GET /assets/<ip_addr>
```

#### Update Asset
```http
PUT /assets/<ip_addr>
{
  "status": "patched",
  "notes": "Updated remediation"
}
```

#### Delete Asset
```http
DELETE /assets/<ip_addr>
```

---

## ⚡ THREAT INTELLIGENCE (10+ ENDPOINTS)

#### Exploit Database
```http
GET /threat/exploit-db?keyword=wordpress&limit=10
```

#### Default Credentials Database
```http
GET /threat/default-creds?service=jenkins
```

#### Generate Payloads
```http
POST /threat/payloads
{
  "type": "reverse_shell",
  "target_os": "Windows",
  "format": "powershell"
}
```

#### CVE Lookup
```http
GET /threat/cve-lookup?cve=CVE-2021-44228&details=true
```

#### Risk Assessment
```http
POST /threat/risk-assessment
{
  "target": "example.com",
  "services": ["http", "ssh", "smtp"]
}
```

#### Affected Services by CVE
```http
GET /threat/affected-services?cve=CVE-2024-1234
```

#### Mitigation Strategies
```http
GET /threat/mitigations?cve=CVE-2024-1234
```

#### Trending Threats
```http
GET /threat/trending?days=30
```

---

## 📈 ANALYSIS & REPORTING (12+ ENDPOINTS)

#### Vulnerability Statistics
```http
GET /analyze/stats
```

#### CVSS Analysis
```http
POST /analyze/cvss
{
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
}
```

#### Trend Analysis
```http
GET /analyze/trends?days=30
```

#### Summary Report
```http
GET /analyze/report/summary
```

#### Affected Hosts
```http
GET /analyze/affected-hosts?cve=CVE-2024-1234
```

#### Activity Logs
```http
GET /logs?limit=100
```

#### Filter Logs
```http
POST /logs/filter
{
  "action": "CREATE",
  "date_from": "2024-01-01",
  "date_to": "2024-12-31"
}
```

#### Clear Logs
```http
DELETE /logs/clear?older_than=90
```

#### Audit Export
```http
GET /audit/export?format=json
```

---

## 📤 EXPORT FORMATS (4 ENDPOINTS)

#### Export as CSV
```http
GET /export/csv?vuln_ids=1,2,3
```

#### Export as JSON
```http
GET /export/json?format=detailed
```

#### Export as PDF
```http
GET /export/pdf?report_type=executive_summary
```

#### Export as Excel
```http
GET /export/excel?include_stats=true
```

---

## 🔍 SCANNER OPERATIONS (8+ ENDPOINTS)

#### Start Scan
```http
POST /scan/start
{
  "target": "192.168.1.0/24",
  "type": "network",
  "threads": 50
}
```

#### Stream Results (Real-Time)
```http
GET /scan/stream
```

#### Get Statistics
```http
GET /scan/stats
```

#### Stop Scan
```http
POST /scan/stop
```

#### Pause Scan
```http
POST /scan/pause
```

#### Resume Scan
```http
POST /scan/resume
```

#### Load Queries
```http
POST /queries/load
{
  "file": "paths.txt"
}
```

#### Query Categories
```http
GET /queries/categories
```

#### Schedule Scan
```http
POST /scan/schedule
{
  "target": "example.com",
  "frequency": "daily",
  "time": "02:00"
}
```

---

## 🎯 ADVANCED EXPLOITATION (25+ ENDPOINTS)

### Exploitation Chain
```http
POST /exploit/chain
{
  "target": "192.168.1.100",
  "vulnerabilities": [1, 2, 3]
}
```

### Privilege Escalation
```http
POST /privilege-escalation/hunt
{
  "target": "windows_system",
  "search_depth": 3
}
```

### Lateral Movement
```http
POST /lateral-movement/map
{
  "entry_point": "compromised_host",
  "target_network": "10.0.0.0/8"
}
```

### Vulnerability Chaining
```http
POST /vulnerabilities/chain
{
  "vulns": [1, 2, 3],
  "path_analysis": true
}
```

### Attack Surface Mapping
```http
POST /attack-surface/map
{
  "target": "192.168.1.100",
  "deep_scan": true
}
```

### Backdoor Detection
```http
POST /backdoor/detect
{
  "target": "192.168.1.100",
  "scan_type": "comprehensive"
}
```

### Zero-Day Analysis
```http
POST /zeroday/analyze
{
  "services": ["apache", "openssl"],
  "check_unpatched": true
}
```

### Post-Exploitation Framework
```http
POST /post-exploitation/plan
{
  "target": "192.168.1.100",
  "objectives": ["persistence", "exfiltration"]
}
```

### Behavioral Anomaly Detection
```http
POST /behavioral/anomalies
{
  "target": "192.168.1.100",
  "baseline_days": 30
}
```

### AI-Powered Exploit Prediction
```http
POST /ai/exploit-prediction
{
  "target": "192.168.1.100",
  "ml_model": "latest"
}
```

---

## 🔐 CRYPTOGRAPHY (15+ ENDPOINTS)

#### SSL/TLS Analysis
```http
POST /ssl/analyze
{
  "host": "example.com",
  "port": 443
}
```

#### Weak Cipher Detection
```http
POST /cipher/weak-detection
{
  "target": "192.168.1.1",
  "protocol": "TLS"
}
```

#### Key Extraction
```http
POST /crypto/key-extraction
{
  "target": "device",
  "method": "bruteforce"
}
```

#### Downgrade Attack Analysis
```http
POST /crypto/downgrade
{
  "host": "example.com",
  "protocols": ["SSLv3", "TLSv1.0"]
}
```

#### Padding Oracle Detection
```http
POST /crypto/padding-oracle
{
  "target": "192.168.1.1",
  "cipher": "AES"
}
```

#### Certificate Pinning Bypass
```http
POST /pinning/bypass
{
  "target": "example.com",
  "app": "mobile_app"
}
```

#### Side-Channel Attack Analysis
```http
POST /crypto/sidechannel
{
  "target": "encrypted_system",
  "timing": true
}
```

#### Cryptographic Leakage Detection
```http
POST /crypto/leakage
{
  "target": "192.168.1.1"
}
```

#### Master Key Discovery
```http
POST /masterkey/discovery
{
  "device": "router",
  "firmware": "custom"
}
```

#### Hardware Flaw Detection
```http
POST /crypto/hardware-flaws
{
  "hardware": "tpm",
  "check_spectre": true
}
```

---

## 🌐 WEB APPLICATION SECURITY (12+ ENDPOINTS)

#### SQL Injection Hunting
```http
POST /sqli/blind-hunt
{
  "target_url": "http://target.com",
  "parameters": ["id", "search"]
}
```

#### Template Injection Detection
```http
POST /injection/template
{
  "target_url": "http://target.com",
  "test_payloads": true
}
```

#### Language Injection Testing
```http
POST /injection/language
{
  "target_url": "http://target.com",
  "languages": ["python", "ruby", "php"]
}
```

#### XXE (XML External Entity) Detection
```http
POST /injection/xxe
{
  "target_url": "http://target.com",
  "dtd_payloads": true
}
```

#### SSRF (Server-Side Request Forgery) Mapping
```http
POST /ssrf/map
{
  "target_url": "http://target.com",
  "internal_ports": [3306, 5432, 6379]
}
```

#### Open Redirect Chain Analysis
```http
POST /redirect/chain
{
  "target_url": "http://target.com",
  "follow_chain": true
}
```

#### GraphQL Auditing
```http
POST /graphql/audit
{
  "target_url": "http://target.com/graphql",
  "introspection": true
}
```

#### API Key Exposure Detection
```http
POST /apikey/exposure
{
  "target_url": "http://target.com",
  "source_maps": true
}
```

#### Microservices Auditing
```http
POST /microservices/audit
{
  "service_mesh": "istio",
  "check_segmentation": true
}
```

#### WebSocket Auditing
```http
POST /websocket/audit
{
  "target_url": "ws://target.com",
  "protocol_version": "13"
}
```

#### Web Crawler Intelligence
```http
POST /web/crawl
{
  "target_url": "http://target.com",
  "depth": 3
}
```

#### Service Version Detection
```http
POST /service/version-detect
{
  "target": "192.168.1.1",
  "port": 80
}
```

---

## 🌍 RECONNAISSANCE (10+ ENDPOINTS)

#### DNS Intelligence
```http
POST /dns/intelligence
{
  "domain": "example.com",
  "enumerate": true
}
```

#### Port Fingerprinting
```http
POST /fingerprint/port
{
  "ip": "192.168.1.1",
  "port": 22
}
```

#### Protocol Analysis
```http
POST /protocol/analyze
{
  "target": "192.168.1.1",
  "protocols": ["HTTP", "SSH", "FTP"]
}
```

#### Advanced Banner Grabbing
```http
POST /banner/grab-advanced
{
  "target": "192.168.1.1",
  "aggressive": true
}
```

#### Subdomain Enumeration
```http
POST /subdomain/enumerate
{
  "domain": "example.com",
  "wordlist": "large"
}
```

#### Geolocation Mapping
```http
POST /geolocation/map
{
  "ip": "1.2.3.4",
  "include_asn": true
}
```

#### Network Topology Mapping
```http
POST /network/topology
{
  "target": "192.168.1.0/24",
  "hops": 10
}
```

#### Asset Discovery
```http
POST /asset/discovery
{
  "range": "192.168.0.0/16",
  "deep_scan": true
}
```

---

## 🕸️ NETWORK SECURITY (15+ ENDPOINTS)

#### DNS Spoofing Simulation
```http
POST /dns/spoofing
{
  "target": "192.168.1.1",
  "victim": "client_ip"
}
```

#### BGP Hijacking Analysis
```http
POST /bgp/hijacking
{
  "asn": "AS16509",
  "prefixes": ["10.0.0.0/8"]
}
```

#### DHCP Starvation Testing
```http
POST /dhcp/starvation
{
  "target_segment": "192.168.1.0/24"
}
```

#### ARP Spoofing Mapping
```http
POST /arp/spoofing
{
  "target": "192.168.1.0/24",
  "victim": "gateway_ip"
}
```

#### MITM Vulnerability Analysis
```http
POST /mitm/analysis
{
  "target": "192.168.1.1",
  "protocols": ["HTTP", "DNS"]
}
```

#### DDoS Attack Vector Analysis
```http
POST /ddos/vectors
{
  "target": "192.168.1.1",
  "vector_types": ["amplification", "reflection"]
}
```

#### IP Fragmentation Attacks
```http
POST /fragmentation/attacks
{
  "target": "192.168.1.1",
  "test_teardrop": true
}
```

#### TCP/IP Stack Exploitation
```http
POST /tcp/exploitation
{
  "target": "192.168.1.1",
  "test_sequence_prediction": true
}
```

#### VPN Vulnerability Assessment
```http
POST /vpn/assessment
{
  "vpn_endpoint": "openvpn.example.com",
  "protocol": "openvpn"
}
```

#### Network Segmentation Bypass
```http
POST /network/segmentation-bypass
{
  "control_domain": "192.168.1.0/24",
  "target_domain": "10.0.0.0/8"
}
```

---

## 🖥️ SYSTEM EXPLOITATION (15+ ENDPOINTS)

#### Kernel Exploit Analysis
```http
POST /kernel/exploits
{
  "os": "linux",
  "kernel_version": "5.10"
}
```

#### Driver Analysis
```http
POST /driver/analysis
{
  "target": "192.168.1.1",
  "check_loaded": true
}
```

#### UEFI Backdoor Detection
```http
POST /uefi/backdoor
{
  "target_device": "system",
  "firmware_check": true
}
```

#### UAC Bypass Techniques
```http
POST /uac/bypass
{
  "target": "192.168.1.100",
  "method": "auto"
}
```

#### Sudo Misconfiguration
```http
POST /sudo/misconfig
{
  "target": "unix_server",
  "audit_all": true
}
```

#### SUID Binary Analysis
```http
POST /suid/analysis
{
  "target": "unix_server",
  "check_bypass": true
}
```

#### Directory Permission Abuse
```http
POST /permissions/abuse
{
  "target": "192.168.1.1",
  "escalation_methods": true
}
```

#### Capability-Based Privilege Escalation
```http
POST /capabilities/abuse
{
  "target": "unix_server",
  "dangerous_caps": ["cap_sys_admin"]
}
```

#### Token Impersonation Detection
```http
POST /token/impersonation
{
  "target": "192.168.1.100",
  "check_primary": true
}
```

#### Race Condition Detection
```http
POST /race/conditions
{
  "target": "192.168.1.1",
  "file_operations": true
}
```

#### Memory Corruption Exploit Finder
```http
POST /memory/corruption
{
  "target": "192.168.1.1",
  "check_aslr": true
}
```

#### Heap Spray Attacks
```http
POST /heap/spray
{
  "target": "192.168.1.100",
  "allocation_size": 4096
}
```

#### ROP Gadget Discovery
```http
POST /rop/gadgets
{
  "binary": "/usr/bin/bash",
  "gadget_chains": true
}
```

#### Format String Vulnerabilities
```http
POST /format/strings
{
  "target_url": "http://target.com",
  "test_read_write": true
}
```

#### Code Injection Detection
```http
POST /injection/code
{
  "target": "binary",
  "methods": ["dlopen", "mmap"]
}
```

---

## 🛡️ ADVANCED DETECTION (10+ ENDPOINTS)

#### Process Hollowing Detection
```http
POST /hollowing/detect
{
  "target": "192.168.1.100"
}
```

#### Reflective DLL Injection
```http
POST /rdll/injection
{
  "target": "windows_system",
  "check_hooks": true
}
```

#### Control Flow Guard Bypass
```http
POST /cfg/bypass
{
  "target": "windows_system",
  "cfi_enabled": true
}
```

#### Return-Oriented Programming Hijacking
```http
POST /return/hijacking
{
  "target": "192.168.1.1",
  "architecture": "x86_64"
}
```

#### ASLR Bypass Techniques
```http
POST /aslr/bypass
{
  "target": "192.168.1.1",
  "leak_methods": true
}
```

---

## 🔗 SHODAN INTEGRATION (5+ ENDPOINTS)

#### Direct SHODAN API Query
```http
POST /shodan/search
{
  "query": "mongodb port:27017",
  "limit": 100
}
```

#### SHODAN Host Intelligence
```http
GET /shodan/host/<ip>
```

#### SHODAN Account Info
```http
GET /shodan/account
```

---

## 🚨 ALERT SYSTEM (4 ENDPOINTS)

#### Send Email Alert
```http
POST /alerts/email
{
  "subject": "Critical RCE Found",
  "body": "New vulnerability detected",
  "recipients": ["admin@example.com"]
}
```

#### Send Slack Alert
```http
POST /alerts/slack
{
  "channel": "#security",
  "message": "Critical vulnerability alert",
  "severity": "CRITICAL"
}
```

#### Alert History
```http
GET /alerts/history?limit=50
```

---

## ⏰ SCHEDULER (4+ ENDPOINTS)

#### Schedule Recurring Scan
```http
POST /scheduler/schedule
{
  "target": "192.168.1.0/24",
  "frequency": "weekly",
  "day": "Sunday",
  "time": "02:00"
}
```

#### List Scheduled Jobs
```http
GET /scheduler/jobs
```

#### Start Scheduler
```http
POST /scheduler/start
```

#### Stop Scheduler
```http
POST /scheduler/stop
```

---

## 📊 ANALYTICS & MONITORING (5+ ENDPOINTS)

#### Vulnerability Trends
```http
GET /analytics/trends?days=30
```

#### Risk Score Trending
```http
GET /analytics/risk-score?days=30
```

#### Vulnerability Forecast
```http
GET /analytics/forecast?days=7
```

#### Performance Metrics
```http
GET /metrics/performance
```

#### Performance Statistics
```http
GET /metrics/stats
```

---

## 🔧 UTILITY ENDPOINTS (5+ ENDPOINTS)

#### API Health Check
```http
GET /health
```

#### API Information
```http
GET /info
```

#### Dashboard Metrics
```http
GET /dashboard/metrics
```

#### NMAP Port Scan Integration
```http
POST /nmap/scan
{
  "target": "192.168.1.1",
  "ports": "1-1000",
  "aggressive": false
}
```

#### NMAP Scan Results
```http
GET /nmap/results?limit=10
```

---

## 🛡️ v6.0 NEW FEATURES

### CLI GUI Interface
- Interactive terminal UI with menu system
- Real-time progress visualization
- Color-coded output by severity
- Command auto-completion
- History navigation

### Enhanced Import/Export
- Automatic CSV import with validation
- Duplicate detection and merging
- Bulk vulnerability creation from file
- XML/JSON schema validation

### Advanced Rules Engine
- Custom detection rule creation
- Rule templates for 100+ frameworks
- Automated rule testing
- Rule version control

### Detection Rules Database
- Pre-built rules for:
  - OWASP Top 10
  - CWE Top 25
  - CVSS 3.1 compliance
  - Industry standards (PCI, HIPAA)

### Payload Templates
- 500+ ready-to-use payloads
- Custom payload generation
- Payload encoding/obfuscation
- Interactive payload builder

### Rules Management
- CRUD operations on detection rules
- Rule activation/deactivation
- Rule impact analysis
- Rule performance metrics

### Scan History
- Complete scan timeline
- Scan replay capability
- Historical comparison
- Trend analysis

### Advanced Statistics
- Vulnerability distribution
- Severity breakdown
- Asset correlation
- Time-series analysis

---

## 📝 REQUEST/RESPONSE EXAMPLES

### Example 1: Create Vulnerability
**Request:**
```bash
curl -X POST http://localhost:5000/api/v4/vulns \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Remote Code Execution",
    "severity": "CRITICAL",
    "cve": "CVE-2024-1234",
    "target": "192.168.1.100"
  }'
```

**Response:**
```json
{
  "success": true,
  "id": 42,
  "message": "Vulnerability created successfully"
}
```

### Example 2: Start Scan
**Request:**
```bash
curl -X POST http://localhost:5000/api/v4/scan/start \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.0/24",
    "type": "network",
    "threads": 50
  }'
```

**Response:**
```json
{
  "success": true,
  "scan_id": "scan_20260217_123456",
  "status": "running",
  "results_streaming": "/api/v4/scan/stream"
}
```

---

## 🔑 AUTHENTICATION

All requests should include API key via:

**Header Method:**
```bash
Authorization: Bearer YOUR_API_KEY
```

**Environment Variable:**
```bash
export SHODAN_API_KEY=your_api_key_here
```

**Query Parameter:**
```bash
/api/v4/vulns?api_key=your_api_key_here
```

---

## ⚡ RATE LIMITING

| API Tier | Rate Limit | Burst |
|----------|-----------|-------|
| Free | 1 req/sec | 5 req/sec |
| Premium | 15 req/sec | 50 req/sec |
| Enterprise | Unlimited | Unlimited |

---

## 📖 RESPONSE CODES

| Code | Meaning | Example |
|------|---------|---------|
| 200 | OK | Successful request |
| 201 | Created | Vulnerability created |
| 400 | Bad Request | Missing required field |
| 401 | Unauthorized | Invalid API key |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Vulnerability ID doesn't exist |
| 429 | Rate Limited | Too many requests |
| 500 | Server Error | Internal server error |

---

## 🚀 QUICK START

### 1. Check API Health
```bash
curl http://localhost:5000/api/v4/health
```

### 2. Get Info
```bash
curl http://localhost:5000/api/v4/info
```

### 3. List Vulnerabilities
```bash
curl http://localhost:5000/api/v4/vulns
```

### 4. Start a Scan
```bash
curl -X POST http://localhost:5000/api/v4/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com"}'
```

### 5. Stream Results
```bash
curl http://localhost:5000/api/v4/scan/stream
```

---

## 🔗 Related Documentation

- [Installation & Setup](INSTALLATION.md)
- [CLI GUI Guide](CLI_GUI.md)
- [Configuration](CONFIGURATION.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Features](FEATURES.md)
