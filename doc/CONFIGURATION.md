# ⚙️ CONFIGURATION GUIDE

**Complete Configuration & Setup Instructions**

---

## 🔑 ENVIRONMENT VARIABLES (.env)

Create a `.env` file in the project root:

```
# SHODAN API
SHODAN_API_KEY=your_api_key_here
USE_SHODAN_PREMIUM=true

# Server Configuration  
SERVER_HOST=127.0.0.1
SERVER_PORT=5000
DEBUG_MODE=false

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/app.log

# Results Storage
RESULTS_DIR=scan_results/

# Timeouts (seconds)
SCAN_TIMEOUT=300
CONNECTION_TIMEOUT=30

# Batch Settings
BATCH_SIZE=100
RATE_LIMIT=5  # requests per second

# Export Formats
EXPORT_FORMATS=csv,json,pdf,excel

# Security
ENABLE_SSL=false
SSL_CERT=cert.pem
SSL_KEY=key.pem

# Advanced
ENABLE_MEMORY_SCAN=true
ENABLE_NETWORK_SCAN=true
ENABLE_CRYPTO_SCAN=true
ENABLE_PRIVILEGE_ESCALATION=true
ENABLE_EXPLOITATION=true
ENABLE_WEB_SCAN=true
ENABLE_RECONNAISSANCE=true
```

---

## 🔐 SHODAN API KEY SETUP

### 1. Obtain API Key

1. Visit [shodan.io](https://shodan.io)
2. Create free or paid account
3. Go to **Account** → **API Key**
4. Copy your API key

### 2. Configure API Key

Option A: Add to .env
```
SHODAN_API_KEY=<your_key>
```

Option B: Set environment variable
```bash
# Windows (CMD)
set SHODAN_API_KEY=<your_key>

# Windows (PowerShell)
$env:SHODAN_API_KEY="<your_key>"

# Linux/Mac
export SHODAN_API_KEY="<your_key>"
```

Option C: Add to app/config.py
```python
SHODAN_API_KEY = "your_key_here"
```

### 3. Verify Configuration
```bash
python -c "from app.config import SHODAN_API_KEY; print('✓ API Key Configured')"
```

---

## 🎛️ SCANNING CONFIGURATION

### 1. Basic Scan Settings

In `.env`:
```
# Scan Type
SCAN_TYPE=network  # network, web, memory, crypto

# Target
TARGET_HOST=example.com
TARGET_PORT=8080

# Scope
SCAN_TIMEOUT=300        # 5 minutes
BATCH_SIZE=100          # Results per batch
RATE_LIMIT=5            # Requests/sec
```

### 2. Advanced Scanning

```
# Memory Analysis
MEMORY_SCAN_TYPE=full    # full, running, heap
MEMORY_DUMP_PATH=dumps/

# Network Mapping
NETWORK_SCAN_DEPTH=3
NETWORK_INCLUDE_INTERNAL=true

# Exploitation
SAFE_MODE=true           # Prevents destructive actions
ENABLE_PAYLOADS=true
PAYLOAD_TIMEOUT=30
```

---

## 🗄️ DATA STORAGE

### 1. Results Directory

Results automatically saved to:
```
scan_results/
├── ultimate_scan_<date>_<time>.csv
├── ultimate_scan_<date>_<time>.json
└── ultimate_scan_<date>_<time>.xlsx
```

### 2. Custom Storage Path

In `.env`:
```
RESULTS_DIR=/custom/path/scan_results/
```

### 3. Database Configuration

```
# Database (Optional)
DB_TYPE=sqlite              # sqlite, postgresql, mysql
DB_NAME=shodan_app
DB_HOST=localhost
DB_PORT=5432
DB_USER=admin
DB_PASSWORD=password
```

---

## 📊 LOGGING CONFIGURATION

### 1. Log Levels

```
LOG_LEVEL=DEBUG    # Verbose, debug info
LOG_LEVEL=INFO     # General info (default)
LOG_LEVEL=WARNING  # Warnings only
LOG_LEVEL=ERROR    # Errors only
```

### 2. Log Files

```
LOG_FILE=logs/app.log          # Main log
LOG_FILE_MAXBYTES=10485760     # 10 MB
LOG_FILE_BACKUPS=5             # Keep 5 old logs
```

### 3. Console Output

```
ENABLE_CONSOLE_LOG=true
CONSOLE_LOG_FORMAT=json        # json or text
```

---

## 🔒 SECURITY CONFIGURATION

### 1. SSL/TLS

```
ENABLE_SSL=true
SSL_CERT=/path/to/cert.pem
SSL_KEY=/path/to/key.pem
SSL_PORT=5443
```

### 2. Authentication

```
AUTH_ENABLED=true
AUTH_TYPE=basic                # basic, token, oauth2
SECRET_KEY=your-secret-key
TOKEN_EXPIRY=3600              # 1 hour
```

### 3. CORS

```
CORS_ORIGINS=http://localhost:3000,https://yourdomain.com
CORS_ALLOW_CREDENTIALS=true
```

---

## 🚀 MODULE CONFIGURATION

### 1. Enable/Disable Modules

```
# Advanced Modules
ENABLE_RECONNAISSANCE=true
ENABLE_NETWORK_SCAN=true
ENABLE_MEMORY_SCAN=true
ENABLE_EXPLOITATION=true
ENABLE_PRIVILEGE_ESCALATION=true
ENABLE_CRYPTOGRAPHY=true
ENABLE_WEB_APPS=true
```

### 2. Module-Specific Settings

**Reconnaissance Module:**
```
RECON_DEPTH=3                  # Scan depth
RECON_PASSIVE=true             # Passive only
RECON_TIMEOUT=600              # 10 minutes
```

**Exploitation Module:**
```
SAFE_MODE=true                 # Don't modify targets
AUTO_REMEDIATE=false           # Don't fix issues
PAYLOAD_TIMEOUT=30
```

**Network Module:**
```
NETWORK_THREADS=10
NETWORK_TIMEOUT=30
NETWORK_UDP_SCAN=true
```

---

## 🌐 WEB INTERFACE CONFIGURATION

### 1. Dashboard Settings

```
DASHBOARD_THEME=dark           # light, dark, auto
DASHBOARD_REFRESH=5            # Refresh interval (seconds)
DASHBOARD_ENABLE_CHARTS=true
DASHBOARD_ENABLE_MAPS=true
```

### 2. Frontend Configuration

```
API_ENDPOINT=http://localhost:5000/api/v4/
WS_ENDPOINT=ws://localhost:5000/ws
ASSET_PATH=/static/
```

---

## 📱 CLI CONFIGURATION

### 1. CLI Defaults

```
CLI_OUTPUT_FORMAT=table        # table, json, csv
CLI_COLORS=true
CLI_VERBOSE=false
CLI_QUIET=false
```

### 2. Command Aliases

```
ALIAS_SCAN=quick-scan
ALIAS_EXPLOIT=exploit-target
ALIAS_REPORT=generate-report
```

---

## 🧪 TESTING CONFIGURATION

```
ENABLE_TEST_MODE=false
TEST_DATA_PATH=test_data/
TEST_RESULTS_PATH=test_results/
```

---

## ✅ CONFIGURATION VALIDATION

### 1. Validate Configuration

```bash
python -c "from app.config import validate_config; validate_config()"
```

### 2. Print Current Configuration

```bash
python -c "from app.config import print_config; print_config()"
```

### 3. Test API Connection

```bash
python -c "from app.config import test_api; test_api()"
```

---

## 🔄 CONFIGURATION BEST PRACTICES

1. **Never commit `.env` to Git** - Use `.env.example` instead
2. **Use strong secret keys** - At least 32 characters
3. **Enable logging** - For troubleshooting and auditing
4. **Set appropriate timeouts** - Prevent hanging operations
5. **Use rate limiting** - Respect API quotas and avoid bans
6. **Enable SSL in production** - For secure communication
7. **Regularly update API keys** - For security
8. **Test after configuration changes** - Before production use

---

## 🆘 CONFIGURATION TROUBLESHOOTING

### API Key Not Working
```
1. Verify key in .env: SHODAN_API_KEY=<key>
2. Check key is correct: shodan.io/account/api
3. Ensure no whitespace/quotes: SHODAN_API_KEY=abc123 (not "abc123")
4. Restart application after changed
```

### Port Already in Use
```
# Check what's using port 5000
lsof -i :5000          # Linux/Mac
netstat -ano | find ":5000"  # Windows

# Use different port in .env
SERVER_PORT=5001
```

### Can't Find .env File
```
# .env must be in project root:
c:\Users\User\Desktop\SHODAN\.env

# Not in subdirectories
```

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for more help.
