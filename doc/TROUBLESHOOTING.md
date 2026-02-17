# 🔧 TROUBLESHOOTING GUIDE

**Common Issues & Solutions**

---

## ⚠️ INSTALLATION ISSUES

### 1. Python Version Error
```
ERROR: Python 3.8+ required, found 3.7.x
```

**Solution:**
```bash
# Check Python version
python --version

# Install Python 3.9+ from python.org

# Or use pyenv/conda to manage versions
conda create -n shodan python=3.9
conda activate shodan
```

---

### 2. pip Install Fails
```
ERROR: Could not find a version that satisfies the requirement
```

**Solution:**
```bash
# Update pip
python -m pip install --upgrade pip

# Clear pip cache
pip cache purge

# Install with verbose output
pip install -r requirements.txt -v

# Use specific Python version
python3.9 -m pip install -r requirements.txt
```

---

### 3. Module Import Error
```
ModuleNotFoundError: No module named 'shodan'
```

**Solution:**
```bash
# Verify requirements installed
pip list | grep shodan

# Reinstall all requirements
pip install -r requirements.txt --force-reinstall

# Install individual package
pip install shodan requests colorama
```

---

### 4. Permission Denied
```
PermissionError: [Errno 13] Permission denied
```

**Solutions:**

Windows:
```bash
# Run as Administrator
# Right-click Command Prompt → "Run as administrator"
pip install -r requirements.txt
```

Linux/Mac:
```bash
# Use sudo (not recommended)
sudo pip install -r requirements.txt

# Better: Use virtual environment
python -m venv venv
source venv/bin/activate  # Mac/Linux
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

---

## 🔑 API & AUTHENTICATION ISSUES

### 1. API Key Not Working
```
Error: Invalid API Key
Error: 401 Unauthorized
```

**Solution:**
```bash
# 1. Verify API key is correct
# Visit: https://shodan.io/account/api

# 2. Check .env file
more .env  # or type .env on Windows

# 3. Ensure proper format
SHODAN_API_KEY=abc123def456  # No quotes, no spaces

# 4. Test API key
python -c "import shodan; api = shodan.Shodan('YOUR_KEY'); print(api.info())"

# 5. Restart application
```

---

### 2. Rate Limit Exceeded
```
Error: 429 Too Many Requests
```

**Solution:**
```
# Free tier: 1 request/second
# Premium: 15+ requests/second

# In .env, adjust rate limiting:
RATE_LIMIT=1          # Free tier
RATE_LIMIT=10         # Premium

# Add delay between requests
import time
time.sleep(1)  # Wait 1 second between requests
```

---

### 3. Authentication Fails
```
Error: 403 Forbidden
Error: Client Error 403
```

**Solution:**
```bash
# Check API key permissions on shodan.io
# Verify account is not suspended
# Check IP is allowed (if IP whitelist enabled)
# Restart with fresh API key if updated
```

---

## 🌐 CONNECTION ISSUES

### 1. Connection Refused
```
Error: Connection refused
Error: Unable to connect to localhost:5000
```

**Solution:**
```bash
# 1. Check if server is running
# Open new terminal and run:
python start_premium.py

# 2. Check if port is in use
# Windows:
netstat -ano | findstr :5000

# Linux/Mac:
lsof -i :5000

# 3. Use different port in .env
SERVER_PORT=5001

# 4. Check firewall not blocking
```

---

### 2. Network Timeout
```
Error: Connection timeout
Error: Read timed out
```

**Solution:**
```
# In .env, increase timeout
CONNECTION_TIMEOUT=60        # Increase from 30

# Or in command:
--timeout=60

# Check internet connection
ping google.com

# Try different network
# Disable VPN if enabled
```

---

### 3. DNS Resolution Failed
```
Error: Name or service not known
Error: getaddrinfo failed
```

**Solution:**
```bash
# Check DNS servers
# Windows: ipconfig /all
# Linux/Mac: cat /etc/resolv.conf

# Try different DNS in system settings
# Or restart network adapter
```

---

## 💾 FILE & PATH ISSUES

### 1. File Not Found
```
FileNotFoundError: [Errno 2] No such file or directory
```

**Solution:**
```bash
# 1. Check current directory
pwd  # Linux/Mac
cd   # Windows (shows current path)

# 2. Navigate to project root
cd /path/to/SHODAN

# 3. Verify files exist
ls -la  # Linux/Mac
dir     # Windows

# 4. Use absolute paths
python c:\Users\User\Desktop\SHODAN\start_premium.py
```

---

### 2. Permission Denied (File Write)
```
PermissionError: [Errno 13] Permission denied: 'scan_results/...'
```

**Solution:**
```bash
# Windows:
# Right-click folder → Properties → Security → Edit → Allow Full Control

# Linux/Mac:
chmod 755 scan_results/
chmod 755 logs/

# Or run with sudo
sudo python start_premium.py
```

---

### 3. .env File Not Found
```
Error: No .env file in project root
```

**Solution:**
```bash
# 1. Create .env file
# Navigate to project root
cd c:\Users\User\Desktop\SHODAN

# 2. Create file
type nul > .env  # Windows
touch .env       # Linux/Mac

# 3. Add configuration
echo SHODAN_API_KEY=your_key >> .env

# 4. Verify
cat .env  # or type .env on Windows
```

---

## 🖥️ SERVER & WEB INTERFACE ISSUES

### 1. Server Won't Start
```
Error: Address already in use
Error: [Port] is already allocated
```

**Solution:**
```bash
# Option 1: Kill existing process
# Windows:
taskkill /PID <process_id> /F

# Linux/Mac:
kill -9 <process_id>

# Option 2: Use different port
# In .env:
SERVER_PORT=5001

# Start server:
python start_premium.py
```

---

### 2. Web Dashboard Not Loading
```
Error: Cannot GET /
Blank page loading
```

**Solution:**
```bash
# 1. Verify server is running
# Check terminal for startup messages

# 2. Try different port
# In .env: SERVER_PORT=5001

# 3. Clear browser cache
# Chrome: Ctrl+Shift+Delete
# Firefox: Ctrl+Shift+Delete

# 4. Check browser console for errors
# F12 → Console tab

# 5. Verify templates exist
# Check: app/templates/ folder
```

---

### 3. Pages Load Slowly
```
Dashboard takes 30+ seconds to load
```

**Solution:**
```
# 1. Check system resources
# Windows Task Manager
# Linux: htop, top

# 2. Reduce scan results in .env
BATCH_SIZE=50               # From 100

# 3. Disable animations/charts
# In .env:
DASHBOARD_ENABLE_CHARTS=false

# 4. Check network latency
# Run: ping localhost

# 5. Restart server
```

---

## 🔍 SCANNING ISSUES

### 1. Scan Won't Start
```
Error: Scan failed to initialize
Error: Invalid target format
```

**Solution:**
```bash
# 1. Check target format
# Valid: example.com, 192.168.1.1, domain.co.uk
# Invalid: http://example.com (remove protocol)

# 2. Verify target is reachable
ping example.com

# 3. Check firewall
# Disable temporarily to test

# 4. Verify SHODAN API permissions
# Check API key at shodan.io/account/api
```

---

### 2. Scan Hangs/Freezes
```
Scan not progressing
Process using 100% CPU
```

**Solution:**
```bash
# 1. Increase timeout in .env
SCAN_TIMEOUT=600            # 10 minutes

# 2. Reduce batch size
BATCH_SIZE=50               # Smaller batches

# 3. Kill process and restart
# Windows: Ctrl+C in terminal
# Linux/Mac: Ctrl+C

# 4. Check system resources
# Free up RAM if low
```

---

### 3. Scan Returns No Results
```
Scan completed: 0 results
Empty CSV output
```

**Solution:**
```bash
# 1. Verify API key is premium
# Free tier has limited results

# 2. Try known target
# Test with: port:22
# This should find SSH services

# 3. Check scan status
# Visit dashboard: http://localhost:5000/

# 4. Review API limit
# Free: 1 result/month usage
# Premium: 1000s of results
```

---

### 4. CSV/Export Not Creating
```
No CSV file in scan_results/
Export button does nothing
```

**Solution:**
```bash
# 1. Check permissions
chmod 755 scan_results/

# 2. Verify scan completed
# Should show "Scan Status: Complete"

# 3. Check file size
ls -la scan_results/         # Linux/Mac
dir scan_results/            # Windows

# 4. Try manual export
python scanner_premium.py --export csv
```

---

## 🔐 SECURITY & PERMISSION ISSUES

### 1. SSL/TLS Certificate Error
```
Error: [SSL: CERTIFICATE_VERIFY_FAILED]
```

**Solution:**
```bash
# For testing (not production):
# In .env:
ENABLE_SSL=false

# For production:
# 1. Obtain valid certificate
# 2. Add to .env:
ENABLE_SSL=true
SSL_CERT=/path/to/cert.pem
SSL_KEY=/path/to/key.pem

# 3. Restart server
```

---

### 2. CORS Errors
```
Error: No 'Access-Control-Allow-Origin' header
```

**Solution:**
```
# In .env, configure CORS:
CORS_ORIGINS=http://localhost:3000,https://yourdomain.com
CORS_ALLOW_CREDENTIALS=true

# For development (allow all):
CORS_ORIGINS=*  # Not for production!
```

---

## 📊 DATA & EXPORT ISSUES

### 1. CSV File Corrupted
```
Error: Malformed CSV
Cannot open Excel file
```

**Solution:**
```bash
# 1. Check file encoding
# Use UTF-8 encoding in .env:
OUTPUT_ENCODING=utf-8

# 2. Re-export from dashboard
# Dashboard → Export → CSV

# 3. Verify scan data
# Check if scan results exist first
```

---

### 2. Large Exports Fail
```
Error: Memory exceeded
Export timeout with 100K+ results
```

**Solution:**
```
# 1. Export in smaller batches
# Don't export 100K results at once

# 2. Use CSV format (smallest)
# Avoid PDF format for large sets

# 3. Increase system memory
# Close other applications

# 4. Stream results instead
# Use API: GET /scan/stream
```

---

## 🐍 PYTHON ISSUES

### 1. IndentationError
```
IndentationError: unexpected indent
```

**Solution:**
```bash
# Check Python file uses consistent indentation
# Use spaces, not tabs

# Use linter to check
pip install pylint
pylint scanner_premium.py

# Fix indentation
python -m autopep8 --in-place scanner_premium.py
```

---

### 2. Syntax Error
```
SyntaxError: invalid syntax
```

**Solution:**
```bash
# Check Python version compatibility
python -c "import sys; print(sys.version)"

# Use Python 3.8+
python3.9 scanner_premium.py

# Check file encoding
# Ensure UTF-8 format
```

---

### 3. Import Error (Virtual Environment)
```
ModuleNotFoundError: module not found
```

**Solution:**
```bash
# 1. Verify virtual environment activated
# Windows: venv\Scripts\activate
# Linux/Mac: source venv/bin/activate

# 2. Check activated environment
# Should show: (venv) in prompt

# 3. Reinstall in correct environment
pip install -r requirements.txt

# 4. Use explicit Python path
/path/to/venv/bin/python scanner_premium.py
```

---

## 🔄 RESTART & RECOVERY

### Full System Reset

```bash
# 1. Stop server
# Press Ctrl+C in terminal

# 2. Clear cache/temp files
rm -rf app/__pycache__/      # Linux/Mac
rmdir /s app\__pycache__\    # Windows

# 3. Clear old scan results (optional)
rm -rf scan_results/         # Linux/Mac
rmdir /s scan_results\       # Windows

# 4. Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# 5. Restart server
python start_premium.py
```

---

## 📞 GET MORE HELP

1. **Documentation:** See [README.md](README.md) and [INSTALLATION.md](INSTALLATION.md)
2. **Configuration:** See [CONFIGURATION.md](CONFIGURATION.md)
3. **API Reference:** See [APIs.md](APIs.md)
4. **GitHub Issues:** Report bugs on GitHub
5. **SHODAN Forums:** Visit shodan.io/community
