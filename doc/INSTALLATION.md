# 📦 Installation & Setup Guide

**VulnScopeX v5.0 Enterprise**

---

## ⚡ Quick Installation (5 minutes)

### 1️⃣ **Clone Repository**
```bash
git clone https://github.com/mohidqx/VulnScopeX.git
cd VulnScopeX
```

### 2️⃣ **Install Dependencies**
```bash
pip install -r requirements.txt
```

### 3️⃣ **Configure API Key**
```bash
# Edit .env file and add your SHODAN API key
echo "SHODAN_API_KEY=your_api_key_here" > .env
```

### 4️⃣ **Run Application**
```bash
# Windows
python start_premium.py

# Linux/Mac
python3 start_premium.py
```

---

## 📋 Requirements

### System Requirements
- **Python:** 3.8+ (tested on 3.11.9)
- **OS:** Windows, Linux, macOS
- **RAM:** 4GB minimum
- **Disk Space:** 1GB for application + scan results

### Python Dependencies
```
shodan==1.30.0        # Shodan API client
flask==3.1.2          # Web framework
flask-cors==4.0.0     # CORS support
requests==2.31.0      # HTTP client
colorama==0.4.6       # Terminal colors
emoji==2.8.0          # Emoji support
```

### API Requirements
- **SHODAN API Key** - Free or paid account at shodan.io
- **Internet Connection** - For API calls and threat intel feeds

---

## 🔧 Detailed Setup

### Windows Installation

**Step 1: Install Python 3.11+**
```bash
# Download from python.org or use Windows Store
# Verify installation:
python --version
```

**Step 2: Clone Repository**
```bash
git clone https://github.com/mohidqx/VulnScopeX.git
cd VulnScopeX
```

**Step 3: Create Virtual Environment (Recommended)**
```bash
python -m venv venv
venv\Scripts\activate
```

**Step 4: Install Dependencies**
```bash
pip install -r requirements.txt
```

**Step 5: Configure**
```bash
# Edit .env file
# Add your SHODAN API key
notepad .env
```

**Step 6: Run**
```bash
python start_premium.py
# Choose option 1 for Web UI
# Open http://localhost:5000
```

---

### Linux/Mac Installation

**Step 1: Install Python 3.11+**
```bash
# Ubuntu/Debian
sudo apt-get install python3.11 python3-pip

# macOS (using Homebrew)
brew install python@3.11
```

**Step 2: Clone Repository**
```bash
git clone https://github.com/mohidqx/VulnScopeX.git
cd VulnScopeX
```

**Step 3: Create Virtual Environment**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Step 4: Install Dependencies**
```bash
pip install -r requirements.txt
```

**Step 5: Configure**
```bash
# Edit .env file
# Add your SHODAN API key
nano .env
```

**Step 6: Run**
```bash
python3 start_premium.py
# Choose option 1 for Web UI
# Open http://localhost:5000
```

---

## 🚀 Automated Setup (Windows)

Use the setup scripts for automated installation:

```bash
# Windows batch script
run.bat

# Or use Python setup wizard
python setup.py
```

---

## ⚙️ Configuration Files

### `.env` File
```env
# SHODAN API Configuration
SHODAN_API_KEY=your_actual_api_key_here

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
```

### Database Initialization
```bash
# Automatic on first run or:
python
>>> from app.premium_live import init_database
>>> init_database()
```

---

## 🔑 Getting SHODAN API Key

1. Visit **https://shodan.io**
2. Sign up for free account
3. Go to **Account Settings** → **API Key**
4. Copy your key
5. Paste in `.env` file: `SHODAN_API_KEY=your_key`

---

## ✅ Verify Installation

```bash
# Test API connection
python -c "import shodan; print('Shodan library installed')"

# Test Flask
python -c "import flask; print('Flask installed')"

# Test all dependencies
pip list | grep -E "shodan|flask|requests|colorama|emoji"
```

---

## 🆘 Troubleshooting Installation

### Issue: "ModuleNotFoundError: No module named 'shodan'"
**Solution:**
```bash
pip install --upgrade shodan
```

### Issue: "Port 5000 already in use"
**Solution:** Change port in .env:
```env
FLASK_PORT=5001
```

### Issue: "SHODAN API key invalid"
**Solution:** Verify key in .env:
```bash
python
>>> import os
>>> print(os.getenv('SHODAN_API_KEY'))
```

### Issue: Database errors
**Solution:** Delete and reinitialize:
```bash
rm scan_results/vulnerabilities.db
python start_premium.py
```

---

## 🐳 Docker Installation (Optional)

```dockerfile
FROM python:3.11
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
ENV SHODAN_API_KEY=your_key_here
CMD ["python", "start_premium.py"]
```

```bash
# Build
docker build -t vulnscope .

# Run
docker run -p 5000:5000 -e SHODAN_API_KEY=your_key vulnscope
```

---

## 📚 Next Steps

After installation:

1. **[Quick Start Guide](QUICKSTART.md)** - Get running in 60 seconds
2. **[Feature List](FEATURES.md)** - Explore 200+ features
3. **[API Documentation](APIs.md)** - 70+ REST endpoints
4. **[Module Guide](MODULES.md)** - 7 advanced modules
5. **[Configuration](CONFIGURATION.md)** - Customize settings

---

**✅ Installation complete! Ready to scan.**
