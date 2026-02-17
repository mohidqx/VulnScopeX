# 🚀 QUICK START GUIDE (60 Seconds)

**Get VulnScopeX running in under a minute**

---

## ⚡ JUST WANT TO RUN IT?

### Windows Users:
```bash
# 1. Install Python packages
pip install -r requirements.txt

# 2. Set API key
$env:SHODAN_API_KEY = "your_api_key"

# 3. Run application
python start_premium.py

# 4. Select option 1 (Web UI)
# 5. Open http://localhost:5000
```

### Linux/Mac Users:
```bash
# 1. Install packages
pip3 install -r requirements.txt

# 2. Set API key
export SHODAN_API_KEY="your_api_key"

# 3. Run
python3 start_premium.py

# 4. Pick option 1
# 5. Visit http://localhost:5000
```

---

## 🎯 THREE WAYS TO USE

### 1️⃣ WEB UI (Easiest)
```bash
python start_premium.py
# Select: 1
# Go to: http://localhost:5000
```
**Features:** Buttons, dashboards, real-time results

### 2️⃣ CLI SCANNER (Fastest)
```bash
python start_premium.py
# Select: 2
# Results: CSV + Database
```
**Features:** Parallel threads, color output, statistics

### 3️⃣ REST API (Flexible)
```bash
curl http://localhost:5000/api/v4/health

curl -X POST http://localhost:5000/api/v4/scan/start \
  -H "Content-Type: application/json" \
  -d '{"queries": ["mongodb"], "limit": 50}'
```
**Features:** 70+ endpoints, automation, integration

---

## 📋 YOU NEED

| Requirement | What | Where |
|-------------|------|-------|
| **API Key** | SHODAN | Get at shodan.io (free account) |
| **Python** | 3.8+ | python.org or Windows Store |
| **Time** | 5 minutes | Now! |

---

## ✅ DONE!

Welcome to VulnScopeX! 🔥

**Next:**
- [Full Installation Guide](INSTALLATION.md)
- [Feature Overview](FEATURES.md)
- [API Documentation](APIs.md)
- [Module Guide](MODULES.md)

---

**Version:** 5.0 | **Status:** ✅ Ready | **Support:** [GitHub Issues](https://github.com/mohidqx/VulnScopeX/issues)
