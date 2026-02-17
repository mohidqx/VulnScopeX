# 🛠️ MODULES GUIDE

**7 Advanced Analysis Modules**

---

## 📦 AVAILABLE MODULES

### 1️⃣ Crypto Module (`crypto_module.py`)
SSL/TLS vulnerability analysis
```bash
python modules/crypto_module.py -t example.com
```

### 2️⃣ Reconnaissance Module (`reconnaissance_module.py`)
DNS enumeration and port scanning
```bash
python modules/reconnaissance_module.py -t example.com --dns
```

### 3️⃣ Network Module (`network_module.py`)
Network-level attacks and vulnerabilities
```bash
python modules/network_module.py -t example.com --ddos
```

### 4️⃣ Exploitation Module (`exploitation_module.py`)
Advanced exploitation chain analysis
```bash
python modules/exploitation_module.py -t example.com --chain
```

### 5️⃣ Privilege Module (`privilege_module.py`)
Privilege escalation vector analysis
```bash
python modules/privilege_module.py -o Linux --sudo
```

### 6️⃣ Memory Module (`memory_module.py`)
Memory corruption and code injection detection
```bash
python modules/memory_module.py -f binary.exe
```

### 7️⃣ Web App Module (`webapp_module.py`)
Web application vulnerability testing
```bash
python modules/webapp_module.py -u http://example.com --xss
```

---

## 🚀 RUN ALL MODULES

```bash
python modules/modules_launcher.py
# Interactive menu to select any module
```

---

See [README_FULL.md](README_FULL.md) for detailed module documentation
