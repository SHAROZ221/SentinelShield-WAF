<div align="center">

<img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&size=32&duration=3000&pause=1000&color=00FF88&center=true&vCenter=true&width=600&lines=🛡️+SentinelShield+WAF;Advanced+Web+Protection;Real-Time+Attack+Detection" alt="Typing SVG" />

### Advanced Intrusion Detection & Web Protection System

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Status](https://img.shields.io/badge/Status-Active-00ff88?style=flat-square)]()
[![Type](https://img.shields.io/badge/Type-WAF%20%2F%20IDS-red?style=flat-square)]()
[![Live Demo](https://img.shields.io/badge/🛡️_Live_Demo-Railway-blueviolet?style=flat-square)](https://web-production-41b62.up.railway.app)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)]()

<br/>

> *A Python-based Web Application Firewall that detects real-world attacks, monitors traffic behaviour, logs every event, and displays everything on a live dashboard — just like Cloudflare, AWS WAF, and ModSecurity.*

<br/>

**[🚀 Live Demo](https://web-production-41b62.up.railway.app)** · **[📊 Dashboard](https://web-production-41b62.up.railway.app/dashboard)** · **[📋 API Logs](https://web-production-41b62.up.railway.app/api/logs)**

</div>

---

## 🔍 What is SentinelShield?

SentinelShield acts as a **Web Application Firewall (WAF)** — it sits between incoming HTTP requests and your web application, inspecting every request before it gets through.

- 🚫 Malicious payload detected? → **Blocked with 403 Forbidden**
- ⏱️ Too many requests from one IP? → **Rate limited with 429**
- ✅ Clean request? → **Allowed and logged**
- 📊 Everything visualised → **Live dashboard in real time**

This is the same concept used by enterprise-grade tools like **Cloudflare WAF**, **AWS WAF**, and **ModSecurity**.

---

## ⚙️ How It Works

```
Incoming HTTP Request
        │
        ▼
┌───────────────────┐
│  Rate Limit Check │──► Too many requests? ──► BLOCK 429
└───────────────────┘
        │
        ▼
┌───────────────────┐
│  Signature Scan   │──► Malicious payload? ──► BLOCK 403
└───────────────────┘
        │
        ▼
   ALLOW ✅ + Log Event → Dashboard updates live
```

Every event — allowed or blocked — is saved to a **SIEM-compatible JSON log** and reflected on the dashboard in real time.

---

## 🚨 Attacks Detected

| Attack Type | Example Payload | Severity |
|---|---|:---:|
| SQL Injection | `' OR '1'='1` | 🔴 HIGH |
| Cross-Site Scripting (XSS) | `<script>alert(1)</script>` | 🔴 HIGH |
| Command Injection | `; cat /etc/passwd` | 🔴 HIGH |
| Local File Inclusion (LFI) | `../../../../etc/passwd` | 🔴 HIGH |
| Directory Traversal | `../../../windows/system32` | 🟡 MEDIUM |
| XXE Injection | `<!ENTITY xxe SYSTEM "file://">` | 🟡 MEDIUM |
| Scanner Detection | User-Agent: `sqlmap/1.7` | 🟢 LOW |
| Brute Force | 15+ requests / 30 seconds | 🟡 MEDIUM |

---

## 📊 Live Dashboard

> Try the live demo → **[web-production-41b62.up.railway.app](https://web-production-41b62.up.railway.app)**

The dashboard shows in real time:

- 🔢 **Live counters** — total requests, blocked attacks, clean requests, rate-limited IPs
- 🥧 **Attack type chart** — distribution of detected attack categories
- 📈 **Severity breakdown** — HIGH / MEDIUM / LOW with detection rate %
- 🌐 **Top attacking IPs** — most active threat sources
- 📋 **Live event log** — every request with timestamp, IP, status, and attack type

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/SHAROZ221/SentinelShield-WAF.git
cd SentinelShield-WAF

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the WAF
python app.py

# 4. Open the dashboard
# → http://localhost:5000/
```

### Run Attack Simulator *(optional — in a second terminal)*

```bash
python simulator.py
```

Watch the dashboard update live as attacks are detected and blocked in real time.

---

## 📁 Project Structure

```
SentinelShield/
├── app.py              → Main WAF server & Flask routes
├── rules.py            → Attack signature patterns (regex)
├── monitor.py          → Rate limiting & IP tracking
├── logger.py           → JSON event logging & statistics
├── simulator.py        → Automated attack test suite
├── requirements.txt    → Python dependencies
├── templates/
│   └── dashboard.html  → Live web dashboard (Chart.js)
└── logs/
    └── sentinel.log    → Auto-generated SIEM-compatible log
```

---

## 🧰 Built With

| Technology | Purpose |
|---|---|
| **Python 3.8+** | Core language |
| **Flask** | Web server and routing |
| **Python `re`** | Regex-based signature matching |
| **Chart.js** | Dashboard visualisations |
| **JSON logging** | SIEM-compatible structured logs |
| **Flask-CORS** | Cross-origin request handling |

---

## 🌐 Test the Live WAF

Try sending these URLs in your browser — watch them get **blocked**:

```
# SQL Injection
https://web-production-41b62.up.railway.app/search?q=' OR '1'='1

# XSS Attack
https://web-production-41b62.up.railway.app/search?q=<script>alert(1)</script>

# Directory Traversal
https://web-production-41b62.up.railway.app/search?q=../../../etc/passwd
```

---

## 🎯 Learning Outcomes

Building this project covers real SOC skills:

- ✅ Understanding WAF architecture and request inspection
- ✅ Writing attack detection signatures (regex patterns)
- ✅ Rate limiting and IP-based threat tracking
- ✅ SIEM-compatible structured logging
- ✅ Real-time dashboard with live data
- ✅ Cloud deployment (Railway)

---

<div align="center">

Made with 🔐 by **[Sharoz](https://github.com/SHAROZ221)**

BCA Year 3 · Cybersecurity (SOC Track) · India

[![GitHub](https://img.shields.io/badge/GitHub-SHAROZ221-181717?style=flat-square&logo=github)](https://github.com/SHAROZ221)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Sharoz_Mohd-0077B5?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/sharoz-mohd-86057a408/)

*"Detect • Analyze • Defend"*

</div>
