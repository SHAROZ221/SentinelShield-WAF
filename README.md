<div align="center">

# 🛡️ SentinelShield
### Advanced Intrusion Detection & Web Protection System

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-00ff88?style=flat-square)
![Type](https://img.shields.io/badge/Type-WAF%20%2F%20IDS-red?style=flat-square)

*A Python-based Web Application Firewall that detects real-world attacks, monitors traffic behaviour, logs events, and displays everything on a live dashboard.*

</div>

---

## 🔍 What is SentinelShield?

SentinelShield acts as a **Web Application Firewall (WAF)** — it sits between incoming HTTP requests and your web application, inspecting every request before it gets through.

If a request contains a malicious payload like SQL Injection or XSS, it gets **blocked with a 403**. If an IP sends too many requests too fast, it gets **rate limited with a 429**. Everything is logged and visualised on a live dashboard.

This is the same concept used by real WAFs like Cloudflare, AWS WAF, and ModSecurity.

---

## ⚙️ How It Works

```
Incoming Request
      │
      ▼
  Rate Limit Check ──► Too many requests? ──► BLOCK (429)
      │
      ▼
  Signature Scan ───► Malicious payload? ──► BLOCK (403)
      │
      ▼
  ALLOW (200) + Log everything
```

Every event — allowed or blocked — is saved to a structured JSON log file and reflected on the dashboard in real time.

---

## 🚨 Attacks Detected

| Attack Type | Example | Severity |
|---|---|---|
| SQL Injection | `' OR '1'='1` | 🔴 HIGH |
| Cross-Site Scripting (XSS) | `<script>alert(1)</script>` | 🔴 HIGH |
| Command Injection | `; cat /etc/passwd` | 🔴 HIGH |
| Local File Inclusion (LFI) | `../../../../etc/passwd` | 🔴 HIGH |
| Directory Traversal | `../../../windows/system32` | 🟡 MEDIUM |
| XXE Injection | `<!ENTITY xxe SYSTEM "file://">` | 🟡 MEDIUM |
| Scanner Detection | User-Agent: `sqlmap/1.7` | 🟢 LOW |
| Brute Force | 15+ requests / 30 seconds | 🟡 MEDIUM |

---

## 🚀 Getting Started

**1. Install dependencies**
```bash
pip install -r requirements.txt
```

**2. Start the WAF**
```bash
python app.py
```

**3. Open the dashboard**
```
http://localhost:5000/
```

**4. Run the attack simulator** *(in a second terminal)*
```bash
python simulator.py
```

Watch the dashboard update live as attacks are detected and blocked.

---

## 📁 Project Structure

```
SentinelShield/
├── app.py            → Main WAF server
├── rules.py          → Attack signature patterns
├── monitor.py        → Rate limiting & IP tracking
├── logger.py         → JSON event logging & statistics
├── simulator.py      → Automated attack test suite
├── templates/
│   └── dashboard.html → Live web dashboard
└── logs/
    └── sentinel.log  → Auto-generated event log
```

---

## 📊 Dashboard Preview

The dashboard shows:
- **Live counters** — total requests, blocked attacks, clean requests, rate-limited IPs
- **Attack type chart** — distribution of detected attack categories
- **Severity breakdown** — HIGH / MEDIUM / LOW with detection rate percentage
- **Top attacking IPs** — most active sources
- **Live event log** — every request with timestamp, IP, status, and attack type

---

## 🧰 Built With

- **Flask** — Web server and routing
- **Python re** — Regex-based signature matching
- **Chart.js** — Dashboard visualisations
- **JSON logging** — SIEM-compatible structured logs

---

<div align="center">

**Sharoz** · BCA Year 3 · Cybersecurity (SOC Track)

[github.com/SHAROZ221](https://github.com/SHAROZ221)

</div>
