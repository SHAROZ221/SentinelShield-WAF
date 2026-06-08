# 🛡️ SentinelShield
## Advanced Intrusion Detection & Web Protection System

A lightweight Web Application Firewall (WAF) that detects and blocks
real-world web attacks including SQL Injection, XSS, Command Injection,
LFI, Directory Traversal, and brute-force attacks.

---

## 📁 Project Structure

```
SentinelShield/
├── app.py          → Main Flask WAF server (run this first)
├── rules.py        → Attack signature detection engine
├── monitor.py      → Rate limiting & IP tracking
├── logger.py       → Structured JSON event logging
├── simulator.py    → Automated attack test suite
├── requirements.txt→ Python dependencies
├── templates/
│   └── dashboard.html → Live web dashboard
└── logs/
    └── sentinel.log   → Auto-generated event log
```

---

## 🚀 How to Run (Step by Step)

### Step 1 — Install dependencies
Open a terminal in the SentinelShield folder and run:
```bash
pip install -r requirements.txt
```

### Step 2 — Start the WAF server
```bash
python app.py
```
You will see:
```
╔══════════════════════════════════════════════════════════════╗
║  Dashboard  →  http://localhost:5000/                        ║
╚══════════════════════════════════════════════════════════════╝
```

### Step 3 — Open the Dashboard
Open your browser and go to:
```
http://localhost:5000/
```

### Step 4 — Run the Attack Simulator
Open a **second terminal** (keep app.py running) and run:
```bash
python simulator.py
```
This fires 20+ real attack payloads at the WAF and shows what was
blocked vs allowed. Watch the dashboard update in real time.

---

## 🔍 What the WAF Detects

| Attack Type           | Example Payload                          | Severity |
|-----------------------|------------------------------------------|----------|
| SQL Injection         | `' OR '1'='1`                           | HIGH     |
| XSS                   | `<script>alert('xss')</script>`         | HIGH     |
| Command Injection     | `; cat /etc/passwd`                     | HIGH     |
| LFI                   | `../../../../etc/passwd`                 | HIGH     |
| Directory Traversal   | `../../../windows/system32`              | MEDIUM   |
| XXE Injection         | `<!ENTITY xxe SYSTEM "file://">`        | MEDIUM   |
| Scanner Detection     | User-Agent: `sqlmap/1.7`                | LOW      |
| Brute Force           | 15+ requests in 30 seconds from one IP  | MEDIUM   |

---

## 🌐 API Endpoints

| Endpoint         | Method | Description                          |
|------------------|--------|--------------------------------------|
| `/`              | GET    | Dashboard UI                         |
| `/test`          | GET/POST | Protected test endpoint            |
| `/login`         | GET/POST | Simulated login (brute-force test) |
| `/search`        | GET/POST | Simulated search (SQLi/XSS test)   |
| `/api/stats`     | GET    | JSON statistics for dashboard        |
| `/api/logs`      | GET    | Recent log entries as JSON           |
| `/api/clear`     | POST   | Clear all logs                       |

---

## 📊 Log Format

Each log entry is a JSON object:
```json
{
  "timestamp": "2026-06-07 12:00:00 UTC",
  "ip": "127.0.0.1",
  "method": "POST",
  "path": "/login",
  "event": "BLOCKED",
  "detections": [
    {"name": "SQL Injection", "severity": "HIGH"}
  ],
  "payload_sample": "admin' OR '1'='1",
  "user_agent": "Mozilla/5.0..."
}
```

---

## 📖 For Your Practical Journal

When writing your practical submission, cover these points:

1. **Purpose** — Building a WAF that detects common web attacks
2. **Tools** — Python, Flask, regex pattern matching, JSON logging
3. **Architecture** — Request → WAF inspection → Allow/Block → Log → Dashboard
4. **Attacks tested** — See simulator.py for full list
5. **Detection results** — Screenshot the dashboard after running simulator.py
6. **Log analysis** — Open logs/sentinel.log and show sample entries
7. **False positives** — Note any clean requests that were blocked
8. **Recommendations** — How to improve the rules engine

---

Built by Sharoz | BCA Year 3 | Cybersecurity Lab
