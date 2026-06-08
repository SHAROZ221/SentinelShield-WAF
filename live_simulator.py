"""
live_simulator.py – SentinelShield Live Attack Simulator
=========================================================
Fires real attack payloads at the live Railway deployment.
Run this script and watch the dashboard update in real time.

Usage:
    python live_simulator.py
"""

import requests
import time
import random

# ─────────────────────────────────────────────────────────────
# TARGET
# ─────────────────────────────────────────────────────────────
BASE_URL = "https://web-production-41b62.up.railway.app"

# ─────────────────────────────────────────────────────────────
# ATTACK PAYLOADS
# ─────────────────────────────────────────────────────────────
ATTACKS = [

    # SQL Injection
    {"name": "SQL Injection #1",       "url": "/search",  "params": {"q": "' OR '1'='1"}},
    {"name": "SQL Injection #2",       "url": "/login",   "params": {"username": "admin' --", "password": "x"}},
    {"name": "SQL Injection #3",       "url": "/search",  "params": {"q": "1; DROP TABLE users--"}},
    {"name": "SQL Injection #4",       "url": "/search",  "params": {"q": "' UNION SELECT * FROM users--"}},

    # XSS
    {"name": "XSS #1",                 "url": "/search",  "params": {"q": "<script>alert(1)</script>"}},
    {"name": "XSS #2",                 "url": "/search",  "params": {"q": "<img src=x onerror=alert(1)>"}},
    {"name": "XSS #3",                 "url": "/search",  "params": {"q": "javascript:alert('xss')"}},

    # Command Injection
    {"name": "Command Injection #1",   "url": "/search",  "params": {"q": "; cat /etc/passwd"}},
    {"name": "Command Injection #2",   "url": "/search",  "params": {"q": "| whoami"}},
    {"name": "Command Injection #3",   "url": "/search",  "params": {"q": "&& rm -rf /"}},

    # Directory Traversal / LFI
    {"name": "Directory Traversal #1", "url": "/search",  "params": {"q": "../../../etc/passwd"}},
    {"name": "Directory Traversal #2", "url": "/search",  "params": {"q": "../../../../windows/system32"}},
    {"name": "LFI #1",                 "url": "/search",  "params": {"q": "../../../../etc/shadow"}},

    # Scanner Detection
    {"name": "Scanner (sqlmap)",       "url": "/test",    "params": {}, "headers": {"User-Agent": "sqlmap/1.7.8"}},
    {"name": "Scanner (nikto)",        "url": "/test",    "params": {}, "headers": {"User-Agent": "Nikto/2.1.6"}},
    {"name": "Scanner (nmap)",         "url": "/test",    "params": {}, "headers": {"User-Agent": "Nmap Scripting Engine"}},

    # XXE
    {"name": "XXE Injection",          "url": "/search",  "params": {"q": "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>"}},

    # Clean requests (should be ALLOWED)
    {"name": "Clean Request #1",       "url": "/search",  "params": {"q": "hello world"}},
    {"name": "Clean Request #2",       "url": "/test",    "params": {}},
    {"name": "Clean Request #3",       "url": "/login",   "params": {"username": "john", "password": "pass123"}},
]

# ─────────────────────────────────────────────────────────────
# COLORS FOR TERMINAL
# ─────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ─────────────────────────────────────────────────────────────
# SIMULATOR
# ─────────────────────────────────────────────────────────────
def run_simulation():
    print(f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════════╗
║      SentinelShield – Live Attack Simulator          ║
║      Target: {BASE_URL}  ║
╚══════════════════════════════════════════════════════╝
{RESET}""")

    print(f"  {YELLOW}Firing {len(ATTACKS)} attack payloads...{RESET}")
    print(f"  {YELLOW}Watch dashboard → {BASE_URL}{RESET}\n")
    time.sleep(1)

    blocked = 0
    allowed = 0
    errors  = 0

    for i, attack in enumerate(ATTACKS, 1):
        url     = BASE_URL + attack["url"]
        params  = attack.get("params", {})
        headers = attack.get("headers", {})

        try:
            resp = requests.get(url, params=params, headers=headers, timeout=8)

            if resp.status_code == 403:
                status = f"{RED}BLOCKED 403{RESET}"
                blocked += 1
            elif resp.status_code == 429:
                status = f"{YELLOW}RATE LTD 429{RESET}"
                blocked += 1
            elif resp.status_code == 200:
                status = f"{GREEN}ALLOWED 200{RESET}"
                allowed += 1
            else:
                status = f"{YELLOW}STATUS {resp.status_code}{RESET}"

            print(f"  [{i:02d}/{len(ATTACKS)}] {status}  {attack['name']}")

        except requests.exceptions.RequestException as e:
            print(f"  [{i:02d}/{len(ATTACKS)}] {YELLOW}ERROR{RESET}     {attack['name']} ({str(e)[:40]})")
            errors += 1

        # Small delay between requests
        time.sleep(0.4 + random.uniform(0, 0.3))

    # ── Summary ──
    print(f"""
{CYAN}{'─'*54}
  Results:
    {RED}Blocked / Rate Limited : {blocked}{RESET}
    {GREEN}Allowed                : {allowed}{RESET}
    {YELLOW}Errors                 : {errors}{RESET}
{CYAN}{'─'*54}{RESET}
""")

    # ── Rate limit test ──
    print(f"  {YELLOW}Running brute force rate limit test (20 rapid requests)...{RESET}")
    rate_blocked = 0
    for i in range(20):
        try:
            resp = requests.get(f"{BASE_URL}/login",
                                params={"username": "admin", "password": "test"},
                                timeout=5)
            if resp.status_code == 429:
                rate_blocked += 1
                print(f"  [{i+1:02d}/20] {YELLOW}RATE LIMITED{RESET}")
            else:
                print(f"  [{i+1:02d}/20] {GREEN}ALLOWED{RESET}")
        except:
            pass
        time.sleep(0.1)

    print(f"\n  {CYAN}Rate limit triggered on {rate_blocked}/20 requests{RESET}")
    print(f"\n  {GREEN}{BOLD}✓ Simulation complete! Check your dashboard now.{RESET}")
    print(f"  {CYAN}→ {BASE_URL}{RESET}\n")


if __name__ == "__main__":
    run_simulation()
