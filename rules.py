"""
rules.py – Attack Signature Detection Engine
=============================================
This file contains all the attack patterns SentinelShield looks for.
Each rule is a regular expression (regex) pattern that matches known
malicious input seen in real-world web attacks.

HOW IT WORKS:
- When a request comes in, every part of it (URL, parameters, headers, body)
  is checked against these patterns.
- If a match is found, the request is flagged with the attack category name.
- This is exactly how real WAFs (like ModSecurity) work.
"""

import re

# ─────────────────────────────────────────────────────────────────────────────
# ATTACK RULES
# Each rule is a dict with:
#   "name"        → Human-readable attack category
#   "severity"    → HIGH / MEDIUM / LOW
#   "patterns"    → List of regex strings to match against input
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_RULES = [

    {
        "name": "SQL Injection",
        "severity": "HIGH",
        "patterns": [
            r"('|\")\s*(OR|AND)\s*('|\")?\s*\d+\s*=\s*\d+",   # ' OR 1=1
            r"(union[\s\+]+select)",                                # UNION SELECT
            r"(DROP\s+TABLE|DROP\s+DATABASE)",                   # DROP TABLE
            r"(INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+\w+\s+SET)", # DML attacks
            r"(--|\#|\/\*)",                                  # SQL comments at end
            r"(\bOR\b|\bAND\b)\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+[\'\"]?",
            r"(SELECT\s+.+\s+FROM\s+\w+)",                       # SELECT ... FROM
            r"(SLEEP\s*\(\s*\d+\s*\))",                          # Time-based blind
            r"(BENCHMARK\s*\()",                                  # Benchmark attack
            r"xp_cmdshell",                                       # MSSQL command exec
        ]
    },

    {
        "name": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "patterns": [
            r"<\s*script[^>]*>",                                  # <script> tags
            r"<\s*\/\s*script\s*>",                               # </script>
            r"javascript\s*:",                                     # javascript: URI
            r"on\w+\s*=\s*['\"]?[^'\"]*['\"]?",                  # onerror= onclick=
            r"<\s*img[^>]+src\s*=\s*['\"]?\s*x['\"]?[^>]*onerror", # <img src=x onerror>
            r"alert\s*\(",                                         # alert()
            r"document\.(cookie|write|location)",                  # DOM manipulation
            r"eval\s*\(",                                          # eval()
            r"<\s*iframe[^>]*>",                                   # iframes
            r"vbscript\s*:",                                       # VBScript URI
        ]
    },

    {
        "name": "Local File Inclusion (LFI)",
        "severity": "HIGH",
        "patterns": [
            r"\.\./",                                              # Directory traversal ../
            r"\.\.\\",                                             # Windows traversal ..\
            r"%2e%2e%2f",                                          # URL-encoded ../
            r"%252e%252e%252f",                                    # Double-encoded ../
            r"(\/etc\/passwd|\/etc\/shadow)",                      # Linux sensitive files
            r"(\/windows\/system32|boot\.ini|win\.ini)",           # Windows sensitive files
            r"(php:\/\/filter|php:\/\/input)",                     # PHP wrappers
            r"(data:\/\/|expect:\/\/|zip:\/\/)",                   # Dangerous URI schemes
        ]
    },

    {
        "name": "Command Injection",
        "severity": "HIGH",
        "patterns": [
            r";\s*(ls|cat|pwd|whoami|id|uname|ifconfig|ipconfig)", # ; command
            r"\|\s*(ls|cat|pwd|whoami|id|uname|wget|curl)",        # | command
            r"&&\s*(ls|cat|pwd|whoami|id|rm|wget)",                # && command
            r"`[^`]+`",                                            # Backtick execution
            r"\$\([^)]+\)",                                        # $(command)
            r"(\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)",        # Shell references
            r"(wget|curl)\s+http",                                 # Download commands
            r"nc\s+-[el]",                                         # Netcat listener
        ]
    },

    {
        "name": "Directory Traversal",
        "severity": "MEDIUM",
        "patterns": [
            r"(\.\./){2,}",                                        # Multiple ../
            r"(%2f\.\.){2,}",                                      # Encoded multiple
            r"(\/proc\/self\/environ)",                            # /proc access
            r"(\/var\/log\/|\/var\/www\/)",                        # Log/web dir access
            r"(%00|\\x00)",                                        # Null byte injection
        ]
    },

    {
        "name": "XML/XXE Injection",
        "severity": "MEDIUM",
        "patterns": [
            r"<!ENTITY",                                           # XXE entity
            r"SYSTEM\s+['\"]file:\/\/",                           # File URI in XML
            r"<!DOCTYPE[^>]+\[",                                   # DOCTYPE with internal subset
        ]
    },

    {
        "name": "Scanner / Automated Tool",
        "severity": "LOW",
        "patterns": [
            r"(sqlmap|nikto|nmap|masscan|acunetix|nessus)",        # Known scanner names
            r"(python-requests|go-http-client|libwww-perl)",       # Scripted clients
            r"(burpsuite|owasp zap)",                              # Proxy tools
        ]
    },

]


def inspect_request(data: str) -> list:
    """
    Check a string (URL, params, headers, body) against all attack rules.

    Parameters:
        data (str): The string to check (could be URL, param value, header value, etc.)

    Returns:
        list: A list of matched rule dicts (name, severity) — empty if no match.

    Example:
        inspect_request("1' OR '1'='1")
        → [{"name": "SQL Injection", "severity": "HIGH"}]
    """
    matches = []
    data_lower = data.lower()  # Case-insensitive matching

    for rule in ATTACK_RULES:
        for pattern in rule["patterns"]:
            if re.search(pattern, data_lower, re.IGNORECASE):
                # Avoid duplicate entries for the same attack type
                if not any(m["name"] == rule["name"] for m in matches):
                    matches.append({
                        "name": rule["name"],
                        "severity": rule["severity"]
                    })
                break  # One match per rule is enough

    return matches


def get_all_rule_names() -> list:
    """Return a list of all rule names (used for dashboard stats)."""
    return [rule["name"] for rule in ATTACK_RULES]
