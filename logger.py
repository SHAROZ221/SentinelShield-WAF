"""
logger.py – Structured Event Logging System
============================================
Every request that SentinelShield processes gets logged here.
Logs are stored in JSON format — one JSON object per line (JSONL format).
This makes them easy to read, parse, and analyze later.

WHY JSON LOGS?
- Real SIEM systems (Splunk, Elastic Stack) ingest JSON logs natively.
- Each field (IP, timestamp, attack type) can be filtered and queried.
- It's the industry standard for security event logging.

LOG FILE LOCATION: logs/sentinel.log
"""

import json
import os
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "sentinel.log")

# Ensure the logs directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# LOG EVENT TYPES
# ─────────────────────────────────────────────────────────────────────────────

EVENT_ALLOWED   = "ALLOWED"    # Normal, clean request
EVENT_BLOCKED   = "BLOCKED"    # Malicious payload detected
EVENT_RATE_LIMIT = "RATE_LIMITED"  # Too many requests from one IP
EVENT_ALERT     = "ALERT"      # High-severity detection


def log_event(
    ip: str,
    method: str,
    path: str,
    event_type: str,
    detections: list = None,
    payload_sample: str = "",
    user_agent: str = "",
    extra: dict = None
):
    """
    Write a single log entry to the log file.

    Parameters:
        ip           : IP address of the requester
        method       : HTTP method (GET, POST, etc.)
        path         : Request URL path
        event_type   : One of ALLOWED / BLOCKED / RATE_LIMITED / ALERT
        detections   : List of detected attack dicts [{"name": ..., "severity": ...}]
        payload_sample: The suspicious part of the request (truncated for safety)
        user_agent   : Browser/tool identifier from User-Agent header
        extra        : Any additional key-value pairs to include
    """

    entry = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "ip": ip,
        "method": method,
        "path": path,
        "event": event_type,
        "detections": detections or [],
        "payload_sample": payload_sample[:200] if payload_sample else "",  # Limit length
        "user_agent": user_agent[:150] if user_agent else "",
    }

    # Merge any extra fields
    if extra:
        entry.update(extra)

    # Write to log file (append mode)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def read_logs(limit: int = 200) -> list:
    """
    Read the most recent log entries.

    Parameters:
        limit (int): Maximum number of entries to return (most recent first)

    Returns:
        List of log entry dicts
    """
    if not os.path.exists(LOG_FILE):
        return []

    entries = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # Skip malformed lines

    # Return most recent first
    return list(reversed(entries))[-limit:]


def get_statistics() -> dict:
    """
    Analyze all log entries and return summary statistics for the dashboard.

    Returns a dict with:
        total_requests     : Total logged requests
        blocked_count      : Number of blocked requests
        allowed_count      : Number of allowed requests
        rate_limited_count : Number of rate-limited requests
        attack_breakdown   : { "SQL Injection": 5, "XSS": 3, ... }
        severity_breakdown : { "HIGH": 8, "MEDIUM": 2, "LOW": 1 }
        top_attacking_ips  : [ {"ip": "...", "count": N}, ... ]
        recent_alerts      : Last 10 high-severity events
        detection_rate     : Percentage of requests that were malicious
    """
    logs = read_logs(limit=10000)  # Read all for stats

    if not logs:
        return {
            "total_requests": 0,
            "blocked_count": 0,
            "allowed_count": 0,
            "rate_limited_count": 0,
            "attack_breakdown": {},
            "severity_breakdown": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "top_attacking_ips": [],
            "recent_alerts": [],
            "detection_rate": 0,
        }

    # Count event types
    blocked   = [l for l in logs if l.get("event") == EVENT_BLOCKED]
    allowed   = [l for l in logs if l.get("event") == EVENT_ALLOWED]
    rate_ltd  = [l for l in logs if l.get("event") == EVENT_RATE_LIMIT]

    # Attack type breakdown
    attack_counts = {}
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for entry in blocked:
        for det in entry.get("detections", []):
            name = det.get("name", "Unknown")
            sev  = det.get("severity", "LOW")
            attack_counts[name] = attack_counts.get(name, 0) + 1
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Top attacking IPs
    ip_counts = {}
    for entry in blocked + rate_ltd:
        ip = entry.get("ip", "unknown")
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    top_ips = sorted(
        [{"ip": ip, "count": count} for ip, count in ip_counts.items()],
        key=lambda x: x["count"],
        reverse=True
    )[:10]

    # Recent high-severity alerts
    recent_alerts = [
        l for l in logs
        if any(d.get("severity") == "HIGH" for d in l.get("detections", []))
    ][:10]

    total = len(logs)
    malicious = len(blocked) + len(rate_ltd)
    detection_rate = round((malicious / total * 100), 1) if total > 0 else 0

    return {
        "total_requests":     total,
        "blocked_count":      len(blocked),
        "allowed_count":      len(allowed),
        "rate_limited_count": len(rate_ltd),
        "attack_breakdown":   attack_counts,
        "severity_breakdown": severity_counts,
        "top_attacking_ips":  top_ips,
        "recent_alerts":      recent_alerts,
        "detection_rate":     detection_rate,
    }


def clear_logs():
    """Clear all log entries (useful for resetting during testing)."""
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("")
    return {"status": "logs cleared"}
