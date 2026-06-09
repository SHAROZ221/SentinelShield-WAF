"""
monitor.py – Rate Limiting & IP Behaviour Monitor
==================================================
This module tracks how many requests each IP address sends in a given
time window. If an IP exceeds the allowed limit, it is flagged as
potentially running a brute-force attack or automated scan.

HOW IT WORKS:
- Every request that arrives is recorded in a dictionary keyed by IP.
- We store a list of timestamps for each IP.
- Old timestamps (outside the time window) are cleaned up on every check.
- If the count of recent requests exceeds MAX_REQUESTS, the IP is flagged.

This is how real systems implement rate limiting (e.g., Nginx limit_req,
Cloudflare rate limiting rules).
"""

import time
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# Maximum requests allowed from one IP within the time window
MAX_REQUESTS = 15

# Time window in seconds (30 seconds)
TIME_WINDOW = 30

# How long (seconds) a flagged IP stays on the blocklist
BLOCK_DURATION = 120  # 2 minutes

# ─────────────────────────────────────────────────────────────────────────────
# STATE (kept in memory — resets when server restarts)
# ─────────────────────────────────────────────────────────────────────────────

# { "ip_address": [timestamp1, timestamp2, ...] }
request_log = defaultdict(list)

# { "ip_address": unblock_timestamp }
blocked_ips = {}


def record_request(ip: str) -> dict:
    """
    Record a new request from the given IP and check if rate limit is exceeded.

    Parameters:
        ip (str): The IP address of the incoming request.

    Returns:
        dict with keys:
            "blocked"      → True if this IP is currently rate-limited
            "request_count"→ Number of requests from this IP in the window
            "is_new_block" → True if this request caused a NEW block
    """
    now = time.time()

    # ── Step 1: Check if IP is already blocked ────────────────────────────
    if ip in blocked_ips:
        if now < blocked_ips[ip]:
            # Still within block duration
            return {
                "blocked": True,
                "request_count": len(request_log[ip]),
                "is_new_block": False
            }
        else:
            # Block has expired — remove it
            del blocked_ips[ip]

    # ── Step 2: Record this request's timestamp ───────────────────────────
    request_log[ip].append(now)

    # ── Step 3: Remove timestamps older than the time window ─────────────
    request_log[ip] = [
        t for t in request_log[ip]
        if now - t <= TIME_WINDOW
    ]

    count = len(request_log[ip])

    # ── Step 4: Check if limit exceeded ───────────────────────────────────
    if count > MAX_REQUESTS:
        blocked_ips[ip] = now + BLOCK_DURATION
        return {
            "blocked": True,
            "request_count": count,
            "is_new_block": True
        }

    return {
        "blocked": False,
        "request_count": count,
        "is_new_block": False
    }


def is_blocked(ip: str) -> bool:
    """Quick check: is this IP currently blocked?"""
    now = time.time()
    if ip in blocked_ips:
        if now < blocked_ips[ip]:
            return True
        else:
            del blocked_ips[ip]
    return False


def get_top_ips(n: int = 10) -> list:
    """
    Return the top N most active IPs sorted by request count.

    Returns:
        List of dicts: [{"ip": "...", "count": N, "blocked": bool}, ...]
    """
    now = time.time()
    summary = []

    for ip, timestamps in request_log.items():
        # Count only recent requests
        recent = [t for t in timestamps if now - t <= TIME_WINDOW * 10]
        if recent:
            summary.append({
                "ip": ip,
                "count": len(recent),
                "blocked": ip in blocked_ips
            })

    # Sort by count descending
    summary.sort(key=lambda x: x["count"], reverse=True)
    return summary[:n]


def get_blocked_ips() -> list:
    """Return list of currently blocked IPs."""
    now = time.time()
    active = []
    for ip, unblock_time in list(blocked_ips.items()):
        if now < unblock_time:
            active.append({
                "ip": ip,
                "unblocks_in": round(unblock_time - now)
            })
        else:
            del blocked_ips[ip]
    return active


def get_stats() -> dict:
    """Return a summary dict for the dashboard."""
    return {
        "total_tracked_ips": len(request_log),
        "currently_blocked": len(get_blocked_ips()),
        "top_ips": get_top_ips(5),
        "rate_limit_config": {
            "max_requests": MAX_REQUESTS,
            "time_window_seconds": TIME_WINDOW,
            "block_duration_seconds": BLOCK_DURATION
        }
    }
