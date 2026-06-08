"""
app.py – SentinelShield Main WAF Server
========================================
This is the heart of SentinelShield. It is a Flask web server that acts
as a Web Application Firewall (WAF).

HOW IT WORKS:
1. Every incoming HTTP request is intercepted BEFORE being processed.
2. The request is inspected for malicious patterns (via rules.py).
3. The IP is checked for rate-limit violations (via monitor.py).
4. The event is logged (via logger.py).
5. If malicious → return 403 FORBIDDEN with an alert message.
6. If clean → return 200 OK and allow it through.

The dashboard at http://localhost:5000/ shows live statistics.

RUN THIS FILE TO START THE SERVER:
    python app.py
"""

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
import json
import os

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)

# Import our custom modules
from rules   import inspect_request
from monitor import record_request, is_blocked, get_stats as monitor_stats
from logger  import log_event, get_statistics, read_logs, clear_logs, \
                    EVENT_ALLOWED, EVENT_BLOCKED, EVENT_RATE_LIMIT

# ─────────────────────────────────────────────────────────────────────────────
# FLASK APP SETUP
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)  # Allow cross-origin requests (needed for the simulator)

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Extract and combine all inspectable data from a request
# ─────────────────────────────────────────────────────────────────────────────

def extract_request_data(req) -> tuple:
    """
    Pull together all parts of an HTTP request into a single string
    that can be scanned for malicious patterns.

    Returns:
        (combined_string, payload_sample)
        combined_string : Everything concatenated for scanning
        payload_sample  : A short sample of what was suspicious
    """
    parts = []

    # URL path
    parts.append(req.path)

    # Query string parameters (e.g., ?id=1&name=test)
    parts.append(req.query_string.decode("utf-8", errors="ignore"))

    # POST form data
    for key, value in req.form.items():
        parts.append(f"{key}={value}")

    # JSON body
    if req.is_json:
        try:
            body = req.get_json(force=True, silent=True)
            if body:
                parts.append(json.dumps(body))
        except Exception:
            pass

    # Raw body (for non-JSON POST)
    try:
        raw = req.get_data(as_text=True)
        if raw:
            parts.append(raw[:500])  # Limit to 500 chars
    except Exception:
        pass

    # User-Agent header (scanners often reveal themselves here)
    parts.append(req.headers.get("User-Agent", ""))

    combined = " ".join(parts)
    payload_sample = combined[:300]  # Keep a sample for the log

    return combined, payload_sample


# ─────────────────────────────────────────────────────────────────────────────
# BEFORE EVERY REQUEST: Run WAF inspection
# ─────────────────────────────────────────────────────────────────────────────

@app.before_request
def waf_inspect():
    """
    This function runs BEFORE every single request.
    It is the core WAF gate — allow or block.
    """

    # Skip WAF for dashboard and API routes (they're internal)
    # IMPORTANT: Use exact match for "/" to avoid skipping everything
    internal_paths_prefix = ["/api/", "/static/", "/dashboard"]
    internal_paths_exact  = ["/", "/favicon.ico"]

    if request.path in internal_paths_exact:
        return None
    if any(request.path.startswith(p) for p in internal_paths_prefix):
        return None

    ip         = request.remote_addr or "unknown"
    method     = request.method
    path       = request.path
    user_agent = request.headers.get("User-Agent", "")

    # ── Step 1: Rate limit check ──────────────────────────────────────────
    rate_result = record_request(ip)

    if rate_result["blocked"]:
        log_event(
            ip=ip, method=method, path=path,
            event_type=EVENT_RATE_LIMIT,
            detections=[{"name": "Rate Limit Exceeded", "severity": "MEDIUM"}],
            payload_sample=f"Request #{rate_result['request_count']} in window",
            user_agent=user_agent
        )
        return jsonify({
            "status":  "BLOCKED",
            "reason":  "Rate limit exceeded — too many requests",
            "ip":      ip,
            "allowed": False
        }), 429  # 429 = Too Many Requests

    # ── Step 2: Attack signature inspection ──────────────────────────────
    combined_data, payload_sample = extract_request_data(request)
    detections = inspect_request(combined_data)

    if detections:
        # Log the blocked request
        log_event(
            ip=ip, method=method, path=path,
            event_type=EVENT_BLOCKED,
            detections=detections,
            payload_sample=payload_sample,
            user_agent=user_agent
        )

        # Build a human-readable response
        attack_names = [d["name"] for d in detections]
        severities   = [d["severity"] for d in detections]
        top_severity = "HIGH" if "HIGH" in severities else \
                       "MEDIUM" if "MEDIUM" in severities else "LOW"

        return jsonify({
            "status":       "BLOCKED",
            "reason":       f"Malicious content detected: {', '.join(attack_names)}",
            "attack_types": attack_names,
            "severity":     top_severity,
            "ip":           ip,
            "allowed":      False,
            "message":      "Your request was blocked by SentinelShield WAF."
        }), 403  # 403 = Forbidden

    # ── Step 3: Request is clean — allow it ──────────────────────────────
    log_event(
        ip=ip, method=method, path=path,
        event_type=EVENT_ALLOWED,
        detections=[],
        payload_sample="",
        user_agent=user_agent
    )

    return None  # None = allow the request to continue


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES: Protected test endpoints (the WAF guards these)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/test", methods=["GET", "POST"])
def test_endpoint():
    """
    A simple test endpoint. Send requests here to test the WAF.
    Clean requests will see this response; malicious ones get blocked.
    """
    return jsonify({
        "status":  "ALLOWED",
        "message": "Request passed WAF inspection — no threats detected.",
        "method":  request.method,
        "path":    request.path,
        "allowed": True
    }), 200


@app.route("/login", methods=["GET", "POST"])
def login():
    """Simulated login form — good target for brute-force rate limit testing."""
    username = request.form.get("username", request.args.get("username", ""))
    password = request.form.get("password", request.args.get("password", ""))

    return jsonify({
        "status":   "ALLOWED",
        "message":  "Login endpoint reached (WAF passed this request)",
        "username": username[:50] if username else "",
        "allowed":  True
    }), 200


@app.route("/search", methods=["GET", "POST"])
def search():
    """Simulated search — common target for SQLi and XSS attacks."""
    query = request.args.get("q", request.form.get("q", ""))
    return jsonify({
        "status":  "ALLOWED",
        "message": "Search endpoint reached",
        "query":   query[:100] if query else "",
        "allowed": True
    }), 200


@app.route("/upload", methods=["POST"])
def upload():
    """Simulated file upload endpoint."""
    return jsonify({
        "status":  "ALLOWED",
        "message": "Upload endpoint reached",
        "allowed": True
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# API ROUTES: Used by the dashboard and simulator
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Return combined statistics from logger + monitor for the dashboard."""
    log_stats  = get_statistics()
    mon_stats  = monitor_stats()

    return jsonify({
        **log_stats,
        "monitor": mon_stats
    })


@app.route("/api/logs", methods=["GET"])
def api_logs():
    """Return recent log entries for the live log table."""
    limit = int(request.args.get("limit", 50))
    logs  = read_logs(limit=limit)
    return jsonify({"logs": logs, "count": len(logs)})


@app.route("/api/clear", methods=["POST"])
def api_clear():
    """Clear all logs (for resetting between test runs)."""
    result = clear_logs()
    return jsonify(result)


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD ROUTE
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
@app.route("/dashboard")
def dashboard():
    """Serve the main dashboard HTML page."""
    return render_template("dashboard.html")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║          SentinelShield WAF – Starting Up                    ║
╠══════════════════════════════════════════════════════════════╣
║  Dashboard  →  http://localhost:5000/                        ║
║  Test WAF   →  http://localhost:5000/test                    ║
║  Logs API   →  http://localhost:5000/api/logs                ║
║  Stats API  →  http://localhost:5000/api/stats               ║
╚══════════════════════════════════════════════════════════════╝
    """)
    app.run(debug=True, host="0.0.0.0", port=5000)
