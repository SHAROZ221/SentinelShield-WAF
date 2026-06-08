"""
app.py – SentinelShield Main WAF Server
"""

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
import json
import os

# Import our custom modules
from rules   import inspect_request
from monitor import record_request, is_blocked, get_stats as monitor_stats
from logger  import log_event, get_statistics, read_logs, clear_logs, \
                    EVENT_ALLOWED, EVENT_BLOCKED, EVENT_RATE_LIMIT

# ─────────────────────────────────────────────────────────────────────────────
# FLASK APP SETUP
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Extract and combine all inspectable data from a request
# ─────────────────────────────────────────────────────────────────────────────

def extract_request_data(req) -> tuple:
    parts = []
    parts.append(req.path)
    parts.append(req.query_string.decode("utf-8", errors="ignore"))
    for key, value in req.form.items():
        parts.append(f"{key}={value}")
    if req.is_json:
        try:
            body = req.get_json(force=True, silent=True)
            if body:
                parts.append(json.dumps(body))
        except Exception:
            pass
    try:
        raw = req.get_data(as_text=True)
        if raw:
            parts.append(raw[:500])
    except Exception:
        pass
    parts.append(req.headers.get("User-Agent", ""))
    combined = " ".join(parts)
    payload_sample = combined[:300]
    return combined, payload_sample


# ─────────────────────────────────────────────────────────────────────────────
# BEFORE EVERY REQUEST: Run WAF inspection
# ─────────────────────────────────────────────────────────────────────────────

@app.before_request
def waf_inspect():
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
        }), 429

    combined_data, payload_sample = extract_request_data(request)
    detections = inspect_request(combined_data)

    if detections:
        log_event(
            ip=ip, method=method, path=path,
            event_type=EVENT_BLOCKED,
            detections=detections,
            payload_sample=payload_sample,
            user_agent=user_agent
        )
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
        }), 403

    log_event(
        ip=ip, method=method, path=path,
        event_type=EVENT_ALLOWED,
        detections=[],
        payload_sample="",
        user_agent=user_agent
    )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/test", methods=["GET", "POST"])
def test_endpoint():
    return jsonify({
        "status":  "ALLOWED",
        "message": "Request passed WAF inspection — no threats detected.",
        "method":  request.method,
        "path":    request.path,
        "allowed": True
    }), 200


@app.route("/login", methods=["GET", "POST"])
def login():
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
    query = request.args.get("q", request.form.get("q", ""))
    return jsonify({
        "status":  "ALLOWED",
        "message": "Search endpoint reached",
        "query":   query[:100] if query else "",
        "allowed": True
    }), 200


@app.route("/upload", methods=["POST"])
def upload():
    return jsonify({
        "status":  "ALLOWED",
        "message": "Upload endpoint reached",
        "allowed": True
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/stats", methods=["GET"])
def api_stats():
    log_stats = get_statistics()
    mon_stats = monitor_stats()
    return jsonify({**log_stats, "monitor": mon_stats})


@app.route("/api/logs", methods=["GET"])
def api_logs():
    limit = int(request.args.get("limit", 50))
    logs  = read_logs(limit=limit)
    return jsonify({"logs": logs, "count": len(logs)})


@app.route("/api/clear", methods=["POST"])
def api_clear():
    result = clear_logs()
    return jsonify(result)


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
@app.route("/dashboard")
def dashboard():
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
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
