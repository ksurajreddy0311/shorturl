import re
import string
import random
import os
from urllib.parse import urlparse
from datetime import datetime
from flask import Flask, request, jsonify, redirect, send_from_directory, render_template

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")

# =========================================================
# In-Memory Database Storage
# Stores shortened links as dictionaries
# =========================================================
links_db = {}

# Seed initial sample data for demonstration
INITIAL_SAMPLES = [
    {
        "short_code": "link-1",
        "original_url": "https://en.wikipedia.org/wiki/URL_shortening",
        "clicks": 12,
        "is_suspicious": False,
        "security_reason": "Safe & Verified",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")
    },
    {
        "short_code": "link-2",
        "original_url": "https://docs.python.org/3/library/urllib.parse.html",
        "clicks": 5,
        "is_suspicious": False,
        "security_reason": "Safe & Verified",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")
    }
]

for item in INITIAL_SAMPLES:
    links_db[item["short_code"]] = item


# =========================================================
# Security & Malicious Link Detection Logic
# =========================================================
# Known suspicious keywords frequently used in phishing/credential harvesting
SUSPICIOUS_KEYWORDS = [
    "free-gift", "claim-reward", "free-crypto", "paypal-security-update",
    "banking-login", "account-verification-alert", "recover-password",
    "free-robux", "bit.ly-fake", "free-vbucks"
]

# High-risk TLDs often abused in fast-flux phishing campaigns
SUSPICIOUS_TLDS = [".xyz", ".top", ".buzz", ".work", ".tk", ".gq", ".ml", ".cf"]

# Regular expression to identify direct raw IPv4 address usage (e.g. http://192.168.1.1/login)
IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$")


def inspect_url_security(url: str):
    """
    Analyzes submitted URL against common malicious patterns:
    1. Direct raw IP addresses as hostnames
    2. High-risk top-level domains (.tk, .xyz, etc.)
    3. Phishing and credential-theft keywords
    4. Excessive subdomains / @ symbol obfuscation
    Returns (is_suspicious: bool, reason: str)
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    full_url_lower = url.lower()

    # Check 1: Userinfo / @ symbol in URL (often used to obscure destination)
    if parsed.username or "@" in parsed.netloc:
        return True, "Suspicious: Contains '@' symbol which can hide destination"

    # Check 2: Direct raw IP address host
    if IPV4_REGEX.match(parsed.netloc):
        return True, "Warning: Hostname is a raw IP address"

    # Check 3: Known phishing/credential scam keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in full_url_lower:
            return True, f"High risk: Contains phishing pattern '{keyword}'"

    # Check 4: Suspicious TLD check
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            return True, f"Caution: Registered on high-risk domain extension '{tld}'"

    # Check 5: Excessive subdomains (> 4 dots)
    if hostname.count(".") > 4:
        return True, "Suspicious: Unusually excessive subdomain nesting"

    return False, "Safe & Verified"


def is_valid_url(url: str) -> bool:
    """
    Validates URL structure:
    - Must be a non-empty string
    - Scheme must strictly be 'http' or 'https'
    - Must contain a valid network location (hostname)
    """
    if not url or not isinstance(url, str):
        return False

    url = url.strip()
    try:
        parsed = urlparse(url)
        # Scheme must strictly be http or https
        if parsed.scheme not in ["http", "https"]:
            return False
        # Must have a hostname/netloc (e.g. example.com)
        if not parsed.netloc:
            return False
        # Hostname must have at least one dot (domain.tld) or be localhost
        if "." not in parsed.netloc and parsed.netloc.split(":")[0] != "localhost":
            return False
        return True
    except Exception:
        return False


def generate_short_code(length: int = 6) -> str:
    """
    Generates a unique random alphanumeric short code (e.g. 'aB3x9z').
    Ensures no collision with existing keys.
    """
    chars = string.ascii_letters + string.digits
    while True:
        code = "".join(random.choices(chars, k=length))
        if code not in links_db:
            return code


# =========================================================
# Frontend Routes
# =========================================================
@app.route("/")
def index():
    """Serves the main HTML page."""
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/<path:filename>")
def serve_static(filename):
    """Serves static CSS, JS or assets."""
    return send_from_directory(BASE_DIR, filename)


# =========================================================
# REST API Endpoints
# =========================================================
@app.route("/api/shorten", methods=["POST"])
def shorten_url():
    """
    POST /api/shorten
    Request JSON: { "url": "https://example.com" }
    Response JSON: {
        "success": true,
        "short_code": "abc123",
        "short_url": "http://127.0.0.1:5000/r/abc123",
        "original_url": "https://example.com",
        "is_suspicious": false,
        "security_reason": "Safe & Verified"
    }
    """
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"success": False, "error": "Missing 'url' field in request JSON"}), 400

    raw_url = str(data["url"]).strip()

    # Step 1: Validate scheme and format
    if not is_valid_url(raw_url):
        return jsonify({
            "success": False,
            "error": "Invalid URL. Please enter a complete URL starting with http:// or https://"
        }), 400

    # Step 2: Check for malicious / suspicious patterns
    is_suspicious, security_reason = inspect_url_security(raw_url)

    # Step 3: Check if this URL was already shortened (optional reuse)
    for code, item in links_db.items():
        if item["original_url"] == raw_url:
            short_url = f"{request.host_url.rstrip('/')}/r/{code}"
            return jsonify({
                "success": True,
                "short_code": code,
                "short_url": short_url,
                "original_url": item["original_url"],
                "clicks": item["clicks"],
                "is_suspicious": item["is_suspicious"],
                "security_reason": item["security_reason"],
                "message": "Existing link retrieved"
            }), 200

    # Step 4: Generate unique code and save
    short_code = generate_short_code(6)
    short_url = f"{request.host_url.rstrip('/')}/r/{short_code}"

    link_entry = {
        "short_code": short_code,
        "original_url": raw_url,
        "clicks": 0,
        "is_suspicious": is_suspicious,
        "security_reason": security_reason,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")
    }
    links_db[short_code] = link_entry

    return jsonify({
        "success": True,
        "short_code": short_code,
        "short_url": short_url,
        "original_url": raw_url,
        "clicks": 0,
        "is_suspicious": is_suspicious,
        "security_reason": security_reason
    }), 201


@app.route("/api/links", methods=["GET"])
def get_all_links():
    """
    GET /api/links
    Returns the list of all shortened links with click counts and security statuses.
    """
    links_list = []
    # Display newest first
    for code, item in reversed(list(links_db.items())):
        links_list.append({
            "short_code": item["short_code"],
            "short_url": f"{request.host_url.rstrip('/')}/r/{item['short_code']}",
            "original_url": item["original_url"],
            "clicks": item["clicks"],
            "is_suspicious": item["is_suspicious"],
            "security_reason": item["security_reason"],
            "created_at": item.get("created_at", "")
        })

    return jsonify({"success": True, "links": links_list})


# =========================================================
# Redirection Endpoint
# =========================================================
@app.route("/r/<short_code>")
def redirect_to_url(short_code):
    """
    GET /r/<short_code>
    Increments click count and redirects user to target destination.
    If the link was flagged as suspicious, warns the user first with an intermediate page.
    """
    if short_code not in links_db:
        return """
        <!DOCTYPE html>
        <html>
        <head><title>404 Not Found</title></head>
        <body style="font-family: Arial; padding: 40px; text-align: center;">
            <h2>Link Not Found</h2>
            <p>The short link you followed does not exist.</p>
            <a href="/" style="color: #0066cc;">Go back to Home</a>
        </body>
        </html>
        """, 404

    item = links_db[short_code]
    item["clicks"] += 1

    # If flagged as suspicious, show a security caution warning page
    if item["is_suspicious"] and request.args.get("proceed") != "1":
        escaped_url = item["original_url"].replace('"', '&quot;')
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Security Warning - Suspicious Link</title>
            <style>
                body {{ font-family: Arial, sans-serif; background: #fff; color: #000; padding: 40px 20px; }}
                .box {{ max-width: 550px; margin: 0 auto; border: 2px solid #d9534f; padding: 25px; border-radius: 6px; }}
                h2 {{ color: #d9534f; margin-top: 0; }}
                .reason {{ background: #fdf7f7; border-left: 4px solid #d9534f; padding: 10px 15px; margin: 15px 0; }}
                .url {{ word-break: break-all; font-family: monospace; background: #f1f1f1; padding: 6px; display: block; margin: 10px 0; }}
                .btn-danger {{ background: #d9534f; color: white; padding: 8px 16px; border: none; text-decoration: none; border-radius: 4px; display: inline-block; }}
                .btn-safe {{ background: #0066cc; color: white; padding: 8px 16px; border: none; text-decoration: none; border-radius: 4px; display: inline-block; margin-right: 10px; }}
            </style>
        </head>
        <body>
            <div class="box">
                <h2>⚠️ Security Warning</h2>
                <p>CypherLink security filter detected potentially suspicious patterns in this link:</p>
                <div class="reason"><strong>Reason:</strong> {item['security_reason']}</div>
                <p>Destination URL:</p>
                <span class="url">{escaped_url}</span>
                <p style="font-size: 13px; color: #666;">If you do not trust this destination, return to safety.</p>
                <br>
                <a href="/" class="btn-safe">Go Back to Home</a>
                <a href="/r/{short_code}?proceed=1" class="btn-danger">Proceed Anyway (Unsafe)</a>
            </div>
        </body>
        </html>
        """, 200

    # Safe redirect
    return redirect(item["original_url"], code=302)


if __name__ == "__main__":
    # Runs locally on port 8080 (port 8080 is reliable and avoids Windows port 5000 permission conflicts)
    print("Starting Secure URL Shortener on http://127.0.0.1:8080")
    app.run(host="127.0.0.1", port=8080, debug=True)
