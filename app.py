from flask import Flask, request, render_template, jsonify, send_file, redirect, url_for
import socket
import os
import json
from datetime import datetime

app = Flask(__name__)

# Default ports and their descriptions with threat levels
PORT_INFO = {
    20: ("FTP Data Transfer", 1),
    21: ("FTP Control", 2),
    22: ("SSH - Secure Shell", 3),
    23: ("Telnet - Remote Login", 3),
    25: ("SMTP - Email Sending", 2),
    53: ("DNS - Domain Resolution", 1),
    80: ("HTTP - Web Traffic", 2),
    110: ("POP3 - Email Receiving", 2),
    143: ("IMAP - Email Sync", 2),
    443: ("HTTPS - Secure Web", 1),
    3306: ("MySQL Database", 3),
    3389: ("Remote Desktop Protocol", 4),
    5900: ("VNC - Remote Access", 3),
    8080: ("Alternative Web Traffic", 2)
}

# Neon-themed threat levels
THREAT_LEVELS = {
    1: ("🟢 Static Breeze", "Harmless background noise, idle services", "#00FFC6"),
    2: ("🟡 Phantom Echo", "Unsecured services, misconfigured ports", "#FFE156"),
    3: ("🟠 Crimson Pulse", "Vulnerable services, suspicious patterns", "#FF6F61"),
    4: ("🔴 Zero Protocol", "Known exploits, active malware", "#FF3B3B"),
    5: ("⚫ Blackout Eclipse", "Critical breach, APTs, rootkits", "#191919")
}

# Scan log to store search history
SCAN_LOG = []

@app.route("/")
def index():
    return render_template("index.html", threat_levels=THREAT_LEVELS)

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/download-log")
def download_log():
    filename = "scan_log.json"
    with open(filename, "w") as f:
        json.dump(SCAN_LOG, f, indent=4)
    return send_file(filename, as_attachment=True)

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    host = data.get("host")
    justification = data.get("justification")
    confirm = data.get("confirm")
    age = data.get("age")

    if not confirm or not justification or not age or int(age) < 16:
        return jsonify({"error": "Permission not granted or age requirement not met."}), 403

    results = []
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return jsonify({"error": f"Could not resolve host: {e}"}), 400

    for port, (desc, level) in PORT_INFO.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((host, port))
                status = "Open" if result == 0 else "Closed"
                results.append({
                    "port": port,
                    "status": status,
                    "description": desc,
                    "threat_level": level,
                    "threat_name": THREAT_LEVELS[level][0],
                    "threat_description": THREAT_LEVELS[level][1],
                    "color": THREAT_LEVELS[level][2]
                })
        except Exception as e:
            results.append({
                "port": port,
                "status": f"Error: {str(e)}",
                "description": desc,
                "threat_level": level,
                "threat_name": THREAT_LEVELS[level][0],
                "threat_description": THREAT_LEVELS[level][1],
                "color": THREAT_LEVELS[level][2]
            })

    SCAN_LOG.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host": host,
        "justification": justification,
        "results": results
    })

    return jsonify({"ip": ip, "host": host, "results": results})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
