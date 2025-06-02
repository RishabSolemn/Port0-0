from flask import Flask, request, render_template, jsonify, send_file
import socket
import os
import json
from datetime import datetime

app = Flask(__name__)

# Default ports and their descriptions
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

THREAT_LEVELS = {
    1: ("🟢 Static Breeze", "Harmless background noise, idle services", "Soft green"),
    2: ("🟡 Phantom Echo", "Unsecured services, misconfigured ports", "Golden yellow"),
    3: ("🟠 Crimson Pulse", "Vulnerable services, suspicious patterns", "Bright orange"),
    4: ("🔴 Zero Protocol", "Known exploits, active malware", "Red"),
    5: ("⚫ Blackout Eclipse", "Critical breach, APTs, rootkits", "Black")
}

SCAN_LOG = []

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
    results = []

    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return jsonify({"error": f"Could not resolve host: {e}"})

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
                    "threat_name": THREAT_LEVELS[level][0]
                })
        except Exception as e:
            results.append({
                "port": port,
                "status": f"Error: {str(e)}",
                "description": desc,
                "threat_level": level,
                "threat_name": THREAT_LEVELS[level][0]
            })

    SCAN_LOG.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host": host,
        "results": results
    })

    return jsonify({"ip": ip, "host": host, "results": results})

@app.route("/")
def index():
    return render_template("index.html", threat_levels=THREAT_LEVELS)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
