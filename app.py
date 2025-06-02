app_py_code = '''
from flask import Flask, request, render_template, jsonify, send_file
import socket
import os
import json
from datetime import datetime
import geoip2.database

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

# Threat level definitions
THREAT_LEVELS = {
    1: ("🟢 Static Breeze", "Idle services, low risk", "#00FFC6"),
    2: ("🟡 Phantom Echo", "Misconfigured or public services", "#FFE156"),
    3: ("🟠 Crimson Pulse", "Known vulnerabilities or risks", "#FF6F61"),
    4: ("🔴 Zero Protocol", "Exploitable services", "#FF3B3B"),
    5: ("⚫ Blackout Eclipse", "Critical threat", "#191919")
}

# Scan log to power timeline
SCAN_LOG = []

@app.route("/")
def index():
    return render_template("index.html", threat_levels=THREAT_LEVELS)

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    host = data.get("host")
    results = []

    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return jsonify({"error": f"Could not resolve host: {e}"}), 400

    open_ports = 0
    total_threat_score = 0

    for port, (desc, level) in PORT_INFO.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((host, port))
                if result == 0:
                    status = "Open"
                    open_ports += 1
                    total_threat_score += level
                else:
                    status = "Closed"

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

    threat_rating = "Low" if open_ports < 10 else "Medium" if open_ports < 50 else "High"

    geo_data = {}
    try:
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        response = reader.city(ip)
        geo_data = {
            "ip": ip,
            "city": response.city.name,
            "region": response.subdivisions.most_specific.name,
            "country": response.country.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude
        }
    except:
        geo_data = {"ip": ip, "error": "GeoIP lookup failed or database missing"}

    scan_record = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host": host,
        "ip": ip,
        "open_ports": open_ports,
        "threat_score": total_threat_score,
        "threat_rating": threat_rating,
        "geo_data": geo_data,
        "results": results
    }
    SCAN_LOG.append(scan_record)

    return jsonify(scan_record)

@app.route("/download-log")
def download_log():
    filename = "scan_log.json"
    with open(filename, "w") as f:
        json.dump(SCAN_LOG, f, indent=4)
    return send_file(filename, as_attachment=True)

@app.route("/scan-log")
def scan_log():
    return jsonify(SCAN_LOG)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
'''

app_py_code
