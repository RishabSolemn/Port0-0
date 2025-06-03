from flask import Flask, request, jsonify, send_file
import os
import json
import datetime
import socket

app = Flask(__name__)
SCAN_LOG = []

# Threat scoring system
def get_threat_score(open_ports):
    count = len(open_ports)
    if count >= 50:
        return "High", 90
    elif count >= 10:
        return "Medium", 50
    else:
        return "Low", 15

# AI-powered port interpretation
def interpret_port(port):
    descriptions = {
        21: "FTP - File Transfer Protocol",
        22: "SSH - Secure Shell",
        23: "Telnet - Remote Terminal",
        25: "SMTP - Email",
        53: "DNS - Domain Name System",
        80: "HTTP - Web Traffic",
        110: "POP3 - Email Retrieval",
        143: "IMAP - Email Access",
        443: "HTTPS - Secure Web Traffic",
        3306: "MySQL Database",
        3389: "Remote Desktop",
        8080: "Alternative HTTP"
    }
    return descriptions.get(port, "Unknown or uncommon service")

# Fake DNS/CDN deception check
def check_dns_deception(host):
    try:
        ip = socket.gethostbyname(host)
        return "cdn" in host.lower() or ip.startswith("192.")
    except:
        return False

def port_scan(host, ports):
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex((host, port)) == 0:
                    open_ports.append(port)
        except:
            continue
    return open_ports

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    host = data.get("host")

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return jsonify({"error": "Invalid host"}), 400

    ports_to_scan = list(range(1, 1025))
    open_ports = port_scan(ip, ports_to_scan)
    threat_rating, threat_score = get_threat_score(open_ports)

    results = [{
        "port": port,
        "status": "open",
        "description": interpret_port(port),
        "color": "#FF3B3B" if port < 1024 else "#00ffc6"
    } for port in open_ports]

    geo_data = {
        "city": "Unknown",
        "region": "Unknown",
        "country": "Unknown",
        "latitude": "0.0000",
        "longitude": "0.0000"
    }

    result = {
        "host": host,
        "ip": ip,
        "timestamp": datetime.datetime.now().isoformat(),
        "threat_rating": threat_rating,
        "threat_score": threat_score,
        "results": results,
        "geo_data": geo_data,
        "dns_deception": check_dns_deception(host)
    }

    SCAN_LOG.append(result)
    return jsonify(result)

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
