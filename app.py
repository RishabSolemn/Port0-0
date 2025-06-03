from flask import Flask, render_template, request, jsonify
import socket
from datetime import datetime

app = Flask(__name__)

# Helper: interpret port with AI-style logic
def interpret_port(port):
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP"
    }
    return common_ports.get(port, "Unknown service or uncommon port")

# Threat level calculator
def get_threat_level(open_ports):
    count = len(open_ports)
    if count < 10:
        return "Low"
    elif 10 <= count < 50:
        return "Medium"
    else:
        return "High"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    try:
        target = request.form.get("target", "").strip()
        start_port = int(request.form.get("start_port", 1))
        end_port = int(request.form.get("end_port", 1024))

        if not target:
            return jsonify({"error": "Target cannot be empty."}), 400

        open_ports = []

        for port in range(start_port, end_port + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append({
                        "port": port,
                        "service": interpret_port(port)
                    })
                sock.close()
            except Exception:
                continue

        threat_level = get_threat_level(open_ports)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return jsonify({
            "open_ports": open_ports,
            "threat_level": threat_level,
            "scanned_at": timestamp
        })

    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True)
