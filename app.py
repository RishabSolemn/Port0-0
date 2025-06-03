from flask import Flask, request, jsonify, send_file, render_template
import os
import json
import datetime

app = Flask(__name__)

# Sample scan log (should be updated dynamically in real use)
SCAN_LOG = []

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    host = data.get("host")

    # Placeholder scan result
    result = {
        "host": host,
        "ip": "192.168.1.1",
        "timestamp": datetime.datetime.now().isoformat(),
        "threat_rating": "Low",
        "threat_score": 15,
        "results": [
            {"port": 80, "status": "open", "description": "HTTP", "color": "#00ffc6"},
            {"port": 443, "status": "open", "description": "HTTPS", "color": "#00ffc6"},
        ],
        "geo_data": {
            "city": "Example City",
            "region": "Example Region",
            "country": "Example Country",
            "latitude": "0.0000",
            "longitude": "0.0000"
        }
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
    port = int(os.environ.get("PORT", 5000))  # Render uses PORT env var
    app.run(host="0.0.0.0", port=port)
