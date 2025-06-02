from flask import Flask, request, render_template_string, send_file, redirect
import socket
import os
from datetime import datetime
import csv

app = Flask(__name__)

SAFE_PORTS = {
    20: ("FTP Data Transfer", 1),
    21: ("FTP Control", 2),
    22: ("SSH Remote Login", 3),
    23: ("Telnet Remote Login", 3),
    25: ("SMTP Email Routing", 2),
    53: ("DNS Services", 2),
    80: ("HTTP Web Traffic", 2),
    110: ("POP3 Email", 2),
    143: ("IMAP Email", 2),
    443: ("HTTPS Secure Web Traffic", 1),
    3306: ("MySQL Database", 4)
}

THREAT_LEVELS = {
    1: ("🟢 Static Breeze", "Barely a ripple in the network."),
    2: ("🟡 Phantom Echo", "Something’s moving… just out of view."),
    3: ("🟠 Crimson Pulse", "The heartbeat of a lurking menace."),
    4: ("🔴 Zero Protocol", "They’ve seen you. They’re responding."),
    5: ("⚫ Blackout Eclipse", "The system falls silent… before it breaks.")
}

html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PSX – Port Scanner eXtreme</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #111; color: #eee; text-align: center; margin: 0; padding: 0; }
        h1 { color: #38bdf8; padding-top: 1em; }
        form, .results, .threat-chart, .log-download { margin: 20px auto; width: 80%; max-width: 800px; }
        input[type=text] { padding: 10px; width: 60%; background: #222; color: #eee; border: 1px solid #444; border-radius: 5px; }
        input[type=submit] { padding: 10px 20px; background: #38bdf8; color: #000; border: none; border-radius: 5px; cursor: pointer; }
        .port-box { background: #222; border: 1px solid #444; padding: 10px; margin: 5px; border-radius: 8px; display: inline-block; width: 200px; }
        .threat-box { background: #222; border-left: 10px solid; padding: 10px; margin: 10px 0; border-radius: 5px; text-align: left; }
        .level-1 { border-color: green; }
        .level-2 { border-color: yellow; }
        .level-3 { border-color: orange; }
        .level-4 { border-color: red; }
        .level-5 { border-color: black; color: red; }
        .overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); display: flex; justify-content: center; align-items: center; z-index: 9999; }
        .overlay video { max-width: 300px; }
        .permission-modal { position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: #222; padding: 30px; border-radius: 12px; box-shadow: 0 0 20px #000; z-index: 10000; }
        .hidden { display: none; }
    </style>
</head>
<body>
<div class="permission-modal" id="permissionModal">
    <h2>Permission Required</h2>
    <p>Do you have permission to scan the entered domain or IP?</p>
    <button onclick="grantPermission(true)">Yes</button>
    <button onclick="grantPermission(false)">No</button>
</div>

<div class="overlay hidden" id="loadingOverlay">
    <video autoplay muted loop>
        <source src="https://media.tenor.com/2UyPmYZzAwoAAAPo/naruto-rasengan.mp4" type="video/mp4">
    </video>
</div>

<h1>PSX – Port Scanner eXtreme</h1>
<form method="post" onsubmit="return showLoader()">
    <input type="text" name="host" placeholder="Enter IP or hostname" required>
    <input type="submit" value="Scan">
</form>

<div class="threat-chart">
    <h3>Threat Level Reference Chart</h3>
    {% for level, data in threat_levels.items() %}
    <div class="threat-box level-{{ level }}">
        <strong>{{ data[0] }}</strong>: {{ data[1] }}
    </div>
    {% endfor %}
</div>

{% if results is not none %}
<div class="results">
    <h2>Results for {{ host }}</h2>
    {% for port, info in results.items() %}
        <div class="port-box">
            <strong>Port {{ port }}</strong><br>
            Status: {{ info.status }}<br>
            Use: {{ info.purpose }}<br>
            Danger: {{ info.threat }}<br>
        </div>
    {% endfor %}
</div>
<div class="log-download">
    <a href="/download-log">Download Scan Log</a>
</div>
{% endif %}

<script>
    function grantPermission(granted) {
        if (!granted) window.location.href = "https://www.google.com";
        else document.getElementById("permissionModal").classList.add("hidden");
    }
    function showLoader() {
        document.getElementById("loadingOverlay").classList.remove("hidden");
        return true;
    }
</script>
</body>
</html>
"""

scan_log = []

@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    host = None
    if request.method == "POST":
        host = request.form["host"]
        scan_log.append((host, datetime.now().isoformat()))
        results = {}
        for port, (purpose, level) in SAFE_PORTS.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    result = s.connect_ex((host, port))
                    status = "Open" if result == 0 else "Closed"
                    results[port] = {
                        "status": status,
                        "purpose": purpose,
                        "threat": THREAT_LEVELS[level][0] if status == "Open" else "-"
                    }
            except Exception as e:
                results[port] = {
                    "status": f"Error: {str(e)}",
                    "purpose": purpose,
                    "threat": "-"
                }
    return render_template_string(html_template, results=results, host=host, threat_levels=THREAT_LEVELS)

@app.route("/download-log")
def download_log():
    with open("scan_log.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Timestamp"])
        writer.writerows(scan_log)
    return send_file("scan_log.csv", as_attachment=True)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
