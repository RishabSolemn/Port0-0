from flask import Flask, request, render_template_string, send_file, redirect, url_for
import socket
import os
import datetime

app = Flask(__name__)

SAFE_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3306]

LOG_FILE = "search_logs.txt"

html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PSX – Port Scanner eXtreme</title>
    <style>
        body {
            background: #121212;
            color: #f0f0f0;
            font-family: 'Segoe UI', sans-serif;
            padding: 20px;
        }
        .rasengan-loader {
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.85);
            z-index: 1000;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-direction: column;
        }
        .rasengan-circle {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            border: 5px solid #00bfff;
            animation: spin 1s linear infinite;
            box-shadow: 0 0 30px #00bfff;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        input[type=text] { padding: 10px; width: 300px; }
        input[type=submit] { padding: 10px 20px; }
        .port-box {
            background: #1e1e1e;
            border-radius: 8px;
            padding: 10px;
            margin: 5px;
            display: inline-block;
            min-width: 120px;
        }
        .green { border-left: 5px solid #66ff66; }
        .yellow { border-left: 5px solid #ffff66; }
        .orange { border-left: 5px solid #ffcc66; }
        .red { border-left: 5px solid #ff6666; }
        .black { border-left: 5px solid #666666; }
    </style>
    <script>
        function showLoader() {
            document.getElementById('loader').style.display = 'flex';
            document.getElementById('scan-form').submit();
        }
    </script>
</head>
<body>
    <div id="loader" class="rasengan-loader" style="display:none;">
        <div class="rasengan-circle"></div>
        <p style="margin-top:20px; color:white;">Naruto is charging the Rasengan...</p>
        <audio autoplay loop>
            <source src="https://actions.google.com/sounds/v1/cartoon/cartoon_boing.ogg" type="audio/ogg">
        </audio>
    </div>

    <h1>🔍 PSX – Port Scanner eXtreme</h1>
    {% if not permission %}
    <form method="post" onsubmit="showLoader()">
        <p>⚠️ Do you have permission to scan the IP or domain you are entering?</p>
        <button type="submit" name="permission" value="yes">Yes, I have permission</button>
    </form>
    {% else %}
    <form id="scan-form" method="post" onsubmit="showLoader()">
        <input type="text" name="host" placeholder="Enter IP or hostname" required>
        <input type="submit" value="Scan">
    </form>
    {% endif %}

    {% if results %}
        <h2>Results for {{ host }}</h2>
        <div>
        {% for port, info in results.items() %}
            <div class="port-box {{ info.level_class }}">
                <strong>Port {{ port }}</strong><br>
                Status: {{ info.status }}<br>
                Threat: {{ info.level }}<br>
                Tagline: {{ info.tagline }}
            </div>
        {% endfor %}
        </div>
        <br>
        <a href="/download">📥 Download Scan Log</a>
    {% endif %}
</body>
</html>
"""

THREAT_LEVELS = [
    ("🟢 Level 1: Static Breeze", "green", "Barely a ripple in the network."),
    ("🟡 Level 2: Phantom Echo", "yellow", "Something’s moving… just out of view."),
    ("🟠 Level 3: Crimson Pulse", "orange", "The heartbeat of a lurking menace."),
    ("🔴 Level 4: Zero Protocol", "red", "They’ve seen you. They’re responding."),
    ("⚫ Level 5: Blackout Eclipse", "black", "The system falls silent… before it breaks.")
]

def assess_threat(port, status):
    if status != "Open":
        return THREAT_LEVELS[0]
    if port in [80, 110]:
        return THREAT_LEVELS[1]
    elif port in [21, 22, 23]:
        return THREAT_LEVELS[2]
    elif port in [25, 143, 3306]:
        return THREAT_LEVELS[3]
    elif port in [53]:
        return THREAT_LEVELS[4]
    return THREAT_LEVELS[1]

@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    host = None
    permission = False

    if request.method == "POST":
        if "permission" in request.form:
            permission = True
        else:
            permission = True
            host = request.form.get("host")
            results = {}
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(LOG_FILE, "a") as f:
                f.write(f"[{timestamp}] Host scanned: {host}\n")

            for port in SAFE_PORTS:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.5)
                        result = s.connect_ex((host, port))
                        status = "Open" if result == 0 else "Closed"
                        level, level_class, tagline = assess_threat(port, status)
                        results[port] = {
                            "status": status,
                            "level": level,
                            "level_class": level_class,
                            "tagline": tagline
                        }
                except Exception as e:
                    results[port] = {
                        "status": f"Error: {str(e)}",
                        "level": "N/A",
                        "level_class": "",
                        "tagline": "Connection issue"
                    }

    return render_template_string(html_template, results=results, host=host, permission=permission)

@app.route("/download")
def download():
    return send_file(LOG_FILE, as_attachment=True)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
