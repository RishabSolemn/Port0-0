from flask import Flask, request, render_template_string, send_file
import socket
import os
import json
import datetime
import requests
from io import BytesIO

app = Flask(__name__)

# Common service mapping
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 8080: "HTTP Proxy"
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <title>PSX – Port Scanner eXtreme</title>
    <script src="https://cdn.jsdelivr.net/npm/particles.js@2.0.0/particles.min.js"></script>
    <style>
        :root {
            color-scheme: dark;
        }
        body {
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', sans-serif;
            background-color: #121212;
            color: #e0e0e0;
        }
        .container {
            max-width: 800px;
            margin: auto;
            padding: 2em;
            position: relative;
            z-index: 1;
        }
        h1 {
            font-size: 2.5em;
            color: #00ffff;
        }
        form {
            margin-top: 1em;
            display: flex;
            flex-direction: column;
        }
        input, button {
            margin: 0.5em 0;
            padding: 10px;
            font-size: 1em;
            border: none;
            border-radius: 5px;
        }
        input[type=text], input[type=number] {
            background: #1e1e1e;
            color: #fff;
        }
        button {
            background: #00ffff;
            color: #000;
            cursor: pointer;
        }
        .result {
            background: #1e1e1e;
            margin-top: 1em;
            padding: 1em;
            border-radius: 10px;
        }
        .status-open {
            color: #00ff00;
        }
        .status-closed {
            color: #ff3333;
        }
        .status-error {
            color: #ffaa00;
        }
        #particles-js {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 0;
        }
        .toggle-theme {
            position: fixed;
            top: 1em;
            right: 1em;
            background: #00ffff;
            color: #000;
            padding: 0.5em;
            border-radius: 10px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div id="particles-js"></div>
    <div class="container">
        <h1>🔒 PSX – Port Scanner eXtreme</h1>
        <p>Fast, Flexible, and Free Network Scanning</p>
        <form method="POST">
            <input type="text" name="host" placeholder="Enter IP or domain" required>
            <input type="number" name="start_port" placeholder="Start Port (default 20)" min="1" max="65535">
            <input type="number" name="end_port" placeholder="End Port (default 1024)" min="1" max="65535">
            <label><input type="checkbox" name="stealth"> Stealth mode (slower)</label>
            <button type="submit">Scan</button>
        </form>
        {% if results %}
            <div class="result">
                <h2>Results for {{ host }}</h2>
                <p><strong>Geo Info:</strong> {{ geo_info }}</p>
                <ul>
                    {% for port, status in results.items() %}
                        <li>
                            Port {{ port }} -
                            <span class="status-{{ status[1] }}">
                                {{ status[0] }}{% if status[2] %} ({{ status[2] }}){% endif %}
                            </span>
                        </li>
                    {% endfor %}
                </ul>
                <form action="/export" method="post">
                    <input type="hidden" name="host" value="{{ host }}">
                    <input type="hidden" name="scan_data" value='{{ results | tojson }}'>
                    <button type="submit">Download Report</button>
                </form>
            </div>
        {% endif %}
    </div>
    <div class="toggle-theme" onclick="toggleTheme()">🌓 Toggle Theme</div>
    <script>
        particlesJS.load('particles-js', 'https://cdn.jsdelivr.net/gh/VincentGarreau/particles.js/particles.json');
        function toggleTheme() {
            let html = document.querySelector("html");
            html.dataset.theme = html.dataset.theme === "dark" ? "light" : "dark";
        }
    </script>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    results = {}
    geo_info = "Unavailable"
    host = ""
    if request.method == "POST":
        host = request.form["host"]
        start_port = int(request.form.get("start_port") or 20)
        end_port = int(request.form.get("end_port") or 1024)
        stealth = "stealth" in request.form

        timeout = 1 if stealth else 0.3

        try:
            ip = socket.gethostbyname(host)
            geo_info = get_geo_info(ip)
        except:
            geo_info = "Invalid host"

        for port in range(start_port, end_port + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((host, port))
                    status = "Open" if result == 0 else "Closed"
                    style = "open" if result == 0 else "closed"
                    service = COMMON_SERVICES.get(port, "")
                    results[port] = (status, style, service)
            except Exception as e:
                results[port] = (f"Error: {str(e)}", "error", "")

    return render_template_string(HTML_TEMPLATE, results=results, geo_info=geo_info, host=host)

@app.route("/export", methods=["POST"])
def export():
    host = request.form["host"]
    scan_data = json.loads(request.form["scan_data"])
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"PSX_Report_{host}_{timestamp}.txt"

    content = f"PSX Scan Report for {host} – {timestamp}\n\n"
    for port, (status, _, service) in scan_data.items():
        content += f"Port {port}: {status}"
        if service:
            content += f" ({service})"
        content += "\n"

    return send_file(BytesIO(content.encode()), download_name=filename, as_attachment=True)

def get_geo_info(ip):
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json/")
        data = res.json()
        return f"{data.get('country_name', '?')} - {data.get('org', '?')}"
    except:
        return "Geo lookup failed"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
