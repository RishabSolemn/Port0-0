from flask import Flask, request, render_template_string
import socket
import os

html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PSX – Port Scanner eXtreme</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #121212;
            color: #f0f0f0;
            padding: 20px;
            margin: 0;
        }
        h1 {
            color: #00bfff;
            text-align: center;
        }
        form {
            text-align: center;
            margin-bottom: 30px;
        }
        input[type=text], input[type=number] {
            padding: 10px;
            margin: 5px;
            width: 200px;
            border-radius: 5px;
            border: none;
        }
        input[type=submit] {
            padding: 10px 20px;
            background-color: #00bfff;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .loader-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background-color: rgba(0, 0, 0, 0.85);
            z-index: 1000;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .rasengan-loader {
            width: 100px;
            height: 100px;
            border: 10px solid #00bfff;
            border-top: 10px solid #1e90ff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .results-container {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            justify-content: center;
        }
        .port-box {
            background-color: #1e1e1e;
            padding: 15px;
            border-radius: 8px;
            width: 220px;
            box-shadow: 0 0 10px rgba(0,0,0,0.5);
            text-align: center;
        }
        .level-1 { border-left: 6px solid #00ff00; }
        .level-2 { border-left: 6px solid #ffff00; }
        .level-3 { border-left: 6px solid #ffa500; }
        .level-4 { border-left: 6px solid #ff0000; }
        .level-5 { border-left: 6px solid #000000; color: #ff4444; font-weight: bold; }
        .legend {
            margin: 20px auto;
            max-width: 600px;
            background-color: #1e1e1e;
            padding: 20px;
            border-radius: 8px;
        }
    </style>
    <script>
        function showLoader() {
            document.getElementById('loader').style.display = 'flex';
        }
        window.onload = function() {
            document.getElementById('loader').style.display = 'none';
        }
    </script>
</head>
<body>
    <div id="loader" class="loader-overlay">
        <div class="rasengan-loader"></div>
    </div>
    <h1>PSX – Port Scanner eXtreme</h1>
    <form method="post" onsubmit="showLoader()">
        <input type="text" name="host" placeholder="Enter IP or hostname" required>
        <input type="number" name="start" placeholder="Start Port" min="1" max="65535">
        <input type="number" name="end" placeholder="End Port" min="1" max="65535">
        <input type="submit" value="Scan">
    </form>
    <div class="legend">
        <h3>Threat Level Guide:</h3>
        <ul>
            <li class="level-1">🟢 Level 1: <b>Static Breeze</b> — No real danger</li>
            <li class="level-2">🟡 Level 2: <b>Phantom Echo</b> — Misconfigurations</li>
            <li class="level-3">🟠 Level 3: <b>Crimson Pulse</b> — Suspicious services</li>
            <li class="level-4">🔴 Level 4: <b>Zero Protocol</b> — Known vulnerabilities</li>
            <li class="level-5">⚫ Level 5: <b>Blackout Eclipse</b> — Critical breach</li>
        </ul>
    </div>
    {% if results is not none %}
    <h2 style="text-align:center;">Results for {{ host }}</h2>
    <div class="results-container">
        {% for port, data in results.items() %}
        <div class="port-box level-{{ data.level }}">
            <strong>Port {{ port }}</strong><br>
            Status: {{ data.status }}<br>
            Threat: {{ data.threat }}
        </div>
        {% endfor %}
    </div>
    {% endif %}
</body>
</html>
"""

app = Flask(__name__)

THREAT_LEVELS = [
    ("Open", 1, "Static Breeze"),
    ("Open (No Auth)", 2, "Phantom Echo"),
    ("Suspicious", 3, "Crimson Pulse"),
    ("Vulnerable", 4, "Zero Protocol"),
    ("Critical", 5, "Blackout Eclipse")
]

def get_threat_level(port, is_open):
    if not is_open:
        return 1, "Static Breeze"
    if port in [80, 110, 143]:
        return 2, "Phantom Echo"
    if port in [21, 22]:
        return 3, "Crimson Pulse"
    if port in [25, 3306]:
        return 4, "Zero Protocol"
    return 5, "Blackout Eclipse"

@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    host = None
    if request.method == "POST":
        host = request.form["host"]
        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            return render_template_string(html_template, results=None, host=f"Invalid hostname: {host}")

        try:
            start_port = int(request.form.get("start", 20))
            end_port = int(request.form.get("end", 1024))
        except ValueError:
            start_port, end_port = 20, 1024

        results = {}
        for port in range(start_port, end_port + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    result = s.connect_ex((host, port))
                    is_open = (result == 0)
                    level, threat = get_threat_level(port, is_open)
                    results[port] = {
                        "status": "Open" if is_open else "Closed",
                        "level": level,
                        "threat": threat
                    }
            except Exception as e:
                results[port] = {"status": f"Error: {str(e)}", "level": 1, "threat": "Static Breeze"}
    return render_template_string(html_template, results=results, host=host)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
