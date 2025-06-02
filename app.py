from flask import Flask, request, render_template_string, send_file
import socket
import os
import datetime

app = Flask(__name__)

# Define ports and their purposes
PORT_INFO = {
    20: ("FTP Data", "File Transfer Protocol (data)"),
    21: ("FTP Control", "File Transfer Protocol (control)"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Unencrypted Remote Login"),
    25: ("SMTP", "Send Mail Transfer Protocol"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Web Traffic (insecure)"),
    110: ("POP3", "Post Office Protocol 3"),
    143: ("IMAP", "Internet Message Access Protocol"),
    443: ("HTTPS", "Secure Web Traffic"),
    3306: ("MySQL", "Database Server")
}

SAFE_PORTS = list(PORT_INFO.keys())

THREAT_LEVELS = {
    1: ("Static Breeze", "🟢", "Barely a ripple in the network."),
    2: ("Phantom Echo", "🟡", "Something's moving... just out of view."),
    3: ("Crimson Pulse", "🟠", "The heartbeat of a lurking menace."),
    4: ("Zero Protocol", "🔴", "They've seen you. They're responding."),
    5: ("Blackout Eclipse", "⚫", "The system falls silent... before it breaks.")
}

LOG_FILE = "scan_log.txt"

html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PSX – Port Scanner eXtreme</title>
    <style>
        body { background-color: #111; color: #f5f5f5; font-family: monospace; }
        .box { display: inline-block; border: 1px solid #555; padding: 10px; margin: 5px; border-radius: 5px; background: #222; width: 280px; }
        .green { border-left: 5px solid lime; }
        .yellow { border-left: 5px solid yellow; }
        .orange { border-left: 5px solid orange; }
        .red { border-left: 5px solid red; }
        .black { border-left: 5px solid #444; }
        .rasengan-loader {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
        }
        .hidden { display: none; }
    </style>
</head>
<body>
    <div id="loader" class="rasengan-loader">
        <img src="https://media.giphy.com/media/zOvBKUUEERdNm/giphy.gif" alt="Loading Rasengan...">
    </div>
    <h1>PSX – Port Scanner eXtreme</h1>
    <form method="post" onsubmit="return confirm('Do you have permission to scan this domain/IP?')">
        <input type="text" name="host" placeholder="Enter IP or hostname" required>
        <input type="submit" value="Scan">
    </form>
    {% if results %}
        <h2>Results for {{ host }}</h2>
        <div>
        {% for port, status, info, purpose, css in results %}
            <div class="box {{ css }}">
                <strong>Port {{ port }} - {{ info }}</strong><br>
                Status: {{ status }}<br>
                Purpose: {{ purpose }}
            </div>
        {% endfor %}
        </div>
        <h3>Threat Level: {{ threat_icon }} {{ threat_title }}</h3>
        <p>{{ threat_desc }}</p>
        <a href="/download">Download Log</a>
    {% endif %}
    <script>
        window.onload = function() {
            document.getElementById("loader").classList.add("hidden");
        };
    </script>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    threat_count = 0
    host = None
    if request.method == "POST":
        host = request.form["host"]
        log_entry = f"Scan at {datetime.datetime.now()} for {host}\n"
        for port in SAFE_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    result = s.connect_ex((host, port))
                    status = "Open" if result == 0 else "Closed"
                    if result == 0:
                        threat_count += 1
                    name, purpose = PORT_INFO.get(port, ("Unknown", "Unknown purpose"))
                    css = "green" if result != 0 else "orange"  # default to mid-tier threat for demo
                    results.append((port, status, name, purpose, css))
                    log_entry += f"Port {port} ({name}) - {status}\n"
            except Exception as e:
                results.append((port, f"Error: {e}", "N/A", "N/A", "black"))
                log_entry += f"Port {port} - Error: {e}\n"

        with open(LOG_FILE, "a") as f:
            f.write(log_entry + "\n")

    # Determine threat level
    if threat_count == 0:
        level = 1
    elif threat_count < 3:
        level = 2
    elif threat_count < 6:
        level = 3
    elif threat_count < 9:
        level = 4
    else:
        level = 5

    title, icon, desc = THREAT_LEVELS[level]
    return render_template_string(html_template, results=results, host=host,
                                  threat_title=title, threat_icon=icon, threat_desc=desc)

@app.route("/download")
def download_log():
    return send_file(LOG_FILE, as_attachment=True)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
