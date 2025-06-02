from flask import Flask, request, render_template_string
import socket
import os

app = Flask(__name__)

html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PSX – Port Scanner eXtreme</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(to right, #0f2027, #203a43, #2c5364);
            color: #fff;
            padding: 40px;
        }
        h1 {
            text-align: center;
            font-size: 3rem;
            margin-bottom: 10px;
        }
        form {
            display: flex;
            flex-direction: column;
            align-items: center;
            margin-bottom: 30px;
        }
        input[type=text], input[type=number] {
            padding: 10px;
            width: 300px;
            margin: 5px;
            border-radius: 10px;
            border: none;
        }
        input[type=submit] {
            padding: 10px 20px;
            border-radius: 10px;
            background: #1abc9c;
            color: #fff;
            border: none;
            cursor: pointer;
        }
        .results {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 15px;
        }
        .port-box {
            background: #1e1e2f;
            padding: 15px;
            border-radius: 10px;
            min-width: 180px;
            text-align: center;
            box-shadow: 0 0 10px rgba(0,0,0,0.5);
        }
        .level-1 { background-color: #2ecc71; }
        .level-2 { background-color: #f1c40f; }
        .level-3 { background-color: #e67e22; }
        .level-4 { background-color: #e74c3c; }
        .level-5 { background-color: #2c3e50; color: #ff4757; }
        .rasengan-loader {
            display: none;
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 2rem;
            animation: spin 1.5s linear infinite;
        }
        @keyframes spin {
            from { transform: translateX(-50%) rotate(0deg); }
            to { transform: translateX(-50%) rotate(360deg); }
        }
    </style>
    <script>
        function showLoader() {
            document.getElementById("loader").style.display = "block";
        }
    </script>
</head>
<body>
    <h1>PSX – Port Scanner eXtreme</h1>
    <div id="loader" class="rasengan-loader">🌀 Naruto forming Rasengan...</div>
    <form method="post" onsubmit="showLoader()">
        <input type="text" name="host" placeholder="Enter IP or hostname" required>
        <input type="number" name="start_port" placeholder="Start Port" min="1" max="65535" required>
        <input type="number" name="end_port" placeholder="End Port" min="1" max="65535" required>
        <input type="submit" value="Scan Ports">
    </form>
    {% if results is not none %}
    <h2 style="text-align:center">Results for {{ host }}</h2>
    <div class="results">
        {% for port, status, level in results %}
        <div class="port-box level-{{ level }}">
            <strong>Port {{ port }}</strong><br>
            {{ status }}<br>
            {% if level == 1 %}🟢 Static Breeze{% endif %}
            {% if level == 2 %}🟡 Phantom Echo{% endif %}
            {% if level == 3 %}🟠 Crimson Pulse{% endif %}
            {% if level == 4 %}🔴 Zero Protocol{% endif %}
            {% if level == 5 %}⚫ Blackout Eclipse{% endif %}
        </div>
        {% endfor %}
    </div>
    {% endif %}
</body>
</html>
"""

def get_threat_level(port):
    if port in [80, 443]:
        return 1  # harmless web services
    elif port in [21, 110]:
        return 2  # unsecured ftp/pop
    elif port in [22, 23, 25]:
        return 3  # ssh/telnet/smtp
    elif port in [3306]:
        return 4  # database exposed
    else:
        return 5  # unknown or critical

@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    host = None
    if request.method == "POST":
        host = request.form["host"]
        try:
            socket.gethostbyname(host)
        except:
            return render_template_string(html_template, results=[], host=f"Invalid host: {host}")

        start_port = int(request.form["start_port"])
        end_port = int(request.form["end_port"])
        results = []

        for port in range(start_port, end_port + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    result = s.connect_ex((host, port))
                    if result == 0:
                        level = get_threat_level(port)
                        results.append((port, "Open", level))
                    else:
                        results.append((port, "Closed", 1))
            except Exception as e:
                results.append((port, f"Error: {str(e)}", 5))

    return render_template_string(html_template, results=results, host=host)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
