from flask import Flask, request, render_template_string
import socket

html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Python Port Scanner</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }
        h1 { color: #333; }
        form { margin-bottom: 20px; }
        input[type=text] { padding: 10px; width: 300px; }
        input[type=submit] { padding: 10px 20px; }
        .result { background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <h1>Python Port Scanner</h1>
    <form method="post">
        <input type="text" name="host" placeholder="Enter IP or hostname" required>
        <input type="submit" value="Scan">
    </form>
    {% if results is not none %}
    <div class="result">
        <h2>Results for {{ host }}</h2>
        <ul>
        {% for port, status in results.items() %}
            <li>Port {{ port }}: {{ status }}</li>
        {% endfor %}
        </ul>
    </div>
    {% endif %}
</body>
</html>
"""

app = Flask(__name__)

SAFE_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3306]

@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    host = None
    if request.method == "POST":
        host = request.form["host"]
        results = {}
        for port in SAFE_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    result = s.connect_ex((host, port))
                    results[port] = "Open" if result == 0 else "Closed"
            except Exception as e:
                results[port] = f"Error: {str(e)}"
    return render_template_string(html_template, results=results, host=host)

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
