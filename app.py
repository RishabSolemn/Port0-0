from flask import Flask, request, render_template_string
import socket
import os

app = Flask(__name__)

SAFE_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3306]

html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PSX – Port Scanner eXtreme</title>
    <style>
        body {
            background: #0d0d0d;
            color: #f1f1f1;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            padding: 40px;
        }
        h1 {
            font-size: 2.5em;
            margin-bottom: 20px;
            background: linear-gradient(90deg, #ff007f, #00f2ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        form {
            margin-bottom: 20px;
        }
        input[type=text] {
            padding: 10px;
            width: 300px;
            border: none;
            border-radius: 6px;
            margin-right: 10px;
        }
        input[type=submit] {
            padding: 10px 20px;
            background-color: #ff007f;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        input[type=submit]:hover {
            background-color: #e6006f;
        }
        .result {
            background: #1e1e1e;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 10px rgba(255, 0, 128, 0.3);
        }
        .loader {
            display: none;
            margin-top: 30px;
            text-align: center;
        }
        .orb {
            width: 40px;
            height: 40px;
            background: #00f2ff;
            border-radius: 50%;
            animation: pulse 1s infinite ease-in-out;
            margin: 0 auto 10px;
        }
        @keyframes pulse {
            0% { transform: scale(1); opacity: 0.8; }
            50% { transform: scale(1.4); opacity: 1; }
            100% { transform: scale(1); opacity: 0.8; }
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
    <form method="post" onsubmit="showLoader()">
        <input type="text" name="host" placeholder="Enter IP or hostname" required>
        <input type="submit" value="Scan">
    </form>
    <div id="loader" class="loader">
        <div class="orb"></div>
        <p>Scanning with eXtreme precision...</p>
    </div>
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
