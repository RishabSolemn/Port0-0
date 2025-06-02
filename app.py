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
            margin: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #0d1117;
            color: #ffffff;
            padding: 20px;
        }

        h1 {
            font-size: 2.5rem;
            color: #58a6ff;
        }

        form {
            margin-bottom: 20px;
        }

        input[type=text], input[type=number] {
            padding: 10px;
            width: 250px;
            margin-right: 10px;
            background: #161b22;
            color: white;
            border: 1px solid #30363d;
            border-radius: 5px;
        }

        input[type=submit] {
            padding: 10px 20px;
            background: #238636;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }

        .result {
            background: #161b22;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 5px rgba(255,255,255,0.1);
        }

        .loading-overlay {
            display: none;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(4px);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }

        .rasengan {
            width: 80px;
            height: 80px;
            border: 5px solid #00f0ff;
            border-radius: 50%;
            border-top-color: transparent;
            animation: spin 0.6s linear infinite;
            box-shadow: 0 0 20px #00f0ff, 0 0 40px #00f0ff inset;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <h1>🔥 PSX – Port Scanner eXtreme</h1>
    <form method="post" onsubmit="showLoading()">
        <input type="text" name="host" placeholder="Enter IP or hostname" required>
        <input type="submit" value="Scan Ports">
    </form>

    <div class="loading-overlay" id="loading">
        <div class="rasengan"></div>
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

    <script>
        function showLoading() {
            document.getElementById('loading').style.display = 'flex';
        }
    </script>
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
