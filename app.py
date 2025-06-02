from flask import Flask, request, render_template_string
import socket
import os

app = Flask(__name__)

html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Python Port Scanner</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .fade-in {
            animation: fadeIn 0.7s ease-in-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .pulse:hover {
            animation: pulse 1s infinite;
        }
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(0, 128, 255, 0.4); }
            70% { box-shadow: 0 0 0 10px rgba(0, 128, 255, 0); }
            100% { box-shadow: 0 0 0 0 rgba(0, 128, 255, 0); }
        }
    </style>
</head>
<body class="bg-gray-100 font-sans p-6">
    <div class="max-w-xl mx-auto bg-white p-8 rounded-xl shadow-md fade-in">
        <h1 class="text-2xl font-bold mb-4 text-blue-600">Python Port Scanner</h1>
        <form method="POST" class="space-y-4">
            <input type="text" name="host" placeholder="Enter IP or hostname" required class="w-full p-2 border rounded" />
            <input type="text" name="ports" placeholder="Enter port range (e.g. 20-100)" required class="w-full p-2 border rounded" />
            <input type="submit" value="Scan" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 pulse cursor-pointer" />
        </form>
        <p class="text-sm text-gray-500 mt-4">
            Only scan IPs you own or have permission to test. This scanner checks open TCP ports in your specified range.
        </p>

        {% if results is not none %}
        <div class="mt-6 fade-in">
            <h2 class="text-lg font-semibold mb-2 text-green-600">Scan Results for {{ host }} (Ports {{ port_range }})</h2>
            <ul class="list-disc pl-5 space-y-1 text-gray-800">
                {% for port, status in results.items() %}
                    <li><strong>Port {{ port }}</strong>: {{ status }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    host = None
    port_range = ""
    if request.method == "POST":
        host = request.form["host"]
        port_input = request.form["ports"]
        results = {}

        # Validate and parse the port range
        try:
            start_port, end_port = map(int, port_input.strip().split("-"))
            port_range = f"{start_port}-{end_port}"
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError("Invalid range")
        except Exception:
            return render_template_string(html_template, results={"Error": "Invalid port range format. Use format like 20-80."}, host=host, port_range=port_input)

        # Scan the specified ports
        for port in range(start_port, end_port + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    result = s.connect_ex((host, port))
                    results[port] = "Open" if result == 0 else "Closed"
            except Exception as e:
                results[port] = f"Error: {str(e)}"

    return render_template_string(html_template, results=results, host=host, port_range=port_range)

# Run app on Render with proper host/port binding
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
