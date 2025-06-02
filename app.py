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
