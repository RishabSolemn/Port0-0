from flask import Flask, render_template, request, jsonify
import socket
import whois
import ipapi
import os

app = Flask(__name__)

def scan_ports(ip, start, end):
    open_ports = []
    for port in range(start, end + 1):
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            sock.connect((ip, port))
            open_ports.append(port)
            sock.close()
        except:
            continue
    return open_ports

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/learn')
def learn():
    return render_template('learn.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target = data['target']
    start = int(data['start'])
    end = int(data['end'])

    try:
        ip = socket.gethostbyname(target)
    except:
        return jsonify({"error": "Invalid domain"}), 400

    open_ports = scan_ports(ip, start, end)
    threat = "Low" if len(open_ports) < 10 else "Medium" if len(open_ports) < 50 else "High"

    try:
        w = whois.whois(ip)
    except:
        w = "WHOIS lookup failed"

    geo = ipapi.location(ip)

    return jsonify({
        "ip": ip,
        "open_ports": open_ports,
        "threat": threat,
        "geo": geo,
        "whois": str(w)
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
