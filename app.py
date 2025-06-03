from flask import Flask, request, jsonify, render_template
import socket
import whois
import requests

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target = data.get('target')
    start_port = int(data.get('start', 1))
    end_port = int(data.get('end', 1024))

    result = {
        "ip": "",
        "open_ports": [],
        "geo": {},
        "whois": "",
        "threat": "Low"
    }

    try:
        ip = socket.gethostbyname(target)
        result["ip"] = ip

        open_ports = []
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()

        result["open_ports"] = open_ports

        # Threat level logic
        if len(open_ports) >= 50:
            result["threat"] = "High"
        elif len(open_ports) >= 10:
            result["threat"] = "Medium"

        # Geo info
        geo = requests.get(f'https://ipapi.co/{ip}/json/').json()
        result["geo"] = geo if isinstance(geo, dict) else {}

        # WHOIS
        try:
            whois_info = whois.whois(target)
            result["whois"] = str(whois_info)
        except:
            result["whois"] = "WHOIS lookup failed"

    except Exception as e:
        print("Error during scan:", e)

    return jsonify(result)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
