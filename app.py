from flask import Flask, request, jsonify
import socket
import ipapi
import whois

app = Flask(__name__)

def scan_ports(ip, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return open_ports

def get_threat_level(open_ports):
    if len(open_ports) >= 50:
        return "High"
    elif len(open_ports) >= 10:
        return "Medium"
    else:
        return "Low"

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target = data.get('target')
    start = int(data.get('start', 1))
    end = int(data.get('end', 1024))

    try:
        ip = socket.gethostbyname(target)
        open_ports = scan_ports(ip, start, end)
        geo = ipapi.location(ip=ip)
        w = whois.whois(target)
        threat = get_threat_level(open_ports)

        return jsonify({
            'ip': ip,
            'open_ports': open_ports,
            'geo': geo,
            'whois': str(w),
            'threat': threat
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/')
def index():
    return 'PSX – Port Scanner eXtreme API Running'

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=10000)
