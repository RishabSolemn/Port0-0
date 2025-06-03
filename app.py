from flask import Flask, render_template, request, jsonify
import socket
import whois
from ipwhois import IPWhois
import requests

app = Flask(__name__)

def scan_ports(target, start_port=1, end_port=1024):
    open_ports = []
    try:
        ip = socket.gethostbyname(target)
        for port in range(start_port, end_port + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        return open_ports
    except socket.gaierror:
        return []

def get_geo_info(ip):
    try:
        response = requests.get(f'https://ipapi.co/{ip}/json/')
        return response.json()
    except:
        return {}

def get_whois_info(target):
    try:
        return whois.whois(target)
    except:
        return {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target = data.get('target')
    start = int(data.get('start', 1))
    end = int(data.get('end', 1024))

    open_ports = scan_ports(target, start, end)
    ip = socket.gethostbyname(target)
    geo = get_geo_info(ip)
    whois_data = get_whois_info(target)

    threat_level = (
        "High" if len(open_ports) >= 50 else
        "Medium" if len(open_ports) >= 10 else
        "Low"
    )

    return jsonify({
        'open_ports': open_ports,
        'ip': ip,
        'geo': geo,
        'whois': str(whois_data),
        'threat': threat_level
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10000)
