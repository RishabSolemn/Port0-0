from flask import Flask, render_template, request, jsonify
import socket
import threading
import ipwhois
import whois
import dns.resolver
import requests
from datetime import datetime

app = Flask(__name__)

# === AI-style interpretation for common ports ===
port_descriptions = {
    20: "FTP Data Transfer",
    21: "FTP Control",
    22: "SSH - Secure Shell",
    23: "Telnet - Remote Login",
    25: "SMTP - Email Sending",
    53: "DNS - Domain Name System",
    80: "HTTP - Web Traffic",
    110: "POP3 - Incoming Email",
    123: "NTP - Network Time Protocol",
    143: "IMAP - Email Retrieval",
    443: "HTTPS - Secure Web",
    3306: "MySQL Database",
    3389: "Remote Desktop",
    8080: "Alternative Web Port"
}

def scan_port(ip, port, results):
    try:
        sock = socket.socket()
        sock.settimeout(0.5)
        sock.connect((ip, port))
        description = port_descriptions.get(port, "Unknown service")
        results.append({
            'port': port,
            'status': 'open',
            'description': description
        })
        sock.close()
    except:
        pass

def get_geo_ip(ip):
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/")
        data = r.json()
        return {
            'ip': ip,
            'city': data.get('city'),
            'region': data.get('region'),
            'country': data.get('country_name'),
            'org': data.get('org')
        }
    except:
        return {}

def check_dns_deception(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [str(rdata) for rdata in answers]
    except:
        return ["Failed to resolve"]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    ip_or_domain = request.form['target']
    try:
        ip = socket.gethostbyname(ip_or_domain)
    except:
        return jsonify({'error': 'Invalid domain or IP'}), 400

    open_ports = []
    threads = []

    for port in range(1, 1025):
        t = threading.Thread(target=scan_port, args=(ip, port, open_ports))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    threat_level = "Low"
    if len(open_ports) >= 50:
        threat_level = "High"
    elif len(open_ports) >= 10:
        threat_level = "Medium"

    geo_info = get_geo_ip(ip)
    deception_check = check_dns_deception(ip_or_domain)
    timeline = [datetime.now().strftime("%H:%M:%S") for _ in open_ports]

    return jsonify({
        'open_ports': sorted(open_ports, key=lambda x: x['port']),
        'threat_level': threat_level,
        'geo_info': geo_info,
        'deception': deception_check,
        'timeline': timeline
    })

if __name__ == '__main__':
    app.run(debug=True)
