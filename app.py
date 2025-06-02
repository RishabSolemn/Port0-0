from flask import Flask, render_template, request
from flask_socketio import SocketIO
import socket
import threading

app = Flask(__name__)
socketio = SocketIO(app)

# Threat level calculator
def calculate_threat_level(open_ports):
    dangerous_ports = {21, 23, 445, 3389}
    if any(p in open_ports for p in dangerous_ports):
        return "High"
    elif len(open_ports) > 5:
        return "Medium"
    else:
        return "Low"

# Port scanning function
def scan_ports(domain, port_range, sid):
    open_ports = []
    start, end = port_range

    socketio.emit('log', f"Starting scan on {domain}", room=sid)

    for port in range(start, end + 1):
        try:
            s = socket.socket()
            s.settimeout(0.5)
            result = s.connect_ex((domain, port))
            if result == 0:
                open_ports.append(port)
                socketio.emit('log', f"✅ Port {port} is open", room=sid)
            else:
                socketio.emit('log', f"❌ Port {port} is closed", room=sid)
            s.close()
        except Exception as e:
            socketio.emit('log', f"⚠️ Error on port {port}: {e}", room=sid)

    threat_level = calculate_threat_level(open_ports)
    socketio.emit('done', {"open_ports": open_ports, "threat_level": threat_level}, room=sid)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('start_scan')
def handle_scan(data):
    domain = data['domain']
    start = int(data['start_port'])
    end = int(data['end_port'])
    thread = threading.Thread(target=scan_ports, args=(domain, (start, end), request.sid))
    thread.start()

if __name__ == '__main__':
    socketio.run(app, debug=True)
