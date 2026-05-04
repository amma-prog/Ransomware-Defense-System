from flask import Flask, render_template, jsonify, send_file
from flask_socketio import SocketIO
import os
import datetime

from canary_manager import CanaryManager
from entropy import calculate_shannon_entropy
from alarm import AlarmSystem
from db_manager import init_db, log_alert, log_event, get_alerts, get_stats
from report_generator import generate_report

app = Flask(__name__)
app.config['SECRET_KEY'] = 'canaryshield'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

base_path = os.path.dirname(os.path.abspath(__file__))
canary_mgr = CanaryManager(base_path)
alarm = AlarmSystem()
monitor = None
init_db()

app_state = {
    'status': 'inactive',
    'alerts': [],
    'logs': []
}

def get_ts():
    return datetime.datetime.now().strftime("%H:%M:%S")

def on_info(message):
    ts = get_ts()
    entry = {'message': message, 'type': 'info', 'timestamp': ts}
    app_state['logs'].append(entry)
    socketio.emit('log_message', entry)
    if 'Entropie:' in message:
        try:
            parts = message.split('|')
            fname = parts[0].replace('Modifié:', '').strip()
            ent = float(parts[1].split(':')[1].strip())
            socketio.emit('entropy_data', {'file': fname, 'entropy': ent, 'timestamp': ts})
            socketio.emit('files_update', {'files': scan_files()})
        except:
            pass

def on_alert(message):
    ts = get_ts()
    entry = {'message': message, 'type': 'alert', 'timestamp': ts}
    app_state['status'] = 'alert'
    app_state['alerts'].append(entry)
    app_state['logs'].append(entry)
    alarm.trigger()
    # Persist to SQLite
    try:
        fname = ''
        ent_val = 0.0
        action = ''
        if 'Entropie' in message:
            parts = message.split('\n')
            for p in parts:
                if 'sur' in p and 'detect' in p:
                    fname = p.split('sur')[-1].split('!')[0].strip()
                if 'mesur' in p:
                    ent_val = float(p.split(':')[1].split('>')[0].strip())
                if 'Action' in p:
                    action = p.split('Action:')[1].strip()
        log_alert(fname, ent_val, 7.5, action)
        log_event('ALERT', message.replace('\n', ' ')[:200])
    except:
        pass
    socketio.emit('alert_message', entry)
    socketio.emit('status_update', {'status': 'alert'})
    socketio.emit('files_update', {'files': scan_files()})

def scan_files():
    cdir = canary_mgr.get_canary_dir()
    files = []
    if os.path.exists(cdir):
        for f in sorted(os.listdir(cdir)):
            fp = os.path.join(cdir, f)
            if os.path.isfile(fp):
                ent = calculate_shannon_entropy(fp)
                files.append({
                    'name': f,
                    'entropy': round(ent, 2),
                    'size': os.path.getsize(fp),
                    'status': 'danger' if ent > 7.0 else 'safe'
                })
    return files

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/deploy', methods=['POST'])
def deploy():
    canary_mgr.deploy_canaries()
    files = scan_files()
    socketio.emit('log_message', {'message': 'Leurres déployés + sauvegarde créée', 'type': 'info', 'timestamp': get_ts()})
    socketio.emit('files_update', {'files': files})
    return jsonify({'success': True, 'files': files})

@app.route('/api/start', methods=['POST'])
def start_monitor():
    try:
        global monitor
        from monitor import RansomwareMonitor
        cdir = canary_mgr.get_canary_dir()
        if not os.path.exists(cdir):
            return jsonify({'success': False, 'message': 'Déployez les canaris d\'abord'})
        if monitor and monitor.is_running:
            return jsonify({'success': False, 'message': 'Déjà actif'})
        monitor = RansomwareMonitor(cdir, on_alert, on_info)
        monitor.start()
        app_state['status'] = 'monitoring'
        files = scan_files()
        ts = get_ts()
        for f in files:
            socketio.emit('entropy_data', {'file': f['name'], 'entropy': f['entropy'], 'timestamp': ts})
        socketio.emit('status_update', {'status': 'monitoring'})
        socketio.emit('files_update', {'files': files})
        return jsonify({'success': True})
    except Exception as e:
        import traceback
        err = traceback.format_exc()
        print('START ERROR:', err)
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/stop', methods=['POST'])
def stop_monitor():
    global monitor
    if monitor and monitor.is_running:
        monitor.stop()
        monitor = None
    alarm.stop()
    app_state['status'] = 'inactive'
    socketio.emit('status_update', {'status': 'inactive'})
    return jsonify({'success': True})

@app.route('/api/restore', methods=['POST'])
def restore():
    alarm.stop()
    success, msg = canary_mgr.restore_canaries()
    files = scan_files()
    if success:
        app_state['status'] = 'restored'
        socketio.emit('status_update', {'status': 'restored'})
        socketio.emit('log_message', {'message': msg, 'type': 'info', 'timestamp': get_ts()})
    socketio.emit('files_update', {'files': files})
    return jsonify({'success': success, 'message': msg, 'files': files})

@app.route('/api/status')
def get_status():
    return jsonify({'status': app_state['status'], 'files': scan_files(), 'has_backup': canary_mgr.has_backup()})

@app.route('/api/history')
def history():
    alerts = get_alerts(50)
    stats = get_stats()
    return jsonify({'alerts': alerts, 'stats': stats})

@app.route('/api/report')
def download_report():
    filepath, filename = generate_report()
    return send_file(filepath, as_attachment=True, download_name=filename)

if __name__ == '__main__':
    print("\n  [*] CanaryShield Dashboard")
    print("  --> http://localhost:5000\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
