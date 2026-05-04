import sqlite3
import os
import datetime

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "canaryshield.db")

def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            filename TEXT NOT NULL,
            entropy REAL NOT NULL,
            threshold REAL NOT NULL DEFAULT 7.5,
            action_taken TEXT,
            severity TEXT DEFAULT 'CRITICAL'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            message TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def log_alert(filename, entropy, threshold, action_taken):
    conn = get_connection()
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO alerts (timestamp, filename, entropy, threshold, action_taken) VALUES (?, ?, ?, ?, ?)",
        (ts, filename, entropy, threshold, action_taken)
    )
    conn.commit()
    conn.close()

def log_event(event_type, message):
    conn = get_connection()
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO events (timestamp, event_type, message) VALUES (?, ?, ?)",
        (ts, event_type, message)
    )
    conn.commit()
    conn.close()

def get_alerts(limit=50):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_events(limit=100):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_stats():
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    today = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE timestamp LIKE ?",
        (datetime.datetime.now().strftime("%Y-%m-%d") + "%",)
    ).fetchone()[0]
    files_hit = conn.execute("SELECT COUNT(DISTINCT filename) FROM alerts").fetchone()[0]
    conn.close()
    return {'total_alerts': total, 'today_alerts': today, 'unique_files_hit': files_hit}
