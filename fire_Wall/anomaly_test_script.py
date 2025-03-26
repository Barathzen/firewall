import sqlite3
import random
from datetime import datetime
import uuid

def generate_test_logs():
    """Generate synthetic network logs to test anomaly detection"""
    conn = sqlite3.connect('firewall_policies.db')
    cursor = conn.cursor()

    # Normal traffic logs
    for _ in range(50):
        cursor.execute('''
            INSERT INTO network_logs 
            (id, app_name, timestamp, destination, protocol, bytes_sent, bytes_received)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            str(uuid.uuid4()),
            'chrome.exe',
            str(datetime.now()),
            f'192.168.1.{random.randint(1,255)}',
            'TCP',
            random.randint(100, 5000),  # Normal bytes sent
            random.randint(100, 5000)   # Normal bytes received
        ))

    # Anomalous traffic logs
    for _ in range(5):
        cursor.execute('''
            INSERT INTO network_logs 
            (id, app_name, timestamp, destination, protocol, bytes_sent, bytes_received)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            str(uuid.uuid4()),
            'suspicious_app.exe',
            str(datetime.now()),
            f'unknown_host_{random.randint(1,100)}',
            'UDP',
            random.randint(50000, 500000),  # Unusually high bytes sent
            random.randint(50000, 500000)   # Unusually high bytes received
        ))

    conn.commit()
    conn.close()
    print("Test logs generated successfully!")

# Run this script to populate database with test logs
generate_test_logs()
