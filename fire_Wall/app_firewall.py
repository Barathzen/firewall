# Application Firewall Prototype

import os
import json
import uuid
import logging
import hashlib
import psutil
import sqlite3
import threading
import subprocess
from typing import Dict, List, Any
from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import socket
import requests
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# Logging Configuration
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s: %(message)s',
                    filename='app_firewall.log')

# Global Configuration
class FirewallConfig:
    DATABASE = 'firewall_policies.db'
    CENTRAL_SERVER = 'http://localhost:5000'
    LOG_DIRECTORY = 'network_logs'
    POLLING_INTERVAL = 60  # seconds
    ANOMALY_THRESHOLD = 0.8  # Confidence level for anomaly detection

# Database Initialization
class DatabaseManager:
    @staticmethod
    def init_db():
        conn = sqlite3.connect(FirewallConfig.DATABASE)
        cursor = conn.cursor()
        
        # Application Policies Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS app_policies (
                id TEXT PRIMARY KEY,
                app_name TEXT,
                allowed_domains TEXT,
                allowed_ips TEXT,
                allowed_protocols TEXT,
                is_active BOOLEAN
            )
        ''')
        
        # Network Logs Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_logs (
                id TEXT PRIMARY KEY,
                app_name TEXT,
                timestamp DATETIME,
                destination TEXT,
                protocol TEXT,
                bytes_sent INTEGER,
                bytes_received INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()

# Application Firewall Agent
class ApplicationFirewallAgent:
    def __init__(self):
        self.agent_id = str(uuid.uuid4())
        DatabaseManager.init_db()
        
    def get_running_processes(self) -> List[Dict[str, Any]]:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'path': proc.info.get('exe', 'Unknown')
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return processes
    
    def monitor_network_traffic(self, app_name: str):
        """Monitor network traffic for a specific application"""
        try:
            connections = [conn for conn in psutil.net_connections() 
                           if conn.laddr and conn.raddr]
            
            for conn in connections:
                log_entry = {
                    'id': str(uuid.uuid4()),
                    'app_name': app_name,
                    'timestamp': datetime.now(),
                    'destination': f"{conn.raddr.ip}:{conn.raddr.port}",
                    'protocol': conn.type.name if hasattr(conn.type, 'name') else 'Unknown',
                    'bytes_sent': conn.sent or 0,
                    'bytes_received': conn.recv or 0
                }
                
                self._log_network_activity(log_entry)
        except Exception as e:
            logging.error(f"Network monitoring error: {e}")
    
    def _log_network_activity(self, log_entry: Dict):
        """Log network activity to database"""
        conn = sqlite3.connect(FirewallConfig.DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO network_logs 
            (id, app_name, timestamp, destination, protocol, bytes_sent, bytes_received)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            log_entry['id'], 
            log_entry['app_name'], 
            str(log_entry['timestamp']),
            log_entry['destination'], 
            log_entry['protocol'], 
            log_entry['bytes_sent'], 
            log_entry['bytes_received']
        ))
        
        conn.commit()
        conn.close()
    
    def detect_anomalies(self):
        """Detect network behavior anomalies using Isolation Forest"""
        conn = sqlite3.connect(FirewallConfig.DATABASE)
        
        # Check if there are enough logs for anomaly detection
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM network_logs")
        log_count = cursor.fetchone()[0]
        
        if log_count < 10:  # Not enough data for meaningful anomaly detection
            conn.close()
            return []
        
        # Fetch logs and perform anomaly detection
        df = pd.read_sql_query("SELECT * FROM network_logs", conn)
        conn.close()
        
        try:
            # Extract features for anomaly detection
            features = df[['bytes_sent', 'bytes_received']].values
            
            # Train Isolation Forest
            clf = IsolationForest(
                contamination=0.1,  # 10% of data considered anomalous
                random_state=42
            )
            clf.fit(features)
            
            # Predict anomalies
            predictions = clf.predict(features)
            anomalies = df[predictions == -1]
            
            return anomalies.to_dict('records')
        except Exception as e:
            logging.error(f"Anomaly detection error: {e}")
            return []

# Web Management Console (Flask Application)
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{FirewallConfig.DATABASE}'
db = SQLAlchemy(app)

@app.route('/')
def dashboard():
    """Central dashboard for firewall management"""
    agent = ApplicationFirewallAgent()
    processes = agent.get_running_processes()
    
    # Safely handle anomaly detection
    try:
        anomalies = agent.detect_anomalies()
    except Exception as e:
        logging.error(f"Dashboard anomaly detection error: {e}")
        anomalies = []
    
    return render_template('dashboard.html', 
                           processes=processes, 
                           anomalies=anomalies)

@app.route('/policy/create', methods=['POST'])
def create_policy():
    """Create firewall policy for an application"""
    data = request.json
    
    conn = sqlite3.connect(FirewallConfig.DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO app_policies 
        (id, app_name, allowed_domains, allowed_ips, allowed_protocols, is_active)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        str(uuid.uuid4()),
        data['app_name'],
        ','.join(data.get('allowed_domains', [])),
        ','.join(data.get('allowed_ips', [])),
        ','.join(data.get('allowed_protocols', [])),
        data.get('is_active', True)
    ))
    
    conn.commit()
    conn.close()
    
    return jsonify({"status": "success"})

@app.route('/logs/application/<app_name>')
def get_app_logs(app_name):
    """Retrieve network logs for a specific application"""
    conn = sqlite3.connect(FirewallConfig.DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM network_logs WHERE app_name = ?", (app_name,))
    logs = cursor.fetchall()
    
    conn.close()
    
    return jsonify(logs)

if __name__ == '__main__':
    # Ensure log directory exists
    os.makedirs(FirewallConfig.LOG_DIRECTORY, exist_ok=True)
    
    # Start the Flask application
    app.run(debug=True, host='0.0.0.0', port=5000)