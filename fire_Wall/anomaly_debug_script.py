import sqlite3
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

def debug_anomaly_detection():
    """Comprehensive anomaly detection debugging"""
    # Connect to database
    conn = sqlite3.connect('firewall_policies.db')
    
    # Read network logs
    df = pd.read_sql_query("SELECT * FROM network_logs", conn)
    conn.close()

    # Extract features
    features = df[['bytes_sent', 'bytes_received']].values

    # Anomaly Detection
    clf = IsolationForest(
        contamination=0.1,  # 10% of data considered anomalous
        random_state=42
    )
    
    # Fit and predict
    predictions = clf.fit_predict(features)
    
    # Mark anomalies
    df['is_anomaly'] = predictions == -1

    # Print Detailed Anomaly Information
    print("\n--- Anomaly Detection Report ---")
    print(f"Total Logs: {len(df)}")
    print(f"Anomalous Logs: {sum(df['is_anomaly'])}")
    
    # Print Anomalous Entries
    print("\nAnomalous Log Details:")
    anomalies = df[df['is_anomaly']]
    print(anomalies[['app_name', 'destination', 'bytes_sent', 'bytes_received']])

    # Visualization
    plt.figure(figsize=(10, 6))
    plt.scatter(
        df[~df['is_anomaly']]['bytes_sent'], 
        df[~df['is_anomaly']]['bytes_received'], 
        c='blue', 
        label='Normal'
    )
    plt.scatter(
        df[df['is_anomaly']]['bytes_sent'], 
        df[df['is_anomaly']]['bytes_received'], 
        c='red', 
        label='Anomaly'
    )
    plt.xlabel('Bytes Sent')
    plt.ylabel('Bytes Received')
    plt.title('Network Traffic Anomaly Detection')
    plt.legend()
    plt.show()

# Run this to analyze anomalies
debug_anomaly_detection()
