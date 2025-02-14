import mysql.connector
import json
import os
from datetime import datetime, timedelta
from flask import Flask, render_template_string, request, jsonify
import requests
import matplotlib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import threading
import time

matplotlib.use('Agg')  # Use a non-GUI backend

app = Flask(__name__)

# Database Configuration
DB_HOST = "69.30.247.130"
DB_USER = "moodlelogs"
DB_PASSWORD = "shrijana"
DB_NAME = "moodlelogs"
DB_TABLE = "moodle_external_logs"

# IP Lists
IP_WHITELIST = ["192.168.0.1", "10.0.0.1"]
IP_BLACKLIST = ["123.45.67.89", "111.222.333.444"]

# JSON File for Cached Geo Data
CACHE_FILE = "geo_cache.json"

# Machine Learning Model
model = IsolationForest(contamination=0.1)  # Adjust contamination based on expected anomaly rate
scaler = StandardScaler()

# Load Cached Data
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as file:
            return json.load(file)
    return {}

# Save Cached Data
def save_cache(cache):
    with open(CACHE_FILE, "w") as file:
        json.dump(cache, file, indent=4)

# Get IP Location with Caching (Using IP-API)
def get_geo_location(ip):
    cache = load_cache()

    if ip in cache:
        return cache[ip]  # Return cached value

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data.get("status") == "success":
            ip_info = {
                "IP": data.get("query", "Unknown"),
                "Country": data.get("country", "Unknown"),
                "Region": data.get("regionName", "Unknown"),
                "City": data.get("city", "Unknown"),
                "ZIP": data.get("zip", "Unknown"),
                "Latitude": data.get("lat", "Unknown"),
                "Longitude": data.get("lon", "Unknown"),
                "Timezone": data.get("timezone", "Unknown"),
                "ISP": data.get("isp", "Unknown"),
                "Organization": data.get("org", "Unknown"),
                "AS": data.get("as", "Unknown"),
            }
        else:
            ip_info = {"IP": ip, "Error": "Unable to fetch data"}

        cache[ip] = ip_info  # Save to cache
        save_cache(cache)  # Update JSON file
        return ip_info
    except:
        return {"IP": ip, "Error": "Unknown Location"}

def fetch_logs_from_external_db(days=1):
    """
    Fetch logs from the external database for the past `days` days.
    """
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = connection.cursor(dictionary=True)
        time_threshold = datetime.now() - timedelta(days=days)
        query = f"SELECT * FROM {DB_TABLE} WHERE timecreated >= %s"
        cursor.execute(query, (int(time_threshold.timestamp()),))
        logs = cursor.fetchall()
        cursor.close()
        return logs
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return []
    finally:
        if connection and connection.is_connected():
            connection.close()

def preprocess_logs(logs):
    """
    Preprocess logs for machine learning.
    """
    features = []
    for log in logs:
        ip = log.get("ip")
        
        # Handle missing or malformed IP addresses
        if not ip or not isinstance(ip, str):
            ip = "0.0.0.0"  # Assign a default IP
        
        try:
            ip_parts = list(map(int, ip.split(".")))
        except ValueError:
            ip_parts = [0, 0, 0, 0]  # Default to a safe format if parsing fails

        features.append(ip_parts + [log.get("timecreated", 0)])

    return np.array(features)


def train_model(logs):
    """
    Train the anomaly detection model.
    """
    features = preprocess_logs(logs)
    features = scaler.fit_transform(features)
    model.fit(features)

def detect_anomalies(logs):
    """
    Detect anomalies in logs using the trained model.
    """
    features = preprocess_logs(logs)
    features = scaler.transform(features)
    predictions = model.predict(features)
    return predictions

def analyze_logs(logs):
    """
    Analyze logs and detect potential threats.
    """
    flagged_logs = []
    anomalies = detect_anomalies(logs)

    for log, is_anomaly in zip(logs, anomalies):
        ip = log.get("ip", "unknown")
        log["geo_data"] = get_geo_location(ip)  # Fetch detailed IP information

        # Threat scoring
        threat_score = 0
        if ip in IP_BLACKLIST:
            threat_score += 100
        elif ip not in IP_WHITELIST:
            threat_score += 50
        if is_anomaly == -1:  # Anomaly detected
            threat_score += 30

        log["threat_score"] = threat_score
        log["flag"] = "High" if threat_score >= 80 else "Medium" if threat_score >= 50 else "Low"
        flagged_logs.append(log)

    return flagged_logs

@app.route("/")
def index():
    """
    Display logs, threats, and the interactive chart.
    """
    days = request.args.get("days", 1, type=int)
    logs = fetch_logs_from_external_db(days=days)
    threats = analyze_logs(logs)

    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Advanced Threat Detection Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            body {
                font-family: 'Inter', sans-serif;
                background: linear-gradient(135deg, #1e3a8a, #1e40af);
                color: #f3f4f6;
            }
            .glassmorphism {
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
                border-radius: 12px;
                border: 1px solid rgba(255, 255, 255, 0.2);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            }
            .navbar {
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            }
            .chart-container {
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
                border-radius: 12px;
                padding: 1.5rem;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 1.5rem;
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
                border-radius: 12px;
                overflow: hidden;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            }
            th, td {
                padding: 0.75rem;
                text-align: left;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }
            th {
                background: rgba(255, 255, 255, 0.2);
                color: white;
                font-weight: 600;
            }
            tr:hover {
                background: rgba(255, 255, 255, 0.05);
            }
            .flag-high {
                background: #ef4444;
                color: white;
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-weight: 600;
            }
            .flag-medium {
                background: #f59e0b;
                color: white;
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-weight: 600;
            }
            .flag-low {
                background: #10b981;
                color: white;
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-weight: 600;
            }
            .animate-fade-in {
                animation: fadeIn 0.5s ease-in-out;
            }
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(10px); }
                to { opacity: 1; transform: translateY(0); }
            }
        </style>
    </head>
    <body>
        <div class="navbar p-4">
            <h1 class="text-2xl font-bold text-white">Advanced Threat Detection Dashboard</h1>
        </div>

        <div class="container mx-auto p-4">
            <div class="grid grid-cols-1 gap-6">
                <!-- Chart Section -->
                <div class="chart-container animate-fade-in">
                    <h2 class="text-xl font-semibold mb-4 text-white">Threat Activity Over Time</h2>
                    <canvas id="activityChart"></canvas>
                </div>

                <!-- Table Section -->
                <div class="glassmorphism p-6 animate-fade-in">
                    <h2 class="text-xl font-semibold mb-4 text-white">Detected Threats & IP Information</h2>
                    <table>
                        <thead>
                            <tr>
                                <th class="text-white">IP</th>
                                <th class="text-white">Country</th>
                                <th class="text-white">City</th>
                                <th class="text-white">ISP</th>
                                <th class="text-white">Threat Score</th>
                                <th class="text-white">Flag</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for threat in threats %}
                            <tr class="hover:bg-opacity-10">
                                <td class="text-white">{{ threat.geo_data.IP }}</td>
                                <td class="text-white">{{ threat.geo_data.Country }}</td>
                                <td class="text-white">{{ threat.geo_data.City }}</td>
                                <td class="text-white">{{ threat.geo_data.ISP }}</td>
                                <td class="text-white">{{ threat.threat_score }}</td>
                                <td>
                                    <span class="flag-{{ threat.flag.lower() }}">{{ threat.flag }}</span>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <script>
        document.addEventListener("DOMContentLoaded", function() {
            fetch('/chart-data')
            .then(response => response.json())
            .then(chartData => {
                const ctx = document.getElementById('activityChart').getContext('2d');
                new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: chartData.labels,
                        datasets: [{
                            label: 'Threat Activity',
                            data: chartData.data,
                            backgroundColor: 'rgba(79, 70, 229, 0.2)',
                            borderColor: 'rgba(79, 70, 229, 1)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.4
                        }]
                    },
                    options: {
                        scales: {
                            y: {
                                beginAtZero: true,
                                grid: {
                                    color: 'rgba(255, 255, 255, 0.1)'
                                },
                                ticks: {
                                    color: 'white'
                                }
                            },
                            x: {
                                grid: {
                                    color: 'rgba(255, 255, 255, 0.1)'
                                },
                                ticks: {
                                    color: 'white'
                                }
                            }
                        },
                        plugins: {
                            legend: {
                                display: false
                            }
                        }
                    }
                });
            });
        });
        </script>
    </body>
    </html>
    """
    return render_template_string(html_template, threats=threats)

@app.route("/chart-data")
def chart_data():
    """
    Generate chart data for the past 7 days.
    """
    labels = [f"Day {i}" for i in range(7, 0, -1)]
    data = [10, 15, 12, 18, 20, 25, 30]  # Example data
    return jsonify({"labels": labels, "data": data})

def real_time_monitoring():
    """
    Continuously monitor logs for real-time threat detection.
    """
    while True:
        logs = fetch_logs_from_external_db(days=1)
        threats = analyze_logs(logs)
        print(f"Detected {len(threats)} threats in real-time.")
        time.sleep(60)  # Check every 60 seconds

if __name__ == "__main__":
    # Train the model on historical logs
    logs = fetch_logs_from_external_db(days=7)
    train_model(logs)

    # Start real-time monitoring in a separate thread
    threading.Thread(target=real_time_monitoring, daemon=True).start()

    app.run(debug=True)
