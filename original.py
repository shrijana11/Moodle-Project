import mysql.connector
from datetime import datetime, timedelta
from flask import Flask, render_template_string, request
import matplotlib.pyplot as plt
import io
import base64
import requests

DB_HOST = "69.30.247.130"
DB_USER = "moodlelogs"
DB_PASSWORD = "shrijana"
DB_NAME = "moodlelogs"
DB_TABLE = "moodle_external_logs"

app = Flask(__name__)


IP_WHITELIST = ["192.168.0.1", "10.0.0.1"]
IP_BLACKLIST = ["123.45.67.89", "111.222.333.444"]

IP_REPUTATION_API = "https://api.abuseipdb.com/api/v2/check"
IP_REPUTATION_API_KEY = "your_api_key_here"

def test_database_connection():
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = connection.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchall()
        print("Database connection successful!")
        cursor.close()
        return True
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return False
    finally:
        if connection and connection.is_connected():
            connection.close()

def fetch_logs_from_external_db(days=1):
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

def check_ip_reputation(ip):
    """
    Check IP reputation using an external API like AbuseIPDB.
    """
    try:
        headers = {"Key": IP_REPUTATION_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        response = requests.get(IP_REPUTATION_API, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            if data.get("data", {}).get("isPublic") and data["data"].get("abuseConfidenceScore", 0) > 50:
                return "High Risk"
        return "Safe"
    except Exception as e:
        print(f"Error checking IP reputation: {e}")
        return "Unknown"

def analyze_logs(logs):
    """
    Advanced threat detection logic.
    """
    flagged_logs = []
    user_ip_map = {}
    user_device_map = {}
    ip_attempts = {}
    geo_data_cache = {}

    for log in logs:
        action = log.get("action", "").lower()
        ip = log.get("ip", "unknown")
        userid = log.get("userid", "unknown")
        courseid = log.get("courseid", "unknown")
        user_agent = log.get("useragent", "unknown")
        time = datetime.fromtimestamp(log.get("timecreated", 0))

        if userid not in user_ip_map:
            user_ip_map[userid] = set()
        user_ip_map[userid].add(ip)

        if userid not in user_device_map:
            user_device_map[userid] = set()
        user_device_map[userid].add(user_agent)

        if "failedlogin" in action:
            ip_attempts[ip] = ip_attempts.get(ip, 0) + 1

        if ip in IP_BLACKLIST:
            log["flag"] = "IP Blacklisted"
            flagged_logs.append(log)

        if len(user_ip_map[userid]) > 3:
            log["flag"] = "Multiple IPs Used"
            flagged_logs.append(log)

        if len(user_device_map[userid]) > 2:
            log["flag"] = "Multiple Devices Used"
            flagged_logs.append(log)


        if ip_attempts.get(ip, 0) > 10:
            log["flag"] = "Excessive Failed Logins"
            flagged_logs.append(log)

        if "delete" in action or "update" in action:
            log["flag"] = "Suspicious Course Action"
            flagged_logs.append(log)

        if "role" in action and "admin" in action:
            log["flag"] = "Role Escalation"
            flagged_logs.append(log)

        if ip not in geo_data_cache:
            geo_data_cache[ip] = get_geo_location(ip)
        log["geo_location"] = geo_data_cache[ip]
        if geo_data_cache[ip] != "Known Location":
            log["flag"] = "Login from Unusual Location"
            flagged_logs.append(log)

        if check_ip_reputation(ip) == "High Risk":
            log["flag"] = "High Risk IP"
            flagged_logs.append(log)

    return flagged_logs

def get_geo_location(ip):
    """
    Get the geographical location of an IP.
    """
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        data = response.json()
        city = data.get("city", "Unknown")
        country = data.get("country_name", "Unknown")
        return f"{city}, {country}"
    except Exception:
        return "Unknown Location"

def generate_activity_chart(logs):
    """
    Generate a line chart for activity over time.
    """
    activity_per_hour = {}
    for log in logs:
        time = datetime.fromtimestamp(log.get("timecreated", 0))
        hour = time.strftime("%Y-%m-%d %H:00")
        activity_per_hour[hour] = activity_per_hour.get(hour, 0) + 1

    hours = list(activity_per_hour.keys())
    counts = list(activity_per_hour.values())

    plt.figure(figsize=(12, 6))
    plt.plot(hours, counts, marker="o")
    plt.xlabel("Hour")
    plt.ylabel("Activity Count")
    plt.title("Activity Over Time")
    plt.xticks(rotation=45, ha="right")

    img = io.BytesIO()
    plt.tight_layout()
    plt.savefig(img, format="png")
    img.seek(0)
    chart_url = base64.b64encode(img.getvalue()).decode()
    plt.close()
    return chart_url

@app.route("/")
def index():
    """
    Display logs, threats, and visualizations in the web UI.
    """
    days = request.args.get("days", 1, type=int)
    logs = fetch_logs_from_external_db(days=days)
    threats = analyze_logs(logs)
    activity_chart = generate_activity_chart(logs)

    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Advanced Threat Detection</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css">
    </head>
    <body>
        <div class="container">
            <h1 class="text-center mt-4">Advanced Moodle Threat Detection</h1>
            <h2>Threats</h2>
            <table class="table table-bordered table-striped">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Action</th>
                        <th>IP</th>
                        <th>Geo Location</th>
                        <th>Flag</th>
                    </tr>
                </thead>
                <tbody>
                    {% for threat in threats %}
                    <tr>
                        <td>{{ threat.id }}</td>
                        <td>{{ threat.action }}</td>
                        <td>{{ threat.ip }}</td>
                        <td>{{ threat.geo_location }}</td>
                        <td>{{ threat.flag }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <h2>Activity Over Time</h2>
            <img src="data:image/png;base64,{{ activity_chart }}" class="img-fluid">
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template, logs=logs, threats=threats, activity_chart=activity_chart)

if __name__ == "__main__":
    app.run(debug=True)
