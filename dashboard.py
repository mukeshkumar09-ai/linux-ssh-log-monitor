from flask import Flask, jsonify, render_template_string
import json
import os
from collections import Counter

app = Flask(__name__)

ALERT_FILE = "alerts.json"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SSH Security Analytics Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial; background: #111; color: white; }
        h1 { color: #00ffcc; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; border: 1px solid #333; }
        th { background: #222; }
        .high { color: red; font-weight: bold; }
        .medium { color: orange; }
        canvas { background: #222; margin-top: 20px; }
    </style>
</head>
<body>
    <h1>🚀 SSH Security Analytics Dashboard</h1>

    <canvas id="attackChart"></canvas>

    <table>
        <tr>
            <th>IP</th>
            <th>User</th>
            <th>Attempts</th>
            <th>Severity</th>
            <th>Timestamp</th>
        </tr>
        {% for alert in alerts %}
        <tr>
            <td>{{ alert.ip }}</td>
            <td>{{ alert.user }}</td>
            <td>{{ alert.attempts }}</td>
            <td class="{{ alert.severity }}">{{ alert.severity.upper() }}</td>
            <td>{{ alert.timestamp }}</td>
        </tr>
        {% endfor %}
    </table>

<script>
async function fetchData() {
    const response = await fetch('/api/alerts');
    const data = await response.json();

    const ipCounts = {};
    data.forEach(alert => {
        ipCounts[alert.ip] = (ipCounts[alert.ip] || 0) + 1;
    });

    const labels = Object.keys(ipCounts);
    const values = Object.values(ipCounts);

    attackChart.data.labels = labels;
    attackChart.data.datasets[0].data = values;
    attackChart.update();
}

const ctx = document.getElementById('attackChart').getContext('2d');
const attackChart = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: [],
        datasets: [{
            label: 'Attack Attempts per IP',
            data: [],
            backgroundColor: 'rgba(255, 99, 132, 0.6)'
        }]
    },
    options: {
        scales: {
            y: { beginAtZero: true }
        }
    }
});

fetchData();
setInterval(fetchData, 5000);
</script>

</body>
</html>
"""

def load_alerts():
    alerts = []
    if os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "r") as f:
            for line in f:
                alerts.append(json.loads(line))
    return alerts[::-1]

@app.route("/")
def dashboard():
    alerts = load_alerts()
    return render_template_string(HTML_TEMPLATE, alerts=alerts)

@app.route("/api/alerts")
def api_alerts():
    return jsonify(load_alerts())

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
