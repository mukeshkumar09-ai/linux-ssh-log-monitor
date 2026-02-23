


from flask import Flask, render_template, jsonify, request
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

# ==============================
# DATABASE CONFIGURATION
# ==============================

DATABASE_URL = os.environ.get("DATABASE_URL")

# Fix for Render postgres:// issue
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ==============================
# DATABASE MODEL
# ==============================

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50))
    user = db.Column(db.String(100))
    attempts = db.Column(db.Integer)
    severity = db.Column(db.String(20))
    timestamp = db.Column(db.String(50))

# Create tables automatically
with app.app_context():
    db.create_all()

# ==============================
# STORE ALERT API (POST)
# ==============================

@app.route("/api/store", methods=["POST"])
def store_alert():
    data = request.json

    alert = Alert(
        ip=data["ip"],
        user=data["user"],
        attempts=data["attempts"],
        severity=data["severity"],
        timestamp=data["timestamp"]
    )

    db.session.add(alert)
    db.session.commit()

    return {"status": "stored"}, 200

# ==============================
# FETCH ALERTS API (GET)
# ==============================

@app.route("/api/alerts")
def get_alerts():
    alerts = Alert.query.order_by(Alert.id.desc()).limit(50).all()

    result = []
    for a in alerts:
        result.append({
            "ip": a.ip,
            "user": a.user,
            "attempts": a.attempts,
            "severity": a.severity,
            "timestamp": a.timestamp
        })

    return jsonify(result)

# ==============================
# HOME PAGE
# ==============================

@app.route("/")
def index():
    return render_template("index.html")

# ==============================
# RUN (LOCAL ONLY)
# ==============================

if __name__ == "__main__":
    app.run(debug=True)
