from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

# ==============================
# BASIC CONFIG
# ==============================

app.secret_key = "supersecretkey"

DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if DATABASE_URL:
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "connect_args": {"sslmode": "require"}
    }
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ==============================
# EMAIL CONFIG
# ==============================

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get("EMAIL_USER")
app.config['MAIL_PASSWORD'] = os.environ.get("EMAIL_PASS")

mail = Mail(app)

# ==============================
# INIT DATABASE + LOGIN
# ==============================

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ==============================
# DATABASE MODELS
# ==============================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(200))

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50))
    user = db.Column(db.String(100))
    attempts = db.Column(db.Integer)
    severity = db.Column(db.String(20))
    timestamp = db.Column(db.String(50))

# ==============================
# CREATE TABLES + DEFAULT ADMIN
# ==============================

with app.app_context():
    db.create_all()

    if not User.query.filter_by(username="admin").first():
        hashed_pw = generate_password_hash("admin123")
        admin = User(username="admin", password=hashed_pw)
        db.session.add(admin)
        db.session.commit()

# ==============================
# LOGIN MANAGER
# ==============================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==============================
# EMAIL FUNCTION
# ==============================

def send_email(ip, user, attempts):
    try:
        msg = Message(
            subject="🚨 HIGH SSH ATTACK DETECTED",
            sender=app.config['MAIL_USERNAME'],
            recipients=[app.config['MAIL_USERNAME']]
        )

        msg.body = f"""
High severity SSH attack detected!

IP: {ip}
User: {user}
Attempts: {attempts}

Check dashboard immediately.
"""

        mail.send(msg)

    except Exception as e:
        print("Email failed:", e)

# ==============================
# LOGIN ROUTE
# ==============================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("index"))

    return render_template("login.html")

# ==============================
# LOGOUT ROUTE
# ==============================

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ==============================
# DASHBOARD
# ==============================

@app.route("/")
@login_required
def index():
    return render_template("index.html")

# ==============================
# STORE ALERT API
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

    # 🔥 Send email if HIGH severity
    if data["severity"] == "HIGH":
        send_email(data["ip"], data["user"], data["attempts"])

    return {"status": "stored"}, 200

# ==============================
# FETCH ALERTS
# ==============================

@app.route("/api/alerts")
@login_required
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
# STATS API
# ==============================

@app.route("/api/stats")
@login_required
def get_stats():
    total_attacks = Alert.query.count()
    unique_ips = db.session.query(Alert.ip).distinct().count()
    high_severity = Alert.query.filter_by(severity="HIGH").count()

    return jsonify({
        "total_attacks": total_attacks,
        "unique_ips": unique_ips,
        "high_severity": high_severity
    })

# ==============================
# RUN
# ==============================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)