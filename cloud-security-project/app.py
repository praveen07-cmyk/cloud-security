"""
app.py
------------------------------------------------
AI-Powered Cloud Security Analytics and Intelligent
Threat Response Platform - Main Flask Application.

Run with:
    py app.py

Then open:
    http://127.0.0.1:5000

Demo login:
    username: admin
    password: admin
------------------------------------------------
"""

import os
import io
import csv
from datetime import datetime, timedelta
from ipaddress import ip_address

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, send_file, flash
)
from flask_socketio import SocketIO
from flask_login import (
    LoginManager, UserMixin, current_user, login_required,
    login_user, logout_user
)
from dotenv import load_dotenv

from analytics.risk_engine import calculate_risk
from analytics.recommendation_engine import get_recommendations
from analytics.ip_reputation import get_ip_reputation
from analytics.security_score import calculate_security_score, get_risk_level
from database.db import (
    authenticate_user,
    get_user_by_id,
    get_user_by_username,
    init_db,
    load_incidents,
    seed_demo_data,
)
from ml.predict import predict, is_model_available
from reports.generate_pdf import generate_incident_report

load_dotenv()

# ------------------------------------------------
# App setup
# ------------------------------------------------
app = Flask(
    __name__,
    template_folder="frontend/templates",
    static_folder="frontend/static",
)
app.config["SECRET_KEY"] = (
    os.getenv("SECRET_KEY")
    or os.getenv("FLASK_SECRET_KEY")
    or "demo-secret-key-change-in-production"
)
app.permanent_session_lifetime = timedelta(days=30)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE="Lax",
    REMEMBER_COOKIE_DURATION=timedelta(days=30),
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
    REMEMBER_COOKIE_SECURE=os.getenv("REMEMBER_COOKIE_SECURE", "false").lower() == "true",
)

socketio = SocketIO(app, cors_allowed_origins="*")
login_manager = LoginManager(app)
login_manager.login_view = "login_page"
login_manager.login_message_category = "warning"

init_db()

# ------------------------------------------------
# Fixed demo data (NO random data, NO simulation)
# ------------------------------------------------
DEMO_USERS = {
    "Praveen": "SOC Analyst",
    "Sanjay": "Cloud Administrator",
    "Sai Nathan": "Threat Analyst",
    "Faran": "Security Engineer",
    "Kowshika": "SOC Manager",
}

DEFAULT_INCIDENTS = [
    {
        "id": 1,
        "time": "10:15",
        "source_ip": "192.168.1.45",
        "destination_ip": "10.0.0.5",
        "attack_type": "Brute Force",
        "severity": "Critical",
        "confidence": 98,
        "assigned_to": "Praveen",
        "status": "Investigating",
    },
    {
        "id": 2,
        "time": "10:18",
        "source_ip": "172.16.0.22",
        "destination_ip": "10.0.0.8",
        "attack_type": "Port Scan",
        "severity": "Medium",
        "confidence": 87,
        "assigned_to": "Sanjay",
        "status": "Open",
    },
    {
        "id": 3,
        "time": "10:21",
        "source_ip": "203.0.113.12",
        "destination_ip": "10.0.0.10",
        "attack_type": "SQL Injection",
        "severity": "High",
        "confidence": 93,
        "assigned_to": "Sai Nathan",
        "status": "Investigating",
    },
    {
        "id": 4,
        "time": "10:25",
        "source_ip": "198.51.100.21",
        "destination_ip": "10.0.0.3",
        "attack_type": "DDoS",
        "severity": "Critical",
        "confidence": 99,
        "assigned_to": "Faran",
        "status": "Blocked",
    },
]

seed_demo_data(DEFAULT_INCIDENTS)

# Fixed (non-random) baseline traffic pattern used for the "Live Traffic"
# demo chart. Represents packets-per-minute over a 12 minute sample window.
DEMO_TRAFFIC_PATTERN = [120, 135, 128, 150, 210, 480, 460, 300, 190, 160, 145, 130]

# Fixed packets captured counter for the demo (static, not simulated live capture)
DEMO_PACKETS_CAPTURED = 48213


class User(UserMixin):
    def __init__(self, user_id, username, display_name, role):
        self.id = str(user_id)
        self.username = username
        self.display_name = display_name
        self.role = role

    @classmethod
    def from_row(cls, row):
        if row is None:
            return None
        return cls(
            row["id"],
            row["username"],
            row["display_name"] or row["username"],
            row["role"] or "User",
        )


@login_manager.user_loader
def load_user(user_id):
    row = get_user_by_id(user_id)
    return User.from_row(row)


# ------------------------------------------------
# Auth helper
# ------------------------------------------------
def get_incidents():
    incidents = load_incidents()
    return incidents or DEFAULT_INCIDENTS


def get_logged_in_username():
    if current_user.is_authenticated:
        return current_user.display_name
    return session.get("username")


def get_logged_in_role():
    if current_user.is_authenticated:
        return current_user.role
    return session.get("role")


def is_valid_username(value):
    return bool(value) and 1 <= len(value) <= 64


def is_valid_password(value):
    return bool(value) and 1 <= len(value) <= 128


def is_valid_ip_address(value):
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


@app.after_request
def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://cdn.jsdelivr.net data:; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "script-src 'self' https://cdn.jsdelivr.net https://cdn.socket.io 'unsafe-inline'; "
        "connect-src 'self' https://cdn.socket.io ws: wss:;"
    )
    return response


# ------------------------------------------------
# Routes: Auth
# ------------------------------------------------
@app.route("/")
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return redirect(url_for("login_page"))

    username = (request.form.get("username", "") or "").strip()
    password = request.form.get("password", "") or ""
    remember_me = request.form.get("remember_me") == "on"

    if not is_valid_username(username) or not is_valid_password(password):
        flash("Please enter a valid username and password.")
        return redirect(url_for("login_page"))

    user = authenticate_user(username, password)
    if user:
        user_row = get_user_by_username(username)
        user_object = User.from_row(user_row)
        if user_object is None:
            flash("Login failed. Please try again.")
            return redirect(url_for("login_page"))

        logout_user()
        login_user(user_object, remember=remember_me)
        session.permanent = remember_me
        session["username"] = user["display_name"]
        session["role"] = user["role"]
        session["login_name"] = user["username"]
        session["remember_me"] = remember_me
        return redirect(url_for("dashboard"))

    flash("Invalid username or password. Use the seeded demo account or a configured user.")
    return redirect(url_for("login_page"))


@app.route("/logout")
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("login_page"))


@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(error):
    return render_template("500.html"), 500


# ------------------------------------------------
# Routes: Pages
# ------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    incidents = get_incidents()
    security_score = calculate_security_score(incidents)
    risk_level = get_risk_level(security_score)
    threat_score = max(0, 100 - security_score)
    system_health = "Healthy" if security_score >= 80 else "Degraded" if security_score >= 60 else "At Risk"
    cloud_health = "Operational" if len([i for i in incidents if i["status"] == "Blocked"]) >= 1 else "Monitoring"

    active_threats = len([i for i in incidents if i["status"] != "Blocked"])
    critical_count = len([i for i in incidents if i["severity"] == "Critical"])
    high_count = len([i for i in incidents if i["severity"] == "High"])
    medium_count = len([i for i in incidents if i["severity"] == "Medium"])
    low_count = len([i for i in incidents if i["severity"] == "Low"])
    notification_counts = {
        "Critical": critical_count,
        "High": high_count,
        "Medium": medium_count,
        "Low": low_count,
    }
    notification_items = []
    for inc in incidents:
        notification_items.append(
            {
                "title": f"{inc['attack_type']} from {inc['source_ip']}",
                "detail": f"{inc['severity']} · {inc['status']} · assigned to {inc['assigned_to']}",
                "severity": inc["severity"],
            }
        )

    # Attack type distribution (derived from real fixed incidents)
    attack_distribution = {}
    for inc in incidents:
        attack_distribution[inc["attack_type"]] = attack_distribution.get(inc["attack_type"], 0) + 1

    return render_template(
        "dashboard.html",
        username=get_logged_in_username(),
        role=get_logged_in_role(),
        incidents=incidents,
        security_score=security_score,
        threat_score=threat_score,
        risk_level=risk_level,
        system_health=system_health,
        cloud_health=cloud_health,
        active_threats=active_threats,
        critical_count=critical_count,
        notification_counts=notification_counts,
        notification_items=notification_items,
        packets_captured=DEMO_PACKETS_CAPTURED,
        attack_distribution=attack_distribution,
        traffic_pattern=DEMO_TRAFFIC_PATTERN,
        model_available=is_model_available(),
    )


@app.route("/load-demo-threats")
@login_required
def load_demo_threats():
    """Returns the 4 fixed demo incidents as JSON. No random data."""
    incidents = get_incidents()
    return jsonify({"incidents": incidents, "count": len(incidents)})


@app.route("/investigate/<ip>")
@login_required
def investigate(ip):
    if not is_valid_ip_address(ip):
        flash("Invalid IP address provided.")
        return redirect(url_for("dashboard"))

    incidents = get_incidents()
    incident = next((i for i in incidents if i["source_ip"] == ip), None)

    if incident is None:
        flash(f"No incident found for IP {ip}.")
        return redirect(url_for("dashboard"))

    risk_data = calculate_risk(
        incident["attack_type"], incident["severity"], incident["confidence"]
    )
    reputation_data = get_ip_reputation(ip, incidents)
    recommendations = get_recommendations(incident["attack_type"])
    ml_result = predict({})

    # Simple attack timeline built from the fixed incident record
    timeline = [
        {"time": incident["time"], "event": f"{incident['attack_type']} detected from {ip}"},
        {"time": incident["time"], "event": f"Confidence score recorded at {incident['confidence']}%"},
        {"time": incident["time"], "event": f"Incident assigned to {incident['assigned_to']}"},
        {"time": incident["time"], "event": f"Current status: {incident['status']}"},
    ]

    return render_template(
        "investigate.html",
        username=get_logged_in_username(),
        role=get_logged_in_role(),
        incident=incident,
        risk_data=risk_data,
        reputation_data=reputation_data,
        recommendations=recommendations,
        timeline=timeline,
        ml_result=ml_result,
    )


@app.route("/analytics")
@login_required
def analytics():
    incidents = get_incidents()
    attack_distribution = {}
    severity_distribution = {}
    status_distribution = {}

    for inc in incidents:
        attack_distribution[inc["attack_type"]] = attack_distribution.get(inc["attack_type"], 0) + 1
        severity_distribution[inc["severity"]] = severity_distribution.get(inc["severity"], 0) + 1
        status_distribution[inc["status"]] = status_distribution.get(inc["status"], 0) + 1

    # Weekly view derived deterministically from the fixed incident times
    # (grouped by hour of detection - demo has all incidents around 10 AM)
    weekly_labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    # Deterministic distribution: today's real incident count on "today",
    # 0 for the rest (no random simulated history).
    today_index = datetime.now().weekday()
    weekly_counts = [0] * 7
    weekly_counts[today_index] = len(incidents)

    return render_template(
        "analytics.html",
        username=get_logged_in_username(),
        role=get_logged_in_role(),
        attack_distribution=attack_distribution,
        severity_distribution=severity_distribution,
        status_distribution=status_distribution,
        weekly_labels=weekly_labels,
        weekly_counts=weekly_counts,
    )


@app.route("/reports")
@login_required
def reports():
    incidents = get_incidents()
    return render_template(
        "reports.html",
        username=get_logged_in_username(),
        role=get_logged_in_role(),
        incidents=incidents,
    )


@app.route("/reports/download-pdf")
@login_required
def download_pdf_report():
    path = generate_incident_report(get_incidents())
    return send_file(path, as_attachment=True, download_name="security_report.pdf")


@app.route("/reports/download-csv")
@login_required
def download_csv_report():
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Time", "Source IP", "Destination IP", "Attack Type", "Severity", "Confidence", "Assigned To", "Status"])
    for inc in get_incidents():
        writer.writerow([
            inc["time"], inc["source_ip"], inc["destination_ip"], inc["attack_type"],
            inc["severity"], inc["confidence"], inc["assigned_to"], inc["status"],
        ])

    mem = io.BytesIO(buffer.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name="security_report.csv", mimetype="text/csv")


@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html", username=get_logged_in_username(), role=get_logged_in_role())


@app.route("/profile")
@login_required
def profile():
    return render_template(
        "profile.html",
        username=get_logged_in_username(),
        role=get_logged_in_role(),
        demo_users=DEMO_USERS,
    )


# ------------------------------------------------
# SocketIO events
# ------------------------------------------------
@socketio.on("connect")
def handle_connect():
    """When a dashboard client connects, push the current fixed incidents."""
    socketio.emit("incidents_update", {"incidents": get_incidents()})


# ------------------------------------------------
# Entry point
# ------------------------------------------------
if __name__ == "__main__":
    print("=" * 50)
    print(" AI-Powered Cloud Security Analytics Platform")
    print(" Running at: http://127.0.0.1:5000")
    print(" Login: seeded demo account or SECURITY_ADMIN_USERNAME / SECURITY_ADMIN_PASSWORD")
    print("=" * 50)
    socketio.run(app, host="127.0.0.1", port=5000, debug=True)
