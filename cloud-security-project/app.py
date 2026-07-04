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
import logging
import re
import shutil
import sys
import traceback
from functools import wraps
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, send_file, flash, abort, has_request_context
)
from flask_socketio import SocketIO
from flask_login import (
    LoginManager, UserMixin, current_user, login_required,
    login_user, logout_user
)
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from config import Config
from logging_config import setup_logging
from analytics.risk_engine import calculate_risk
from analytics.recommendation_engine import get_recommendations
from analytics.ip_reputation import get_ip_reputation
from database.db import (
    DB_PATH,
    add_prediction_incident,
    authenticate_user,
    get_all_incidents,
    get_all_assets,
    get_all_reports,
    get_audit_logs,
    get_dashboard_stats,
    get_demo_incidents,
    get_incidents_by_ip,
    get_latest_model_version,
    get_prediction_incidents,
    get_timeline_for_incident,
    get_or_create_firebase_user,
    get_user_by_id,
    init_db,
    log_audit_event,
    role_can_access,
)
from ml.predict import predict, is_model_available, get_model_metadata, predict_csv, predict_pcap
from reports.generate_pdf import generate_incident_report
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
import firebase_admin
from firebase_admin import auth as firebase_auth
from firebase_admin import credentials as firebase_credentials

load_dotenv()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGGERS = setup_logging(BASE_DIR)
app_logger = LOGGERS["app"]
security_logger = LOGGERS["security"]
audit_logger = LOGGERS["audit"]
error_logger = LOGGERS["error"]

# ------------------------------------------------
# App setup
# ------------------------------------------------
app = Flask(
    __name__,
    template_folder="frontend/templates",
    static_folder="frontend/static",
)
app.config.from_object(Config)
app.permanent_session_lifetime = app.config["PERMANENT_SESSION_LIFETIME"]

socketio = SocketIO(app, cors_allowed_origins="*")
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["300 per day", "120 per hour"],
    storage_uri=app.config["RATELIMIT_STORAGE_URI"],
)
login_manager = LoginManager(app)
login_manager.login_view = "login_page"
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"

UPLOAD_EXTENSIONS = {".csv", ".pcap", ".pcapng"}
UPLOADS_DIR = os.path.join(BASE_DIR, app.config["UPLOAD_FOLDER"])
BACKUPS_DIR = os.path.join(BASE_DIR, app.config["BACKUP_FOLDER"])
MODELS_DIR = os.path.join(BASE_DIR, "models")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
DATABASE_DIR = os.path.dirname(DB_PATH)
LOGIN_ATTEMPTS = {}
LOGIN_IP_FAILURES = {}
ACCOUNT_LOCKS = {}
IP_BLOCKS = {}
FAILED_LOGIN_WINDOW = timedelta(minutes=10)
ACCOUNT_LOCK_DURATION = timedelta(minutes=15)
IP_BLOCK_DURATION = timedelta(minutes=15)
SESSION_TIMEOUT_SECONDS = int(app.config["PERMANENT_SESSION_LIFETIME"].total_seconds())
SAFE_HTTP_METHODS = {"GET", "POST", "HEAD", "OPTIONS"}
FIREBASE_SERVICE_ACCOUNT_PATH = os.getenv(
    "FIREBASE_SERVICE_ACCOUNT_PATH",
    os.path.join(BASE_DIR, "firebase-service-account.json"),
)

REQUIRED_DIRECTORIES = {
    "database": DATABASE_DIR,
    "uploads": UPLOADS_DIR,
    "logs": os.path.join(BASE_DIR, "logs"),
    "backups": BACKUPS_DIR,
    "models": MODELS_DIR,
    "reports": REPORTS_DIR,
}
REQUIRED_TEMPLATES = {
    "login.html",
    "dashboard.html",
    "analytics.html",
    "reports.html",
    "trust_center.html",
    "upload_center.html",
    "audit_logs.html",
    "settings.html",
    "profile.html",
    "investigate.html",
    "error.html",
    "403.html",
    "404.html",
    "429.html",
    "500.html",
}
REQUIRED_STATIC_FILES = {
    "css/style.css",
    "css/dashboard.css",
    "css/login.css",
    "js/dashboard.js",
    "js/firebase-auth.js",
}


def log_exception_context(logger, message, exc):
    tb = exc.__traceback__ if exc else None
    frames = traceback.extract_tb(tb) if tb else []
    last_frame = frames[-1] if frames else None
    logger.error(
        "%s | path=%s | exception=%s | filename=%s | line=%s",
        message,
        request.path if has_request_context() else "startup",
        repr(exc),
        last_frame.filename if last_frame else "unknown",
        last_frame.lineno if last_frame else "unknown",
    )
    logger.error("Full traceback:\n%s", "".join(traceback.format_exception(type(exc), exc, tb)) if exc else "No traceback available")


def validate_startup():
    for name, path in REQUIRED_DIRECTORIES.items():
        os.makedirs(path, exist_ok=True)
        app_logger.info("Startup validation: %s folder ready at %s", name, path)

    template_root = os.path.join(BASE_DIR, "frontend", "templates")
    static_root = os.path.join(BASE_DIR, "frontend", "static")
    os.makedirs(static_root, exist_ok=True)

    missing_templates = [
        template
        for template in sorted(REQUIRED_TEMPLATES)
        if not os.path.exists(os.path.join(template_root, template))
    ]
    missing_static = [
        filename
        for filename in sorted(REQUIRED_STATIC_FILES)
        if not os.path.exists(os.path.join(static_root, filename))
    ]

    if missing_templates:
        error_logger.error("Startup validation: missing templates: %s", ", ".join(missing_templates))
    else:
        app_logger.info("Startup validation: all required templates exist")

    if missing_static:
        error_logger.error("Startup validation: missing static files: %s", ", ".join(missing_static))
    else:
        app_logger.info("Startup validation: all required static files exist")

    if app.config.get("SECRET_KEY_SOURCE") != "environment":
        security_logger.warning("SECRET_KEY is using the development fallback. Set SECRET_KEY in Render environment variables.")

    if app.config.get("RATELIMIT_STORAGE_URI") == "memory://":
        security_logger.warning("Flask-Limiter is using memory storage. Set RATELIMIT_STORAGE_URI for multi-instance production deployments.")

    init_db()
    if not os.path.exists(DB_PATH):
        error_logger.error("Startup validation: database was not created at %s", DB_PATH)
    else:
        app_logger.info("Startup validation: database ready at %s", DB_PATH)


try:
    validate_startup()
except Exception as exc:
    app_logger.error("Startup validation failed but app will continue: %s", exc)
    app_logger.error("Full traceback:\n%s", traceback.format_exc())


def initialize_firebase_admin():
    if firebase_admin._apps:
        return True
    if not os.path.exists(FIREBASE_SERVICE_ACCOUNT_PATH):
        logging.warning("Firebase service account file not found: %s", FIREBASE_SERVICE_ACCOUNT_PATH)
        return False
    try:
        cred = firebase_credentials.Certificate(FIREBASE_SERVICE_ACCOUNT_PATH)
        firebase_admin.initialize_app(cred)
        return True
    except Exception as exc:
        error_logger.error("Firebase Admin initialization failed: %s", exc)
        error_logger.error("Full traceback:\n%s", traceback.format_exc())
        return False

# ------------------------------------------------
# Fixed demo display data (NO random data, NO simulation)
# ------------------------------------------------
DEMO_USERS = {
    "Praveen": "SOC Analyst",
    "Sanjay": "Cloud Administrator",
    "Sai Nathan": "Threat Analyst",
    "Faran": "Security Engineer",
    "Kowshika": "SOC Manager",
}

# Fixed (non-random) baseline traffic pattern used for the "Live Traffic"
# demo chart. Represents packets-per-minute over a 12 minute sample window.
DEMO_TRAFFIC_PATTERN = [120, 135, 128, 150, 210, 480, 460, 300, 190, 160, 145, 130]

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
            row.get("display_name") or row.get("full_name") or row["username"],
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
    return get_demo_incidents()


def allowed_upload(filename):
    if not filename or filename != os.path.basename(filename):
        return False
    _, extension = os.path.splitext(filename.lower())
    return extension in UPLOAD_EXTENSIONS


def safe_upload_path(filename):
    cleaned = secure_filename(filename or "")
    if not cleaned or not allowed_upload(cleaned):
        return None
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    upload_root = os.path.abspath(UPLOADS_DIR)
    candidate = os.path.abspath(os.path.join(upload_root, cleaned))
    if os.path.commonpath([upload_root, candidate]) != upload_root:
        return None
    return candidate


def is_allowed_report_type(report_type):
    return report_type in {"pdf", "csv", "executive", "incident", "threat", "business"}


def get_logged_in_username():
    if current_user.is_authenticated:
        return current_user.display_name
    return session.get("username")


def get_logged_in_role():
    if current_user.is_authenticated:
        return current_user.role
    return session.get("role")


def current_username():
    if current_user.is_authenticated:
        return current_user.username
    return session.get("login_name", "anonymous")


def current_user_id():
    if current_user.is_authenticated:
        try:
            return int(current_user.id)
        except (TypeError, ValueError):
            return None
    return None


def utc_now():
    return datetime.now(UTC).replace(tzinfo=None)


def utc_timestamp():
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def user_agent():
    return (request.headers.get("User-Agent") or "unknown")[:255]


def audit_event(action, resource, detail="", status="success", username=None):
    actor = username or current_username()
    try:
        log_audit_event(
            actor,
            action,
            resource,
            detail,
            client_ip(),
            status,
            user_id=current_user_id(),
            route=request.path,
            user_agent=user_agent(),
        )
    except Exception as exc:
        error_logger.error("Audit database write failed: %s", exc)
    audit_logger.info("%s %s %s %s", actor, action, resource, status)


def api_response(success=True, message="", data=None, error=None, status_code=200):
    payload = {
        "success": success,
        "message": message,
        "data": data,
        "error": error,
    }
    return jsonify(payload), status_code


def permission_required(resource):
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapper(*args, **kwargs):
            role = get_logged_in_role()
            if not role_can_access(role, resource):
                audit_event("access_denied", resource, f"Role {role} denied", "denied")
                security_logger.warning("Access denied for role=%s resource=%s route=%s ip=%s", role, resource, request.path, client_ip())
                flash("You do not have permission to access that page.")
                return redirect(url_for("dashboard"))
            return view_func(*args, **kwargs)
        return wrapper
    return decorator


def role_required(*roles):
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapper(*args, **kwargs):
            if get_logged_in_role() not in roles:
                audit_event("role_denied", request.endpoint or "unknown", f"Required roles: {', '.join(roles)}", "denied")
                security_logger.warning("Role denied for user=%s role=%s route=%s ip=%s", current_username(), get_logged_in_role(), request.path, client_ip())
                abort(403)
            return view_func(*args, **kwargs)
        return wrapper
    return decorator


def admin_required(view_func):
    return role_required("Administrator")(view_func)


def sanitize_text(value, max_length=255):
    value = (value or "").strip()
    value = re.sub(r"[\x00-\x1f\x7f]", "", value)
    return value[:max_length]


def strong_password_policy(password):
    """Future-user policy: 12+ chars with upper, lower, digit, and symbol."""
    if not password or len(password) < 12:
        return False
    return all(
        (
            re.search(r"[A-Z]", password),
            re.search(r"[a-z]", password),
            re.search(r"\d", password),
            re.search(r"[^A-Za-z0-9]", password),
        )
    )


def is_valid_username(value):
    return bool(value) and 1 <= len(value) <= 64 and re.fullmatch(r"[A-Za-z0-9_.@-]+", value) is not None


def is_valid_password(value):
    return bool(value) and 1 <= len(value) <= 128


def is_valid_ip_address(value):
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


def prune_login_attempts(attempts):
    return [timestamp for timestamp in attempts if utc_now() - timestamp < FAILED_LOGIN_WINDOW]


def is_account_locked(username):
    if not username:
        return False
    locked_until = ACCOUNT_LOCKS.get(username.lower())
    if locked_until and utc_now() < locked_until:
        return True
    ACCOUNT_LOCKS.pop(username.lower(), None)
    return False


def is_ip_blocked(ip):
    blocked_until = IP_BLOCKS.get(ip)
    if blocked_until and utc_now() < blocked_until:
        return True
    IP_BLOCKS.pop(ip, None)
    return False


def record_failed_login(username):
    ip = client_ip()
    now = utc_now()
    username_key = (username or "unknown").lower()
    attempt_key = f"{ip}:{username_key}"

    attempts = prune_login_attempts(LOGIN_ATTEMPTS.get(attempt_key, []))
    attempts.append(now)
    LOGIN_ATTEMPTS[attempt_key] = attempts
    if len(attempts) >= 5:
        ACCOUNT_LOCKS[username_key] = now + ACCOUNT_LOCK_DURATION
        security_logger.warning("Account temporarily locked after failed login attempts: %s", username_key)

    ip_attempts = prune_login_attempts(LOGIN_IP_FAILURES.get(ip, []))
    ip_attempts.append(now)
    LOGIN_IP_FAILURES[ip] = ip_attempts
    if len(ip_attempts) >= 10:
        IP_BLOCKS[ip] = now + IP_BLOCK_DURATION
        security_logger.warning("IP temporarily blocked after brute-force attempts: %s", ip)


def clear_failed_login_state(username):
    username_key = (username or "").lower()
    ip = client_ip()
    LOGIN_ATTEMPTS.pop(f"{ip}:{username_key}", None)
    ACCOUNT_LOCKS.pop(username_key, None)


def get_csrf_token():
    return generate_csrf()


@app.context_processor
def inject_security_helpers():
    return {"csrf_token": get_csrf_token}


@app.after_request
def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com data:; "
        "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; "
        "script-src 'self' https://cdn.jsdelivr.net https://cdn.socket.io https://www.gstatic.com 'unsafe-inline'; "
        "connect-src 'self' https://cdn.socket.io https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://www.googleapis.com https://firebaseinstallations.googleapis.com ws: wss:;"
    )
    if app.config.get("ENABLE_HSTS") and request.is_secure:
        response.headers["Strict-Transport-Security"] = f"max-age={app.config['HSTS_MAX_AGE']}; includeSubDomains"
    return response


@app.before_request
def secure_request_guard():
    if request.method not in SAFE_HTTP_METHODS:
        security_logger.warning("Unsupported HTTP method %s on %s from %s", request.method, request.path, client_ip())
        abort(405)

    suspicious_patterns = ("../", "..\\", "%2e%2e", "<script", "\x00")
    target = f"{request.path}?{request.query_string.decode('utf-8', errors='ignore')}".lower()
    if any(pattern in target for pattern in suspicious_patterns):
        security_logger.warning("Suspicious request detected from %s: %s", client_ip(), request.full_path)
        if request.endpoint:
            audit_event("suspicious_request", request.endpoint, "Suspicious path or query pattern", "blocked")
        abort(400)

    if current_user.is_authenticated:
        session.permanent = True
        now = utc_now().timestamp()
        last_activity = session.get("last_activity")
        if last_activity and now - float(last_activity) > SESSION_TIMEOUT_SECONDS:
            audit_event("session_timeout", "authentication", "Session expired due to inactivity", "expired")
            logout_user()
            session.clear()
            flash("Your session expired. Please sign in again.")
            return redirect(url_for("login_page"))
        session["last_activity"] = now

    if request.endpoint in {
        "dashboard",
        "analytics",
        "reports",
        "settings",
        "profile",
        "investigate",
        "audit_logs",
        "upload_center",
        "security_status",
        "backup_database",
    }:
        security_logger.info("Sensitive route access attempt: %s %s from %s", request.method, request.path, client_ip())


# ------------------------------------------------
# Routes: Auth
# ------------------------------------------------
@app.route("/")
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "GET":
        return redirect(url_for("login_page"))

    username = (request.form.get("username", "") or "").strip()
    username = sanitize_text(username, 64)
    password = request.form.get("password", "") or ""
    remember_me = request.form.get("remember_me") == "on"

    if is_ip_blocked(client_ip()):
        audit_event("failed_login", "authentication", "IP temporarily blocked", "blocked", username=username or "unknown")
        flash("Too many failed login attempts. Please wait before trying again.")
        return redirect(url_for("login_page"))

    if is_account_locked(username):
        audit_event("failed_login", "authentication", "Account temporarily locked", "blocked", username=username or "unknown")
        flash("Too many failed login attempts. Please wait before trying again.")
        return redirect(url_for("login_page"))

    if not is_valid_username(username) or not is_valid_password(password):
        record_failed_login(username)
        audit_event("failed_login", "authentication", "Invalid login format", "failed", username=username or "unknown")
        flash("Invalid username or password.")
        return redirect(url_for("login_page"))

    user = authenticate_user(username, password)
    if user:
        user_object = User.from_row(user)
        if user_object is None:
            flash("Login failed. Please try again.")
            return redirect(url_for("login_page"))

        logout_user()
        session.clear()
        login_user(user_object, remember=remember_me)
        session.permanent = remember_me
        session["username"] = user.get("display_name") or user.get("full_name") or user["username"]
        session["role"] = user["role"]
        session["login_name"] = user["username"]
        session["remember_me"] = remember_me
        session["last_activity"] = utc_now().timestamp()
        clear_failed_login_state(user["username"])
        audit_event("login", "authentication", "User logged in", username=user["username"])
        return redirect(url_for("dashboard"))

    record_failed_login(username)
    audit_event("failed_login", "authentication", "Invalid credentials", "failed", username=username or "unknown")
    flash("Invalid username or password.")
    return redirect(url_for("login_page"))


@app.route("/firebase-login", methods=["POST"])
@csrf.exempt
@limiter.limit("20 per minute")
def firebase_login():
    data = request.get_json(silent=True) or {}
    id_token = data.get("idToken")
    provider = data.get("provider", "firebase")

    if not id_token:
        audit_event("failed_login", "authentication", "Missing Firebase ID token", "failed", username="firebase")
        return api_response(False, "Missing Firebase ID token.", error="missing_token", status_code=400)

    if not initialize_firebase_admin():
        audit_event("failed_login", "authentication", "Firebase Admin is not configured", "failed", username="firebase")
        return api_response(False, "Firebase authentication is not configured.", error="firebase_unavailable", status_code=503)

    try:
        decoded_token = firebase_auth.verify_id_token(id_token)
    except Exception as exc:
        security_logger.warning("Firebase token verification failed: %s", exc)
        audit_event("failed_login", "authentication", "Invalid Firebase token", "failed", username="firebase")
        return api_response(False, "Invalid Firebase token.", error="invalid_token", status_code=401)

    firebase_uid = decoded_token.get("uid")
    email = decoded_token.get("email")
    full_name = decoded_token.get("name") or email or "Firebase User"
    firebase_claims = decoded_token.get("firebase", {})
    provider = firebase_claims.get("sign_in_provider") or provider

    if not firebase_uid:
        return api_response(False, "Firebase token did not include a UID.", error="missing_uid", status_code=400)

    user = get_or_create_firebase_user(firebase_uid, email, full_name, provider)
    user_object = User.from_row(user)
    if user_object is None:
        return api_response(False, "Unable to create Flask session.", error="session_failed", status_code=500)

    logout_user()
    session.clear()
    login_user(user_object, remember=True)
    session.permanent = True
    session["username"] = user.get("display_name") or user.get("full_name") or user["username"]
    session["role"] = user["role"]
    session["login_name"] = user["username"]
    session["auth_provider"] = provider
    audit_event("firebase_login", "authentication", f"Firebase login via {provider}", username=user["username"])

    return jsonify({"success": True, "message": "Firebase login successful.", "data": {"redirect": url_for("dashboard")}, "error": None, "redirect": url_for("dashboard")})


@app.route("/logout")
def logout():
    audit_event("logout", "authentication", "User logged out")
    logout_user()
    session.clear()
    return redirect(url_for("login_page"))


@app.errorhandler(404)
def not_found(error):
    error_logger.info("404 %s from %s", request.path, client_ip())
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(error):
    original = getattr(error, "original_exception", None) or error
    log_exception_context(error_logger, f"500 from {client_ip()}", original)
    return render_template("500.html"), 500


@app.errorhandler(Exception)
def unhandled_exception(error):
    if isinstance(error, HTTPException):
        return error
    log_exception_context(error_logger, f"Unhandled exception from {client_ip()}", error)
    return render_template("500.html"), 500


@app.errorhandler(400)
def bad_request(error):
    error_logger.info("400 %s from %s", request.path, client_ip())
    return render_template("error.html", code=400, title="Bad Request", message="The request could not be processed safely."), 400


@app.errorhandler(401)
def unauthorized(error):
    return render_template("error.html", code=401, title="Authentication Required", message="Please sign in to continue."), 401


@app.errorhandler(403)
def forbidden(error):
    audit_event("forbidden", request.endpoint or "unknown", "Forbidden request", "denied")
    return render_template("403.html"), 403


@app.errorhandler(413)
def file_too_large(error):
    security_logger.warning("Upload too large from %s", client_ip())
    return render_template("error.html", code=413, title="Upload Too Large", message="The uploaded file exceeds the configured safety limit."), 413


@app.errorhandler(429)
def too_many_requests(error):
    security_logger.warning("Rate limit exceeded from %s on %s", client_ip(), request.path)
    return render_template("429.html"), 429


@app.errorhandler(405)
def method_not_allowed(error):
    security_logger.warning("Method not allowed: %s %s from %s", request.method, request.path, client_ip())
    return render_template("error.html", code=405, title="Method Not Allowed", message="That request method is not supported for this page."), 405


@app.errorhandler(CSRFError)
def csrf_error(error):
    audit_event("csrf_failure", request.endpoint or "unknown", "Invalid CSRF token", "failed")
    return render_template("error.html", code=400, title="Request Verification Failed", message="The request could not be verified. Please refresh and try again."), 400


# ------------------------------------------------
# Routes: Pages
# ------------------------------------------------
@app.route("/dashboard")
@permission_required("dashboard")
def dashboard():
    audit_event("dashboard_access", "dashboard", "Dashboard viewed")
    incidents = get_incidents()
    dashboard_stats = get_dashboard_stats()
    security_score = dashboard_stats["security_score"]
    risk_level = dashboard_stats["risk_level"]
    threat_score = dashboard_stats["threat_score"]
    system_health = "Healthy" if security_score >= 80 else "Degraded" if security_score >= 60 else "At Risk"
    cloud_health = "Operational" if len([i for i in incidents if i["status"] == "Blocked"]) >= 1 else "Monitoring"

    active_threats = dashboard_stats["active_threats"]
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
                "detail": f"{inc['severity']} - {inc['status']} - assigned to {inc['assigned_to']}",
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
        packets_captured=dashboard_stats["packets_captured"],
        attack_distribution=attack_distribution,
        traffic_pattern=DEMO_TRAFFIC_PATTERN,
        model_available=is_model_available(),
        executive_mode=request.args.get("view") == "executive",
        assets=get_all_assets(),
    )


@app.route("/load-demo-threats")
@permission_required("dashboard")
@limiter.limit("60 per minute")
def load_demo_threats():
    """Returns the 4 fixed demo incidents from SQLite as JSON. No random data."""
    incidents = get_incidents()
    return jsonify({
        "success": True,
        "message": "Demo threats loaded.",
        "data": {"incidents": incidents, "count": len(incidents)},
        "error": None,
        "incidents": incidents,
        "count": len(incidents),
    })


@app.route("/prediction-incidents")
@permission_required("dashboard")
@limiter.limit("60 per minute")
def prediction_incidents():
    """Returns uploaded/ML prediction incidents separately from fixed demo incidents."""
    incidents = get_prediction_incidents()
    return api_response(
        True,
        "Prediction incidents loaded.",
        {"incidents": incidents, "count": len(incidents)},
    )


@app.route("/investigate/<ip>")
@permission_required("investigation")
def investigate(ip):
    if not is_valid_ip_address(ip):
        flash("Invalid IP address provided.")
        return redirect(url_for("dashboard"))

    incidents = get_incidents()
    matching_incidents = get_incidents_by_ip(ip)
    incident = matching_incidents[0] if matching_incidents else None

    if incident is None:
        flash(f"No incident found for IP {ip}.")
        return render_template(
            "investigate.html",
            username=get_logged_in_username(),
            role=get_logged_in_role(),
            incident=None,
            reputation_data=None,
            risk_data=None,
            recommendations=[],
            timeline=[],
            ml_result=predict({}),
        )

    risk_data = calculate_risk(
        incident["attack_type"], incident["severity"], incident["confidence"]
    )
    reputation_data = get_ip_reputation(ip, incidents)
    recommendations = get_recommendations(incident["attack_type"])
    ml_result = predict({})

    timeline = get_timeline_for_incident(incident["id"])
    audit_event("threat_investigation", "investigation", f"Investigated {ip}")

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
@permission_required("analytics")
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
        model_metadata=get_model_metadata(),
        latest_model=get_latest_model_version(),
    )


@app.route("/reports")
@permission_required("reports")
def reports():
    incidents = get_incidents()
    report_history = get_all_reports()
    return render_template(
        "reports.html",
        username=get_logged_in_username(),
        role=get_logged_in_role(),
        incidents=incidents,
        reports=report_history,
    )


@app.route("/trust-center")
@permission_required("reports")
def trust_center():
    trust_badges = [
        "SSL Ready",
        "RBAC Enabled",
        "Audit Logs Enabled",
        "ML Detection Ready",
        "Privacy Aware",
    ]
    return render_template(
        "trust_center.html",
        username=get_logged_in_username(),
        role=get_logged_in_role(),
        trust_badges=trust_badges,
    )


@app.route("/upload-center", methods=["GET", "POST"])
@permission_required("upload")
@limiter.limit("12 per hour")
def upload_center():
    prediction_results = []
    uploaded_filename = None
    if request.method == "POST":
        upload = request.files.get("threat_file")
        if not upload or not upload.filename:
            audit_event("file_upload_attempt", "upload_center", "Upload missing file", "failed")
            flash("Please choose a CSV or PCAP file to upload.")
            return redirect(url_for("upload_center"))

        if not allowed_upload(upload.filename):
            audit_event("file_upload_attempt", "upload_center", "Rejected unsupported file extension", "blocked")
            flash("Only CSV, PCAP, and PCAPNG files are supported.")
            return redirect(url_for("upload_center"))

        filename = secure_filename(upload.filename)
        saved_path = safe_upload_path(filename)
        if saved_path is None:
            security_logger.warning("Rejected suspicious upload filename: %s", upload.filename)
            audit_event("file_upload_attempt", "upload_center", "Rejected suspicious filename", "blocked")
            flash("Invalid upload filename.")
            return redirect(url_for("upload_center"))

        uploaded_filename = filename
        upload.save(saved_path)
        audit_event("file_upload_attempt", "upload_center", f"Accepted {filename}")
        extension = os.path.splitext(filename.lower())[1]

        if extension == ".csv":
            prediction_results = predict_csv(saved_path)
            action = "csv_upload"
        else:
            prediction_results = predict_pcap(saved_path)
            action = "pcap_upload"

        for result in prediction_results[:5]:
            if result.get("available"):
                add_prediction_incident(
                    source_ip="0.0.0.0",
                    destination_ip="10.0.0.1",
                    attack_type=result.get("prediction", "Unknown"),
                    confidence=result.get("confidence", 80),
                )

        audit_event(action, "upload_center", f"Processed {filename} with {len(prediction_results)} prediction rows")
        flash(f"Processed {filename}. Prediction rows: {len(prediction_results)}")

    return render_template(
        "upload_center.html",
        username=get_logged_in_username(),
        role=get_logged_in_role(),
        prediction_results=prediction_results,
        uploaded_filename=uploaded_filename,
        model_available=is_model_available(),
    )


@app.route("/audit-logs")
@permission_required("audit_logs")
def audit_logs():
    logs = get_audit_logs()
    return render_template(
        "audit_logs.html",
        username=get_logged_in_username(),
        role=get_logged_in_role(),
        audit_logs=logs,
    )


@app.route("/health")
def health():
    try:
        incident_count = len(get_incidents())
        database_status = "ok" if incident_count >= 0 else "unknown"
    except Exception:
        database_status = "error"

    try:
        log_audit_event(
            "system",
            "health_check",
            "health",
            "Health check accessed",
            client_ip(),
            user_id=None,
            route=request.path,
            user_agent=user_agent(),
        )
    except Exception as exc:
        error_logger.error("Health audit write failed: %s", exc)
    return jsonify({
        "success": database_status == "ok",
        "message": "Health check complete.",
        "data": {
            "app": "ok",
            "database": database_status,
            "model": "available" if is_model_available() else "not_loaded",
            "timestamp": utc_timestamp(),
        },
        "error": None if database_status == "ok" else "database_unavailable",
    }), 200


@app.route("/security-status")
@admin_required
@limiter.limit("20 per hour")
def security_status():
    audit_event("security_status_viewed", "security_status", "Security status viewed")
    data = {
        "authentication": "enabled",
        "rbac": "enabled",
        "csrf": "enabled",
        "rate_limiting": "enabled",
        "secure_cookies": "enabled" if app.config["SESSION_COOKIE_SECURE"] else "development_mode",
        "hsts": "enabled" if app.config["ENABLE_HSTS"] else "disabled",
        "database": "ok" if os.path.exists(DB_PATH) else "missing",
        "model": "available" if is_model_available() else "not_loaded",
        "debug": bool(app.config["DEBUG"]),
        "timestamp": utc_timestamp(),
    }
    return api_response(True, "Security status loaded.", data)


@app.route("/backup-database", methods=["POST"])
@app.route("/admin/backup-db", methods=["POST"])
@admin_required
@limiter.limit("3 per hour")
def backup_database():
    os.makedirs(BACKUPS_DIR, exist_ok=True)
    if not os.path.exists(DB_PATH):
        audit_event("database_backup", "database", "Database file missing", "failed")
        return api_response(False, "Database is not available for backup.", error="database_missing", status_code=503)
    timestamp = utc_now().strftime("%Y%m%d%H%M%S")
    backup_name = f"security_platform_{timestamp}.db"
    backup_path = os.path.join(BACKUPS_DIR, backup_name)
    shutil.copy2(DB_PATH, backup_path)
    audit_event("database_backup", "database", f"Backup created: {backup_name}")
    return api_response(True, "Database backup created.", {"backup": backup_name})


@app.route("/reports/download-pdf")
@permission_required("reports")
def download_pdf_report():
    audit_event("report_generation", "reports", "PDF report generated")
    try:
        path = generate_incident_report(get_incidents())
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        return send_file(path, as_attachment=True, download_name="security_report.pdf")
    except RuntimeError as exc:
        error_logger.warning("PDF report generation unavailable: %s", exc)
        flash(str(exc))
        return redirect(url_for("reports"))
    except Exception as exc:
        error_logger.exception("PDF report generation failed: %s", exc)
        flash("Report generation is temporarily unavailable.")
        return redirect(url_for("reports"))


@app.route("/reports/download-csv")
@permission_required("reports")
def download_csv_report():
    audit_event("report_generation", "reports", "CSV report generated")
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


@app.route("/settings", methods=["GET", "POST"])
@permission_required("settings")
def settings():
    if request.method == "POST":
        setting_name = sanitize_text(request.form.get("setting_name", "security_settings"), 80)
        setting_value = sanitize_text(request.form.get("setting_value", "updated"), 120)
        audit_event("settings_changed", "settings", f"{setting_name} changed to {setting_value}")
        flash("Settings update recorded.")
        return redirect(url_for("settings"))
    return render_template("settings.html", username=get_logged_in_username(), role=get_logged_in_role())


@app.route("/profile")
@permission_required("profile")
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
    print(" Login: admin/admin or any seeded SOC team account")
    print("=" * 50)
    socketio.run(
        app,
        host="127.0.0.1",
        port=5000,
        debug=app.config["DEBUG"],
        use_reloader=app.config["DEBUG"],
    )
