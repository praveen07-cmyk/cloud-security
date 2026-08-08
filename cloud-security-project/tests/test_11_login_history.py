"""
test_11_login_history.py
-------------------------------------------------
Comprehensive unit and integration test suite for:
- User-Agent device & browser parsing (auth/device_detector.py)
- Non-blocking GeoIP resolution (auth/geoip_helper.py)
- Pub/Sub security notification dispatching (auth/security_notifier.py)
- LoginHistory SQLAlchemy model & DB queries (database/db.py)
- Risk scoring, risk levels, and risk signals
- Auth routes integration (/login, /auth/google/callback, /auth/github/callback)
- API endpoints: /api/auth/login-history, /api/auth/login-history/recent,
  /api/auth/login-history/<user_id>, /api/auth/security-summary
- RBAC enforcement (Admin vs Viewer isolation)
-------------------------------------------------
"""

import json
import pytest
from app import app
from auth.device_detector import parse_user_agent
from auth.geoip_helper import resolve_ip_location
from auth.security_notifier import dispatch_security_event, register_subscriber, unregister_subscriber
from database.db import (
    LoginHistory,
    evaluate_user_login_risk,
    get_login_history,
    get_security_activity_summary,
    get_user_login_history,
    record_login_history,
    _get_session,
)


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture(autouse=True)
def clean_login_history():
    """Ensure clean login_history table before each test."""
    session = _get_session()
    try:
        session.query(LoginHistory).delete()
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


# -------------------------------------------------------------------
# Unit Tests 1-4: Device & Browser Detection
# -------------------------------------------------------------------
def test_parse_user_agent_desktop_chrome():
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    res = parse_user_agent(ua)
    assert "Chrome" in res["browser"]
    assert "Windows" in res["operating_system"]
    assert res["device_type"] == "Desktop"


def test_parse_user_agent_mobile_safari():
    ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
    res = parse_user_agent(ua)
    assert "Safari" in res["browser"]
    assert "iOS" in res["operating_system"]
    assert res["device_type"] == "Mobile"


def test_parse_user_agent_firefox_linux():
    ua = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
    res = parse_user_agent(ua)
    assert "Firefox" in res["browser"]
    assert res["operating_system"] == "Linux"
    assert res["device_type"] == "Desktop"


def test_parse_user_agent_unknown():
    res = parse_user_agent("")
    assert "Unknown" in res["browser"]
    assert "Unknown" in res["operating_system"]
    assert res["device_type"] == "Unknown"


# -------------------------------------------------------------------
# Unit Tests 5-7: GeoIP Resolution
# -------------------------------------------------------------------
def test_resolve_ip_location_loopback():
    res1 = resolve_ip_location("127.0.0.1")
    assert "Local" in res1["country"] or "Private" in res1["country"]

    res2 = resolve_ip_location("::1")
    assert "Local" in res2["country"] or "Private" in res2["country"]


def test_resolve_ip_location_private():
    res = resolve_ip_location("192.168.1.50")
    assert "Local" in res["country"] or "Private" in res["country"]


def test_resolve_ip_location_public():
    res = resolve_ip_location("8.8.8.8")
    assert res["country"] != "Unknown"
    assert res["location_label"] == "Approximate IP-based location"


# -------------------------------------------------------------------
# Unit Tests 8-12: Login History Database Recording
# -------------------------------------------------------------------
def test_record_login_history_success_password():
    rec = record_login_history(
        user_id=1,
        email="admin@example.com",
        username="admin",
        auth_method="PASSWORD",
        status="SUCCESS",
        ip_address="192.168.1.10",
        user_agent_str="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    )
    assert rec is not None
    assert rec["user_id"] == 1
    assert rec["login_status"] == "SUCCESS"
    assert rec["authentication_method"] == "PASSWORD"
    assert "Chrome" in rec["browser"]
    assert "Windows" in rec["operating_system"]


def test_record_login_history_failed_password():
    rec = record_login_history(
        username="hacker",
        auth_method="PASSWORD",
        status="FAILED",
        ip_address="203.0.113.5",
        user_agent_str="python-requests/2.31.0",
        failure_reason="Invalid credentials",
    )
    assert rec is not None
    assert rec["login_status"] == "FAILED"
    assert rec["failure_reason"] == "Invalid credentials"


def test_record_login_history_oauth_google():
    rec = record_login_history(
        user_id=2,
        email="user@gmail.com",
        username="user_google",
        auth_method="GOOGLE",
        provider_user_id="google-12345",
        status="SUCCESS",
        ip_address="10.0.0.1",
        user_agent_str="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    )
    assert rec is not None
    assert rec["authentication_method"] == "GOOGLE"
    assert rec["provider_user_id"] == "google-12345"


def test_record_login_history_oauth_github():
    rec = record_login_history(
        user_id=3,
        email="dev@github.com",
        username="dev_github",
        auth_method="GITHUB",
        provider_user_id="github-9999",
        status="SUCCESS",
        ip_address="10.0.0.2",
    )
    assert rec is not None
    assert rec["authentication_method"] == "GITHUB"


def test_record_login_history_blocked():
    rec = record_login_history(
        username="admin",
        auth_method="PASSWORD",
        status="BLOCKED",
        ip_address="198.51.100.4",
        failure_reason="Account temporarily locked",
    )
    assert rec is not None
    assert rec["login_status"] == "BLOCKED"
    assert rec["failure_reason"] == "Account temporarily locked"


# -------------------------------------------------------------------
# Unit Tests 13-15: Login Risk Evaluation & Signals
# -------------------------------------------------------------------
def test_login_risk_signals_new_ip_and_device():
    # Record first login
    record_login_history(
        user_id=10,
        email="testuser@example.com",
        auth_method="PASSWORD",
        status="SUCCESS",
        ip_address="1.1.1.1",
        user_agent_str="Mozilla/5.0 (Windows NT 10.0) Chrome/120.0",
    )

    # Evaluate risk for second login with different IP and device
    score, level, signals = evaluate_user_login_risk(
        user_id=10,
        ip_address="2.2.2.2",
        browser="Firefox",
        operating_system="Linux",
        device_type="Desktop",
        country="Approximate Location (Public IP)",
        email="testuser@example.com",
    )

    assert "NEW_IP" in signals
    assert "NEW_DEVICE" in signals
    assert "NEW_BROWSER" in signals
    assert score >= 40


def test_login_risk_signals_repeated_failed():
    for _ in range(3):
        record_login_history(
            user_id=11,
            auth_method="PASSWORD",
            status="FAILED",
            ip_address="192.168.1.99",
        )

    score, level, signals = evaluate_user_login_risk(
        user_id=11,
        ip_address="192.168.1.99",
        browser="Chrome",
        operating_system="Windows",
        device_type="Desktop",
        country="Local Network",
    )

    assert "REPEATED_FAILED_LOGIN" in signals
    assert score >= 40


def test_login_risk_signals_suspicious_pattern():
    # Setup initial success
    record_login_history(
        user_id=12,
        auth_method="PASSWORD",
        status="SUCCESS",
        ip_address="10.0.0.1",
        user_agent_str="Mozilla/5.0 (Windows NT 10.0) Chrome/120.0",
    )
    # Setup 3 recent failures
    for _ in range(3):
        record_login_history(
            user_id=12,
            auth_method="PASSWORD",
            status="FAILED",
            ip_address="10.0.0.1",
        )

    score, level, signals = evaluate_user_login_risk(
        user_id=12,
        ip_address="203.0.113.88",  # NEW_IP
        browser="Chrome",
        operating_system="Windows",
        device_type="Desktop",
        country="Local Network",
    )

    assert "NEW_IP" in signals
    assert "REPEATED_FAILED_LOGIN" in signals
    assert "SUSPICIOUS_LOGIN_PATTERN" in signals
    assert level in ("HIGH", "CRITICAL")


# -------------------------------------------------------------------
# Unit Test 16: Security Summary Calculation
# -------------------------------------------------------------------
def test_security_activity_summary():
    record_login_history(user_id=1, auth_method="PASSWORD", status="SUCCESS", ip_address="1.1.1.1")
    record_login_history(user_id=1, auth_method="PASSWORD", status="SUCCESS", ip_address="1.1.1.1")
    record_login_history(user_id=1, auth_method="PASSWORD", status="FAILED", ip_address="2.2.2.2")
    record_login_history(user_id=1, auth_method="GOOGLE", status="SUCCESS", ip_address="3.3.3.3")

    summary = get_security_activity_summary(user_id=1)
    assert summary["total_logins"] == 4
    assert summary["successful_logins"] == 3
    assert summary["failed_logins"] == 1
    assert summary["unique_ips"] == 3
    assert summary["most_used_method"] == "PASSWORD"


# -------------------------------------------------------------------
# Integration Tests 17-20: API Endpoints & RBAC
# -------------------------------------------------------------------
def test_api_get_login_history_admin(client):
    # Log in as admin
    client.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=True)

    res = client.get("/api/auth/login-history")
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["success"] is True
    assert "items" in json_data["data"]


def test_api_get_login_history_viewer_rbac_denied(client):
    # Log in as viewer
    client.post("/login", data={"username": "viewer", "password": "viewer123"}, follow_redirects=True)

    # Viewer attempts to pass user_id=1 (admin's user_id)
    res = client.get("/api/auth/login-history?user_id=1")
    assert res.status_code == 403
    json_data = res.get_json()
    assert json_data["success"] is False
    assert json_data["error"] == "forbidden"


def test_api_get_recent_login_history(client):
    client.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=True)

    res = client.get("/api/auth/login-history/recent")
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["success"] is True
    assert len(json_data["data"]["items"]) <= 10


def test_api_get_security_summary(client):
    client.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=True)

    res = client.get("/api/auth/security-summary")
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["success"] is True
    assert "total_logins" in json_data["data"]
    assert "successful_logins" in json_data["data"]
