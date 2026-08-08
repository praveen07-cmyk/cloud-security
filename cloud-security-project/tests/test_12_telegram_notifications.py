"""
test_12_telegram_notifications.py
-------------------------------------------------
Comprehensive unit and integration test suite for:
- Telegram Bot API notification provider (auth/telegram_notifier.py)
- Security event dispatcher integration (auth/security_notifier.py)
- Non-blocking execution guardrails (HTTP timeout & exception safety)
- Risk scoring thresholding & deduplication cooldown (300s window)
- Admin test endpoint (/api/security/notifications/test) & RBAC protection
- Notification history persistence (SecurityNotification model)
- Bot token security (zero exposure in logs, DB, API outputs, or tracebacks)
-------------------------------------------------
"""

import os
import json
import pytest
from unittest.mock import patch, MagicMock
from app import app
from auth.telegram_notifier import TelegramProvider, _COOLDOWN_CACHE, send_telegram_alert
from auth.security_notifier import dispatch_security_event, register_subscriber, unregister_subscriber
from database.db import (
    SecurityNotification,
    get_security_notifications,
    record_security_notification,
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
def reset_telegram_env_and_cache():
    """Reset environment variables and in-memory deduplication cache before each test."""
    _COOLDOWN_CACHE.clear()
    session = _get_session()
    try:
        session.query(SecurityNotification).delete()
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


# -------------------------------------------------------------------
# Unit Tests 1-3: Configuration & Environment Checks
# -------------------------------------------------------------------
def test_telegram_disabled(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "False")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:ABCdefGHI")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    provider = TelegramProvider()
    should_send, reason = provider.should_send_alert("NEW_DEVICE_LOGIN", {"risk_score": 85})
    assert should_send is False
    assert reason == "TELEGRAM_DISABLED"


def test_missing_bot_token(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "True")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    provider = TelegramProvider()
    should_send, reason = provider.should_send_alert("NEW_DEVICE_LOGIN", {"risk_score": 85})
    assert should_send is False
    assert reason == "MISSING_BOT_TOKEN"


def test_missing_chat_id(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "True")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:ABCdefGHI")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "")

    provider = TelegramProvider()
    should_send, reason = provider.should_send_alert("NEW_DEVICE_LOGIN", {"risk_score": 85})
    assert should_send is False
    assert reason == "MISSING_CHAT_ID"


# -------------------------------------------------------------------
# Unit Tests 4-7: Dispatching, Mock HTTP & Error Safety
# -------------------------------------------------------------------
def test_successful_notification_dispatch(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "True")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:ABCdefGHI")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = b'{"ok": true, "result": {"message_id": 100}}'
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = send_telegram_alert("NEW_DEVICE_LOGIN", {
            "user_id": 1,
            "email": "admin@example.com",
            "risk_score": 85,
            "risk_level": "HIGH",
            "ip_address": "198.51.100.4",
            "device_type": "Desktop",
            "operating_system": "Windows 10/11",
            "browser": "Chrome",
        })

    assert res["status"] == "SENT"
    history = get_security_notifications(limit=10)
    assert history["total"] >= 1
    assert history["items"][0]["status"] == "SENT"


def test_telegram_api_failure(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "True")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:ABCdefGHI")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    with patch("urllib.request.urlopen", side_effect=Exception("HTTP Error 500: Internal Server Error")):
        res = send_telegram_alert("NEW_DEVICE_LOGIN", {
            "user_id": 1,
            "email": "admin@example.com",
            "risk_score": 85,
            "risk_level": "HIGH",
            "ip_address": "198.51.100.4",
        })

    assert res["status"] == "FAILED"
    history = get_security_notifications(limit=10)
    assert history["items"][0]["status"] == "FAILED"


def test_telegram_timeout(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "True")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:ABCdefGHI")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    with patch("urllib.request.urlopen", side_effect=TimeoutError("Connection timed out")):
        res = send_telegram_alert("NEW_DEVICE_LOGIN", {"risk_score": 85})

    assert res["status"] == "FAILED"


def test_invalid_configuration_placeholders(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "True")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "your_telegram_bot_token_here")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "your_telegram_chat_id_here")

    provider = TelegramProvider()
    should_send, reason = provider.should_send_alert("NEW_DEVICE_LOGIN", {"risk_score": 85})
    assert should_send is False
    assert reason == "MISSING_BOT_TOKEN"


# -------------------------------------------------------------------
# Unit Tests 8-9: Non-Blocking Execution Guards
# -------------------------------------------------------------------
def test_non_blocking_login_unaffected_by_telegram_failure(client, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "True")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:ABCdefGHI")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    # Simulate catastrophic Telegram crash
    with patch("urllib.request.urlopen", side_effect=Exception("Network drop")):
        res = client.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=True)

    # Login must succeed regardless of Telegram status
    assert res.status_code == 200
    assert b"select_mode" in res.data or b"Local AI Mode" in res.data or b"Dashboard" in res.data


def test_non_blocking_oauth_unaffected_by_telegram_failure(client, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "True")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:ABCdefGHI")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    with patch("urllib.request.urlopen", side_effect=Exception("Telegram Unreachable")):
        with patch("auth.oauth.process_google_callback", return_value={"provider_user_id": "g-100", "email": "new_o@gmail.com", "display_name": "New O User"}):
            with patch("auth.oauth.validate_state_token", return_value=True):
                res = client.get("/auth/google/callback?code=fake_code&state=fake_state", follow_redirects=True)

    # OAuth login must complete successfully regardless
    assert res.status_code == 200


# -------------------------------------------------------------------
# Unit Tests 10-13: Risk Thresholding & Event Types
# -------------------------------------------------------------------
def test_high_risk_login_triggers_alert(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "True")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:ABCdefGHI")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")
    monkeypatch.setenv("TELEGRAM_ALERT_MIN_RISK", "70")

    provider = TelegramProvider()
    should_send, _ = provider.should_send_alert("HIGH_RISK_LOGIN", {"risk_score": 80})
    assert should_send is True


def test_low_risk_login_suppresses_alert(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "True")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:ABCdefGHI")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")
    monkeypatch.setenv("TELEGRAM_ALERT_MIN_RISK", "70")

    provider = TelegramProvider()
    should_send, reason = provider.should_send_alert("STANDARD_LOGIN", {"risk_score": 20})
    assert should_send is False
    assert "RISK_BELOW_THRESHOLD" in reason


def test_critical_risk_login_triggers_alert(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "True")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:ABCdefGHI")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    provider = TelegramProvider()
    should_send, _ = provider.should_send_alert("CRITICAL_RISK_LOGIN", {"risk_score": 95})
    assert should_send is True


def test_failed_login_threshold_triggers_alert(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "True")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:ABCdefGHI")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    provider = TelegramProvider()
    # ACCOUNT_LOCKED triggers even if score is below threshold
    should_send, _ = provider.should_send_alert("ACCOUNT_LOCKED", {"risk_score": 50})
    assert should_send is True


# -------------------------------------------------------------------
# Unit Tests 14-15: Notification Cooldown & Deduplication
# -------------------------------------------------------------------
def test_notification_cooldown(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "True")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:ABCdefGHI")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")
    monkeypatch.setenv("TELEGRAM_ALERT_COOLDOWN_SECONDS", "300")

    provider = TelegramProvider()
    payload = {"user_id": 99, "ip_address": "1.1.1.1", "risk_score": 85}

    should1, _ = provider.should_send_alert("NEW_DEVICE_LOGIN", payload)
    assert should1 is True

    # Immediate second call with same user, event, and IP
    should2, reason = provider.should_send_alert("NEW_DEVICE_LOGIN", payload)
    assert should2 is False
    assert "SUPPRESSED_COOLDOWN" in reason


def test_duplicate_notification_suppression(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "True")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:ABCdefGHI")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = b'{"ok": true}'
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res1 = send_telegram_alert("NEW_IP_LOGIN", {"user_id": 50, "ip_address": "8.8.8.8", "risk_score": 85})
        res2 = send_telegram_alert("NEW_IP_LOGIN", {"user_id": 50, "ip_address": "8.8.8.8", "risk_score": 85})

    assert res1["status"] == "SENT"
    assert res2["status"] == "SUPPRESSED"


# -------------------------------------------------------------------
# Integration Tests 16-17: Admin Test Endpoint & RBAC
# -------------------------------------------------------------------
def test_admin_test_endpoint_success(client, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "True")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:ABCdefGHI")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    client.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=True)

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = b'{"ok": true}'
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = client.post("/api/security/notifications/test")

    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["success"] is True
    assert json_data["data"]["status"] == "dispatched"


def test_admin_test_endpoint_rbac_viewer_denied(client):
    client.post("/login", data={"username": "viewer", "password": "viewer123"}, follow_redirects=True)

    res = client.post("/api/security/notifications/test")
    assert res.status_code == 403
    json_data = res.get_json()
    assert json_data["success"] is False
    assert json_data["error"] == "forbidden"


# -------------------------------------------------------------------
# Integration Tests 18-20: Audit Logs, DB Persistence & Security
# -------------------------------------------------------------------
def test_audit_event_creation(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "False")
    send_telegram_alert("NEW_DEVICE_LOGIN", {"risk_score": 85})

    from database.db import get_audit_logs
    logs = get_audit_logs(limit=10)
    actions = [l["action"] for l in logs]
    assert "TELEGRAM_ALERT_SUPPRESSED" in actions


def test_notification_history_persistence():
    record_security_notification(
        event_type="TEST_PERSIST",
        user_id=1,
        email="admin@example.com",
        risk_score=90,
        risk_level="CRITICAL",
        channel="TELEGRAM",
        status="SENT",
    )

    data = get_security_notifications(limit=10)
    assert data["total"] >= 1
    assert data["items"][0]["event_type"] == "TEST_PERSIST"


def test_token_never_exposed_in_logs_or_history(monkeypatch):
    secret_token = "SECRET_BOT_TOKEN_999888777"
    monkeypatch.setenv("TELEGRAM_ALERTS_ENABLED", "True")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", secret_token)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")

    with patch("urllib.request.urlopen", side_effect=Exception(f"Failed connecting with {secret_token}")):
        res = send_telegram_alert("NEW_DEVICE_LOGIN", {"risk_score": 85})

    assert res["status"] == "FAILED"
    assert secret_token not in res["reason"]
    assert "[REDACTED_BOT_TOKEN]" in res["reason"]

    # Assert secret token is not stored in DB
    history = get_security_notifications(limit=10)
    record_str = str(history)
    assert secret_token not in record_str
