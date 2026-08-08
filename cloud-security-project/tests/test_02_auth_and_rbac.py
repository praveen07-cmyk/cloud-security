import os
import re
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from app import app
from database.db import authenticate_user, change_user_password, init_db, reset_user_password, role_can_access


def csrf_from(response):
    text = response.get_data(as_text=True)
    match = re.search(r'name="csrf_token" value="([^"]+)"', text)
    return match.group(1) if match else ""


def login_client(client, username="admin", password="admin"):
    page = client.get("/")
    token = csrf_from(page)
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token, "remember_me": "on"},
        follow_redirects=False,
    )


def test_09_login_success():
    init_db()
    with app.test_client() as client:
        res = login_client(client, "admin", "admin")
        assert res.status_code in (302, 303)


def test_10_login_failure_invalid_credentials():
    init_db()
    with app.test_client() as client:
        res = login_client(client, "admin", "wrongpassword")
        assert res.status_code in (302, 303)
        assert authenticate_user("admin", "wrongpassword") is None


def test_11_logout():
    with app.test_client() as client:
        login_client(client, "admin", "admin")
        res = client.get("/logout")
        assert res.status_code in (302, 303)


def test_12_password_hashing():
    from werkzeug.security import check_password_hash, generate_password_hash
    pw_hash = generate_password_hash("secret123")
    assert check_password_hash(pw_hash, "secret123") is True
    assert check_password_hash(pw_hash, "wrong") is False


def test_13_password_change_api():
    init_db()
    with app.test_client() as client:
        login_client(client, "admin", "admin")
        res = client.post("/change-password", json={"old_password": "wrong", "new_password": "newpass123!"})
        assert res.status_code == 400


def test_14_forgot_and_reset_password():
    init_db()
    with app.test_client() as client:
        res_forgot = client.post("/forgot-password", json={"username": "admin"})
        assert res_forgot.status_code == 200

        res_reset = client.post("/reset-password", json={"username": "admin", "token": "demo-reset-token-12345", "new_password": "admin"})
        assert res_reset.status_code == 200


def test_15_rbac_administrator_permissions():
    assert role_can_access("Administrator", "dashboard") is True
    assert role_can_access("Administrator", "settings") is True
    assert role_can_access("Administrator", "audit_logs") is True


def test_16_rbac_cloud_administrator_permissions():
    assert role_can_access("Cloud Administrator", "dashboard") is True
    assert role_can_access("Cloud Administrator", "settings") is True
    assert role_can_access("Cloud Administrator", "audit_logs") is False


def test_17_rbac_security_analyst_permissions():
    assert role_can_access("Security Analyst", "dashboard") is True
    assert role_can_access("Security Analyst", "investigation") is True
    assert role_can_access("Security Analyst", "settings") is False


def test_18_rbac_auditor_and_viewer_permissions():
    assert role_can_access("Auditor", "audit_logs") is True
    assert role_can_access("Auditor", "settings") is False
    assert role_can_access("Viewer", "dashboard") is True
    assert role_can_access("Viewer", "upload") is False
