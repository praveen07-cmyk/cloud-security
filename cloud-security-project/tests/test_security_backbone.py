import os
import re
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from app import app
from database.db import authenticate_user, get_all_incidents, init_db


def csrf_from(response):
    text = response.get_data(as_text=True)
    match = re.search(r'name="csrf_token" value="([^"]+)"', text)
    return match.group(1) if match else ""


def login(client, username="admin", password="admin"):
    page = client.get("/")
    token = csrf_from(page)
    return client.post(
        "/login",
        data={"username": username, "password": password, "remember_me": "on", "csrf_token": token},
        follow_redirects=False,
    )


def test_login_success():
    init_db()
    with app.test_client() as client:
        response = login(client)
        assert response.status_code in (302, 303)


def test_login_failure():
    init_db()
    with app.test_client() as client:
        response = login(client, "admin", "wrong")
        assert response.status_code in (302, 303)
        assert authenticate_user("admin", "wrong") is None


def test_protected_route_redirect():
    with app.test_client() as client:
        response = client.get("/dashboard")
        assert response.status_code in (302, 401)


def test_role_access_denied_for_audit_logs():
    with app.test_client() as client:
        login(client, "praveen", "praveen123")
        response = client.get("/audit-logs", follow_redirects=False)
        assert response.status_code in (302, 403)


def test_load_demo_threats_after_login():
    with app.test_client() as client:
        login(client)
        response = client.get("/load-demo-threats")
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["success"] is True
        assert len(payload["incidents"]) >= 4


def test_investigate_valid_ip():
    with app.test_client() as client:
        login(client)
        response = client.get("/investigate/192.168.1.45")
        assert response.status_code == 200


def test_investigate_invalid_ip_redirects():
    with app.test_client() as client:
        login(client)
        response = client.get("/investigate/not-an-ip")
        assert response.status_code in (302, 303)


def test_health_check():
    response = app.test_client().get("/health")
    assert response.status_code == 200
    assert response.get_json()["success"] in (True, False)


def test_security_status_admin_only():
    with app.test_client() as client:
        login(client, "praveen", "praveen123")
        denied = client.get("/security-status", follow_redirects=False)
        assert denied.status_code in (302, 403)

    with app.test_client() as client:
        login(client)
        allowed = client.get("/security-status")
        assert allowed.status_code == 200
        assert allowed.get_json()["success"] is True


def test_backup_database_admin_only():
    with app.test_client() as client:
        login(client, "praveen", "praveen123")
        denied = client.post("/backup-database", follow_redirects=False)
        assert denied.status_code in (302, 403)


def test_database_initializes():
    init_db()
    assert len(get_all_incidents()) >= 4
