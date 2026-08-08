import io
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from app import app, socketio
from database.db import get_audit_logs, init_db, log_audit_event


def test_53_api_runtime_status():
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")
        res = client.get("/api/status")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["data"]["runtime"] == "running"


def test_54_api_diagnostics():
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")
        res = client.get("/api/diagnostics")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["data"]["tables_count"] == 42


def test_55_api_dashboard_summary():
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")
        res = client.get("/api/dashboard-summary")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert "security_score" in data["data"]


def test_56_socketio_connection_handler():
    client = socketio.test_client(app)
    assert client.is_connected()
    received = client.get_received()
    assert len(received) >= 1
    assert received[0]["name"] == "incidents_update"
    client.disconnect()


def test_57_pdf_report_generation_download():
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")
        res = client.get("/reports/download-pdf")
        assert res.status_code == 200
        assert res.mimetype == "application/pdf"


def test_58_csv_report_generation_download():
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")
        res = client.get("/reports/download-csv")
        assert res.status_code == 200
        assert res.mimetype == "text/csv"


def test_59_api_reports_json():
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")
        res = client.get("/api/reports/json")
        assert res.status_code == 200
        assert "incidents" in res.get_json()["data"]


def test_60_api_reports_compliance():
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")
        res = client.get("/api/reports/compliance")
        assert res.status_code == 200
        data = res.get_json()
        assert data["data"]["compliance_score"] >= 90


def test_61_audit_logging_recording():
    init_db()
    log_audit_event("unit_test_user", "test_action", "test_resource", "test_detail", "127.0.0.1")
    logs = get_audit_logs()
    assert len(logs) > 0
    assert any(l["username"] == "unit_test_user" for l in logs)


def test_62_security_headers_enforcement():
    with app.test_client() as client:
        res = client.get("/health")
        assert res.headers.get("X-Frame-Options") == "DENY"
        assert res.headers.get("X-Content-Type-Options") == "nosniff"
        assert "Content-Security-Policy" in res.headers


def test_63_file_upload_center_validation():
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")
        page = client.get("/upload-center")
        from tests.test_02_auth_and_rbac import csrf_from
        token = csrf_from(page)

        # Upload a sample csv file
        csv_data = (io.BytesIO(b"Source Port,Destination Port,Protocol,Flow Duration,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets,Label\n443,80,6,100,5,5,200,200,DDoS\n"), "test_threat.csv")
        res = client.post("/upload-center", data={"threat_file": csv_data, "csrf_token": token}, content_type="multipart/form-data")
        assert res.status_code == 200


def test_64_production_readiness_scorecard():
    from config import Config
    assert Config.DEBUG in (True, False)
    assert len(Config.SECRET_KEY) > 8
