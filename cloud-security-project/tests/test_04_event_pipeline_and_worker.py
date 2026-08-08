import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from analytics.aws_engine import BackgroundWorker
from app import app


def test_29_worker_start():
    status = BackgroundWorker.start()
    assert status["status"] == "RUNNING"


def test_30_worker_heartbeat_and_metrics():
    status = BackgroundWorker.get_status()
    assert status["status"] == "RUNNING"
    assert "processed_count" in status
    assert "dlq_depth" in status


def test_31_worker_stop():
    status = BackgroundWorker.stop()
    assert status["status"] == "STOPPED"


def test_32_worker_status_api():
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")
        res = client.get("/api/worker/status")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True


def test_33_worker_start_stop_api():
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")

        res_start = client.post("/api/worker/start")
        assert res_start.status_code == 200
        assert res_start.get_json()["data"]["status"] == "RUNNING"

        res_stop = client.post("/api/worker/stop")
        assert res_stop.status_code == 200
        assert res_stop.get_json()["data"]["status"] == "STOPPED"


def test_34_event_pipeline_stages_verified():
    from analytics.cais_engine import evaluate_rules
    event = {"event_name": "Root Login", "source_ip": "192.168.1.100"}
    triggered = evaluate_rules(event)
    assert len(triggered) >= 1
    assert triggered[0]["rule_id"] == "RULE-AWS-001"


def test_35_queue_polling_and_dlq():
    status = BackgroundWorker.get_status()
    assert "queue_depth" in status
    assert "dlq_depth" in status


def test_36_worker_graceful_shutdown():
    status = BackgroundWorker.get_status()
    assert status["graceful_shutdown"] is True
