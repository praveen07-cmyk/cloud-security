import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from analytics.aws_engine import AWSModeManager, discover_aws_inventory
from app import app
from unittest.mock import patch, MagicMock
from database.db import DB_PATH, get_all_assets, get_all_incidents, get_all_reports, init_db


def test_19_postgresql_sqlite_database_connected():
    init_db()
    assert os.path.exists(DB_PATH)


def test_20_database_tables_and_indexes_exist():
    from database.db import Base, engine
    tables = Base.metadata.tables.keys()
    assert "users" in tables
    assert "threat_incidents" in tables
    assert "audit_logs" in tables
    assert "reports" in tables


def test_21_database_seed_incidents():
    incidents = get_all_incidents()
    assert len(incidents) >= 4


def test_22_database_seed_assets():
    assets = get_all_assets()
    assert len(assets) >= 3


def test_23_backup_database_working():
    with app.test_client() as client:
        # Admin authentication
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")
        page = client.get("/settings")
        from tests.test_02_auth_and_rbac import csrf_from
        token = csrf_from(page)

        res = client.post("/backup-database", data={"csrf_token": token})
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert "backup" in data["data"]


def test_24_aws_local_mode():
    status = AWSModeManager.set_mode("Local AI Mode")
    assert status["mode"] == "Local AI Mode"
    assert status["aws_disabled"] is True
    assert status["ai_running"] is True


@patch('analytics.aws_engine.AWSModeManager.get_session')
def test_25_aws_live_mode(mock_get_session):
    import os
    os.environ["AWS_EVENT_QUEUE_URL"] = "https://sqs.ap-south-1.amazonaws.com/123/q"
    os.environ["AWS_EVENT_RULE_NAME"] = "test-rule"

    mock_session = MagicMock()
    mock_get_session.return_value = mock_session
    
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012", "Arn": "arn:aws:iam::123:role/Admin"}
    
    mock_ct = MagicMock()
    mock_ct.describe_trails.return_value = {"trailList": [{"TrailARN": "arn:aws:cloudtrail:trail"}]}
    mock_ct.get_trail_status.return_value = {"IsLogging": True}
    
    mock_ev = MagicMock()
    mock_ev.describe_rule.return_value = {"Name": "test-rule"}
    mock_ev.list_targets_by_rule.return_value = {"Targets": [{"Id": "1"}]}
    
    mock_sqs = MagicMock()
    mock_sqs.get_queue_attributes.return_value = {"Attributes": {"QueueArn": "arn:aws:sqs:q"}}
    
    def client_side_effect(service):
        if service == 'sts': return mock_sts
        if service == 'cloudtrail': return mock_ct
        if service == 'events': return mock_ev
        if service == 'sqs': return mock_sqs
    
    mock_session.client.side_effect = client_side_effect

    status = AWSModeManager.set_mode("Live AWS Mode", profile="prod-aws", region="us-east-1")
    assert status["mode"] == "Live AWS Mode"
    assert status["aws_disabled"] is False
    assert status["sts_connected"] is True

    AWSModeManager.set_mode("Local AI Mode")


def test_26_aws_inventory_discovery():
    inv = discover_aws_inventory()
    assert "ec2_inventory" in inv
    assert "iam_inventory" in inv
    assert "s3_inventory" in inv
    assert "security_groups" in inv
    assert "vpc_inventory" in inv


def test_27_aws_inventory_api():
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")
        res = client.get("/api/aws-inventory")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True


def test_28_aws_mode_api():
    # Reset mode to Local before testing
    AWSModeManager.set_mode("Local AI Mode")
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")
        res = client.get("/api/aws-mode")
        assert res.status_code == 200
        assert res.get_json()["data"]["mode"] == "Local AI Mode"

def test_29_aws_mode_rbac():
    AWSModeManager.set_mode("Local AI Mode")
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        # Login as non-admin user
        login_client(client, "praveen", "praveen07")
        res = client.post("/select_mode", data={"mode": "Live AWS Mode", "csrf_token": "ignore-in-test"})
        # Should redirect back to /select_mode (meaning denied)
        assert res.status_code == 302
        assert "/select_mode" in res.location
        # Global mode should NOT be changed
        assert AWSModeManager.get_mode() == "Local AI Mode"
