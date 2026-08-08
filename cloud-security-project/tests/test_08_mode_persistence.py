import os
import sys
import pytest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from analytics.aws_engine import AWSModeManager, BackgroundWorker
from app import app
from database.db import DB_PATH, init_db, get_system_setting, set_system_setting, get_audit_logs

@pytest.fixture(autouse=True)
def setup_database():
    init_db()
    # Reset to default
    AWSModeManager.set_mode("Local AI Mode")
    yield

def test_default_local_ai_mode_persists():
    # After init, it should be Local AI Mode
    mode = get_system_setting("aws_mode", "Local AI Mode")
    assert mode == "Local AI Mode"
    assert AWSModeManager.get_mode() == "Local AI Mode"
    
def test_local_survives_restart():
    # Simulate restart
    AWSModeManager.set_mode("Local AI Mode")
    
    # Change memory state forcefully
    AWSModeManager._mode = "Unknown"
    
    # Initialize on startup
    AWSModeManager.initialize_on_startup()
    
    assert AWSModeManager.get_mode() == "Local AI Mode"
    assert get_system_setting("aws_mode") == "Local AI Mode"
    assert get_system_setting("aws_connection_state") == "DISCONNECTED"

@patch('analytics.aws_engine.AWSModeManager.validate_live_mode')
@patch('analytics.aws_engine.BackgroundWorker.start')
def test_live_mode_survives_restart_after_revalidation(mock_start, mock_validate):
    # Setup live mode in DB
    set_system_setting("aws_mode", "Live AWS Mode")
    
    # Mock validate to succeed
    mock_validate.return_value = (True, None, {})
    
    AWSModeManager.initialize_on_startup()
    
    assert AWSModeManager.get_mode() == "Live AWS Mode"
    assert get_system_setting("aws_connection_state") == "CONNECTED"
    mock_start.assert_called_once()
    
    # Audit log should be created
    logs = get_audit_logs()
    found = any(log["action"] == "startup_recovery" and "Restored Live AWS Mode" in log["details"] for log in logs)
    assert found is True

@patch('analytics.aws_engine.AWSModeManager.validate_live_mode')
@patch('analytics.aws_engine.BackgroundWorker.stop')
def test_failed_live_recovery_falls_back_safely(mock_stop, mock_validate):
    # Setup live mode in DB
    set_system_setting("aws_mode", "Live AWS Mode")
    set_system_setting("aws_worker_pid", "12345")
    
    # Mock validate to fail
    mock_validate.return_value = (False, "STS Failed", {})
    
    AWSModeManager.initialize_on_startup()
    
    # Should fall back to Local AI Mode
    assert AWSModeManager.get_mode() == "Local AI Mode"
    assert get_system_setting("aws_mode") == "Local AI Mode"
    assert get_system_setting("aws_connection_state") == "ERROR"
    assert get_system_setting("aws_last_error") == "STS Failed"
    
    # Audit log should record fallback
    logs = get_audit_logs()
    found = any(log["action"] == "startup_recovery" and "Falling back to Local AI Mode" in log["details"] for log in logs)
    assert found is True

@patch('analytics.aws_engine.BackgroundWorker._worker_loop')
def test_stale_pid_is_cleared(mock_loop):
    # Start worker manually
    BackgroundWorker.start()
    pid = get_system_setting("aws_worker_pid")
    assert pid is not None and pid != ""
    
    # Stop worker
    BackgroundWorker.stop()
    new_pid = get_system_setting("aws_worker_pid")
    assert new_pid == ""

@patch('analytics.aws_engine.AWSModeManager.validate_live_mode')
def test_duplicate_worker_prevented(mock_validate):
    mock_validate.return_value = (True, None, {})
    
    AWSModeManager.set_mode("Live AWS Mode")
    pid1 = get_system_setting("aws_worker_pid")
    
    # Try calling start again directly
    BackgroundWorker.start()
    pid2 = get_system_setting("aws_worker_pid")
    
    assert pid1 == pid2 # Worker ID should be identical, no new thread started
    
    AWSModeManager.set_mode("Local AI Mode")

@patch('analytics.aws_engine.AWSModeManager.validate_live_mode')
@patch('app.socketio.emit')
def test_socket_io_mode_changed_emitted(mock_emit, mock_validate):
    mock_validate.return_value = (True, None, {})
    
    AWSModeManager.set_mode("Live AWS Mode")
    
    mock_emit.assert_called_with("mode_changed", AWSModeManager.get_status())
    AWSModeManager.set_mode("Local AI Mode")

def test_db_mode_and_memory_cache_stay_synchronized():
    AWSModeManager.set_mode("Local AI Mode")
    assert AWSModeManager.get_mode() == "Local AI Mode"
    assert get_system_setting("aws_mode") == "Local AI Mode"

def test_unauthorized_user_cannot_change_mode():
    with app.test_client() as client:
        # User without correct role
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "viewer", "viewer123")
        
        # We need a valid CSRF token, but since we ignore it in test by patching or other ways,
        # let's just make the request. The decorator will catch RBAC.
        res = client.post("/select_mode", data={"mode": "Live AWS Mode", "csrf_token": "ignore"})
        
        # 302 redirect usually back to dashboard or same page when unauthorized in this app
        assert res.status_code == 302
        assert AWSModeManager.get_mode() == "Local AI Mode"
