import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from app import app
from database.db import init_db


def test_01_flask_app_starts_without_errors():
    assert app is not None
    assert app.name == "app"


def test_02_app_imports_successfully():
    import app as main_app
    assert hasattr(main_app, "app")


def test_03_configuration_loads_correctly():
    assert app.config["SECRET_KEY"] is not None
    assert "PERMANENT_SESSION_LIFETIME" in app.config


def test_04_health_endpoint_working():
    with app.test_client() as client:
        res = client.get("/health")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["data"]["app"] == "ok"


def test_05_ready_endpoint_working():
    with app.test_client() as client:
        res = client.get("/ready")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["data"]["app"] == "ready"


def test_06_logging_initialized():
    from logging_config import setup_logging
    loggers = setup_logging(BASE_DIR)
    assert "app" in loggers
    assert "security" in loggers
    assert "audit" in loggers
    assert "error" in loggers


def test_07_error_handlers_implemented():
    with app.test_client() as client:
        res = client.get("/non-existent-page-12345")
        assert res.status_code == 404


def test_08_production_configuration_available():
    from config import Config
    assert hasattr(Config, "DEBUG")
    assert hasattr(Config, "ENABLE_HSTS")
