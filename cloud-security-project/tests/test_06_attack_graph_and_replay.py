import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from analytics.cais_engine import generate_attack_graph, generate_attack_replay
from analytics.ip_reputation import get_ip_reputation
from app import app
from database.db import get_all_incidents


def test_47_attack_graph_generation():
    graph = generate_attack_graph()
    assert "nodes" in graph
    assert "edges" in graph
    assert len(graph["nodes"]) >= 4
    assert len(graph["edges"]) >= 3


def test_48_attack_replay_timeline_playback():
    replay = generate_attack_replay()
    assert replay["total_steps"] >= 4
    assert len(replay["replay_steps"]) >= 4
    assert "controls" in replay


def test_49_threat_intelligence_geoip_and_reputation():
    incidents = get_all_incidents()
    rep = get_ip_reputation("192.168.1.45", incidents)
    assert rep["ip_address"] == "192.168.1.45"
    assert rep["reputation"] in ("Dangerous", "Suspicious", "Unknown")
    assert "country" in rep


def test_50_api_attack_graph():
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")
        res = client.get("/api/attack-graph")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert "nodes" in data["data"]


def test_51_api_attack_replay():
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")
        res = client.get("/api/attack-replay")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert "replay_steps" in data["data"]


def test_52_api_incident_correlate():
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")
        res = client.get("/api/incident/correlate")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert "cais_analysis" in data["data"]
