import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from analytics.cais_engine import (
    analyze_security_brain,
    calculate_cais_score,
    evaluate_rules,
    get_mitre_mapping,
)
from app import app
from ml.predict import is_model_available, predict


def test_37_random_forest_model_loads():
    assert is_model_available() is True


def test_38_random_forest_prediction():
    features = {
        "Source Port": 443,
        "Destination Port": 80,
        "Protocol": 6,
        "Flow Duration": 1000,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 5,
        "Total Length of Fwd Packets": 500,
        "Total Length of Bwd Packets": 200,
    }
    result = predict(features)
    assert result["available"] is True
    assert result["prediction"] in ("BENIGN", "DDoS", "PortScan", "Brute Force", "SQL Injection")
    assert result["confidence"] > 0


def test_39_rule_engine_root_login():
    triggered = evaluate_rules({"event_name": "Root Login"})
    assert any(t["rule_id"] == "RULE-AWS-001" for t in triggered)


def test_40_rule_engine_mfa_disabled():
    triggered = evaluate_rules({"event_name": "MFA Disabled"})
    assert any(t["rule_id"] == "RULE-AWS-002" for t in triggered)


def test_41_rule_engine_iam_policy_change():
    triggered = evaluate_rules({"event_name": "IAM Policy Change"})
    assert any(t["rule_id"] == "RULE-AWS-003" for t in triggered)


def test_42_rule_engine_public_s3_and_sg_open():
    triggered_s3 = evaluate_rules({"event_name": "Public S3"})
    assert any(t["rule_id"] == "RULE-AWS-004" for t in triggered_s3)

    triggered_sg = evaluate_rules({"event_name": "Security Group Open"})
    assert any(t["rule_id"] == "RULE-AWS-005" for t in triggered_sg)


def test_43_cais_engine_score_calculation():
    res = calculate_cais_score(incident_severity="Critical", asset_criticality="Critical")
    assert 0 <= res["cais_score"] <= 100
    assert res["risk_category"] in ("Critical Risk", "High Risk")


def test_44_mitre_attck_mapping():
    mapping = get_mitre_mapping("Brute Force")
    assert mapping["primary_match"]["tactic"] == "Initial Access"
    assert mapping["primary_match"]["attack_id"] == "T1078.004"


def test_45_ai_security_brain_synthesis():
    incident = {
        "id": 1,
        "attack_type": "Brute Force",
        "severity": "Critical",
        "source_ip": "192.168.1.45",
        "confidence": 98,
    }
    brain = analyze_security_brain(incident)
    assert "explanation" in brain
    assert "root_cause" in brain
    assert "mitre_mapping" in brain
    assert "cais_analysis" in brain
    assert len(brain["recommendations"]) >= 3


def test_46_api_cais_and_mitre_endpoints():
    with app.test_client() as client:
        from tests.test_02_auth_and_rbac import login_client
        login_client(client, "admin", "admin")

        res_cais = client.post("/api/cais/score", json={"severity": "High", "criticality": "High"})
        assert res_cais.status_code == 200
        assert res_cais.get_json()["success"] is True

        res_mitre = client.get("/api/mitre/mapping?attack_type=DDoS")
        assert res_mitre.status_code == 200
        assert res_mitre.get_json()["success"] is True
