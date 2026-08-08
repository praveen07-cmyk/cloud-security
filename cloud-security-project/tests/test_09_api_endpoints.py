"""
test_09_api_endpoints.py
------------------------------------------------
Comprehensive tests for Section 21 REST API endpoints:
AWS, Dashboard, Alerts, Incidents, Blast Radius, Risk, Reports, and Response Action Guardrails.
"""

import pytest
import json
from app import app
from database.db import init_db
from tests.test_02_auth_and_rbac import login_client

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    init_db()
    with app.test_client() as client:
        login_client(client, "admin", "admin")
        yield client

def test_api_aws_status(client):
    res = client.get('/api/aws/status')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'aws_connected' in data['data']
    assert 'services' in data['data']

def test_api_aws_sync(client):
    res = client.post('/api/aws/sync')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'ec2_inventory' in data['data']

def test_api_aws_resources(client):
    res = client.get('/api/aws/resources')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'resources' in data['data']

def test_api_aws_cloudtrail_status(client):
    res = client.get('/api/aws/cloudtrail/status')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['data']['trail_name'] == 'cloudsec-trail'

def test_api_dashboard_summary(client):
    res = client.get('/api/dashboard/summary')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'security_score' in data['data']

def test_api_dashboard_threats(client):
    res = client.get('/api/dashboard/threats')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'incidents' in data['data']

def test_api_dashboard_timeline(client):
    res = client.get('/api/dashboard/timeline')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'replay_steps' in data['data']

def test_api_dashboard_security_score(client):
    res = client.get('/api/dashboard/security-score')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'security_score' in data['data']

def test_api_alerts(client):
    res = client.get('/api/alerts')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'alerts' in data['data']

def test_api_alert_detail(client):
    res = client.get('/api/alerts/1')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['data']['alert_id'] == 1

def test_api_incidents_list(client):
    res = client.get('/api/incidents')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'incidents' in data['data']

def test_api_incident_detail(client):
    res = client.get('/api/incidents/1')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'id' in data['data']

def test_api_update_incident_status(client):
    res = client.patch('/api/incidents/1/status', json={'status': 'RESOLVED'})
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['data']['status'] == 'RESOLVED'

def test_api_incident_timeline(client):
    res = client.get('/api/incidents/1/timeline')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'timeline' in data['data']

def test_api_incident_attack_path(client):
    res = client.get('/api/incidents/1/attack-path')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'nodes' in data['data']

def test_api_incident_blast_radius(client):
    res = client.get('/api/incidents/1/blast-radius')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'directly_affected_resources' in data['data']

def test_api_incident_risk(client):
    res = client.get('/api/incidents/1/risk')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'cais_score' in data['data']

def test_api_create_report(client):
    res = client.post('/api/reports', json={'name': 'Q3 Audit Report'})
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'report_id' in data['data']

def test_api_get_report(client):
    res = client.get('/api/reports/1001')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['data']['report_id'] == 1001

def test_api_response_workflow_with_guardrails(client):
    # 1. Recommend actions
    rec_res = client.post('/api/incidents/1/response/recommend')
    assert rec_res.status_code == 200
    rec_data = rec_res.get_json()
    assert rec_data['success'] is True
    actions = rec_data['data']['recommended_actions']
    assert len(actions) > 0
    
    action_id = actions[0]['action_id']

    # 2. Attempt execute BEFORE approval (must be blocked by guardrail)
    exec_blocked = client.post('/api/incidents/1/response/execute', json={'action_id': action_id})
    assert exec_blocked.status_code == 403
    blocked_data = exec_blocked.get_json()
    assert blocked_data['success'] is False
    assert blocked_data['error'] == 'APPROVAL_REQUIRED'

    # 3. Approve action as Administrator
    appr_res = client.post('/api/incidents/1/response/approve', json={'action_id': action_id})
    assert appr_res.status_code == 200
    appr_data = appr_res.get_json()
    assert appr_data['success'] is True
    assert appr_data['data']['status'] == 'APPROVED'

    # 4. Execute approved action
    exec_res = client.post('/api/incidents/1/response/execute', json={'action_id': action_id})
    assert exec_res.status_code == 200
    exec_data = exec_res.get_json()
    assert exec_data['success'] is True
    assert exec_data['data']['status'] == 'EXECUTED'
