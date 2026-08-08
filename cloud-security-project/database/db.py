"""
db.py
-------------------------------------------------
SQLite + SQLAlchemy storage for the cloud security
platform.

The rest of the Flask app uses small helper functions
from this file, so routes can stay simple and beginner
friendly.
-------------------------------------------------
"""

import os
import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, inspect
from sqlalchemy.orm import declarative_base, sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv

from analytics.risk_engine import calculate_risk
from analytics.security_score import calculate_security_score, get_risk_level


load_dotenv()
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_DIR = os.path.join(BASE_DIR, "database")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///database/security_platform.db")
if DATABASE_URL.startswith("sqlite:///"):
    configured_path = DATABASE_URL.replace("sqlite:///", "", 1)
    DB_PATH = configured_path if os.path.isabs(configured_path) else os.path.join(BASE_DIR, configured_path)
    DATABASE_URL = "sqlite:///" + DB_PATH.replace("\\", "/")
else:
    DB_PATH = os.path.join(DATABASE_DIR, "security_platform.db")
DEMO_PACKETS_CAPTURED = 48213

Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine)


def utc_now():
    return datetime.now(UTC).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(120), nullable=False)
    role = Column(String(80), nullable=False)
    department = Column(String(120), nullable=False)
    firebase_uid = Column(String(128), unique=True, nullable=True, index=True)
    email = Column(String(160), nullable=True, index=True)
    auth_provider = Column(String(80), default="local", nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)


class OAuthIdentity(Base):
    __tablename__ = "oauth_identities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    provider = Column(String(40), nullable=False, index=True)  # 'google' or 'github'
    provider_user_id = Column(String(128), nullable=False, index=True)
    email = Column(String(160), nullable=True, index=True)
    display_name = Column(String(120), nullable=True)
    profile_image_url = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    last_login_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)



class ThreatIncident(Base):
    __tablename__ = "threat_incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    time = Column(String(20), nullable=False)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False)
    attack_type = Column(String(80), nullable=False)
    severity = Column(String(40), nullable=False)
    confidence = Column(Integer, nullable=False)
    assigned_to = Column(String(120), nullable=False)
    status = Column(String(40), nullable=False)
    risk_score = Column(String(20), nullable=False)
    business_impact = Column(String(80), nullable=False)
    priority = Column(String(80), nullable=False)
    estimated_downtime = Column(String(80), nullable=False)
    estimated_financial_loss = Column(String(80), nullable=False)
    feedback_status = Column(String(40), default="None", nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(160), nullable=False)
    report_type = Column(String(60), nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    generated_by = Column(String(120), nullable=False)


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(80), unique=True, nullable=False)
    description = Column(String(255), nullable=False)

class SystemSettings(Base):
    __tablename__ = "system_settings"

    key = Column(String(80), primary_key=True)
    value = Column(String(255), nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)


def get_system_setting(key, default_value=None):
    db = SessionLocal()
    try:
        setting = db.query(SystemSettings).filter_by(key=key).first()
        return setting.value if setting else default_value
    finally:
        db.close()


def set_system_setting(key, value):
    db = SessionLocal()
    try:
        setting = db.query(SystemSettings).filter_by(key=key).first()
        if setting:
            setting.value = str(value)
        else:
            setting = SystemSettings(key=key, value=str(value))
            db.add(setting)
        db.commit()
    finally:
        db.close()


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    role = Column(String(80), nullable=False, index=True)
    resource = Column(String(80), nullable=False)
    can_view = Column(Boolean, default=True, nullable=False)
    can_manage = Column(Boolean, default=False, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False)
    user_id = Column(Integer, nullable=True)
    username = Column(String(80), nullable=False)
    action = Column(String(120), nullable=False)
    route = Column(String(160), nullable=False)
    resource = Column(String(120), nullable=False)
    details = Column(Text, nullable=False)
    detail = Column(Text, nullable=False)
    ip_address = Column(String(45), nullable=False)
    user_agent = Column(String(255), nullable=False)
    status = Column(String(40), nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)


class LoginHistory(Base):
    __tablename__ = "login_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    email = Column(String(255), nullable=True, index=True)
    username = Column(String(100), nullable=True, index=True)
    authentication_method = Column(String(50), nullable=False, default="PASSWORD")
    provider_user_id = Column(String(255), nullable=True)
    login_timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)
    login_status = Column(String(20), nullable=False, default="SUCCESS")
    ip_address = Column(String(100), nullable=True, index=True)
    user_agent = Column(String(500), nullable=True)
    browser = Column(String(100), default="Unknown")
    browser_version = Column(String(50), nullable=True)
    operating_system = Column(String(100), default="Unknown")
    device_type = Column(String(50), default="Unknown")
    device_name = Column(String(100), nullable=True)
    country = Column(String(100), default="Unknown")
    region = Column(String(100), default="Unknown")
    city = Column(String(100), default="Unknown")
    session_id_hash = Column(String(64), nullable=True)
    failure_reason = Column(String(255), nullable=True)
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(20), default="LOW")
    risk_signals = Column(Text, default="[]")
    created_at = Column(DateTime, default=utc_now, nullable=False)

    def to_dict(self):
        signals = []
        if self.risk_signals:
            try:
                signals = json.loads(self.risk_signals) if isinstance(self.risk_signals, str) else self.risk_signals
            except Exception:
                signals = [s.strip() for s in str(self.risk_signals).split(",") if s.strip()]
        return {
            "id": self.id,
            "user_id": self.user_id,
            "email": self.email,
            "username": self.username,
            "authentication_method": self.authentication_method,
            "provider_user_id": self.provider_user_id,
            "login_timestamp": self.login_timestamp.isoformat() if self.login_timestamp else None,
            "login_status": self.login_status,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "browser": self.browser,
            "browser_version": self.browser_version,
            "operating_system": self.operating_system,
            "device_type": self.device_type,
            "device_name": self.device_name,
            "country": self.country,
            "region": self.region,
            "city": self.city,
            "location_label": "Approximate IP-based location",
            "session_id_hash": self.session_id_hash,
            "failure_reason": self.failure_reason,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_signals": signals,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class SecurityNotification(Base):
    __tablename__ = "security_notifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    correlation_id = Column(String(64), nullable=True, index=True)
    event_type = Column(String(80), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    email = Column(String(255), nullable=True)
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(20), default="LOW")
    channel = Column(String(40), default="TELEGRAM", nullable=False)
    status = Column(String(20), default="PENDING", nullable=False)  # PENDING, SENT, FAILED, SUPPRESSED
    failure_reason_safe = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    sent_at = Column(DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "correlation_id": self.correlation_id,
            "event_type": self.event_type,
            "user_id": self.user_id,
            "email": self.email,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "channel": self.channel,
            "status": self.status,
            "failure_reason_safe": self.failure_reason_safe,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
        }


class Setting(Base):

    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(120), unique=True, nullable=False)
    value = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=utc_now, nullable=False)


class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, nullable=False, index=True)
    event_time = Column(String(40), nullable=False)
    event = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)


class BusinessRisk(Base):
    __tablename__ = "business_risk"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, nullable=False, index=True)
    risk_score = Column(Float, nullable=False)
    business_impact = Column(String(80), nullable=False)
    priority = Column(String(80), nullable=False)
    estimated_downtime = Column(String(80), nullable=False)
    estimated_financial_loss = Column(String(80), nullable=False)
    recovery_recommendation = Column(Text, nullable=False)


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    version = Column(String(80), unique=True, nullable=False)
    model_path = Column(String(255), nullable=False)
    dataset_name = Column(String(160), nullable=False)
    accuracy = Column(Float, default=0.0, nullable=False)
    precision = Column(Float, default=0.0, nullable=False)
    recall = Column(Float, default=0.0, nullable=False)
    f1_score = Column(Float, default=0.0, nullable=False)
    confusion_matrix = Column(Text, default="[]", nullable=False)
    roc_curve = Column(Text, default="{}", nullable=False)
    training_history = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(160), nullable=False)
    detail = Column(Text, nullable=False)
    severity = Column(String(40), nullable=False)
    is_read = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)


class IPReputation(Base):
    __tablename__ = "ip_reputation"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    attack_count = Column(Integer, default=0, nullable=False)
    last_seen = Column(String(40), nullable=False)
    reputation = Column(String(40), nullable=False)
    country = Column(String(80), nullable=False)
    severity_history = Column(Text, nullable=False)
    status = Column(String(40), nullable=False)


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(120), nullable=False)
    asset_type = Column(String(80), nullable=False)
    criticality = Column(String(40), nullable=False)
    owner = Column(String(120), nullable=False)
    status = Column(String(40), nullable=False)


DEFAULT_USERS = [
    {
        "username": "admin",
        "password": "admin",
        "full_name": "Security Administrator",
        "role": "Administrator",
        "department": "Security Operations",
    },
      {
          "username": "praveen",
          "password": "praveen07",
          "full_name": "Praveen",
          "role": "Cloud Administrator",
          "department": "Security Operations",
      },
    {
        "username": "sanjay",
        "password": "sanjay123",
        "full_name": "Sanjay",
        "role": "Cloud Administrator",
        "department": "Cloud Infrastructure",
    },
    {
        "username": "auditor",
        "password": "auditor123",
        "full_name": "Compliance Auditor",
        "role": "Auditor",
        "department": "Audit & Compliance",
    },
    {
        "username": "viewer",
        "password": "viewer123",
        "full_name": "Read Only Viewer",
        "role": "Viewer",
        "department": "Security Operations",
    },
    {
        "username": "sainathan",
        "password": "sainathan123",
        "full_name": "Sai Nathan",
        "role": "Threat Analyst",
        "department": "Threat Intelligence",
    },
    {
        "username": "faran",
        "password": "faran123",
        "full_name": "Faran",
        "role": "Security Engineer",
        "department": "Security Engineering",
    },
    {
        "username": "kowshika",
        "password": "kowshika123",
        "full_name": "Kowshika",
        "role": "SOC Manager",
        "department": "Security Operations",
    },
]

DEFAULT_INCIDENTS = [
    {
        "time": "10:15",
        "source_ip": "192.168.1.45",
        "destination_ip": "10.0.0.5",
        "attack_type": "Brute Force",
        "severity": "Critical",
        "confidence": 98,
        "assigned_to": "Praveen",
        "status": "Investigating",
    },
    {
        "time": "10:18",
        "source_ip": "172.16.0.22",
        "destination_ip": "10.0.0.8",
        "attack_type": "Port Scan",
        "severity": "Medium",
        "confidence": 87,
        "assigned_to": "Sanjay",
        "status": "Open",
    },
    {
        "time": "10:21",
        "source_ip": "203.0.113.12",
        "destination_ip": "10.0.0.10",
        "attack_type": "SQL Injection",
        "severity": "High",
        "confidence": 93,
        "assigned_to": "Sai Nathan",
        "status": "Investigating",
    },
    {
        "time": "10:25",
        "source_ip": "198.51.100.21",
        "destination_ip": "10.0.0.3",
        "attack_type": "DDoS",
        "severity": "Critical",
        "confidence": 99,
        "assigned_to": "Faran",
        "status": "Blocked",
    },
]

DEFAULT_REPORTS = [
    {"title": "Daily Security Report", "report_type": "Daily", "generated_by": "System"},
    {"title": "Weekly Threat Summary", "report_type": "Weekly", "generated_by": "System"},
    {"title": "Monthly Executive Overview", "report_type": "Monthly", "generated_by": "System"},
]

ROLE_PERMISSIONS = {
    "Administrator": {
        "dashboard": True,
        "analytics": True,
        "reports": True,
        "settings": True,
        "profile": True,
        "investigation": True,
        "audit_logs": True,
        "upload": True,
    },
    "Cloud Administrator": {
        "dashboard": True,
        "analytics": True,
        "reports": False,
        "settings": True,
        "profile": True,
        "investigation": False,
        "audit_logs": False,
        "upload": False,
    },
    "Security Analyst": {
        "dashboard": True,
        "analytics": True,
        "reports": False,
        "settings": False,
        "profile": True,
        "investigation": True,
        "audit_logs": False,
        "upload": False,
    },
    "Auditor": {
        "dashboard": True,
        "analytics": False,
        "reports": True,
        "settings": False,
        "profile": True,
        "investigation": False,
        "audit_logs": True,
        "upload": False,
    },
    "Viewer": {
        "dashboard": True,
        "analytics": True,
        "reports": False,
        "settings": False,
        "profile": True,
        "investigation": False,
        "audit_logs": False,
        "upload": False,
    },
    "SOC Manager": {
        "dashboard": True,
        "analytics": True,
        "reports": True,
        "settings": False,
        "profile": True,
        "investigation": True,
        "audit_logs": True,
        "upload": False,
    },
    "Security Engineer": {
        "dashboard": True,
        "analytics": False,
        "reports": True,
        "settings": False,
        "profile": True,
        "investigation": True,
        "audit_logs": False,
        "upload": False,
    },
    "Threat Analyst": {
        "dashboard": True,
        "analytics": True,
        "reports": False,
        "settings": False,
        "profile": True,
        "investigation": True,
        "audit_logs": False,
        "upload": False,
    },
    "SOC Analyst": {
        "dashboard": True,
        "analytics": True,
        "reports": False,
        "settings": False,
        "profile": True,
        "investigation": True,
        "audit_logs": False,
        "upload": False,
    },
    "Read Only Analyst": {
        "dashboard": True,
        "analytics": True,
        "reports": False,
        "settings": False,
        "profile": False,
        "investigation": False,
        "audit_logs": False,
        "upload": False,
    },
}

DEFAULT_SETTINGS = [
    {"key": "session_timeout_minutes", "value": "30"},
    {"key": "prediction_mode", "value": "demo"},
    {"key": "oauth_google_ready", "value": "false"},
    {"key": "oauth_github_ready", "value": "false"},
    {"key": "oauth_azure_ad_ready", "value": "false"},
]

DEFAULT_ASSETS = [
    {"name": "Cloud API Gateway", "asset_type": "Gateway", "criticality": "Critical", "owner": "Cloud Team", "status": "Operational"},
    {"name": "Customer Database", "asset_type": "Database", "criticality": "Critical", "owner": "Security Operations", "status": "Healthy"},
    {"name": "Identity Provider", "asset_type": "IAM", "criticality": "High", "owner": "Security Engineering", "status": "Monitoring"},
]


def _get_session():
    return SessionLocal()


def _user_to_dict(user):
    if user is None:
        return None
    return {
        "id": user.id,
        "username": user.username,
        "password_hash": user.password_hash,
        "full_name": user.full_name,
        "display_name": user.full_name,
        "role": user.role,
        "department": user.department,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
        "firebase_uid": user.firebase_uid,
        "email": user.email,
        "auth_provider": user.auth_provider,
    }


def _incident_to_dict(incident):
    return {
        "id": incident.id,
        "time": incident.time,
        "source_ip": incident.source_ip,
        "destination_ip": incident.destination_ip,
        "attack_type": incident.attack_type,
        "severity": incident.severity,
        "confidence": incident.confidence,
        "assigned_to": incident.assigned_to,
        "status": incident.status,
        "risk_score": incident.risk_score,
        "business_impact": incident.business_impact,
        "priority": incident.priority,
        "estimated_downtime": incident.estimated_downtime,
        "estimated_financial_loss": incident.estimated_financial_loss,
        "created_at": incident.created_at.isoformat() if hasattr(incident.created_at, "isoformat") else str(incident.created_at),
        "updated_at": incident.updated_at.isoformat() if hasattr(incident.updated_at, "isoformat") else str(incident.updated_at),
    }


def _report_to_dict(report):
    return {
        "id": report.id,
        "title": report.title,
        "report_type": report.report_type,
        "created_at": report.created_at,
        "generated_by": report.generated_by,
    }


def _audit_to_dict(log):
    return {
        "id": log.id,
        "timestamp": log.timestamp,
        "user_id": log.user_id,
        "username": log.username,
        "action": log.action,
        "route": log.route,
        "resource": log.resource,
        "details": log.details,
        "detail": log.detail,
        "ip_address": log.ip_address,
        "user_agent": log.user_agent,
        "status": log.status,
        "created_at": log.created_at,
    }


def _model_version_to_dict(model_version):
    if model_version is None:
        return None
    return {
        "id": model_version.id,
        "version": model_version.version,
        "model_path": model_version.model_path,
        "dataset_name": model_version.dataset_name,
        "accuracy": model_version.accuracy,
        "precision": model_version.precision,
        "recall": model_version.recall,
        "f1_score": model_version.f1_score,
        "confusion_matrix": json.loads(model_version.confusion_matrix or "[]"),
        "roc_curve": json.loads(model_version.roc_curve or "{}"),
        "training_history": json.loads(model_version.training_history or "{}"),
        "created_at": model_version.created_at,
    }


def _notification_to_dict(notification):
    return {
        "id": notification.id,
        "title": notification.title,
        "detail": notification.detail,
        "severity": notification.severity,
        "is_read": notification.is_read,
        "created_at": notification.created_at,
    }


def _asset_to_dict(asset):
    return {
        "id": asset.id,
        "name": asset.name,
        "asset_type": asset.asset_type,
        "criticality": asset.criticality,
        "owner": asset.owner,
        "status": asset.status,
    }


def _build_incident(data):
    risk = calculate_risk(data["attack_type"], data["severity"], data["confidence"])
    return ThreatIncident(
        time=data["time"],
        source_ip=data["source_ip"],
        destination_ip=data["destination_ip"],
        attack_type=data["attack_type"],
        severity=data["severity"],
        confidence=data["confidence"],
        assigned_to=data["assigned_to"],
        status=data["status"],
        risk_score=str(risk["risk_score"]),
        business_impact=risk["business_impact"],
        priority=risk["priority"],
        estimated_downtime=risk["estimated_downtime"],
        estimated_financial_loss=risk["estimated_financial_loss"],
    )


def _seed_incident_children(session, incident):
    existing_risk = session.query(BusinessRisk).filter_by(incident_id=incident.id).first()
    if existing_risk is None:
        session.add(
            BusinessRisk(
                incident_id=incident.id,
                risk_score=float(incident.risk_score),
                business_impact=incident.business_impact,
                priority=incident.priority,
                estimated_downtime=incident.estimated_downtime,
                estimated_financial_loss=incident.estimated_financial_loss,
                recovery_recommendation=f"Contain {incident.attack_type}, validate affected assets, and document recovery actions.",
            )
        )

    if session.query(IncidentTimeline).filter_by(incident_id=incident.id).count() == 0:
        events = [
            f"{incident.attack_type} detected from {incident.source_ip}",
            f"Confidence score recorded at {incident.confidence}%",
            f"Incident assigned to {incident.assigned_to}",
            f"Current status: {incident.status}",
        ]
        for event in events:
            session.add(IncidentTimeline(incident_id=incident.id, event_time=incident.time, event=event))


def _reset_old_demo_tables_if_needed():
    """Remove old demo tables that used a different schema."""
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    expected_tables = {
        "users",
        "threat_incidents",
        "reports",
        "audit_logs",
        "settings",
        "incident_timeline",
        "business_risk",
        "model_versions",
        "notifications",
        "ip_reputation",
        "assets",
        "roles",
        "permissions",
    }
    expected_columns = {
        "users": {
            "id",
            "username",
            "password_hash",
            "full_name",
            "role",
            "department",
            "firebase_uid",
            "email",
            "auth_provider",
            "created_at",
            "updated_at",
        },
        "threat_incidents": {
            "id",
            "time",
            "source_ip",
            "destination_ip",
            "attack_type",
            "severity",
            "confidence",
            "assigned_to",
            "status",
            "risk_score",
            "business_impact",
            "priority",
            "estimated_downtime",
            "estimated_financial_loss",
            "created_at",
            "updated_at",
        },
        "reports": {"id", "title", "report_type", "created_at", "generated_by"},
        "audit_logs": {
            "id",
            "timestamp",
            "user_id",
            "username",
            "action",
            "route",
            "resource",
            "details",
            "detail",
            "ip_address",
            "user_agent",
            "status",
            "created_at",
        },
        "model_versions": {"id", "version", "model_path", "dataset_name", "accuracy", "precision", "recall", "f1_score"},
    }

    schema_mismatch = False
    for table_name, columns in expected_columns.items():
        if table_name in table_names:
            existing_columns = {column["name"] for column in inspector.get_columns(table_name)}
            if not columns.issubset(existing_columns):
                schema_mismatch = True

    if (
        "incidents" in table_names
        or ("users" in table_names and "threat_incidents" not in table_names)
        or schema_mismatch
    ):
        Base.metadata.drop_all(bind=engine)
        with engine.begin() as conn:
            if "incidents" in table_names:
                conn.exec_driver_sql("DROP TABLE IF EXISTS incidents")

    elif not expected_tables.issubset(table_names):
        Base.metadata.create_all(bind=engine)


def init_db():
    """Create tables and seed default users, reports, and fixed demo incidents."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    _reset_old_demo_tables_if_needed()
    Base.metadata.create_all(bind=engine)
    seed_demo_data()
    print(f"[INFO] Database ready at: {DB_PATH}")


def seed_demo_data(incidents=None):
    """Insert default users and the 4 fixed demo incidents if they do not exist."""
    session = _get_session()
    try:
        for user_data in DEFAULT_USERS:
            existing = session.query(User).filter_by(username=user_data["username"]).first()
            if existing is None:
                session.add(
                    User(
                        username=user_data["username"],
                        password_hash=generate_password_hash(user_data["password"]),
                        full_name=user_data["full_name"],
                        role=user_data["role"],
                        department=user_data["department"],
                    )
                )

        fixed_incidents = incidents or DEFAULT_INCIDENTS
        for incident_data in fixed_incidents:
            existing = session.query(ThreatIncident).filter_by(
                source_ip=incident_data["source_ip"],
                attack_type=incident_data["attack_type"],
                time=incident_data["time"],
            ).first()
            if existing is None:
                existing = _build_incident(incident_data)
                session.add(existing)
                session.flush()
            _seed_incident_children(session, existing)

        if session.query(Report).count() == 0:
            for report_data in DEFAULT_REPORTS:
                session.add(Report(**report_data))

        for role_name, permissions in ROLE_PERMISSIONS.items():
            if session.query(Role).filter_by(name=role_name).first() is None:
                session.add(Role(name=role_name, description=f"{role_name} enterprise access profile"))
            for resource, allowed in permissions.items():
                existing_permission = session.query(Permission).filter_by(role=role_name, resource=resource).first()
                if existing_permission is None:
                    session.add(
                        Permission(
                            role=role_name,
                            resource=resource,
                            can_view=bool(allowed),
                            can_manage=role_name in ("Administrator", "SOC Manager"),
                        )
                    )
                else:
                    existing_permission.can_view = bool(allowed)
                    existing_permission.can_manage = role_name in ("Administrator", "SOC Manager")

        for setting in DEFAULT_SETTINGS:
            if session.query(Setting).filter_by(key=setting["key"]).first() is None:
                session.add(Setting(**setting))

        for asset in DEFAULT_ASSETS:
            if session.query(Asset).filter_by(name=asset["name"]).first() is None:
                session.add(Asset(**asset))

        for incident in session.query(ThreatIncident).all():
            if session.query(Notification).filter_by(title=f"{incident.severity} {incident.attack_type}").first() is None:
                session.add(
                    Notification(
                        title=f"{incident.severity} {incident.attack_type}",
                        detail=f"{incident.source_ip} targeting {incident.destination_ip}",
                        severity=incident.severity,
                    )
                )
            reputation = session.query(IPReputation).filter_by(ip_address=incident.source_ip).first()
            if reputation is None:
                session.add(
                    IPReputation(
                        ip_address=incident.source_ip,
                        attack_count=1,
                        last_seen=incident.time,
                        reputation="Dangerous" if incident.severity == "Critical" else "Suspicious",
                        country="Unknown",
                        severity_history=incident.severity,
                        status="Dangerous" if incident.severity == "Critical" else "Suspicious",
                    )
                )

        session.commit()
    finally:
        session.close()


def get_user_by_username(username):
    session = _get_session()
    try:
        user = session.query(User).filter_by(username=username).first()
        return _user_to_dict(user)
    finally:
        session.close()


def get_user_by_id(user_id):
    session = _get_session()
    try:
        user = session.query(User).filter_by(id=int(user_id)).first()
        return _user_to_dict(user)
    except (TypeError, ValueError):
        return None
    finally:
        session.close()


def authenticate_user(username, password):
    user = get_user_by_username(username)
    if user is None:
        return None
    if not check_password_hash(user["password_hash"], password):
        return None
    return user


def get_or_create_firebase_user(firebase_uid, email, full_name, provider):
    """Create or update a Firebase-backed user in SQLite."""
    session = _get_session()
    try:
        user = session.query(User).filter_by(firebase_uid=firebase_uid).first()
        if user is None and email:
            user = session.query(User).filter_by(email=email).first()

        if user is None:
            username_source = email or firebase_uid
            username = username_source.split("@")[0].lower().replace(" ", "_")
            existing_username = session.query(User).filter_by(username=username).first()
            if existing_username is not None:
                username = f"firebase_{firebase_uid[:12]}"

            user = User(
                username=username,
                password_hash=generate_password_hash(secrets_safe_password(firebase_uid)),
                full_name=full_name or email or "Firebase User",
                role="Read Only Analyst",
                department="External Identity",
                firebase_uid=firebase_uid,
                email=email,
                auth_provider=provider or "firebase",
            )
            session.add(user)
        else:
            user.firebase_uid = firebase_uid
            user.email = email or user.email
            user.full_name = full_name or user.full_name
            user.auth_provider = provider or user.auth_provider

        session.commit()
        session.refresh(user)
        return _user_to_dict(user)
    finally:
        session.close()


def secrets_safe_password(seed):
    return f"oauth-auth-{seed}-{utc_now().timestamp()}"


def get_or_create_oauth_user(provider, provider_user_id, email=None, display_name=None, profile_image_url=None, current_authenticated_user=None):
    """
    Safely finds or creates a user for OAuth (Google/GitHub).
    Ensures safe role assignment (Read Only Analyst) and prevents unauthenticated email-linking account takeover.
    """
    session = _get_session()
    try:
        # 1. Search for existing OAuthIdentity
        identity = session.query(OAuthIdentity).filter_by(provider=provider, provider_user_id=str(provider_user_id)).first()
        
        if identity:
            identity.last_login_at = utc_now()
            if email:
                identity.email = email
            if display_name:
                identity.display_name = display_name
            if profile_image_url:
                identity.profile_image_url = profile_image_url
                
            user = session.query(User).filter_by(id=identity.user_id).first()
            if user:
                user.updated_at = utc_now()
                session.commit()
                session.refresh(user)
                return _user_to_dict(user), "LOGIN_SUCCESS"

        # 2. Handle account linking if user is already authenticated
        user = None
        if current_authenticated_user and current_authenticated_user.get("id"):
            user = session.query(User).filter_by(id=current_authenticated_user["id"]).first()
            
        if user is None and email:
            # Check if an existing local account shares the email
            existing_user = session.query(User).filter_by(email=email).first()
            if existing_user:
                # DO NOT blindly merge! Require existing user to be logged in to link account safely.
                return None, "ACCOUNT_LINK_REQUIRED"

        # 3. Create new user if not found and not linking to existing account
        if user is None:
            base_username = (email.split("@")[0] if email else f"{provider}_{provider_user_id}").lower().replace(" ", "_")
            username = base_username
            idx = 1
            while session.query(User).filter_by(username=username).first() is not None:
                username = f"{base_username}_{idx}"
                idx += 1
                
            user = User(
                username=username,
                password_hash=generate_password_hash(secrets_safe_password(provider_user_id)),
                full_name=display_name or email or f"{provider.capitalize()} User",
                role="Read Only Analyst",  # Safest default role (Viewer)
                department="Social Identity",
                email=email,
                auth_provider=provider,
            )
            session.add(user)
            session.flush()

        # 4. Attach new OAuthIdentity
        new_identity = OAuthIdentity(
            user_id=user.id,
            provider=provider,
            provider_user_id=str(provider_user_id),
            email=email,
            display_name=display_name,
            profile_image_url=profile_image_url,
            created_at=utc_now(),
            last_login_at=utc_now()
        )
        session.add(new_identity)
        session.commit()
        session.refresh(user)
        return _user_to_dict(user), "USER_CREATED"
    finally:
        session.close()



def get_all_incidents():
    session = _get_session()
    try:
        incidents = session.query(ThreatIncident).order_by(ThreatIncident.id.asc()).all()
        return [_incident_to_dict(incident) for incident in incidents]
    finally:
        session.close()


def get_demo_incidents():
    """Return only the four fixed demo incidents, excluding uploaded predictions."""
    session = _get_session()
    try:
        demo_keys = {
            (item["source_ip"], item["attack_type"], item["time"])
            for item in DEFAULT_INCIDENTS
        }
        incidents = session.query(ThreatIncident).order_by(ThreatIncident.id.asc()).all()
        return [
            _incident_to_dict(incident)
            for incident in incidents
            if (incident.source_ip, incident.attack_type, incident.time) in demo_keys
        ]
    finally:
        session.close()


def get_prediction_incidents():
    """Return uploaded/ML-created incidents separately from fixed demo incidents."""
    session = _get_session()
    try:
        demo_keys = {
            (item["source_ip"], item["attack_type"], item["time"])
            for item in DEFAULT_INCIDENTS
        }
        incidents = session.query(ThreatIncident).order_by(ThreatIncident.id.asc()).all()
        return [
            _incident_to_dict(incident)
            for incident in incidents
            if (incident.source_ip, incident.attack_type, incident.time) not in demo_keys
        ]
    finally:
        session.close()


def get_incidents_by_ip(ip):
    session = _get_session()
    try:
        incidents = (
            session.query(ThreatIncident)
            .filter_by(source_ip=ip)
            .order_by(ThreatIncident.id.asc())
            .all()
        )
        return [_incident_to_dict(incident) for incident in incidents]
    finally:
        session.close()


def get_all_reports():
    session = _get_session()
    try:
        reports = session.query(Report).order_by(Report.created_at.desc()).all()
        return [_report_to_dict(report) for report in reports]
    finally:
        session.close()


def get_all_assets():
    session = _get_session()
    try:
        assets = session.query(Asset).order_by(Asset.criticality.desc()).all()
        return [_asset_to_dict(asset) for asset in assets]
    finally:
        session.close()


def get_notifications(limit=10):
    session = _get_session()
    try:
        notifications = session.query(Notification).order_by(Notification.created_at.desc()).limit(limit).all()
        return [_notification_to_dict(notification) for notification in notifications]
    finally:
        session.close()


def get_audit_logs(limit=100):
    session = _get_session()
    try:
        logs = session.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
        return [_audit_to_dict(log) for log in logs]
    finally:
        session.close()


def log_audit_event(
    username,
    action,
    resource,
    detail="",
    ip_address="unknown",
    status="success",
    user_id=None,
    route=None,
    user_agent="unknown",
):
    session = _get_session()
    try:
        session.add(
            AuditLog(
                user_id=user_id,
                username=username or "anonymous",
                action=action,
                route=route or resource or "unknown",
                resource=resource,
                details=detail or "",
                detail=detail or "",
                ip_address=ip_address or "unknown",
                user_agent=(user_agent or "unknown")[:255],
                status=status,
            )
        )
        session.commit()
    finally:
        session.close()


def role_can_access(role, resource):
    if role == "Administrator":
        return True
    session = _get_session()
    try:
        permission = session.query(Permission).filter_by(role=role, resource=resource).first()
        return bool(permission and permission.can_view)
    finally:
        session.close()


def get_timeline_for_incident(incident_id):
    session = _get_session()
    try:
        events = (
            session.query(IncidentTimeline)
            .filter_by(incident_id=incident_id)
            .order_by(IncidentTimeline.id.asc())
            .all()
        )
        return [{"time": event.event_time, "event": event.event} for event in events]
    finally:
        session.close()


def get_latest_model_version():
    session = _get_session()
    try:
        model_version = session.query(ModelVersion).order_by(ModelVersion.created_at.desc()).first()
        return _model_version_to_dict(model_version)
    finally:
        session.close()


def save_model_version(metadata):
    session = _get_session()
    try:
        version = metadata.get("version") or utc_now().strftime("rf-%Y%m%d%H%M%S")
        existing = session.query(ModelVersion).filter_by(version=version).first()
        if existing is None:
            session.add(
                ModelVersion(
                    version=version,
                    model_path=metadata.get("model_path", "models/rf_model.pkl"),
                    dataset_name=metadata.get("dataset_name", "unknown"),
                    accuracy=float(metadata.get("accuracy", 0)),
                    precision=float(metadata.get("precision", 0)),
                    recall=float(metadata.get("recall", 0)),
                    f1_score=float(metadata.get("f1_score", 0)),
                    confusion_matrix=json.dumps(metadata.get("confusion_matrix", [])),
                    roc_curve=json.dumps(metadata.get("roc_curve", {})),
                    training_history=json.dumps(metadata.get("training_history", {})),
                )
            )
            session.commit()
    finally:
        session.close()


def add_prediction_incident(source_ip, destination_ip, attack_type, confidence=80, assigned_to="AI Engine"):
    risk = calculate_risk(attack_type, "High", int(confidence))
    session = _get_session()
    try:
        incident = ThreatIncident(
            time=datetime.now().strftime("%H:%M"),
            source_ip=source_ip or "0.0.0.0",
            destination_ip=destination_ip or "10.0.0.1",
            attack_type=attack_type or "Unknown",
            severity="High",
            confidence=int(confidence),
            assigned_to=assigned_to,
            status="Open",
            risk_score=str(risk["risk_score"]),
            business_impact=risk["business_impact"],
            priority=risk["priority"],
            estimated_downtime=risk["estimated_downtime"],
            estimated_financial_loss=risk["estimated_financial_loss"],
        )
        session.add(incident)
        session.flush()
        _seed_incident_children(session, incident)
        session.add(
            Notification(
                title=f"ML Prediction: {incident.attack_type}",
                detail=f"{incident.source_ip} targeting {incident.destination_ip}",
                severity=incident.severity,
            )
        )
        session.commit()
        return _incident_to_dict(incident)
    finally:
        session.close()


def get_user_by_username(username):
    if not username:
        return None
    session = _get_session()
    try:
        user = session.query(User).filter(User.username.ilike(username.strip())).first()
        return _user_to_dict(user)
    finally:
        session.close()


def change_user_password(username, old_password, new_password):
    session = _get_session()
    try:
        user = session.query(User).filter(User.username.ilike(username.strip())).first()
        if user and check_password_hash(user.password_hash, old_password):
            user.password_hash = generate_password_hash(new_password)
            user.updated_at = utc_now()
            session.commit()
            return True
        return False
    finally:
        session.close()


def reset_user_password(username, new_password):
    session = _get_session()
    try:
        user = session.query(User).filter(User.username.ilike(username.strip())).first()
        if user:
            user.password_hash = generate_password_hash(new_password)
            user.updated_at = utc_now()
            session.commit()
            return True
        return False
    finally:
        session.close()


def restore_database_from_file(backup_path):
    if not os.path.exists(backup_path):
        return False
    import shutil
    shutil.copy2(backup_path, DB_PATH)
    return True


def get_dashboard_stats():
    incidents = get_demo_incidents()
    security_score = calculate_security_score(incidents)
    threat_score = max(0, 100 - security_score)
    active_threats = len(
        [incident for incident in incidents if incident["status"] not in ("Blocked", "Resolved")]
    )

    status_counts = {"Open": 0, "Investigating": 0, "Blocked": 0, "Resolved": 0}
    for incident in incidents:
        status = incident["status"]
        status_counts[status] = status_counts.get(status, 0) + 1

    return {
        "active_threats": active_threats,
        "security_score": security_score,
        "threat_score": threat_score,
        "packets_captured": DEMO_PACKETS_CAPTURED,
        "risk_level": get_risk_level(security_score),
        "status_counts": status_counts,
    }


# Backwards-compatible name used by earlier app code.
def load_incidents():
    return get_all_incidents()


def evaluate_user_login_risk(user_id, ip_address, browser, operating_system, device_type, country, email=None):
    """
    Evaluates login risk signals based on historical patterns:
    - NEW_IP: IP address not seen in user's previous successful logins
    - NEW_DEVICE: (device_type, OS) combination not seen previously
    - NEW_BROWSER: Browser not seen previously
    - NEW_COUNTRY: Country not seen previously
    - REPEATED_FAILED_LOGIN: >= 3 failed logins from user/IP in last 15 minutes
    - RAPID_LOGIN_ATTEMPTS: Attempt within 5s of previous login from same IP
    - MULTIPLE_IPS: User logged in from >= 2 distinct IPs in last 1 hour
    - SUSPICIOUS_LOGIN_PATTERN: Severe combination of signals
    """
    session = _get_session()
    signals = []
    try:
        now = utc_now()
        fifteen_mins_ago = now - timedelta(minutes=15)
        one_hour_ago = now - timedelta(hours=1)
        five_secs_ago = now - timedelta(seconds=5)

        query = session.query(LoginHistory)
        if user_id:
            user_history = query.filter(LoginHistory.user_id == user_id, LoginHistory.login_status == "SUCCESS").all()
        elif email:
            user_history = query.filter(LoginHistory.email == email, LoginHistory.login_status == "SUCCESS").all()
        else:
            user_history = []

        if user_history:
            prev_ips = {h.ip_address for h in user_history if h.ip_address}
            prev_devices = {(h.device_type, h.operating_system) for h in user_history if h.device_type and h.operating_system}
            prev_browsers = {h.browser for h in user_history if h.browser}
            prev_countries = {h.country for h in user_history if h.country and h.country != "Unknown"}

            if ip_address and ip_address not in prev_ips and len(prev_ips) > 0:
                signals.append("NEW_IP")
            if (device_type, operating_system) not in prev_devices and len(prev_devices) > 0:
                signals.append("NEW_DEVICE")
            if browser and browser not in prev_browsers and len(prev_browsers) > 0:
                signals.append("NEW_BROWSER")
            if country and country != "Unknown" and country not in prev_countries and len(prev_countries) > 0:
                signals.append("NEW_COUNTRY")

        # Check recent failures for this user / IP
        fail_query = session.query(LoginHistory).filter(
            LoginHistory.login_status == "FAILED",
            LoginHistory.login_timestamp >= fifteen_mins_ago
        )
        if user_id:
            fail_count = fail_query.filter(LoginHistory.user_id == user_id).count()
        elif email:
            fail_count = fail_query.filter(LoginHistory.email == email).count()
        elif ip_address:
            fail_count = fail_query.filter(LoginHistory.ip_address == ip_address).count()
        else:
            fail_count = 0

        if fail_count >= 3:
            signals.append("REPEATED_FAILED_LOGIN")

        # Check rapid login attempts from same IP
        if ip_address:
            recent_rapid = session.query(LoginHistory).filter(
                LoginHistory.ip_address == ip_address,
                LoginHistory.login_timestamp >= five_secs_ago
            ).count()
            if recent_rapid >= 2:
                signals.append("RAPID_LOGIN_ATTEMPTS")

        # Check multiple IPs in last 1 hour
        if user_id:
            recent_ips = session.query(LoginHistory.ip_address).filter(
                LoginHistory.user_id == user_id,
                LoginHistory.login_timestamp >= one_hour_ago
            ).distinct().all()
            if len(recent_ips) >= 2:
                signals.append("MULTIPLE_IPS")

        # Suspicious pattern combination
        if ("NEW_COUNTRY" in signals and "NEW_DEVICE" in signals) or ("REPEATED_FAILED_LOGIN" in signals and "NEW_IP" in signals):
            signals.append("SUSPICIOUS_LOGIN_PATTERN")

        # Calculate score and level
        score = len(signals) * 20
        if "SUSPICIOUS_LOGIN_PATTERN" in signals:
            score += 30
        if "REPEATED_FAILED_LOGIN" in signals:
            score += 20

        score = min(100, score)

        if score >= 75:
            level = "CRITICAL"
        elif score >= 50:
            level = "HIGH"
        elif score >= 25:
            level = "MEDIUM"
        else:
            level = "LOW"

        return score, level, signals
    finally:
        session.close()


def record_login_history(
    user_id=None,
    email=None,
    username=None,
    auth_method="PASSWORD",
    provider_user_id=None,
    status="SUCCESS",
    ip_address=None,
    user_agent_str=None,
    failure_reason=None,
    session_id=None,
):
    """
    Records an authentication attempt in the login_history table.
    Enforces security: no raw passwords/tokens stored.
    """
    import hashlib
    from auth.device_detector import parse_user_agent
    from auth.geoip_helper import resolve_ip_location
    from auth.security_notifier import dispatch_security_event

    dev_info = parse_user_agent(user_agent_str)
    geo_info = resolve_ip_location(ip_address)

    # Risk evaluation
    risk_score, risk_level, risk_signals = evaluate_user_login_risk(
        user_id=user_id,
        ip_address=ip_address,
        browser=dev_info["browser"],
        operating_system=dev_info["operating_system"],
        device_type=dev_info["device_type"],
        country=geo_info["country"],
        email=email,
    )

    sess_hash = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:64] if session_id else None

    history_entry = LoginHistory(
        user_id=user_id,
        email=email,
        username=username,
        authentication_method=auth_method,
        provider_user_id=provider_user_id,
        login_timestamp=utc_now(),
        login_status=status,
        ip_address=ip_address or "127.0.0.1",
        user_agent=(user_agent_str or "unknown")[:500],
        browser=dev_info["browser"],
        browser_version=dev_info["browser_version"],
        operating_system=dev_info["operating_system"],
        device_type=dev_info["device_type"],
        device_name=dev_info["device_name"],
        country=geo_info["country"],
        region=geo_info["region"],
        city=geo_info["city"],
        session_id_hash=sess_hash,
        failure_reason=failure_reason,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_signals=json.dumps(risk_signals),
    )

    session = _get_session()
    try:
        session.add(history_entry)
        session.commit()
        session.refresh(history_entry)
        record_dict = history_entry.to_dict()

        # Trigger notification events for high risk or new device/IP signals
        if risk_level in ("HIGH", "CRITICAL") or any(s in risk_signals for s in ["NEW_DEVICE", "NEW_IP", "SUSPICIOUS_LOGIN_PATTERN", "REPEATED_FAILED_LOGIN"]):
            event_type = "SUSPICIOUS_LOGIN" if "SUSPICIOUS_LOGIN_PATTERN" in risk_signals or risk_level in ("HIGH", "CRITICAL") else ("NEW_DEVICE_LOGIN" if "NEW_DEVICE" in risk_signals else "NEW_IP_LOGIN")
            dispatch_security_event(event_type, record_dict)

        return record_dict
    except Exception as exc:
        session.rollback()
        return None
    finally:
        session.close()


def get_login_history(
    user_id=None,
    limit=50,
    offset=0,
    status=None,
    method=None,
    date_from=None,
    date_to=None,
    search=None,
):
    """Retrieves paginated login history items."""
    session = _get_session()
    try:
        query = session.query(LoginHistory)
        if user_id is not None:
            query = query.filter(LoginHistory.user_id == user_id)
        if status:
            query = query.filter(LoginHistory.login_status.ilike(status.strip()))
        if method:
            query = query.filter(LoginHistory.authentication_method.ilike(method.strip()))
        if date_from:
            try:
                dt_from = datetime.fromisoformat(date_from)
                query = query.filter(LoginHistory.login_timestamp >= dt_from)
            except Exception:
                pass
        if date_to:
            try:
                dt_to = datetime.fromisoformat(date_to)
                query = query.filter(LoginHistory.login_timestamp <= dt_to)
            except Exception:
                pass
        if search:
            term = f"%{search.strip()}%"
            query = query.filter(
                (LoginHistory.username.ilike(term)) |
                (LoginHistory.email.ilike(term)) |
                (LoginHistory.ip_address.ilike(term)) |
                (LoginHistory.browser.ilike(term)) |
                (LoginHistory.operating_system.ilike(term))
            )

        total = query.count()
        items = query.order_by(LoginHistory.login_timestamp.desc()).offset(offset).limit(limit).all()
        return {
            "items": [item.to_dict() for item in items],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    finally:
        session.close()


def get_user_login_history(user_id, limit=50, offset=0):
    """Retrieves login history for a specific user ID."""
    return get_login_history(user_id=user_id, limit=limit, offset=offset)


def get_security_activity_summary(user_id=None):
    """
    Computes backend aggregate security activity summary metrics:
    - total_logins
    - successful_logins
    - failed_logins
    - blocked_logins
    - unique_ips
    - unique_devices
    - last_successful_login
    - last_failed_login
    - most_used_method
    - new_device_count
    - suspicious_login_count
    """
    session = _get_session()
    try:
        query = session.query(LoginHistory)
        if user_id is not None:
            query = query.filter(LoginHistory.user_id == user_id)

        all_records = query.all()
        total_logins = len(all_records)
        successful_logins = len([r for r in all_records if r.login_status == "SUCCESS"])
        failed_logins = len([r for r in all_records if r.login_status == "FAILED"])
        blocked_logins = len([r for r in all_records if r.login_status == "BLOCKED"])

        unique_ips = len({r.ip_address for r in all_records if r.ip_address})
        unique_devices = len({(r.device_type, r.operating_system, r.browser) for r in all_records if r.device_type and r.operating_system})

        success_records = [r for r in all_records if r.login_status == "SUCCESS" and r.login_timestamp]
        failed_records = [r for r in all_records if r.login_status in ("FAILED", "BLOCKED") and r.login_timestamp]

        last_success = max([r.login_timestamp for r in success_records]).isoformat() if success_records else None
        last_failed = max([r.login_timestamp for r in failed_records]).isoformat() if failed_records else None

        methods = {}
        new_device_count = 0
        suspicious_count = 0

        for r in all_records:
            m = r.authentication_method or "PASSWORD"
            methods[m] = methods.get(m, 0) + 1

            signals = []
            if r.risk_signals:
                try:
                    signals = json.loads(r.risk_signals) if isinstance(r.risk_signals, str) else r.risk_signals
                except Exception:
                    signals = [s.strip() for s in str(r.risk_signals).split(",")]

            if "NEW_DEVICE" in signals:
                new_device_count += 1
            if r.risk_level in ("HIGH", "CRITICAL") or "SUSPICIOUS_LOGIN_PATTERN" in signals:
                suspicious_count += 1

        most_used_method = max(methods.items(), key=lambda x: x[1])[0] if methods else "None"

        return {
            "total_logins": total_logins,
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "blocked_logins": blocked_logins,
            "unique_ips": unique_ips,
            "unique_devices": unique_devices,
            "last_successful_login": last_success,
            "last_failed_login": last_failed,
            "most_used_method": most_used_method,
            "new_device_count": new_device_count,
            "suspicious_login_count": suspicious_count,
        }
    finally:
        session.close()


def purge_old_login_history(days=None):
    """Optional retention purging for login history records older than given days."""
    if not days or days <= 0:
        return 0
    session = _get_session()
    try:
        cutoff = utc_now() - timedelta(days=days)
        deleted_count = session.query(LoginHistory).filter(LoginHistory.login_timestamp < cutoff).delete()
        session.commit()
        return deleted_count
    except Exception:
        session.rollback()
        return 0
    finally:
        session.close()


def record_security_notification(
    event_type,
    user_id=None,
    email=None,
    risk_score=0,
    risk_level="LOW",
    channel="TELEGRAM",
    status="PENDING",
    failure_reason_safe=None,
    correlation_id=None,
):
    """Records a notification dispatch attempt in security_notifications."""
    session = _get_session()
    try:
        sent_time = utc_now() if status == "SENT" else None
        notif = SecurityNotification(
            correlation_id=correlation_id,
            event_type=event_type,
            user_id=user_id,
            email=email,
            risk_score=risk_score,
            risk_level=risk_level,
            channel=channel,
            status=status,
            failure_reason_safe=failure_reason_safe,
            created_at=utc_now(),
            sent_at=sent_time,
        )
        session.add(notif)
        session.commit()
        session.refresh(notif)
        return notif.to_dict()
    except Exception:
        session.rollback()
        return None
    finally:
        session.close()


def get_security_notifications(limit=50, offset=0, channel=None, status=None):
    """Retrieves paginated security notification history records."""
    session = _get_session()
    try:
        query = session.query(SecurityNotification)
        if channel:
            query = query.filter(SecurityNotification.channel.ilike(channel.strip()))
        if status:
            query = query.filter(SecurityNotification.status.ilike(status.strip()))

        total = query.count()
        items = query.order_by(SecurityNotification.created_at.desc()).offset(offset).limit(limit).all()
        return {
            "items": [item.to_dict() for item in items],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    finally:
        session.close()


