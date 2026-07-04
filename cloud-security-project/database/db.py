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
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, create_engine, inspect
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
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


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
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(160), nullable=False)
    report_type = Column(String(60), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    generated_by = Column(String(120), nullable=False)


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(80), unique=True, nullable=False)
    description = Column(String(255), nullable=False)


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
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
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
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Setting(Base):
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(120), unique=True, nullable=False)
    value = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, nullable=False, index=True)
    event_time = Column(String(40), nullable=False)
    event = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


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
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(160), nullable=False)
    detail = Column(Text, nullable=False)
    severity = Column(String(40), nullable=False)
    is_read = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


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
        "password": "praveen123",
        "full_name": "Praveen",
        "role": "SOC Analyst",
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
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
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
    os.makedirs(DATABASE_DIR, exist_ok=True)
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
    return f"firebase-auth-{seed}-{datetime.utcnow().timestamp()}"


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
        version = metadata.get("version") or datetime.utcnow().strftime("rf-%Y%m%d%H%M%S")
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
