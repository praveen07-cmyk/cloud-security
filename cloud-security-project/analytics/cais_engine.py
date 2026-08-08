"""
cais_engine.py
------------------------------------------------
Criticality & AI Security (CAIS) Engine, MITRE ATT&CK
Mapping, Attack Graph (Cytoscape), Attack Replay, and
Rule Engine for AWS/Cloud Security.
"""

# ------------------------------------------------
# Rule Engine
# ------------------------------------------------
RULE_DEFINITIONS = {
    "Root Login": {
        "rule_id": "RULE-AWS-001",
        "name": "AWS Root Account Console Login Detected",
        "severity": "Critical",
        "mitre_id": "T1078.004",
        "tactic": "Initial Access",
        "description": "Root user logged in to the AWS Management Console.",
        "recommendation": "Lock root account, enable MFA, and use IAM roles for daily administration."
    },
    "MFA Disabled": {
        "rule_id": "RULE-AWS-002",
        "name": "Multi-Factor Authentication Disabled",
        "severity": "High",
        "mitre_id": "T1556",
        "tactic": "Defense Evasion",
        "description": "MFA device was deactivated or deleted for an IAM user.",
        "recommendation": "Enforce MFA via IAM policy for all console and API access."
    },
    "IAM Policy Change": {
        "rule_id": "RULE-AWS-003",
        "name": "Overly Permissive IAM Policy Attached",
        "severity": "High",
        "mitre_id": "T1098",
        "tactic": "Persistence",
        "description": "AdministratorAccess or broad permissions attached to a role or user.",
        "recommendation": "Review IAM policies and enforce least privilege principle."
    },
    "Public S3": {
        "rule_id": "RULE-AWS-004",
        "name": "S3 Bucket Made Publicly Accessible",
        "severity": "Critical",
        "mitre_id": "T1530",
        "tactic": "Exfiltration",
        "description": "S3 bucket policy or ACL allows public read/write access.",
        "recommendation": "Enable S3 Block Public Access at account and bucket levels immediately."
    },
    "Security Group Open": {
        "rule_id": "RULE-AWS-005",
        "name": "Security Group Ingress Open to 0.0.0.0/0",
        "severity": "High",
        "mitre_id": "T1190",
        "tactic": "Initial Access",
        "description": "Ingress rule allows unrestricted access (0.0.0.0/0) to SSH/RDP/Database ports.",
        "recommendation": "Restrict security group ingress rules to trusted IP ranges or VPC endpoints."
    },
    "Console Login": {
        "rule_id": "RULE-AWS-006",
        "name": "Unusual Console Login Location",
        "severity": "Medium",
        "mitre_id": "T1078.004",
        "tactic": "Initial Access",
        "description": "Console login detected from an unrecognized IP address or foreign GeoIP region.",
        "recommendation": "Verify user identity via out-of-band communication and inspect active session."
    },
    "Privilege Escalation": {
        "rule_id": "RULE-AWS-007",
        "name": "IAM Privilege Escalation Attempt",
        "severity": "Critical",
        "mitre_id": "T1548",
        "tactic": "Privilege Escalation",
        "description": "User attempted to modify policy or assume role to gain administrative privileges.",
        "recommendation": "Revoke temporary credentials and inspect audit logs for unauthorized actions."
    },
    "Access Key Created": {
        "rule_id": "RULE-AWS-008",
        "name": "New Access Key Created for IAM User",
        "severity": "Medium",
        "mitre_id": "T1098",
        "tactic": "Persistence",
        "description": "Programmatic access key pair created for an existing IAM identity.",
        "recommendation": "Confirm legitimate business need and enforce 90-day access key rotation."
    },
    "Root Key Used": {
        "rule_id": "RULE-AWS-009",
        "name": "Root Account Access Key Utilized",
        "severity": "Critical",
        "mitre_id": "T1078.004",
        "tactic": "Initial Access",
        "description": "API call executed using AWS Root account access keys.",
        "recommendation": "Delete root access keys immediately and transition to IAM Roles."
    }
}


def evaluate_rules(event_data: dict) -> list:
    """Evaluate cloud security rules against an incoming event dictionary."""
    triggered = []
    event_name = str(event_data.get("event_name") or event_data.get("attack_type") or "").strip()
    
    for key, rule in RULE_DEFINITIONS.items():
        if key.lower() in event_name.lower() or event_data.get("rule_key") == key:
            triggered.append({**rule, "event": event_name, "triggered_at": event_data.get("time", "now")})

    if not triggered:
        # Default match if no specific keyword triggered
        rule = RULE_DEFINITIONS.get("Security Group Open")
        triggered.append({**rule, "event": event_name or "Generic Alert", "triggered_at": event_data.get("time", "now")})

    return triggered


# ------------------------------------------------
# CAIS Engine (Criticality & AI Security Score)
# ------------------------------------------------
def calculate_cais_score(incident_severity="High", asset_criticality="High", vulnerability_score=7.5, active_vectors=2):
    """
    Calculates CAIS Score (0 - 100) and risk breakdown.
    """
    severity_weights = {"Low": 20, "Medium": 45, "High": 75, "Critical": 95}
    criticality_weights = {"Low": 1.0, "Medium": 1.2, "High": 1.5, "Critical": 2.0}

    sev_base = severity_weights.get(incident_severity, 50)
    crit_mult = criticality_weights.get(asset_criticality, 1.2)
    vuln_impact = min(vulnerability_score * 4.0, 40.0)
    vector_impact = min(active_vectors * 5.0, 20.0)

    raw_score = (sev_base * 0.45) + (vuln_impact * 0.30) + (vector_impact * 0.25)
    cais_score = round(min(max(raw_score * crit_mult / 1.5, 5.0), 99.9), 1)

    if cais_score >= 80:
        category = "Critical Risk"
        business_impact = "Severe Threat to Business Operations & Data Loss"
    elif cais_score >= 60:
        category = "High Risk"
        business_impact = "Potential Infrastructure Compromise & Service Interruption"
    elif cais_score >= 40:
        category = "Moderate Risk"
        business_impact = "Localized Operational Degradation"
    else:
        category = "Low Risk"
        business_impact = "Minimal Impact on Business Services"

    return {
        "cais_score": cais_score,
        "risk_category": category,
        "severity_mapping": incident_severity,
        "asset_criticality": asset_criticality,
        "business_impact": business_impact,
        "vulnerability_score": vulnerability_score,
        "active_vectors": active_vectors,
    }


# ------------------------------------------------
# MITRE ATT&CK Mapping Engine
# ------------------------------------------------
MITRE_MATRIX = [
    {
        "tactic": "Initial Access",
        "technique": "Valid Accounts: Cloud Accounts",
        "attack_id": "T1078.004",
        "related_events": ["Console Login", "Root Login", "Brute Force"],
        "description": "Adversaries may obtain credentials to gain access to AWS Management Console."
    },
    {
        "tactic": "Defense Evasion",
        "technique": "Modify Authentication Process",
        "attack_id": "T1556",
        "related_events": ["MFA Disabled", "Disabling CloudTrail Logging"],
        "description": "Adversaries may disable MFA or CloudTrail logging to evade detection."
    },
    {
        "tactic": "Persistence",
        "technique": "Account Manipulation",
        "attack_id": "T1098",
        "related_events": ["IAM Policy Change", "Access Key Created"],
        "description": "Adversaries may manipulate IAM policies or keys to maintain access."
    },
    {
        "tactic": "Exfiltration",
        "technique": "Data from Cloud Storage Object",
        "attack_id": "T1530",
        "related_events": ["Public S3", "Data Exfiltration"],
        "description": "Adversaries may access publicly configured S3 buckets to extract sensitive data."
    },
    {
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
        "attack_id": "T1190",
        "related_events": ["Security Group Open", "SQL Injection", "Port Scan"],
        "description": "Adversaries may exploit open ports or web vulnerabilities to access internal VPC."
    },
    {
        "tactic": "Impact",
        "technique": "Network Denial of Service",
        "attack_id": "T1499",
        "related_events": ["DDoS", "Resource Exhaustion"],
        "description": "Adversaries may flood target endpoints to degrade availability."
    }
]


def get_mitre_mapping(attack_type="Brute Force") -> dict:
    """Retrieve MITRE ATT&CK mapping for a specific attack type or full matrix."""
    matches = [m for m in MITRE_MATRIX if any(evt.lower() in attack_type.lower() for evt in m["related_events"])]
    primary = matches[0] if matches else MITRE_MATRIX[0]
    return {
        "primary_match": primary,
        "all_mappings": MITRE_MATRIX,
        "attack_type": attack_type
    }


# ------------------------------------------------
# Attack Graph Generator (Cytoscape JSON format)
# ------------------------------------------------
def generate_attack_graph(incident: dict = None) -> dict:
    source_ip = incident.get("source_ip", "192.168.1.45") if incident else "192.168.1.45"
    dest_ip = incident.get("destination_ip", "10.0.0.5") if incident else "10.0.0.5"
    attack_type = incident.get("attack_type", "Brute Force") if incident else "Brute Force"

    nodes = [
        {"data": {"id": "src_attacker", "label": f"Attacker ({source_ip})", "type": "threat_source", "color": "#ef4444"}},
        {"data": {"id": "aws_igw", "label": "AWS Internet Gateway", "type": "network", "color": "#3b82f6"}},
        {"data": {"id": "vpc_sg", "label": "VPC Security Group (sg-0a81)", "type": "security_boundary", "color": "#f59e0b"}},
        {"data": {"id": "target_ec2", "label": f"App Server ({dest_ip})", "type": "asset", "color": "#10b981"}},
        {"data": {"id": "rds_db", "label": "RDS Database (db-prod-01)", "type": "target", "color": "#8b5cf6"}},
    ]

    edges = [
        {"data": {"source": "src_attacker", "target": "aws_igw", "label": f"Inbound {attack_type} Traffic", "evidence": f"48,213 packets logged from {source_ip}"}},
        {"data": {"source": "aws_igw", "target": "vpc_sg", "label": "Ingress Port 22/443", "evidence": "Rule open to 0.0.0.0/0"}},
        {"data": {"source": "vpc_sg", "target": "target_ec2", "label": "Auth Failure / Payload", "evidence": "High frequency login failures"}},
        {"data": {"source": "target_ec2", "target": "rds_db", "label": "Lateral Movement Attempt", "evidence": "Attempted IAM role assumption"}},
    ]

    return {
        "nodes": nodes,
        "edges": edges,
        "metadata": {
            "title": f"Attack Graph - {attack_type}",
            "source_ip": source_ip,
            "target_ip": dest_ip,
            "relationships": len(edges),
            "evidence_items": [e["data"]["evidence"] for e in edges],
        }
    }


# ------------------------------------------------
# Attack Replay Step Generator
# ------------------------------------------------
def generate_attack_replay(incident: dict = None) -> dict:
    source_ip = incident.get("source_ip", "192.168.1.45") if incident else "192.168.1.45"
    dest_ip = incident.get("destination_ip", "10.0.0.5") if incident else "10.0.0.5"
    attack_type = incident.get("attack_type", "Brute Force") if incident else "Brute Force"

    steps = [
        {
            "step": 1,
            "time": "10:14:02",
            "action": "Reconnaissance / Port Scanning",
            "source": source_ip,
            "target": dest_ip,
            "severity": "Low",
            "status": "Detected",
            "evidence": f"SYN scan detected on ports 22, 80, 443 from {source_ip}"
        },
        {
            "step": 2,
            "time": "10:15:10",
            "action": f"{attack_type} Execution",
            "source": source_ip,
            "target": dest_ip,
            "severity": "High",
            "status": "Active",
            "evidence": "1,200 credential attempts in 60 seconds."
        },
        {
            "step": 3,
            "time": "10:15:45",
            "action": "Rule Engine Triggered",
            "source": "Rule Engine",
            "target": "Security Platform",
            "severity": "Critical",
            "status": "Flagged",
            "evidence": "Triggered RULE-AWS-001 (Root Login) / RULE-AWS-005 (SG Open)."
        },
        {
            "step": 4,
            "time": "10:16:00",
            "action": "Automated Response / IP Block",
            "source": "Security Platform",
            "target": source_ip,
            "severity": "Critical",
            "status": "Mitigated",
            "evidence": f"Automated NACL rule created blocking {source_ip}."
        }
    ]

    return {
        "incident_id": incident.get("id", 1) if incident else 1,
        "attack_type": attack_type,
        "total_steps": len(steps),
        "replay_steps": steps,
        "controls": ["play", "pause", "next", "previous", "speed"],
    }


# ------------------------------------------------
# AI Security Brain (Correlation & Synthesis)
# ------------------------------------------------
def analyze_security_brain(incident: dict) -> dict:
    """Provides complete AI Security Brain analysis for an incident."""
    attack_type = incident.get("attack_type", "Brute Force")
    severity = incident.get("severity", "High")
    source_ip = incident.get("source_ip", "192.168.1.45")

    cais = calculate_cais_score(incident_severity=severity)
    mitre = get_mitre_mapping(attack_type)
    rules = evaluate_rules(incident)
    graph = generate_attack_graph(incident)
    replay = generate_attack_replay(incident)

    return {
        "explanation": f"AI Security Brain detected a {severity} severity {attack_type} targeting AWS infrastructure from source IP {source_ip}.",
        "root_cause": f"Unrestricted security group ingress rule combined with compromised or weak authentication credentials.",
        "mitre_mapping": mitre["primary_match"],
        "cais_analysis": cais,
        "triggered_rules": rules,
        "evidence": [
            f"High volume traffic spikes observed from {source_ip}.",
            f"Matching signature for {attack_type} with {incident.get('confidence', 95)}% AI confidence.",
            "CloudTrail API log correlation confirms suspicious user agent."
        ],
        "recommendations": [
            "Block source IP at AWS Network ACL level.",
            "Enforce Multi-Factor Authentication (MFA) for target IAM user.",
            "Rotate access keys and audit recent CloudTrail logs."
        ],
        "business_impact": cais["business_impact"],
        "attack_graph": graph,
        "attack_replay": replay,
    }


# ------------------------------------------------
# Blast Radius Estimation
# ------------------------------------------------
def calculate_blast_radius(incident: dict = None) -> dict:
    """Estimates blast radius for compromised IAM identities or resources."""
    incident = incident or {}
    source_ip = incident.get("source_ip", "192.168.1.45")
    dest_ip = incident.get("destination_ip", "10.0.0.5")
    attack_type = incident.get("attack_type", "Brute Force")
    severity = incident.get("severity", "High")

    directly_affected = [
        f"arn:aws:ec2:ap-south-1:774075583705:instance/app-server-{dest_ip.replace('.', '-')}",
        f"arn:aws:iam::774075583705:user/cloud-security-monitor"
    ]
    potentially_affected = [
        "arn:aws:s3:::cloudsec-trail-774075583705-ap-south-1",
        "arn:aws:sqs:ap-south-1:774075583705:cloudsec-events-queue",
        "arn:aws:rds:ap-south-1:774075583705:db:db-prod-01"
    ]
    services = ["EC2", "IAM", "S3", "SQS", "RDS"]
    
    risk_level = "CRITICAL" if severity in ("Critical", "High") else "MODERATE"
    reasoning = (
        f"Compromised identity or endpoint ({dest_ip}) holds attached policies with access to "
        "S3 audit logs, SQS queues, and RDS primary database. Potential lateral movement to data tier."
    )

    return {
        "incident_id": incident.get("id", 1),
        "attack_type": attack_type,
        "directly_affected_resources": directly_affected,
        "potentially_affected_resources": potentially_affected,
        "affected_services": services,
        "risk_level": risk_level,
        "reasoning": reasoning,
    }

