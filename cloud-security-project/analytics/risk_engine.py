"""
risk_engine.py
------------------------------------------------
Calculates a risk score and business impact summary
for a given security incident.

This is rule-based logic (not ML) so it works
immediately, even before any model is trained.
------------------------------------------------
"""

# Base weight for each attack type (out of 100)
ATTACK_TYPE_WEIGHT = {
    "Brute Force": 70,
    "Port Scan": 40,
    "SQL Injection": 85,
    "DDoS": 90,
}

# Extra weight added based on severity label
SEVERITY_WEIGHT = {
    "Low": 5,
    "Medium": 15,
    "High": 25,
    "Critical": 35,
}

# Rough estimated downtime (in minutes) if attack is not stopped
DOWNTIME_ESTIMATE = {
    "Brute Force": 30,
    "Port Scan": 10,
    "SQL Injection": 90,
    "DDoS": 180,
}

# Rough estimated financial loss per incident (USD) - for demo only
FINANCIAL_LOSS_ESTIMATE = {
    "Brute Force": 5000,
    "Port Scan": 1000,
    "SQL Injection": 25000,
    "DDoS": 50000,
}


def calculate_risk(attack_type, severity, confidence):
    """
    Calculate a risk score (0-100) using attack type, severity
    and detection confidence.

    Returns a dictionary with:
        risk_score, business_impact, priority,
        estimated_downtime, estimated_financial_loss
    """

    base_weight = ATTACK_TYPE_WEIGHT.get(attack_type, 50)
    severity_bonus = SEVERITY_WEIGHT.get(severity, 10)

    # confidence acts as a multiplier (0.0 - 1.0)
    confidence_factor = max(0, min(confidence, 100)) / 100

    raw_score = (base_weight + severity_bonus) * confidence_factor
    risk_score = round(min(raw_score, 100), 1)

    # Decide business impact label from score
    if risk_score >= 80:
        business_impact = "Severe"
        priority = "P1 - Immediate Action"
    elif risk_score >= 60:
        business_impact = "High"
        priority = "P2 - Urgent"
    elif risk_score >= 35:
        business_impact = "Moderate"
        priority = "P3 - Scheduled Review"
    else:
        business_impact = "Low"
        priority = "P4 - Monitor"

    estimated_downtime = DOWNTIME_ESTIMATE.get(attack_type, 15)
    estimated_financial_loss = FINANCIAL_LOSS_ESTIMATE.get(attack_type, 2000)

    return {
        "risk_score": risk_score,
        "business_impact": business_impact,
        "priority": priority,
        "estimated_downtime": f"{estimated_downtime} minutes",
        "estimated_financial_loss": f"${estimated_financial_loss:,}",
    }


if __name__ == "__main__":
    demo = calculate_risk("SQL Injection", "High", 93)
    print(demo)
