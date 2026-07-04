"""
security_score.py
------------------------------------------------
Calculates an overall "Cloud Security Score" for
the environment, starting from a perfect score of
100 and deducting points based on active incidents
and their severity.
------------------------------------------------
"""

SEVERITY_PENALTY = {
    "Low": 2,
    "Medium": 5,
    "High": 10,
    "Critical": 15,
}


def calculate_security_score(incidents):
    """
    Args:
        incidents (list[dict]): list of incident records,
            each containing a "severity" key.

    Returns:
        int: security score between 0 and 100.
    """
    score = 100

    for incident in incidents:
        severity = incident.get("severity", "Low")
        score -= SEVERITY_PENALTY.get(severity, 2)

    score = max(0, min(100, score))
    return score


def get_risk_level(score):
    """Map a numeric score to a human readable risk level."""
    if score >= 80:
        return "Low"
    elif score >= 60:
        return "Moderate"
    elif score >= 40:
        return "High"
    else:
        return "Critical"


if __name__ == "__main__":
    demo_incidents = [
        {"severity": "Critical"},
        {"severity": "Medium"},
        {"severity": "High"},
        {"severity": "Critical"},
    ]
    s = calculate_security_score(demo_incidents)
    print(s, get_risk_level(s))
