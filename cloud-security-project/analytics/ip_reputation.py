"""
ip_reputation.py
------------------------------------------------
Estimates a reputation label for a source IP
based on how many times it has been seen in the
incident list, and the severity of those incidents.

Labels: "Unknown", "Suspicious", "Dangerous"

This is deterministic/rule-based so it works
immediately without any external threat-intel feed.
A real implementation could later call an external
IP reputation API (e.g. AbuseIPDB, VirusTotal).
------------------------------------------------
"""

SEVERITY_SCORE = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


def get_ip_reputation(source_ip, all_incidents):
    """
    Determine reputation of an IP based on the demo incident list.

    Args:
        source_ip (str): the IP address to look up.
        all_incidents (list[dict]): list of incident records.

    Returns:
        dict: { "reputation": str, "attack_count": int, "score": int }
    """
    matching = [i for i in all_incidents if i.get("source_ip") == source_ip]
    attack_count = len(matching)

    severity_total = sum(SEVERITY_SCORE.get(i.get("severity"), 1) for i in matching)

    if attack_count == 0:
        reputation = "Unknown"
    elif severity_total >= 4 or attack_count >= 3:
        reputation = "Dangerous"
    elif severity_total >= 2 or attack_count >= 1:
        reputation = "Suspicious"
    else:
        reputation = "Unknown"

    severity_history = [i.get("severity", "Unknown") for i in matching]
    last_seen = matching[-1].get("time") if matching else "Never"

    return {
        "reputation": reputation,
        "status": reputation if reputation != "Unknown" else "Unknown",
        "attack_count": attack_count,
        "score": severity_total,
        "country": "Unknown",
        "last_seen": last_seen,
        "severity_history": severity_history,
        "future_integrations": ["AbuseIPDB", "VirusTotal", "OTX"],
    }


if __name__ == "__main__":
    demo_incidents = [
        {"source_ip": "1.1.1.1", "severity": "Critical"},
        {"source_ip": "1.1.1.1", "severity": "High"},
    ]
    print(get_ip_reputation("1.1.1.1", demo_incidents))
