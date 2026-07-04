"""
recommendation_engine.py
------------------------------------------------
Returns a list of recommended response actions
for a given attack type. This powers the
"AI Assistant Recommendation Panel" on the
dashboard and investigation page.

This is a rule-based knowledge base today.
It can later be replaced/augmented by a real
ML or LLM based recommendation model.
------------------------------------------------
"""

RECOMMENDATIONS = {
    "Brute Force": [
        "Block the source IP at the firewall / security group immediately.",
        "Enforce account lockout after repeated failed login attempts.",
        "Enable multi-factor authentication (MFA) on the targeted account.",
        "Review authentication logs for other affected accounts.",
    ],
    "Port Scan": [
        "Flag the source IP for monitoring - not always malicious.",
        "Close unused ports on the target host.",
        "Enable rate-limiting on network scanning attempts.",
        "Verify no follow-up exploitation attempts occurred from the same IP.",
    ],
    "SQL Injection": [
        "Block the source IP and isolate the affected application server.",
        "Patch the vulnerable endpoint and use parameterized queries.",
        "Enable a Web Application Firewall (WAF) rule for SQLi patterns.",
        "Audit the database for unauthorized data access or changes.",
    ],
    "DDoS": [
        "Activate DDoS protection / traffic scrubbing service.",
        "Enable auto-scaling to absorb legitimate traffic spikes.",
        "Rate-limit or geo-block traffic from the offending source range.",
        "Notify the cloud provider's network security / NOC team.",
    ],
}

DEFAULT_RECOMMENDATION = [
    "Escalate to the on-call security analyst for manual review.",
    "Capture relevant logs for forensic analysis.",
]


def get_recommendations(attack_type):
    """Return a list of recommended actions for the given attack type."""
    return RECOMMENDATIONS.get(attack_type, DEFAULT_RECOMMENDATION)


if __name__ == "__main__":
    print(get_recommendations("DDoS"))
