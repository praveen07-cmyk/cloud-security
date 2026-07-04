"""
generate_pdf.py
------------------------------------------------
PDF report generator PLACEHOLDER using ReportLab.

Generates a simple, real PDF summarizing the current
demo incidents. This proves the pipeline works end to
end; a future version can add charts, branding, and
richer formatting.
------------------------------------------------
"""

import os
from datetime import datetime
from collections import Counter

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, "reports")
REPORTLAB_MISSING_MESSAGE = (
    "PDF generation requires ReportLab. Install dependencies using "
    "py -m pip install -r requirements.txt"
)


def generate_incident_report(incidents, output_filename="security_report.pdf"):
    """
    Generate a simple PDF report listing all given incidents.

    Args:
        incidents (list[dict]): incident records.
        output_filename (str): file name to save inside /reports.

    Returns:
        str: full path to the generated PDF.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError as exc:
        raise RuntimeError(REPORTLAB_MISSING_MESSAGE) from exc

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, output_filename)
    styles = getSampleStyleSheet()

    total_incidents = len(incidents)
    critical_incidents = sum(1 for inc in incidents if inc.get("severity") == "Critical")
    high_incidents = sum(1 for inc in incidents if inc.get("severity") == "High")
    blocked_incidents = sum(1 for inc in incidents if inc.get("status") == "Blocked")
    top_attack_type = Counter(inc.get("attack_type", "Unknown") for inc in incidents).most_common(1)
    top_attack_label = top_attack_type[0][0] if top_attack_type else "N/A"

    doc = SimpleDocTemplate(output_path, pagesize=A4)
    elements = []

    title = Paragraph("Cloud Security Analytics - Incident Report", styles["Title"])
    generated_at = Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]
    )
    elements.append(title)
    elements.append(generated_at)
    elements.append(Spacer(1, 16))

    summary = Table(
        [
            ["Total Incidents", "Critical", "High", "Blocked", "Top Attack Type"],
            [str(total_incidents), str(critical_incidents), str(high_incidents), str(blocked_incidents), top_attack_label],
        ],
        repeatRows=1,
    )
    summary.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.HexColor("#EEF2FF")]),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ]
        )
    )
    elements.append(summary)
    elements.append(Spacer(1, 14))

    elements.append(Paragraph("Executive Summary", styles["Heading2"]))
    elements.append(
        Paragraph(
            (
                "This report summarizes the current incident snapshot from the cloud security "
                "platform. Critical and high-severity events should be reviewed first, while "
                "blocked incidents indicate the platform has already contained part of the threat surface."
            ),
            styles["BodyText"],
        )
    )
    elements.append(Spacer(1, 12))

    table_data = [["Time", "Source IP", "Destination IP", "Attack Type", "Severity", "Status"]]
    for inc in incidents:
        table_data.append(
            [
                inc.get("time", ""),
                inc.get("source_ip", ""),
                inc.get("destination_ip", ""),
                inc.get("attack_type", ""),
                inc.get("severity", ""),
                inc.get("status", ""),
            ]
        )

    table = Table(table_data, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F1F5F9")]),
            ]
        )
    )
    elements.append(table)

    doc.build(elements)
    return output_path


if __name__ == "__main__":
    demo_incidents = [
        {
            "time": "10:15",
            "source_ip": "192.168.1.45",
            "destination_ip": "10.0.0.5",
            "attack_type": "Brute Force",
            "severity": "Critical",
            "status": "Investigating",
        }
    ]
    path = generate_incident_report(demo_incidents)
    print(f"[INFO] Report generated at: {path}")
