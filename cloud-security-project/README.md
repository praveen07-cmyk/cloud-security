# AI-Powered Cloud Security Analytics and Intelligent Threat Response Platform

A beginner-friendly, upgraded mini SOC (Security Operations Center) dashboard
built with Flask. It ships with 4 fixed demo incidents so the UI works immediately
— no live traffic, no random data, no ML training required to get started.

---

## Overview

This project simulates a cloud security monitoring platform: a SOC analyst logs in,
sees active threats on a dashboard, investigates individual IPs, reviews analytics,
and exports reports. The platform now includes SQLite-backed incident storage and
user authentication, while still keeping the demo experience lightweight. The "AI"
layer today is a deterministic **rule-based** risk engine and recommendation
engine — the project also includes a full ML training pipeline
(RandomForestClassifier) ready to plug in a real dataset later.

For a feature-by-feature implementation view, see [FEATURE_MATRIX.md](FEATURE_MATRIX.md).

---

## Features

- SQLite-backed login flow with seeded demo credentials
- Remember me option and password visibility toggle on login
- Dashboard with security score, threat score, active threats, risk level, packet counter, and health/status cards
- Live Traffic, Attack Distribution, Severity Gauge, and Threat Heatmap widgets
- Recent Alerts table + Recent Activity feed + Quick Actions
- AI Assistant recommendation panel (rule-based today, ML-ready)
- Full investigation page per IP: reputation, business risk, recommendations, timeline
- Analytics page: weekly trend, attack type, severity, and status charts
- Reports page: real PDF export (ReportLab) and real CSV export
- Settings & Profile pages
- Dark / light theme toggle, toasts, counter + chart animations
- ML training scaffold for CICIDS2017 / CSE-CIC-IDS2018 / NSL-KDD datasets
- Safe Scapy packet-capture placeholder (not active by default)
- SQLite incident store and user auth foundation

---

## Tech Stack

**Frontend:** HTML5, CSS3, Bootstrap 5, Bootstrap Icons, JavaScript, Chart.js
**Backend:** Python, Flask, Flask-SocketIO
**ML:** Scikit-learn, Pandas, NumPy, Joblib
**Database:** SQLite
**Reports:** ReportLab
**Cybersecurity:** Scapy (placeholder)

---

## Security Notes

- Frontend code cannot be fully hidden in a Flask app because templates, CSS, and JavaScript are delivered to the browser.
- Real protection is enforced on the backend through authentication, route protection, session security, input validation, and security headers.
- Demo-only frontend deterrents such as right-click or F12 warnings are only cosmetic and should not be treated as security controls.

---

## Project Structure

```
cloud-security-project/
├── app.py                     # Main Flask app (routes, SocketIO, demo data)
├── requirements.txt
├── README.md
├── .gitignore
│
├── frontend/
│   ├── templates/              # Jinja2 HTML templates
│   └── static/
│       ├── css/                # style.css, login.css, dashboard.css
│       └── js/                 # dashboard.js
│
├── analytics/
│   ├── risk_engine.py           # Risk score + business impact
│   ├── recommendation_engine.py # AI recommendation text
│   ├── ip_reputation.py         # IP reputation logic
│   └── security_score.py        # Overall security score
│
├── ml/
│   ├── train_model.py          # Train RandomForestClassifier on a real dataset
│   ├── preprocess.py           # Cleaning / feature-label split helpers
│   └── predict.py              # Loads trained model if available (graceful fallback)
│
├── models/                     # rf_model.pkl goes here after training
├── datasets/                   # Place your training CSV here
├── packet_capture/
│   └── sniffer.py              # Safe Scapy placeholder (not active)
├── database/
│   └── db.py                   # SQLite incident storage and auth helpers
└── reports/
    └── generate_pdf.py         # Real ReportLab PDF generator
```

---

## Setup Steps

1. Make sure Python 3.9+ is installed.
2. Open this folder in VS Code.
3. Install dependencies:

   ```
   py -m pip install -r requirements.txt
   ```

## Run Steps

```
py app.py
```

Then open your browser at:

```
http://127.0.0.1:5000
```

### Demo Credentials

```
Username: admin
Password: admin
```

---

## Demo Data

The dashboard uses exactly 4 fixed demo incidents (no random generation):

| Time  | Source IP       | Attack Type    | Severity | Assigned To |
|-------|-----------------|----------------|----------|-------------|
| 10:15 | 192.168.1.45    | Brute Force    | Critical | Praveen     |
| 10:18 | 172.16.0.22     | Port Scan      | Medium   | Sanjay      |
| 10:21 | 203.0.113.12    | SQL Injection  | High     | Sai Nathan  |
| 10:25 | 198.51.100.21   | DDoS           | Critical | Faran       |

---

## ML Training Steps (Optional)

The dashboard works fully without training a model. To enable real ML predictions:

1. Download a network intrusion dataset:
   - **CICIDS2017** — https://www.unb.ca/cic/datasets/ids-2017.html
   - **CSE-CIC-IDS2018** — https://www.unb.ca/cic/datasets/ids-2018.html
   - **NSL-KDD** — https://www.unb.ca/cic/datasets/nsl.html

2. Place the CSV file inside the `datasets/` folder. It must contain a
   `Label` or `label` column.

3. Run the training script:

   ```
   py ml/train_model.py
   ```

   This cleans the data, trains a `RandomForestClassifier`, prints
   accuracy/precision/recall/F1-score, and saves the model to
   `models/rf_model.pkl`.

4. Restart the app — `ml/predict.py` will automatically detect and load
   the trained model.

---

## Future Enhancements

- Wire Flask-SocketIO to push live incident updates instead of only fixed demo data
- Expand the SQLite foundation into a multi-user incident workflow with RBAC and audit logs
- Enable real (opt-in, authorized) packet capture using the Scapy sniffer module
- Add real external IP reputation lookups (e.g. AbuseIPDB, VirusTotal APIs)
- Add role-based access control per SOC team member
- Add scheduled/automated PDF report generation and email delivery
- Integrate a real LLM-based recommendation assistant

---

## Notes

- This is a **demo/educational** project. The login system, database, and packet
  capture are intentionally simplified placeholders — do not deploy this as-is
  to a production environment without adding proper authentication, secrets
  management, and input validation.
