# AI-Powered Cloud Security Analytics and Intelligent Threat Response Platform

Educational IEEE-inspired Flask mini project for cloud security analytics, SOC-style dashboards, threat investigation, reporting, audit logging, upload validation, and machine-learning-assisted prediction.

This repository is prepared for GitHub sharing, Render deployment, and college demonstration. It is not marketed as an enterprise production SIEM; it is a demo platform with production-minded security practices.

## Implemented Features

- Flask dashboard with dark glossy and snow light glossy themes
- Login, logout, secure sessions, and role-based access control
- SOC dashboard cards, charts, tables, notifications, search, profile dropdown, and quick actions
- Threat investigation page with IP validation, risk context, and recommendations
- Analytics page with Chart.js visualizations
- Reports page with PDF and CSV export
- Upload center for CSV and PCAP/PCAPNG validation paths
- Audit logs and security status endpoint
- SQLite database with automatic initialization and seeded demo users/incidents
- Random Forest training and prediction modules with graceful missing-model fallback
- ReportLab PDF generation with safe error handling
- Flask-WTF CSRF protection
- Flask-Limiter rate limiting
- Security headers and custom error pages
- Render-ready startup validation for folders, templates, static files, logs, and database

## Technology Stack

- Python 3.12
- Flask, Flask-Login, Flask-WTF, Flask-Limiter, Flask-SocketIO
- SQLite and SQLAlchemy
- Pandas, NumPy, Scikit-learn, Joblib
- ReportLab
- Bootstrap 5, Bootstrap Icons, Chart.js, JavaScript
- Gunicorn with Eventlet for Render/Linux deployment

## Project Structure

```text
.
├── Procfile
├── requirements.txt
├── runtime.txt
├── LICENSE
├── README.md
└── cloud-security-project/
    ├── app.py
    ├── config.py
    ├── logging_config.py
    ├── analytics/
    ├── database/
    ├── datasets/
    ├── frontend/
    │   ├── static/
    │   └── templates/
    ├── ml/
    ├── models/
    ├── packet_capture/
    ├── reports/
    ├── uploads/
    ├── logs/
    └── backups/
```

## Local Setup

```powershell
cd cloud-security-project
py -m pip install -r requirements.txt
py app.py
```

Open:

```text
http://127.0.0.1:5000
```

Default demo login:

```text
Username: admin
Password: admin
```

## Render Deployment

Use the repository root for Render.

Build command:

```bash
pip install -r requirements.txt
```

Start command is provided by `Procfile`:

```bash
web: cd cloud-security-project && gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:$PORT app:app
```

Required environment variable:

```text
SECRET_KEY=<strong-random-secret>
```

Recommended environment variables:

```text
DEBUG=false
SESSION_COOKIE_SECURE=true
ENABLE_HSTS=true
RATELIMIT_STORAGE_URI=memory://
```

The application creates missing runtime folders and the SQLite database automatically during startup.

## Security Notes

- Do not commit `.env`, SQLite databases, logs, uploaded files, backups, generated PDFs, trained models, or Firebase service account files.
- Replace demo credentials before any public internet deployment.
- Use HTTPS before enabling secure cookies and HSTS.
- Keep `SECRET_KEY` in Render environment variables or another secret manager.
- This project uses SQLite for demo deployment. For sustained multi-user production usage, migrate to a managed database.

## Machine Learning

Train a Random Forest model with:

```powershell
cd cloud-security-project
py ml/train_model.py --file datasets/your_dataset.csv
```

If no trained model exists, the app starts normally and uses a safe fallback response for prediction paths.

## Testing

```powershell
cd cloud-security-project
py -m pytest -q
```

The tests cover authentication protection, security headers, upload validation, backup authorization, health checks, and core runtime behavior.

## Future Enhancements

- Managed PostgreSQL deployment
- Docker and Docker Compose files
- GitHub Actions CI
- Real cloud log connectors
- Real threat intelligence API integration
- Centralized production log forwarding
- More browser-based UI regression tests
- Expanded ML evaluation datasets

## Project Status

Release Candidate 1.0 is suitable for GitHub publication, Render demo deployment, IEEE-inspired mini-project submission, and college demonstration.

It remains an educational demonstration platform and should be hardened further before real enterprise production use.
