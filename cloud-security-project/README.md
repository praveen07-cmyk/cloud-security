# AI-Powered Cloud Security Analytics and Intelligent Threat Response Platform

Enterprise-style Flask SOC platform for cloud security analytics, threat investigation, reporting, upload-based prediction, audit logging, and role-based access control.

The application keeps the original Flask architecture and UI pages while adding enterprise-ready foundations around SQLite storage, RBAC, audit trails, ML model metadata, CSV/PCAP upload processing, and security hardening.

## Current Capabilities

- Flask dashboard, analytics, investigation, reports, settings, profile, upload center, and audit logs pages
- Compliance & Trust Center page for demo-ready security posture and compliance summaries
- SQLite database stored at `database/security_platform.db`
- Seeded SOC users with Werkzeug password hashing
- Flask-Login authentication, remember me, secure cookie settings, session protection, and login rate limiting
- Firebase Authentication premium login options for Google and GitHub
- Role-based route protection
- CSRF validation for POST requests
- Security headers and content security policy
- Four fixed demo incidents for demo mode
- CSV upload flow for IDS datasets
- PCAP upload flow using Scapy when available
- Random Forest training pipeline with preprocessing, scaling, model saving, metrics, confusion matrix, and model version metadata
- Rule-based fallback when no trained model is available
- Business risk scoring, IP reputation, recommendations, and investigation timeline
- PDF and CSV report export
- Audit logging for login, logout, failed login, dashboard access, investigations, uploads, report generation, and access denial
- Dark glossy theme, light theme, glassmorphism cards, charts, animations, responsive layout, and dashboard quick actions

## Setup

1. Install Python 3.9 or newer.
2. Open this folder:

   ```powershell
   cd cloud-security-project
   ```

3. Verify Python and pip are available:

   ```powershell
   py --version
   py -m pip --version
   ```

4. Install dependencies:

   ```powershell
   py -m pip install -r requirements.txt
   ```

5. Run the app:

   ```powershell
   py app.py
   ```

6. Open:

   ```text
   http://127.0.0.1:5000
   ```

## Manual Verification

Run these commands before pushing to GitHub or sharing the project:

```powershell
py --version
py -m pip --version
py -m pip install -r requirements.txt
py app.py
```

Expected result: Flask starts at `http://127.0.0.1:5000`, the login page opens, and `admin/admin` can access the dashboard.

## Python Troubleshooting

### `pip is not recognized`

Use pip through the Python launcher instead:

```powershell
py -m pip install -r requirements.txt
```

If that still fails, install Python from `python.org`, select **Add Python to PATH**, then reopen the terminal.

### `python is not recognized`

Use the Windows Python launcher:

```powershell
py --version
py app.py
```

If `py --version` also fails, Python is not installed correctly. Install Python 3.9 or newer, then reopen PowerShell.

### `py app.py` not working

Check these items in order:

```powershell
py --version
py -m pip --version
py -m pip install -r requirements.txt
py app.py
```

Also confirm you are running the command from the `cloud-security-project` folder that contains `app.py`.

## Default Users

| Username | Password | Role |
| --- | --- | --- |
| admin | admin | Administrator |
| praveen | praveen123 | SOC Analyst |
| sanjay | sanjay123 | Cloud Administrator |
| sainathan | sainathan123 | Threat Analyst |
| faran | faran123 | Security Engineer |
| kowshika | kowshika123 | SOC Manager |

## Firebase Authentication Setup

The existing Flask username/password login remains active. Firebase Google and GitHub login is optional and future-ready. Until valid Firebase web config values are added, the login buttons show a graceful message: `Firebase OAuth is not configured yet.`

1. Create a Firebase project in the Firebase Console.
2. Open Authentication and enable the Google provider.
3. Enable the GitHub provider and configure the GitHub OAuth client ID and secret in Firebase.
4. Open `frontend/static/js/firebase-auth.js` and replace the placeholder `firebaseConfig` values with your Firebase web app config.
5. In Firebase project settings, download the Admin SDK service account JSON.
6. Store it locally at the project root as:

   ```text
   firebase-service-account.json
   ```

7. Keep `firebase-service-account.json` out of Git. It is already listed in `.gitignore`.

Optional environment variable:

```powershell
set FIREBASE_SERVICE_ACCOUNT_PATH=C:\path\to\firebase-service-account.json
```

After a successful Firebase login, the frontend sends the Firebase ID token to `/firebase-login`. Flask verifies the token with Firebase Admin SDK, stores the Firebase UID, email, name, and provider in SQLite if needed, creates the normal Flask-Login session, and redirects to `/dashboard`.

## Input Modes

### Demo Mode

The platform seeds exactly four fixed demo incidents:

| Time | Source IP | Attack Type | Severity | Assigned To |
| --- | --- | --- | --- | --- |
| 10:15 | 192.168.1.45 | Brute Force | Critical | Praveen |
| 10:18 | 172.16.0.22 | Port Scan | Medium | Sanjay |
| 10:21 | 203.0.113.12 | SQL Injection | High | Sai Nathan |
| 10:25 | 198.51.100.21 | DDoS | Critical | Faran |

No random incident data is generated.

### CSV Upload

Use Upload Center to upload IDS CSV datasets. The system cleans the dataset, extracts model features, runs prediction when a trained model exists, and creates prediction incidents for dashboard review.

### PCAP Upload

Use Upload Center to upload `.pcap` or `.pcapng` files. The system parses packet metadata with Scapy when available and runs prediction through the same model path.

## Machine Learning

Train a Random Forest model:

```powershell
py ml/train_model.py --file datasets/your_dataset.csv
```

The training pipeline performs:

- Dataset loading
- Missing value handling
- Feature encoding
- Scaling
- Train/test split
- Random Forest training
- Accuracy, Precision, Recall, F1 Score
- Confusion Matrix
- ROC Curve for binary datasets
- Model version metadata
- Model saving to `models/rf_model.pkl`

The Analytics page displays the latest model metrics when available.

## Database Schema

SQLite tables are created automatically by `init_db()`:

- `users`
- `threat_incidents`
- `audit_logs`
- `reports`
- `settings`
- `incident_timeline`
- `business_risk`
- `model_versions`
- `notifications`
- `ip_reputation`
- `assets`
- `roles`
- `permissions`

## RBAC

Supported roles:

- Administrator
- SOC Manager
- SOC Analyst
- Threat Analyst
- Security Engineer
- Cloud Administrator
- Read Only Analyst

Protected resources:

- Dashboard
- Analytics
- Reports
- Settings
- Profile
- Investigation
- Upload Center
- Audit Logs

## Security Hardening

Implemented security controls:

- Flask-Login authentication
- Werkzeug password hashing
- Account lockout after repeated failed login attempts
- Temporary IP-based login blocking for brute-force bursts
- CSRF validation
- Secure session settings
- Environment variable support through `.env`
- Login, upload, and API rate limiting
- Input validation
- SQLAlchemy query layer
- Security HTTP headers
- Configurable HSTS for production HTTPS
- Permissions Policy
- Content Security Policy
- Custom 403, 404, 405, 429, and 500 error handling
- Audit logging
- Rotating application, security, audit, and error logs
- Upload extension, filename, and size controls
- Health check endpoint
- Admin-only security status endpoint
- Admin-only SQLite backup route

### Authentication

The platform keeps local Flask username/password login and Firebase Google/GitHub login. Local passwords are hashed before storage. Login failure messages intentionally do not reveal whether the username or password was incorrect. Repeated failures temporarily lock the account and can temporarily block the source IP.

### RBAC

Routes are protected with Flask-Login plus role/permission decorators. Administrators have full access. SOC Managers can view audit logs. Database backup and `/security-status` are Administrator-only. Other SOC users receive access based on their seeded role permissions.

### CSRF

Forms use CSRF tokens through Flask-WTF. JSON authentication endpoints are explicitly controlled and rate limited.

### Rate Limiting

Flask-Limiter protects login, uploads, health checks, Firebase login, and API-style routes from repeated abuse.

### Audit Logs

Audit logs store timestamp, user id, username, action, route, IP address, user agent, status, and details. Login, logout, failed login, route access denial, dashboard access, investigations, uploads, report generation, suspicious requests, database backups, security status views, health checks, and CSRF failures are recorded.

### File Upload Safety

Uploads are stored in `uploads/`, not executed, and are restricted to `.csv`, `.pcap`, and `.pcapng`. Filenames are sanitized with `secure_filename`, path traversal is rejected, and Flask enforces the configured maximum upload size.

### Error Handling

The app shows clean SOC-themed error pages instead of Python tracebacks. Internal errors are written to `logs/error.log`, and security events are written to `logs/security.log`.

### Input Validation

Login fields, IP investigation routes, uploads, and report actions are validated before use. SQLAlchemy ORM queries are used for database access, which keeps database inputs parameterized and avoids raw SQL for normal operations.

### Environment Variables

Use `.env` for secrets and runtime configuration. Start from `.env.example`. Never commit `.env` or `firebase-service-account.json`.

### HTTPS and Reverse Proxy Readiness

Use HTTPS in production. Set `SESSION_COOKIE_SECURE=True` only after HTTPS is active. Set `ENABLE_HSTS=True` only after HTTPS is working correctly for the final domain. When deploying behind Nginx or Apache, forward the original scheme and client IP headers carefully and only trust proxy headers from your own proxy.

Example production start command:

```powershell
gunicorn --worker-class eventlet -w 1 app:app
```

### WAF Recommendation

Use a web application firewall such as Cloudflare WAF, AWS WAF, Azure Web Application Firewall, or Google Cloud Armor. A WAF should block common injection attempts, suspicious bots, path traversal attempts, and abusive request rates before they reach Flask.

### Server Firewall Checklist

- Allow only required inbound ports such as 80 and 443.
- Restrict SSH/RDP to trusted IP addresses.
- Block direct database access from the internet.
- Keep the operating system and Python runtime patched.
- Monitor failed login and firewall deny events.

### Cloud Monitoring Checklist

- Enable cloud audit logs.
- Monitor failed administrative logins.
- Alert on suspicious API calls.
- Track unusual upload activity.
- Forward app, security, audit, and error logs to a central log platform.

### Backup and Restore Checklist

- Back up `database/security_platform.db` regularly.
- Store backups outside the application folder.
- Encrypt production backups.
- Test restore steps before relying on backups.
- Restrict `/backup-database` to Administrator accounts only.

### Secret Management Checklist

- Use a strong `SECRET_KEY`.
- Do not commit `.env`, Firebase service accounts, database files, uploads, logs, backups, or trained model files.
- Rotate secrets after exposure or staff changes.
- Prefer cloud secret managers for production.
- Keep Firebase Admin credentials outside the repository.

### Production Deployment Checklist

- Use HTTPS.
- Enable HSTS only after HTTPS is working.
- Use a WAF such as Cloudflare or cloud provider WAF.
- Use server firewall rules.
- Set `DEBUG=False`.
- Use a strong `SECRET_KEY`.
- Rotate secrets regularly.
- Set `SESSION_COOKIE_SECURE=True`.
- Back up the database regularly.
- Monitor `logs/app.log`, `logs/security.log`, `logs/audit.log`, and `logs/error.log`.
- Remove demo passwords before public deployment.
- Review CSP domains before adding new CDNs or integrations.

Frontend code cannot be fully hidden because HTML, CSS, and JavaScript are delivered to the browser. Real protection must be enforced on the backend through authentication, RBAC, validation, CSRF protection, rate limiting, and secure session handling.

Future-ready authentication integrations:

- Google OAuth
- GitHub OAuth
- Microsoft Azure AD

## Reporting

Available reports:

- PDF incident report
- CSV incident export
- Report placeholders for daily, weekly, monthly, executive, incident, threat, and business reporting

## Compliance & Trust Center

The `/trust-center` page provides a demo-friendly trust portal with security controls, access control summary, audit logging status, backup and recovery status, data privacy summary, compliance readiness, report downloads, and risk assessment summary. It uses static demo data and the existing dark/light glossy theme.

## Deployment Readiness

Recommended next deployment steps:

- Add Dockerfile
- Add Docker Compose
- Add production `.env`
- Add GitHub Actions checks
- Configure Render, Railway, AWS EC2, or Azure App Service
- Use a production WSGI server
- Set secure cookie environment variables to `true`

## Documentation

Additional project documents:

- `FEATURE_MATRIX.md`
- `ENTERPRISE_ROADMAP.md`

## Notes

This project is still a local educational SOC platform. It now has enterprise-style architecture foundations, but production deployment still requires real cloud connectors, real SIEM integrations, stronger secret management, formal tests, and operational monitoring.
