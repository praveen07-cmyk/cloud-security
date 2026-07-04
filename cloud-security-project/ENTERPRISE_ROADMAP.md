# Enterprise Improvement Roadmap

This roadmap describes how to grow the current Flask mini-SOC demo into an enterprise-ready cloud security analytics platform. The current project intentionally keeps 4 fixed demo incidents and SQLite-backed storage so the app remains easy to run and present.

## Current Foundation

Implemented or partially implemented today:

- Flask dashboard, analytics, investigation, reports, settings, and profile pages
- SQLite database initialization with seeded users and fixed demo incidents
- Werkzeug password hashing
- Flask-Login session handling
- Rule-based risk scoring and recommendations
- PDF and CSV report export
- ML training scaffold for future Random Forest use
- Safe packet-capture placeholder
- Security headers, input validation, and custom error pages
- Dark/light theme, dashboard charts, heatmap, live clock, activity feed, and quick actions

## Phase 1: Data And Security Foundation

Goal: make the app safer, testable, and easier to extend before adding live threat feeds.

1. Strengthen database models
   - Add audit log, role, permission, asset, and model metadata tables.
   - Add timestamps to incidents and reports.
   - Add status history for incident resolution.
   - Keep SQLite for local demo mode.

2. Role-based access control
   - Implement roles: Administrator, SOC Manager, Security Engineer, Threat Analyst, Cloud Administrator, Read-Only Analyst.
   - Protect dashboard, investigation, reports, analytics, and settings by permission.
   - Add route decorators such as `@role_required()` and `@permission_required()`.

3. Audit logging
   - Record login, logout, failed login, dashboard access, investigation access, report export, and settings changes.
   - Add an Audit page for administrators and SOC managers.
   - Store audit records in SQLite.

4. Security hardening
   - Add CSRF protection with Flask-WTF.
   - Move all secrets to `.env`.
   - Enforce secure cookie settings for production.
   - Add rate limiting for login attempts.
   - Keep SQLAlchemy queries parameterized.
   - Improve form validation and error messages.

## Phase 2: Machine Learning Pipeline

Goal: replace the current rule-based-only detection mode with a real trained model path.

1. Dataset support
   - Support CICIDS2017 and NSL-KDD CSV imports.
   - Document required dataset columns.
   - Store raw datasets under `datasets/` and trained models under `models/`.

2. Preprocessing and feature engineering
   - Clean missing, infinite, and invalid values.
   - Encode labels consistently.
   - Normalize or scale numeric features when needed.
   - Save feature column order with the model bundle.

3. Training and evaluation
   - Train a Random Forest classifier.
   - Calculate Accuracy, Precision, Recall, F1-Score, and Confusion Matrix.
   - Save model artifacts with version, timestamp, dataset name, feature list, and metrics.

4. Analytics integration
   - Display latest model version and metrics on the Analytics page.
   - Show confusion matrix as a chart.
   - Show whether the app is running in rule-based mode or trained-model mode.

## Phase 3: Real-Time Threat Data Ingestion

Goal: support controlled live and file-based network security data ingestion.

1. Packet capture
   - Add opt-in Scapy or PyShark capture behind explicit authorization.
   - Restrict interface selection and capture duration.
   - Never run live capture automatically on app startup.

2. File imports
   - Add PCAP import.
   - Add CSV network log import.
   - Validate file type, size, and schema before processing.

3. Feature extraction
   - Convert packets and logs into the same feature schema used by the ML model.
   - Store imported records and prediction results.
   - Feed features into `ml/predict.py`.

## Phase 4: Cloud Security Monitoring

Goal: prepare multi-cloud connectors without coupling the UI to one provider.

1. Connector architecture
   - Add a `connectors/` package.
   - Define a common event format for cloud alerts.
   - Add provider-specific adapters for AWS, Azure, and Google Cloud.

2. AWS
   - Prepare CloudTrail event ingestion.
   - Track failed console logins, suspicious API calls, IAM changes, and security group changes.

3. Azure
   - Prepare Azure Monitor and Entra ID sign-in event ingestion.
   - Track failed logins, privileged role changes, and suspicious resource operations.

4. Google Cloud
   - Prepare Google Cloud Logging ingestion.
   - Track IAM changes, service account key activity, and suspicious admin actions.

## Phase 5: Enterprise Dashboards And BI

Goal: make operational and executive views useful for different audiences.

1. Executive dashboard
   - Overall Security Score
   - Business Risk Score
   - Open Incidents
   - Critical Systems
   - Cloud Infrastructure Health
   - Security Maturity Index
   - Executive Summary

2. Business intelligence engine
   - Risk Score
   - Business Impact
   - Estimated Downtime
   - Estimated Financial Loss
   - Asset Criticality
   - Incident Priority
   - Recovery Recommendation

3. Investigation module
   - IP reputation
   - Attack timeline
   - Attack chain visualization
   - Future-ready MITRE ATT&CK mapping
   - Incident status
   - Assigned analyst
   - Resolution history

## Phase 6: Reporting And Notification System

Goal: make reporting repeatable and management-friendly.

1. Report types
   - PDF reports
   - CSV reports
   - Daily reports
   - Weekly reports
   - Monthly reports
   - Executive reports

2. Scheduling
   - Store report schedules in the database.
   - Generate reports from stored incidents and audit logs.
   - Keep manual export available.

3. Notifications
   - Add email alerts.
   - Add SMS alerts as a future provider integration.
   - Support alert thresholds by severity and business risk.

## Phase 7: Performance, Testing, And Deployment

Goal: prepare the project for repeatable development and deployment.

1. Performance
   - Lazy-load heavy dashboard data.
   - Optimize database queries.
   - Minify CSS and JavaScript for production.
   - Keep modules small and focused.

2. Automated testing
   - Authentication tests
   - Dashboard route tests
   - Analytics tests
   - Database tests
   - ML prediction tests
   - API endpoint tests

3. Logging
   - Application logs
   - Security logs
   - Error logs
   - Audit logs
   - Use Python's `logging` module with separate log files.

4. Deployment readiness
   - Docker
   - Docker Compose
   - Render
   - Railway
   - AWS EC2
   - Azure App Service
   - GitHub Actions CI/CD

## Phase 8: Advanced Future Enhancements

Long-term roadmap items:

- SIEM integration
- Threat intelligence APIs
- Multi-tenant support
- Continuous ML model retraining
- Multi-cloud monitoring
- AI security assistant
- Zero Trust readiness
- Google OAuth
- GitHub OAuth
- Microsoft Azure AD authentication

## Recommended Implementation Order

1. Add RBAC and audit logging.
2. Add tests for authentication, database helpers, and protected routes.
3. Add model metadata storage and display model metrics in Analytics.
4. Improve the ML preprocessing/training pipeline.
5. Add CSV import before live packet capture.
6. Add PCAP import after CSV import is stable.
7. Add cloud connector interfaces before provider-specific integrations.
8. Add Docker and CI/CD after core tests exist.
