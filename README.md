# AI-Powered Cloud Security Analytics & Intelligent Threat Response Platform

> An IEEE-inspired CSBS (Computer Science and Business Systems) mini project that combines **Cloud Computing, Cybersecurity, Machine Learning, Business Analytics, and Secure Web Development** into a modern Security Operations Center (SOC) platform.

---

# Overview

This project is designed to help organizations monitor cybersecurity events, analyze potential threats, assess business risks, investigate suspicious activities, and generate security reports through a professional enterprise-style dashboard.

The application follows a modular architecture using Flask and integrates secure authentication, role-based access control, business risk analysis, and a machine learning pipeline prepared for real-world datasets.

---

# Key Features

## Security Operations Center (SOC) Dashboard
- Enterprise SOC Dashboard
- Security Score
- Threat Score
- Active Threat Monitoring
- Risk Level Indicator
- Cloud Infrastructure Status
- Security Checklist
- AI Recommendation Panel
- Executive Summary
- Recent Alerts
- Recent Activity Feed
- Quick Action Panel
- Live Clock

---

## Threat Investigation

- Threat Details
- IP Reputation Analysis
- Business Risk Assessment
- AI Security Recommendations
- Attack Timeline
- Assigned Analyst
- Incident Status Tracking

---

## Analytics

- Weekly Threat Analysis
- Attack Type Distribution
- Severity Distribution
- Incident Status Analytics
- Interactive Charts
- Trend Analysis

---

## Reports

- Daily Security Reports
- Weekly Reports
- Monthly Reports
- PDF Report Generation (Ready)
- CSV Export (Ready)

---

## Security Features

- Secure Login Authentication
- Password Hashing
- Role-Based Access Control (RBAC)
- Secure Sessions
- CSRF Protection
- Rate Limiting
- Audit Logging
- Security Headers
- Input Validation
- Secure File Upload Validation
- SQLAlchemy ORM
- Safe Error Handling
- Environment Variable Support

---

## Machine Learning

- Random Forest Classifier
- Data Preprocessing
- Model Training Pipeline
- Prediction Module
- Model Version Ready
- Dataset Ready Architecture

---

# Technology Stack

## Frontend

- HTML5
- CSS3
- Bootstrap 5
- Bootstrap Icons
- JavaScript
- Chart.js

## Backend

- Python
- Flask
- Flask-SocketIO
- Flask-Login
- Flask-WTF
- Flask-Limiter

## Database

- SQLite
- SQLAlchemy

## Machine Learning

- Scikit-learn
- Pandas
- NumPy
- Joblib

## Cybersecurity

- Authentication
- Password Hashing
- Audit Logs
- RBAC
- Secure Sessions
- Security Headers
- CSRF Protection
- Input Validation

## Reports

- ReportLab
- CSV Export

---

# Demo Users

| User | Role |
|------|------|
| Praveen | SOC Analyst |
| Sanjay | Cloud Administrator |
| Sai Nathan | Threat Analyst |
| Faran | Security Engineer |
| Kowshika | SOC Manager |

---

# Demo Credentials

```
Username : admin
Password : admin
```

---

# Demo Threat Incidents

| Time | Attack Type | Severity | Assigned To | Status |
|------|-------------|-----------|-------------|---------|
|10:15|Brute Force|Critical|Praveen|Investigating|
|10:18|Port Scan|Medium|Sanjay|Open|
|10:21|SQL Injection|High|Sai Nathan|Investigating|
|10:25|DDoS|Critical|Faran|Blocked|

---

# Project Structure

```text
cloud-security-project/
│
├── app.py
├── config.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── frontend/
│   ├── templates/
│   └── static/
│
├── analytics/
├── database/
├── datasets/
├── ml/
├── models/
├── packet_capture/
├── reports/
├── uploads/
├── logs/
└── backups/
```

---

# Installation

Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/cloud-security-project.git
```

Move into project

```bash
cd cloud-security-project
```

Install dependencies

```bash
py -m pip install -r requirements.txt
```

Run application

```bash
py app.py
```

Open

```
http://127.0.0.1:5000
```

---

# Machine Learning

Supported datasets

- CICIDS2017
- CSE-CIC-IDS2018
- NSL-KDD

Training workflow

```
Dataset
    ↓
Preprocessing
    ↓
Random Forest Training
    ↓
Model Evaluation
    ↓
Save Model
    ↓
Prediction
```

Train the model

```bash
py ml/train_model.py
```

Model output

```
models/rf_model.pkl
```

---

# Security Architecture

The backend is designed with multiple security layers.

- Flask Authentication
- Password Hashing
- RBAC
- Secure Sessions
- Audit Logging
- Security Headers
- CSRF Protection
- Rate Limiting
- SQLAlchemy Safe Queries
- Secure File Upload Validation
- Environment Variables
- Safe Error Handling

---

# Project Status

| Module | Status |
|---------|--------|
| Enterprise UI/UX | ✅ Completed |
| Dashboard | ✅ Completed |
| Authentication | ✅ Completed |
| Database | ✅ Completed |
| Threat Investigation | ✅ Completed |
| Analytics | ✅ Completed |
| Reports | ✅ Completed |
| Business Risk Engine | ✅ Completed |
| Security Hardening | ✅ Implemented |
| Machine Learning Pipeline | ✅ Training Ready |
| CSV/PCAP Ingestion | 🚧 Planned |
| Real-Time Packet Capture | 🚧 Planned |
| Cloud Log Integration | 🚧 Planned |
| Threat Intelligence APIs | 🚧 Planned |

---

# Production Recommendations

Before production deployment:

- Disable DEBUG mode
- Replace demo credentials
- Use HTTPS
- Enable HSTS
- Configure a Web Application Firewall (WAF)
- Configure server firewall rules
- Store secrets using `.env`
- Rotate credentials regularly
- Schedule automated database backups
- Enable monitoring and centralized logging
- Remove demo data before production

---

# Future Enhancements

- Real-Time Packet Capture
- CSV Threat Upload
- PCAP Upload
- Live Machine Learning Prediction
- Firebase Authentication
- Google Login
- GitHub Login
- Docker Deployment
- AWS CloudTrail Integration
- Azure Monitor Integration
- Google Cloud Logging
- Threat Intelligence APIs
- Email Alerts
- SMS Notifications
- Continuous ML Model Retraining

---

# Learning Objectives

This project demonstrates practical knowledge in:

- Cloud Computing
- Cybersecurity
- Secure Backend Development
- Machine Learning
- Business Analytics
- Database Design
- Full Stack Web Development
- Enterprise UI/UX Design

---

# Disclaimer

This project is developed for **educational and research purposes** as part of a CSBS mini project.

The current implementation uses controlled demo incidents to demonstrate the complete workflow. The architecture is prepared for future integration with real datasets, packet capture, and cloud security logs.

---

---

# Developer

**Developed by:** **Praveen**

**Program:** B.Tech – Computer Science and Business Systems (CSBS)

**Project Type:** IEEE-Inspired Mini Project

**Domain:**
- Cloud Computing
- Cybersecurity
- Machine Learning
- Business Analytics
- Full Stack Web Development

---

# About the Developer

This project was independently designed and developed by **Praveen** as a CSBS mini project. It demonstrates practical implementation of secure backend development, modern frontend design, machine learning integration, business risk analysis, and cloud security concepts using open-source technologies.

The project focuses on building a professional Security Operations Center (SOC)-style platform that is scalable, modular, and ready for future enhancements such as real-time threat ingestion, cloud log integration, and advanced security analytics.

---

## License

This project is intended for **educational and research purposes**.

You are welcome to learn from the code, but please provide appropriate credit if you reuse significant parts of the project.

---

⭐ If you found this project useful, consider giving it a **Star** on GitHub.

