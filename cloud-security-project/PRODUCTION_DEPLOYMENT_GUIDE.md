# Production Deployment & Hardening Guide

**Project:** Cloud Intrusion Detection & Intelligent Threat Response (`cloud-security-project`)  
**Target Environment:** Production (Linux / AWS EC2 / Containerized Docker / Heroku / App Engine)

---

## 1. Prerequisites & Production Environment Variables

Copy `.env.production.example` to `.env` on your production server:

```bash
cp .env.production.example .env
```

Ensure the following variables are strictly populated:

| Variable | Description | Recommended Value |
| :--- | :--- | :--- |
| `FLASK_ENV` | Application execution mode | `production` |
| `DEBUG` | Flask debug mode | `False` |
| `SECRET_KEY` | Cryptographic session signing key | Generate via `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATABASE_URL` | Production database connection string | `postgresql://cloudsec_user:secure_password@postgres-db:5432/cloudsec_prod` |
| `SESSION_COOKIE_SECURE` | Require HTTPS for session cookies | `True` |
| `ENABLE_HSTS` | Enable HTTP Strict Transport Security | `True` |
| `RATELIMIT_STORAGE_URI` | Shared rate limit storage engine | `redis://redis-server:6379/0` |
| `TELEGRAM_BOT_TOKEN` | Bot API token for security notifications | `8970487611:AAE47fnDiy0jQWpVF89Gmdk-RiJL8Lg5ZgU` |
| `TELEGRAM_CHAT_ID` | Admin or Channel numeric Chat ID | e.g. `123456789` or `-100123456789` |
| `TELEGRAM_ALERTS_ENABLED`| Enable real-time security alerts | `True` |

---

## 2. Web Application Server Setup (Gunicorn + Eventlet / Gevent)

For multi-worker production serving, run Gunicorn with worker processes:

```bash
gunicorn --workers 4 --worker-class eventlet --bind 0.0.0.0:5000 app:app
```

---

## 3. Database Preparation (PostgreSQL)

1. Provision a PostgreSQL 15+ instance.
2. Initialize database schema & seed initial admin user:

```bash
python -c "from database.db import init_db; init_db()"
```

3. Configure automated daily backups using standard `pg_dump` or the built-in backup module (`backup_database()`).

---

## 4. Redis Rate Limiter & Cooldown Storage Setup

Install and start Redis:

```bash
sudo apt update && sudo apt install redis-server -y
sudo systemctl enable --now redis-server
```

Set `RATELIMIT_STORAGE_URI=redis://localhost:6379/0` in `.env`.

---

## 5. Reverse Proxy Configuration (Nginx + TLS)

Configure Nginx as a reverse proxy with TLS termination and security headers:

```nginx
server {
    listen 443 ssl http2;
    server_name cloudsec.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/cloudsec.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cloudsec.yourdomain.com/privkey.pem;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /socket.io {
        proxy_pass http://127.0.0.1:5000/socket.io;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
    }
}
```

---

## 6. Telegram Security Bot Setup (`@CloudSec_Securitybot`)

1. Search for `@CloudSec_Securitybot` on Telegram and send `/start`.
2. Get your numeric Telegram Chat ID from `@userinfobot`.
3. Set `TELEGRAM_CHAT_ID=<your_numeric_chat_id>` in `.env`.
4. Test notification dispatch via curl or admin dashboard:

```bash
curl -X POST https://cloudsec.yourdomain.com/api/security/notifications/test \
  -H "Cookie: session=<admin_session_cookie>" \
  -H "X-CSRFToken: <csrf_token>"
```

---

## 7. Health Check & Monitoring

- **Liveness Probe:** `GET /api/health` (Returns HTTP 200 `{"status": "ok"}`)
- **Readiness Probe:** `GET /api/ready` (Returns HTTP 200 `{"status": "ready", "database": "connected"}`)
