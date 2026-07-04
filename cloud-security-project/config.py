import os
from datetime import timedelta

from dotenv import load_dotenv


load_dotenv()


def env_bool(name, default=False):
    value = os.getenv(name, str(default)).strip().lower()
    return value in ("1", "true", "yes", "on")


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY") or os.getenv("FLASK_SECRET_KEY") or "change-this-development-secret"
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///database/security_platform.db")
    DEBUG = env_bool("DEBUG", os.getenv("FLASK_ENV", "development") == "development")
    PROPAGATE_EXCEPTIONS = False
    TRAP_HTTP_EXCEPTIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)
    REMEMBER_COOKIE_DURATION = timedelta(days=int(os.getenv("REMEMBER_COOKIE_DAYS", "30")))
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.getenv("SESSION_TIMEOUT_MINUTES", "30")))
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(25 * 1024 * 1024)))
    WTF_CSRF_TIME_LIMIT = int(os.getenv("WTF_CSRF_TIME_LIMIT", "3600"))
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
    BACKUP_FOLDER = os.getenv("BACKUP_FOLDER", "backups")
    ENABLE_HSTS = env_bool("ENABLE_HSTS", False)
    HSTS_MAX_AGE = int(os.getenv("HSTS_MAX_AGE", "31536000"))
