"""
telegram_notifier.py
-------------------------------------------------
Real-Time Security Notifications via Telegram Bot API.
Extends notification provider architecture with non-blocking execution,
privacy protection, risk thresholding, and alert deduplication.
-------------------------------------------------
"""

import html
import json
import logging
import os
import time
import urllib.parse
import urllib.request
from datetime import datetime, UTC

logger = logging.getLogger("cloudsec.telegram_notifier")

_COOLDOWN_CACHE = {}  # In-memory deduplication cache: key -> timestamp


class NotificationProvider:
    """Abstract base class for notification channels."""

    def send_alert(self, event_type, payload):
        raise NotImplementedError("Subclasses must implement send_alert")


class TelegramProvider(NotificationProvider):
    """Telegram Bot API Notification Provider."""

    def __init__(self):
        pass

    @property
    def is_enabled(self):
        val = os.getenv("TELEGRAM_ALERTS_ENABLED", "False").strip().lower()
        return val in ("true", "1", "yes", "on")

    @property
    def bot_token(self):
        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        if token.startswith("your_") or "placeholder" in token.lower():
            return ""
        return token

    @property
    def chat_id(self):
        cid = os.getenv("TELEGRAM_CHAT_ID", "").strip()
        if cid.startswith("your_") or "placeholder" in cid.lower():
            return ""
        return cid

    @property
    def min_risk_score(self):
        try:
            return int(os.getenv("TELEGRAM_ALERT_MIN_RISK", "70"))
        except Exception:
            return 70

    @property
    def cooldown_seconds(self):
        try:
            return int(os.getenv("TELEGRAM_ALERT_COOLDOWN_SECONDS", "300"))
        except Exception:
            return 300

    def format_message(self, event_type, payload):
        """Formats concise, security-focused notification text in clean HTML."""
        user = html.escape(str(payload.get("email") or payload.get("username") or "System / Anonymous"))
        method = html.escape(str(payload.get("authentication_method") or payload.get("auth_method") or "N/A"))
        risk_level = html.escape(str(payload.get("risk_level") or "LOW"))
        risk_score = payload.get("risk_score", 0)
        ip = html.escape(str(payload.get("ip_address") or "N/A"))
        device = html.escape(str(payload.get("device_type") or "Unknown"))
        os_name = html.escape(str(payload.get("operating_system") or payload.get("os") or "Unknown"))
        browser = html.escape(str(payload.get("browser") or "Unknown"))
        
        signals_raw = payload.get("risk_signals") or []
        if isinstance(signals_raw, str):
            try:
                signals_raw = json.loads(signals_raw)
            except Exception:
                signals_raw = [s.strip() for s in signals_raw.split(",") if s.strip()]

        signals_str = "\n".join([f"• {html.escape(s)}" for s in signals_raw]) if signals_raw else "• Standard Login Activity"

        now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

        header_icon = "🚨" if risk_level in ("HIGH", "CRITICAL") else "🛡️"

        return (
            f"<b>{header_icon} CLOUDSEC SECURITY ALERT</b>\n\n"
            f"<b>Event:</b> {html.escape(str(event_type))}\n"
            f"<b>User:</b> {user}\n"
            f"<b>Auth Method:</b> {method}\n"
            f"<b>Risk Level:</b> {risk_level} (Score: {risk_score})\n\n"
            f"<b>Risk Signals:</b>\n{signals_str}\n\n"
            f"<b>IP Address:</b> {ip}\n"
            f"<b>Device:</b> {device} ({os_name})\n"
            f"<b>Browser:</b> {browser}\n"
            f"<b>Timestamp:</b> {now_str}\n\n"
            f"<i>Action Required: Review Security Activity Dashboard</i>"
        )

    def should_send_alert(self, event_type, payload):
        """
        Determines whether to trigger or suppress a notification.
        Returns: (should_send: bool, reason: str)
        """
        if not self.is_enabled:
            return False, "TELEGRAM_DISABLED"

        if not self.bot_token:
            return False, "MISSING_BOT_TOKEN"

        if not self.chat_id:
            return False, "MISSING_CHAT_ID"

        risk_score = payload.get("risk_score", 0)
        critical_events = [
            "ACCOUNT_LOCKED",
            "LOGIN_FAILURE_THRESHOLD",
            "CRITICAL_RISK_LOGIN",
            "SUSPICIOUS_LOGIN",
            "PUBLIC_S3_EXPOSURE",
            "ROOT_ACCOUNT_LOGIN",
            "HIGH_RISK_AWS_INCIDENT",
        ]

        if risk_score < self.min_risk_score and event_type not in critical_events:
            return False, f"RISK_BELOW_THRESHOLD ({risk_score} < {self.min_risk_score})"

        # Deduplication / Cooldown check
        user_key = payload.get("user_id") or payload.get("email") or payload.get("username") or "anonymous"
        ip_key = payload.get("ip_address") or "no-ip"
        dedup_key = f"{user_key}:{event_type}:{ip_key}"

        now_ts = time.time()
        last_sent = _COOLDOWN_CACHE.get(dedup_key, 0)
        if now_ts - last_sent < self.cooldown_seconds:
            return False, f"SUPPRESSED_COOLDOWN (Deduplicated within {self.cooldown_seconds}s)"

        _COOLDOWN_CACHE[dedup_key] = now_ts
        return True, "QUALIFIED"

    def send_alert(self, event_type, payload):
        """
        Sends Telegram alert safely and non-blockingly.
        Never leaks bot token, never throws uncaught exceptions.
        """
        from database.db import log_audit_event, record_security_notification

        user_id = payload.get("user_id")
        email = payload.get("email")
        username = payload.get("username") or email or "system"
        risk_score = payload.get("risk_score", 0)
        risk_level = payload.get("risk_level", "LOW")

        should_send, reason = self.should_send_alert(event_type, payload)
        if not should_send:
            record_security_notification(
                event_type=event_type,
                user_id=user_id,
                email=email,
                risk_score=risk_score,
                risk_level=risk_level,
                channel="TELEGRAM",
                status="SUPPRESSED",
                failure_reason_safe=reason,
            )
            log_audit_event(
                username=username,
                action="TELEGRAM_ALERT_SUPPRESSED",
                resource="telegram_notifier",
                detail=f"Alert suppressed: {reason}",
                ip_address=payload.get("ip_address") or "127.0.0.1",
                status="suppressed",
                user_id=user_id,
                route="/auth/security_notifier",
                user_agent=payload.get("user_agent") or "system",
            )
            return {"status": "SUPPRESSED", "reason": reason}

        text = self.format_message(event_type, payload)
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        req_data = urllib.parse.urlencode({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": "true",
        }).encode("utf-8")

        # Retry policy: max 2 retries with short 0.5s backoff for 5xx/network errors
        max_attempts = 2
        last_error = ""

        for attempt in range(1, max_attempts + 1):
            try:
                req = urllib.request.Request(url, data=req_data, headers={"Content-Type": "application/x-www-form-urlencoded"})
                with urllib.request.urlopen(req, timeout=10.0) as resp:
                    resp_data = resp.read().decode("utf-8")
                    if resp.status == 200:
                        record_security_notification(
                            event_type=event_type,
                            user_id=user_id,
                            email=email,
                            risk_score=risk_score,
                            risk_level=risk_level,
                            channel="TELEGRAM",
                            status="SENT",
                        )
                        log_audit_event(
                            username=username,
                            action="TELEGRAM_ALERT_SENT",
                            resource="telegram_notifier",
                            detail=f"Telegram alert sent for event {event_type}",
                            ip_address=payload.get("ip_address") or "127.0.0.1",
                            status="success",
                            user_id=user_id,
                            route="/auth/security_notifier",
                            user_agent=payload.get("user_agent") or "system",
                        )
                        return {"status": "SENT", "attempt": attempt}
            except Exception as exc:
                raw_err = str(exc)
                # Strip token from error string if present
                safe_err = raw_err.replace(self.bot_token, "[REDACTED_BOT_TOKEN]") if self.bot_token else raw_err
                last_error = safe_err
                logger.warning("Telegram dispatch attempt %d failed: %s", attempt, safe_err)
                if attempt < max_attempts and "40" not in safe_err:  # Don't retry 4xx errors
                    time.sleep(0.5)

        # Log failure safely
        record_security_notification(
            event_type=event_type,
            user_id=user_id,
            email=email,
            risk_score=risk_score,
            risk_level=risk_level,
            channel="TELEGRAM",
            status="FAILED",
            failure_reason_safe=last_error[:255],
        )
        log_audit_event(
            username=username,
            action="TELEGRAM_ALERT_FAILED",
            resource="telegram_notifier",
            detail=f"Telegram dispatch failed: {last_error[:100]}",
            ip_address=payload.get("ip_address") or "127.0.0.1",
            status="failed",
            user_id=user_id,
            route="/auth/security_notifier",
            user_agent=payload.get("user_agent") or "system",
        )
        return {"status": "FAILED", "reason": last_error}


_telegram_provider_instance = TelegramProvider()


def send_telegram_alert(event_type, payload):
    """Standalone helper function to send Telegram alert."""
    return _telegram_provider_instance.send_alert(event_type, payload)
