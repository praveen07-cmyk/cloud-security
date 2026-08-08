"""
security_notifier.py
------------------------------------------------
Security Notification Event Dispatcher.
Decouples authentication security alerts (NEW_DEVICE_LOGIN, NEW_IP_LOGIN,
SUSPICIOUS_LOGIN, LOGIN_FAILURE_THRESHOLD) from downstream notification sinks
(e.g., Telegram, Webhooks, Email).
"""

import logging

logger = logging.getLogger("cloudsec.security_notifier")

_SUBSCRIBERS = []


def register_subscriber(callback):
    """Registers a listener callback: callback(event_type, payload)."""
    if callback not in _SUBSCRIBERS:
        _SUBSCRIBERS.append(callback)


def unregister_subscriber(callback):
    """Unregisters a listener callback."""
    if callback in _SUBSCRIBERS:
        _SUBSCRIBERS.remove(callback)


def dispatch_security_event(event_type, payload):
    """
    Dispatches a security event to all registered subscribers.
    - event_type: e.g. "NEW_DEVICE_LOGIN", "NEW_IP_LOGIN", "SUSPICIOUS_LOGIN", "LOGIN_FAILURE_THRESHOLD"
    - payload: dict containing event metadata (user_id, email, ip_address, device_type, risk_signals, etc.)
    """
    logger.info("Security Event Dispatched: %s | User: %s | Risk: %s", event_type, payload.get("username") or payload.get("email"), payload.get("risk_level", "UNKNOWN"))
    
    for subscriber in list(_SUBSCRIBERS):
        try:
            subscriber(event_type, payload)
        except Exception as exc:
            logger.error("Error in security event subscriber %s: %s", subscriber, exc)
