"""
auth/oauth.py
------------------------------------------------
OAuth 2.0 Engine for Google & GitHub Authentication.
Provides state-token CSRF protection, secure profile extraction,
and environment configuration management.
"""

import os
import json
import secrets
import urllib.parse
import requests
from flask import session, request, url_for

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USERINFO_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


def get_oauth_config(provider: str) -> dict:
    """Retrieve OAuth configuration for specified provider from environment variables."""
    provider_upper = provider.upper()
    return {
        "client_id": os.getenv(f"{provider_upper}_CLIENT_ID", "").strip(),
        "client_secret": os.getenv(f"{provider_upper}_CLIENT_SECRET", "").strip(),
        "redirect_uri": os.getenv(f"{provider_upper}_REDIRECT_URI", "").strip(),
    }


def is_provider_configured(provider: str) -> bool:
    """Check if required OAuth environment variables exist for provider."""
    config = get_oauth_config(provider)
    return bool(config["client_id"] and config["client_secret"])


def generate_state_token(provider: str) -> str:
    """Generate and store a secure state token in session for CSRF prevention."""
    state = secrets.token_urlsafe(32)
    session[f"oauth_state_{provider}"] = state
    return state


def validate_state_token(provider: str, state: str) -> bool:
    """Validate callback state token against stored session state token."""
    stored_state = session.pop(f"oauth_state_{provider}", None)
    if not stored_state or not state:
        return False
    return secrets.compare_digest(stored_state, state)


def get_google_auth_url(redirect_uri: str = None) -> str:
    """Construct Google OAuth 2.0 authorization redirect URL."""
    config = get_oauth_config("google")
    client_id = config["client_id"]
    target_redirect = redirect_uri or config["redirect_uri"] or url_for("google_callback", _external=True)
    state = generate_state_token("google")

    params = {
        "client_id": client_id,
        "redirect_uri": target_redirect,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account"
    }
    return f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}"


def get_github_auth_url(redirect_uri: str = None) -> str:
    """Construct GitHub OAuth authorization redirect URL."""
    config = get_oauth_config("github")
    client_id = config["client_id"]
    target_redirect = redirect_uri or config["redirect_uri"] or url_for("github_callback", _external=True)
    state = generate_state_token("github")

    params = {
        "client_id": client_id,
        "redirect_uri": target_redirect,
        "scope": "read:user user:email",
        "state": state
    }
    return f"{GITHUB_AUTH_URL}?{urllib.parse.urlencode(params)}"


def process_google_callback(code: str, redirect_uri: str = None) -> dict:
    """Exchange authorization code for Google profile data."""
    config = get_oauth_config("google")
    target_redirect = redirect_uri or config["redirect_uri"] or url_for("google_callback", _external=True)

    token_data = {
        "code": code,
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "redirect_uri": target_redirect,
        "grant_type": "authorization_code"
    }

    resp = requests.post(GOOGLE_TOKEN_URL, data=token_data, timeout=10)
    if resp.status_code != 200:
        raise ValueError(f"Google token exchange failed ({resp.status_code})")

    access_token = resp.json().get("access_token")
    if not access_token:
        raise ValueError("Missing access token in Google response")

    user_resp = requests.get(
        GOOGLE_USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10
    )
    if user_resp.status_code != 200:
        raise ValueError(f"Failed to fetch Google user profile ({user_resp.status_code})")

    profile = user_resp.json()
    return {
        "provider": "google",
        "provider_user_id": profile.get("id"),
        "email": profile.get("email"),
        "display_name": profile.get("name") or profile.get("given_name"),
        "profile_image_url": profile.get("picture"),
        "email_verified": profile.get("verified_email", True)
    }


def process_github_callback(code: str, redirect_uri: str = None) -> dict:
    """Exchange authorization code for GitHub profile data."""
    config = get_oauth_config("github")
    target_redirect = redirect_uri or config["redirect_uri"] or url_for("github_callback", _external=True)

    token_data = {
        "code": code,
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "redirect_uri": target_redirect
    }

    headers = {"Accept": "application/json"}
    resp = requests.post(GITHUB_TOKEN_URL, data=token_data, headers=headers, timeout=10)
    if resp.status_code != 200:
        raise ValueError(f"GitHub token exchange failed ({resp.status_code})")

    access_token = resp.json().get("access_token")
    if not access_token:
        raise ValueError("Missing access token in GitHub response")

    auth_header = {"Authorization": f"token {access_token}", "User-Agent": "CSBS-CloudSec-Platform"}
    user_resp = requests.get(GITHUB_USERINFO_URL, headers=auth_header, timeout=10)
    if user_resp.status_code != 200:
        raise ValueError(f"Failed to fetch GitHub profile ({user_resp.status_code})")

    profile = user_resp.json()
    email = profile.get("email")

    # If email is private in primary profile, fetch from emails endpoint
    if not email:
        try:
            emails_resp = requests.get(GITHUB_EMAILS_URL, headers=auth_header, timeout=10)
            if emails_resp.status_code == 200:
                emails = emails_resp.json()
                primary_email = next((e["email"] for e in emails if e.get("primary") and e.get("verified")), None)
                email = primary_email or (emails[0]["email"] if emails else None)
        except Exception:
            pass

    return {
        "provider": "github",
        "provider_user_id": str(profile.get("id")),
        "email": email,
        "display_name": profile.get("name") or profile.get("login"),
        "profile_image_url": profile.get("avatar_url"),
        "email_verified": True
    }
