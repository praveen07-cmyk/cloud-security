"""
test_10_oauth_auth.py
------------------------------------------------
Automated test suite for Google and GitHub Social Authentication.
Mocks external OAuth 2.0 network calls and validates:
- Start routes & state token generation
- Callback handling & token exchange
- State mismatch (CSRF prevention)
- Provider error / cancellation
- Safe default role (Read Only Analyst) for new social users
- Duplicate email account linking guardrail
- Audit log generation
- Non-regression of local authentication and mode selection
"""

import pytest
from unittest.mock import patch, PropertyMock, MagicMock
from app import app
from database.db import init_db, get_audit_logs, SessionLocal, User, OAuthIdentity
from tests.test_02_auth_and_rbac import login_client


@pytest.fixture(autouse=True)
def setup_database():
    init_db()
    db = SessionLocal()
    try:
        db.query(OAuthIdentity).delete()
        db.query(User).filter(
            User.email.in_([
                "new_google_user@secdev.org",
                "new_github_user@secdev.org",
                "local_dup@secdev.org",
                "viewer_social@secdev.org",
                "audit_user@secdev.org"
            ]) | User.username.like("google_%") | User.username.like("github_%") | User.username.like("local_dup%")
        ).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def test_google_login_unconfigured():
    """If Google OAuth is unconfigured, start route redirects with user warning."""
    with app.test_client() as client:
        with patch("auth.oauth.is_provider_configured", return_value=False):
            res = client.get("/auth/google", follow_redirects=True)
            assert res.status_code == 200
            assert b"Google OAuth is not configured" in res.data


def test_github_login_unconfigured():
    """If GitHub OAuth is unconfigured, start route redirects with user warning."""
    with app.test_client() as client:
        with patch("auth.oauth.is_provider_configured", return_value=False):
            res = client.get("/auth/github", follow_redirects=True)
            assert res.status_code == 200
            assert b"GitHub OAuth is not configured" in res.data


def test_google_login_start_redirect():
    """Configured Google OAuth generates authorization redirect and session state."""
    with app.test_client() as client:
        with patch("auth.oauth.is_provider_configured", return_value=True), \
             patch("auth.oauth.get_oauth_config", return_value={"client_id": "test_google_id", "client_secret": "secret", "redirect_uri": "http://localhost:5000/auth/google/callback"}):
            res = client.get("/auth/google")
            assert res.status_code == 302
            assert "accounts.google.com" in res.headers["Location"]
            assert "client_id=test_google_id" in res.headers["Location"]


def test_github_login_start_redirect():
    """Configured GitHub OAuth generates authorization redirect and session state."""
    with app.test_client() as client:
        with patch("auth.oauth.is_provider_configured", return_value=True), \
             patch("auth.oauth.get_oauth_config", return_value={"client_id": "test_github_id", "client_secret": "secret", "redirect_uri": "http://localhost:5000/auth/github/callback"}):
            res = client.get("/auth/github")
            assert res.status_code == 302
            assert "github.com/login/oauth/authorize" in res.headers["Location"]
            assert "client_id=test_github_id" in res.headers["Location"]


def test_oauth_callback_error_param():
    """Callback with error param handles cancellation gracefully."""
    with app.test_client() as client:
        res = client.get("/auth/google/callback?error=access_denied", follow_redirects=True)
        assert res.status_code == 200
        assert b"cancelled or encountered an error" in res.data


def test_oauth_callback_invalid_state():
    """Callback with invalid state parameter is rejected (CSRF protection)."""
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["oauth_state_google"] = "valid_state_token_123"

        res = client.get("/auth/google/callback?code=abc&state=wrong_state_token", follow_redirects=True)
        assert res.status_code == 200
        assert b"Invalid authentication state token" in res.data


def test_google_callback_success_new_user():
    """Successful Google callback creates new user with safe default role (Read Only Analyst)."""
    with app.test_client() as client:
        mock_profile = {
            "provider": "google",
            "provider_user_id": "google_uid_999",
            "email": "new_google_user@secdev.org",
            "display_name": "Google SecUser",
            "profile_image_url": "https://lh3.googleusercontent.com/photo.jpg",
            "email_verified": True
        }

        with client.session_transaction() as sess:
            sess["oauth_state_google"] = "mock_valid_state"

        with patch("app.validate_state_token", return_value=True), \
             patch("app.process_google_callback", return_value=mock_profile):

            res = client.get("/auth/google/callback?code=mock_code&state=mock_valid_state", follow_redirects=True)
            assert res.status_code == 200

            db = SessionLocal()
            user = db.query(User).filter_by(email="new_google_user@secdev.org").first()
            assert user is not None
            assert user.role == "Read Only Analyst"
            assert user.auth_provider == "google"

            identity = db.query(OAuthIdentity).filter_by(provider="google", provider_user_id="google_uid_999").first()
            assert identity is not None
            assert identity.user_id == user.id
            db.close()


def test_github_callback_success_new_user():
    """Successful GitHub callback creates new user with safe default role."""
    with app.test_client() as client:
        mock_profile = {
            "provider": "github",
            "provider_user_id": "github_uid_888",
            "email": "new_github_user@secdev.org",
            "display_name": "GitHub DevSec",
            "profile_image_url": "https://avatars.githubusercontent.com/u/888",
            "email_verified": True
        }

        with patch("app.validate_state_token", return_value=True), \
             patch("app.process_github_callback", return_value=mock_profile):

            res = client.get("/auth/github/callback?code=mock_code&state=mock_valid_state", follow_redirects=True)
            assert res.status_code == 200

            db = SessionLocal()
            user = db.query(User).filter_by(email="new_github_user@secdev.org").first()
            assert user is not None
            assert user.role == "Read Only Analyst"
            assert user.auth_provider == "github"
            db.close()


def test_oauth_duplicate_email_linking_guardrail():
    """Unauthenticated OAuth login with existing local email prompts for password login first."""
    # Seed a local password user with an email address in DB
    db = SessionLocal()
    user_in_db = db.query(User).filter_by(email="local_dup@secdev.org").first()
    if not user_in_db:
        local_user = User(
            username="local_dup_user",
            password_hash="hash_secret",
            full_name="Local Duplicate",
            role="Security Analyst",
            department="SOC",
            email="local_dup@secdev.org",
            auth_provider="local"
        )
        db.add(local_user)
        db.commit()
    db.close()

    mock_profile = {
        "provider": "google",
        "provider_user_id": "google_uid_777",
        "email": "local_dup@secdev.org",
        "display_name": "Attacker Impersonator",
        "profile_image_url": None,
        "email_verified": True
    }

    mock_anon = MagicMock()
    type(mock_anon).is_authenticated = PropertyMock(return_value=False)

    with app.test_client() as unauth_client:
        with patch("app.current_user", mock_anon), \
             patch("app.validate_state_token", return_value=True), \
             patch("app.process_google_callback", return_value=mock_profile):

            res = unauth_client.get("/auth/google/callback?code=mock_code&state=mock_state", follow_redirects=True)
            assert res.status_code == 200
            assert b"An account with this email address already exists" in res.data


def test_social_user_rbac_restriction():
    """Social login users with default role cannot modify global operating mode."""
    client = app.test_client()
    mock_profile = {
        "provider": "google",
        "provider_user_id": "google_viewer_100",
        "email": "viewer_social@secdev.org",
        "display_name": "Social Viewer",
        "profile_image_url": None,
        "email_verified": True
    }

    with patch("app.validate_state_token", return_value=True), \
         patch("app.process_google_callback", return_value=mock_profile):

        client.get("/auth/google/callback?code=mock_code&state=mock_state")

        res = client.post("/select_mode", data={"mode": "Live AWS Mode"}, follow_redirects=True)
        assert res.status_code == 200
        assert b"do not have permission" in res.data


def test_audit_logs_record_social_auth():
    """Audit logs properly record SOCIAL_LOGIN_SUCCESS and GOOGLE_LOGIN_SUCCESS."""
    client = app.test_client()
    mock_profile = {
        "provider": "google",
        "provider_user_id": "google_audit_user_1",
        "email": "audit_user@secdev.org",
        "display_name": "Audit User",
        "profile_image_url": None,
        "email_verified": True
    }

    with patch("app.validate_state_token", return_value=True), \
         patch("app.process_google_callback", return_value=mock_profile):

        client.get("/auth/google/callback?code=mock_code&state=mock_state")

        logs = get_audit_logs(limit=20)
        actions = [log["action"] for log in logs]
        assert "SOCIAL_LOGIN_SUCCESS" in actions
        assert "GOOGLE_LOGIN_SUCCESS" in actions


def test_normal_login_regression():
    """Existing password login functionality remains 100% operational."""
    client = app.test_client()
    res = login_client(client, "admin", "admin")
    assert res.status_code == 302 or res.status_code == 200
    with client.session_transaction() as sess:
        assert sess.get("login_name") == "admin"
        assert sess.get("role") in ["admin", "Administrator"]


def test_mode_selection_regression():
    """Existing mode selection remains 100% operational for admin users."""
    client = app.test_client()
    login_client(client, "admin", "admin")
    res = client.get("/select_mode")
    assert res.status_code == 200
    assert b"Operating Mode" in res.data or b"Select Operating Mode" in res.data
