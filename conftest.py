"""
Shared pytest fixtures and configuration for Email Sending API tests.
"""
import pytest


@pytest.fixture(autouse=True)
def setup_test_env(monkeypatch):
    """
    Automatically set up test environment variables for each test.
    Individual tests can override these via monkeypatch.setenv/delenv.
    """
    monkeypatch.setenv("SENDER_EMAIL", "sender@example.com")
    monkeypatch.setenv("SENDGRID_API_KEY", "test-sendgrid-api-key")
    monkeypatch.setenv("GCP_PROJECT_ID", "test-project-id")
    monkeypatch.setenv("EMAIL_SUBJECT", "Test Email")
    monkeypatch.setenv("PORT", "8080")
    # Disable BQ audit logging in tests by default
    monkeypatch.setenv("BQ_AUDIT_ENABLED", "false")
    monkeypatch.setenv("BQ_DATASET", "test_dataset")
    monkeypatch.setenv("BQ_TABLE", "test_audit_log")


@pytest.fixture
def sample_blocked_domains():
    """Provide sample blocked domains for testing."""
    return ["blocked.com", "spam.org", "unwanted.net"]


@pytest.fixture
def sample_email_payload():
    """Provide a sample valid email payload."""
    return {
        "to_list": ["recipient@example.com"],
        "cc_list": ["cc@example.com"],
        "mail_body": "<h1>Test Email</h1><p>This is a test email body.</p>"
    }
