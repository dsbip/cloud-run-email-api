"""
Comprehensive test suite for Email Sending API.
Tests all endpoints with mocked external dependencies.

Environment variables are automatically set by conftest.py's autouse fixture.
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from main import app
from models import MAX_RECIPIENTS
from services.firestore_service import (
    get_blocked_domains, get_allowed_domains,
    check_blocked_domains, check_allowed_domains,
)
from services.sendgrid_service import get_sendgrid_api_key


@pytest.fixture
def client():
    """Create a test client for the FastAPI application."""
    return TestClient(app)


@pytest.fixture
def mock_firestore():
    """Mock the lazy-initialized Firestore client."""
    with patch('services.firestore_service._get_firestore_client') as mock_get_client:
        yield mock_get_client


@pytest.fixture
def mock_secret_manager():
    """Mock Secret Manager client."""
    with patch('services.sendgrid_service.secretmanager.SecretManagerServiceClient') as mock_client:
        yield mock_client


@pytest.fixture
def mock_sendgrid():
    """Mock SendGrid client."""
    with patch('services.sendgrid_service.SendGridAPIClient') as mock_client:
        yield mock_client


def _setup_firestore_mock(mock_firestore, blocked=None, allowed=None):
    """Helper to configure Firestore mock with blocked and allowed domains.

    Firestore reads two documents: 'blocked_domains' and 'allowed_domains'.
    This sets up the mock to return different data based on the document name.
    mock_firestore is a patch of _get_firestore_client, so its return_value
    is the db client object.
    """
    if blocked is None:
        blocked = []
    if allowed is None:
        allowed = []

    docs = {
        "blocked_domains": {"domains": blocked},
        "allowed_domains": {"domains": allowed},
    }

    mock_db = MagicMock()
    mock_firestore.return_value = mock_db

    def make_doc(doc_name):
        mock_doc_ref = MagicMock()
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = docs.get(doc_name, {"domains": []})
        mock_doc_ref.get.return_value = mock_doc
        return mock_doc_ref

    mock_collection = MagicMock()
    mock_collection.document.side_effect = make_doc
    mock_db.collection.return_value = mock_collection
    return mock_db


def _setup_sendgrid_mock(mock_sendgrid, status_code=202):
    """Helper to configure SendGrid mock."""
    mock_sg_instance = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_sg_instance.send.return_value = mock_response
    mock_sendgrid.return_value = mock_sg_instance
    return mock_sg_instance


class TestHealthEndpoints:
    """Test health check endpoints."""

    def test_root_endpoint(self, client):
        """Test root endpoint returns healthy status."""
        response = client.get("/")
        assert response.status_code == 200
        assert response.json() == {
            "status": "healthy",
            "service": "Email Sending API"
        }

    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}


class TestEmailValidation:
    """Test email validation in request models."""

    def test_valid_email_addresses(self, client, mock_firestore, mock_sendgrid):
        """Test that valid email addresses are accepted."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["test@example.com", "user@domain.org"],
            "cc_list": ["cc@example.com"],
            "mail_body": "<p>Test email</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 200

    def test_invalid_email_in_to_list(self, client):
        """Test that invalid email in to_list is rejected."""
        payload = {
            "to_list": ["invalid-email", "test@example.com"],
            "cc_list": [],
            "mail_body": "<p>Test email</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422
        assert "Invalid email address" in response.json()["detail"][0]["msg"]

    def test_invalid_email_in_cc_list(self, client):
        """Test that invalid email in cc_list is rejected."""
        payload = {
            "to_list": ["test@example.com"],
            "cc_list": ["not-an-email"],
            "mail_body": "<p>Test email</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422
        assert "Invalid email address" in response.json()["detail"][0]["msg"]

    def test_empty_to_list(self, client):
        """Test that empty to_list is rejected."""
        payload = {
            "to_list": [],
            "cc_list": [],
            "mail_body": "<p>Test email</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422
        assert "to_list cannot be empty" in response.json()["detail"][0]["msg"]

    def test_empty_mail_body(self, client):
        """Test that empty mail_body is rejected."""
        payload = {
            "to_list": ["test@example.com"],
            "cc_list": [],
            "mail_body": ""
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422

    def test_whitespace_only_mail_body(self, client):
        """Test that whitespace-only mail_body is rejected."""
        payload = {
            "to_list": ["test@example.com"],
            "cc_list": [],
            "mail_body": "   \n\t  "
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422

    def test_missing_required_fields(self, client):
        """Test that missing required fields are rejected."""
        payload = {"cc_list": []}
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422

    def test_missing_mail_body(self, client):
        """Test that missing mail_body is rejected."""
        payload = {
            "to_list": ["test@example.com"],
            "cc_list": []
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422

    def test_optional_cc_list(self, client, mock_firestore, mock_sendgrid):
        """Test that cc_list is optional."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["test@example.com"],
            "mail_body": "<p>Test email</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 200


class TestBlockedDomains:
    """Test blocked domain functionality."""

    def test_get_blocked_domains_success(self, mock_firestore):
        """Test successful retrieval of blocked domains from Firestore."""
        _setup_firestore_mock(mock_firestore, blocked=["blocked.com", "spam.org", "unwanted.net"])

        blocked = get_blocked_domains()
        assert len(blocked) == 3
        assert "blocked.com" in blocked
        assert "spam.org" in blocked

    def test_get_blocked_domains_empty_document(self, mock_firestore):
        """Test when blocked domains document is empty."""
        _setup_firestore_mock(mock_firestore, blocked=[])

        blocked = get_blocked_domains()
        assert blocked == []

    def test_get_blocked_domains_missing_document(self, mock_firestore):
        """Test when blocked domains document doesn't exist."""
        mock_db = MagicMock()
        mock_firestore.return_value = mock_db
        mock_doc = MagicMock()
        mock_doc.exists = False
        mock_db.collection.return_value.document.return_value.get.return_value = mock_doc

        blocked = get_blocked_domains()
        assert blocked == []

    def test_get_blocked_domains_missing_domains_field(self, mock_firestore):
        """Test when Firestore document exists but has no 'domains' field."""
        mock_db = MagicMock()
        mock_firestore.return_value = mock_db
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {}
        mock_db.collection.return_value.document.return_value.get.return_value = mock_doc

        blocked = get_blocked_domains()
        assert blocked == []

    def test_check_blocked_domains_with_blocked_email(self):
        """Test checking emails against blocked domains."""
        emails = ["user@blocked.com", "test@example.com"]
        blocked_domains = ["blocked.com", "spam.org"]

        blocked_email = check_blocked_domains(emails, blocked_domains)
        assert blocked_email == "user@blocked.com"

    def test_check_blocked_domains_with_subdomain(self):
        """Test blocking works with subdomains."""
        emails = ["user@mail.blocked.com"]
        blocked_domains = ["blocked.com"]

        blocked_email = check_blocked_domains(emails, blocked_domains)
        assert blocked_email == "user@mail.blocked.com"

    def test_check_blocked_domains_all_allowed(self):
        """Test when all emails are allowed."""
        emails = ["user@example.com", "test@domain.org"]
        blocked_domains = ["blocked.com", "spam.org"]

        blocked_email = check_blocked_domains(emails, blocked_domains)
        assert blocked_email is None

    def test_check_blocked_domains_empty_list(self):
        """Test with empty email list."""
        blocked_email = check_blocked_domains([], ["blocked.com"])
        assert blocked_email is None

    def test_check_blocked_domains_empty_blocked(self):
        """Test with empty blocked domains list."""
        blocked_email = check_blocked_domains(["user@example.com"], [])
        assert blocked_email is None

    def test_send_email_with_blocked_domain(self, client, mock_firestore):
        """Test that emails to blocked domains are rejected."""
        _setup_firestore_mock(mock_firestore, blocked=["blocked.com"])

        payload = {
            "to_list": ["user@blocked.com"],
            "cc_list": [],
            "mail_body": "<p>Test email</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 403
        assert "blocked domain" in response.json()["detail"].lower()

    def test_send_email_with_blocked_domain_in_cc(self, client, mock_firestore):
        """Test that emails with blocked domains in CC are rejected."""
        _setup_firestore_mock(mock_firestore, blocked=["spam.org"])

        payload = {
            "to_list": ["valid@example.com"],
            "cc_list": ["user@spam.org"],
            "mail_body": "<p>Test email</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 403

    def test_case_insensitive_domain_blocking(self):
        """Test that domain blocking is case-insensitive."""
        emails = ["User@BLOCKED.COM", "test@Example.com"]
        blocked_domains = ["blocked.com"]

        blocked_email = check_blocked_domains(emails, blocked_domains)
        assert blocked_email == "User@BLOCKED.COM"


class TestAllowedDomains:
    """Test allowed domain functionality."""

    def test_check_allowed_domains_all_allowed(self):
        """Test when all emails match allowed domains."""
        emails = ["user@example.com", "admin@example.com"]
        allowed = ["example.com"]
        assert check_allowed_domains(emails, allowed) is None

    def test_check_allowed_domains_subdomain_allowed(self):
        """Test that subdomains of allowed domains are permitted."""
        emails = ["user@mail.example.com"]
        allowed = ["example.com"]
        assert check_allowed_domains(emails, allowed) is None

    def test_check_allowed_domains_not_allowed(self):
        """Test when an email does not match any allowed domain."""
        emails = ["user@example.com", "other@forbidden.com"]
        allowed = ["example.com"]
        assert check_allowed_domains(emails, allowed) == "other@forbidden.com"

    def test_check_allowed_domains_empty_allowlist(self):
        """Test that empty allowlist permits all domains."""
        emails = ["user@anything.com"]
        assert check_allowed_domains(emails, []) is None

    def test_check_allowed_domains_empty_email_list(self):
        """Test with empty email list."""
        assert check_allowed_domains([], ["example.com"]) is None

    def test_check_allowed_domains_case_insensitive(self):
        """Test that allowed domain matching is case-insensitive."""
        emails = ["User@EXAMPLE.COM"]
        allowed = ["example.com"]
        assert check_allowed_domains(emails, allowed) is None

    def test_check_allowed_domains_multiple_allowed(self):
        """Test with multiple allowed domains."""
        emails = ["a@foo.com", "b@bar.org", "c@baz.net"]
        allowed = ["foo.com", "bar.org", "baz.net"]
        assert check_allowed_domains(emails, allowed) is None

    def test_get_allowed_domains_success(self, mock_firestore):
        """Test fetching allowed domains from Firestore."""
        mock_db = MagicMock()
        mock_firestore.return_value = mock_db
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {"domains": ["example.com", "corp.net"]}
        mock_db.collection.return_value.document.return_value.get.return_value = mock_doc

        allowed = get_allowed_domains()
        assert len(allowed) == 2
        assert "example.com" in allowed

    def test_get_allowed_domains_empty(self, mock_firestore):
        """Test when allowed domains document is empty."""
        mock_db = MagicMock()
        mock_firestore.return_value = mock_db
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {"domains": []}
        mock_db.collection.return_value.document.return_value.get.return_value = mock_doc

        allowed = get_allowed_domains()
        assert allowed == []

    def test_get_allowed_domains_missing_document(self, mock_firestore):
        """Test when allowed domains document doesn't exist."""
        mock_db = MagicMock()
        mock_firestore.return_value = mock_db
        mock_doc = MagicMock()
        mock_doc.exists = False
        mock_db.collection.return_value.document.return_value.get.return_value = mock_doc

        allowed = get_allowed_domains()
        assert allowed == []

    def test_send_email_blocked_by_allowlist(self, client, mock_firestore, mock_sendgrid):
        """Test that email to a non-allowed domain is rejected."""
        _setup_firestore_mock(mock_firestore, allowed=["corp.com"])

        payload = {
            "to_list": ["user@external.com"],
            "cc_list": [],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 403
        assert "does not belong to an allowed domain" in response.json()["detail"]

    def test_send_email_cc_blocked_by_allowlist(self, client, mock_firestore, mock_sendgrid):
        """Test that CC to a non-allowed domain is rejected."""
        _setup_firestore_mock(mock_firestore, allowed=["corp.com"])

        payload = {
            "to_list": ["user@corp.com"],
            "cc_list": ["external@other.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 403
        assert "external@other.com" in response.json()["detail"]

    def test_send_email_allowed_domain_passes(self, client, mock_firestore, mock_sendgrid):
        """Test that email to an allowed domain succeeds."""
        _setup_firestore_mock(mock_firestore, allowed=["example.com", "corp.com"])
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["user@example.com"],
            "cc_list": ["admin@corp.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 200

    def test_send_email_empty_allowlist_permits_all(self, client, mock_firestore, mock_sendgrid):
        """Test that empty allowlist allows all domains."""
        _setup_firestore_mock(mock_firestore, allowed=[])
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["anyone@anywhere.com"],
            "cc_list": [],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 200

    def test_blocked_check_runs_before_allowed(self, client, mock_firestore):
        """Test that blocked domain check runs before allowed domain check."""
        # Email is both blocked AND not in allowed list.
        # Should get blocked domain error (not allowed domain error).
        _setup_firestore_mock(
            mock_firestore,
            blocked=["evil.com"],
            allowed=["corp.com"]
        )

        payload = {
            "to_list": ["user@evil.com"],
            "cc_list": [],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 403
        assert "blocked domain" in response.json()["detail"].lower()


class TestSendGridIntegration:
    """Test SendGrid API integration."""

    def test_get_sendgrid_api_key_from_env(self):
        """Test loading SendGrid API key from environment variable."""
        # conftest sets SENDGRID_API_KEY="test-sendgrid-api-key"
        api_key = get_sendgrid_api_key()
        assert api_key == "test-sendgrid-api-key"

    def test_get_sendgrid_api_key_from_secret_manager(self, monkeypatch, mock_secret_manager):
        """Test loading SendGrid API key from Secret Manager."""
        monkeypatch.delenv("SENDGRID_API_KEY", raising=False)
        monkeypatch.setenv("GCP_PROJECT_ID", "test-project")

        mock_client_instance = MagicMock()
        mock_secret_manager.return_value = mock_client_instance
        mock_response = MagicMock()
        mock_response.payload.data = b"secret-api-key-from-sm"
        mock_client_instance.access_secret_version.return_value = mock_response

        api_key = get_sendgrid_api_key()
        assert api_key == "secret-api-key-from-sm"

    def test_get_sendgrid_api_key_no_env_no_project(self, monkeypatch):
        """Test error when neither SENDGRID_API_KEY nor GCP_PROJECT_ID is set."""
        monkeypatch.delenv("SENDGRID_API_KEY", raising=False)
        monkeypatch.delenv("GCP_PROJECT_ID", raising=False)

        with pytest.raises(ValueError, match="Neither SENDGRID_API_KEY nor GCP_PROJECT_ID"):
            get_sendgrid_api_key()

    def test_send_email_success(self, client, mock_firestore, mock_sendgrid):
        """Test successful email sending."""
        _setup_firestore_mock(mock_firestore)
        mock_sg = _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["recipient@example.com"],
            "cc_list": ["cc@example.com"],
            "mail_body": "<h1>Test</h1><p>Email body</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200
        assert response.json()["status"] == "success"
        assert response.json()["message"] == "Email sent successfully"
        assert response.json()["status_code"] == 202

        mock_sendgrid.assert_called_once()
        mock_sg.send.assert_called_once()

    def test_send_email_sendgrid_failure(self, client, mock_firestore, mock_sendgrid):
        """Test handling of SendGrid API failure."""
        _setup_firestore_mock(mock_firestore)

        mock_sg_instance = MagicMock()
        mock_sg_instance.send.side_effect = Exception("SendGrid API error")
        mock_sendgrid.return_value = mock_sg_instance

        payload = {
            "to_list": ["recipient@example.com"],
            "cc_list": [],
            "mail_body": "<p>Test email</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 500
        assert "unexpected error occurred" in response.json()["detail"].lower()

    def test_send_email_missing_sender_email_env(self, client, monkeypatch, mock_firestore, mock_sendgrid):
        """Test error when SENDER_EMAIL environment variable is missing."""
        monkeypatch.delenv("SENDER_EMAIL", raising=False)

        _setup_firestore_mock(mock_firestore)

        payload = {
            "to_list": ["recipient@example.com"],
            "cc_list": [],
            "mail_body": "<p>Test email</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 422
        assert "SENDER_EMAIL" in response.json()["detail"]


class TestHTMLEmailSupport:
    """Test HTML email body support."""

    def test_send_html_email(self, client, mock_firestore, mock_sendgrid):
        """Test sending email with HTML content."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        html_body = """
        <!DOCTYPE html>
        <html>
        <head><title>Test Email</title></head>
        <body>
            <h1>Welcome</h1>
            <p>This is a <strong>test</strong> email.</p>
            <a href="https://example.com">Click here</a>
        </body>
        </html>
        """

        payload = {
            "to_list": ["recipient@example.com"],
            "cc_list": [],
            "mail_body": html_body
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200
        assert response.json()["status"] == "success"

    def test_send_multiline_email(self, client, mock_firestore, mock_sendgrid):
        """Test sending email with multiline content."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        multiline_body = "Line 1\nLine 2\nLine 3\n\nLine 5 with gap"

        payload = {
            "to_list": ["recipient@example.com"],
            "cc_list": [],
            "mail_body": multiline_body
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_firestore_connection_error(self, client, mock_firestore):
        """Test handling of Firestore connection error."""
        mock_firestore.side_effect = Exception("Firestore connection failed")

        payload = {
            "to_list": ["recipient@example.com"],
            "cc_list": [],
            "mail_body": "<p>Test email</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 500
        assert "Failed to fetch blocked domains" in response.json()["detail"]

    def test_multiple_recipients(self, client, mock_firestore, mock_sendgrid):
        """Test sending email to multiple recipients."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": [
                "user1@example.com",
                "user2@example.com",
                "user3@domain.org"
            ],
            "cc_list": ["cc1@example.com", "cc2@example.com"],
            "mail_body": "<p>Test email to multiple recipients</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200

    def test_special_characters_in_email(self, client, mock_firestore, mock_sendgrid):
        """Test email addresses with special characters."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["user.name+tag@example.com", "first_last@domain.co.uk"],
            "cc_list": [],
            "mail_body": "<p>Test email</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200

    def test_invalid_json_body(self, client):
        """Test handling of invalid JSON body."""
        response = client.post(
            "/send-email",
            content="not json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422

    def test_wrong_content_type(self, client):
        """Test handling of wrong content type."""
        response = client.post(
            "/send-email",
            content="to_list=test@example.com",
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        assert response.status_code == 422


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_very_long_email_body(self, client, mock_firestore, mock_sendgrid):
        """Test sending email with very long body."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        long_body = "<p>" + ("Test content. " * 1000) + "</p>"

        payload = {
            "to_list": ["recipient@example.com"],
            "cc_list": [],
            "mail_body": long_body
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200

    def test_unicode_in_email_body(self, client, mock_firestore, mock_sendgrid):
        """Test sending email with unicode characters."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["recipient@example.com"],
            "cc_list": [],
            "mail_body": "<p>Hello world! Привет мир!</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200

    def test_empty_blocked_domains_list(self, client, mock_firestore, mock_sendgrid):
        """Test when Firestore returns empty blocked domains list."""
        _setup_firestore_mock(mock_firestore, blocked=[])
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["recipient@anydomain.com"],
            "cc_list": [],
            "mail_body": "<p>Test email</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200

    def test_single_to_recipient_no_cc(self, client, mock_firestore, mock_sendgrid):
        """Test minimal valid request: one recipient, no CC."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["only@example.com"],
            "mail_body": "plain text body"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200

    def test_cc_list_explicit_none(self, client, mock_firestore, mock_sendgrid):
        """Test that cc_list as null/None is handled."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["test@example.com"],
            "cc_list": None,
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200

    def test_duplicate_emails_in_to_list(self, client, mock_firestore, mock_sendgrid):
        """Test that duplicate emails in to_list are accepted (SendGrid handles dedup)."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["user@example.com", "user@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200

    def test_same_email_in_to_and_cc(self, client, mock_firestore, mock_sendgrid):
        """Test same email in both to_list and cc_list."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["user@example.com"],
            "cc_list": ["user@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200

    def test_extra_fields_ignored(self, client, mock_firestore, mock_sendgrid):
        """Test that extra/unknown fields in request body are ignored."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["user@example.com"],
            "mail_body": "<p>Test</p>",
            "unknown_field": "should be ignored",
            "priority": 1
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200

    def test_cc_list_empty_list(self, client, mock_firestore, mock_sendgrid):
        """Test cc_list as empty list (explicit [])."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["user@example.com"],
            "cc_list": [],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200


class TestEmailRegexValidation:
    """Test email regex edge cases for stricter validation."""

    def test_leading_dot_rejected(self, client):
        """Test that email with leading dot in local part is rejected."""
        payload = {
            "to_list": [".user@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422

    def test_trailing_dot_local_rejected(self, client):
        """Test that email with trailing dot in local part is rejected."""
        payload = {
            "to_list": ["user.@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422

    def test_consecutive_dots_rejected(self, client):
        """Test that email with consecutive dots in local part is rejected."""
        payload = {
            "to_list": ["user..name@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422

    def test_leading_hyphen_domain_rejected(self, client):
        """Test that email with leading hyphen in domain is rejected."""
        payload = {
            "to_list": ["user@-example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422

    def test_trailing_hyphen_domain_rejected(self, client):
        """Test that email with trailing hyphen in domain label is rejected."""
        payload = {
            "to_list": ["user@example-.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422

    def test_valid_plus_tag_accepted(self, client, mock_firestore, mock_sendgrid):
        """Test that email with + tag is accepted."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["user+tag@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 200

    def test_valid_hyphen_in_domain_accepted(self, client, mock_firestore, mock_sendgrid):
        """Test that domain with hyphens in the middle is accepted."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["user@my-domain.example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 200

    def test_single_char_local_part_accepted(self, client, mock_firestore, mock_sendgrid):
        """Test that single character local part is accepted."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["a@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 200

    def test_non_string_in_to_list_rejected(self, client):
        """Test that non-string items in to_list are rejected."""
        payload = {
            "to_list": [123, True],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422

    def test_partial_domain_not_blocked(self):
        """Test that notblocked.com is NOT caught when blocked.com is blocked."""
        emails = ["user@notblocked.com"]
        blocked_domains = ["blocked.com"]
        assert check_blocked_domains(emails, blocked_domains) is None

    def test_partial_domain_not_in_allowlist(self):
        """Test that notexample.com does NOT match when example.com is allowed."""
        emails = ["user@notexample.com"]
        allowed = ["example.com"]
        assert check_allowed_domains(emails, allowed) == "user@notexample.com"


class TestSecretManagerEdgeCases:
    """Test Secret Manager failure paths and edge cases."""

    def test_secret_manager_failure_returns_502(self, client, monkeypatch, mock_firestore, mock_secret_manager):
        """Test that Secret Manager failure returns 502 via RuntimeError path."""
        monkeypatch.delenv("SENDGRID_API_KEY", raising=False)
        monkeypatch.setenv("GCP_PROJECT_ID", "test-project")

        _setup_firestore_mock(mock_firestore)
        mock_secret_manager.return_value.access_secret_version.side_effect = Exception("SM down")

        payload = {
            "to_list": ["user@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 502
        assert "sendgrid" in response.json()["detail"].lower()

    def test_secret_manager_custom_secret_name(self, monkeypatch, mock_secret_manager):
        """Test Secret Manager uses custom secret name and version from env."""
        monkeypatch.delenv("SENDGRID_API_KEY", raising=False)
        monkeypatch.setenv("GCP_PROJECT_ID", "my-project")
        monkeypatch.setenv("SENDGRID_SECRET_NAME", "custom-key")
        monkeypatch.setenv("SENDGRID_SECRET_VERSION", "5")

        mock_client = MagicMock()
        mock_secret_manager.return_value = mock_client
        mock_response = MagicMock()
        mock_response.payload.data = b"the-api-key"
        mock_client.access_secret_version.return_value = mock_response

        api_key = get_sendgrid_api_key()
        assert api_key == "the-api-key"

        call_args = mock_client.access_secret_version.call_args
        assert "my-project" in call_args[1]["request"]["name"]
        assert "custom-key" in call_args[1]["request"]["name"]
        assert "versions/5" in call_args[1]["request"]["name"]


class TestSendGridResponseValidation:
    """Test SendGrid response status code validation."""

    def test_sendgrid_non_success_status_returns_502(self, client, mock_firestore, mock_sendgrid):
        """Test that SendGrid returning non-2xx status code results in 502."""
        _setup_firestore_mock(mock_firestore)

        mock_sg = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.body = "Bad Request"
        mock_sg.send.return_value = mock_response
        mock_sendgrid.return_value = mock_sg

        payload = {
            "to_list": ["user@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 502
        detail = response.json()["detail"].lower()
        assert "sendgrid" in detail
        assert "400" in response.json()["detail"]

    def test_sendgrid_server_error_status_returns_502(self, client, mock_firestore, mock_sendgrid):
        """Test that SendGrid returning 500 status code results in 502."""
        _setup_firestore_mock(mock_firestore)

        mock_sg = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.body = "Internal Server Error"
        mock_sg.send.return_value = mock_response
        mock_sendgrid.return_value = mock_sg

        payload = {
            "to_list": ["user@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 502
        assert "sendgrid" in response.json()["detail"].lower()
        assert "500" in response.json()["detail"]

    def test_sendgrid_202_accepted_succeeds(self, client, mock_firestore, mock_sendgrid):
        """Test that SendGrid 202 Accepted is treated as success."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid, status_code=202)

        payload = {
            "to_list": ["user@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200
        assert response.json()["status_code"] == 202


class TestFirestoreEdgeCases:
    """Test Firestore failure paths and edge cases."""

    def test_allowed_domains_firestore_failure(self, client, mock_firestore):
        """Test that Firestore failure during allowed domains fetch returns 500."""
        mock_db = MagicMock()
        mock_firestore.return_value = mock_db

        call_count = [0]
        def make_doc(doc_name):
            call_count[0] += 1
            if doc_name == "blocked_domains":
                # First call succeeds (blocked domains)
                mock_doc_ref = MagicMock()
                mock_doc = MagicMock()
                mock_doc.exists = True
                mock_doc.to_dict.return_value = {"domains": []}
                mock_doc_ref.get.return_value = mock_doc
                return mock_doc_ref
            else:
                # Second call fails (allowed domains)
                mock_doc_ref = MagicMock()
                mock_doc_ref.get.side_effect = Exception("Firestore read error")
                return mock_doc_ref

        mock_collection = MagicMock()
        mock_collection.document.side_effect = make_doc
        mock_db.collection.return_value = mock_collection

        payload = {
            "to_list": ["user@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 500
        assert "Failed to fetch allowed domains" in response.json()["detail"]

    def test_firestore_domains_field_not_a_list(self, mock_firestore):
        """Test when Firestore domains field is a string instead of list."""
        mock_db = MagicMock()
        mock_firestore.return_value = mock_db
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {"domains": "not-a-list"}
        mock_db.collection.return_value.document.return_value.get.return_value = mock_doc

        result = get_blocked_domains()
        # Non-list domains field should be treated as empty
        assert result == []

    def test_firestore_document_empty_dict(self, mock_firestore):
        """Test when Firestore document has no fields at all."""
        mock_db = MagicMock()
        mock_firestore.return_value = mock_db
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {}
        mock_db.collection.return_value.document.return_value.get.return_value = mock_doc

        result = get_allowed_domains()
        assert result == []


class TestMaxRecipientValidation:
    """Test max recipient count enforcement."""

    def test_to_list_exceeds_max_recipients(self, client):
        """Test that to_list exceeding MAX_RECIPIENTS is rejected."""
        payload = {
            "to_list": [f"user{i}@example.com" for i in range(MAX_RECIPIENTS + 1)],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422
        assert "exceeds maximum" in response.json()["detail"][0]["msg"]

    def test_cc_list_exceeds_max_recipients(self, client):
        """Test that cc_list exceeding MAX_RECIPIENTS is rejected."""
        payload = {
            "to_list": ["user@example.com"],
            "cc_list": [f"cc{i}@example.com" for i in range(MAX_RECIPIENTS + 1)],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422
        assert "exceeds maximum" in response.json()["detail"][0]["msg"]

    def test_to_list_at_max_is_accepted(self, client, mock_firestore, mock_sendgrid):
        """Test that to_list at exactly MAX_RECIPIENTS is accepted."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": [f"user{i}@example.com" for i in range(MAX_RECIPIENTS)],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 200


class TestInputTypeValidation:
    """Test Pydantic type coercion and rejection edge cases."""

    def test_to_list_as_string_rejected(self, client):
        """Test that to_list as a plain string (not list) is rejected."""
        payload = {
            "to_list": "user@example.com",
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422

    def test_mail_body_as_number_rejected(self, client):
        """Test that numeric mail_body is rejected by Pydantic strict typing."""
        payload = {
            "to_list": ["user@example.com"],
            "mail_body": 12345
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422

    def test_email_at_sign_only_rejected(self, client):
        """Test that '@' alone is rejected."""
        payload = {
            "to_list": ["@"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422

    def test_email_no_domain_rejected(self, client):
        """Test that email without domain is rejected."""
        payload = {
            "to_list": ["user@"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422

    def test_email_no_local_part_rejected(self, client):
        """Test that email without local part is rejected."""
        payload = {
            "to_list": ["@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422

    def test_empty_body_post(self, client):
        """Test POST with empty body."""
        response = client.post("/send-email")
        assert response.status_code == 422

    def test_mail_body_with_script_tags(self, client, mock_firestore, mock_sendgrid):
        """Test that HTML with script tags is accepted (passed through to SendGrid)."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["user@example.com"],
            "mail_body": "<p>Hello</p><script>alert('xss')</script>"
        }
        response = client.post("/send-email", json=payload)
        # Script tags pass through - email clients handle XSS protection
        assert response.status_code == 200

    def test_whitespace_only_email_rejected(self, client):
        """Test that whitespace-only string in to_list is rejected."""
        payload = {
            "to_list": ["  "],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)
        assert response.status_code == 422


class TestSendGridApiKeyEndpointFlow:
    """Test API key failure paths through the full endpoint."""

    def test_no_api_key_no_project_returns_422(self, client, monkeypatch, mock_firestore):
        """Test that missing SENDGRID_API_KEY + GCP_PROJECT_ID returns 422 via ValueError."""
        monkeypatch.delenv("SENDGRID_API_KEY", raising=False)
        monkeypatch.delenv("GCP_PROJECT_ID", raising=False)

        _setup_firestore_mock(mock_firestore)

        payload = {
            "to_list": ["user@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 422
        assert "Neither SENDGRID_API_KEY nor GCP_PROJECT_ID" in response.json()["detail"]

    def test_sendgrid_200_status_succeeds(self, client, mock_firestore, mock_sendgrid):
        """Test that SendGrid 200 OK is treated as success."""
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid, status_code=200)

        payload = {
            "to_list": ["user@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200
        assert response.json()["status_code"] == 200


class TestFirestoreDomainTypeValidation:
    """Test Firestore domains field type validation."""

    def test_firestore_domains_field_is_int(self, mock_firestore):
        """Test when Firestore domains field is an integer."""
        mock_db = MagicMock()
        mock_firestore.return_value = mock_db
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {"domains": 42}
        mock_db.collection.return_value.document.return_value.get.return_value = mock_doc

        result = get_blocked_domains()
        assert result == []

    def test_firestore_domains_field_is_dict(self, mock_firestore):
        """Test when Firestore domains field is a dict."""
        mock_db = MagicMock()
        mock_firestore.return_value = mock_db
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {"domains": {"key": "value"}}
        mock_db.collection.return_value.document.return_value.get.return_value = mock_doc

        result = get_allowed_domains()
        assert result == []


class TestBQAuditLogging:
    """Test BigQuery audit logging integration."""

    @pytest.fixture
    def mock_bq_audit(self):
        """Mock log_audit to inspect calls without hitting BQ."""
        with patch('routes.log_audit') as mock_log:
            yield mock_log

    def test_audit_called_on_success(self, client, mock_firestore, mock_sendgrid, mock_bq_audit, monkeypatch):
        """Test that log_audit is called with status=success on successful send."""
        monkeypatch.setenv("BQ_AUDIT_ENABLED", "true")
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["user@example.com"],
            "cc_list": ["cc@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200
        mock_bq_audit.assert_called_once()
        call_args = mock_bq_audit.call_args
        assert call_args[0][4] == "success"  # status
        assert call_args[0][5] == 200  # status_code
        assert call_args[0][6] == ""  # error_detail

    def test_audit_called_on_blocked_domain(self, client, mock_firestore, mock_bq_audit, monkeypatch):
        """Test that log_audit is called with status=failure on blocked domain."""
        monkeypatch.setenv("BQ_AUDIT_ENABLED", "true")
        _setup_firestore_mock(mock_firestore, blocked=["blocked.com"])

        payload = {
            "to_list": ["user@blocked.com"],
            "cc_list": [],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 403
        mock_bq_audit.assert_called_once()
        call_args = mock_bq_audit.call_args
        assert call_args[0][4] == "failure"  # status
        assert call_args[0][5] == 403  # status_code
        assert "blocked domain" in call_args[0][6].lower()  # error_detail

    def test_audit_called_on_sendgrid_failure(self, client, mock_firestore, mock_sendgrid, mock_bq_audit, monkeypatch):
        """Test that log_audit is called with status=failure on SendGrid error."""
        monkeypatch.setenv("BQ_AUDIT_ENABLED", "true")
        _setup_firestore_mock(mock_firestore)
        mock_sg_instance = MagicMock()
        mock_sg_instance.send.side_effect = Exception("SendGrid API error")
        mock_sendgrid.return_value = mock_sg_instance

        payload = {
            "to_list": ["user@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 500
        mock_bq_audit.assert_called_once()
        call_args = mock_bq_audit.call_args
        assert call_args[0][4] == "failure"  # status
        assert call_args[0][5] == 500  # status_code

    def test_audit_called_on_value_error(self, client, monkeypatch, mock_firestore, mock_bq_audit):
        """Test that log_audit is called with status=failure on ValueError (missing API key)."""
        monkeypatch.setenv("BQ_AUDIT_ENABLED", "true")
        monkeypatch.delenv("SENDGRID_API_KEY", raising=False)
        monkeypatch.delenv("GCP_PROJECT_ID", raising=False)
        _setup_firestore_mock(mock_firestore)

        payload = {
            "to_list": ["user@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 422
        mock_bq_audit.assert_called_once()
        call_args = mock_bq_audit.call_args
        assert call_args[0][4] == "failure"
        assert call_args[0][5] == 422

    def test_requestor_header_extracted(self, client, mock_firestore, mock_sendgrid, mock_bq_audit, monkeypatch):
        """Test that X-Requestor-Email header is passed to log_audit."""
        monkeypatch.setenv("BQ_AUDIT_ENABLED", "true")
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["user@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post(
            "/send-email",
            json=payload,
            headers={"X-Requestor-Email": "admin@corp.com"}
        )

        assert response.status_code == 200
        call_args = mock_bq_audit.call_args
        assert call_args[0][0] == "admin@corp.com"  # requestor

    def test_requestor_defaults_to_unknown(self, client, mock_firestore, mock_sendgrid, mock_bq_audit, monkeypatch):
        """Test that missing X-Requestor-Email defaults to 'unknown'."""
        monkeypatch.setenv("BQ_AUDIT_ENABLED", "true")
        _setup_firestore_mock(mock_firestore)
        _setup_sendgrid_mock(mock_sendgrid)

        payload = {
            "to_list": ["user@example.com"],
            "mail_body": "<p>Test</p>"
        }
        response = client.post("/send-email", json=payload)

        assert response.status_code == 200
        call_args = mock_bq_audit.call_args
        assert call_args[0][0] == "unknown"  # requestor


class TestBQAuditLoggerUnit:
    """Unit tests for bq_audit_logger module directly."""

    def test_audit_disabled_skips_bq_client(self, monkeypatch):
        """Test that log_audit returns immediately when BQ_AUDIT_ENABLED=false."""
        monkeypatch.setenv("BQ_AUDIT_ENABLED", "false")

        from utilities.bq_audit_logger import log_audit as real_log_audit
        with patch('utilities.bq_audit_logger._get_bq_client') as mock_client:
            real_log_audit("req", "1.2.3.4", ["a@b.com"], [], "success", 200, "")
            mock_client.assert_not_called()

    def test_log_audit_inserts_row(self, monkeypatch):
        """Test that log_audit calls insert_rows_json with correct data."""
        monkeypatch.setenv("BQ_AUDIT_ENABLED", "true")
        monkeypatch.setenv("BQ_PROJECT_ID", "test-proj")
        monkeypatch.setenv("BQ_DATASET", "test_ds")
        monkeypatch.setenv("BQ_TABLE", "test_tbl")

        with patch('utilities.bq_audit_logger._get_bq_client') as mock_get:
            mock_client = MagicMock()
            mock_client.insert_rows_json.return_value = []
            mock_get.return_value = mock_client

            from utilities.bq_audit_logger import log_audit as real_log_audit
            real_log_audit("admin@co.com", "10.0.0.1",
                           ["to@x.com"], ["cc@x.com"],
                           "success", 200, "")

            mock_client.insert_rows_json.assert_called_once()
            call_args = mock_client.insert_rows_json.call_args
            assert "test-proj.test_ds.test_tbl" in call_args[0][0]
            row = call_args[0][1][0]
            assert row["requestor"] == "admin@co.com"
            assert row["status"] == "success"
            assert row["to_list"] == ["to@x.com"]

    def test_log_audit_handles_insert_errors(self, monkeypatch):
        """Test that BQ insert errors are logged as warnings, not raised."""
        monkeypatch.setenv("BQ_AUDIT_ENABLED", "true")
        monkeypatch.setenv("BQ_PROJECT_ID", "test-proj")

        with patch('utilities.bq_audit_logger._get_bq_client') as mock_get:
            mock_client = MagicMock()
            mock_client.insert_rows_json.return_value = [{"error": "bad row"}]
            mock_get.return_value = mock_client

            from utilities.bq_audit_logger import log_audit as real_log_audit
            # Should not raise
            real_log_audit("r", "1.1.1.1", ["a@b.com"], [], "success", 200, "")

    def test_log_audit_handles_client_exception(self, monkeypatch):
        """Test that BQ client exceptions are caught and logged."""
        monkeypatch.setenv("BQ_AUDIT_ENABLED", "true")
        monkeypatch.setenv("BQ_PROJECT_ID", "test-proj")

        with patch('utilities.bq_audit_logger._get_bq_client') as mock_get:
            mock_get.side_effect = Exception("BQ connection failed")

            from utilities.bq_audit_logger import log_audit as real_log_audit
            # Should not raise
            real_log_audit("r", "1.1.1.1", ["a@b.com"], [], "failure", 500, "err")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
