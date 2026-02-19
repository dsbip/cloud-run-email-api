# Email Sending API - Learnings and Patterns

## Project Overview
FastAPI-based email sending service with domain validation, Firestore integration for blocked/allowed domains, SendGrid API integration, and BigQuery audit logging — designed for Google Cloud Run deployment.

### Architecture
The codebase follows a **modular architecture** with clear separation of concerns:

```
bt/
├── main.py                          # Thin entry point (imports app factory)
├── app.py                           # FastAPI app factory + exception handlers
├── models.py                        # Pydantic request models + validators
├── routes.py                        # API route handlers (/send-email, /health)
├── services/
│   ├── __init__.py
│   ├── firestore_service.py         # Firestore client + domain checking logic
│   └── sendgrid_service.py          # SendGrid API key retrieval + email sending
├── utilities/
│   ├── __init__.py
│   ├── logging_config.py            # Centralized Cloud Logging setup
│   └── bq_audit_logger.py           # BigQuery audit log writer
├── conftest.py                      # Shared test fixtures (autouse env vars)
├── test_main.py                     # All tests (104 tests, 16 test classes)
├── Dockerfile                       # Multi-stage Docker build for Cloud Run
├── requirements.txt                 # Dev + test dependencies
├── requirements-prod.txt            # Production-only dependencies
├── .env.example                     # Environment variable documentation
├── .coveragerc                      # Coverage configuration
├── pytest.ini                       # Pytest configuration
└── run_tests.py                     # Test runner script
```

---

## Key Learnings

### 1. **FastAPI Application Structure (Modular)**
- **Learning**: FastAPI with Pydantic models provides automatic request validation
- **Implementation**: Used `@field_validator` decorators for custom email validation
- **Pattern**: App factory pattern in `app.py` with `create_app()` — keeps `main.py` as a thin entry point
- **Routing**: Use `APIRouter` in `routes.py`, included via `app.include_router(router)` in the factory
- **Benefit**: Reduces boilerplate code, provides automatic API documentation, and keeps each module focused on a single concern

### 2. **Email Validation**
- **Pattern**: Use regex for email validation: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
- **Implementation**: Validate in Pydantic model validators before processing
- **Mistake to Avoid**: Don't rely on simple string checks; use proper regex patterns

### 3. **Google Cloud Services Integration**

#### Firestore
- **Pattern**: Use hierarchical document structure: `collection/document/field`
- **Implementation**: `config` collection → `blocked_domains` and `allowed_domains` documents → `domains` array each
- **Shared Helper**: Use `_fetch_domain_list(document_name, label)` to avoid duplicating Firestore read logic
- **Error Handling**: Always check if document exists before accessing data
- **Mistake to Avoid**: Don't assume Firestore documents always exist; handle missing documents gracefully

#### Secret Manager
- **Pattern**: Use environment variables first, fallback to Secret Manager
- **Best Practice**: Set secrets as Cloud Run environment variables (recommended by Google)
- **Format**: `projects/{project_id}/secrets/{secret_name}/versions/{version}`
- **Mistake to Avoid**: Don't hardcode API keys; always use Secret Manager or env vars

### 4. **SendGrid Integration**
- **Pattern**: Use the official SendGrid Python SDK
- **Implementation**: Create `Mail` object with from_email, to_emails, subject, and html_content
- **CC Recipients**: Use `Cc()` objects (NOT `Email()`), TO recipients use `To()` objects
- **Error Handling**: Let exceptions propagate to the endpoint handler; don't wrap in try-except inside helper functions
- **Non-2xx Responses**: Raise `RuntimeError` with the SendGrid status code and response body, caught as HTTP 502 (Bad Gateway) by the route handler — surfaces the actual SendGrid error to the caller instead of a generic message

### 5. **Docker for Cloud Run**

#### Key Patterns:
1. **Base Image**: Use `python:3.11-slim` for smaller image size
2. **Non-root User**: Create and run as `appuser` for security
3. **Port Handling**: Use `${PORT:-8080}` to respect Cloud Run's PORT env var
4. **PYTHONUNBUFFERED**: Set to 1 for proper logging in Cloud Run
5. **Multi-stage Builds**: Essential for keeping image size small when gcc is needed

#### Docker Image Optimization (Achieved 50% reduction: 428MB → 212MB):
- **Multi-stage build**: Use a `builder` stage with gcc for compiling C extensions, then copy only installed packages to a clean `python:3.11-slim` final stage
- **Separate requirements files**: Use `requirements-prod.txt` (no test deps) in Docker; `requirements.txt` (with test deps) for development
- **gcc layer is the biggest bloat** (~196MB) — multi-stage build eliminates it from the final image
- **`--prefix=/install`**: Install packages to a separate directory in builder, then `COPY --from=builder /install /usr/local` to final stage
- Copy requirements before code to leverage Docker cache
- Use `exec` in CMD to properly handle signals

### 6. **Environment Variable Management**
- **Pattern**: Create `.env.example` for documentation
- **Required vs Optional**: Clearly document which vars are required
- **Lazy Reading**: Read env vars at call time inside functions (not at module level) — critical for test compatibility with `monkeypatch`
- **Validation**: Validate required env vars when they're needed, not at import time
- **Mistake to Avoid**: Module-level constants like `ENABLED = os.getenv(...)` are evaluated once at import time and cannot be overridden by `monkeypatch.setenv()` in tests. Always read env vars inside functions.

### 7. **Error Handling Strategy**

#### HTTP Status Codes:
- `200`: Success
- `403`: Blocked domain or non-allowed domain (Forbidden)
- `422`: Invalid email format or missing config (Unprocessable Entity) — from `ValueError`
- `502`: SendGrid API failure or Secret Manager failure (Bad Gateway) — from `RuntimeError`
- `500`: Unexpected internal errors (generic catch-all)

#### Pattern (in `routes.py`):
```python
try:
    # Main logic
except HTTPException:
    raise  # Re-raise HTTP exceptions (e.g., 403 blocked domain)
except ValueError as ve:
    raise HTTPException(status_code=422, detail=str(ve))
except RuntimeError as re:
    raise HTTPException(status_code=502, detail=str(re))  # Upstream service failures
except Exception as e:
    raise HTTPException(status_code=500, detail="An unexpected error occurred...")
```

#### Exception Hierarchy in Service Layer:
- `ValueError` — configuration/validation issues (missing API key, missing env var)
- `RuntimeError` — upstream service failures (SendGrid non-2xx response, Secret Manager down)
- `HTTPException` — domain policy violations (blocked/not-allowed domains, raised directly in routes)
- `Exception` — unexpected errors (catch-all safety net)

**Key Principle**: Service functions (`sendgrid_service.py`, `firestore_service.py`) raise domain-appropriate exceptions (`ValueError`, `RuntimeError`). HTTP conversion belongs exclusively in the route handler (`routes.py`).

### 8. **Logging Best Practices**
- **Pattern**: Use Python's `logging` module via centralized `utilities/logging_config.py`
- **Setup**: `setup_logging()` tries Google Cloud Logging first, falls back to `logging.basicConfig`
- **Levels**: INFO for normal operations, WARNING for blocked emails and audit failures, ERROR for critical failures
- **Format**: Include context in messages (e.g., email count, status codes)
- **Cloud Run**: Logs automatically appear in Google Cloud Logging
- **Audit Logging**: Every `/send-email` request is logged to BigQuery with requestor identity, status, and error details (see BigQuery Audit Logging below)

### 9. **API Design Patterns**
- **Health Check**: Always include `/health` endpoint for Cloud Run health checks
- **Root Endpoint**: Include simple `/` endpoint for quick service verification
- **Request/Response Models**: Use Pydantic models for type safety and documentation
- **Optional Fields**: Use `Optional[List[str]] = []` for optional cc_list

### 10. **Modular Architecture**
- **Pattern**: Split monolithic `main.py` into focused modules by responsibility
- **App Factory**: `app.py` defines `create_app()` that configures logging, exception handlers, and includes the router
- **Entry Point**: `main.py` is a thin wrapper that calls `create_app()` and runs uvicorn
- **Service Layer**: `services/` package encapsulates external API interactions (Firestore, SendGrid)
- **Utilities Layer**: `utilities/` package provides cross-cutting concerns (logging, audit)
- **Benefits**: Each module is independently testable, mock paths are explicit (`services.firestore_service._get_firestore_client`), and new services can be added without modifying existing code
- **Singleton Pattern**: Thread-safe lazy-initialized clients using `threading.Lock()` + double-checked locking (same pattern across Firestore and BigQuery clients)

### 11. **BigQuery Audit Logging**
- **Purpose**: Log every `/send-email` API request to BigQuery for audit trail
- **Module**: `utilities/bq_audit_logger.py`
- **Requestor Identity**: Extracted from `X-Requestor-Email` request header (defaults to `"unknown"`)
- **Client IP**: Extracted from `request.client.host`
- **Write Mode**: Synchronous (`insert_rows_json`) — blocks until insert completes
- **Graceful Failure**: BQ errors are logged as warnings but never propagate to the caller; audit failures cannot break the API
- **Kill Switch**: `BQ_AUDIT_ENABLED=false` env var disables all BQ writes

#### BQ Table Schema (assumed to already exist):
| Column | Type | Description |
|---|---|---|
| `timestamp` | TIMESTAMP | When the request was made |
| `requestor` | STRING | Value of `X-Requestor-Email` header |
| `client_ip` | STRING | Caller's IP address |
| `to_list` | STRING (REPEATED) | Recipient email list |
| `cc_list` | STRING (REPEATED) | CC email list |
| `status` | STRING | `success` or `failure` |
| `status_code` | INTEGER | HTTP status code returned |
| `error_detail` | STRING | Error description (empty on success) |

#### BQ Environment Variables:
| Env var | Default | Purpose |
|---|---|---|
| `BQ_PROJECT_ID` | falls back to `GCP_PROJECT_ID` | GCP project for BigQuery |
| `BQ_DATASET` | `email_api_logs` | BigQuery dataset name |
| `BQ_TABLE` | `audit_log` | BigQuery table name |
| `BQ_AUDIT_ENABLED` | `true` | Kill-switch to disable audit logging |

#### Key Design Decision — Reading Config at Call Time:
```python
# WRONG: Module-level constant — evaluated once at import time
BQ_AUDIT_ENABLED = os.getenv("BQ_AUDIT_ENABLED", "true").lower() == "true"

# RIGHT: Function that reads at call time — testable with monkeypatch
def _get_bq_config():
    enabled = os.getenv("BQ_AUDIT_ENABLED", "true").lower() == "true"
    return ..., enabled
```
This pattern is essential for test isolation: `monkeypatch.setenv()` runs after module import, so module-level constants can't be overridden in tests.

### 12. **Centralized Logging Utility**
- **Module**: `utilities/logging_config.py`
- **Pattern**: Extract logging setup from the app factory into a reusable utility
- **Behavior**: Attempts Google Cloud Logging; falls back to `logging.basicConfig` for local development
- **Usage**: Called once by `create_app()` in `app.py`

---

## Common Mistakes and How to Avoid Them

### 1. **Missing Email Validation**
- ❌ **Mistake**: Accepting any string as email address
- ✅ **Solution**: Validate with regex in Pydantic validators
- **Impact**: Prevents SendGrid API failures and invalid email sends

### 2. **Not Handling Missing Firestore Documents**
- ❌ **Mistake**: Assuming blocked_domains document always exists
- ✅ **Solution**: Check `doc.exists` before accessing data
- **Impact**: Prevents runtime errors in production

### 3. **Hardcoding Credentials**
- ❌ **Mistake**: Hardcoding API keys in code
- ✅ **Solution**: Use environment variables and Secret Manager
- **Impact**: Security vulnerability if code is exposed

### 4. **Incorrect Docker Port Configuration**
- ❌ **Mistake**: Hardcoding port 8080 in Dockerfile
- ✅ **Solution**: Use `${PORT:-8080}` to respect Cloud Run's PORT variable
- **Impact**: Cloud Run won't be able to communicate with your app

### 5. **Running Docker Container as Root**
- ❌ **Mistake**: Running application as root user
- ✅ **Solution**: Create and switch to non-root user (`appuser`)
- **Impact**: Security risk; violates least privilege principle

### 6. **Not Including .dockerignore**
- ❌ **Mistake**: Including all files in Docker image
- ✅ **Solution**: Create comprehensive .dockerignore file
- **Impact**: Larger image size, slower builds, potential security issues

### 7. **Improper Error Propagation**
- ❌ **Mistake**: Catching all exceptions and returning generic errors
- ✅ **Solution**: Re-raise HTTPException, convert specific exceptions to appropriate HTTP errors
- **Impact**: Users can't debug issues without proper error messages

### 8. **Missing CC Support in SendGrid**
- ❌ **Mistake**: Only sending to "to_list" recipients
- ✅ **Solution**: Add CC recipients as `[Email(email) for email in cc_list]`
- **Impact**: CC recipients won't receive emails

### 9. **Not Validating Empty Lists**
- ❌ **Mistake**: Allowing empty to_list
- ✅ **Solution**: Validate `to_list` is not empty in Pydantic validator
- **Impact**: Prevents unnecessary API calls to SendGrid

### 10. **Incorrect GCP Service Account Permissions**
- ❌ **Mistake**: Using default service account or overly permissive roles
- ✅ **Solution**: Create dedicated service account with minimal permissions:
  - `roles/datastore.user` for Firestore
  - `roles/secretmanager.secretAccessor` for Secret Manager
  - `roles/bigquery.dataEditor` for BigQuery audit logging
- **Impact**: Security risk; violates least privilege principle

---

## Deployment Checklist

### Pre-Deployment:
- [ ] Create Firestore document with blocked domains (`config/blocked_domains`)
- [ ] Create Firestore document with allowed domains (`config/allowed_domains`) — leave empty to allow all
- [ ] Store SendGrid API key in Secret Manager
- [ ] Create BigQuery dataset and `audit_log` table matching the schema (see Key Learnings #11)
- [ ] Create service account with appropriate permissions
- [ ] Enable required GCP APIs (Cloud Run, Firestore, Secret Manager, BigQuery)
- [ ] Set SENDER_EMAIL environment variable
- [ ] Set BQ_PROJECT_ID, BQ_DATASET, BQ_TABLE, BQ_AUDIT_ENABLED environment variables

### Deployment:
- [ ] Build and push Docker image to GCR
- [ ] Deploy to Cloud Run with environment variables
- [ ] Set secrets as environment variables (recommended)
- [ ] Configure service account for Cloud Run service
- [ ] Test health endpoint
- [ ] Test email sending functionality
- [ ] Verify BigQuery audit logs are being written

### Post-Deployment:
- [ ] Monitor Cloud Run logs
- [ ] Set up alerting for failures
- [ ] Configure Cloud Run autoscaling (if needed)
- [ ] Set up custom domain (if needed)
- [ ] Implement rate limiting (if needed)

---

## Performance Considerations

1. **Firestore Reads**: Cache blocked domains in memory if high traffic expected
2. **Secret Manager**: Use environment variables instead for faster access
3. **Cloud Run Concurrency**: Default is 80 concurrent requests per instance
4. **Cold Starts**: Consider minimum instances if low latency required
5. **Timeouts**: Cloud Run default timeout is 300 seconds, adjust if needed

---

## Security Best Practices

1. ✅ Non-root Docker user
2. ✅ Secrets in Secret Manager or env vars
3. ✅ Service account with minimal permissions
4. ✅ Email validation to prevent injection
5. ✅ Domain blocking and allowlisting for spam prevention
6. ✅ HTTPS only (enforced by Cloud Run)
7. ✅ No hardcoded credentials
8. ✅ Input validation with Pydantic
9. ✅ Audit trail via BigQuery (requestor identity, IP, status, error details)
10. ✅ Requestor identity tracking via `X-Requestor-Email` header

---

## Testing Strategy

### Local Testing:
```bash
# Start service locally
python main.py

# Test health endpoint
curl http://localhost:8080/health

# Test email sending
curl -X POST http://localhost:8080/send-email \
  -H "Content-Type: application/json" \
  -d '{"to_list": ["test@example.com"], "cc_list": [], "mail_body": "<p>Test</p>"}'
```

### Docker Testing:
```bash
# Build image
docker build -t email-api .

# Run container
docker run -p 8080:8080 -e SENDER_EMAIL=test@example.com -e SENDGRID_API_KEY=key email-api

# Test endpoints (same as above)
```

### Cloud Run Testing:
```bash
# Deploy to Cloud Run
gcloud run deploy email-api --image gcr.io/project-id/email-api

# Get service URL
gcloud run services describe email-api --format='value(status.url)'

# Test deployed service
curl -X POST https://your-service-url/send-email -H "Content-Type: application/json" -d '{...}'
```

---

## Monitoring and Debugging

### Cloud Run Logs:
```bash
# View logs
gcloud run services logs read email-api --limit 50

# Stream logs
gcloud run services logs tail email-api
```

### Common Issues:

1. **503 Service Unavailable**: Container didn't start properly; check logs
2. **Permission Denied**: Service account missing IAM roles
3. **Secret Not Found**: Check secret name and version
4. **SendGrid Error**: Verify API key and sender email verification

---

## Future Enhancements

1. **Rate Limiting**: Implement per-user rate limiting
2. **Email Templates**: Support for HTML templates with variable substitution
3. **Async Processing**: Queue emails for bulk sending
4. **Retry Logic**: Implement exponential backoff for failed sends
5. **Email Tracking**: Track opens and clicks via SendGrid
6. **Attachment Support**: Add file attachment capability
7. **Scheduled Emails**: Support for delayed/scheduled sending
8. ~~**Database Logging**: Store sent email records in Firestore/BigQuery~~ ✅ Implemented (BigQuery audit logging)

---

## Cost Optimization

1. **Cloud Run**: Pay only for request time (sub-second billing)
2. **Firestore**: Cache blocked domains to reduce reads
3. **Secret Manager**: Use env vars instead (no API calls)
4. **Container Registry**: Clean up old images
5. **Logs**: Set retention policy for Cloud Logging

---

## Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [SendGrid Python SDK](https://github.com/sendgrid/sendgrid-python)
- [Google Cloud Run Documentation](https://cloud.google.com/run/docs)
- [Firestore Documentation](https://cloud.google.com/firestore/docs)
- [Secret Manager Documentation](https://cloud.google.com/secret-manager/docs)
- [Pytest Documentation](https://docs.pytest.org/)

---

## Testing Patterns and Best Practices

### 10. **Comprehensive Test Suite with Mocking**

#### Test Structure
- **Pattern**: Organize tests by functionality into test classes
- **Implementation**: Use pytest with fixtures for reusable test components
- **Test Classes** (16 classes, 104 tests):
  - `TestHealthEndpoints`: Health check and root endpoint tests
  - `TestEmailValidation`: Input validation tests
  - `TestBlockedDomains`: Domain blocking functionality tests
  - `TestAllowedDomains`: Allowed domain allowlisting tests (15 tests)
  - `TestSendGridIntegration`: SendGrid API integration tests
  - `TestHTMLEmailSupport`: HTML email body tests
  - `TestErrorHandling`: Error handling and edge cases
  - `TestEdgeCases`: Boundary conditions and special cases
  - `TestEmailRegexValidation`: Regex edge cases (dots, hyphens, plus tags)
  - `TestSecretManagerEdgeCases`: Secret Manager failure paths
  - `TestSendGridResponseValidation`: Non-2xx status codes → 502
  - `TestFirestoreEdgeCases`: Firestore failure paths
  - `TestMaxRecipientValidation`: Recipient list limits
  - `TestInputTypeValidation`: Type safety edge cases
  - `TestBQAuditLogging`: Integration tests for audit log calls (7 tests)
  - `TestBQAuditLoggerUnit`: Unit tests for `bq_audit_logger.py` directly (4 tests)

#### Mocking Strategy

**Environment Variables Mocking:**
```python
@pytest.fixture
def mock_env_vars(monkeypatch):
    monkeypatch.setenv("SENDER_EMAIL", "sender@example.com")
    monkeypatch.setenv("SENDGRID_API_KEY", "test-api-key")
    monkeypatch.setenv("GCP_PROJECT_ID", "test-project")
```

**Firestore Mocking** (patch at `services.firestore_service`):
```python
@pytest.fixture
def mock_firestore():
    with patch('services.firestore_service._get_firestore_client') as mock_client:
        mock_db = MagicMock()
        mock_client.return_value = mock_db
        yield mock_client

# Helper function for setting up Firestore mock responses:
def _setup_firestore_mock(mock_firestore, blocked=None, allowed=None):
    mock_db = MagicMock()
    mock_firestore.return_value = mock_db
    docs = {
        "blocked_domains": {"domains": blocked or []},
        "allowed_domains": {"domains": allowed or []},
    }
    def make_doc(doc_name):
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = docs.get(doc_name, {"domains": []})
        return mock_doc
    mock_db.collection.return_value.document.side_effect = \
        lambda name: MagicMock(get=MagicMock(return_value=make_doc(name)))
```

**SendGrid Mocking** (patch at `services.sendgrid_service`):
```python
@pytest.fixture
def mock_sendgrid():
    with patch('services.sendgrid_service.SendGridAPIClient') as mock_client:
        yield mock_client

def _setup_sendgrid_mock(mock_sendgrid, status_code=202):
    mock_sg = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_sg.send.return_value = mock_response
    mock_sendgrid.return_value = mock_sg
```

**Secret Manager Mocking** (patch at `services.sendgrid_service`):
```python
@pytest.fixture
def mock_secret_manager():
    with patch('services.sendgrid_service.secretmanager.SecretManagerServiceClient') as mock_client:
        mock_sm = MagicMock()
        mock_response = MagicMock()
        mock_response.payload.data = b"secret-api-key"
        mock_sm.access_secret_version.return_value = mock_response
        mock_client.return_value = mock_sm
        yield mock_client
```

**BQ Audit Mocking** (patch at `routes`):
```python
@pytest.fixture
def mock_bq_audit(self):
    with patch('routes.log_audit') as mock_log:
        yield mock_log
```

#### Key Testing Patterns

**1. Test Client Setup:**
```python
from fastapi.testclient import TestClient
from main import app

@pytest.fixture
def client():
    return TestClient(app)
```

**2. Autouse Fixtures (Run automatically, in conftest.py):**
```python
@pytest.fixture(autouse=True)
def setup_test_env(monkeypatch):
    # Runs before every test automatically
    monkeypatch.setenv("SENDER_EMAIL", "sender@example.com")
    monkeypatch.setenv("SENDGRID_API_KEY", "test-sendgrid-api-key")
    monkeypatch.setenv("GCP_PROJECT_ID", "test-project-id")
    monkeypatch.setenv("EMAIL_SUBJECT", "Test Email")
    monkeypatch.setenv("PORT", "8080")
    # Disable BQ audit logging in tests by default
    monkeypatch.setenv("BQ_AUDIT_ENABLED", "false")
    monkeypatch.setenv("BQ_DATASET", "test_dataset")
    monkeypatch.setenv("BQ_TABLE", "test_audit_log")
```

**3. Shared Fixtures in conftest.py:**
- Place common fixtures in `conftest.py` for reuse across all tests
- Use `scope="session"` for expensive fixtures that can be shared
- Use `scope="function"` (default) for isolated fixtures

**4. Parametrized Tests:**
```python
@pytest.mark.parametrize("email,expected", [
    ("valid@example.com", True),
    ("invalid-email", False),
    ("@nodomain.com", False),
])
def test_email_validation(email, expected):
    # Test multiple cases with one test function
    pass
```

#### Test Coverage Best Practices

**Recommended Coverage:**
- **Overall Coverage Target**: 80%+ (configured in pytest.ini)
- **Critical Functions**: 100% (email validation, domain checking, sending)
- **Error Paths**: Test all exception paths
- **Edge Cases**: Empty lists, None values, special characters

**Coverage Commands:**
```bash
# Run tests with coverage (--cov=. covers all modules in the project)
pytest test_main.py --cov=. --cov-report=term-missing

# Generate HTML coverage report
pytest test_main.py --cov=. --cov-report=html

# View HTML report
# Open htmlcov/index.html in browser
```

#### Test Categories and Markers

**Using Markers:**
```python
@pytest.mark.unit
def test_email_validation():
    pass

@pytest.mark.integration
def test_full_email_flow():
    pass

@pytest.mark.slow
def test_large_recipient_list():
    pass
```

**Running Specific Tests:**
```bash
# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Skip slow tests
pytest -m "not slow"

# Run specific test class
pytest -k TestEmailValidation

# Run specific test method
pytest -k test_valid_email_addresses
```

#### Common Testing Mistakes and Solutions

**1. Not Mocking External Dependencies**
- ❌ **Mistake**: Calling real Firestore/SendGrid in tests
- ✅ **Solution**: Mock all external services using `unittest.mock.patch`
- **Impact**: Tests become slow, unreliable, and may incur costs

**2. Test Data Pollution**
- ❌ **Mistake**: Sharing mutable test data between tests
- ✅ **Solution**: Use fixtures that return new instances each time
- **Impact**: Tests may pass/fail depending on execution order

**3. Not Testing Error Paths**
- ❌ **Mistake**: Only testing happy path scenarios
- ✅ **Solution**: Test all exception paths and error conditions
- **Impact**: Production bugs go undetected

**4. Incomplete Environment Variable Mocking**
- ❌ **Mistake**: Missing some required env vars in tests
- ✅ **Solution**: Use `autouse=True` fixture to set all required env vars
- **Impact**: Tests fail with confusing errors

**5. Not Testing Edge Cases**
- ❌ **Mistake**: Only testing typical inputs
- ✅ **Solution**: Test empty lists, None values, unicode, long strings
- **Impact**: Application crashes on edge case inputs

**6. Hardcoding Test Values**
- ❌ **Mistake**: Using same test data in every test
- ✅ **Solution**: Use fixtures to provide reusable test data
- **Impact**: Changes require updating multiple tests

**7. Not Asserting Enough**
- ❌ **Mistake**: Only checking status code
- ✅ **Solution**: Assert response body, headers, mock call counts
- **Impact**: Tests may pass despite incorrect behavior

**8. Ignoring Mock Call Verification**
- ❌ **Mistake**: Not verifying mocks were called correctly
- ✅ **Solution**: Use `mock.assert_called_once()`, `mock.assert_called_with()`
- **Impact**: Can't verify integration between components

**9. Not Using Test Client Properly**
- ❌ **Mistake**: Making real HTTP requests in tests
- ✅ **Solution**: Use FastAPI's `TestClient` for synchronous testing
- **Impact**: Tests become slow and require running server

**10. Poor Test Isolation**
- ❌ **Mistake**: Tests depend on execution order
- ✅ **Solution**: Each test should be independent with its own fixtures
- **Impact**: Tests fail randomly when run in different orders

#### Test File Organization

```
bt/
├── main.py                          # Entry point
├── app.py                           # App factory
├── models.py                        # Pydantic models
├── routes.py                        # Route handlers
├── services/                        # Service layer
│   ├── firestore_service.py
│   └── sendgrid_service.py
├── utilities/                       # Cross-cutting utilities
│   ├── logging_config.py
│   └── bq_audit_logger.py
├── test_main.py                     # All tests (104 tests)
├── conftest.py                      # Shared fixtures + autouse env vars
├── pytest.ini                       # Pytest configuration
├── run_tests.py                     # Test runner script
└── .coveragerc                      # Coverage configuration
```

#### Running Tests

**Basic Commands:**
```bash
# Run all tests
pytest test_main.py -v

# Run with coverage
pytest test_main.py --cov=. --cov-report=term-missing --cov-report=html

# Run specific test class
pytest test_main.py::TestEmailValidation -v

# Run specific test method
pytest test_main.py::TestEmailValidation::test_valid_email_addresses -v

# Run tests matching pattern
pytest test_main.py -k "email" -v

# Run with detailed output
pytest test_main.py -vv -s

# Run tests in parallel (requires pytest-xdist)
pytest test_main.py -n auto
```

**Using Test Runner Script:**
```bash
# Interactive test runner
python run_tests.py

# Or run directly
python test_main.py
```

#### CI/CD Integration

**GitHub Actions Example:**
```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pytest test_main.py --cov=. --cov-report=xml
      - uses: codecov/codecov-action@v2
```

**Cloud Build Example:**
```yaml
steps:
  - name: 'python:3.11'
    entrypoint: 'pip'
    args: ['install', '-r', 'requirements.txt']
  - name: 'python:3.11'
    entrypoint: 'pytest'
    args: ['test_main.py', '--cov=.', '--cov-fail-under=80']
```

#### Test Data Management

**Sample Fixtures (in conftest.py):**
```python
@pytest.fixture
def sample_email_payload():
    return {
        "to_list": ["recipient@example.com"],
        "cc_list": ["cc@example.com"],
        "mail_body": "<p>Test email</p>"
    }

@pytest.fixture
def sample_blocked_domains():
    return ["blocked.com", "spam.org"]

@pytest.fixture
def sample_html_email():
    return "<h1>Welcome</h1><p>Test content</p>"
```

#### Debugging Failed Tests

**Useful Options:**
```bash
# Show print statements
pytest test_main.py -s

# Stop at first failure
pytest test_main.py -x

# Show full traceback
pytest test_main.py --tb=long

# Show local variables
pytest test_main.py -l

# Start debugger on failure
pytest test_main.py --pdb

# Show 10 slowest tests
pytest test_main.py --durations=10
```

#### Test Performance Optimization

1. **Use session-scoped fixtures** for expensive operations
2. **Mock external calls** - never make real API calls in unit tests
3. **Run tests in parallel** - use `pytest-xdist`
4. **Skip slow tests** during development - use markers
5. **Cache fixture results** when possible

#### Testing Checklist

**Before Committing:**
- [ ] All tests pass locally
- [ ] Coverage is above 80%
- [ ] No hardcoded credentials in tests
- [ ] All external dependencies are mocked
- [ ] Edge cases are tested
- [ ] Error paths are tested
- [ ] Mock assertions verify correct behavior

**Test Coverage Areas:**
- [ ] Health endpoints (GET /, GET /health)
- [ ] Email validation (valid/invalid formats)
- [ ] Empty and missing field validation
- [ ] Blocked domain checking
- [ ] Allowed domain checking (with empty allowlist = all allowed)
- [ ] SendGrid integration (success/failure/non-2xx → 502)
- [ ] Environment variable handling
- [ ] HTML email support
- [ ] CC recipients functionality
- [ ] Multiple recipients
- [ ] Error handling (Firestore, Secret Manager, SendGrid)
- [ ] Unicode and special characters
- [ ] Case-insensitive domain blocking
- [ ] Subdomain blocking
- [ ] BigQuery audit logging (success/failure/disabled/BQ errors)
- [ ] Requestor header extraction (present/missing → "unknown")
- [ ] Audit log called on all paths (success, 403, 422, 500, 502)

---

## Code Review Findings (2026-02-10)

### Bugs Found and Fixed

**1. CRITICAL: SendGrid CC Recipients Used Wrong Object Type**
- **Bug**: `message.cc = [Email(email) for email in cc_list]` used `Email` objects for CC
- **Fix**: Changed to `message.cc = [Cc(email) for email in cc_list]` and `to_emails=[To(email) for email in to_list]`
- **Root Cause**: SendGrid SDK validates that CC recipients use `Cc` class, not generic `Email`
- **Impact**: ALL emails with CC recipients would fail with "Please use a To, From, Cc or Bcc object"
- **Lesson**: Always import and use the correct SendGrid helper class for each recipient type (`To`, `Cc`, `Bcc`)

**2. Unused Imports in main.py**
- **Bug**: `validator`, `To`, `Content` imported but never used
- **Fix**: Removed `validator` and `Content`; kept `To` (now used properly)
- **Lesson**: Unused imports can mask real dependency issues and confuse readers

**3. config.py Was Dead Code**
- **Bug**: `config.py` defined a `Config` class that was never imported by `main.py`
- **Bug**: Class attributes evaluated at import time (env vars baked in at startup)
- **Bug**: Auto-validated on import, printing warnings during test runs
- **Fix**: Converted to function-based config that reads env vars lazily
- **Lesson**: Don't auto-execute validation on module import; it breaks test isolation

**4. Dockerfile Missing config.py**
- **Bug**: `COPY main.py .` only copied main.py, not config.py
- **Fix**: Changed to `COPY main.py config.py ./`
- **Lesson**: Always verify Dockerfile copies ALL necessary application files

**5. send_email_via_sendgrid Swallowed HTTPExceptions**
- **Bug**: Broad `except Exception` caught `HTTPException` from `get_sendgrid_api_key()` and re-wrapped it
- **Fix**: Removed unnecessary try/except; let exceptions propagate to the endpoint handler
- **Lesson**: Don't wrap every function in try/except. Let exceptions bubble up to a single handler

**6. get_sendgrid_api_key Wrapped ValueError in HTTPException**
- **Bug**: Converted `ValueError` to `HTTPException` inside the function, losing the ability for callers to distinguish error types
- **Fix**: Let `ValueError` propagate naturally; endpoint handler converts it to HTTP 422
- **Lesson**: Functions should raise domain-appropriate exceptions; HTTP conversion belongs in the endpoint

### Test Infrastructure Issues Found and Fixed

**7. Redundant mock_env_vars Fixture**
- **Bug**: `test_main.py` had `mock_env_vars` fixture that duplicated conftest.py's `autouse` fixture
- **Fix**: Removed `mock_env_vars`; all tests rely on conftest.py's autouse fixture
- **Lesson**: Autouse fixtures in conftest.py run for ALL tests; don't duplicate them

**8. Unused Imports and Fixtures in conftest.py**
- **Bug**: `Generator`, `os`, `MagicMock` imported but unused; `test_config`, `sample_html_email`, `mock_firestore_client`, `mock_sendgrid_client`, `mock_secret_manager_client`, `assert_valid_email`, `cleanup` fixtures defined but never used
- **Bug**: `pytest_configure` duplicated marker definitions already in pytest.ini
- **Fix**: Removed all unused code; kept only what tests actually use
- **Lesson**: Keep test infrastructure lean; unused fixtures add confusion

**9. Coverage Config in Wrong File**
- **Bug**: `[coverage:run]` and `[coverage:report]` sections in pytest.ini are ignored (coverage reads from `.coveragerc` or `pyproject.toml`)
- **Fix**: Created proper `.coveragerc` file; simplified pytest.ini
- **Lesson**: Coverage config must be in `.coveragerc`, `setup.cfg`, or `pyproject.toml`

**10. Firestore Collection/Document Hardcoded**
- **Bug**: Firestore collection and document names were hardcoded strings in `get_blocked_domains()`
- **Fix**: Made configurable via `FIRESTORE_COLLECTION` and `FIRESTORE_DOCUMENT` env vars
- **Lesson**: Configuration values should come from environment, not be hardcoded

### Test Improvements Made (2026-02-10)

- Added `_setup_firestore_mock()` and `_setup_sendgrid_mock()` helpers to reduce mock boilerplate
- Added new test cases: `test_whitespace_only_mail_body`, `test_missing_mail_body`, `test_get_blocked_domains_missing_domains_field`, `test_check_blocked_domains_empty_list`, `test_check_blocked_domains_empty_blocked`, `test_get_sendgrid_api_key_no_env_no_project`, `test_invalid_json_body`, `test_wrong_content_type`, `test_single_to_recipient_no_cc`, `test_cc_list_explicit_none`
- Total: 41 tests, 97.56% coverage, all passing

### Allowed Domains Feature (2026-02-10)

**11. Allowed Domains (Allowlisting)**
- **Implementation**: Added `allowed_domains` Firestore document alongside `blocked_domains`
- **Logic**: Blocked domains checked first → allowed domains checked second → email sent
- **Empty Allowlist = All Permitted**: If `allowed_domains` document is empty or missing, no allowlist filtering is applied
- **Shared Helper**: `_fetch_domain_list(document_name, label)` handles both blocked and allowed domain fetches
- **Subdomain Support**: Both `check_blocked_domains()` and `check_allowed_domains()` support subdomain matching (e.g., `sub.blocked.com` matches `blocked.com`)
- **Firestore Mock for Multiple Documents**: Use `side_effect` on `document()` to return different mock data based on document name:
  ```python
  def make_doc(doc_name):
      mock_doc = MagicMock()
      mock_doc.exists = True
      mock_doc.to_dict.return_value = docs.get(doc_name, {"domains": []})
      ...
  mock_collection.document.side_effect = make_doc
  ```
- **15 new tests added** covering: allowed-only, blocked+allowed, empty allowlist, subdomains, case insensitivity, CC recipients against allowlist

### Key Takeaway Patterns

1. **Always run tests against real SDK classes** - Mocking only the network layer (SendGridAPIClient) caught the CC bug because real `Mail` object validation ran
2. **Mock at the boundary, not everywhere** - Mock external API clients, not internal data classes
3. **One autouse fixture for env vars** - Centralizes test setup, avoids duplication
4. **Helper functions over fixture bloat** - `_setup_firestore_mock()` is simpler than complex fixture chains
5. **Let exceptions propagate** - Handle them at the outermost layer (endpoint), not in every function

---

## Codebase Modularization (2026-02-18)

### What Changed
Refactored monolithic `main.py` (374 lines) into 7 focused modules:

| Before | After | Purpose |
|---|---|---|
| `main.py` (374 lines) | `main.py` (8 lines) | Thin entry point |
| — | `app.py` | App factory + exception handlers |
| — | `models.py` | Pydantic models + validators |
| — | `routes.py` | API route handlers |
| — | `services/firestore_service.py` | Firestore operations |
| — | `services/sendgrid_service.py` | SendGrid operations |
| — | `utilities/logging_config.py` | Centralized Cloud Logging |
| — | `utilities/bq_audit_logger.py` | BigQuery audit logging |

### Mock Path Updates
When modularizing, **all mock paths must be updated** to target the new module locations:

| Before (monolith) | After (modular) |
|---|---|
| `main.firestore.Client` | `services.firestore_service._get_firestore_client` |
| `main.SendGridAPIClient` | `services.sendgrid_service.SendGridAPIClient` |
| `main.secretmanager.SecretManagerServiceClient` | `services.sendgrid_service.secretmanager.SecretManagerServiceClient` |
| — (new) | `routes.log_audit` |
| — (new) | `utilities.bq_audit_logger._get_bq_client` |

### Learnings from Modularization

**12. Module-Level Environment Variables Break Test Isolation**
- **Bug**: `BQ_AUDIT_ENABLED = os.getenv("BQ_AUDIT_ENABLED", "true").lower() == "true"` was a module-level constant
- **Root Cause**: Module-level code runs once at import time, before any test's `monkeypatch.setenv()` can override it
- **Fix**: Moved env var reading into `_get_bq_config()` function called inside `log_audit()` at request time
- **Lesson**: In a test environment using `monkeypatch`, NEVER use module-level `os.getenv()` for values that tests need to override. Always read env vars inside functions.

**13. Endpoint Signature Change for Audit Logging**
- **Change**: `send_email(request: EmailRequest)` → `send_email(request: Request, body: EmailRequest)`
- **Reason**: FastAPI's `Request` object needed to access headers (`X-Requestor-Email`) and client IP (`request.client.host`)
- **Pattern**: When you need both the raw request and a Pydantic body, accept `Request` first and the body parameter second

**14. SendGrid Non-2xx → HTTP 502 Bad Gateway**
- **Before**: `RuntimeError` caught by generic `except Exception` → returned 500 with "An unexpected error occurred"
- **After**: `RuntimeError` caught by explicit `except RuntimeError` → returned 502 with actual SendGrid error details
- **Benefit**: Callers can distinguish between upstream service failures (502) and internal bugs (500)
- **Lesson**: Use specific exception types to provide meaningful HTTP status codes: `ValueError` → 422, `RuntimeError` → 502, `Exception` → 500

**15. Dockerfile Must Copy All New Directories**
- **Change**: Added `COPY services/ ./services/` and `COPY utilities/ ./utilities/` to Dockerfile
- **Lesson**: Every new Python package added to the project must be explicitly copied in the Dockerfile

**16. Coverage Flag Change**
- **Before**: `--cov=main` (only covered the single main.py file)
- **After**: `--cov=.` (covers all Python modules in the project)
- **Lesson**: When modularizing, update coverage configuration to cover the full source tree

### Test Results After Modularization
- All 94 existing tests continued to pass after modularization (mock paths updated)
- 10 new tests added for BigQuery audit logging (7 integration + 4 unit - 1 overlap)
- **Total: 104 tests, 94.12% coverage**

---

**Last Updated**: 2026-02-19
**Project Version**: 2.0.0
**Test Results**: 104 passed, 0 failed
**Test Coverage**: 94.12% (minimum: 80%)
**Docker Image Size**: 212MB (optimized from 428MB via multi-stage build)
