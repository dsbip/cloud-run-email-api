# Email Sending API

A FastAPI-based email sending service with domain blocking and SendGrid integration, designed for deployment on Google Cloud Run.

## Features

- ✉️ Send emails via SendGrid API
- ✅ Email address validation
- 🚫 Blocked domain checking via Firestore
- 🔐 Secure credential management via Secret Manager
- 🐳 Dockerized for Cloud Run deployment
- 📝 HTML email support

## API Endpoint

### POST `/send-email`

Send an email to specified recipients with optional CC.

**Request Body:**
```json
{
  "to_list": ["recipient1@example.com", "recipient2@example.com"],
  "cc_list": ["cc@example.com"],
  "subject": "Hello from Cloud Run",
  "mail_body": "<h1>Hello</h1><p>This is an HTML email</p>"
}
```

> `subject` is now a **required** field on every request. The legacy
> `EMAIL_SUBJECT` env var is no longer consulted.

**Response (Success):**
```json
{
  "status": "success",
  "message": "Email sent successfully",
  "status_code": 202
}
```

**Response (Error - Invalid Email):**
```json
{
  "detail": "Invalid email address: invalid-email"
}
```

**Response (Error - Blocked Domain):**
```json
{
  "detail": "Email address 'user@blocked.com' belongs to a blocked domain"
}
```

## Environment Variables

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `PORT` | No | Server port | `8080` |
| `SENDER_EMAIL` | Yes | Email address to send from | - |
| `SENDGRID_API_KEY` | Yes* | SendGrid API key | - |
| `GCP_PROJECT_ID` | Yes* | GCP Project ID (for Secret Manager) | - |
| `SENDGRID_SECRET_NAME` | No | Secret Manager secret name | `sendgrid-api-key` |
| `SENDGRID_SECRET_VERSION` | No | Secret version | `latest` |
| `FIRESTORE_COLLECTION` | No | Firestore collection name | `config` |
| `FIRESTORE_BLOCKED_DOCUMENT` | No | Blocked domains document | `blocked_domains` |
| `FIRESTORE_ALLOWED_DOCUMENT` | No | Allowed domains document | `allowed_domains` |
| `FIRESTORE_DATABASE` | No | Firestore database id (non-default) | `default-dev` (see note) |
| `BQ_PROJECT_ID` | No | Project for BigQuery audit logging | falls back to `GCP_PROJECT_ID` |
| `BQ_DATASET` | No | BQ dataset for audit log | `email_api_logs` |
| `BQ_TABLE` | No | BQ table for audit log | `audit_log` |
| `BQ_AUDIT_ENABLED` | No | Kill-switch for BQ writes | `true` |
| `MAX_RECIPIENTS` | No | Max TO/CC recipients per request | `500` |

*Either `SENDGRID_API_KEY` or `GCP_PROJECT_ID` must be set.

## Firestore Setup

The service reads two documents in the `config` collection (configurable via
`FIRESTORE_BLOCKED_DOCUMENT` / `FIRESTORE_ALLOWED_DOCUMENT`):

**Collection:** `config`
**Documents:** `blocked_domains`, `allowed_domains`

The `domains` field may be either an **array** *or* a **map** (the service
normalises both shapes — maps are flattened to a list of their values). Example:

```json
// array form
{ "domains": ["blocked-domain.com", "spam-domain.org"] }

// map form (each key is an arbitrary id)
{
  "domains": {
    "0": "blocked-domain.com",
    "1": "spam-domain.org"
  }
}
```

An empty/missing `allowed_domains` document means *no allowlist is enforced*
(all non-blocked domains are permitted).

### Firestore database id
If you use a non-default Firestore database (e.g., `default-dev`), the
service initialises the client with that database id in
`services/firestore_service.py`. Update the string there (or promote it to
an env var) for your project.

## Local Development

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Set up Google Cloud credentials:
```bash
export GOOGLE_APPLICATION_CREDENTIALS="path/to/service-account-key.json"
```

4. Run the application:
```bash
python main.py
```

The API will be available at `http://localhost:8080`

## Docker Build

Build the Docker image:
```bash
docker build -t email-api .
```

Run locally:
```bash
docker run -p 8080:8080 \
  -e SENDER_EMAIL="noreply@example.com" \
  -e SENDGRID_API_KEY="your-api-key" \
  -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/keys/service-account.json \
  -v /path/to/service-account.json:/tmp/keys/service-account.json:ro \
  email-api
```

## Google Cloud Run Deployment

### Prerequisites

1. Enable required APIs:
```bash
gcloud services enable run.googleapis.com
gcloud services enable secretmanager.googleapis.com
gcloud services enable firestore.googleapis.com
gcloud services enable containerregistry.googleapis.com
```

2. Create SendGrid API key secret:
```bash
echo -n "your-sendgrid-api-key" | gcloud secrets create sendgrid-api-key --data-file=-
```

### Deploy to Cloud Run

1. Set project ID:
```bash
export PROJECT_ID=your-gcp-project-id
gcloud config set project $PROJECT_ID
```

2. Build and push Docker image:
```bash
gcloud builds submit --tag gcr.io/$PROJECT_ID/email-api
```

3. Deploy to Cloud Run:
```bash
gcloud run deploy email-api \
  --image gcr.io/$PROJECT_ID/email-api \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars SENDER_EMAIL=noreply@yourdomain.com \
  --set-env-vars GCP_PROJECT_ID=$PROJECT_ID \
  --set-secrets SENDGRID_API_KEY=sendgrid-api-key:latest \
  --service-account email-api-sa@$PROJECT_ID.iam.gserviceaccount.com
```

### Service Account Setup

Create a service account with required permissions:

```bash
# Create service account
gcloud iam service-accounts create email-api-sa \
  --display-name "Email API Service Account"

# Grant Firestore access
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member serviceAccount:email-api-sa@$PROJECT_ID.iam.gserviceaccount.com \
  --role roles/datastore.user

# Grant Secret Manager access
gcloud secrets add-iam-policy-binding sendgrid-api-key \
  --member serviceAccount:email-api-sa@$PROJECT_ID.iam.gserviceaccount.com \
  --role roles/secretmanager.secretAccessor
```

## Testing

Test the API using curl:

```bash
curl -X POST "https://your-cloud-run-url/send-email" \
  -H "Content-Type: application/json" \
  -H "x-requestor-system: my-service" \
  -d '{
    "to_list": ["recipient@example.com"],
    "cc_list": ["cc@example.com"],
    "subject": "Test Email",
    "mail_body": "<h1>Test Email</h1><p>This is a test email from the API.</p>"
  }'
```

### OpenAPI / Swagger

A full OpenAPI 3.0 spec ships at [`swagger.yaml`](swagger.yaml). Every
endpoint ships with `x-codeSamples` blocks (cURL, Python `requests`,
JavaScript `fetch`, Node `axios`, Go `net/http`) that render as copy-paste
code panels in Redoc / SwaggerHub / any viewer that honours the extension.

Render locally with Redoc:

```bash
npx @redocly/cli preview-docs swagger.yaml
# or static HTML
npx @redocly/cli build-docs swagger.yaml -o swagger.html
```

## Error Codes

| Status Code | Description |
|-------------|-------------|
| 200 | Email sent successfully |
| 403 | Blocked domain detected, or recipient not in allowlist |
| 422 | Validation error (invalid email, empty `subject`, empty `mail_body`, missing config) |
| 502 | Upstream failure (SendGrid non-2xx or Secret Manager error) |
| 500 | Unexpected internal error |

## Security Considerations

- API runs as non-root user in Docker container
- Credentials stored in Secret Manager (recommended) or environment variables
- Email validation prevents malformed addresses
- Domain blocking prevents sending to unwanted recipients
- Service account with minimal required permissions

## License

MIT
