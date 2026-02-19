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
  "mail_body": "<h1>Hello</h1><p>This is an HTML email</p>"
}
```

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
| `EMAIL_SUBJECT` | No | Default email subject | `Notification` |
| `SENDGRID_SECRET_NAME` | No | Secret Manager secret name | `sendgrid-api-key` |
| `SENDGRID_SECRET_VERSION` | No | Secret version | `latest` |
| `FIRESTORE_COLLECTION` | No | Firestore collection name | `config` |
| `FIRESTORE_DOCUMENT` | No | Firestore document name | `blocked_domains` |

*Either `SENDGRID_API_KEY` or `GCP_PROJECT_ID` must be set.

## Firestore Setup

Create a Firestore document with the following structure:

**Collection:** `config`
**Document:** `blocked_domains`
**Structure:**
```json
{
  "domains": [
    "blocked-domain.com",
    "spam-domain.com",
    "unwanted-domain.org"
  ]
}
```

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
  -d '{
    "to_list": ["recipient@example.com"],
    "cc_list": ["cc@example.com"],
    "mail_body": "<h1>Test Email</h1><p>This is a test email from the API.</p>"
  }'
```

## Error Codes

| Status Code | Description |
|-------------|-------------|
| 200 | Email sent successfully |
| 403 | Blocked domain detected |
| 422 | Invalid email format |
| 500 | Internal server error (SendGrid failure, Firestore error, etc.) |

## Security Considerations

- API runs as non-root user in Docker container
- Credentials stored in Secret Manager (recommended) or environment variables
- Email validation prevents malformed addresses
- Domain blocking prevents sending to unwanted recipients
- Service account with minimal required permissions

## License

MIT
