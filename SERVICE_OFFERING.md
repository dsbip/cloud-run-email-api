# Email Sending Service — Service Offering

A centrally-managed HTTP service that lets teams send transactional email
without running their own SMTP stack, API keys, or deliverability
infrastructure. Deployed on Google Cloud Run and backed by SendGrid.

> **Placeholders used in this document.** Before publishing to Confluence,
> find-and-replace the following with your values:
> - `<GCP_DEV_PROJECT_ID>`, `<GCP_PROD_PROJECT_ID>`
> - `<CLOUD_RUN_DEV_SERVICE_NAME>`, `<CLOUD_RUN_PROD_SERVICE_NAME>`
> - `<CLOUD_RUN_DEV_URL>`, `<CLOUD_RUN_PROD_URL>`
> - `<SUPPORT_TEAM_EMAIL>`
> - `<SWAGGER_DOCS_URL>` (the Confluence page or GitLab/GitHub Pages URL
>   where the Redoc reference is hosted)

---

## 1. What the service does

A team sends a `POST /send-email` request with recipients, subject, and
an HTML body. The service:

1. Validates the request (email format, recipient caps, non-empty subject
   and body, no unknown fields).
2. Rejects the send if any recipient domain is on the **blocked** list.
3. Rejects the send if an **allowlist** is configured and a recipient
   domain isn't on it.
4. Removes duplicate CC addresses that already appear in the TO list.
5. Forwards the message to SendGrid for delivery.
6. Returns a unique `request_id` (UUID4) in the response body and
   `x-request-id` response header.
7. Writes an audit record to BigQuery (request_id, requestor,
   recipients, status, timestamp, client IP).

Callers never hold a SendGrid API key, never manage deliverability, and
never run their own SMTP relay. One team owns those concerns; everyone
else owns only their payload.

---

## 2. About SendGrid (our delivery provider)

[SendGrid](https://sendgrid.com) is a cloud email-delivery platform owned
by Twilio. It's the actual system that takes our outbound messages and
puts them in recipient inboxes. We use it because running in-house SMTP
at scale is painful and easy to get wrong.

What SendGrid handles for us:

| Concern | What SendGrid does |
|---|---|
| **Deliverability** | Maintains IP reputation, feedback loops with major providers, rotates sending IPs |
| **Authentication** | Signs every outgoing mail with SPF / DKIM / DMARC using our verified sender domain |
| **Bounce & complaint handling** | Processes soft/hard bounces and spam complaints; exposes suppression lists |
| **Rate limiting & queueing** | Absorbs traffic bursts so our Cloud Run service doesn't have to |
| **Analytics** | Delivery / open / click / bounce metrics per message or campaign |

What our service adds on top:

- **Central audit trail** — every send is logged to BigQuery with the
  caller's identity, so we can answer "who sent what, when" without
  going to SendGrid's UI. Validation errors (422) are also logged.
- **Request tracing** — every response includes a unique `request_id`
  (UUID4) in both the JSON body and the `x-request-id` response header.
  The same id is written to BigQuery, enabling end-to-end correlation
  between caller logs and the audit trail.
- **Domain policy** — a Firestore-backed blocklist and allowlist let us
  block known-bad domains or enforce "only send to `@example.com`"
  without modifying SendGrid configuration.
- **Caller attribution** — every request carries an `x-requestor-system`
  header that identifies the upstream application or service (e.g.,
  `billing-service`, `crm-app`), independent of the service-account
  used to invoke the service.
- **CC deduplication** — if the same address appears in both `to_list`
  and `cc_list`, the service automatically removes it from CC to avoid
  duplicate delivery.
- **Strict payload validation** — unknown request fields are rejected
  immediately (HTTP 422), catching common typos like `email_body`
  instead of `mail_body` at the API boundary.
- **Verified sender** — callers do not choose the `from` address; the
  service enforces a single verified sender, so deliverability is never
  put at risk by a caller misconfiguration.

---

## 3. Environments

Two environments are deployed:

| | **Dev** | **Prod** |
|---|---|---|
| GCP project | `<GCP_DEV_PROJECT_ID>` | `<GCP_PROD_PROJECT_ID>` |
| Cloud Run service name | `<CLOUD_RUN_DEV_SERVICE_NAME>` | `<CLOUD_RUN_PROD_SERVICE_NAME>` |
| Base URL | `<CLOUD_RUN_DEV_URL>` | `<CLOUD_RUN_PROD_URL>` |
| SendGrid account | Shared dev sandbox (no real delivery) | Production SendGrid account (real delivery) |
| Audit dataset (BigQuery) | `email_api_logs` in `<GCP_DEV_PROJECT_ID>` | `email_api_logs` in `<GCP_PROD_PROJECT_ID>` |
| Domain policy source | `config/blocked_domains`, `config/allowed_domains` in dev Firestore | Same, in prod Firestore |
| Allowed caller roles | `roles/run.invoker` granted to each onboarded team's **dev** service account | Same, for **prod** service accounts |

**Important:** test all integration from **dev first**. The dev SendGrid
account is sandboxed — messages are accepted and logged but never
delivered to a real inbox — so you can exercise the happy path and all
error paths without spamming real users.

---

## 4. Authentication

Cloud Run is deployed with IAM-based authentication (no
`--allow-unauthenticated`). Every call must include a Google-signed OIDC
ID token whose **audience** equals the target Cloud Run service URL.

- **From another GCP workload** (Cloud Run, GKE, GCE, Cloud Build): the
  metadata server mints the token for you; most Google client libraries
  do this automatically if you use their ID-token helpers.
- **From a developer workstation (smoke testing)**:

  ```bash
  gcloud auth print-identity-token \
    --audiences="<CLOUD_RUN_DEV_URL>"
  ```

- **From a non-GCP workload**: use a service-account key (carefully)
  with the Google auth client libraries' `fetch_id_token` helper.

Full per-language examples live in the Swagger reference (see §7).

---

## 5. Onboarding a new caller

To start using the service, reach out to the support team at
**<SUPPORT_TEAM_EMAIL>** with the following information:

1. **Team / application name** (for attribution in audit logs).
2. **Caller service account email** in each environment where you want
   access — e.g., `my-app-dev@<GCP_DEV_PROJECT_ID>.iam.gserviceaccount.com`
   and `my-app-prod@<GCP_PROD_PROJECT_ID>.iam.gserviceaccount.com`.
3. **Expected volume** (messages/day, peak burst).
4. **Recipient domains** you intend to send to — needed if the
   allowlist is enforced in your target environment.
5. **Requestor identifier** you'll pass in the `x-requestor-system`
   header (e.g., `billing-service`, `crm-notifications`).

The support team will:

- Grant `roles/run.invoker` on the Cloud Run service to your service
  account in each environment.
- Add your recipient domains to the Firestore allowlist, if the
  environment enforces one.
- Confirm via email once access is live.

Typical turnaround: **1–2 business days**.

---

## 6. How to call the service

Minimal request:

```bash
SERVICE_URL="<CLOUD_RUN_DEV_URL>"
TOKEN=$(gcloud auth print-identity-token --audiences="$SERVICE_URL")

curl -X POST "$SERVICE_URL/send-email" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "x-requestor-system: my-billing-service" \
  -d '{
    "to_list": ["recipient@example.com"],
    "subject": "Hello from the Email API",
    "mail_body": "<p>Hello.</p>"
  }'
```

Successful response (HTTP 200):

```json
{
  "status": "success",
  "message": "Email sent successfully",
  "status_code": 202,
  "request_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
}
```

Every response also includes an `x-request-id` response header with the
same UUID. Save this value — the support team can use it to look up the
exact BigQuery audit row for your request.

| HTTP status | Meaning |
|---|---|
| 200 | Accepted by SendGrid for delivery |
| 401 | Missing or invalid OIDC token |
| 403 | Recipient domain blocked, or not on the allowlist |
| 422 | Validation error — invalid email, empty subject/body, unknown fields, or too many recipients |
| 502 | Upstream failure (SendGrid or Secret Manager) |
| 500 | Unexpected internal error (contact support) |

---

## 7. API reference (Swagger / OpenAPI)

The full request / response schema, all field validators, every error
example, and per-language code samples (cURL, Python, Node, Go) live in
the Swagger reference:

**→ [API reference](<SWAGGER_DOCS_URL>)**

The reference is a Redoc-rendered view of `swagger.yaml` from the
repository. It is embedded directly into Confluence via an iframe; edits
made to `swagger.yaml` on the default branch publish automatically
within ~60 seconds. (Source repository and deployment pipeline are
described in the Deployment Guide page.)

---

## 8. Support

- **Primary channel:** <SUPPORT_TEAM_EMAIL>
- **What to include in a support request:**
  - Environment (dev or prod)
  - Timestamp of the failing request (UTC)
  - Requestor system identifier sent in `x-requestor-system`
  - HTTP status and response body you received
  - The `request_id` from the response body or `x-request-id` response
    header — the support team can look up the exact BigQuery audit row
    and Cloud Run logs using this identifier.
- **Business-hours support** is the default. For production-impacting
  incidents, follow your organisation's standard on-call escalation
  path and include **<SUPPORT_TEAM_EMAIL>** on the thread.

---

## 9. Frequently asked questions

**Can I change the `from` address per request?**
No. The sender is a single verified domain owned by the service; letting
callers pick a `from` address would break SPF/DKIM alignment and damage
deliverability for everyone else on the same SendGrid account.

**Can I send attachments?**
Not currently. This is on the roadmap but not yet implemented. Reach
out to <SUPPORT_TEAM_EMAIL> if you have a concrete use-case — it helps
prioritise.

**What's the rate limit?**
Cloud Run is configured for 80 concurrent requests per instance with
autoscaling up to *N* instances (current value documented on the
Deployment Guide page). SendGrid's plan-level quota is the practical
upper bound; if you expect sustained high volume, flag it on
onboarding so the quota can be reviewed.

**Is the message body scanned or modified?**
No. Bodies are forwarded to SendGrid unchanged after validation (non-
empty check only). SendGrid may itself rewrite tracking pixels or
click-through URLs depending on account configuration; coordinate with
support if that's undesirable for your use-case.

**Where do I see delivery status (opened, bounced, etc.)?**
SendGrid's dashboard. Our service only records whether SendGrid *accepted*
the message (HTTP 202). Post-acceptance events (delivered / opened /
bounced / spam complaint) live in SendGrid. Support can grant read-only
dashboard access on request.
