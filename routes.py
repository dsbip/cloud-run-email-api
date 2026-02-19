import logging
from fastapi import APIRouter, HTTPException, Request, status
from models import EmailRequest
from services.firestore_service import (
    get_blocked_domains, get_allowed_domains,
    check_blocked_domains, check_allowed_domains,
)
from services.sendgrid_service import send_email_via_sendgrid
from utilities.bq_audit_logger import log_audit

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "healthy", "service": "Email Sending API"}


@router.get("/health")
async def health_check():
    """Health check endpoint for Cloud Run."""
    return {"status": "healthy"}


@router.post("/send-email", status_code=status.HTTP_200_OK)
def send_email(request: Request, body: EmailRequest):
    """
    Send email endpoint.

    Validates email addresses, checks against blocked domains,
    and sends email via SendGrid.
    """
    requestor = request.headers.get("X-Requestor-Email", "unknown")
    client_ip = request.client.host if request.client else "unknown"
    to_list = body.to_list
    cc_list = body.cc_list or []

    try:
        # Step 1: Email validation is done by Pydantic validators
        logger.info(f"Received request to send email to {len(to_list)} recipients")

        all_emails = to_list + cc_list

        # Step 2: Check blocked domains
        blocked_domains = get_blocked_domains()
        blocked_email = check_blocked_domains(all_emails, blocked_domains)
        if blocked_email:
            logger.warning(f"Blocked email address detected: {blocked_email}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Email address '{blocked_email}' belongs to a blocked domain"
            )

        # Step 3: Check allowed domains
        allowed_domains = get_allowed_domains()
        not_allowed_email = check_allowed_domains(all_emails, allowed_domains)
        if not_allowed_email:
            logger.warning(f"Email address not in allowed domains: {not_allowed_email}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Email address '{not_allowed_email}' does not belong to an allowed domain"
            )

        # Step 4: Send email via SendGrid
        result = send_email_via_sendgrid(
            to_list=to_list,
            cc_list=cc_list,
            mail_body=body.mail_body
        )

        # Step 5: Audit log on success
        log_audit(requestor, client_ip, to_list, cc_list,
                  "success", 200, "")

        return result

    except HTTPException as he:
        log_audit(requestor, client_ip, to_list, cc_list,
                  "failure", he.status_code, he.detail)
        raise
    except ValueError as ve:
        log_audit(requestor, client_ip, to_list, cc_list,
                  "failure", 422, str(ve))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(ve)
        ) from ve
    except RuntimeError as re:
        log_audit(requestor, client_ip, to_list, cc_list,
                  "failure", 502, str(re))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(re)
        ) from re
    except Exception as e:
        log_audit(requestor, client_ip, to_list, cc_list,
                  "failure", 500, str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while sending the email"
        ) from e
