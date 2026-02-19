import os
import threading
import logging
from typing import List, Optional
from fastapi import HTTPException, status
from google.cloud import firestore

logger = logging.getLogger(__name__)

# Firestore configuration from environment
FIRESTORE_COLLECTION = os.getenv("FIRESTORE_COLLECTION", "config")
FIRESTORE_BLOCKED_DOCUMENT = os.getenv("FIRESTORE_BLOCKED_DOCUMENT", "blocked_domains")
FIRESTORE_ALLOWED_DOCUMENT = os.getenv("FIRESTORE_ALLOWED_DOCUMENT", "allowed_domains")

# Lazy-initialized Firestore client (reused across requests)
_firestore_client = None
_firestore_lock = threading.Lock()


def _get_firestore_client():
    """Get or create a shared Firestore client (thread-safe)."""
    global _firestore_client
    if _firestore_client is None:
        with _firestore_lock:
            if _firestore_client is None:
                _firestore_client = firestore.Client()
    return _firestore_client


def _fetch_domain_list(document_name: str, label: str) -> List[str]:
    """
    Fetch a domain list from a Firestore document.
    Expected structure: document with a 'domains' array field.
    """
    try:
        db = _get_firestore_client()
        doc_ref = db.collection(FIRESTORE_COLLECTION).document(document_name)
        doc = doc_ref.get()

        if doc.exists:
            data = doc.to_dict()
            domains = data.get('domains', [])
            if not isinstance(domains, list):
                logger.warning(f"{label.capitalize()} domains field is not a list, ignoring")
                return []
            logger.debug(f"Fetched {len(domains)} {label} domains from Firestore")
            return domains
        else:
            logger.warning(f"{label.capitalize()} domains document not found in Firestore")
            return []
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch {label} domains"
        ) from e


def get_blocked_domains() -> List[str]:
    """Fetch blocked email domains from Firestore."""
    return _fetch_domain_list(FIRESTORE_BLOCKED_DOCUMENT, "blocked")


def get_allowed_domains() -> List[str]:
    """Fetch allowed email domains from Firestore."""
    return _fetch_domain_list(FIRESTORE_ALLOWED_DOCUMENT, "allowed")


def check_blocked_domains(email_list: List[str], blocked_domains: List[str]) -> Optional[str]:
    """
    Check if any email in the list belongs to a blocked domain.
    Returns the first blocked email found, or None if all emails are allowed.
    """
    for email in email_list:
        domain = email.split('@')[1].lower()
        for blocked_domain in blocked_domains:
            if domain == blocked_domain.lower() or domain.endswith('.' + blocked_domain.lower()):
                return email
    return None


def check_allowed_domains(email_list: List[str], allowed_domains: List[str]) -> Optional[str]:
    """
    Check if all emails belong to an allowed domain.
    If allowed_domains is empty, all domains are permitted (no allowlist enforced).
    Returns the first non-allowed email found, or None if all are allowed.
    """
    if not allowed_domains:
        return None

    allowed_lower = [d.lower() for d in allowed_domains]
    for email in email_list:
        domain = email.split('@')[1].lower()
        is_allowed = False
        for allowed_domain in allowed_lower:
            if domain == allowed_domain or domain.endswith('.' + allowed_domain):
                is_allowed = True
                break
        if not is_allowed:
            return email
    return None
