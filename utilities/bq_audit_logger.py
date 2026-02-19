import os
import logging
import threading
from datetime import datetime, timezone
from typing import List
from google.cloud import bigquery

logger = logging.getLogger(__name__)

# Lazy-initialized BigQuery client (reused across requests)
_bq_client = None
_bq_lock = threading.Lock()


def _get_bq_config():
    """Read BQ configuration from environment at call time (testable via monkeypatch)."""
    project = os.getenv("BQ_PROJECT_ID") or os.getenv("GCP_PROJECT_ID")
    dataset = os.getenv("BQ_DATASET", "email_api_logs")
    table = os.getenv("BQ_TABLE", "audit_log")
    enabled = os.getenv("BQ_AUDIT_ENABLED", "true").lower() == "true"
    return project, dataset, table, enabled


def _get_bq_client(project_id):
    """Get or create a shared BigQuery client (thread-safe)."""
    global _bq_client
    if _bq_client is None:
        with _bq_lock:
            if _bq_client is None:
                _bq_client = bigquery.Client(project=project_id)
    return _bq_client


def log_audit(
    requestor: str,
    client_ip: str,
    to_list: List[str],
    cc_list: List[str],
    status: str,
    status_code: int,
    error_detail: str,
) -> None:
    """
    Insert an audit log row into BigQuery.

    Fails gracefully — BQ errors are logged as warnings but never
    propagate to the caller, so audit failures cannot break the API.
    """
    project_id, dataset, table, enabled = _get_bq_config()

    if not enabled:
        logger.debug("BQ audit logging is disabled, skipping")
        return

    try:
        client = _get_bq_client(project_id)
        table_ref = f"{project_id}.{dataset}.{table}"

        row = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "requestor": requestor,
            "client_ip": client_ip,
            "to_list": to_list,
            "cc_list": cc_list,
            "status": status,
            "status_code": status_code,
            "error_detail": error_detail,
        }

        errors = client.insert_rows_json(table_ref, [row])
        if errors:
            logger.warning(f"BQ audit log insert errors: {errors}")
        else:
            logger.debug("BQ audit log row inserted successfully")
    except Exception as e:
        logger.warning(f"Failed to write BQ audit log: {e}")
