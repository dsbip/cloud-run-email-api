import logging

logger = logging.getLogger(__name__)


def setup_logging():
    """Configure Cloud Logging when running on GCP, fallback to standard logging locally."""
    try:
        import google.cloud.logging
        cloud_logging_client = google.cloud.logging.Client()
        cloud_logging_client.setup_logging(log_level=logging.INFO)
        logger.info("Cloud Logging initialized successfully")
    except Exception:
        logging.basicConfig(level=logging.INFO)
        logger.info("Cloud Logging not available, using standard logging")
