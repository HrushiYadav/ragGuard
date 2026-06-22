import logging

logger = logging.getLogger(__name__)


def connect(valkey_url, api_key):
    logger.debug(f"Connected to Valkey at {valkey_url}")
    logger.info(f"Using API key: {api_key}")
