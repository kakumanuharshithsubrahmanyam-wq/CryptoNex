"""Logging setup.

Log records must not include secrets, database URLs, tokens, or request bodies.
"""

import logging


def configure_logging(log_level: str) -> None:
    """Configure root logging once for the API process."""
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level)
    # SQL echo can include bound parameter values.
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
