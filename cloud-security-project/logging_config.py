import logging
import os
from logging.handlers import RotatingFileHandler


def _build_handler(path):
    handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=5)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    return handler


def setup_logging(base_dir):
    logs_dir = os.path.join(base_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)

    logger_names = {
        "app": "app.log",
        "security": "security.log",
        "audit": "audit.log",
        "error": "error.log",
    }

    loggers = {}
    for name, filename in logger_names.items():
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        if not logger.handlers:
            logger.addHandler(_build_handler(os.path.join(logs_dir, filename)))
        loggers[name] = logger

    return loggers
