import logging
import os
import sys
from logging.handlers import RotatingFileHandler


def _build_handler(path):
    handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=5)
    handler.setFormatter(_formatter())
    return handler


def _build_stream_handler():
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_formatter())
    return handler


def _formatter():
    return logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")


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
            logger.addHandler(_build_stream_handler())
        loggers[name] = logger

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    if not any(isinstance(handler, logging.StreamHandler) for handler in root_logger.handlers):
        root_logger.addHandler(_build_stream_handler())

    return loggers
