"""
logger.py
---------
Sets up a scan log so every scan run leaves a timestamped audit trail.
This mirrors what a real SOC environment expects: every detection tool
should log what it scanned, what it found, and what action it took.
"""

import logging
import os


def setup_logger(log_dir=None, log_filename="scan_log.txt"):
    """
    Configure and return a logger that writes to both a log file and
    the console. Each run appends to the same log file so you build up
    a history of scans over time (useful for review / reporting).
    """
    if log_dir is None:
        log_dir = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(log_dir, exist_ok=True)

    log_path = os.path.join(log_dir, log_filename)

    logger = logging.getLogger("basic_av_sim")
    logger.setLevel(logging.INFO)

    # Avoid adding duplicate handlers if setup_logger() gets called more
    # than once in the same process (e.g. in tests).
    if not logger.handlers:
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger, log_path
