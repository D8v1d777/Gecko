"""
GECKO APOCALYPSE - LOGGING SETUP
Structured logging with file and console output.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict


def setup_logging(config: Dict) -> logging.Logger:
    """Configure structured logging."""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"gecko_{timestamp}.log"

    logger = logging.getLogger("gecko_apocalypse")
    logger.setLevel(logging.DEBUG)

    # File handler - detailed
    fh = logging.FileHandler(log_file, encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    fh.setFormatter(file_fmt)

    # Console handler - minimal
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.WARNING)
    console_fmt = logging.Formatter('%(levelname)s: %(message)s')
    ch.setFormatter(console_fmt)

    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger
