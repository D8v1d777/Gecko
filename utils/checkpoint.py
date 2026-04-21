"""
GECKO APOCALYPSE - CHECKPOINT MANAGER
Resume scan capability with persistent checkpoints.
"""

import json
import hashlib
from typing import Dict, Optional
from datetime import datetime


class CheckpointManager:
    """Manages scan checkpoints for resume capability."""

    def __init__(self, db):
        self.db = db
        self.scan_id: Optional[str] = None

    def initialize(self, target: str) -> str:
        """Initialize checkpoint for a scan."""
        self.scan_id = hashlib.md5(
            f"{target}-{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:12]
        return self.scan_id

    def save(self, data: Dict):
        """Save checkpoint data."""
        if self.scan_id:
            self.db.store_checkpoint(self.scan_id, data)

    def load(self, scan_id: str) -> Optional[Dict]:
        """Load checkpoint for resume."""
        self.scan_id = scan_id
        return self.db.get_latest_checkpoint(scan_id)

    def get_resume_data(self, target: str) -> Optional[Dict]:
        """Try to find a resumable checkpoint for target."""
        target_id = hashlib.md5(target.encode()).hexdigest()[:12]
        return self.db.get_latest_checkpoint(target_id)
