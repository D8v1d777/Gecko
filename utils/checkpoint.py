"""
GECKO APOCALYPSE - CHECKPOINT MANAGER
Save and resume scan progress
"""

import json
import pickle
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional


class CheckpointManager:
    """Manage scan checkpoints for resume capability."""

    def __init__(self, db):
        self.db = db
        self.checkpoint_dir = Path("data/checkpoints")
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

    def save(self, state: Dict) -> str:
        """Save checkpoint."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        checkpoint_file = self.checkpoint_dir / f"checkpoint_{timestamp}.json"

        checkpoint_data = {
            "timestamp": datetime.now().isoformat(),
            "target": state.get("target"),
            "visited_urls_count": len(state.get("visited", [])),
            "findings_count": len(state.get("findings", [])),
            "stats": state.get("stats", {}),
        }

        # Save lightweight metadata
        with open(checkpoint_file, "w") as f:
            json.dump(checkpoint_data, f, indent=2)

        # Save full state in pickle
        pickle_file = checkpoint_file.with_suffix(".pkl")
        with open(pickle_file, "wb") as f:
            pickle.dump(state, f)

        return str(checkpoint_file)

    def load_latest(self, target: str) -> Optional[Dict]:
        """Load latest checkpoint for target."""
        checkpoints = sorted(
            self.checkpoint_dir.glob("checkpoint_*.json"), reverse=True
        )

        for checkpoint_file in checkpoints:
            try:
                with open(checkpoint_file, "r") as f:
                    metadata = json.load(f)

                if metadata.get("target") == target:
                    # Load full state from pickle
                    pickle_file = checkpoint_file.with_suffix(".pkl")
                    if pickle_file.exists():
                        with open(pickle_file, "rb") as f:
                            return pickle.load(f)
            except:
                continue

        return None

    def list_checkpoints(self) -> list:
        """List all available checkpoints."""
        checkpoints = []

        for checkpoint_file in sorted(
            self.checkpoint_dir.glob("checkpoint_*.json"), reverse=True
        ):
            try:
                with open(checkpoint_file, "r") as f:
                    metadata = json.load(f)
                    checkpoints.append(metadata)
            except:
                continue

        return checkpoints
