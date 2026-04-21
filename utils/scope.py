"""
GECKO APOCALYPSE - SCOPE MANAGER
Legal scope enforcement and domain validation.
"""

from typing import Dict, List, Set
from urllib.parse import urlparse
from pathlib import Path


class ScopeManager:
    """Manages scan scope and legal boundaries."""

    def __init__(self, config: Dict):
        self.config = config
        self.allowed_domains: Set[str] = set()
        self.excluded_domains: Set[str] = set()
        self.allowed_ips: Set[str] = set()

        # Load out-of-scope domains
        for domain in config.get('out_of_scope_domains', []):
            self.excluded_domains.add(domain.lower())

        # Load scope file
        scope_file = config.get('scope_file', '')
        if scope_file and Path(scope_file).exists():
            self._load_scope_file(scope_file)

    def _load_scope_file(self, path: str):
        """Load scope definitions from file."""
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if line.startswith('!'):
                        self.excluded_domains.add(line[1:].lower())
                    else:
                        self.allowed_domains.add(line.lower())

    def add_target(self, target: str):
        """Add a target to scope."""
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path
        domain = domain.split(':')[0].lower()
        self.allowed_domains.add(domain)

    def is_in_scope(self, url: str) -> bool:
        """Check if URL is within authorized scope."""
        try:
            parsed = urlparse(url)
            domain = (parsed.netloc or parsed.path).split(':')[0].lower()

            # Check exclusions first
            if any(domain.endswith(exc) for exc in self.excluded_domains):
                return False

            # If no explicit scope defined, allow target domain and subdomains
            if not self.allowed_domains:
                return True

            # Check if domain matches any allowed domain
            return any(
                domain == allowed or domain.endswith('.' + allowed)
                for allowed in self.allowed_domains
            )
        except Exception:
            return False

    def print_disclaimer(self):
        """Print legal disclaimer."""
        disclaimer = self.config.get('disclaimer', '')
        if disclaimer:
            print(f"\n{'='*60}")
            print("LEGAL DISCLAIMER")
            print(f"{'='*60}")
            print(disclaimer)
            print(f"{'='*60}\n")
