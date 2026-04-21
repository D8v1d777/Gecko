"""GECKO APOCALYPSE - Plugin Architecture for extensibility"""

import importlib
import os
import sys
from pathlib import Path
from typing import Dict, List


class PluginManager:
    """Dynamic plugin loader for extending Gecko Apocalypse."""

    def __init__(self, plugins_dir: str = "plugins"):
        self.plugins_dir = Path(plugins_dir)
        self.plugins: Dict = {}
        self.plugins_dir.mkdir(exist_ok=True)

    def discover(self) -> List[str]:
        """Discover available plugins."""
        found = []
        if not self.plugins_dir.exists():
            return found
        for f in self.plugins_dir.glob("*.py"):
            if f.name.startswith("_"):
                continue
            found.append(f.stem)
        return found

    def load_all(self, session, config, db):
        """Load all discovered plugins."""
        sys.path.insert(0, str(self.plugins_dir.parent))
        for name in self.discover():
            try:
                mod = importlib.import_module(f"plugins.{name}")
                # Plugin must have a class named Plugin with a scan() method
                if hasattr(mod, "Plugin"):
                    instance = mod.Plugin(session, config, db)
                    if hasattr(instance, "scan"):
                        self.plugins[name] = instance
            except Exception as e:
                print(f"  [!] Failed to load plugin {name}: {e}")
        return self.plugins

    def get_loaded(self) -> Dict:
        return self.plugins


# Example plugin template
PLUGIN_TEMPLATE = '''"""
Gecko Apocalypse Plugin Template
Save as plugins/my_plugin.py
"""

class Plugin:
    """Custom security check plugin."""
    
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db
    
    async def scan(self, url, content, headers, response):
        """Run custom security checks. Return list of finding dicts."""
        findings = []
        # Your custom logic here
        # findings.append({
        #     'type': 'Custom Check',
        #     'severity': 'MEDIUM',
        #     'url': url,
        #     'evidence': 'Found something',
        #     'remediation': 'Fix it',
        #     'cwe': 'CWE-XXX'
        # })
        return findings
'''
