"""
GECKO APOCALYPSE ENGINE v10.0 - MAIN ORCHESTRATOR
Professional Vulnerability Scanner & Penetration Testing Framework
================================================================================
Full CLI with argparse, plugin system, notifications, resume capability
================================================================================
"""

import asyncio
import aiohttp
import argparse
import logging
import sys
import yaml
import signal
import random
import re
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime
from urllib.parse import urljoin, urlparse

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH = True
except ImportError:
    RICH = False

from utils.database import DatabaseManager
from utils.logger import setup_logging
from utils.scope import ScopeManager
from utils.checkpoint import CheckpointManager

from modules.reconnaissance import ReconEngine
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.graphql_fuzzer import GraphQLFuzzer
from modules.jwt_manipulator import JWTManipulator
from modules.ssti_detector import SSTIDetector
from modules.ssrf_prober import SSRFProber
from modules.xxe_attacker import XXEAttacker
from modules.cors_tester import CORSTester
from modules.websocket_tester import WebSocketTester
from modules.http_smuggler import HTTPSmuggler
from modules.oauth_exploiter import OAuthExploiter
from modules.api_fuzzer import APIFuzzer
from modules.cloud_hunter import CloudHunter
from modules.auth_bypass import AuthBypass
from modules.js_framework_hunter import JSFrameworkHunter
from modules.business_logic import BusinessLogicTester
from modules.classic_attacks import ClassicAttacks
from modules.secret_scanner import SecretScanner
from modules.tech_detector import TechDetector
from modules.header_analyzer import HeaderAnalyzer
from modules.ssl_analyzer import SSLAnalyzer
from modules.crlf_injector import CRLFInjector
from modules.waf_detector import WAFDetector

from reports.report_generator import ReportGenerator
from reports.dashboard import DashboardServer
from plugins.loader import PluginManager

console = Console() if RICH else None


def cprint(msg, style=""):
    if console:
        console.print(msg, style=style)
    else:
        print(msg)


class GeckoApocalypse:
    """Main orchestrator for the Gecko Apocalypse Engine."""

    def __init__(self, target: str, config_path: str = "config/config.yaml",
                 resume: bool = False, modules_filter: List[str] = None,
                 proxy: str = None, output_formats: List[str] = None,
                 no_dashboard: bool = False):
        self.target = target.rstrip('/')
        self.start_time = datetime.utcnow()
        self.resume = resume
        self.modules_filter = modules_filter
        self.no_dashboard = no_dashboard

        self.config = self._load_config(config_path)

        # CLI overrides
        if proxy:
            self.config['advanced']['proxy_enabled'] = True
            parts = proxy.rsplit(':', 1)
            self.config['advanced']['proxy_host'] = parts[0].replace('http://', '')
            self.config['advanced']['proxy_port'] = int(parts[1]) if len(parts) > 1 else 8080
        if output_formats:
            self.config['reporting']['formats'] = output_formats
        if no_dashboard:
            self.config['dashboard']['enabled'] = False

        self.logger = setup_logging(self.config)
        self.db = DatabaseManager(self.config['database'])
        self.scope = ScopeManager(self.config['legal'])
        self.scope.add_target(self.target)
        self.checkpoint = CheckpointManager(self.db)

        self.visited_urls: Set[str] = set()
        self.queue: asyncio.Queue = asyncio.Queue()
        self.findings: List[Dict] = []
        self.stats = {
            'urls_scanned': 0, 'vulnerabilities_found': 0,
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
        }
        self.modules: Dict = {}
        self.dashboard: Optional[DashboardServer] = None
        self._shutdown = False

    def _load_config(self, path: str) -> Dict:
        try:
            with open(path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            cprint(f"[yellow]Config not found at {path}, using defaults[/yellow]")
            return self._default_config()
        except Exception as e:
            cprint(f"[red]Error loading config: {e}[/red]")
            sys.exit(1)

    def _default_config(self):
        return {
            'engine': {'threads': 30, 'timeout': 15, 'max_depth': 5, 'delay_range': [0.1, 0.5]},
            'legal': {'require_authorization': True, 'scope_file': '', 'out_of_scope_domains': [],
                      'disclaimer': 'For authorized testing only.'},
            'modules': {k: True for k in [
                'reconnaissance','vulnerability_scanner','graphql_fuzzing','jwt_manipulation',
                'ssti_detection','ssrf_probing','xxe_attacks','cors_misconfiguration',
                'websocket_testing','http_smuggling','oauth_exploitation','api_fuzzing',
                'cloud_hunter','auth_bypass','js_framework','business_logic',
                'classic_attacks','secret_scanner','tech_detector','header_analyzer','ssl_analyzer']},
            'recon': {}, 'reporting': {'formats': ['html', 'json']},
            'notifications': {'triggers': {'critical_finding': False, 'scan_complete': False}},
            'database': {'sqlite_path': 'data/gecko_apocalypse.db'},
            'dashboard': {'enabled': False, 'host': '127.0.0.1', 'port': 8888},
            'advanced': {'proxy_enabled': False, 'plugins_enabled': True, 'plugins_directory': 'plugins/'}
        }

    def _print_banner(self):
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║   ██████╗ ███████╗ ██████╗██╗  ██╗ ██████╗                  ║
║  ██╔════╝ ██╔════╝██╔════╝██║ ██╔╝██╔═══██╗                 ║
║  ██║  ███╗█████╗  ██║     █████╔╝ ██║   ██║                 ║
║  ██║   ██║██╔══╝  ██║     ██╔═██╗ ██║   ██║                 ║
║  ╚██████╔╝███████╗╚██████╗██║  ██╗╚██████╔╝                 ║
║   ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝                  ║
║                                                               ║
║         APOCALYPSE ENGINE v10.0 · 2026 Edition               ║
║    Professional Vulnerability Assessment Framework           ║
╚═══════════════════════════════════════════════════════════════╝"""
        cprint(banner, style="bold cyan")

        if RICH and console:
            t = Table(show_header=False, box=box.ROUNDED)
            t.add_row("[cyan]Target[/]", self.target)
            t.add_row("[cyan]Threads[/]", str(self.config['engine']['threads']))
            t.add_row("[cyan]Max Depth[/]", str(self.config['engine']['max_depth']))
            t.add_row("[cyan]Modules[/]", str(sum(1 for v in self.config['modules'].values() if v)))
            t.add_row("[cyan]Reports[/]", ", ".join(self.config['reporting']['formats']))
            t.add_row("[cyan]Start[/]", self.start_time.strftime("%Y-%m-%d %H:%M:%S UTC"))
            console.print(Panel(t, title="[bold]Scan Configuration[/]", border_style="cyan"))
        else:
            print(f"Target: {self.target}")

    async def initialize_modules(self, session):
        module_map = {
            'reconnaissance': ReconEngine,
            'vulnerability_scanner': VulnerabilityScanner,
            'graphql_fuzzing': GraphQLFuzzer,
            'jwt_manipulation': JWTManipulator,
            'ssti_detection': SSTIDetector,
            'ssrf_probing': SSRFProber,
            'xxe_attacks': XXEAttacker,
            'cors_misconfiguration': CORSTester,
            'websocket_testing': WebSocketTester,
            'http_smuggling': HTTPSmuggler,
            'oauth_exploitation': OAuthExploiter,
            'api_fuzzing': APIFuzzer,
            'cloud_hunter': CloudHunter,
            'auth_bypass': AuthBypass,
            'js_framework': JSFrameworkHunter,
            'business_logic': BusinessLogicTester,
            'classic_attacks': ClassicAttacks,
            'secret_scanner': SecretScanner,
            'tech_detector': TechDetector,
            'header_analyzer': HeaderAnalyzer,
            'ssl_analyzer': SSLAnalyzer,
            'crlf_injector': CRLFInjector,
            'waf_detector': WAFDetector,
        }

        for name, cls in module_map.items():
            if not self.config['modules'].get(name, False):
                continue
            if self.modules_filter and name not in self.modules_filter:
                continue
            try:
                self.modules[name] = cls(session, self.config, self.db)
                self.logger.info(f"✓ Loaded: {name}")
            except Exception as e:
                self.logger.error(f"✗ Failed: {name}: {e}")

        # Load plugins
        if self.config['advanced'].get('plugins_enabled'):
            pm = PluginManager(self.config['advanced'].get('plugins_directory', 'plugins/'))
            plugins = pm.load_all(session, self.config, self.db)
            for pname, plugin in plugins.items():
                self.modules[f"plugin_{pname}"] = plugin
                self.logger.info(f"✓ Plugin: {pname}")

        cprint(f"[green]✓ Initialized {len(self.modules)} modules[/green]")

    async def start_dashboard(self):
        if self.config['dashboard']['enabled'] and not self.no_dashboard:
            self.dashboard = DashboardServer(self.config['dashboard'], self.db, self.stats)
            await self.dashboard.start()
            port = self.config['dashboard']['port']
            cprint(f"[green]✓ Dashboard: http://127.0.0.1:{port}[/green]")

    async def run_reconnaissance(self, session):
        cprint("\n[bold yellow]═══ PHASE 1: RECONNAISSANCE ═══[/bold yellow]")
        if 'reconnaissance' not in self.modules:
            return

        recon = self.modules['reconnaissance']
        steps = [
            ("Enumerating subdomains", recon.enumerate_subdomains),
            ("DNS analysis", recon.dns_analysis),
            ("WHOIS lookup", recon.whois_lookup),
            ("Certificate transparency", recon.certificate_transparency),
            ("Technology detection", recon.detect_technologies),
            ("Wayback Machine", recon.wayback_analysis),
        ]

        recon_data = {'target': self.target}
        for desc, func in steps:
            cprint(f"  [cyan]→ {desc}...[/cyan]")
            try:
                result = await func(self.target)
                key = desc.lower().replace(' ', '_')
                recon_data[key] = result
            except Exception as e:
                self.logger.error(f"Recon error ({desc}): {e}")

        self.db.store_reconnaissance(recon_data)
        subs = recon_data.get('enumerating_subdomains', [])
        cprint(f"[green]✓ Recon complete: {len(subs)} subdomains found[/green]")

    async def run_vulnerability_scan(self):
        cprint("\n[bold yellow]═══ PHASE 2: VULNERABILITY SCANNING ═══[/bold yellow]")

        proxy = None
        if self.config['advanced'].get('proxy_enabled'):
            h = self.config['advanced']['proxy_host']
            p = self.config['advanced']['proxy_port']
            proxy = f"http://{h}:{p}"

        conn = aiohttp.TCPConnector(ssl=False, limit=self.config['engine']['threads'])
        timeout = aiohttp.ClientTimeout(total=self.config['engine']['timeout'])

        async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
            await self.initialize_modules(session)
            await self.queue.put((self.target, 0))

            workers = [
                asyncio.create_task(self._worker(session, i))
                for i in range(min(self.config['engine']['threads'], 50))
            ]

            await self.queue.join()
            for w in workers:
                w.cancel()

    async def _worker(self, session, wid):
        while not self._shutdown:
            try:
                url, depth = await asyncio.wait_for(self.queue.get(), timeout=10)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                break

            try:
                if url in self.visited_urls or depth > self.config['engine']['max_depth']:
                    continue
                if not self.scope.is_in_scope(url):
                    continue

                self.visited_urls.add(url)
                self.stats['urls_scanned'] += 1

                delay = self.config['engine'].get('delay_range', [0.1, 0.5])
                await asyncio.sleep(random.uniform(*delay))

                try:
                    uas = self.config['engine'].get('user_agents', ['Mozilla/5.0'])
                    headers = {'User-Agent': random.choice(uas)}
                    async with session.get(url, headers=headers, allow_redirects=True) as response:
                        content = await response.text(errors='ignore')
                        resp_headers = dict(response.headers)
                        self.db.store_url(url, response.status,
                                         resp_headers.get('Content-Type', ''),
                                         len(content))

                        await self._run_modules(url, content, resp_headers, response)

                        if depth < self.config['engine']['max_depth']:
                            for new_url in self._extract_urls(url, content):
                                if new_url not in self.visited_urls:
                                    await self.queue.put((new_url, depth + 1))
                except Exception as e:
                    self.logger.debug(f"Fetch error {url}: {e}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Worker {wid}: {e}")
            finally:
                self.queue.task_done()

    async def _run_modules(self, url, content, headers, response):
        tasks = []
        for name, mod in self.modules.items():
            if name == 'reconnaissance':
                continue
            if hasattr(mod, 'scan'):
                tasks.append(self._safe_scan(name, mod, url, content, headers, response))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                for finding in result:
                    self._add_finding(finding)

    async def _safe_scan(self, name, mod, url, content, headers, response):
        try:
            return await asyncio.wait_for(
                mod.scan(url, content, headers, response),
                timeout=30
            )
        except asyncio.TimeoutError:
            self.logger.warning(f"Module {name} timed out on {url}")
            return []
        except Exception as e:
            self.logger.debug(f"Module {name} error on {url}: {e}")
            return []

    def _add_finding(self, finding):
        self.findings.append(finding)
        self.db.store_finding(finding)
        sev = finding.get('severity', 'INFO').lower()
        self.stats['vulnerabilities_found'] += 1
        self.stats[sev] = self.stats.get(sev, 0) + 1

        # Real-time output
        sev_upper = finding.get('severity', 'INFO')
        colors = {'CRITICAL': 'red bold', 'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'green', 'INFO': 'blue'}
        style = colors.get(sev_upper, '')
        cprint(f"  [{style}][{sev_upper}][/{style}] {finding.get('type','')} → {finding.get('url','')[:80]}")

        if sev_upper == 'CRITICAL':
            asyncio.create_task(self._notify(finding))

    def _extract_urls(self, base_url, content):
        urls = set()
        for pattern in [r'href=["\']([^"\']+)["\']', r'src=["\']([^"\']+)["\']',
                         r'action=["\']([^"\']+)["\']']:
            for match in re.findall(pattern, content):
                full = urljoin(base_url, match)
                if self.scope.is_in_scope(full) and full not in self.visited_urls:
                    urls.add(full)
        return list(urls)[:100]

    async def _notify(self, finding):
        """Send notifications for critical findings."""
        notif = self.config.get('notifications', {})

        # Discord
        webhook = notif.get('discord_webhook', '')
        if webhook:
            try:
                payload = {"content": f"🚨 **{finding.get('severity')}**: {finding.get('type')}\nURL: {finding.get('url')}\nEvidence: {finding.get('evidence','')[:200]}"}
                async with aiohttp.ClientSession() as s:
                    await s.post(webhook, json=payload, timeout=aiohttp.ClientTimeout(total=5))
            except: pass

        # Slack
        webhook = notif.get('slack_webhook', '')
        if webhook:
            try:
                payload = {"text": f"🚨 *{finding.get('severity')}*: {finding.get('type')}\nURL: {finding.get('url')}"}
                async with aiohttp.ClientSession() as s:
                    await s.post(webhook, json=payload, timeout=aiohttp.ClientTimeout(total=5))
            except: pass

    async def generate_reports(self):
        cprint("\n[bold yellow]═══ PHASE 3: REPORT GENERATION ═══[/bold yellow]")
        gen = ReportGenerator(self.config['reporting'], self.db, self.stats)
        for fmt in self.config['reporting']['formats']:
            try:
                path = await gen.generate(fmt, self.target, self.findings)
                cprint(f"[green]  ✓ {fmt.upper()}: {path}[/green]")
            except Exception as e:
                cprint(f"[red]  ✗ {fmt}: {e}[/red]")

    def print_summary(self):
        elapsed = (datetime.utcnow() - self.start_time).total_seconds()
        if RICH and console:
            t = Table(title="Scan Summary", box=box.DOUBLE_EDGE)
            t.add_column("Metric", style="cyan")
            t.add_column("Value", style="yellow")
            t.add_row("Duration", f"{elapsed:.1f}s")
            t.add_row("URLs Scanned", str(self.stats['urls_scanned']))
            t.add_row("Total Findings", str(self.stats['vulnerabilities_found']))
            t.add_row("", "")
            t.add_row("Critical", f"[red]{self.stats.get('critical',0)}[/red]")
            t.add_row("High", f"[orange1]{self.stats.get('high',0)}[/orange1]")
            t.add_row("Medium", f"[yellow]{self.stats.get('medium',0)}[/yellow]")
            t.add_row("Low", f"[green]{self.stats.get('low',0)}[/green]")
            t.add_row("Info", f"[blue]{self.stats.get('info',0)}[/blue]")
            console.print(t)
        else:
            print(f"\nScan Summary: {self.stats['vulnerabilities_found']} findings in {elapsed:.1f}s")

    async def run(self):
        try:
            self._print_banner()

            # Legal disclaimer
            if self.config['legal']['require_authorization']:
                self.scope.print_disclaimer()
                cprint("[yellow]⚠ Press ENTER to confirm authorized scope...[/yellow]")
                input()

            await self.start_dashboard()

            # Phase 1
            conn = aiohttp.TCPConnector(ssl=False, limit=10)
            async with aiohttp.ClientSession(connector=conn) as session:
                recon = ReconEngine(session, self.config, self.db)
                self.modules['reconnaissance'] = recon
                await self.run_reconnaissance(session)

            # Phase 2
            await self.run_vulnerability_scan()

            # Phase 3
            await self.generate_reports()
            self.print_summary()
            cprint("\n[bold green]✓ Scan complete![/bold green]")

        except KeyboardInterrupt:
            cprint("\n[yellow]⚠ Interrupted. Saving checkpoint...[/yellow]")
            self.checkpoint.save({
                'target': self.target, 'visited': list(self.visited_urls),
                'stats': self.stats, 'timestamp': datetime.utcnow().isoformat()
            })
            cprint("[green]✓ Checkpoint saved.[/green]")
        except Exception as e:
            cprint(f"[red]✗ Fatal: {e}[/red]")
            self.logger.exception("Fatal error")
            raise
        finally:
            if self.dashboard:
                await self.dashboard.stop()
            self.db.close()


def build_parser():
    p = argparse.ArgumentParser(
        prog='gecko_apocalypse',
        description='Gecko Apocalypse Engine v10.0 - Professional Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python gecko_apocalypse.py https://example.com
  python gecko_apocalypse.py https://example.com -o html json markdown
  python gecko_apocalypse.py https://example.com --modules classic_attacks api_fuzzing
  python gecko_apocalypse.py https://example.com --proxy http://127.0.0.1:8080
  python gecko_apocalypse.py https://example.com --no-dashboard --threads 20
        """
    )
    p.add_argument('target', help='Target URL to scan')
    p.add_argument('-c', '--config', default='config/config.yaml', help='Config file path')
    p.add_argument('-o', '--output', nargs='+', default=None,
                   choices=['html', 'json', 'markdown', 'pdf'], help='Output formats')
    p.add_argument('-m', '--modules', nargs='+', default=None, help='Only run specific modules')
    p.add_argument('-t', '--threads', type=int, default=None, help='Number of threads')
    p.add_argument('-d', '--depth', type=int, default=None, help='Max crawl depth')
    p.add_argument('--proxy', default=None, help='Proxy URL (e.g. http://127.0.0.1:8080)')
    p.add_argument('--resume', action='store_true', help='Resume previous scan')
    p.add_argument('--no-dashboard', action='store_true', help='Disable web dashboard')
    p.add_argument('--no-recon', action='store_true', help='Skip reconnaissance phase')
    p.add_argument('--skip-auth-check', action='store_true', help='Skip authorization prompt')
    p.add_argument('--list-modules', action='store_true', help='List available modules')
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.list_modules:
        mods = [
            'reconnaissance', 'vulnerability_scanner', 'graphql_fuzzing', 'jwt_manipulation',
            'ssti_detection', 'ssrf_probing', 'xxe_attacks', 'cors_misconfiguration',
            'websocket_testing', 'http_smuggling', 'oauth_exploitation', 'api_fuzzing',
            'cloud_hunter', 'auth_bypass', 'js_framework', 'business_logic',
            'classic_attacks', 'secret_scanner', 'tech_detector', 'header_analyzer', 'ssl_analyzer',
            'crlf_injector', 'waf_detector'
        ]
        print("Available modules:")
        for m in mods:
            print(f"  • {m}")
        sys.exit(0)

    engine = GeckoApocalypse(
        target=args.target,
        config_path=args.config,
        resume=args.resume,
        modules_filter=args.modules,
        proxy=args.proxy,
        output_formats=args.output,
        no_dashboard=args.no_dashboard,
    )

    # CLI overrides
    if args.threads:
        engine.config['engine']['threads'] = args.threads
    if args.depth:
        engine.config['engine']['max_depth'] = args.depth
    if args.skip_auth_check:
        engine.config['legal']['require_authorization'] = False
    if args.no_recon:
        engine.config['modules']['reconnaissance'] = False

    asyncio.run(engine.run())


if __name__ == "__main__":
    main()
