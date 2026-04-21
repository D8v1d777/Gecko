"""GECKO APOCALYPSE - Web Dashboard (FastAPI + WebSocket real-time updates)"""
import asyncio, json
from typing import Dict, Optional
from pathlib import Path


class DashboardServer:
    """Lightweight web dashboard for real-time scan monitoring."""

    def __init__(self, config, db, stats):
        self.config = config
        self.db = db
        self.stats = stats
        self.host = config.get('host', '127.0.0.1')
        self.port = config.get('port', 8888)
        self.server = None
        self.app = None

    async def start(self):
        """Start the dashboard server."""
        try:
            from aiohttp import web
            self.app = web.Application()
            self.app.router.add_get('/', self._index)
            self.app.router.add_get('/api/stats', self._api_stats)
            self.app.router.add_get('/api/findings', self._api_findings)

            runner = web.AppRunner(self.app)
            await runner.setup()
            self.server = web.TCPSite(runner, self.host, self.port)
            await self.server.start()
        except ImportError:
            pass  # aiohttp not available for dashboard
        except Exception:
            pass

    async def _index(self, request):
        from aiohttp import web
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Gecko Apocalypse Dashboard</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;padding:20px}}
h1{{color:#22d3ee;text-align:center;margin-bottom:20px}}
.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:15px;margin:20px 0}}
.card{{background:#1e293b;border-radius:12px;padding:20px;text-align:center;border:1px solid #334155}}
.card .num{{font-size:48px;font-weight:bold}} .card .label{{color:#94a3b8;font-size:14px}}
.critical .num{{color:#dc2626}} .high .num{{color:#ea580c}} .medium .num{{color:#d97706}}
.low .num{{color:#65a30d}} .info .num{{color:#2563eb}}
#findings{{background:#1e293b;border-radius:12px;padding:20px;margin-top:20px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#334155;padding:10px;text-align:left}} td{{padding:8px;border-bottom:1px solid #334155}}
</style>
<script>
async function refresh() {{
    const s = await (await fetch('/api/stats')).json();
    document.getElementById('critical').textContent = s.critical || 0;
    document.getElementById('high').textContent = s.high || 0;
    document.getElementById('medium').textContent = s.medium || 0;
    document.getElementById('low').textContent = s.low || 0;
    document.getElementById('info').textContent = s.info || 0;
    document.getElementById('urls').textContent = s.urls_scanned || 0;
    const f = await (await fetch('/api/findings')).json();
    let rows = '';
    f.forEach((v,i) => {{
        const colors = {{'CRITICAL':'#dc2626','HIGH':'#ea580c','MEDIUM':'#d97706','LOW':'#65a30d','INFO':'#2563eb'}};
        rows += `<tr><td>${{i+1}}</td><td style="color:${{colors[v.severity]||'#666'}};font-weight:bold">${{v.severity}}</td><td>${{v.type}}</td><td>${{v.url}}</td><td>${{v.evidence?.substring(0,100)||''}}</td></tr>`;
    }});
    document.getElementById('tbody').innerHTML = rows;
}}
setInterval(refresh, 3000); window.onload = refresh;
</script></head><body>
<h1>🦎 Gecko Apocalypse - Live Dashboard</h1>
<div class="grid">
<div class="card critical"><div class="num" id="critical">0</div><div class="label">CRITICAL</div></div>
<div class="card high"><div class="num" id="high">0</div><div class="label">HIGH</div></div>
<div class="card medium"><div class="num" id="medium">0</div><div class="label">MEDIUM</div></div>
<div class="card low"><div class="num" id="low">0</div><div class="label">LOW</div></div>
<div class="card info"><div class="num" id="info">0</div><div class="label">INFO</div></div>
</div>
<p style="text-align:center;color:#94a3b8">URLs Scanned: <span id="urls" style="color:#22d3ee;font-weight:bold">0</span></p>
<div id="findings"><h2 style="color:#38bdf8;margin-bottom:15px">Live Findings</h2>
<table><tr><th>#</th><th>Severity</th><th>Type</th><th>URL</th><th>Evidence</th></tr>
<tbody id="tbody"></tbody></table></div></body></html>"""
        return web.Response(text=html, content_type='text/html')

    async def _api_stats(self, request):
        from aiohttp import web
        return web.json_response(self.stats)

    async def _api_findings(self, request):
        from aiohttp import web
        findings = self.db.get_all_findings()
        return web.json_response(findings[:100])

    async def stop(self):
        """Stop the dashboard server."""
        if self.server:
            await self.server.stop()
