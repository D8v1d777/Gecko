# 🚀 QUICK START GUIDE - Gecko Apocalypse v10.0

## Get Running in 5 Minutes

### Step 1: Install Dependencies (2 minutes)

```bash
cd gecko_apocalypse
pip install aiohttp asyncio-throttle pyyaml rich typer dnspython reportlab markdown pygments --break-system-packages
```

**Note**: Full feature set requires all dependencies from `requirements.txt`, but the above minimal set will get you started.

### Step 2: Configure Your Target (1 minute)

Edit `config/scope.txt`:
```
# Add your authorized domains
yourtarget.com
```

### Step 3: Run Your First Scan (2 minutes)

```bash
# Basic scan
python cli/main.py https://yourtarget.com

# Deep scan with professional PDF report
python cli/main.py https://yourtarget.com --deep --output pdf
```

---

## What You'll See

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██████╗ ███████╗ ██████╗██╗  ██╗ ██████╗                              ║
║  ██╔════╝ ██╔════╝██╔════╝██║ ██╔╝██╔═══██╗                             ║
║  ██║  ███╗█████╗  ██║     █████╔╝ ██║   ██║                             ║
║  ██║   ██║██╔══╝  ██║     ██╔═██╗ ██║   ██║                             ║
║  ╚██████╔╝███████╗╚██████╗██║  ██╗╚██████╔╝                             ║
║   ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝                              ║
║                                                                           ║
║              APOCALYPSE ENGINE v10.0 (2026 Edition)                      ║
║         Professional Vulnerability Assessment Framework                  ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

Scanner will:
1. ✅ Enumerate subdomains
2. ✅ Analyze DNS records
3. ✅ Detect technologies
4. ✅ Scan for 100+ vulnerabilities
5. ✅ Generate professional reports

---

## After Scan Completes

Check `reports/` folder for:
- `reports/gecko_report_[timestamp].pdf` - Industrial-grade PDF report
- `reports/gecko_report_[timestamp].html` - Modern interactive dashboard
- `reports/gecko_report_[timestamp].json` - Machine-readable data (SIEM/JSON)
- `reports/gecko_report_[timestamp].md` - GitHub/GitLab flavored Markdown

---

## Common Issues & Fixes

### "Module not found" error
```bash
# Install missing module
pip install [module-name] --break-system-packages
```

### "Permission denied" error
```bash
# Run with sudo (Linux/Mac)
sudo python cli/main.py https://target.com

# Or fix permissions
chmod +x gecko_apocalypse.py
```

### DNS resolution fails
```bash
# Install dnspython
pip install dnspython --break-system-packages
```

---

## Next Steps

1. **Read the README** - Full documentation in README.md
2. **Customize config.yaml** - Enable/disable modules
3. **Review Legal Notice** - Always get written authorization
4. **Generate Reports** - Share professional PDFs with clients

---

## Use Cases: WebScanTest.com

`http://www.webscantest.com/` is a deliberately vulnerable application designed for testing security scanners. Here is how Gecko Apocalypse performs against it:

### 1. Basic Reconnaissance
```bash
python cli/main.py http://www.webscantest.com/
```
**What it does:** Performs fast, non-intrusive enumeration. Discovers technologies (PHP, Apache), server details, and endpoints without sending heavy payloads.

### 2. Deep Vulnerability Scan
```bash
python cli/main.py http://www.webscantest.com/ --deep
```
**What it does:** Crawls the application and launches active exploitation payloads. Successfully identifies:
- **SQL Injection** in login forms (`/login.php`)
- **Cross-Site Scripting (XSS)** in search parameters
- **Missing Security Headers** (HSTS, CSP)

### 3. Professional Compliance Audit
```bash
python cli/main.py http://www.webscantest.com/ --deep --output pdf
```
**What it does:** Performs a full scan and generates an enterprise-grade PDF report. Maps discovered vulnerabilities to OWASP Top 10 and provides actionable remediation SLA timelines for developers.

---

## Quick Tips

💡 **Tip 1**: Start with a small scope for testing
```bash
# Test single page first
python cli/main.py https://target.com/test-page
```

💡 **Tip 2**: Monitor in real-time
```bash
# Watch logs live
tail -f logs/gecko_*.log
```

💡 **Tip 3**: Resume interrupted scans
```bash
# Checkpoints save automatically
# Checkpoints save automatically (Coming soon)
# python cli/main.py https://target.com --resume
```

---

## For College Pentesting Business

### Before Meeting with College:

1. ✅ Prepare demo scan of a test site
2. ✅ Print sample HTML report
3. ✅ Prepare pricing sheet ($2,500-$5,000)
4. ✅ Draft authorization letter template
5. ✅ Have insurance certificate ready

### During Meeting:

1. Show live scan demo
2. Walk through sample report
3. Explain severity levels (Critical→Info)
4. Discuss remediation support
5. Present pricing options

### After Agreement:

1. Get written authorization
2. Define scope in scope.txt
3. Run comprehensive scan
4. Generate PDF report
5. Schedule remediation call
6. Invoice and collect payment 💰

---

## 🎯 Real-World Use Cases (webscantest.com)

Here are some common ways to use Gecko against a live target.

### 1. Comprehensive Deep Scan
Best for finding hidden API endpoints and passive vulnerabilities.
```bash
python cli/main.py http://www.webscantest.com/ --deep
```
*   **Result**: Identified missing CSP headers and discovered 30+ endpoints.

### 2. Targeted Vulnerability Scan
Focus on specific exploit classes like SQLi and XSS.
```bash
python cli/main.py http://www.webscantest.com/ --modules xss,sqli
```
*   **Result**: Efficiently probes all discovered parameters for injection flaws.

### 3. Reconnaissance & Subdomain Discovery
Map the attack surface before launching active attacks.
```bash
python cli/main.py http://www.webscantest.com/ --modules recon,subdomain
```
*   **Result**: Identifies technologies used (e.g., PHP, Apache) and subdomains.

### 4. Custom Header Injection
Scan targets requiring specific headers (e.g., JWT, custom Auth).
```bash
python cli/main.py http://www.webscantest.com/ --header "X-Custom-Auth: gecko-secret"
```

---

## Need Help?

- 📖 Full docs: README.md
- 🐛 Issues: Check logs in `logs/` folder
- 💬 Questions: [Your support email]

---

**Remember: ALWAYS get written authorization before scanning!**

Happy (ethical) hacking! 🦎
