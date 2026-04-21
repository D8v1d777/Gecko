# 🚀 QUICK START GUIDE - Gecko Apocalypse v10.0

## Get Running in 5 Minutes

### Step 1: Install Dependencies (2 minutes)

```bash
cd gecko_apocalypse
pip install aiohttp asyncio-throttle pyyaml rich typer dnspython --break-system-packages
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
python gecko_apocalypse.py https://yourtarget.com
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
- `gecko_report_[timestamp].html` - Professional HTML report
- `gecko_report_[timestamp].json` - Machine-readable data
- `gecko_report_[timestamp].md` - Markdown format

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
sudo python gecko_apocalypse.py https://target.com

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

## Quick Tips

💡 **Tip 1**: Start with a small scope for testing
```bash
# Test single page first
python gecko_apocalypse.py https://target.com/test-page
```

💡 **Tip 2**: Monitor in real-time
```bash
# Watch logs live
tail -f logs/gecko_*.log
```

💡 **Tip 3**: Resume interrupted scans
```bash
# Checkpoints save automatically
python gecko_apocalypse.py https://target.com --resume
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

## Need Help?

- 📖 Full docs: README.md
- 🐛 Issues: Check logs in `logs/` folder
- 💬 Questions: [Your support email]

---

**Remember: ALWAYS get written authorization before scanning!**

Happy (ethical) hacking! 🦎
