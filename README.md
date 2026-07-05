# 🛡️ SentinelScan

**Signature-Based Malware Detection & SOC Alerting Pipeline**

A Python simulation of how antivirus engines and SOC (Security Operations Center) detection pipelines work — built to understand the fundamentals behind real-world tools like SIEM, EDR, and threat-intel platforms.

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Status](https://img.shields.io/badge/Status-Educational%20Project-yellow?style=flat)
![Platform](https://img.shields.io/badge/Platform-Cross--Platform-lightgrey?style=flat)

---

## 📋 Overview

SentinelScan scans a target folder, fingerprints every file with SHA-256, and checks each hash against a local database of known-malicious signatures. Anything not recognized locally can optionally be cross-checked against **VirusTotal**, which aggregates verdicts from 70+ real antivirus engines. Detections are logged, quarantined, turned into JSON alert reports, pushed to **Email/Slack**, and summarized in a live **HTML dashboard**.

> ⚠️ **Educational use only.** This is a learning project, not production security software. It will not detect real-world malware unless you add real signatures, and it should never replace a real endpoint protection solution.

## 🧩 Pipeline

```
   ┌─────────┐    ┌─────────┐    ┌──────────┐    ┌───────┐    ┌─────────┐    ┌───────────┐
   │  Scan   │ -> │  Hash   │ -> │  Detect  │ -> │  Log  │ -> │  Alert  │ -> │ Visualize │
   │ folder  │    │ SHA-256 │    │ Local DB │    │ audit │    │ Email/  │    │ dashboard │
   │         │    │         │    │ +VirusT. │    │ trail │    │ Slack   │    │  .html    │
   └─────────┘    └─────────┘    └──────────┘    └───────┘    └─────────┘    └───────────┘
```

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Recursive scanning** | Walks any target folder and hashes every file with SHA-256 |
| 🎯 **Signature matching** | Compares against a local JSON database of known-malicious hashes |
| 🌐 **VirusTotal enrichment** | Optionally checks unmatched hashes against 70+ real AV engines |
| 🗂️ **Quarantine** | Automatically isolates flagged files, renamed and timestamped |
| 📝 **Audit logging** | Every scan action is logged with timestamps to `scan_log.txt` |
| 📄 **JSON alert reports** | Each detection run generates a structured incident-style report |
| 📧 **Email & Slack alerts** | Notifies you the moment something is flagged |
| 📊 **HTML dashboard** | Terminal-styled dashboard summarizing all detections across scans |

## 🖥️ Screenshots

> _Add your own screenshots here before publishing — e.g. terminal scan output and the dashboard view._

```
[ <img width="1918" height="1198" alt="Screenshot 2026-07-05 105457" src="https://github.com/user-attachments/assets/92f82aea-6582-436b-9c85-a8b74c832c50" />
Sc<img width="1918" height="1198" alt="Screenshot 2026-07-05 105457" src="https://github.com/user-attachments/assets/37d6665b-c03b-4f08-a495-302431316e24" />
reenshot: terminal output of a scan with a detection ]
<img width="1918" height="1198" alt="output-image" src="https://github.com/user-attachments/assets/80d12f2d-d18c-4bd7-985e-358890242ecc" />

[ Screenshot:<img width="1918" height="1198" alt="output-image" src="https://github.com/user-attachments/assets/737272d3-7ba8-40d2-afc0-80d0b2f837a3" />
 dashboard.html showing detection history ]
```

## 📁 Project Structure

```
sentinelscan/
├── main.py                 # CLI entry point
├── scanner.py               # folder walking + SHA-256 hashing
├── quarantine.py             # moves flagged files to quarantine
├── logger.py                 # timestamped audit trail
├── vt_checker.py              # VirusTotal API integration
├── notifier.py                 # Email + Slack alerting
├── dashboard_generator.py       # builds dashboard.html from reports
├── signatures.json            # local known-malicious hash database
├── config.json.example        # copy to config.json, add your keys
├── test_files/                 # sample files for safe testing
├── quarantine/                  # flagged files land here
├── reports/                      # JSON alert reports
└── dashboard.html                 # generated detection dashboard
```

## 🚀 Getting Started

### Prerequisites
- Python 3.9+
- `pip install requests`

### Basic usage

```bash
# Clone and enter the project
git clone https://github.com/<your-username>/sentinelscan.git
cd sentinelscan

# Scan a folder
python main.py test_files

# Scan + quarantine detections
python main.py test_files --quarantine

# Scan + enrich with VirusTotal + build dashboard
python main.py test_files --quarantine --vt-check --dashboard
```

### Optional integrations

Copy `config.json.example` → `config.json` and fill in what you want to use:

```json
{
  "virustotal_api_key": "YOUR_VT_KEY",
  "email": {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "sender_email": "you@gmail.com",
    "sender_password": "your_app_password",
    "recipient_email": "you@gmail.com"
  },
  "slack_webhook_url": "https://hooks.slack.com/services/..."
}
```

Every integration fails gracefully if left unconfigured — the core scanner always works standalone.

Full setup instructions (VirusTotal key, Gmail App Passwords, Slack webhooks) are in [`README.md`](./README.md) inside the project folder.

## 🎓 What I Learned

- How signature-based antivirus detection actually works, and where it falls short (polymorphic malware, zero-days)
- How threat-intelligence enrichment fits into a detection pipeline
- Why audit logging and alerting matter as much as detection itself in a SOC context
- The building blocks behind real tools like SIEM dashboards and EDR alerting

## 🗺️ Roadmap / Ideas for Extension

- [ ] Multi-hash support (MD5 + SHA-1 + SHA-256)
- [ ] Real-time folder monitoring instead of on-demand scans
- [ ] MITRE ATT&CK technique tagging for detections
- [ ] Basic heuristic checks (extension mismatch, suspicious size)

## 📜 License

MIT — feel free to fork, learn from, and build on this.

---

*Built as a hands-on cybersecurity learning project — not a substitute for real endpoint protection.*
