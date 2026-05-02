# ThreatX SOC Dashboard

A real-time Security Operations Center (SOC) dashboard for Windows threat detection, alert triage, and threat intelligence enrichment.

![ThreatX Dashboard](https://img.shields.io/badge/ThreatX-SOC%20Dashboard-00ffb4?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-2.x-black?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%2F%20WSL-0078d4?style=flat-square)

---

## Features

- **Live Investigation Dashboard** — real-time Sysmon event feed, severity donut chart, animated stat counters
- **Threat Intelligence** — IP and domain analysis via AbuseIPDB + VirusTotal with risk scoring (0–100) and AI-generated narratives
- **Open Cases** — auto-generated security incidents from 13 detection rules mapped to MITRE ATT\&CK, with case management
- **Detection Engine** — background polling of Windows Sysmon logs with rules for PowerShell abuse, LSASS access, process injection, C2 ports, WMI persistence, and more
- **Demo Mode** — works without Sysmon by injecting realistic sample cases automatically

---

## Requirements

| Requirement | Notes |
|---|---|
| Python 3.8+ | [python.org](https://www.python.org/downloads/) |
| Windows (recommended) | For live Sysmon event reading |
| Sysmon (optional) | Required for real event detection |
| AbuseIPDB API key | Free tier sufficient |
| VirusTotal API key | Free tier sufficient |

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/your-username/threatx-soc.git
cd threatx-soc
```

### 2. Install Python dependencies

```bash
pip install flask flask-cors requests python-dotenv
```

### 3. Configure environment variables

```bash
cp .env.example .env
```

Open `.env` and fill in your API keys:

```env
ABUSEIPDB_KEY=your_key_here
VIRUSTOTAL_KEY=your_key_here
```

**Getting your API keys (both free):**

- **AbuseIPDB** — Sign up at [abuseipdb.com](https://www.abuseipdb.com) → Account → API Key
  - Free tier: 1,000 IP checks/day
- **VirusTotal** — Sign up at [virustotal.com](https://www.virustotal.com) → Profile icon → API Key
  - Free tier: 4 lookups/min, 500/day

### 4. Start the server

**On Windows — run as Administrator** (required for Sysmon log access):

```
python server.py
```

**On WSL or macOS (demo mode):**

```bash
python3 server.py
```

> Without administrator privileges or Sysmon, the server runs in demo mode and injects 8 realistic sample cases automatically so the dashboard is fully functional.

You should see:

```
============================================================
  ThreatX SOC — Detection Server
  !! Run as Administrator for full log access !!
============================================================

[+] AbuseIPDB key  : 3c6a9c********** (loaded)
[+] VirusTotal key : aed78d********** (loaded)

[+] Detection engine started (13 rules, every 30s)
[+] Flask API running on http://0.0.0.0:5000
[+] Open dashboard.html in your browser
```

### 5. Open the dashboard

Open `dashboard.html` directly in your browser:

- **Windows:** Double-click `dashboard.html` in File Explorer, or drag it into Chrome/Edge/Firefox
- **Or:** In your browser address bar: `file:///C:/path/to/threatx-soc/dashboard.html`

> Do **not** navigate to `http://localhost:5000` — Flask only serves the API. The HTML file is opened directly.

---

## Installing Sysmon (for real detections on Windows)

Sysmon provides the detailed Windows event logging that powers the detection engine.

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Download a recommended config (e.g. [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)):
   ```
   Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
   ```
3. Install Sysmon with the config (run as Administrator):
   ```
   sysmon64.exe -accepteula -i sysmonconfig.xml
   ```
4. Restart `server.py` — the detection engine will now read live events every 30 seconds.

---

## Project Structure

```
threatx-soc/
├── server.py          # Flask API server + Sysmon reader
├── detector.py        # Detection engine — 13 MITRE ATT&CK rules
├── dashboard.html     # Single-file frontend dashboard
├── .env               # Your API keys (never commit this)
├── .env.example       # Template — commit this instead
├── .gitignore
└── README.md
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/dashboard` | Aggregated metrics, donut data, event timeline |
| `GET` | `/api/alerts` | All open cases (newest first) |
| `GET` | `/api/alerts/<id>` | Single case detail |
| `POST` | `/api/alerts/<id>/close` | Mark a case as closed |
| `POST` | `/api/alerts/clear` | Delete all cases |
| `GET` | `/api/intel?query=<ip>&type=ip` | Threat intelligence lookup |
| `GET` | `/api/status` | Engine health, rule count, case breakdown |

---

## Detection Rules

The engine runs 13 rules on every Sysmon poll, each mapped to a MITRE ATT&CK technique:

| Rule | Severity | MITRE |
|---|---|---|
| PowerShell EncodedCommand | CRITICAL | T1059.001 |
| LSASS Memory Access | CRITICAL | T1003.001 |
| Process Tampering / Hollowing | CRITICAL | T1055.012 |
| Outbound C2 Port (4444, 1337…) | CRITICAL | T1071 |
| Office App Spawned Shell | HIGH | T1566.001 |
| Mimikatz / Credential Dumping | CRITICAL | T1003 |
| LOLBAS Abuse (certutil, mshta…) | HIGH | T1218 |
| Suspicious Outbound from Shell | HIGH | T1071 |
| Process Injection (RemoteThread) | HIGH | T1055 |
| WMI Persistence | HIGH | T1047 |
| Unsigned Driver Loaded | HIGH | T1014 |
| Suspicious DNS / DGA / Tor | HIGH/MEDIUM | T1071.004 |
| Script Drop in Temp/AppData | MEDIUM | T1059 |

---

## Configuration

All settings are controlled via `.env`:

| Variable | Default | Description |
|---|---|---|
| `ABUSEIPDB_KEY` | — | AbuseIPDB API key (required for live threat intel) |
| `VIRUSTOTAL_KEY` | — | VirusTotal API key (required for live threat intel) |
| `FLASK_HOST` | `0.0.0.0` | Host to bind the Flask server |
| `FLASK_PORT` | `5000` | Port to bind the Flask server |
| `POLL_INTERVAL` | `30` | Seconds between Sysmon polls |

---

## Troubleshooting

**"Cannot reach detection server"**
→ `server.py` is not running. Start it and refresh the page.

**"Sysmon read error: creationflags is only supported on Windows"**
→ You are running on WSL/Linux. Demo mode activates automatically — no action needed.

**Threat Intel returns mock data instead of real results**
→ API keys are not set or invalid. Check `server.py` startup output for key status.

**VirusTotal returns 401**
→ Key is wrong. Get it from [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey).

**No cases appear after starting on Windows**
→ Run `server.py` as Administrator. Sysmon must be installed. Wait up to 30 seconds for the first poll.

---

## License

MIT — free to use, modify, and distribute.
