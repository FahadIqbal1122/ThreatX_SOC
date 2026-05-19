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

## Installation (Windows)

### Step 1 — Install Python

1. Go to **https://www.python.org/downloads/** and download Python 3.x
2. Run the installer
3. On the **first screen**, check **"Add python.exe to PATH"** before clicking Install Now

> If you forget to check that box, Python will install but the `python` command won't work in PowerShell.

### Step 2 — Fix the Windows Store alias (common issue)

Windows ships with a fake `python.exe` that opens the Microsoft Store instead of running Python. Disable it:

**Option A — Settings UI:**
- Go to **Settings → Apps → Advanced app settings → App execution aliases**
- Turn **OFF** both `python.exe` and `python3.exe`

**Option B — PowerShell command (paste and run):**
```powershell
$py = "C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python313"
$env:Path = "$py;$py\Scripts;" + $env:Path
[Environment]::SetEnvironmentVariable("Path","$py;$py\Scripts;" + [Environment]::GetEnvironmentVariable("Path","User"),"User")
Rename-Item "$env:LOCALAPPDATA\Microsoft\WindowsApps\python.exe" "python_disabled.exe" -ErrorAction SilentlyContinue
Rename-Item "$env:LOCALAPPDATA\Microsoft\WindowsApps\python3.exe" "python3_disabled.exe" -ErrorAction SilentlyContinue
python --version
```

If the last line prints `Python 3.x.x` you are good to go.

> If your Python version is not 3.13, replace `Python313` in the path above with your version folder name (e.g. `Python311` for 3.11).

### Step 3 — Install dependencies

Open PowerShell and run:

```powershell
pip install flask flask-cors requests python-dotenv
```

### Step 4 — Configure API keys (optional — for live Threat Intel)

Copy the example env file:

```powershell
copy .env.example .env
```

Open `.env` and fill in your keys:

```env
ABUSEIPDB_KEY=your_key_here
VIRUSTOTAL_KEY=your_key_here
```

**Getting your API keys (both free):**

- **AbuseIPDB** — Sign up at [abuseipdb.com](https://www.abuseipdb.com) → Account → API Key
  - Free tier: 1,000 IP checks/day
- **VirusTotal** — Sign up at [virustotal.com](https://www.virustotal.com) → Profile icon → API Key
  - Free tier: 4 lookups/min, 500/day

> API keys are optional. Without them, Threat Intel uses built-in mock data.

### Step 5 — Run the server

Open PowerShell **as Administrator** (right-click → Run as Administrator):

```powershell
cd "C:\Users\FAHAD IQBAL\Desktop\wld"
python server.py
```

You should see:

```
============================================================
  ThreatX SOC — Detection Server
  !! Run as Administrator for full log access !!
============================================================

[+] Detection engine started (13 rules, every 30s)
[+] Flask API running on http://0.0.0.0:5000
[+] Open dashboard.html in your browser
```

### Step 6 — Open the dashboard

Double-click `dashboard.html` in File Explorer, or drag it into Chrome/Edge.

> Do **not** go to `http://localhost:5000` — Flask only serves the API. The HTML file opens directly from disk.

---

## Installing Sysmon (for real detections)

Without Sysmon the server runs in demo mode with sample cases. To enable live detection:

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Download a config file (run in PowerShell as Administrator):
   ```powershell
   Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
   ```
3. Install Sysmon (run as Administrator):
   ```powershell
   .\sysmon64.exe -accepteula -i sysmonconfig.xml
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

| Rule | Severity | MITRE |
|---|---|---|
| PowerShell EncodedCommand | CRITICAL | T1059.001 |
| LSASS Memory Access | CRITICAL | T1003.001 |
| Process Tampering / Hollowing | CRITICAL | T1055.012 |
| Outbound C2 Port (4444, 1337…) | CRITICAL | T1071 |
| Mimikatz / Credential Dumping | CRITICAL | T1003 |
| Office App Spawned Shell | HIGH | T1566.001 |
| LOLBAS Abuse (certutil, mshta…) | HIGH | T1218 |
| Suspicious Outbound from Shell | HIGH | T1071 |
| Process Injection (RemoteThread) | HIGH | T1055 |
| WMI Persistence | HIGH | T1047 |
| Unsigned Driver Loaded | HIGH | T1014 |
| Suspicious DNS / DGA / Tor | HIGH/MEDIUM | T1071.004 |
| Script Drop in Temp/AppData | MEDIUM | T1059 |

---

## Configuration

All settings are in `.env`:

| Variable | Default | Description |
|---|---|---|
| `ABUSEIPDB_KEY` | — | AbuseIPDB API key |
| `VIRUSTOTAL_KEY` | — | VirusTotal API key |
| `FLASK_HOST` | `0.0.0.0` | Host to bind Flask |
| `FLASK_PORT` | `5000` | Port to bind Flask |
| `POLL_INTERVAL` | `30` | Seconds between Sysmon polls |

---

## Troubleshooting

**`python` opens Notepad or Microsoft Store**
→ The Windows Store alias is overriding Python. Run the Step 2 PowerShell command above.

**`python` command not recognized**
→ Python is not on PATH. Run the Step 2 PowerShell command above, then close and reopen PowerShell.

**"Requested registry access is not allowed"**
→ Use `"User"` scope instead of `"Machine"` when setting environment variables, as shown in Step 2.

**"Cannot reach detection server"**
→ `server.py` is not running. Start it and refresh the page.

**`[!] wevtutil not found`**
→ You are running on WSL or Linux. Demo mode activates automatically — no action needed. For live detection, run `server.py` from a native Windows PowerShell as Administrator.

**Threat Intel returns mock data**
→ API keys are not set. Check `.env` and restart `server.py`.

**No cases appear after starting on Windows**
→ Run `server.py` as Administrator. Sysmon must be installed. Wait up to 30 seconds for the first poll.

---

## License

MIT — free to use, modify, and distribute.
