# ThreatX SOC Dashboard

A real-time Security Operations Center (SOC) dashboard for Windows threat detection, alert triage, and threat intelligence enrichment.

![ThreatX Dashboard](https://img.shields.io/badge/ThreatX-SOC%20Dashboard-00ffb4?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-2.x-black?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows-0078d4?style=flat-square)

---

## What This Does

ThreatX is a SOC dashboard that runs on your Windows PC and shows you real security threats happening on your machine in real time. It reads Windows event logs (via Sysmon), applies 13 detection rules mapped to MITRE ATT&CK, and presents everything in a browser-based dashboard with live case management and threat intelligence lookups.

---

## Requirements

- Windows 10 or Windows 11
- An internet connection (for setup and threat intel)
- A browser (Chrome or Edge recommended)

---

## Full Setup Guide

Follow every step in order. Do not skip any step.

---

### Step 1 — Open PowerShell as Administrator

This is required for every step below.

1. Click the **Start** menu (Windows button)
2. Type **PowerShell**
3. Right-click **Windows PowerShell** in the results
4. Click **"Run as administrator"**
5. Click **Yes** when Windows asks for permission

You should see a blue window with `PS C:\WINDOWS\system32>` at the top.

> Every command in this guide must be run in this Administrator PowerShell window.

---

### Step 2 — Install Python

1. Open your browser and go to **https://www.python.org/downloads/**
2. Click the big **"Download Python 3.x.x"** button
3. Run the downloaded installer
4. **IMPORTANT:** On the first screen, check the box that says **"Add python.exe to PATH"** before clicking anything else
5. Click **"Install Now"**
6. Wait for it to finish, then close the installer

---

### Step 3 — Fix the Python PATH (run this every time after a fresh install or reboot issue)

Windows sometimes has a fake `python` command that opens the Microsoft Store instead of running Python. This command fixes it permanently. Paste the entire block into your Administrator PowerShell and press Enter:

```powershell
$py = "C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python313"
[Environment]::SetEnvironmentVariable("Path", "$py;$py\Scripts;" + [Environment]::GetEnvironmentVariable("Path","Machine"), "Machine")
$env:Path = "$py;$py\Scripts;" + $env:Path
Rename-Item "$env:LOCALAPPDATA\Microsoft\WindowsApps\python.exe" "python_disabled.exe" -ErrorAction SilentlyContinue
Rename-Item "$env:LOCALAPPDATA\Microsoft\WindowsApps\python3.exe" "python3_disabled.exe" -ErrorAction SilentlyContinue
python --version
```

The last line should print something like `Python 3.13.7`. If it does, Python is working.

> If your Python version is not 3.13, replace `Python313` in the first line with your version folder. For example, Python 3.11 would be `Python311`. You can find the correct folder name by opening File Explorer and going to `C:\Users\YourName\AppData\Local\Programs\Python\`.

---

### Step 4 — Download the project

If you have Git installed:

```powershell
git clone https://github.com/your-username/threatx-soc.git
cd threatx-soc
```

Or download the ZIP from GitHub, extract it anywhere, then navigate to that folder in PowerShell:

```powershell
cd "C:\Users\FAHAD IQBAL\Desktop\wld"
```

Replace the path with wherever you extracted the project.

---

### Step 5 — Install Python packages

In your Administrator PowerShell, run:

```powershell
pip install flask flask-cors requests python-dotenv
```

Wait for it to finish. You will see a lot of text — that is normal. It is done when you see the prompt return.

---

### Step 6 — Set up your API keys (optional but recommended)

The API keys enable real threat intelligence lookups for IPs and domains. Without them the dashboard still works fully but uses built-in mock data for threat intel.

**Get your free AbuseIPDB key:**
1. Go to **https://www.abuseipdb.com** and create a free account
2. Go to Account → API → copy your key

**Get your free VirusTotal key:**
1. Go to **https://www.virustotal.com** and create a free account
2. Click your profile icon (top right) → API Key → copy your key

**Add the keys to the project:**

In your project folder, find the file called `.env.example`. Make a copy of it and name the copy `.env`:

```powershell
copy .env.example .env
```

Open the `.env` file in Notepad and replace the placeholder values:

```
ABUSEIPDB_KEY=paste_your_abuseipdb_key_here
VIRUSTOTAL_KEY=paste_your_virustotal_key_here
```

Save and close the file.

---

### Step 7 — Install Sysmon (for real threat detection)

Sysmon is a free Microsoft tool that logs detailed security events on your PC. Without it the dashboard runs in demo mode with sample cases. With it you get real detections.

Run all of these commands one by one in your Administrator PowerShell:

**Download Sysmon:**
```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
```

**Extract it:**
```powershell
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon" -Force
```

**Download a detection config:**
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$env:TEMP\sysmonconfig.xml"
```

**Install Sysmon:**
```powershell
& "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i "$env:TEMP\sysmonconfig.xml"
```

You should see `Sysmon64 started.` at the end. That means it worked.

**Verify Sysmon is running:**
```powershell
Get-Service Sysmon64
```

It should show `Running`.

**Verify event log is working:**
```powershell
wevtutil qe "Microsoft-Windows-Sysmon/Operational" /c:3
```

You should see XML output. If you see XML, Sysmon is logging events correctly.

> If `wevtutil` says "The RPC server is unavailable", restart your PC and try again. This happens when the Windows Event Log service gets stuck.

---

### Step 8 — Run the server

In your Administrator PowerShell, navigate to the project folder and start the server:

```powershell
cd "C:\Users\FAHAD IQBAL\Desktop\wld"
python server.py
```

Replace the path with your actual project folder location.

You should see this output:

```
============================================================
  ThreatX SOC — Detection Server
  !! Run as Administrator for full log access !!
============================================================

[+] AbuseIPDB key  : xxxxxx********** (loaded)
[+] VirusTotal key : xxxxxx********** (loaded)

[detector] Engine started — 13 rules loaded, polling every 30s
[+] Flask API running on http://0.0.0.0:5000
[+] Open dashboard.html in your browser

 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
[detector] +4 new case(s)  (total open: 4)
```

The line `[detector] +X new case(s)` means real Sysmon events were detected. Keep this window open — closing it stops the server.

---

### Step 9 — Open the dashboard

Open **File Explorer**, navigate to the project folder, and double-click **dashboard.html**.

It will open in your default browser. You should see the live dashboard with real data.

> Do **not** go to `http://localhost:5000` in your browser — that only serves the API. Always open the `dashboard.html` file directly.

---

## Every Time You Want to Use It

1. Open **PowerShell as Administrator**
2. Run:
```powershell
cd "C:\Users\FAHAD IQBAL\Desktop\wld"
python server.py
```
3. Open `dashboard.html` in your browser

---

## Troubleshooting

**`python` opens Notepad or Microsoft Store**
Run the Step 3 command block again. Make sure you are in an Administrator PowerShell.

**`python` not recognized after a reboot**
Run the Step 3 command block again. The Machine-level PATH set in Step 3 should survive reboots — if it does not, you may need to set it again.

**`pip install` fails with "not recognized"**
Python is not on PATH. Run the Step 3 command block first.

**Server starts but shows "Injected 8 demo cases (Sysmon unavailable)"**
Sysmon is not installed or the event log is not accessible. Complete Step 7, then restart the PC and try again.

**`wevtutil` returns "The RPC server is unavailable"**
The Windows Event Log service crashed. Restart your PC — do not try to restart the service manually as that can make it worse.

**"Cannot reach detection server" banner in the dashboard**
`server.py` is not running. Start it with `python server.py` in an Administrator PowerShell.

**Threat Intel returns mock data instead of real results**
API keys are not set or are incorrect. Check your `.env` file. Make sure there are no spaces around the `=` sign.

**No new cases appearing after setup**
The detection engine polls every 30 seconds. Wait up to 30 seconds. Cases only appear when your activity on the PC triggers one of the 13 detection rules — normal browsing will trigger DNS and network events within a minute or two.

**"Requested registry access is not allowed" when setting PATH**
You are not running PowerShell as Administrator. Close it and reopen using right-click → Run as administrator.

---

## Project Structure

```
threatx-soc/
├── server.py          # Flask API server + Sysmon reader
├── detector.py        # Detection engine — 13 MITRE ATT&CK rules
├── dashboard.html     # Single-file frontend dashboard
├── .env               # Your API keys (never share or commit this file)
├── .env.example       # Template — safe to share
├── .gitignore
└── README.md
```

---

## Detection Rules

The engine checks every Sysmon event against these 13 rules:

| Rule | Severity | MITRE Technique |
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

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/dashboard` | Live metrics, donut chart data, event timeline |
| `GET` | `/api/alerts` | All open cases newest first |
| `GET` | `/api/alerts/<id>` | Single case detail |
| `POST` | `/api/alerts/<id>/close` | Close a case |
| `POST` | `/api/alerts/clear` | Delete all cases |
| `GET` | `/api/intel?query=<ip>&type=ip` | Threat intel lookup |
| `GET` | `/api/status` | Server health and rule count |

---

## Configuration

All settings live in `.env`:

| Variable | Default | Description |
|---|---|---|
| `ABUSEIPDB_KEY` | — | AbuseIPDB API key |
| `VIRUSTOTAL_KEY` | — | VirusTotal API key |
| `FLASK_HOST` | `0.0.0.0` | Host to bind Flask |
| `FLASK_PORT` | `5000` | Port to bind Flask |
| `POLL_INTERVAL` | `30` | Seconds between Sysmon polls |

---

## License

MIT — free to use, modify, and distribute.
