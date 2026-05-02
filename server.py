"""
ThreatX SOC — Flask API Server  (server.py)
============================================
Runs the detection engine in a background thread and exposes
a REST API that the dashboard HTML polls for live case updates.

Usage:
  pip install flask flask-cors
  python server.py          (run as Administrator!)

Endpoints:
  GET  /api/alerts          → list of all open cases (newest first)
  GET  /api/alerts/<id>     → single case detail
  POST /api/alerts/<id>/close  → mark case as closed
  POST /api/alerts/clear    → wipe all cases (dev/testing)
  GET  /api/status          → engine health check

The HTML dashboard polls GET /api/alerts every 5 seconds.
"""

import threading
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
import sys
import os
from pathlib import Path

# Load .env before anything else
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass  # python-dotenv not installed — rely on real env vars

import detector
from flask import Flask, jsonify, request
from flask_cors import CORS

_WIN = sys.platform == 'win32'
_SUBPROCESS_FLAGS = {'creationflags': 0x08000000} if _WIN else {}

# ─────────────────────────────────────────────
app = Flask(__name__)
CORS(app)   # allow the HTML file (file://) to call localhost:5000

# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """Return all open cases newest-first. Optionally filter by severity."""
    sev = request.args.get("severity", "").upper()
    cases = detector.get_active_cases()
    if sev:
        cases = [c for c in cases if c["severity"] == sev]
    return jsonify(cases)


@app.route("/api/alerts/<case_id>", methods=["GET"])
def get_alert(case_id):
    cases = detector.get_active_cases()
    match = next((c for c in cases if c["id"] == case_id), None)
    if match:
        return jsonify(match)
    return jsonify({"error": "Case not found"}), 404


@app.route("/api/alerts/<case_id>/close", methods=["POST"])
def close_alert(case_id):
    with detector.cases_lock:
        for c in detector.cases:
            if c["id"] == case_id:
                c["status"] = "CLOSED"
                return jsonify({"ok": True, "id": case_id})
    return jsonify({"error": "Case not found"}), 404


@app.route("/api/alerts/clear", methods=["POST"])
def clear_alerts():
    detector.clear_cases()
    return jsonify({"ok": True})


@app.route("/api/status", methods=["GET"])
def status():
    cases = detector.get_active_cases()
    by_severity = {}
    for c in cases:
        s = c["severity"]
        by_severity[s] = by_severity.get(s, 0) + 1
    return jsonify({
        "status":     "running",
        "total_cases": len(cases),
        "by_severity": by_severity,
        "rules_count": len(detector.ALL_RULES),
        "poll_interval": detector.POLL_INTERVAL,
    })


# ─────────────────────────────────────────────
#  SYSMON READER  — reads real events via wevtutil (no extra deps)
# ─────────────────────────────────────────────

SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"
NS         = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# EventID → base severity
EID_SEVERITY = {
    1:"MEDIUM", 2:"LOW",    3:"MEDIUM", 4:"LOW",    5:"LOW",
    6:"MEDIUM", 7:"LOW",    8:"CRITICAL",9:"LOW",   10:"HIGH",
    11:"LOW",   12:"LOW",   13:"LOW",   14:"LOW",   15:"LOW",
    17:"MEDIUM",18:"MEDIUM",19:"HIGH",  20:"HIGH",  21:"HIGH",
    22:"MEDIUM",23:"LOW",   25:"CRITICAL",26:"LOW",
}

EID_LABEL = {
    1:"Process Create",      2:"File Time Changed",    3:"Network Connection",
    4:"Service State",       5:"Process Terminated",   6:"Driver Loaded",
    7:"Image Loaded",        8:"CreateRemoteThread",   9:"RawAccessRead",
    10:"ProcessAccess",      11:"File Created",         12:"Registry Create/Delete",
    13:"Registry Set Value", 14:"Registry Rename",      15:"File Stream Hash",
    17:"Pipe Created",       18:"Pipe Connected",       19:"WMI Filter",
    20:"WMI Consumer",       21:"WMI Binding",          22:"DNS Query",
    23:"File Deleted",       25:"Process Tampering",    26:"File Delete Detected",
}

def _xml_data(event, field):
    """Return the text of a <Data Name='field'> element, or empty string."""
    for d in event.findall(".//e:Data", NS):
        if d.get("Name") == field:
            return (d.text or "").strip()
    return ""

def _classify(eid, event):
    sev = EID_SEVERITY.get(eid, "LOW")
    try:
        if eid == 1:
            cmdline = _xml_data(event, "CommandLine").lower()
            image   = _xml_data(event, "Image").lower()
            parent  = _xml_data(event, "ParentImage").lower()
            if any(x in cmdline for x in ["-enc", "-encodedcommand", "mimikatz",
                                           "invoke-", "downloadstring", "iex "]):
                return "CRITICAL"
            if any(p in parent for p in ["winword.exe","excel.exe","powerpnt.exe","outlook.exe"]):
                if any(c in image for c in ["cmd.exe","powershell.exe","wscript.exe","cscript.exe"]):
                    return "HIGH"
        elif eid == 10:
            if "lsass.exe" in _xml_data(event, "TargetImage").lower():
                return "CRITICAL"
        elif eid == 3:
            if _xml_data(event, "DestinationPort") in ["4444","1337","31337","8443"]:
                return "CRITICAL"
    except Exception:
        pass
    return sev

def _make_title(eid, event):
    try:
        if eid == 1:
            img    = _xml_data(event, "Image").split("\\")[-1]
            parent = _xml_data(event, "ParentImage").split("\\")[-1]
            cmd    = _xml_data(event, "CommandLine").lower()
            if "-enc" in cmd or "-encodedcommand" in cmd:
                return "PowerShell -EncodedCommand detected"
            return f"Process created: {img} (parent: {parent})"
        if eid == 3:
            img  = _xml_data(event, "Image").split("\\")[-1]
            dst  = _xml_data(event, "DestinationIp")
            port = _xml_data(event, "DestinationPort")
            return f"Network: {img} → {dst}:{port}"
        if eid == 8:
            src = _xml_data(event, "SourceImage").split("\\")[-1]
            tgt = _xml_data(event, "TargetImage").split("\\")[-1]
            return f"CreateRemoteThread: {src} → {tgt}"
        if eid == 10:
            src = _xml_data(event, "SourceImage").split("\\")[-1]
            tgt = _xml_data(event, "TargetImage").split("\\")[-1]
            return f"ProcessAccess: {src} → {tgt}"
        if eid == 11:
            fname = _xml_data(event, "TargetFilename").split("\\")[-1]
            img   = _xml_data(event, "Image").split("\\")[-1]
            return f"File created: {fname} by {img}"
        if eid == 22:
            return f"DNS query: {_xml_data(event, 'QueryName')}"
        if eid == 25:
            return f"Process tampering: {_xml_data(event, 'Image').split(chr(92))[-1]}"
    except Exception:
        pass
    return EID_LABEL.get(eid, f"Sysmon Event {eid}")

def _sysmon_log_total():
    """Return the total number of records in the Sysmon log."""
    try:
        r = subprocess.run(
            ["wevtutil", "gl", SYSMON_LOG],
            capture_output=True, text=True, timeout=5,
            **_SUBPROCESS_FLAGS,
        )
        for line in r.stdout.splitlines():
            if "numberOfLogRecords" in line.lower():
                return int(line.split(":")[-1].strip())
    except Exception:
        pass
    return 0

def _read_sysmon(count=150):
    """
    Read the most recent `count` Sysmon events via wevtutil.
    Returns a list of event dicts, newest first.
    Works with no extra Python packages — just needs wevtutil on PATH (standard Windows).
    """
    try:
        result = subprocess.run(
            ["wevtutil", "qe", SYSMON_LOG,
             f"/c:{count}", "/rd:true", "/f:xml"],
            capture_output=True, text=True, timeout=15,
            **_SUBPROCESS_FLAGS,
        )
        if result.returncode != 0:
            return []

        xml_text = f"<Root>{result.stdout}</Root>"
        root = ET.fromstring(xml_text)
        events = []

        for ev in root.findall("e:Event", NS):
            try:
                eid    = int(ev.find("e:System/e:EventID", NS).text)
                ts_raw = ev.find("e:System/e:TimeCreated", NS).get("SystemTime", "")
                ts     = ts_raw[:19].replace("T", " ")          # 2024-01-15 02:14:33
                t_part = ts[11:16] if len(ts) >= 16 else ""     # HH:MM
                host   = (ev.find("e:System/e:Computer", NS).text or "UNKNOWN")
                user   = (_xml_data(ev, "User") or
                          _xml_data(ev, "SubjectUserName") or "SYSTEM")
                sev    = _classify(eid, ev)
                title  = _make_title(eid, ev)

                events.append({
                    "eid":       eid,
                    "severity":  sev,
                    "title":     title,
                    "host":      host,
                    "user":      user,
                    "time":      t_part,
                    "timestamp": ts,
                })
            except Exception:
                continue

        return events
    except FileNotFoundError:
        print("[!] wevtutil not found — is this running on Windows?")
    except Exception as e:
        print(f"[!] Sysmon read error: {e}")
    return []

# Simple 10-second cache so rapid dashboard polls don't hammer the event log
_dash_cache = {"ts": 0.0, "data": None}
_dash_lock  = threading.Lock()

def _get_dashboard_data():
    import time
    with _dash_lock:
        now = time.monotonic()
        if _dash_cache["data"] and (now - _dash_cache["ts"]) < 10:
            return _dash_cache["data"]

    # ── Read Sysmon events ──
    events   = _read_sysmon(150)
    total_log = _sysmon_log_total()          # actual log record count

    now_dt   = datetime.utcnow()
    hour_ago = now_dt - timedelta(hours=1)
    today    = now_dt.date()

    events_last_hour = 0
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for ev in events:
        sev_counts[ev["severity"]] = sev_counts.get(ev["severity"], 0) + 1
        try:
            ets = datetime.strptime(ev["timestamp"], "%Y-%m-%d %H:%M:%S")
            if ets >= hour_ago:
                events_last_hour += 1
        except Exception:
            pass

    # ── Cases / alerts from detector ──
    try:
        all_cases = detector.get_active_cases()
    except Exception:
        all_cases = []

    cases_today    = sum(1 for c in all_cases
                        if c.get("timestamp","")[:10] == str(today))
    critical_cases = sum(1 for c in all_cases if c.get("severity") == "CRITICAL")
    alert_sev      = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for c in all_cases:
        s = c.get("severity","LOW")
        alert_sev[s] = alert_sev.get(s,0) + 1

    # Merge case severity into donut counts (on top of raw Sysmon events)
    donut = {
        "CRITICAL": alert_sev["CRITICAL"] or sev_counts["CRITICAL"],
        "HIGH":     alert_sev["HIGH"]     or sev_counts["HIGH"],
        "MEDIUM":   alert_sev["MEDIUM"]   or sev_counts["MEDIUM"],
        "LOW":      alert_sev["LOW"]      or sev_counts["LOW"],
    }
    donut_total = sum(donut.values())

    timeline = [
        {"time": e["time"], "title": e["title"],
         "host": e["host"], "user": e["user"],
         "severity": e["severity"]}
        for e in events[:15]
    ]

    data = {
        "total_events":      total_log or len(events),
        "events_last_hour":  events_last_hour,
        "total_incidents":   len(all_cases),
        "incidents_today":   cases_today,
        "active_alerts":     len(all_cases),
        "critical_count":    critical_cases,
        "donut":             donut,
        "donut_total":       donut_total,
        "timeline":          timeline,
        "total_shown":       len(events),
    }

    with _dash_lock:
        import time
        _dash_cache["ts"]   = time.monotonic()
        _dash_cache["data"] = data

    return data


@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    try:
        return jsonify(_get_dashboard_data())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
#  THREAT INTEL  (VirusTotal + AbuseIPDB)
# ─────────────────────────────────────────────

import requests as _req

ABUSEIPDB_KEY  = os.environ.get("ABUSEIPDB_KEY",  "")
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_KEY", "")

VT_BASE    = "https://www.virustotal.com/api/v3"
ABUSE_BASE = "https://api.abuseipdb.com/api/v2"

def _score_verdict(score):
    if score >= 80: return "CRITICAL"
    if score >= 55: return "HIGH"
    if score >= 25: return "MEDIUM"
    return "CLEAN"

def _vt_score(stats):
    total = sum(stats.values()) or 1
    return min(100, round((stats.get("malicious",0) + stats.get("suspicious",0)*0.5)/total*100))

def _narrative(query, qtype, score, verdict, country, reports, isp, threats, vt_attrs, abuse_data):
    usage    = abuse_data.get("usageType","Unknown")
    last_rep = abuse_data.get("lastReportedAt","")
    distinct = abuse_data.get("numDistinctUsers",0)
    asn      = vt_attrs.get("as_owner", isp or "Unknown ASN")
    if verdict in ("CRITICAL","HIGH"):
        summary = (f'The {"IP" if qtype=="ip" else "domain"} {query} is flagged as {verdict.lower()} '
                   f'risk (score {score}/100). AbuseIPDB recorded {reports:,} reports from {distinct} '
                   f'distinct users. {"Last reported: "+last_rep[:10]+". " if last_rep else ""}'
                   f'Network: {asn} ({country}), usage: {usage}.')
    elif verdict == "MEDIUM":
        summary = (f'{query} shows moderate risk (score {score}/100). '
                   f'{reports:,} abuse reports on record. Network: {asn} ({country}).')
    else:
        summary = (f'{query} has a low risk score ({score}/100) with only {reports:,} '
                   f'historical report(s). No significant threats detected.')
    engines  = [k for k,v in (vt_attrs.get("last_analysis_results") or {}).items()
                if v.get("category")=="malicious"][:5]
    cat_vals = list(set((vt_attrs.get("categories") or {}).values()))[:4]
    if engines:
        behavior = (f'Flagged by {len(engines)} engine(s): {", ".join(engines[:3])}'
                    f'{"…" if len(engines)>3 else ""}. '
                    + (f'Categories: {", ".join(cat_vals)}. ' if cat_vals else "")
                    + ('C2/scanning/brute-force pattern.' if score>55 else 'Scanner/probe activity.'))
    elif cat_vals:
        behavior = f'Categorised: {", ".join(cat_vals)}. Elevated suspicion from {reports} reports.'
    else:
        behavior = ('No malicious VT detections. '
                    f'AbuseIPDB suggests {"occasional" if reports<20 else "frequent"} abuse.')
    actions = {
        "CRITICAL": "BLOCK immediately at perimeter firewall.\nAdd to EDR/XDR blocklist.\nAudit all connections (last 30 days).\nEscalate to Tier 2 if sessions confirmed.\nPreserve PCAP evidence.",
        "HIGH":     "Block at edge firewall and proxy.\nReview connections (last 7 days).\nAlert affected users.\nAdd to watchlist.",
        "MEDIUM":   "Monitor traffic.\nLog all connections with metadata.\nReassess in 48 hours.",
        "CLEAN":    "No action required.\nContinue standard monitoring.",
    }
    return {"summary":summary,"behavior":behavior,"action":actions.get(verdict,actions["CLEAN"])}

def _analyze_ip(ip):
    abuse = _req.get(f"{ABUSE_BASE}/check",
        headers={"Key":ABUSEIPDB_KEY,"Accept":"application/json"},
        params={"ipAddress":ip,"maxAgeInDays":90,"verbose":False}, timeout=10)
    abuse.raise_for_status()
    ad = abuse.json().get("data",{})
    vt = _req.get(f"{VT_BASE}/ip_addresses/{ip}",
        headers={"x-apikey":VIRUSTOTAL_KEY}, timeout=10)
    vt.raise_for_status()
    va = vt.json().get("data",{}).get("attributes",{})
    abuse_score = ad.get("abuseConfidenceScore",0)
    vt_score    = _vt_score(va.get("last_analysis_stats",{}))
    score       = min(100, round(abuse_score*0.6+vt_score*0.4))
    verdict     = _score_verdict(score)
    country     = ad.get("countryCode") or va.get("country","—")
    reports     = ad.get("totalReports",0)
    isp         = ad.get("isp","")
    usage       = (ad.get("usageType") or "Unknown").upper()
    raw_tags    = list(va.get("tags",[]))
    if "tor" in usage.lower(): raw_tags.insert(0,"TOR EXIT")
    hits = sum(1 for v in (va.get("last_analysis_results") or {}).values() if v.get("category")=="malicious")
    if hits: raw_tags.append(f"VT:{hits} HITS")
    if reports>200: raw_tags.append("HIGH REPORTS")
    tags    = [t.upper()[:20] for t in raw_tags[:6]] or [usage[:18]]
    threats = list(dict.fromkeys(r.get("result") for r in
        (va.get("last_analysis_results") or {}).values()
        if r.get("category")=="malicious" and r.get("result")))[:6]
    nav  = _narrative(ip,"ip",score,verdict,country,reports,isp,threats,va,ad)
    conf = min(98,max(60,round((100-abs(abuse_score-vt_score)*0.3+min(reports/50,10))/1.1)))
    return {**nav,"score":score,"verdict":verdict,"country":country,"reports":reports,
            "type":usage[:18],"isp":isp,"tags":tags,"threats":threats,"confidence":f"{conf}%"}

def _analyze_domain(domain):
    vt = _req.get(f"{VT_BASE}/domains/{domain}",
        headers={"x-apikey":VIRUSTOTAL_KEY}, timeout=10)
    vt.raise_for_status()
    va      = vt.json().get("data",{}).get("attributes",{})
    score   = _vt_score(va.get("last_analysis_stats",{}))
    verdict = _score_verdict(score)
    reg     = va.get("registrar","—")
    cd      = va.get("creation_date")
    country = va.get("country","—")
    if cd:
        age_days = (datetime.utcnow()-datetime.utcfromtimestamp(cd)).days
        age_str  = f"{age_days}d old"
    else:
        age_days,age_str = 9999,"—"
    cats     = list(set((va.get("categories") or {}).values()))[:3]
    raw_tags = list(va.get("tags",[]))
    if age_days<30: raw_tags.insert(0,"NEWLY REGISTERED")
    if score>60:    raw_tags.insert(0,"MALICIOUS")
    tags    = [t.upper()[:20] for t in raw_tags[:6]] or [c.upper()[:18] for c in cats] or ["UNKNOWN"]
    reports = va.get("last_analysis_stats",{}).get("malicious",0)
    threats = list(dict.fromkeys(r.get("result") for r in
        (va.get("last_analysis_results") or {}).values()
        if r.get("category")=="malicious" and r.get("result")))[:6]
    nav  = _narrative(domain,"domain",score,verdict,country,reports,reg,threats,va,
                      {"usageType":"Domain","totalReports":reports,"numDistinctUsers":0,"lastReportedAt":""})
    conf = min(95,max(55,100-abs(50-score)//2))
    return {**nav,"score":score,"verdict":verdict,"country":country,"reports":reports,
            "type":"NEWLY REG." if age_days<30 else "DOMAIN","isp":reg,"age":age_str,
            "tags":tags,"threats":threats,"confidence":f"{conf}%"}

@app.route("/api/intel", methods=["GET"])
def intel():
    query = request.args.get("query","").strip()
    qtype = request.args.get("type","ip").lower()
    if not query:
        return jsonify({"error":"query parameter required"}),400
    if not ABUSEIPDB_KEY or not VIRUSTOTAL_KEY:
        return jsonify({"error":"API keys not configured — set ABUSEIPDB_KEY and VIRUSTOTAL_KEY in .env"}),503
    try:
        data = _analyze_ip(query) if qtype=="ip" else _analyze_domain(query)
        return jsonify(data)
    except _req.exceptions.HTTPError as e:
        s = e.response.status_code if e.response else 502
        if s==404: return jsonify({"error":f"{query} not found"}),404
        if s==401: return jsonify({"error":"Invalid API key"}),401
        return jsonify({"error":f"Upstream error {s}"}),502
    except _req.exceptions.Timeout:
        return jsonify({"error":"Threat intel API timed out"}),504
    except Exception as exc:
        return jsonify({"error":str(exc)}),500


# ─────────────────────────────────────────────
#  STARTUP
# ─────────────────────────────────────────────

if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", 5000))

    # Override detector poll interval from env if set
    pi = os.environ.get("POLL_INTERVAL")
    if pi:
        try:
            detector.POLL_INTERVAL = int(pi)
        except ValueError:
            pass

    print("=" * 60)
    print("  ThreatX SOC — Detection Server")
    print("  !! Run as Administrator for full log access !!")
    print("=" * 60)
    print()

    # Key status
    if ABUSEIPDB_KEY:
        print(f"[+] AbuseIPDB key  : {ABUSEIPDB_KEY[:6]}{'*'*10} (loaded)")
    else:
        print("[!] AbuseIPDB key  : NOT SET — Threat Intel will use mock data")
        print("    → Set ABUSEIPDB_KEY in .env")

    if VIRUSTOTAL_KEY:
        print(f"[+] VirusTotal key : {VIRUSTOTAL_KEY[:6]}{'*'*10} (loaded)")
    else:
        print("[!] VirusTotal key : NOT SET — Threat Intel will use mock data")
        print("    → Set VIRUSTOTAL_KEY in .env")

    print()

    # Start detection engine in background daemon thread
    engine_thread = threading.Thread(target=detector.run, daemon=True, name="DetectionEngine")
    engine_thread.start()
    print(f"[+] Detection engine started ({len(detector.ALL_RULES)} rules, every {detector.POLL_INTERVAL}s)")
    print(f"[+] Flask API running on http://{host}:{port}")
    print("[+] Open dashboard.html in your browser")
    print()

    app.run(host=host, port=port, debug=False, threaded=True)
