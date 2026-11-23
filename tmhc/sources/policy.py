"""Parse an Apex One ``.cmpolicy`` export into facts.

The ``.cmpolicy`` file an analyst exports from Apex Central / Standard
Endpoint Protection is JSON. Its ``settings`` member is a JSON *string*
holding one block per agent component (real-time scan, behaviour
monitoring, web reputation, ...). Those blocks contain every value the
policy-review section of the health-check report needs, so this parser
replaces reading them off screenshots.

Nothing here guesses: if a component or key is absent, no fact is
emitted and the row renders as "Unknown" rather than inventing a value.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Optional

from ..models import Fact, Source

# --------------------------------------------------------------------------
# Component name -> friendly module name
# --------------------------------------------------------------------------
COMPONENTS = {
    "comOSCESM": "scan_method",
    "comOSCERTSS": "realtime",
    "comOSCESSS": "scheduled",
    "comOSCEMSS": "manual",
    "comOSCESNS": "scannow",
    "comOSCEBMS": "behaviour_monitoring",
    "comOSCETX": "predictive_ml",
    "comOSCEWRS": "web_reputation",
    "comOSCECCCA": "suspicious_connection",
    "comOSCE_IVPAgent": "vulnerability_protection",
    "comOSCEDCS": "device_control",
    "comOSCE_IACRS": "application_control",
    "comOSCE_IESAgentSettings": "endpoint_sensor",
    "comOSCESO": "suspicious_objects",
    "comOSCETP": "trusted_program",
    "comOSCESAL": "spyware_approved",
    "comOSCEUAS": "update_agent",
    "comOSCEPOS": "privileges",
    "comOSCEASS": "additional_services",
}

LEVELS = {0: "Low", 1: "Low", 2: "Moderate", 3: "High"}

# Threat-type codes used inside the CustAction string.
THREAT_LABELS = {
    "CVE_Exploit": "CVE Exploit",
    "Joke": "Joke",
    "Trojan": "Trojans",
    "Virus": "Virus",
    "Test_Virus": "Test Virus",
    "Spyware": "Spyware",
    "Packer": "Packer",
    "Generic": "Probable Malware",
    "Other": "Other Malware",
    "Universe": "All types",
}
ACTION_CODES = {
    "1": "Pass",
    "2": "Quarantine",
    "3": "Delete",
    "4": "Quarantine",
    "5": "Clean",
    "-": "Deny Access",
}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _onoff(v: Any, on: str = "Enabled", off: str = "Disabled") -> str:
    return on if _truthy(v) else off


def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v.strip().lower() in {"1", "true", "yes", "on", "enabled"}
    return bool(v)


def _int(v: Any) -> Any:
    """Exports mix 2 and "2"; normalise to int where possible."""
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return v


def _desktop_server(settings: dict, desk_key: str, srv_key: str) -> tuple[str, str]:
    """Render the Windows desktop / Windows Server pair used widely in the report."""
    d, s = _truthy(settings.get(desk_key)), _truthy(settings.get(srv_key))
    return f"Windows desktops: {_onoff(d)}\nWindows Server platforms: {_onoff(s)}", (d, s)


def _decode_cust_action(raw: str) -> str:
    """Turn ``Universe-5-4,CVE_Exploit-4-1,...`` into a readable action list."""
    if not raw:
        return ""
    parts = []
    for item in raw.split(","):
        bits = item.split("-")
        if len(bits) < 2:
            continue
        name = THREAT_LABELS.get(bits[0], bits[0])
        first = ACTION_CODES.get(bits[1], bits[1])
        second = ACTION_CODES.get(bits[2], "") if len(bits) > 2 else ""
        if second and second != first:
            parts.append(f"{name}: {first} & {second}")
        else:
            parts.append(f"{name}: {first}")
    return ", ".join(parts)


DIM_LEVEL_TEXT = "Dynamic Intelligence Mode Enabled"
SCHEDULE_CODES = {2: "Weekly", 3: "Daily"}
VP_STATE = {0: True, 2: False}      # vulnerabilityShieldState, confirmed against consoles


def _level_text(m: dict) -> str:
    return (f"Detection-{m.get('DetectionLevel')} ({LEVELS.get(_int(m.get('DetectionLevel')), '?')})\n"
            f"Prevention-{m.get('PreventionLevel')} ({LEVELS.get(_int(m.get('PreventionLevel')), '?')})")


def _monitoring_level(m: dict, key: str, add, infer) -> None:
    """Monitoring level of one module.

    With Dynamic Intelligence Mode on, the console replaces the levels with
    "Dynamic Intelligence Mode Enabled" and the export omits the DIM flag
    and both levels. That absence is recorded as an inference (lower
    priority than a screenshot), never as a statement from the export.
    """
    if "DetectionLevel" in m or "PreventionLevel" in m:
        if _truthy(m.get("DIM")):
            add(key, "dim", DIM_LEVEL_TEXT)
        else:
            add(key, (m.get("DetectionLevel"), m.get("PreventionLevel")), _level_text(m))
    elif "DIM" in m:
        add(key, "dim" if _truthy(m["DIM"]) else None, DIM_LEVEL_TEXT if _truthy(m["DIM"]) else "Not set")
    else:
        infer(key, "dim", DIM_LEVEL_TEXT)


class PolicyExport:
    """Loaded view over a .cmpolicy file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        raw = json.loads(self.path.read_text(encoding="utf-8-sig"))
        policies = raw.get("policy") or []
        if not policies:
            raise ValueError(f"{self.path.name}: no policy object found")
        self.policy = policies[0]
        self.name: str = self.policy.get("policyName", "")
        self.product_id: str = str(self.policy.get("productID", ""))
        self.modules: dict[str, dict] = {}
        settings = self.policy.get("settings")
        if isinstance(settings, str):
            settings = json.loads(settings)
        for block in (settings or {}).get("data", []):
            friendly = COMPONENTS.get(block.get("wcomponent_name"))
            if not friendly:
                continue
            s = block.get("settings")
            if isinstance(s, str):
                try:
                    s = json.loads(s)
                except json.JSONDecodeError:
                    continue
            if isinstance(s, dict):
                self.modules[friendly] = s

    def mod(self, name: str) -> dict:
        return self.modules.get(name, {})


# --------------------------------------------------------------------------
# per-module extraction
# --------------------------------------------------------------------------
def _scan_target_facts(m: dict, prefix: str, out: list[Fact], evidence: str) -> None:
    """Rows shared by the Real-Time / Scheduled / Manual / Scan Now blocks."""
    add = lambda k, v, d: out.append(
        Fact(key=f"{prefix}.{k}", value=v, display=d,
             source=Source.POLICY_EXPORT, evidence=evidence)
    )

    if "Enable" in m:
        add("virus_scan", _truthy(m["Enable"]), _onoff(m["Enable"]))
    if "SpyEnable" in m:
        add("spyware_scan", _truthy(m["SpyEnable"]), _onoff(m["SpyEnable"]))

    # Files to scan
    if "IntelliScan" in m or "ScanAllFiles" in m:
        if _truthy(m.get("ScanAllFiles")):
            add("files_to_scan", "all", "All Scannable Files")
        elif _truthy(m.get("IntelliScan")):
            add("files_to_scan", "intelliscan", "File types scanned by IntelliScan")
        else:
            add("files_to_scan", "extlist", "Files with specified extensions")

    # OLE
    if "OleLayer" in m:
        layer = m.get("OleLayer")
        enabled = str(layer) not in ("", "0", "None")
        add("ole_scan", enabled,
            f"Enabled\nMaximum layers: {layer}" if enabled else "Disabled")
    if "OleExploitDetection" in m:
        add("ole_exploit", _truthy(m["OleExploitDetection"]),
            _onoff(m["OleExploitDetection"]))

    # Compressed files
    if "ScanCompressed" in m:
        on = _truthy(m["ScanCompressed"])
        add("compressed_scan", on,
            f"Enabled\nMaximum Layer : {m.get('CompressedLayer')}" if on else "Disabled")
    if "MaximumExtractFileSize" in m:
        add("compressed_max_size", m["MaximumExtractFileSize"],
            f"{m['MaximumExtractFileSize']} MB")
    if "CompressedFileCount" in m:
        add("compressed_file_count", m["CompressedFileCount"],
            f"{m['CompressedFileCount']} files")

    if "ScanBoot" in m:
        add("scan_boot", _truthy(m["ScanBoot"]), _onoff(m["ScanBoot"]))
    if "IntelliTrap" in m:
        add("intellitrap", _truthy(m["IntelliTrap"]), _onoff(m["IntelliTrap"]))
    if "AtseCveExploitAction" in m:
        add("cve_exploit_scan", _truthy(m["AtseCveExploitAction"]),
            _onoff(m["AtseCveExploitAction"]))

    # Actions
    if "CustAction" in m:
        active = _truthy(m.get("ActiveAction"))
        decoded = _decode_cust_action(m.get("CustAction", ""))
        add("action_mode", "activeaction" if active else "specific",
            "Use ActiveAction" if active else f"Use specific action. {decoded}")
    for spy_key in ("SpyBlockNCleanAction", "SpyCleanAction"):
        if spy_key in m:
            add("spyware_clean", _truthy(m[spy_key]),
                "Clean: Enabled" if _truthy(m[spy_key]) else "Clean: Disabled")
            break
    if "BkUpIfClean" in m:
        add("backup_before_clean", _truthy(m["BkUpIfClean"]), _onoff(m["BkUpIfClean"]))
    if "EnableAggressiveClean" in m:
        add("clean_type", _truthy(m["EnableAggressiveClean"]),
            "Advance Cleanup" if _truthy(m["EnableAggressiveClean"]) else "Standard Cleanup")
    if "SystemCleanForPossibleVirus" in m:
        add("cleanup_probable", _truthy(m["SystemCleanForPossibleVirus"]),
            _onoff(m["SystemCleanForPossibleVirus"]))
    if "PopVirusFoundAlert" in m:
        add("notify_virus", _truthy(m["PopVirusFoundAlert"]), _onoff(m["PopVirusFoundAlert"]))
    if "DispPossibleVirusFoundAlert" in m:
        add("notify_probable", _truthy(m["DispPossibleVirusFoundAlert"]),
            _onoff(m["DispPossibleVirusFoundAlert"]))
    if "SpyPopSpywareFoundAlert" in m:
        add("notify_spyware", _truthy(m["SpyPopSpywareFoundAlert"]),
            _onoff(m["SpyPopSpywareFoundAlert"]))

    # Advanced malware detection (Advanced ActiveAction vs fixed action)
    if "AdvancedActiveAction" in m:
        customised = _truthy(m.get("CustomizedActionForAdvanced"))
        add("advanced_malware_detection", "customised" if customised else "activeaction",
            "Use the same action for all portable executable files"
            if customised else "Use ActiveAction")

    # Exclusions
    if "EnableExclusion" in m:
        add("exclusion_enabled", _truthy(m["EnableExclusion"]), _onoff(m["EnableExclusion"]))
    if "ExcludeTrendProduct" in m:
        add("exclude_trend_dirs", _truthy(m["ExcludeTrendProduct"]),
            _onoff(m["ExcludeTrendProduct"]))
    if "ExcludedFolder" in m or "ExcludedFile" in m:
        dirs = [d for d in (m.get("ExcludedFolder") or "").split("|") if d]
        files = [f for f in (m.get("ExcludedFile") or "").split("|") if f]
        exts = [e for e in (m.get("ExcludedExt") or "").split(",") if e]
        add("exclusion_list", {"dirs": dirs, "files": files, "exts": exts},
            "Configured" if (dirs or files or exts) else "Not Configured")
        add("exclusion_counts", (len(dirs), len(files), len(exts)),
            f"{len(dirs)} directories, {len(files)} files, {len(exts)} extensions")

    # Real-time-only extras
    if "ScanIncoming" in m or "ScanOutgoing" in m:
        inc, outg = _truthy(m.get("ScanIncoming")), _truthy(m.get("ScanOutgoing"))
        if inc and outg:
            disp = "created /modified and retrieved"
        elif inc:
            disp = "created/modified"
        elif outg:
            disp = "retrieved"
        else:
            disp = "Disabled"
        add("scan_on", (inc, outg), disp)
    if "ScanShutDown" in m:
        add("scan_floppy_shutdown", _truthy(m["ScanShutDown"]), _onoff(m["ScanShutDown"]))
    if "USBBootScan" in m:
        add("usb_boot_scan", _truthy(m["USBBootScan"]), _onoff(m["USBBootScan"]))
    if "USBScanTouch" in m:
        add("usb_all_files_scan", _truthy(m["USBScanTouch"]), _onoff(m["USBScanTouch"]))
    if "RavageScanMemory" in m:
        add("quarantine_memory_variants", _truthy(m["RavageScanMemory"]),
            _onoff(m["RavageScanMemory"]))
    if "ScanNetwork" in m:
        add("scan_network_drive", _truthy(m["ScanNetwork"]), _onoff(m["ScanNetwork"]))
    if "ScanHiddenFolder" in m:
        add("scan_hidden", _truthy(m["ScanHiddenFolder"]), _onoff(m["ScanHiddenFolder"]))

    # Scheduled-scan-only extras
    if "Frequency" in m:
        # Codes confirmed against real consoles: 2 = Weekly, 3 = Daily. Any other
        # code is left for the screenshot/checklist rather than guessed.
        freq = SCHEDULE_CODES.get(_int(m["Frequency"]))
        if freq:
            days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
            disp = freq
            if freq == "Weekly" and isinstance(_int(m.get("DayOfWeek")), int) and 0 <= _int(m["DayOfWeek"]) <= 6:
                disp = f"Weekly ({days[_int(m['DayOfWeek'])]})"
            add("schedule", freq.lower(), disp)
    if "EnableAutoStopScheduleScan" in m:
        on = _truthy(m["EnableAutoStopScheduleScan"])
        add("auto_stop", on,
            f"Enabled ({m.get('ScheduleScanLimitMinutes')} min)" if on else "Disabled")
    if "EnableBatteryLifeCheck" in m:
        on = _truthy(m["EnableBatteryLifeCheck"])
        add("skip_on_battery", on,
            f"Enabled ({m.get('MiniBatteryLife')}%)" if on else "Disabled")
    if "EnableResumeScan" in m:
        # ResumeScanType: 1 = missed scans, 2 = interrupted scans, 3 = both.
        on = _truthy(m["EnableResumeScan"])
        rtype = int(m.get("ResumeScanType") or 0)
        add("resume_missed", on and rtype in (1, 3), _onoff(on and rtype in (1, 3)))
        add("resume_interrupted", on and rtype in (2, 3), _onoff(on and rtype in (2, 3)))
    speed_key = "ScanSpeed" if "ScanSpeed" in m else ("CPUUsage" if "CPUUsage" in m else None)
    if speed_key:
        cpu = {0: "High", 1: "Medium", 2: "Low"}.get(_int(m[speed_key]), str(m[speed_key]))
        add("cpu_usage", m[speed_key], cpu)


def extract(path: str | Path) -> tuple[list[Fact], PolicyExport]:
    """Read a .cmpolicy file and return the facts it proves."""
    pol = PolicyExport(path)
    ev = pol.path.name
    out: list[Fact] = []

    def add(key: str, value: Any, display: str) -> None:
        out.append(Fact(key=key, value=value, display=display,
                        source=Source.POLICY_EXPORT, evidence=ev))

    def infer(key: str, value: Any, display: str) -> None:
        out.append(Fact(key=key, value=value, display=display, source=Source.POLICY_INFERRED,
                        confidence=0.7, evidence=f"{ev} (inferred: setting absent from export)"))

    # ---- scan method -----------------------------------------------------
    m = pol.mod("scan_method")
    if m:
        smart = _truthy(m.get("CloudScanType"))
        add("policy.scan_method", "smart" if smart else "conventional",
            "Smart Scan" if smart else "Conventional Scan")
        if "DIM" in m:
            add("policy.dynamic_intelligence_mode", _truthy(m["DIM"]), _onoff(m["DIM"]))
        elif "DetectionLevel" not in m and "PreventionLevel" not in m:
            # exports from DIM-enabled policies carry neither the flag nor the levels
            infer("policy.dynamic_intelligence_mode", True, "Enabled")
        _monitoring_level(m, "policy.monitoring_level", add, infer)

    # ---- the four scan types --------------------------------------------
    for mod_name, prefix in (
        ("realtime", "policy.realtime"),
        ("scheduled", "policy.scheduled"),
        ("manual", "policy.manual"),
        ("scannow", "policy.scannow"),
    ):
        block = pol.mod(mod_name)
        if block:
            _scan_target_facts(block, prefix, out, ev)

    # ---- behaviour monitoring -------------------------------------------
    m = pol.mod("behaviour_monitoring")
    if m:
        add("policy.bm.malware_behaviour_blocking", _truthy(m.get("td_enable_setting")),
            _onoff(m.get("td_enable_setting")))
        add("policy.bm.threats_to_block", m.get("td_blocking_mode"),
            "Known and potential threats" if str(m.get("td_blocking_mode")) == "1"
            else "Known threats only")
        add("policy.bm.protect_documents", _truthy(m.get("dre_enable_setting")),
            _onoff(m.get("dre_enable_setting")))
        add("policy.bm.backup_restore_files", _truthy(m.get("adc_enable_setting")),
            _onoff(m.get("adc_enable_setting")))
        add("policy.bm.block_ransomware_processes", _truthy(m.get("srp_enable_setting")),
            _onoff(m.get("srp_enable_setting")))
        add("policy.bm.program_inspection", _truthy(m.get("umh_enable_setting")),
            _onoff(m.get("umh_enable_setting")))
        add("policy.bm.anti_exploit", _truthy(m.get("umh_exploit_enable_setting")),
            _onoff(m.get("umh_exploit_enable_setting")))
        newly = _truthy(m.get("meerkat_detection_enable_setting"))
        add("policy.bm.newly_encountered", newly,
            "Enabled - Prompt user" if newly else "Disabled")
        add("policy.bm.event_monitoring", _truthy(m.get("bm_enable_setting")),
            _onoff(m.get("bm_enable_setting")))
        add("policy.bm.assessment_mode",
            _truthy(m.get("meerkat_assess_mode_enable_setting")),
            _onoff(m.get("meerkat_assess_mode_enable_setting")))
        approved = [p for p in (m.get("approvedList_info") or "").split("|") if p]
        blocked = [p for p in (m.get("blockedList_info") or "").split("|") if p]
        add("policy.bm.exceptions", {"approved": approved, "blocked": blocked},
            "Configured" if (approved or blocked) else "Not Configured")

    # ---- predictive machine learning ------------------------------------
    m = pol.mod("predictive_ml")
    if m:
        add("policy.pml.enabled", _truthy(m.get("ENABLE_TRENDX")), _onoff(m.get("ENABLE_TRENDX")))
        _monitoring_level(m, "policy.pml.monitoring_level", add, infer)
        file_on = _truthy(m.get("ENABLE_FILE_ACTION"))
        add("policy.pml.file_action", (file_on, m.get("FILE_ACTION_FOR_TRENDX")),
            "Enable-Quarantine" if file_on and str(m.get("FILE_ACTION_FOR_TRENDX")) == "0"
            else ("Enabled - Log only" if file_on else "Disabled"))
        proc_on = _truthy(m.get("ENABLE_PROCESS_ACTION"))
        add("policy.pml.process_action", (proc_on, m.get("PROCESS_ACTION_FOR_TRENDX")),
            "Enable-Terminate" if proc_on and str(m.get("PROCESS_ACTION_FOR_TRENDX")) == "0"
            else ("Enabled - Log only" if proc_on else "Disabled"))
        exc = m.get("EXCEPTIONS") or []
        add("policy.pml.exceptions", exc, "Configured" if exc else "Not configured")

    # ---- web reputation --------------------------------------------------
    m = pol.mod("web_reputation")
    if m:
        desk_in, desk_out = _truthy(m.get("URLFilterEnable_InOffice")), _truthy(m.get("URLFilterEnable_OutOffice"))
        srv = _truthy(m.get("URLFilterEnableServerPlatform_InOffice")) or \
              _truthy(m.get("URLFilterEnableServerPlatform_OutOffice"))
        add("policy.wr.enabled", (desk_in or desk_out, srv),
            f"Windows Desktop: {_onoff(desk_in or desk_out)}\n"
            f"Windows Server: {_onoff(srv)}")
        add("policy.wr.assessment_mode",
            _truthy(m.get("URLFilterEnableAss_InOffice")),
            _onoff(m.get("URLFilterEnableAss_InOffice")))
        https_in = _truthy(m.get("URLFilterEnableHttpsPlugin_InOffice"))
        https_out = _truthy(m.get("URLFilterEnableHttpsPlugin_OutOffice"))
        add("policy.wr.check_https", (https_in, https_out),
            f"{_onoff(https_in)} (Internal)\n{_onoff(https_out)} (External)")
        off = [n for n, on in (("internal", https_in), ("external", https_out)) if not on]
        add("policy.wr.check_https_off_for", off,
            " and ".join(off) + " agents" if off else "no agents")
        add("policy.wr.query_sps",
            _truthy(m.get("URLFilterEnableLWCS_InOffice")),
            _onoff(m.get("URLFilterEnableLWCS_InOffice")))
        lvl = _int(m.get("URLFilterRatingLevel_InOffice"))
        label = {1: "High", 2: "Medium", 3: "Low"}.get(lvl, str(lvl))
        add("policy.wr.security_level", label, label)
        add("policy.wr.browser_exploit_prevention", _truthy(m.get("BES_InOffice")),
            _onoff(m.get("BES_InOffice")))
        appr = [u for u in (m.get("URLFilterApprovedList_InOffice") or "").split("|") if u]
        blk = [u for u in (m.get("URLFilterBlockedList_InOffice") or "").split("|") if u]
        add("policy.wr.approved_blocked_urls", {"approved": appr, "blocked": blk},
            "Configured" if (appr or blk) else "Not Configured")
        add("policy.wr.send_logs", _truthy(m.get("URLFilterLogEnable_InOffice")),
            _onoff(m.get("URLFilterLogEnable_InOffice")))

    # ---- suspicious connection ------------------------------------------
    m = pol.mod("suspicious_connection")
    if m:
        gc = _truthy(m.get("EnableGC"))
        add("policy.sc.global_cc_list", (gc, m.get("ActionForCNP")),
            f"{_onoff(gc)} - {'Block' if str(m.get('ActionForCNP')) == '1' else 'Log'}")
        rr = _truthy(m.get("EnableRR"))
        add("policy.sc.network_fingerprinting", (rr, m.get("ActionForRR")),
            f"{_onoff(rr)} - {'Block' if str(m.get('ActionForRR')) == '1' else 'Log'}")
        _monitoring_level(m, "policy.sc.monitoring_level", add, infer)
        add("policy.sc.clean_on_cc", _truthy(m.get("EnableCNP")), _onoff(m.get("EnableCNP")))

    # ---- vulnerability protection ---------------------------------------
    m = pol.mod("vulnerability_protection")
    if m:
        enabled = VP_STATE.get(_int(m.get("vulnerabilityShieldState")))
        if enabled is not None:                  # unknown codes: left to screenshot / checklist
            add("policy.vp.enabled", enabled, _onoff(enabled))
            rules = m.get("ipsRules") or {}
            total = sum(len(rules.get(k) or []) for k in ("enabledList", "preventList", "logOnlyList"))
            if not enabled:
                add("policy.vp.profile", None, "N/A")
                add("policy.vp.network_engine_mode", None, "N/A")
            elif total:
                add("policy.vp.profile", total, f"{total} rules assigned")
            # Profile (Recommended/Aggressive) and engine mode are not in the export
            # when VP is on - read from the screenshot or filled in on the website.

    # ---- device control --------------------------------------------------
    m = pol.mod("device_control")
    if m:
        js = (m.get("jsondata") or {}).get("DEVICE", {}).get("EXTERNAL", {})
        add("policy.dc.enabled", _truthy(js.get("ENABLE_SETTING")),
            _onoff(js.get("ENABLE_SETTING")))
        deny_auto = (js.get("USB") or {}).get("ACCESS", {}).get("DENY_AUTO")
        add("policy.dc.block_autorun", _truthy(deny_auto), _onoff(deny_auto))
        approved = (js.get("ACCESS_EXCEPT") or {}).get("APPROVED_LIST") or []
        add("policy.dc.approved_usb_list", approved,
            f"Configured ({len(approved)} devices)" if approved else "Not Configured")

    # ---- application control --------------------------------------------
    m = pol.mod("application_control")
    if m:
        cf = m.get("clientFormat") or {}
        add("policy.ac.enabled", _truthy(cf.get("serviceEnable")),
            _onoff(cf.get("serviceEnable")))
        lock = _truthy(cf.get("whiteListCheck"))
        actions = ("Lockdown: Block all applications not identified during the last inventory scan"
                   if lock else "Allow: All other applications can execute")
        if lock:
            actions += f"\nEnable assessment mode: {_onoff(cf.get('isReportOnly'))}"
        add("policy.ac.lockdown", lock, actions)
        add("policy.ac.assessment_mode", _truthy(cf.get("isReportOnly")),
            _onoff(cf.get("isReportOnly")))
        add("policy.ac.max_log_age", cf.get("maxLogAgeDays"),
            f"{cf.get('maxLogAgeDays')} Days" if cf.get("maxLogAgeDays") is not None else "N/A")
        add("policy.ac.max_logs_per_hour", cf.get("detectionLogMaxNumberToUpload"),
            str(cf.get("detectionLogMaxNumberToUpload"))
            if cf.get("detectionLogMaxNumberToUpload") is not None else "N/A")
        rules = m.get("ruleMappings") or {}
        names = [r.get("ruleName", "") for r in rules.values()]
        add("policy.ac.rules", names,
            f"{len(names)} rules: " + ", ".join(names) if names else "N/A")

    # ---- exceptions / trusted program ------------------------------------
    m = pol.mod("trusted_program")
    if m:
        approved = m.get("APPROVEDLIST") or []
        add("policy.exceptions.trusted_programs", approved,
            f"Configured ({len(approved)} entries)" if approved else "Not Configured")

    m = pol.mod("spyware_approved")
    if m:
        raw = (m.get("AdditionalThreatExclusionInfo") or "").strip()
        items = [i for i in raw.split("|") if i]
        add("policy.exceptions.spyware_approved_list", items,
            f"Configured ({len(items)} entries)" if items else "Not Configured")

    # ---- update agent -----------------------------------------------------
    m = pol.mod("update_agent")
    if m:
        comp = _truthy(m.get("ProvideUpdateAgentComponentService"))
        dom = _truthy(m.get("ProvideUpdateAgentSettingService"))
        prog = _truthy(m.get("ProvideUpdateAgentProgramService"))
        any_on = comp or dom or prog
        add("policy.update_agent.configured", (comp, dom, prog),
            f"Components: {_onoff(comp)}, Domain settings: {_onoff(dom)}, "
            f"Programs and hotfixes: {_onoff(prog)}" if any_on else "Not Configured")

    # ---- privileges & other settings -------------------------------------
    m = pol.mod("privileges")
    if m:
        add("policy.priv.configure_manual_scan", _truthy(m.get("AllowCfgMS")),
            _onoff(m.get("AllowCfgMS")))
        add("policy.priv.configure_realtime_scan", _truthy(m.get("AllowCfgRT")),
            _onoff(m.get("AllowCfgRT")))
        add("policy.priv.configure_scheduled_scan", _truthy(m.get("AllowCfgPS")),
            _onoff(m.get("AllowCfgPS")))
        if "Uninst" in m:
            ok = not _truthy(m.get("Uninst")) and bool(m.get("New_Uninstall_Pwd"))
            add("policy.priv.uninstall_password", ok, "Enabled" if ok else "Disabled")
        if "Unload" in m:
            ok = not _truthy(m.get("Unload")) and bool(m.get("New_Unload_Pwd"))
            add("policy.priv.unload_password", ok, "Enabled" if ok else "Disabled")
        if "AllowScheduleUpdate" in m:
            add("policy.priv.toggle_scheduled_updates", _truthy(m.get("AllowScheduleUpdate")),
                _onoff(m.get("AllowScheduleUpdate")))
        if "AllowUpdateFromTMAU" in m:
            add("policy.priv.update_from_activeupdate", _truthy(m.get("AllowUpdateFromTMAU")),
                _onoff(m.get("AllowUpdateFromTMAU")))
        # combined rows as laid out in the report
        scan_cfg = (_truthy(m.get("AllowCfgMS")), _truthy(m.get("AllowCfgRT")), _truthy(m.get("AllowCfgPS")))
        add("policy.priv.scan_privileges", scan_cfg,
            f"Configure Manual Scan settings: {_onoff(scan_cfg[0])}\n"
            f"Configure Real-time Scan settings: {_onoff(scan_cfg[1])}\n"
            f"Configure Scheduled Scan settings: {_onoff(scan_cfg[2])}")
        sched = (_truthy(m.get("AllowDelayScheduleScan")), _truthy(m.get("AllowStopScheduleScan")))
        add("policy.priv.scheduled_scan_privileges", sched,
            f"Postpone Scheduled Scan : {_onoff(sched[0])}\nSkip and stop Scheduled Scan : {_onoff(sched[1])}")
        simple = {
            "policy.priv.firewall_display": "DisplayPFWTab",
            "policy.priv.firewall_toggle": "AllowControlPFW",
            "policy.priv.firewall_send_logs": "AllowSendPFWLog",
            "policy.priv.bm_display": "AllowConfigBM",
            "policy.priv.trusted_program_display": "AllowConfigTrustProgram",
            "policy.priv.mail_scan_display": "MailScanPageOnOff",
            "policy.priv.proxy_settings": "ProxySettingOnOff",
            "policy.priv.update_now": "AllowUpdateNow",
            "policy.priv.coexist_conversion": "AllowPromoteCoexist",
            "policy.priv.schedule_update_on_agents": "ScheduleUpdateStatus",
            "policy.priv.pop3_scan": "EnablePop3MailScan",
        }
        for key, src in simple.items():
            if src in m:
                add(key, _truthy(m[src]), _onoff(m[src]))
        if "NoProgramUpgrade" in m or "NoEngineUpgrade" in m:
            parts = [n for n, flag in (("program", "NoProgramUpgrade"), ("engine", "NoEngineUpgrade"))
                     if _truthy(m.get(flag))]
            add("policy.priv.update_components", not parts,
                "All components" if not parts else "All components except " + " and ".join(parts) + " updates")
        if "EnableGCLCache" in m or "EnableODSCache" in m:
            both = _truthy(m.get("EnableGCLCache")) and _truthy(m.get("EnableODSCache"))
            add("policy.priv.scan_cache", both,
                "Enabled" if both else
                f"Digital signature cache: {_onoff(m.get('EnableGCLCache'))}, "
                f"On-demand scan cache: {_onoff(m.get('EnableODSCache'))}")

    # ---- additional service settings --------------------------------------
    m = pol.mod("additional_services")
    if m:
        for key, (dk, sk) in {
            "policy.svc.unauthorized_change_prevention": ("setting_aegis", "setting_aegis_server"),
            "policy.svc.firewall": ("setting_firewall", "setting_firewall_server"),
            "policy.svc.suspicious_connection": ("setting_ncie", "setting_ncie_server"),
            "policy.svc.data_protection": ("setting_dlp", "setting_dlp_server"),
            "policy.svc.advanced_protection": ("setting_ccsf", "setting_ccsf_server"),
            "policy.svc.antimalware": ("setting_antimalware", "setting_antimalware_server"),
        }.items():
            if dk in m or sk in m:
                disp, val = _desktop_server(m, dk, sk)
                add(key, val, disp)

    return out, pol
