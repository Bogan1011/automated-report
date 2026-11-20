"""Synthetic fixtures - no customer data is ever stored in this repository."""
import csv
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _component(name, settings):
    return {"wcomponent_name": name, "wcomponent_version": "1.0", "type": 0,
            "settings": json.dumps(settings)}


@pytest.fixture
def cmpolicy(tmp_path) -> Path:
    scan = {
        "Enable": 1, "SpyEnable": 1, "IntelliScan": 1, "ScanAllFiles": 0,
        "ScanCompressed": 1, "CompressedLayer": "3", "MaximumExtractFileSize": 10,
        "CompressedFileCount": 30, "OleLayer": "3", "OleExploitDetection": 1,
        "ActiveAction": 0, "CustAction": "Virus-5-4,Trojan-4-2", "AdvancedActiveAction": 1,
        "CustomizedActionForAdvanced": 0, "EnableExclusion": 1, "ExcludeTrendProduct": 1,
        "ExcludedFolder": "C:\\App|C:\\Other", "ExcludedFile": "", "ExcludedExt": "",
        "ScanIncoming": 1, "ScanOutgoing": 1,
    }
    scheduled = dict(scan, IntelliScan=0, ScanAllFiles=1, Frequency=2, DayOfWeek=5,
                     EnableResumeScan=1, ResumeScanType=1, ScanSpeed=1,
                     EnableAutoStopScheduleScan=0, EnableBatteryLifeCheck=1, MiniBatteryLife=20)
    data = [
        _component("comOSCESM", {"CloudScanType": 1, "DetectionLevel": 2, "PreventionLevel": 2, "DIM": 0}),
        _component("comOSCERTSS", scan),
        _component("comOSCESSS", scheduled),
        _component("comOSCEBMS", {"td_enable_setting": 1, "td_blocking_mode": "1", "bm_enable_setting": 0,
                                  "approvedList_info": "C:\\a.exe", "blockedList_info": ""}),
        _component("comOSCEWRS", {"URLFilterEnable_InOffice": 1, "URLFilterEnable_OutOffice": 1,
                                  "URLFilterEnableServerPlatform_InOffice": 0,
                                  "URLFilterEnableHttpsPlugin_InOffice": 0,
                                  "URLFilterEnableHttpsPlugin_OutOffice": 1,
                                  "URLFilterRatingLevel_InOffice": "2", "BES_InOffice": 1}),
        _component("comOSCE_IVPAgent", {"vulnerabilityShieldState": 2, "ipsRules": {}}),
        _component("comOSCE_IACRS", {"clientFormat": {"serviceEnable": False, "maxLogAgeDays": 90,
                                                      "detectionLogMaxNumberToUpload": 10},
                                     "ruleMappings": {"x": {"ruleName": "Block Firefox", "ruleType": "block"}}}),
        _component("comOSCEASS", {"setting_firewall": 1, "setting_firewall_server": 0,
                                  "setting_aegis": 1, "setting_aegis_server": 1}),
    ]
    p = tmp_path / "Policy_Test.cmpolicy"
    p.write_text(json.dumps({"policy": [{"policyName": "Acme Windows", "productID": "15.4",
                                         "settings": json.dumps({"data": data})}]}),
                 encoding="utf-8")
    return p


@pytest.fixture
def agent_list(tmp_path) -> Path:
    rows = []
    def add(n, build, status="Online", pattern="21.363.00", platform="Windows 11", restart="No"):
        for _ in range(n):
            rows.append({"Endpoint": f"PC{len(rows)}", "Connection Status": status,
                         "Agent Program": build, "Smart Scan Agent Pattern": pattern,
                         "Platform": platform, "Restart Required": restart, "Scan Method": "Smart Scan"})
    add(10, "14.0.20958")
    add(3, "14.0.20898", status="Offline")
    add(2, "14.0.20731", pattern="21.351.00")           # exactly 12 releases behind -> fresh
    add(1, "14.0.20524", pattern="21.349.00")           # 14 behind -> stale
    add(2, "14.0.14320", pattern="20.871.00", platform="Windows Server 2019", restart="Yes (update)")
    p = tmp_path / "Apex One Security Agent List.csv"
    with p.open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    return p
