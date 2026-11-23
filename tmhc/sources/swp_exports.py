"""Server & Workload Protection (Vision One SWP / Deep Security) exports.

The SWP evidence zip holds:

* ``Computers.csv``          - every protected computer: platform, policy,
                               status, agent version, component update status
                               and the live state of every protection module.
* ``<name> policy.xml``      - policy exports (Policies > Export). They contain
                               only what is set *on that policy*; inherited
                               values are absent, so anything not in the file
                               is left to the screenshots.
* ``Intrusion_Prevention_Events.csv`` / ``Log_Inspection_Events.csv`` -
                               detections for the efficacy presentation.
* ``Directory_Lists.csv`` / ``File_Lists.csv`` / ``File_Extension_Lists.csv``
                             - common-object lists used by scan exclusions.

Facts use the prefix ``swp.`` (environment) and ``win.`` / ``lin.`` (the
Windows and Linux server policies the report reviews).
"""
from __future__ import annotations

import csv
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from ..models import Fact, Source

ENDASH = "–"


def version_key(v: str) -> tuple:
    try:
        return tuple(int(x) for x in str(v).split("."))
    except (ValueError, AttributeError):
        return (-1,)


def is_windows(platform: str) -> bool:
    return "windows" in (platform or "").lower()


def policy_scope(name: str) -> Optional[str]:
    """'Windows_Server' -> 'win', 'Linux Server' -> 'lin' (the two reviewed policies)."""
    n = (name or "").lower()
    if "basic" in n:
        return None
    if "linux" in n:
        return "lin"
    if "windows" in n and "desktop" not in n:
        return "win"
    return None


def _read_csv(path: Path) -> list[dict]:
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-16", "cp1252", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    lines = text.splitlines()
    csv.field_size_limit(10 ** 8)
    return [r for r in csv.DictReader(lines) if any((v or "").strip() for v in r.values())]


# --------------------------------------------------------------------------
# Computers.csv
# --------------------------------------------------------------------------
MODULE_COLUMNS = {
    "am": "Anti-Malware Status Light",
    "wrs": "Web Reputation Status Light",
    "dc": "Device Control Status Light",
    "ac": "Application Control Status Light",
    "fw": "Firewall Status Light",
    "ips": "Intrusion Prevention Status Light",
    "im": "Integrity Monitoring Status Light",
    "li": "Log Inspection Status Light",
}


class Computers:
    def __init__(self, path: str | Path, latest_windows: str = "", latest_linux: str = ""):
        self.path = Path(path)
        self.rows = _read_csv(self.path)
        self.latest_windows = (latest_windows or "").strip()
        self.latest_linux = (latest_linux or "").strip()

    @property
    def total(self) -> int:
        return len(self.rows)

    def light(self, r: dict) -> str:
        return (r.get("Status Light") or "").split(" [")[0].strip()

    @property
    def lights(self) -> Counter:
        return Counter(self.light(r) for r in self.rows)

    def reasons(self, light: str) -> list[str]:
        return sorted({(r.get("Status") or "").strip() for r in self.rows
                       if self.light(r) == light and (r.get("Status") or "").strip()})

    @property
    def versions(self) -> Counter:
        return Counter((r.get("Version") or "").strip() for r in self.rows if (r.get("Version") or "").strip())

    @property
    def platforms(self) -> Counter:
        return Counter((r.get("Platform") or "").strip() for r in self.rows)

    @property
    def policies(self) -> Counter:
        return Counter((r.get("Policy") or "").strip() or "None" for r in self.rows)

    @property
    def component_status(self) -> Counter:
        return Counter((r.get("Component Update Status") or "").strip() or "Unknown" for r in self.rows)

    def latest_for(self, r: dict) -> str:
        return self.latest_windows if is_windows(r.get("Platform", "")) else self.latest_linux

    def newest_seen(self, windows: bool) -> str:
        vs = [(r.get("Version") or "").strip() for r in self.rows
              if is_windows(r.get("Platform", "")) == windows and (r.get("Version") or "").strip()]
        return max(vs, key=version_key) if vs else ""

    @property
    def outdated(self) -> int:
        n = 0
        for r in self.rows:
            v, latest = (r.get("Version") or "").strip(), self.latest_for(r)
            if not v:
                continue
            if not latest:
                latest = self.newest_seen(is_windows(r.get("Platform", "")))
            if version_key(v) < version_key(latest):
                n += 1
        return n

    def module_state(self, policy: str, module: str) -> Optional[str]:
        """Most common module state among computers on a policy ('On, Prevent', 'Off, installed')."""
        col = MODULE_COLUMNS[module]
        states = Counter()
        for r in self.rows:
            if (r.get("Policy") or "").strip() != policy:
                continue
            val = (r.get(col) or "").split(":", 1)[-1].strip()
            if val:
                states[val] += 1
        return states.most_common(1)[0][0] if states else None


def computers_facts(path: Path, latest_windows: str = "", latest_linux: str = "",
                    check_date: str = "") -> tuple[list[Fact], dict[str, Any], Computers]:
    c = Computers(path, latest_windows, latest_linux)
    ev = path.name
    facts: list[Fact] = []
    m: dict[str, Any] = {}
    lights = c.lights
    crit, warn, managed = lights.get("Critical", 0), lights.get("Warning", 0), lights.get("Managed", 0)
    unmanaged = c.total - crit - warn - managed
    m.update(deployed_agents=c.total, critical=crit, warning=warn, managed=managed, unmanaged=unmanaged)
    m["critical_reasons"] = ", ".join(c.reasons("Critical"))
    m["warning_reasons"] = ", ".join(c.reasons("Warning"))
    m["critical_line"] = f"{crit} Critical agents: {m['critical_reasons']}" if crit else "No Critical agents"
    m["warning_line"] = f"{warn} Warning agents: {m['warning_reasons']}" if warn else "No Warning agents"

    # agent versions
    lw = latest_windows or c.newest_seen(True)
    ll = latest_linux or c.newest_seen(False)
    m["latest_dsa_windows"], m["latest_dsa_linux"] = lw, ll
    m["newest_seen_windows"], m["newest_seen_linux"] = c.newest_seen(True), c.newest_seen(False)
    outdated = c.outdated
    m["outdated_agents"] = outdated
    lines = [f"{v} {ENDASH} {n}" for v, n in sorted(c.versions.items(),
                                                    key=lambda kv: (-kv[1], [-x for x in version_key(kv[0])]))]
    if outdated == c.total and c.total:
        lines.append(f"Agents outdated {ENDASH} all")
        m["outdated_phrase"] = "All"
    elif outdated:
        lines.append(f"Agents outdated {ENDASH} {outdated}")
        m["outdated_phrase"] = str(outdated)
    m["agent_versions"] = [(v, n) for v, n in c.versions.most_common()]
    facts.append(Fact("swp.inventory.agent_versions", outdated, "\n".join(lines), Source.AGENT_LIST, evidence=ev))

    dated = ""
    if check_date:
        try:
            import datetime as dt
            dated = f" (dated {dt.date.fromisoformat(check_date).strftime('%d-%m-%y')})"
        except ValueError:
            dated = ""
    facts.append(Fact("swp.inventory.deployed", c.total,
                      f"{c.total} Agents{dated}\nCritical: {crit}\nWarning: {warn}\nManaged: {managed}",
                      Source.AGENT_LIST, evidence=ev))
    facts.append(Fact("swp.inventory.status_health", crit + warn,
                      f"Managed: {managed}, Warning: {warn}, Critical: {crit}", Source.AGENT_LIST, evidence=ev))

    cs = c.component_status
    up, out, unk = cs.get("Up-to-Date", 0), cs.get("Out-of-Date", 0), cs.get("Unknown", 0)
    m.update(up_to_date=up, out_of_date=out, update_unknown=unk)
    facts.append(Fact("swp.inventory.component_status", out + unk,
                      f"Up-to-date - {up}\nOut-of-Date - {out}\nUnknown: {unk}", Source.AGENT_LIST, evidence=ev))

    pol = c.policies
    m["without_policy"] = pol.get("None", 0)
    m["policy_counts"] = dict(pol)
    facts.append(Fact("swp.inventory.without_policy", pol.get("None", 0),
                      f"{pol.get('None', 0)} computers without policy", Source.AGENT_LIST, evidence=ev))
    m["platform_counts"] = c.platforms.most_common()

    # module state per reviewed policy (what the agents actually run)
    for name in pol:
        scope = policy_scope(name)
        if not scope:
            continue
        m[f"{scope}_policy_name"] = name
        m[f"{scope}_computers"] = pol[name]
        for mod in MODULE_COLUMNS:
            st = c.module_state(name, mod)
            if st is None:
                continue
            on = st.lower().startswith("on")
            facts.append(Fact(f"{scope}.mod.{mod}", on, f"Licensed | {'Enabled' if on else 'Disabled'}",
                              Source.AGENT_LIST, evidence=f"{ev}: {st}"))
            facts.append(Fact(f"{scope}.state.{mod}", on, "Enabled" if on else "Disabled",
                              Source.AGENT_LIST, evidence=f"{ev}: {st}"))
            if mod == "ips" and on:
                beh = "Prevent" if "prevent" in st.lower() else ("Detect" if "detect" in st.lower() else "")
                if beh:
                    facts.append(Fact(f"{scope}.ips.behavior", beh, beh, Source.AGENT_LIST, evidence=f"{ev}: {st}"))
    return facts, m, c


# --------------------------------------------------------------------------
# policy XML exports
# --------------------------------------------------------------------------
ACTION_CODES = {1: "Pass", 2: "Delete", 3: "Quarantine", 4: "Clean", 5: "Deny Access", 6: "Terminate"}
CPU_CODES = {"L": "Low", "M": "Medium", "H": "High", "U": "Unlimited"}


def _bool(t: Optional[str]) -> Optional[bool]:
    if t is None:
        return None
    t = t.strip().lower()
    return True if t == "true" else False if t == "false" else None


def policy_facts(path: Path) -> tuple[list[Fact], dict[str, Any]]:
    """Facts from one policy export. Only values set on the policy itself."""
    root = ET.parse(path).getroot()
    sp = root.find("SecurityProfiles/SecurityProfile")
    if sp is None:
        return [], {}
    name = (sp.findtext("Name") or "").strip()
    scope = policy_scope(name)
    if not scope:
        return [], {"ignored_policy": name}
    ev = f"{path.name}"
    facts = [Fact(f"{scope}.name", name, name, Source.POLICY_EXPORT, evidence=ev)]
    settings = {s.get("name", "").split(":")[-1]: s.get("value") for s in root.iter("Setting") if s.get("name")}

    hard = _bool(settings.get("settings.configuration.agentHardening"))
    if hard is not None:
        facts.append(Fact(f"{scope}.self_protection", hard, "Enabled" if hard else "Disabled",
                          Source.POLICY_EXPORT, evidence=f"{ev}: agentHardening={hard}"))
    cpu = settings.get("settings.configuration.agentCpuUsage")
    if cpu in CPU_CODES:
        facts.append(Fact(f"{scope}.cpu_control", CPU_CODES[cpu], CPU_CODES[cpu], Source.POLICY_EXPORT,
                          evidence=f"{ev}: agentCpuUsage={cpu}"))

    # rules assigned on this policy
    li = len(list(root.iter("SecurityProfileLogInspectionRule")))
    im = len(list(root.iter("SecurityProfileIntegrityRule")))
    fw = len(list(root.iter("SecurityProfilePacketFilter")))
    for key, n, label in (("li.rules", li, "Log Inspection"), ("im.rules", im, "Integrity Monitoring"),
                          ("fw.rules", fw, "Firewall")):
        facts.append(Fact(f"{scope}.{key}", n, f"Configured ({n} rules)" if n else "Not Configured",
                          Source.POLICY_EXPORT, evidence=f"{ev}: {n} {label} rules assigned"))

    # malware scan configurations exported with the policy
    bridge = next(iter(root.iter("SecurityProfileAntiMalware")), None)
    role = {}
    if bridge is not None:
        for tag, which in (("RealTime1_AntiMalwareID", "rt"), ("Scheduled_AntiMalwareID", "sched"),
                           ("Manual_AntiMalwareID", "manual")):
            v = bridge.findtext(tag)
            if v and v.strip().isdigit():
                role[v.strip()] = which
    for am in root.iter("AntiMalware"):
        which = role.get(am.get("id", ""))
        if not which:
            continue
        cfg = (am.findtext("Name") or "").strip()
        e = f"{ev}: {cfg}"

        def add(k, val, disp):
            facts.append(Fact(f"swp.{which}.{k}", val, disp, Source.POLICY_EXPORT, evidence=e))

        for k, tag in (("dim", "DynamicIntelligenceMode"), ("pml", "TrendxScanEnabled"),
                       ("bm", "SuspiciousActivityDetection"), ("amsi", "AmsiScriptScanEnabled"),
                       ("spyware", "SpywareEnabled"), ("intellitrap", "IntelliTrapeEnabled"),
                       ("pms", "RealtimeMemoryScan"), ("compressed", "ScanCompressed"), ("ole", "ScanOLE")):
            b = _bool(am.findtext(tag))
            if b is not None:
                add(k, b, "Enabled" if b else "Disabled")
        for k, tag in (("pml_action", "ScanActionForTrendX"), ("bm_action", "ScanActionForBM")):
            v = am.findtext(tag)
            if v and v.strip().isdigit() and int(v) in ACTION_CODES:
                add(k, ACTION_CODES[int(v)], ACTION_CODES[int(v)])
        excl = [am.findtext(t) for t in ("ExcludedScanDirList", "ExcludedScanFileList", "ExcludedScanFileExtList")]
        if any(x is not None for x in excl):
            for k, x in zip(("excl_dir", "excl_file", "excl_ext"), excl):
                add(k, bool(x and x.strip()), "Enabled" if x and x.strip() else "Disabled")
    return facts, {f"{scope}_policy_export": name}


# --------------------------------------------------------------------------
# event exports (efficacy presentation)
# --------------------------------------------------------------------------
def read_events(path: Path) -> list[dict]:
    return _read_csv(path)


def find_export(folder: Path, *patterns: str) -> Optional[Path]:
    for pat in patterns:
        hits = sorted(p for p in folder.rglob("*") if p.is_file() and re.search(pat, p.name, re.I))
        if hits:
            return hits[0]
    return None


def exclusion_list_facts(folder: Path) -> list[Fact]:
    """Scan-exclusion common objects (directory / file / extension lists)."""
    facts = []
    for pat, key in ((r"Directory_Lists?\.csv$", "swp.lists.directories"), (r"^File_Lists?\.csv$", "swp.lists.files"),
                     (r"File_Extension_Lists?\.csv$", "swp.lists.extensions")):
        p = find_export(folder, pat)
        if not p:
            continue
        rows = _read_csv(p)
        names = [r.get("Name", "") for r in rows]
        facts.append(Fact(key, names, f"{len(rows)} lists", Source.EXCLUSION_CSV, evidence=p.name))
    return facts


RISKY_EXTENSIONS = {"bat", "bin", "cab", "com", "dll", "exe", "gz", "hta", "jar", "jpeg", "jpg", "js", "ocx",
                    "rar", "reg", "scr", "sys", "tar", "vbe", "vbs", "wsf", "zip"}


def risky_extension_exclusions(folder: Path) -> list[str]:
    """Executable/archive extensions found in the File Extension Lists (common objects).

    These lists are what scan exclusions point to; an executable or archive
    extension in them lets malware of that type skip scanning.
    """
    p = find_export(folder, r"File_Extension_Lists?\.csv$")
    if not p:
        return []
    found = set()
    for r in _read_csv(p):
        for ext in re.split(r"[,\s;]+", r.get("File Extension(s)", "") or ""):
            e = ext.strip(" .").lower()
            if e in RISKY_EXTENSIONS:
                found.add(e)
    return sorted(found)
