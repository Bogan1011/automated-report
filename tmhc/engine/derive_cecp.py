"""Combined / derived values for the Cloud Email and Collaboration Protection
(CECP) report.

Run after every source (exports, screenshots, checklist) has been loaded and
before the rule pack is evaluated. Each derived fact restates observed facts
in the wording of the analysts' reports ("Enabled without password",
"Pass (Monitor Only Policy)", "N/A" for the options of a module that is off).
"""
from __future__ import annotations

import datetime as dt

from ..models import Fact, HealthCheck, Source

SERVICES = [("exo", "Exchange Online"), ("odb", "OneDrive"), ("spo", "SharePoint Online"),
            ("teams", "Microsoft Teams")]
COLLAB = ("spo", "odb", "teams")
POLICIES = ("exo",) + COLLAB
DEFAULT_NAMES = {"exo": "Default Exchange Policy ATP",
                 "spo": "Default SharePoint Online Policy ATP (Monitor Only)",
                 "odb": "Default OneDrive Policy ATP (Monitor Only)",
                 "teams": "Default Microsoft Teams Policy ATP (Monitor Only)"}
MONITOR_PASS = "Pass (Monitor Only Policy)"


def _add(hc: HealthCheck, key: str, value, display: str, like: Fact | None, note: str,
         force: bool = False) -> None:
    fact = Fact(key=key, value=value, display=display,
                source=like.source if like else Source.POLICY_INFERRED,
                confidence=like.confidence if like else 0.7, evidence=f"derived: {note}")
    cur = hc.get(key)
    if force and (cur is None or cur.source != Source.MANUAL):
        hc.facts[key] = fact
    else:
        hc.add_fact(fact)


def derive(hc: HealthCheck) -> None:
    f = hc.get
    m = hc.metrics

    exp = f("license.expiry")
    if exp:
        try:
            d = dt.date.fromisoformat(str(exp.value))
            m["license_valid_long"] = d.strftime("%d %b %Y")          # 01 May 2027
        except ValueError:
            pass
    seats = f("license.seats")
    if seats:
        m["license_seats"] = seats.value
    prod = f("license.product")
    m["license_product"] = prod.display if prod else "Email and Collaboration Security"

    # ---- services ------------------------------------------------------------
    on = [(sid, name) for sid, name in SERVICES if f(f"cecp.svc.{sid}") is not None and f(f"cecp.svc.{sid}").value]
    seen = [f(f"cecp.svc.{sid}") for sid, _ in SERVICES if f(f"cecp.svc.{sid}") is not None]
    if seen:
        names = [n for _, n in on]
        _add(hc, "cecp.services", bool(names), ", ".join(names) if names else "None configured", seen[0],
             "service status page")
    elif m.get("services"):
        names = [n for _, n in SERVICES if n in m["services"]]
        _add(hc, "cecp.services", bool(names), ", ".join(names), None, "monthly report PDF")
        on = [(sid, n) for sid, n in SERVICES if n in names]
    m["services_list"] = [n for _, n in on]
    m["services_sentence"] = _join_bold([n for _, n in on])

    # ---- global lists ----------------------------------------------------------
    lists = [x for x in (f("cecp.lists.approved_header"), f("cecp.lists.blocked")) if x is not None]
    if lists:
        any_on = any(bool(x.value) for x in lists)
        _add(hc, "cecp.lists", any_on, "Configured" if any_on else "Not configured", lists[0], "approved/blocked lists")
    pwd, rules = f("cecp.pwd_guess"), f("cecp.pwd_rules")
    if pwd is not None:
        if not pwd.value:
            txt = "Disabled"
        elif rules is not None and rules.value:
            txt = "Enabled with password rules"
        else:
            txt = "Enabled without password"
        _add(hc, "cecp.pwd_display", pwd.value, txt, pwd, "attachment password guessing")

    # ---- DLP ---------------------------------------------------------------------
    dlp = {k: f(f"cecp.dlp.{k}") for k in ("exo", "collab")}
    for k, x in dlp.items():
        if x is not None:
            enabled = str(x.value).lower() in ("enabled", "partially enabled", "true")
            m[f"dlp_{k}_line"] = ("Policy is enabled for Data Loss Prevention." if enabled else
                                  ("Policy is not enabled for all users of Data Loss Prevention." if k == "exo"
                                   else "Policy is not enabled for Data Loss Prevention."))
    seen = [x for x in dlp.values() if x is not None]
    if seen:
        any_on = any(str(x.value).lower() in ("enabled", "partially enabled", "true") for x in seen)
        _add(hc, "cecp.dlp_any", any_on, "Enabled" if any_on else "Disabled", seen[0], "DLP policy lists")
    m.setdefault("dlp_exo_line", "Policy is not enabled for all users of Data Loss Prevention.")
    m.setdefault("dlp_collab_line", "Policy is not enabled for Data Loss Prevention.")

    # ---- per policy ------------------------------------------------------------------
    for p in POLICIES:
        name = f(f"{p}.name")
        if name is not None:
            txt = name.display.strip()
            if txt.count("(") > txt.count(")"):
                txt += ")"                                     # OCR clean-up drops the last bracket
            _add(hc, f"{p}.name", txt, txt, name, "policy name", force=True)
        m[f"{p}_policy_name"] = f(f"{p}.name").display if f(f"{p}.name") else DEFAULT_NAMES[p]

        # options of a module that is off do not apply
        fb = f(f"{p}.fb")
        if fb is not None and not fb.value:
            for k in ("fb.apply", "fb.type", "fb.action"):
                _add(hc, f"{p}.{k}", None, "N/A", fb, f"{p}.fb is off", force=True)
        wrs = f(f"{p}.wrs")
        if wrs is not None and not wrs.value:
            for k in ("wrs.apply", "wrs.level", "wrs.exception", "wrs.actions"):
                _add(hc, f"{p}.{k}", None, "N/A", wrs, f"{p}.wrs is off", force=True)
        va = f(f"{p}.va")
        if va is not None and not va.value:
            for k in ("va.monitor", "va.apply", "va.actions"):
                _add(hc, f"{p}.{k}", None, "N/A", va, f"{p}.va is off", force=True)

    for p in COLLAB:
        name, desc = f(f"{p}.name"), f(f"{p}.description")
        monitor = None
        if desc is not None:
            monitor = bool(desc.value)
        if name is not None and "monitor only" in name.display.lower():
            monitor = True
        if monitor is None:
            continue
        like = desc or name
        _add(hc, f"{p}.monitor_only", monitor, "Monitor only" if monitor else "Enforced", like, "policy mode")
        if monitor:
            for k in ("ms.action_state", "wrs.action_state", "va.action_state"):
                _add(hc, f"{p}.{k}", "Pass", MONITOR_PASS, like, "monitor-only policy: actions fixed to Pass")
            if f(f"{p}.va") is not None and f(f"{p}.va").value and f(f"{p}.va.monitor") is None:
                _add(hc, f"{p}.va.monitor", True, "Enabled", like, "monitor-only policy")
        else:
            for k in ("ms.action_state", "wrs.action_state", "va.action_state"):
                _add(hc, f"{p}.{k}", "Configured", "As per policy", like, "enforced policy")

    # ---- Exchange: modules applied to incoming messages only ---------------------------------
    partial = []
    for key, label in (("exo.asp", "Advanced Spam Protection"), ("exo.wrs", "Web Reputation"),
                       ("exo.va", "Virtual Analyzer")):
        mod, apply = f(key), f(f"{key}.apply")
        if mod is not None and mod.value and apply is not None and str(apply.value).lower() != "all":
            partial.append(label)
    any_apply = [f(f"{k}.apply") for k in ("exo.asp", "exo.wrs", "exo.va") if f(f"{k}.apply") is not None]
    if any_apply:
        _add(hc, "exo.apply_all", not partial, "All messages" if not partial else "Incoming only: " + ", ".join(partial),
             any_apply[0], "Apply to of ASP / WRS / VA")
    m["exo_incoming_modules"] = _join_plain(partial)
    m["exo_incoming_modules_bold"] = _join_bold(partial, glue=" and ")
    unsc, size = f("exo.ms.act_unscannable"), f("exo.ms.act_size")
    passing = [x for x in (unsc, size) if x is not None and str(x.value).lower() == "pass"]
    if unsc is not None or size is not None:
        _add(hc, "exo.ms.unscannable_ok", not passing, "Pass" if passing else "Configured", unsc or size,
             "unscannable / oversize actions")


def _join_plain(items: list[str]) -> str:
    if not items:
        return ""
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _join_bold(items: list[str], glue: str = " and ") -> str:
    if not items:
        return ""
    if len(items) == 1:
        return f"**{items[0]}**"
    return "**" + ", ".join(items[:-1]) + "**" + glue + "**" + items[-1] + "**"
