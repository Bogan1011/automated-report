"""Combined / derived values for the Server & Workload Protection report.

Run after every source (exports, screenshots, checklist) has been loaded and
before the rule pack is evaluated. Nothing here invents a setting: each
derived fact restates facts that were observed, in the wording of the
manual reports ("Enabled (Quarantine)", "Valid till 09-04-2028", "N/A" for
the options of a module that is switched off).
"""
from __future__ import annotations

import datetime as dt

from ..models import Fact, HealthCheck, Source


def _add(hc: HealthCheck, key: str, value, display: str, like: Fact, note: str) -> None:
    hc.add_fact(Fact(key=key, value=value, display=display, source=like.source,
                     confidence=like.confidence, evidence=f"derived: {note}"))


def derive(hc: HealthCheck) -> None:
    f = hc.get
    m = hc.metrics

    exp = f("license.expiry")
    if exp:
        try:
            d = dt.date.fromisoformat(str(exp.value))
            _add(hc, "swp.license_valid", exp.value, f"Valid till {d.strftime('%d-%m-%Y')}", exp, "license.expiry")
            m["license_valid_long"] = d.strftime("%d %B %Y")         # 09 April 2028
            m["license_valid_us"] = d.strftime("%B %d, %Y")          # April 09, 2028
        except ValueError:
            pass
    seats = f("license.seats")
    if seats:
        m["license_seats"] = seats.value

    # executive-summary / gap wording
    total, outdated = m.get("deployed_agents"), m.get("outdated_agents")
    if total and outdated is not None:
        m["outdated_subject"] = "All agents are" if outdated == total else f"{outdated} agents are"

    for c in ("rt", "sched", "manual"):
        excl = [f(f"swp.{c}.excl_{k}") for k in ("dir", "file", "ext")]
        seen = [x for x in excl if x is not None]
        if seen:
            on = any(bool(x.value) for x in seen)
            _add(hc, f"swp.{c}.exclusions", on, "Configured" if on else "Not Configured", seen[0],
                 f"swp.{c}.excl_*")
        for what in ("pml", "bm"):
            st, act = f(f"swp.{c}.{what}"), f(f"swp.{c}.{what}_action")
            if st is not None:
                txt = st.display if not (act and st.value) else f"{st.display} ({act.display})"
                _add(hc, f"swp.{c}.{what}_display", st.value, txt, st, f"swp.{c}.{what}(+action)")

    for p in ("win", "lin"):
        # options of a module that is off do not apply
        for mod, keys in (("dc", ("dc.protocols", "dc.exceptions")), ("ac", ("ac.enforcement", "ac.trust")),
                          ("fw", ("fw.custom",))):
            st = f(f"{p}.state.{mod}")
            if st is not None and not st.value:
                for k in keys:
                    if f(f"{p}.{k}") is None:
                        _add(hc, f"{p}.{k}", None, "N/A", st, f"{p}.state.{mod} is off")
        fw = f(f"{p}.fw.rules")
        st = f(f"{p}.state.fw")
        if fw is not None and st is not None and st.value and f(f"{p}.fw.custom") is None:
            _add(hc, f"{p}.fw.custom", fw.value, fw.display, fw, f"{p}.fw.rules")
        tin, tout = f(f"{p}.ips.tls_inbound"), f(f"{p}.ips.tls_outbound")
        if tin is not None or tout is not None:
            vals = [x for x in (tin, tout) if x is not None]
            on = any(bool(x.value) for x in vals)
            _add(hc, f"{p}.ips.tls", on, "Yes" if on else "No", vals[0], "inbound/outbound TLS inspection")
        for mod in ("im", "li"):
            rules = f(f"{p}.{mod}.rules")
            if rules is None:
                continue
            st = f(f"{p}.state.{mod}")
            if st is not None and not st.value:
                _add(hc, f"{p}.{mod}.rules", None, "N/A", st, f"{p}.state.{mod} is off")
