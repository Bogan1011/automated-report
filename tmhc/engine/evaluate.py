"""Compare collected facts with the rule pack and build report rows and gaps."""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any, Optional

import yaml

from ..models import Fact, Gap, HealthCheck, ReportRow, Status

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
NOT_CAPTURED = "Not captured"


def load_rules(name: str = "apexone_sep") -> dict:
    path = Path(name)
    if not path.exists():
        path = RULES_DIR / f"{name}.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# text helpers
# --------------------------------------------------------------------------

def _fmt(text: Optional[str], hc: HealthCheck, deployed: str = "", extra: dict | None = None) -> str:
    if not text:
        return ""
    ctx = {"deployed": deployed, "deployed_lower": deployed.lower(), "policy_name": hc.policy_name or "Policy"}
    ctx.update(extra or {})

    def sub(match: re.Match) -> str:
        token = match.group(1)
        if token.startswith("m."):
            val = hc.metrics.get(token[2:])
            return str(val) if val not in (None, "") else "N/A"
        if token.startswith("f."):
            f = hc.get(token[2:])
            return f.display if f else "N/A"
        return str(ctx[token]) if token in ctx else match.group(0)

    # one pass, so braces inside substituted values are never re-interpreted
    return re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_.]*)\}", sub, text)


def _norm(v: Any) -> str:
    return re.sub(r"\s+", " ", str(v)).strip().lower()


def _truthy(v: Any) -> bool:
    if isinstance(v, (tuple, list)):
        return bool(v) and all(_truthy(x) for x in v)
    if isinstance(v, str):
        return _norm(v) in {"1", "true", "yes", "on", "enabled", "enable",
                            "subscribed", "configured"}
    return bool(v)


def _to_date(v: Any) -> Optional[dt.date]:
    if isinstance(v, dt.date):
        return v
    s = str(v).strip()
    for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%d %B %Y", "%d %b %Y", "%B %d, %Y"):
        try:
            return dt.datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


# --------------------------------------------------------------------------
# checks
# --------------------------------------------------------------------------
def run_check(check: Any, fact: Fact, hc: HealthCheck) -> Optional[bool]:
    """True = meets baseline, False = gap, None = informational / undecidable."""
    v, d = fact.value, fact.display
    if isinstance(check, str):
        kind, arg = check, None
    elif isinstance(check, dict) and check:
        kind, arg = next(iter(check.items()))
    else:
        return None

    if kind == "info":
        return None
    if kind == "enabled":
        return _truthy(v)
    if kind == "disabled":
        return not _truthy(v)
    if kind == "none_enabled":
        vals = v if isinstance(v, (tuple, list)) else [v]
        return not any(_truthy(x) for x in vals)
    if kind == "first_enabled":
        return _truthy(v[0]) if isinstance(v, (tuple, list)) and v else _truthy(v)
    if kind == "equals":
        return _norm(v) == _norm(arg) or _norm(d) == _norm(arg)
    if kind == "in":
        opts = {_norm(a) for a in arg}
        return _norm(v) in opts or _norm(d) in opts
    if kind == "not_in":
        opts = {_norm(a) for a in arg}
        return not (_norm(v) in opts or _norm(d) in opts)
    if kind == "contains":
        opts = arg if isinstance(arg, list) else [arg]
        return any(_norm(a) in _norm(d) or _norm(a) in _norm(v) for a in opts)
    if kind in ("lte", "gte"):
        try:
            n = float(v)
        except (TypeError, ValueError):
            return None
        return n <= float(arg) if kind == "lte" else n >= float(arg)
    if kind == "zero":
        try:
            return int(v) == 0
        except (TypeError, ValueError):
            return None
    if kind == "configured":
        return _norm(d).startswith("configured")
    if kind == "date_future":
        exp = _to_date(v)
        ref = _to_date(hc.check_date) or dt.date.today()
        return None if exp is None else exp > ref
    if kind == "offline_ratio":
        try:
            online, offline = v
            total = online + offline
            return total == 0 or offline / total <= float(arg)
        except (TypeError, ValueError):
            return None
    if kind == "seats_cover":
        seats = hc.metrics.get("license_seats")
        try:
            return int(seats) >= int(v)
        except (TypeError, ValueError):
            return None
    raise ValueError(f"unknown check type {kind!r}")


def _status(word: Optional[str], default: Status) -> Status:
    return Status(word) if word else default


# --------------------------------------------------------------------------
# row evaluation
# --------------------------------------------------------------------------
class _Builder:
    def __init__(self, hc: HealthCheck):
        self.hc = hc
        self.shared: dict[str, list[str]] = {}
        self.shared_gaps: dict[str, Gap] = {}

    def evaluate(self, rule: dict, section: str, scope: str,
                 extra: dict | None = None) -> Optional[ReportRow]:
        hc = self.hc
        key = rule.get("key")
        fact = hc.get(key) if key and key != "_always" else None
        disp_fact = hc.get(rule["display_key"]) if rule.get("display_key") else fact

        recommended = _fmt(rule.get("recommended", ""), hc, extra=extra)
        component = _fmt(rule.get("component", ""), hc, extra=extra)
        group_label = _fmt(rule.get("group"), hc, extra=extra) or None
        if rule.get("sub"):
            # "Schedule Update" spans rows; each row names its sub-setting.
            group_label = component
            recommended = f"{rule['sub']}: {recommended}"
            component = ""

        if key == "_always":
            result: Optional[bool] = None
            deployed = ""
            status = Status.INFO
        elif fact is None:
            result = None
            deployed = NOT_CAPTURED
            status = Status.UNKNOWN
            hc.warnings.append(f"No data for {key} ({component or recommended})")
        else:
            deployed = (disp_fact or fact).display
            result = run_check(rule.get("check", "info"), fact, hc)
            if result is True:
                status = _status(rule.get("pass"), Status.GOOD)
            elif result is False:
                status = _status(rule.get("fail"), Status.CONCERN)
            else:
                status = Status.INFO

        # ---- executive-summary bullet -------------------------------------
        if result is False and rule.get("summary"):
            summ = rule["summary"]
            if isinstance(summ, dict):              # wording per deployed value
                summ = summ.get(deployed.strip().lower(), summ.get("_default", ""))
            line = _fmt(summ, hc, deployed=deployed, extra=extra)
            if line not in hc.summaries:
                hc.summaries.append(line)

        # ---- gaps --------------------------------------------------------
        gap_text = rule.get("gap")
        fire = (result is False) or (rule.get("gap_always") and key == "_always")
        if fire and rule.get("gap_shared"):
            gid = rule["gap_shared"]
            if gid not in self.shared:
                # reserve the slot where the gap first appears; text filled at the end
                self.shared[gid] = []
                self.shared_gaps[gid] = Gap(text="", key=gid, scope=scope)
                (hc.gaps_server if scope == "server" else hc.gaps_policy).append(self.shared_gaps[gid])
            self.shared[gid].append((extra or {}).get("name", ""))
        elif fire and gap_text and (not rule.get("gap_only") or (extra or {}).get("scope") in rule["gap_only"]):
            text = _fmt(gap_text, hc, deployed=deployed, extra=extra)
            gap = Gap(text=text, severity=status if status != Status.INFO else Status.INFO,
                      key=key, scope=scope, rank=int(rule.get("gap_rank", 50)),
                      group=(extra or {}).get("scope", ""))
            if (extra or {}).get("collect") is not None:
                extra["collect"].append((rule.get("_rid"), gap))
            else:
                (hc.gaps_server if scope == "server" else hc.gaps_policy).append(gap)

        if rule.get("show", True) is False:
            return None
        return ReportRow(
            section=section, component=component, recommended=recommended,
            deployed=deployed, status=status, key=key,
            source=fact.source if fact else None,
            evidence=fact.evidence if fact else None,
            group=group_label,
        )


def evaluate(hc: HealthCheck, rules: dict) -> HealthCheck:
    b = _Builder(hc)

    # Promote license seat count into metrics for the seats_cover check.
    seats = hc.get("license.seats")
    if seats is not None:
        hc.metrics["license_seats"] = seats.value
    hc.metrics.setdefault("license_seats", "N/A")

    def run_groups(groups: list, section: str, default_scope: str, rows_out: list):
        for g in groups:
            scope = g.get("scope", default_scope)
            heading = _fmt(g["heading"], hc)
            rows_out.append(ReportRow(section=section, component=heading, recommended="",
                                      deployed="", status=Status.INFO, group="__heading__"))
            for rule in g.get("rows", []):
                row = b.evaluate(rule, heading, scope)
                if row:
                    rows_out.append(row)

    # Server / global table
    srv = rules.get("server", {})
    run_groups(srv.get("groups", []), srv.get("title", "Server"), "server", hc.rows_server)

    # Policy table
    pol = rules.get("policy", {})
    if pol.get("scopes"):
        _evaluate_scoped(hc, b, pol)
        _order_gaps(hc)
        return hc
    run_groups(pol.get("groups", []), pol.get("title", "Policy"), "policy", hc.rows_policy)

    template = pol.get("scan_template", [])
    for block in pol.get("scan_blocks", []):
        prefix = block["prefix"]
        if not any(k.startswith(prefix + ".") for k in hc.facts):
            hc.warnings.append(f"No policy data for {block['title']}")
        hc.rows_policy.append(ReportRow(section=block["title"], component=block["title"],
                                        recommended="", deployed="", status=Status.INFO,
                                        group="__heading__"))
        for tmpl in template:
            if "only" in tmpl and prefix not in tmpl["only"]:
                continue
            if prefix in tmpl.get("skip", []):
                continue
            rule = dict(tmpl)
            rule["key"] = tmpl["key"].replace("{p}", prefix)
            row = b.evaluate(rule, block["title"], "policy", extra={"name": block["name"]})
            if row:
                hc.rows_policy.append(row)

    run_groups(pol.get("tail_groups", []), pol.get("title", "Policy"), "policy", hc.rows_policy)

    # Shared gaps (one line naming every scan block that failed)
    for gid, names in b.shared.items():
        text = pol.get("shared_gaps", {}).get(gid, "")
        joined = ", ".join(names[:-1])
        blocks = f"{joined} and {names[-1]}" if len(names) > 1 else names[0]
        b.shared_gaps[gid].text = text.format(blocks=blocks)
    for lst in (hc.gaps_server, hc.gaps_policy):
        lst[:] = [g for g in lst if g.text]

    _order_gaps(hc)
    return hc


def _evaluate_scoped(hc: HealthCheck, b: "_Builder", pol: dict) -> None:
    """One block of policy rows per reviewed policy (Windows / Linux server ...).

    Row keys with {p} become per-policy keys (win.heartbeat). A gap raised
    for every policy is listed once under "In Both ... Policy"; the others
    under "In <policy> only", in rule order.
    """
    scopes = []
    for sc in pol["scopes"]:
        name = _fmt(sc.get("name", ""), hc)
        if not name or name == "N/A":
            name = hc.facts.get(f"{sc['id']}.name").display if hc.facts.get(f"{sc['id']}.name") else sc.get(
                "default_name", sc["id"])
        scopes.append((sc["id"], name))
    hc.metrics["policy_names"] = [n for _, n in scopes]
    collected: dict[str, list] = {sid: [] for sid, _ in scopes}
    rid = 0
    for sid, name in scopes:
        rid = 0
        for g in pol.get("groups", []):
            if g.get("only") and sid not in g["only"]:
                rid += len(g.get("rows", []))       # keep rule ids aligned across policies
                continue
            heading = _fmt(g["heading"].replace("{name}", name), hc)
            hc.rows_policy.append(ReportRow(section=name, component=heading, recommended="", deployed="",
                                            status=Status.INFO, group="__heading__"))
            for rule in g.get("rows", []):
                rid += 1
                if rule.get("only") and sid not in rule["only"]:
                    continue
                r = dict(rule, _rid=rid)
                for k in ("key", "display_key"):
                    if r.get(k):
                        r[k] = r[k].replace("{p}", sid)
                row = b.evaluate(r, heading, "policy", extra={"name": name, "scope": sid,
                                                               "collect": collected[sid]})
                if row:
                    hc.rows_policy.append(row)
    # merge: same rule failing in every policy -> one "both" gap
    by_rule: dict[int, dict[str, Gap]] = {}
    for sid, items in collected.items():
        for r_id, gap in items:
            by_rule.setdefault(r_id, {})[sid] = gap
    ids = [sid for sid, _ in scopes]
    names = dict(scopes)
    if pol.get("gap_sets"):
        hc.gaps_policy.extend(_gap_sets(pol, by_rule, names, hc))
        return
    both = [g[ids[0]] for r_id, g in sorted(by_rule.items()) if len(ids) > 1 and all(s in g for s in ids)]
    out: list[Gap] = []
    if both:
        joined = " & ".join(names[s] for s in ids)
        out.append(Gap(text=pol.get("both_heading", "In Both {names} Policy").replace("{names}", joined),
                       scope="policy", group="both", heading=True))
        for g in both:
            g.group = "both"
            out.append(g)
    for sid in ids:
        only = [g[sid] for r_id, g in sorted(by_rule.items()) if sid in g and not all(s in g for s in ids)]
        if only:
            out.append(Gap(text=pol.get("only_heading", "In {name} only").replace("{name}", names[sid]),
                           scope="policy", group=sid, heading=True))
            out.extend(only)
    hc.gaps_policy.extend(out)


def _join_names(names: list[str]) -> str:
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def _gap_sets(pol: dict, by_rule: dict, names: dict, hc: HealthCheck) -> list[Gap]:
    """Gap table grouped by sets of policies (CECP: Exchange on its own, then
    SharePoint / OneDrive / Teams together).

    Within a set, a gap raised by every policy of the set is listed once under
    `set_heading` ({names} = the policies joined "A, B and C"); gaps raised by
    only some of them go under `scope_heading` per policy.
    """
    out: list[Gap] = []
    for gs in pol["gap_sets"]:
        ids = [s for s in gs["scopes"] if s in names]
        if not ids:
            continue
        shared = [g[ids[0]] for _, g in sorted(by_rule.items()) if all(s in g for s in ids)]
        if shared:
            joined = _join_names([names[s] for s in ids])
            tmpl = gs.get("set_heading" if len(ids) > 1 else "heading", gs.get("heading", "In {names}:"))
            out.append(Gap(text=_fmt(tmpl.replace("{names}", joined).replace("{name}", joined), hc),
                           scope="policy", group="+".join(ids), heading=True))
            for g in shared:
                g.group = "+".join(ids)
                out.append(g)
        if len(ids) > 1:
            for sid in ids:
                only = [g[sid] for _, g in sorted(by_rule.items()) if sid in g and not all(s in g for s in ids)]
                if only:
                    tmpl = gs.get("heading", "In {name}:")
                    out.append(Gap(text=_fmt(tmpl.replace("{name}", names[sid]).replace("{names}", names[sid]), hc),
                                   scope="policy", group=sid, heading=True))
                    out.extend(only)
    return out


def _order_gaps(hc: HealthCheck) -> None:
    """Keep inventory gaps first, then the rest, as in the existing reports."""
    def rank(g: Gap) -> tuple:
        k = g.key or ""
        if k.startswith("inventory."):
            return (0, g.rank)
        if k == "_always":
            return (1, g.rank)
        if k.startswith("global."):
            return (2, g.rank)
        return (3, g.rank)
    hc.gaps_server.sort(key=rank)


def status_counts(hc: HealthCheck) -> dict[str, int]:
    out: dict[str, int] = {s.value: 0 for s in Status}
    for r in hc.rows_server + hc.rows_policy:
        if r.group != "__heading__":
            out[r.status.value] += 1
    return out
