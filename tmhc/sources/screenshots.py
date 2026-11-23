"""Read console screenshots (pasted into a Word file) with a vision model.

Workflow
--------
1. ``extract_images`` walks the screenshot .docx in order and pairs every
   picture with the most recent text label above it ("License", "Realtime
   RT", "Schedule update", ...). Those labels are what the analyst already
   types during the Teams session, so they become hints, not requirements.
2. For each picture a vision model is asked for the values of a known list
   of fields (derived from the rule pack) and answers in JSON.
3. Every answer is cached on disk, keyed by the picture's SHA-1. Re-running
   costs nothing, and the analyst can open the cache JSON, correct a value
   and re-render.

Where the model runs (``reader`` option):

* ``local`` (default) - a vision model served by Ollama on THIS machine.
  Screenshots never leave the computer. The host must be localhost; any
  other address is refused unless ``allow_remote_host`` is set (e.g. a GPU
  box on the office LAN that you control).
* ``cloud`` - Anthropic's API. Refused unless the profile also sets
  ``allow_cloud: true``, so client data cannot go to the cloud by accident.

Screenshots whose fields are already proved by a structured export (the
.cmpolicy file) are skipped by default, which removes about half the work.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional
from xml.etree import ElementTree as ET

from ..models import Fact, Source

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
R_EMBED = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}embed"
R_ID = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"

DEFAULT_CLOUD_MODEL = os.environ.get("TMHC_CLOUD_MODEL", "claude-sonnet-5-5")
DEFAULT_LOCAL_MODEL = os.environ.get("TMHC_LOCAL_MODEL", "qwen2.5vl:7b")
DEFAULT_LOCAL_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
DEFAULT_MODEL = DEFAULT_LOCAL_MODEL  # backwards-compatible name
LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


class CloudNotAllowed(RuntimeError):
    pass


class LocalModelUnavailable(RuntimeError):
    pass


# --------------------------------------------------------------------------
# 1. pull pictures out of the evidence docx
# --------------------------------------------------------------------------
@dataclass
class Shot:
    index: int
    section: str        # label typed above the picture, e.g. "Realtime RT"
    filename: str       # media/imageN.png inside the docx
    data: bytes

    @property
    def sha1(self) -> str:
        return hashlib.sha1(self.data).hexdigest()

    @property
    def media_type(self) -> str:
        ext = Path(self.filename).suffix.lower()
        return {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
                ".webp": "image/webp"}.get(ext, "image/png")


def extract_images(docx_path: str | Path) -> list[Shot]:
    z = zipfile.ZipFile(docx_path)
    rels_xml = z.read("word/_rels/document.xml.rels").decode("utf-8")
    rels = dict(re.findall(r'Id="([^"]+)"[^>]*?Target="([^"]+)"', rels_xml))
    rels.update({k: v for v, k in re.findall(r'Target="([^"]+)"[^>]*?Id="([^"]+)"', rels_xml)})
    body = ET.fromstring(z.read("word/document.xml")).find(W + "body")

    shots: list[Shot] = []
    label = ""
    for p in body.iter(W + "p"):
        text = "".join(t.text or "" for t in p.iter(W + "t")).strip()
        rids = [b.get(R_EMBED) for b in p.iter() if b.tag.endswith("}blip") and b.get(R_EMBED)]
        rids += [b.get(R_ID) for b in p.iter() if b.tag.endswith("}imagedata") and b.get(R_ID)]
        if text and not rids:
            label = text
        elif text and rids:
            # caption on the same line as the picture ("PML" + image)
            label = text if len(text) < 60 else label
        for rid in rids:
            target = rels.get(rid)
            if not target:
                continue
            name = "word/" + target.lstrip("/") if not target.startswith("word/") else target
            name = name.replace("word/../", "")
            try:
                data = z.read(name)
            except KeyError:
                continue
            shots.append(Shot(len(shots) + 1, label, target, data))
    return shots


# --------------------------------------------------------------------------
# 2. which fields to ask about
# --------------------------------------------------------------------------
# Section label typed by the analyst -> fact-key prefixes to ask about.
# Matching is case-insensitive on whole words; unmatched labels get every
# field that is still missing.
SECTION_HINTS: list[tuple[str, list[str]]] = [
    (r"\blicen[cs]e\b", ["license."]),
    (r"\bmfa\b", ["platform.mfa"]),
    (r"\bsg\b|service gateway", ["platform.service_gateway"]),
    (r"endpoint inventory", ["inventory.", "platform."]),
    (r"inactive", ["admin.inactive_agent_removal"]),
    (r"\bvcp\b|version control", ["platform.version_control"]),
    (r"agent update|manual update", ["global.agent_update", "global.ua_"]),
    (r"\bsps\b|smart protection", ["global.smart_protection", "global.wrs_frs", "global.sps_proxy"]),
    (r"agent notification|global agent|agent setting", ["global."]),
    (r"suspicious object", ["global.so_", "admin.so_sync"]),
    (r"schedule update", ["admin.schedule_update", "admin.deployment_plan"]),
    (r"\bad\b|active directory", ["admin.ad_sync"]),
    (r"\bapi\b", ["platform.api_keys"]),
    (r"syslog", ["admin.syslog"]),
    (r"log maintenance", ["platform.log_maintenance"]),
    (r"event notification", ["admin.event_notifications"]),
    (r"managed product", ["platform.managed_products"]),
    (r"^policy$|policy management", ["admin.policy_count"]),
    (r"scan method", ["policy.scan_method", "policy.dynamic", "policy.monitoring"]),
    (r"real ?time|\brt\b", ["policy.realtime."]),
    (r"schedule scan|scheduled scan", ["policy.scheduled."]),
    (r"manual scan", ["policy.manual."]),
    (r"scan now|\bsn\b", ["policy.scannow."]),
    (r"\bbm\b|behavio", ["policy.bm.", "policy.pml."]),
    (r"\bpml\b|machine learning", ["policy.pml."]),
    (r"web reputation|\bwr\b", ["policy.wr."]),
    (r"suspicious connection", ["policy.sc."]),
    (r"\bvp\b|vulnerab", ["policy.vp."]),
    (r"\bdc\b|device control", ["policy.dc."]),
    (r"app(lication)? control", ["policy.ac."]),
    (r"exception", ["policy.exceptions."]),
    (r"privilege", ["policy.priv.", "policy.update_agent"]),
    (r"additional service", ["policy.svc."]),
]

# Fields that are not report rows but are useful facts.
EXTRA_FIELDS: dict[str, dict] = {
    "license.expiry": {"label": "License expiration date of the endpoint security licence", "type": "date"},
    "license.seats": {"label": "Licensed seat count (Units) of the endpoint security licence", "type": "int"},
    "license.name": {"label": "Licence product name(s)", "type": "text"},
    "inventory.mac_agents": {"label": "Number of Mac agents (online/offline/total) shown on any dashboard", "type": "text"},
    "platform.mfa": {"label": "Is multi-factor authentication enforced for console accounts?", "type": "bool"},
    "platform.service_gateway": {"label": "Service Gateway appliance(s): name, status, version", "type": "text"},
    "platform.version_control": {"label": "Agent/pattern update policy shown in Version Control Policies (e.g. 'n-1', 'n (latest)')", "type": "text"},
    "platform.api_keys": {"label": "API keys configured and their status", "type": "text"},
    "platform.log_maintenance": {"label": "Log retention / maintenance settings", "type": "text"},
    "platform.managed_products": {"label": "Managed products listed and their connection status", "type": "text"},
}

# Report values whose rule check compares against an internal code. The
# vision model must answer with these codes.
CODE_VOCAB: dict[str, list[str]] = {
    "policy.scan_method": ["smart", "conventional"],
    "files_to_scan": ["all", "intelliscan", "extlist"],
    "action_mode": ["specific", "activeaction"],
    "advanced_malware_detection": ["customised", "activeaction"],
}


def field_catalogue(rules: dict) -> dict[str, dict]:
    """Every fact key the rule pack consumes, with a plain description."""
    cat: dict[str, dict] = {}

    def check_type(check: Any) -> tuple[str, Optional[list]]:
        kind = check if isinstance(check, str) else next(iter(check)) if check else "info"
        arg = None if isinstance(check, str) else check.get(kind) if check else None
        if kind in ("enabled", "disabled"):
            return "bool", None
        if kind == "first_enabled":
            return "desktop_server", None
        if kind in ("zero", "lte", "gte", "seats_cover"):
            return "int", None
        if kind == "date_future":
            return "date", None
        # equals/in arguments are the *passing* values, not the only possible
        # answers, so they must never be presented to the model as a closed list.
        return "text", None

    def add(rule: dict, prefix: Optional[str] = None, block: Optional[str] = None,
            heading: str = "") -> None:
        key = rule.get("key")
        if not key or key == "_always" or key.startswith("inventory.") or key.startswith("logs."):
            return
        if prefix:
            key = key.replace("{p}", prefix)
        typ, vocab = check_type(rule.get("check", "info"))
        for suffix, codes in CODE_VOCAB.items():
            if key.endswith(suffix):
                vocab = codes
        label = " - ".join(x for x in (block, rule.get("group"), rule.get("component"),
                                       rule.get("sub"), rule.get("recommended")) if x)
        chk = rule.get("check")
        suggest: list[str] = []
        if isinstance(chk, dict):
            arg = next(iter(chk.values()))
            suggest = [str(a) for a in (arg if isinstance(arg, list) else [arg])
                       if isinstance(a, (str, int)) and str(a) not in ("smart", "all", "specific", "customised")]
        cat[key] = {"label": label.replace("{p}", ""), "type": typ, "vocab": vocab, "suggest": suggest,
                    "section": (block or heading or "").replace("{policy_name}", "Policy"),
                    "setting": rule.get("component") or rule.get("group") or "",
                    "recommended": rule.get("recommended", "")
                                   if not rule.get("sub") else f"{rule['sub']}: {rule.get('recommended', '')}"}

    for section in ("server", "policy"):
        for g in rules.get(section, {}).get("groups", []) + rules.get(section, {}).get("tail_groups", []):
            for r in g.get("rows", []):
                add(r, heading=g.get("heading", ""))
    pol = rules.get("policy", {})
    for b in pol.get("scan_blocks", []):
        for t in pol.get("scan_template", []):
            if "only" in t and b["prefix"] not in t["only"]:
                continue
            if b["prefix"] in t.get("skip", []):
                continue
            add(t, b["prefix"], b["title"])
    for k, v in EXTRA_FIELDS.items():
        cat.setdefault(k, {**v, "vocab": None, "section": "Platform / licence",
                           "setting": v["label"], "recommended": ""})
    return cat


def fields_for_section(section: str, catalogue: dict[str, dict],
                       wanted: Optional[set[str]] = None) -> dict[str, dict]:
    low = section.lower().strip()
    prefixes: list[str] = []
    for pattern, pre in SECTION_HINTS:
        if re.search(pattern, low):
            prefixes.extend(pre)
    keys = [k for k in catalogue if any(k.startswith(p) for p in prefixes)] if prefixes else list(catalogue)
    if wanted is not None:
        keys = [k for k in keys if k in wanted]
    return {k: catalogue[k] for k in keys}


# --------------------------------------------------------------------------
# 3. the model call
# --------------------------------------------------------------------------
SYSTEM_PROMPT = """You read screenshots of Trend Micro management consoles (Trend Vision One, \
Standard Endpoint Protection / Apex Central, Apex One) captured during a Microsoft Teams \
screen-share, and report configuration values for a security health check.

Rules:
- Read only the console page inside the browser. Ignore the Teams toolbar, participant \
tiles, chat bubbles, cursors, avatars and the Windows taskbar.
- Report a field ONLY if its value is visible in this screenshot. Never infer a value \
from defaults, from other fields, or from what is usually configured. Omit fields you \
cannot see.
- A ticked checkbox or a selected radio button counts as selected even when greyed out \
(read-only view). A toggle switch that is coloured/filled is on; grey is off.
- When a page shows a list of switches (for example notification events), report \
"Enabled" if all are on, "Disabled" if all are off, and "Partially Enabled" otherwise, \
and name the ones that are off in `quote`.
- `confidence` is your probability (0-1) that the value is correct.
- `quote` is the exact on-screen text that supports the value (keep it short).
Answer with JSON only."""

TYPE_HINTS = {
    "bool": 'value: true or false; display: "Enabled" / "Disabled" (or "Not Configured")',
    "desktop_server": 'value: [desktop_on, server_on] booleans; display: '
                      '"Windows Desktop: Enabled Windows Server: Disabled"',
    "int": "value: integer; display: the number as shown",
    "date": "value: ISO date YYYY-MM-DD; display: the date as shown",
    "text": "value and display: the setting as shown on screen",
}


def build_prompt(section: str, fields: dict[str, dict]) -> str:
    lines = []
    for key, spec in fields.items():
        hint = TYPE_HINTS.get(spec["type"], TYPE_HINTS["text"])
        if spec.get("vocab"):
            hint += f"; value MUST be one of {spec['vocab']}"
        lines.append(f'- "{key}": {spec["label"]}  [{hint}]')
    return (
        f'The analyst labelled this screenshot "{section or "unlabelled"}".\n\n'
        "Fields to look for (report only the ones visible):\n" + "\n".join(lines) +
        '\n\nReturn: {"page": "<console page title/breadcrumb>", "fields": '
        '[{"key": "...", "value": ..., "display": "...", "confidence": 0.0, "quote": "..."}]}'
    )


def _parse_json(text: str) -> dict:
    text = text.strip()
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if m:
        text = m.group(1)
    else:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1:
            text = text[start:end + 1]
    return json.loads(text)


def _chunks(fields: dict[str, dict], size: int) -> list[dict[str, dict]]:
    items = list(fields.items())
    return [dict(items[i:i + size]) for i in range(0, len(items), size)] or [{}]


def _clean(result: dict, asked: dict[str, dict]) -> list[dict]:
    """Keep only well-formed answers for fields we actually asked about."""
    out = []
    for f in result.get("fields", []) or []:
        if not isinstance(f, dict) or f.get("key") not in asked:
            continue
        if f.get("value") is None and not f.get("display"):
            continue
        try:
            f["confidence"] = max(0.0, min(1.0, float(f.get("confidence", 0.7))))
        except (TypeError, ValueError):
            f["confidence"] = 0.5
        f.setdefault("display", str(f.get("value")))
        out.append(f)
    return out


class LocalReader:
    """Vision model served by Ollama on this machine. Nothing leaves the computer."""

    name = "local"
    chunk_size = 10   # smaller local models read more accurately with short field lists

    def __init__(self, model: str = DEFAULT_LOCAL_MODEL, host: str = DEFAULT_LOCAL_HOST,
                 allow_remote_host: bool = False, timeout: int = 600):
        from urllib.parse import urlparse
        if "://" not in host:
            host = "http://" + host
        hostname = (urlparse(host).hostname or "").lower()
        if hostname not in LOCAL_HOSTNAMES and not allow_remote_host:
            raise CloudNotAllowed(
                f"Ollama host {host!r} is not this machine. Screenshots would leave the computer. "
                "Use http://127.0.0.1:11434, or set allow_remote_host: true if it is a server you control.")
        self.model, self.host, self.timeout = model, host.rstrip("/"), timeout
        self.label = f"ollama:{model}@{hostname}"

    def check(self) -> None:
        """Fail early with a useful message if Ollama or the model is missing."""
        import urllib.request
        try:
            with urllib.request.urlopen(f"{self.host}/api/tags", timeout=10) as r:
                tags = json.loads(r.read().decode())
        except Exception as exc:
            raise LocalModelUnavailable(
                f"Cannot reach Ollama at {self.host} ({exc}). Install Ollama from ollama.com, "
                f"run `ollama pull {self.model}`, and make sure Ollama is running - "
                "or use the no-AI checklist: `python -m tmhc checklist <profile>`.") from None
        names = {m.get("name", "") for m in tags.get("models", [])}
        base = self.model.split(":")[0]
        if self.model not in names and not any(n.split(":")[0] == base for n in names):
            raise LocalModelUnavailable(
                f"Model {self.model!r} is not installed in Ollama. Run: ollama pull {self.model}")

    def _call(self, shot: Shot, fields: dict[str, dict]) -> dict:
        import urllib.request
        body = {
            "model": self.model, "stream": False, "format": "json",
            "options": {"temperature": 0, "num_ctx": 8192},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_prompt(shot.section, fields),
                 "images": [base64.b64encode(shot.data).decode()]},
            ],
        }
        req = urllib.request.Request(f"{self.host}/api/chat", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            payload = json.loads(r.read().decode())
        return _parse_json(payload.get("message", {}).get("content", "{}"))

    def read(self, shot: Shot, fields: dict[str, dict], retries: int = 2) -> dict:
        page, answers = "", []
        for part in _chunks(fields, self.chunk_size):
            last: Optional[Exception] = None
            for _ in range(retries):
                try:
                    res = self._call(shot, part)
                    page = page or str(res.get("page", ""))
                    answers.extend(_clean(res, part))
                    break
                except Exception as exc:
                    last = exc
            else:
                raise RuntimeError(f"local model failed on {shot.filename}: {last}")
        return {"page": page, "fields": answers}


class CloudReader:
    """Anthropic API. Only constructed when the profile explicitly allows cloud."""

    name = "cloud"
    chunk_size = 60

    def __init__(self, model: str = DEFAULT_CLOUD_MODEL, allow_cloud: bool = False, client: Any = None):
        if not allow_cloud:
            raise CloudNotAllowed(
                "reader 'cloud' sends screenshots to Anthropic's API. Set allow_cloud: true in the "
                "profile options if that is approved for this client; otherwise use reader: local.")
        if client is None:
            import anthropic  # only imported when cloud is explicitly enabled
            client = anthropic.Anthropic()
        self.client, self.model = client, model
        self.label = f"anthropic:{model}"

    def check(self) -> None:
        pass

    def read(self, shot: Shot, fields: dict[str, dict], retries: int = 3) -> dict:
        content = [
            {"type": "image", "source": {"type": "base64", "media_type": shot.media_type,
                                         "data": base64.b64encode(shot.data).decode()}},
            {"type": "text", "text": build_prompt(shot.section, fields)},
        ]
        last: Optional[Exception] = None
        for attempt in range(retries):
            try:
                resp = self.client.messages.create(
                    model=self.model, max_tokens=4000, system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": content}])
                text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
                res = _parse_json(text)
                return {"page": res.get("page", ""), "fields": _clean(res, fields)}
            except json.JSONDecodeError as exc:
                last = exc
            except Exception as exc:  # rate limit / overload
                last = exc
                time.sleep(2 ** attempt * 3)
        raise RuntimeError(f"cloud call failed for {shot.filename}: {last}")


def make_reader(opts: dict):
    """Build the reader named in the profile options. Defaults to local."""
    kind = str(opts.get("reader", "local")).lower()
    if kind == "local":
        return LocalReader(model=opts.get("local_model", DEFAULT_LOCAL_MODEL),
                           host=opts.get("ollama_host", DEFAULT_LOCAL_HOST),
                           allow_remote_host=bool(opts.get("allow_remote_host", False)),
                           timeout=int(opts.get("local_timeout", 600)))
    if kind == "cloud":
        return CloudReader(model=opts.get("cloud_model", DEFAULT_CLOUD_MODEL),
                           allow_cloud=bool(opts.get("allow_cloud", False)))
    raise ValueError(f"unknown reader {kind!r}: use 'local' or 'cloud' "
                     "(or skip screenshots and use `tmhc checklist`)")


# --------------------------------------------------------------------------
# 4. cache + conversion to facts
# --------------------------------------------------------------------------
class ShotCache:
    """JSON file holding every model answer, keyed by image hash."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.data: dict = {"version": 1, "images": {}}
        if self.path.exists():
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
            self.data.setdefault("images", {})

    def get(self, sha1: str) -> Optional[dict]:
        return self.data["images"].get(sha1)

    def put(self, shot: Shot, result: dict, model: str) -> None:
        self.data["images"][shot.sha1] = {
            "index": shot.index, "file": shot.filename, "section": shot.section,
            "model": model, "page": result.get("page", ""), "fields": result.get("fields", []),
        }

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")

    def facts(self, min_confidence: float = 0.6) -> list[Fact]:
        out = []
        for entry in self.data["images"].values():
            for f in entry.get("fields", []):
                if "key" not in f:
                    continue
                conf = float(f.get("confidence", 0.8))
                if conf < min_confidence:
                    continue
                value = f.get("value")
                if isinstance(value, list):
                    value = tuple(value)
                out.append(Fact(
                    key=f["key"], value=value, display=str(f.get("display", value)),
                    source=Source.SCREENSHOT, confidence=conf,
                    evidence=f"{entry.get('file')} ({entry.get('section')})"
                             + (f": {f['quote']}" if f.get("quote") else ""),
                ))
        return out


def run(docx_path: str | Path, rules: dict, cache_path: str | Path,
        covered_keys: Iterable[str] = (), reader: Any = None,
        skip_covered: bool = True, dry_run: bool = False,
        progress=print) -> tuple[list[Fact], ShotCache]:
    """Read every screenshot not already in the cache and return facts.

    ``reader`` is a LocalReader / CloudReader (see ``make_reader``). It is
    only required when there is something left to read.
    """
    catalogue = field_catalogue(rules)
    covered = set(covered_keys)
    wanted = {k for k in catalogue if k not in covered} if skip_covered else set(catalogue)
    cache = ShotCache(cache_path)
    shots = extract_images(docx_path)
    todo = []
    for shot in shots:
        if cache.get(shot.sha1):
            continue
        fields = fields_for_section(shot.section, catalogue, wanted)
        if not fields:
            continue
        todo.append((shot, fields))

    progress(f"{len(shots)} screenshots, {len(shots) - len(todo)} cached or already covered, "
             f"{len(todo)} to read")
    if dry_run:
        for shot, fields in todo:
            progress(f"  would read #{shot.index} {shot.filename} [{shot.section}] "
                     f"-> {len(fields)} fields")
        return cache.facts(), cache

    if todo:
        if reader is None:
            raise ValueError("screenshots need reading but no reader was configured")
        reader.check()
        progress(f"reading with {reader.label}")
    for n, (shot, fields) in enumerate(todo, 1):
        progress(f"  [{n}/{len(todo)}] {shot.filename} [{shot.section}] ({len(fields)} fields)")
        result = reader.read(shot, fields)
        cache.put(shot, result, reader.label)
        cache.save()  # save as we go so an interrupted run loses nothing
    return cache.facts(), cache
