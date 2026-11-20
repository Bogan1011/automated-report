# Trend Micro Health Check Report Generator

Turns the evidence you collect in a customer health-check session into the
finished Word report — same template, same tables, same status icons, same
gap and remediation wording — so the analyst reviews a draft instead of
typing one.

Built and validated against a real Standard Endpoint Protection (Apex One)
engagement: from that evidence pack it reproduced the analyst's report with
the same 11 server-side gaps and 8 policy gaps, and identical counts
(deployed, online/offline, build spread, restart-required, stale patterns,
server-OS agents).

```
 evidence pack                     facts (with source)           report
 ─────────────                     ───────────────────           ──────
 .cmpolicy export   ──parse──┐
 Agent List CSV     ──parse──┤                              ┌─► Word report (.docx)
 V1 log exports     ──parse──┼──► merge by precedence ──► rules ─┤
 Screenshot .docx   ──vision─┤     (export > CSV > screenshot)   └─► review workbook (.xlsx)
 Analyst entries    ─────────┘
```

## Why it is built this way

* **Exports first, screenshots second.** The `.cmpolicy` policy export is
  JSON and contains every policy setting exactly, so ~150 policy rows come
  from it with no OCR at all. The agent-list CSV gives every count. Claude's
  vision model is used only for console pages that have no export (licence,
  administration settings, global agent settings) — about half the
  screenshots, and the cost drops accordingly.
* **Never invents a value.** A setting with no evidence renders as
  *Not captured* with the Unknown icon and raises no gap. The review
  workbook lists those settings with the console page to screenshot next time.
* **The baseline is data, not code.** Every row, its Trend-recommended
  value, how it is judged and the remediation sentence live in
  `tmhc/rules/apexone_sep.yaml`. Change the baseline there.
* **Your template, untouched.** The Word template is made from one of your
  own finished reports, so cover page, styles, intro, Vision One section
  and links are exactly yours. Generated rows are cloned from prototype
  rows in that template, keeping borders, shading and numbering.

## Install

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...      # only needed for reading screenshots
```

## Run a health check

```bash
python -m tmhc init clients/acme/profile.yaml     # starter profile
# put the evidence next to it, edit names/dates/paths in the profile
python -m tmhc run clients/acme/profile.yaml --dry-run   # which screenshots will be read
python -m tmhc run clients/acme/profile.yaml             # build the report
```

Output in `clients/acme/output/`:

| File | Purpose |
|---|---|
| `Acme_SEP_Health_Check_Report_<Mon>_<Year>.docx` | the client report — open in Word and accept the prompt to update the table of contents |
| `..._review.xlsx` | every row with its source and evidence, the gap list, conflicts between sources, and a **Not captured** sheet |
| `screenshot_cache.json` | (next to the profile) every value the vision model read, with the on-screen quote |

### Reviewing and correcting

1. Open the review workbook. Filter **Rows** by *Source = Screenshot* and
   spot-check the quotes in the Evidence column.
2. A wrong screenshot reading: fix the `value`/`display` in
   `screenshot_cache.json`, then `python -m tmhc run profile.yaml --offline`
   (re-renders from the cache, no API calls).
3. A setting you confirmed verbally but have no screenshot for: add it under
   `manual_facts:` in the profile. It wins over every other source and is
   labelled *Analyst entry* in the workbook.

## What to collect in the session

The more that comes from exports, the less is read off pictures.

| Evidence | Where | Feeds |
|---|---|---|
| Policy export (`.cmpolicy`) for the policy under review | SEP › Policies › select policy › Export Settings | all policy-review rows |
| Apex One Security Agent List (CSV) | Apex One › Agents › Agent Management › Export | deployed/online/offline, builds, restart, patterns, server OS |
| Detection logs, scan-exclusion lists (CSV) | SEP › Logs & Reports, policy exclusion lists | narrative counts, exclusion review |
| Screenshot Word file, one short label line above each group of pictures | Teams session | everything else |

Screenshots to make sure you take (no export exists for these):
**License Information**, Apex One **Global Agent Settings** (all tabs),
**Agent Update Source / Automatic Updates**, **Smart Protection Sources/Network**,
**Suspicious Object List Settings**, SEP **Scheduled Update**,
**Active Directory**, **Syslog**, **Event Notifications**,
**Suspicious Object Sync**, **Endpoint Inventory › Global Settings**, **Policy Management**.

Labels such as `License`, `Schedule update`, `Syslog`, `Realtime RT`, `BM`
steer the model to the right fields (see `SECTION_HINTS` in
`tmhc/sources/screenshots.py`). Unlabelled pictures still work; they are
just asked about every missing field.

## Customising

* **Baseline / wording** — `tmhc/rules/apexone_sep.yaml`. The header of
  the file documents every check type and placeholder (`{m.offline}`,
  `{f.some.fact}`, `{deployed}`).
* **Template** — make one from any finished report:
  ```bash
  python tools/make_template.py Finished_Report.docx tmhc/render/templates/my_template.docx \
      --replace "Client Name Pvt Ltd=client_name" --replace "Client Policy=policy_name" \
      --replace "Q4 2026=quarter" --replace "28/10/2026=report_date" \
      --replace "07-10-2026=check_date" --replace "Analyst=prepared_by" \
      --replace "Approver=approved_by" --replace "Owner=account_owner"
  ```
  The tool refuses to save if any of the original client strings survive.
  Use it with `run --template my_template.docx`.
* **Vision model** — `options.model` in the profile or `TMHC_MODEL`.

## Other products

The pipeline is product-neutral; a product needs a rule pack, a template
and (ideally) an export parser. Server & Workload Protection, Cloud Email
Gateway and Cloud Email & Collaboration Protection follow the same pattern:
add `tmhc/rules/<product>.yaml`, a template made from one of your finished
reports with `tools/make_template.py`, and an export parser in
`tmhc/sources/` where the console offers one (for example a Server &
Workload Protection policy export).

## Data handling

Customer evidence and generated reports are **never** committed:
`.gitignore` excludes `clients/`, `output/`, `*.cmpolicy`, `*.csv`, `*.zip`,
caches and every `.docx`/`.xlsx` except the template. Keep client folders
outside the repo or under `clients/`. Screenshots are sent to the Anthropic
API only when you run without `--offline`.

## Tests

```bash
python -m pytest -q
```
Tests use synthetic fixtures only.
