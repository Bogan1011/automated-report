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

**Runs entirely on your own machine.** The report, the evidence and the
screenshots stay on the laptop. Nothing is uploaded unless you deliberately
switch on the cloud reader for a client that has approved it.

```
 evidence pack (on your laptop)          facts            report (on your laptop)
 ─────────────────────────────           ─────            ───────────────────────
 .cmpolicy policy export    ──parse──┐
 Agent List CSV             ──parse──┤
 Vision One log exports     ──parse──┼──► rules ──┬─► Word report (.docx)
 checklist.xlsx (you fill)  ─────────┤            └─► review workbook (.xlsx)
 screenshots (optional)  ─local model┘
```

## Why it is built this way

* **Exports first.** The `.cmpolicy` policy export contains every policy
  setting exactly, so ~150 policy rows need no screenshot at all. The
  agent-list CSV gives every count.
* **About 40 settings have no export** (licence, Apex One global agent
  settings, update schedule, syslog, AD, notifications...). You capture
  those one of two ways, both local:
  * **Checklist (no AI, any laptop)** - an Excel sheet listing just those
    settings with dropdowns and where to find each one in the console.
    Fill it during the Teams session.
  * **Local vision model (needs a GPU)** - an AI model running in Ollama on
    your own PC reads the screenshot Word file.
* **Never invents a value.** A setting with no evidence shows as
  *Not captured* with the Unknown icon and raises no gap.
* **Baseline is data, not code** - `tmhc/rules/apexone_sep.yaml` holds every
  row, its Trend-recommended value, the check and the remediation sentence.
* **Your own template** - made from one of your finished reports, so the
  cover, styles, intro and links are exactly yours.

## Set up on a Windows laptop (once)

1. Install **Python 3.11+** from python.org (tick *Add python.exe to PATH*).
2. Download this repository (Code > Download ZIP, or `git clone`) and open a
   terminal in its folder.
3. `pip install -r requirements.txt`
4. Check it works: `python -m pytest -q`

No account, key or internet connection is needed after this.

## Run a health check

```bash
python -m tmhc init clients/Acme/profile.yaml
```
This creates the client folder. Put the evidence in `clients/Acme/evidence/`:

```
clients/Acme/
  profile.yaml                  <- client name, dates, your name
  evidence/
    Acme_SEP_SS.docx            <- all screenshots in one Word file
    Acme_SEP_Logs.zip           <- CSV + .cmpolicy exports
```

### Office laptop (no GPU) - checklist

```bash
python -m tmhc checklist clients/Acme/profile.yaml   # creates clients/Acme/checklist.xlsx
# fill the yellow "Deployed" column (during or after the session)
python -m tmhc run clients/Acme/profile.yaml         # builds the report
```
The checklist only lists what the exports don't already prove (about 40
rows for an Apex One / SEP check). Blank rows show as *Not captured*.

### PC with a GPU - local AI reads the screenshots

1. Install **Ollama** from ollama.com and run `ollama pull qwen2.5vl:7b`
   (about 6 GB, one-time). On a GPU with less than 8 GB use `qwen2.5vl:3b`.
2. In `profile.yaml` set `reader: local`.
3. `python -m tmhc run clients/Acme/profile.yaml`

The model only answers on `127.0.0.1`; the tool refuses any other address.
Then run `python -m tmhc checklist ...` to confirm or fill whatever the
model missed - its readings are pre-filled in the checklist for you to check.

Without a GPU the local model still works but is slow (minutes per
screenshot); the checklist is quicker.

### Output

In `clients/Acme/output/`:

| File | Purpose |
|---|---|
| `Acme_SEP_Health_Check_Report_<Mon>_<Year>.docx` | the client report - open in Word and accept the prompt to update the table of contents |
| `..._review.xlsx` | every row with its source and evidence, the gap list, and a **Not captured** sheet |

### Reviewing and correcting

1. Open the review workbook. Filter **Rows** by *Source = Screenshot* and
   spot-check the quotes in the Evidence column.
2. A wrong screenshot reading: correct it in the checklist (checklist
   values win over screenshot readings), then run again.
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
* **Local model** — `options.local_model` in the profile (any Ollama vision model).

## Other products

The pipeline is product-neutral; a product needs a rule pack, a template
and (ideally) an export parser. Server & Workload Protection, Cloud Email
Gateway and Cloud Email & Collaboration Protection follow the same pattern:
add `tmhc/rules/<product>.yaml`, a template made from one of your finished
reports with `tools/make_template.py`, and an export parser in
`tmhc/sources/` where the console offers one (for example a Server &
Workload Protection policy export).

## Data handling

* Default is `reader: none` - no AI, nothing leaves the machine.
* `reader: local` talks only to Ollama on `127.0.0.1`. Any other host is
  refused unless `allow_remote_host: true` (for a GPU server you control).
* `reader: cloud` (Anthropic API) is refused unless the profile also sets
  `allow_cloud: true`, and needs `pip install anthropic`. Use it only where
  the client has approved sending screenshots to a cloud service.
* Client evidence and generated reports are never committed: `.gitignore`
  excludes `clients/`, `output/`, `*.cmpolicy`, `*.csv`, `*.zip`, caches,
  checklists and every `.docx`/`.xlsx` except the template.

## Tests

```bash
python -m pytest -q
```
Tests use synthetic fixtures only.
