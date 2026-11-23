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
screenshots stay on that machine. Nothing is uploaded unless you deliberately
switch on the cloud reader for a client that has approved it.

```
 drop into inbox/<Client>/            read locally                 written to <Client>/output/
 ─────────────────────────            ────────────                 ───────────────────────────
 screenshots .docx  ──── OCR + checkbox/radio/toggle detection ─┐
 logs .zip  ─────────── policy export, agent list, log CSVs ────┼─► rules ─► Word report + review workbook
 checklist.xlsx (fill blanks, save) ────────────────────────────┘           STATUS.txt (what to do next)
```

## How screenshots are read

Plain OCR (Tesseract) finds each setting's label, and the checkbox, radio
button or toggle next to it is judged from its pixels: filled blue or a
dark tick/dot means on, an empty box or ring means off. Numbers in input
boxes are read twice, in two different ways, and kept only if both
readings agree. No AI model and no GPU are needed, and it takes about 1.5 s
per screenshot on 2 vCPU.

Measured on a real engagement (119 screenshots, values checked by hand):
**35 settings read correctly, 0 wrong, 12 left blank** for the checklist.
It is built to leave a value blank rather than guess. Settings without a
readable label or control (and anything not in the screenshots) show as
*Not captured* in the report and appear in `checklist.xlsx` to fill in.

## Why it is built this way

* **Exports first.** The `.cmpolicy` policy export contains every policy
  setting exactly, so ~150 policy rows need no screenshot at all. The
  agent-list CSV gives every count.
* **Screenshots for the rest** (licence, Apex One global agent settings,
  update schedule, syslog, AD, notifications...), read by OCR as above.
* **Checklist for whatever is left** - an Excel sheet pre-filled with what
  the screenshots showed; you fill the blanks and save.
* **Never invents a value.** A setting with no evidence shows as
  *Not captured* with the Unknown icon and raises no gap.
* **Baseline is data, not code** - `tmhc/rules/apexone_sep.yaml` holds every
  row, its Trend-recommended value, the check and the remediation sentence;
  `tmhc/rules/apexone_sep_ocr.yaml` says where each setting is on screen.
* **Your own template** - made from one of your finished reports.

## Ubuntu VM (recommended): drop files, get a report

Tested on Ubuntu 24.04 with 2 vCPU / 8 GB RAM.

```bash
git clone https://github.com/Bogan1011/automated-report.git
cd automated-report
./deploy/install.sh --samba
```

The installer asks for the names printed in every report and the usual
logs-zip password, then sets up a background service (`tmhc-watch`) and a
Windows share. Set the share password when asked (or later with
`sudo smbpasswd -a $USER`).

**Every health check after that:**

1. From Windows open `\\<vm-ip>\healthcheck\inbox`, make a folder named after
   the client (e.g. `Acme Industries Private Limited`) and copy in the
   screenshot Word file and the logs zip.
2. Wait ~4 minutes. The folder gets `output/` (the report + review
   workbook), `STATUS.txt`, `profile.yaml` and `checklist.xlsx`.
3. Open `checklist.xlsx`, fill any blank yellow cells, save. The report
   rebuilds by itself within a minute.
4. Open the report in Word and accept the prompt to update the table of
   contents.

The check date and quarter are read from the screenshots' taskbar clock.
To change anything for one client (legal name, dates, people), edit that
folder's `profile.yaml`; saving it rebuilds the report.

| | |
|---|---|
| Settings for all clients | `~/healthcheck/config.yaml` |
| Live log | `journalctl -u tmhc-watch -f` |
| Update | `cd ~/automated-report && git pull && ./deploy/install.sh` |
| No Samba? | copy files with WinSCP / `scp` into `~/healthcheck/inbox/<Client>/` |

**Optional local AI (`--with-ai`).** Installs Ollama with `qwen2.5vl:3b`
(CPU, ~3 GB) and adds 4 GB swap; the AI then reads only what OCR could not.
On 2 vCPU expect a few minutes per screenshot. This path has not been
measured against real captures, so its readings must be checked in the
review workbook. OCR plus the checklist is the dependable route.

## Windows laptop (manual runs)

1. Install **Python 3.11+** from python.org (tick *Add python.exe to PATH*)
   and **Tesseract** from github.com/UB-Mannheim/tesseract/wiki (add to PATH).
2. In the repository folder: `pip install -r requirements.txt`, then
   `python -m pytest -q`.
3. Per client:
   ```bash
   python -m tmhc init clients/Acme/profile.yaml
   # copy the evidence into clients/Acme/evidence/, edit names/paths in profile.yaml
   python -m tmhc run clients/Acme/profile.yaml          # report + reads screenshots
   python -m tmhc checklist clients/Acme/profile.yaml    # checklist pre-filled from screenshots
   python -m tmhc run clients/Acme/profile.yaml          # again after filling it
   ```

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
   values win over screenshot readings) and save. Values you leave as
   pre-filled stay labelled as screenshot evidence.
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

* Default reader is `ocr`: no AI, no network. The watcher service is
  started with network access denied (`IPAddressDeny=any`).
* `reader: ocr+local` / `local` talk only to Ollama on `127.0.0.1`; any other
  host is refused unless `allow_remote_host: true`.
* `reader: cloud` (Anthropic API) is refused unless the profile also sets
  `allow_cloud: true`, and needs `pip install anthropic`.
* The Samba share requires the VM user's share password. `config.yaml` (may
  hold the zip password) is readable only by that user.
* Client evidence and generated reports are never committed: `.gitignore`
  excludes `clients/`, `output/`, `*.cmpolicy`, `*.csv`, `*.zip`, caches,
  checklists and every `.docx`/`.xlsx` except the template.

## Tests

```bash
python -m pytest -q
```
Tests use synthetic fixtures only.
