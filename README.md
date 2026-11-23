# Trend Micro Health Check Report Generator

Turns the evidence you collect in a customer health-check session into the
finished Word report **and the Product Efficacy presentation** — same
templates, same tables, same status icons, same gap and remediation wording
— so the analyst reviews a draft instead of typing one.

Products:

| Product | Word report | Presentation | Validated against |
|---|---|---|---|
| Standard Endpoint Protection (Apex One) — tab **SEP** | yes | yes (19-slide efficacy deck) | real engagement: same 11 server + 8 policy gaps, identical counts |
| Server & Workload Protection (Vision One SWP) — tab **SWP** | yes | yes (12-slide efficacy deck) | real engagement: every row, status icon and gap identical to the analyst's report |
| Cloud Email and Collaboration Protection (formerly Cloud App Security / CAS) — tab **CECP** | yes | yes (12-slide efficacy deck) | real engagement (72 screenshots): all 98 settings rows, status icons, 15 gaps and the executive summary identical to the analyst's report |

SEP, SWP and CECP are kept as separate tabs on the website and separate
reports; they can be merged later. The product is called **CECP** everywhere
(file names, tabs, report); "CAS" in a product name is recognised as CECP.

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

## Ubuntu VM (recommended): upload website

Tested on Ubuntu 24.04 with 2 vCPU / 8 GB RAM.

```bash
git clone https://github.com/Bogan1011/automated-report.git
cd automated-report
./deploy/install.sh
```

Run it as **root** or as a normal user with sudo:

| | services run as | program | data (client folders, settings) |
|---|---|---|---|
| root | system user `tmhc` (no login shell) | `/opt/tmhc` | `/var/lib/tmhc/healthcheck` |
| normal user | that user | the cloned folder | `~/healthcheck` |

The installer asks for the names printed in every report, the logs-zip
password (one password for every client) and a website login, then starts
two background services: `tmhc-web` (the website) and `tmhc-watch` (builds
the reports). It also installs a `tmhc` command, e.g.
`tmhc web --set-password alice` to add a login.
The website uses port **8090**; if that port is taken it uses the next free
one and prints the address (e.g. `http://192.168.1.70:8090`). Use
`--port=NNNN` to choose. Add `--samba` for a Windows share as well.

**Every health check:**

1. Open the website, **New health check**: client name, prepared/approved
   by, dates (blank check date = read from the screenshots), then attach the
   screenshot Word file and the logs zip. **Upload and build report.**
2. The client page shows an upload check straight away (pictures found, zip
   opened with the saved password, policy export and agent list present),
   then the build status. About 4 minutes on 2 vCPU.
3. **Fill in settings** (available from the moment you upload, even while
   it builds): after each build, everything the report shows as
   "Not captured" is listed first, with dropdowns or suggestions; readings
   from screenshots are pre-filled to check. **Save** - the report rebuilds
   in under a minute without those "Not captured" rows.
4. **Download report** (and the review workbook). In Word, accept the prompt
   to update the table of contents.

**Settings** (website): default names for new health checks, **Trend's
latest Apex One agent build** (set it when Trend releases a new one; every
new health check starts with it and asks you to confirm it), the logs zip
password used for every client, and your login password. The latest build
drives the "Latest:" recommendation and the outdated-agent counts; the
build list in the report shows the 5 newest builds and one line for the
rest (`options.build_rows` to change). More logins:
`tmhc web --set-password <name>` on the server.

The website only answers the office network (10.x, 172.16-31.x, 192.168.x)
and its service cannot reach the internet. It uses a login with
PBKDF2-hashed passwords; traffic is plain HTTP inside the LAN.

| | |
|---|---|
| Settings file | `config.yaml` in the data folder (the website edits it) |
| Client folders | `inbox/<Client>/` in the data folder (`output/` holds the report) |
| Live log | `journalctl -u tmhc-web -u tmhc-watch -f` |
| Update | `cd ~/automated-report && git pull && ./deploy/install.sh` |
| Without the website | copy files into `~/healthcheck/inbox/<Client>/` (Samba or WinSCP) - same result |

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
| `Acme_SEP_Health_Check_Report_<Mon>_<Year>.docx` | the client report - open in Word and accept the prompt to update the table of contents (`..._SWP_...` for Server & Workload Protection) |
| `Acme_SEP_Product_Efficacy_Report_<Mon>_<Year>.pptx` | the efficacy presentation: executive summary, agent versions, one chart slide per detection type, findings. Charts are native PowerPoint charts (editable). **The client logo on the title slide is a grey placeholder - right-click it > Change Picture.** |
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

For **Server & Workload Protection** the logs zip should hold:

| Export | Where | Feeds |
|---|---|---|
| `Computers.csv` | SWP › Computers › Export (CSV) | agent counts, status (critical/warning/managed with reasons), agent versions, component update status, computers without policy, module states per policy |
| Policy exports (`.xml`), one per reviewed policy | SWP › Policies › select › Export | self protection, CPU usage, rule counts, real-time scan configuration (only values set on the policy itself; inherited ones come from screenshots) |
| `Intrusion_Prevention_Events.csv`, `Log_Inspection_Events.csv` | SWP › Events & Reports › Export | the IPS and Log Inspection presentation slides |
| `Directory_Lists.csv`, `File_Lists.csv`, `File_Extension_Lists.csv` | SWP › Policies › Common Objects › Export | exclusion review |

SWP screenshots (labels like `Setting windows`, `Am linux`, `Default realtime`
help, but the policy is recognised from the window title too): License,
MFA, Endpoint Inventory Global Settings, Version Control Policies (Version
details), Administration › System Settings tabs (Agents, Alerts, Event
Forwarding, Updates, Smart Feedback, Advanced), Scheduled Tasks, Relay
Management, and for each reviewed policy: Overview, Anti-Malware, Web
Reputation, Device Control, Application Control, Integrity Monitoring, Log
Inspection, Firewall, Intrusion Prevention, Settings (all tabs); plus the
Default Real-Time / Scheduled / Manual scan configurations. The SWP console's
dark grey dropdown text is read with a contrast-stretched OCR pass.

For **Cloud Email and Collaboration Protection (CECP)** the logs zip should hold:

| Export | Where | Feeds |
|---|---|---|
| Detection log export (`result.csv`) | CECP › Detection logs › Export (one month) | the "<threat> Detections" sections and slides: URLs, senders, recipients / affected users, actions |
| Monthly report PDF (`<Company>'s <Month> Report-YYYYMMDD.pdf`) | CECP › Reports › One-Time / Scheduled report | the *Total Items Scanned* panel (cut straight from the PDF), total scans and the threat counts |

CECP screenshots (labels like `Asp exchange`, `Ms sharepoint`, `Va teams`
help; the service is also recognised from the breadcrumb "ATP Policy for
<service>"): License, Email account inventory, Service status, and for
Exchange Online the ATP policy pages General, Advanced Spam Protection (rules,
approved/blocked lists, actions), Malware Scanning (rules, actions), File
Blocking, Web Reputation (rules, approved/blocked list, actions), Virtual
Analyzer (rules, actions), Correlated Intelligence; for SharePoint Online,
OneDrive and Microsoft Teams the same pages of their ATP policy; the DLP policy
lists; and the global settings Approved/Blocked Lists, High Profile Domains and
Users, Internal Domain List, Suspicious Object Settings and Attachment Password
Guessing. Switches are read by colour (blue = on). Options of a module that is
switched off are reported as N/A, and the actions of a *Monitor Only* policy as
"Pass (Monitor Only Policy)", as in the analysts' reports.

**Latest agent builds** (SEP; SWP Windows and Linux) are filled in
automatically from Trend Micro's own release notes — the Apex One as a Service
/ SEP hotfix readme ("Security Agent version: 14.0.NNNNN") and the Deep
Security Agent release notes ("Build number: 20.0.3-NNNNN"). A small
scheduled job, `tmhc-builds` (systemd timer), checks once a day, and within
5 minutes when you press **Check Trend Micro now** in Settings. It is the
only part of the server allowed onto the internet and it reads nothing but
those public pages; the website and the report builder stay offline.
Typing a build in Settings overrides it (shown as *set manually*); tick
*Use Trend's latest automatically* to go back. Each new health check starts
with these values and can still be changed per client. By hand:
`tmhc builds --config ~/healthcheck/config.yaml --force`.

Screenshots to make sure you take for SEP (no export exists for these):
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
* **Template** — made from one of your finished reports, keeping its tables
  row for row (wording, bold labels, merged cells, heading styles); only
  the Deployed text and Status icon of each row are filled in:
  ```bash
  python tools/make_template.py Finished_Report.docx tmhc/render/templates/sep_report_template.docx \
      --rows tools/sep_row_map.yaml \
      --replace "Client Name Pvt Ltd=client_name" --replace "Client Policy=policy_name" \
      --replace "Q4 2026=quarter" --replace "28/10/2026=report_date" \
      --replace "07-10-2026=check_date" --replace "Analyst=prepared_by" \
      --replace "Approver=approved_by" --replace "Owner=account_owner"
  ```
  `tools/sep_row_map.yaml` says which setting each table row shows (by row
  number). If you add, remove or reorder rows in your layout, update the
  map. The tool refuses to save if any of the original client strings survive.
* **Local model** — `options.local_model` in the profile (any Ollama vision model).

* **Presentation templates** — made from one of your finished efficacy decks:
  ```bash
  python tools/make_pptx_template.py Finished_SWP_Deck.pptx tmhc/render/templates/swp_efficacy_template.pptx \
      --product swp --forbid "Client Name" --forbid HOSTPREFIX
  ```
  Keeps one prototype of each slide design, replaces the client logo with a
  placeholder, drops revision history, and refuses to save if a `--forbid`
  word survives.

* **CECP templates** — the Word template has five settings tables and a
  detections section, so it has its own wrapper around `make_template.py`:
  ```bash
  python tools/make_cecp_template.py Finished_CECP_Report.docx tmhc/render/templates/cecp_report_template.docx \
      --client "Client Name Limited" --owner "Account Owner" --by "Analyst" --quarter "Q4 2026" \
      --report-date 18/11/2026 --check-date "27 Oct 2026" --period-from "01 Sept 2026" --period-to "30 Sept 2026" \
      --forbid clientdomain --forbid someuser
  python tools/make_pptx_template.py Finished_CECP_Deck.pptx tmhc/render/templates/cecp_efficacy_template.pptx \
      --product cecp --forbid clientname
  ```
  Rows are mapped in `tools/cecp_row_map.yaml`; the detection blocks are
  rebuilt per threat type found in the logs.

## Other products

The pipeline is product-neutral; a product needs a rule pack, a template
and (ideally) an export parser. SEP, SWP and CECP are done. Cloud Email
Gateway follows the same pattern:
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
