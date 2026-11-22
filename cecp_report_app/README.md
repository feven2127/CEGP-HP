# CECP Executive Report Generator

Turns Trend Vision One **Cloud Email and Collaboration Protection (CECP)**
detections into two customer-facing HTML reports:

- **Executive report**: potential loss avoided (FBI IC3 2025 loss-per-victim),
  threats remediated, a breakdown by protected service, the value ledger,
  top detections, efficacy and most-targeted users.
- **Efficacy dashboard**: remediation score, KPIs, weekly trend, detections
  by service and category, configuration gaps with recommendations, and
  security posture by protection layer.

Sister project of `../cegp_report_app`: same layout, same Potential Loss
method, same IC3 table, so the two products' figures can be compared.

## Run

```bash
cd cecp_report_app
pip install -r requirements.txt
python app.py
```

Open **http://localhost:5001**. It uses port 5001 so it can run next to the
CEGP app on port 5000.

## Data sources

| Mode | What it uses |
|---|---|
| Demo | Randomly generated detections across Exchange Online, OneDrive, SharePoint and Teams |
| Live Vision One API | `search/detections` with `productCode:sca`; `search/emailActivities` count for emails scanned; `audit/logs` for Vision One restores |
| Upload CSV | One or more CECP **Detection logs** exports (threat protection and DLP). Columns are matched loosely: Detected, Scan source, Security filter, Threat type, Action, Affected user, Sender, Subject, File name |

Emails scanned, files scanned and restored-from-quarantine can be entered by
hand, from the CECP console's statistics. They override what the API returns.

## How the numbers work

- **Remediated** means quarantined, deleted, blocked, moved to junk, redirected
  for approval, replaced or encrypted. Pass/Log, monitor and tag-only actions
  are counted as *detected, not remediated*. See `classify_action` in
  `cecp_client.py`.
- **Value** = remediated detections × IC3 loss-per-victim × (days ÷ 91.25),
  covering remediated detections only.
- **IC3 mapping** (`cost_reference.py`): BEC → C1, Account Compromise → C2,
  Advanced Threat (Sandbox) → C3, Malware → C7, Phishing / Malicious URL / Spam
  → C8, Ransomware → C9, DLP → C11. File Blocking, Shared Link Control,
  Graymail and Scan Exception are counted but not valued.
- **Remediation rate** is the headline efficacy figure: CECP scans inside
  mailboxes and apps through their APIs, so there is no perimeter block rate.

## Things to check against a real tenant

- **Protected service, live mode.** Vision One has no documented field for
  the protected service. It is inferred from `scanType` and similar fields,
  and the run log prints the `scanType` values seen. If detections land in
  "Unknown service", extend `_SERVICE_PATTERNS` in `cost_reference.py`.
- **CSV columns.** CSV columns depend on the console's *Manage Columns*
  layout. The run log prints which columns were matched.
