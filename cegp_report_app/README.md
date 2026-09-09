# CEGP Executive Report Generator

Turns Trend Vision One **Cloud Email Gateway Protection (CEGP)** detection logs
into a customer-facing HTML statement: threats blocked and estimated money saved
over a chosen period.

## Setup

```bash
cd cegp_report_app
pip install -r requirements.txt
python app.py
```

Open **http://localhost:5000**.

## Using it

The UI is a dark, card-based console (styled after an internal LogLens3-style
reporting tool). Generating a report runs as a background job with a live
progress log, rather than blocking on one page load.

1. Enter the customer name and reporting period.
2. Choose a data source:
   - **Demo data** — generates realistic sample detections instantly, no API
     key needed. Good for testing the report look and feel.
   - **Live Vision One API** — pick a region, paste in an API key, and click
     **Test API connection** to verify it works before running anything.
3. Click **Generate executive report**. A status panel appears with a live
   log of each step (connecting, pulling detections, pulling scanned volume,
   pulling audit logs, categorizing, rendering). When it finishes, summary
   cards show the headline numbers and an **Open report in new tab** button
   appears.
4. On the report page itself, use **Download HTML** to save a copy to send
   to the customer, or print it to PDF from the browser's print dialog.

There's no manual "cost per incident" field to fill in — see below for why,
and how the money-saved number is actually calculated.

## How the CEGP filter works

CEGP data is exposed through Vision One's unified `/v3.0/search/*` and
`/v3.0/audit/logs` endpoints — there's no separate CEGP-specific REST
namespace, despite what some undocumented endpoint guesses out there might
suggest.

**Important: `pname` means something different on every data source.**
Per Trend Micro's internal Log Schema reference (KA-0015974):

| Data source | `pname` is actually |
|---|---|
| Detection data (`/v3.0/search/detections`) | Text product name — `"Email and Collaboration Security"` for CEGP |
| Email Activity Data (`/v3.0/search/emailActivities`) | A **numeric** internal product ID — `742` for CEGP, `733` for Cloud App Security |

Filtering `emailActivities` with a text string like `"CEGP"` matches **zero
rows silently** — no error, just an empty result — because the real value
there is the number `742`. This client uses `CEGP_DETECTION_PNAME` and
`CEGP_EMAIL_ACTIVITY_PNAME` in `vision_one_client.py` to keep the two
straight. If you see empty results in live mode, this mismatch is the first
thing to check.

Three other gotchas worth knowing:
- **Gateway detections span two scanTypes.** `gateway_realtime_blocking_traffic`
  (the gateway actually stopped the message) and `gateway_realtime_detection_log`
  (same detection pipeline, but the matching policy was set to log/monitor
  instead of block) are both real, observed live on a tenant where the
  blocking-traffic-only count undercounted the true per-product-code
  detection total. `SCANTYPE_GATEWAY_DETECTION_SIDE` in
  `vision_one_client.py` queries both — querying only
  `gateway_realtime_blocking_traffic` silently drops the monitor-mode
  detections, which also means an incomplete "detected, not blocked"
  bucket in the mail tracking breakdown above.
- **30-day default retention.** Unless a tenant has purchased extended
  storage, Vision One only retains searchable data for 30 days — a longer
  reporting period will silently return less data for the older portion,
  not an error.
- **Full-match-only fields don't take wildcards.** Some `TMV1-Query` fields
  (e.g. `eventId` on endpoint activity data) only support exact/full match —
  a wildcard like `eventId:*` against them is likely to fail or match
  nothing, unlike partial-match fields.

## Potential loss avoided calculation (TMES/IC3 methodology)

`cost_reference.py` implements Trend Micro's internal TMES sheet Potential
Loss methodology (matched to a customer-provided template), replacing an
earlier ad-hoc "expected value" model this app used before. For each of
12 TMES threat sub-types:

```
potential loss avoided = detections × IC3 loss-per-victim × (days in period ÷ 91.25)
```

- `IC3 loss-per-victim` — the FBI IC3 2025 Internet Crime Report's average
  loss per victim for the sub-type's mapped category (`IC3_CATEGORIES` in
  `cost_reference.py`, 11 categories C1–C11).
- `91.25` generalizes the source sheet's fixed quarterly divisor (`0.25`,
  i.e. `365 ÷ 4`) to this app's free-form date range — for an exact
  calendar quarter it reduces to ~0.25, and scales proportionally for any
  other range.

**This applies the full loss-per-victim figure to every detection, with
no discount for the share that would have plausibly succeeded if
delivered** — unlike the probability-weighted model this replaced. It's
Trend Micro's own internal reporting standard, implemented as specified
rather than softened, and labeled "potential loss avoided" (not
"estimated value protected") in the report so the two methodologies
aren't confused if you've seen the older version.

### Sub-type → IC3 category mapping

Only 6 of the 12 TMES sub-types are cost-mapped — the rest are
intentionally count-only in the source template (blank Category Mapping
column):

| TMES sub-type | IC3 category | Cost-mapped? |
|---|---|---|
| Spam | C8 (Phishing/Spoofing) | Yes |
| Phishing | C8 | Yes |
| Web Reputation | C8 | Yes |
| Malware | C7 (Malware/Scareware) | Yes |
| Ransomware | C9 (Ransomware) | Yes |
| Advanced Persistent Threat | C3 (Corporate Data Breach) | Yes |
| Email Reputation Service, SPF Violation, Graymail, Scan Exception, Content Filtering, Attachment | — | No — count only |

Vision One doesn't return these 12 TMES labels natively, so
`categorize()` in `cost_reference.py` maps real CEGP detection fields
(`malName`/`objectSubType`/`filterName`/`ruleName`/`eventName`/
`eventSubName`) to them via keyword matching. Notable folding decisions,
worth checking against your own tenant's naming:

- DMARC/SPF/DKIM rule triggers all fold into **SPF Violation** — no
  separate DMARC/DKIM bucket exists in the 12 TMES sub-types.
- CEGP's blended `Spam or Phish` catch-all folds into **Spam** (both Spam
  and Phishing map to the same IC3 category here, so this doesn't skew
  the cost figure).
- `Correlated Intelligence Anomalies` / `Virtual Analyzer` fold into
  **Advanced Persistent Threat**.
- Anything matching none of the keywords falls into **Other** — tracked
  and shown, never silently dropped, but also never cost-mapped.

Edit `IC3_CATEGORIES`, `TMES_SUBTYPE_CATEGORY`, or `_SUBTYPE_KEYWORDS` in
`cost_reference.py` to adjust the figures or mapping.

## Mail tracking — volume by action/status

The report leads with a **Mail tracking** section: the full mail-flow
breakdown for the period, not just blocked threats. Vision One doesn't
expose a single "mail tracking" data source with a status field — the
Search API splits mail flow across two scanTypes, so this section is built
by combining them:

- **Blocked / quarantined** — `search/detections` records scoped to
  `scanType:"gateway_realtime_blocking_traffic"` where `act` indicates a
  real block (same set backing the value-ledger and cost model below).
- **Detected, not blocked (monitor mode)** — detections in that same
  blocking-path scanType whose `act` value shows it was only logged, not
  stopped.
- **Delivered – flagged (spam/graymail)** — accepted mail
  (`scanType:"gateway_realtime_accepted_mail_traffic"` on
  `search/emailActivities`) where `mailThreatType` is present, i.e. mail
  the gateway flagged as spam/graymail/suspected but let through per
  policy. Counted via `get_delivered_flagged_count` in
  `vision_one_client.py`, a `countonly` presence query (`mailThreatType:*`)
  — exact, no paging.
- **Delivered – clean** — total accepted mail minus the flagged count
  above.

Each bucket degrades independently: if the delivered-flagged lookup fails
or lacks permission, that row and "Delivered – clean" drop out and a plain
"Delivered" total (from the existing scanned-volume count) is shown
instead; if scanned volume itself is unavailable, only the
blocked/detected buckets show. Percentages are of total tracked mail
(blocking-path detections + accepted mail activity) for the period.

## Detection efficacy section

The report also includes a **Detection efficacy** section covering:

- **Block rate** — threats blocked ÷ total inbound messages CEGP scanned in
  the period (`get_total_scanned_count` in `vision_one_client.py`, via the
  email-activity search endpoint).
- **Catch rate by threat category** — each category's share of *all scanned
  mail*, not just of the blocked mix (a different cut than the value ledger).
- **False-positive proxy** — count of messages a customer admin restored
  from quarantine, and that as a share of blocked volume. This uses the
  Audit Logs API filtered to the `Response Management` category, matching
  "restore" in the activity text client-side, since Vision One doesn't
  document an exact activity string for this — treat it as a lower bound,
  not an exact false-positive count.

If either of the two efficacy API calls fails (permission issue, or a
tenant with too much mail volume to page through), the report still
generates — it just marks that section as unavailable rather than failing
the whole report.

## Detection taxonomy (matches real CEGP/TMES reporting)

CEGP's actual detections are mostly **policy-rule triggers**, not named
malware families — a real customer's monthly summary is dominated by things
like `Spam or Phish`, `DMARC Rule`, `SPF Rule`, `DKIM Rule`, and `Graymail`,
not "Ransomware.Win32.LOCKBIT"-style names. Real detection field values are
mapped to the 12 TMES sub-types (see "Potential loss avoided calculation"
above) by `categorize()` in `cost_reference.py`. The **"Top 10 Policy
Detection Summary"** section (top blocked signatures by count) is a
separate, un-recategorized breakdown by raw detection name — it mirrors
that real report's naming and format directly.

If your Vision One tenant surfaces policy names that fall through to
"Other" (uncategorized, count-only, never silently dropped), add matching
keywords to `_SUBTYPE_KEYWORDS` in `cost_reference.py`; live detections
already come through the same `eventName`/`eventSubName`/`malName` fields
this taxonomy relies on, so no client changes are needed for live data.

## API key permissions needed

The Vision One API key used for a live pull needs the **Search** role
permission (View, filter, and search) at minimum. For the Detection
Efficacy section's false-positive proxy, it also needs **Audit Logs**
view permission — without it, that section degrades gracefully to "not
available" instead of failing the report. Never share a Master
Administrator key for this purpose if a scoped key is available.

## How report generation works (background job)

`POST /run` validates the form, creates a job ID, and starts a background
thread running the full pipeline (fetch → categorize/cost → render). It
returns immediately with `{job_id}`.

- `GET /status/<job_id>` — polled every second by the browser; returns the
  running log lines, status (`running`/`done`/`error`), and — once done — a
  small summary (total blocked, value protected, block rate, false-positive
  rate) used for the summary cards.
- `GET /report/<job_id>` — returns the full rendered report HTML once the
  job is done.

Jobs are held **in memory** (a plain Python dict) — restarting the app clears
them, and this won't scale across multiple worker processes. Fine for local/
single-user use; swap in Redis or a database-backed job table if you need it
to survive restarts or run behind multiple workers.

## Files

| File | Purpose |
|---|---|
| `app.py` | Flask routes, background job runner, in-memory job store |
| `vision_one_client.py` | Vision One Search API client (region routing, pagination, CEGP filter) |
| `report_builder.py` | Aggregates raw detections into report numbers |
| `cost_reference.py` | Per-category expected-value cost model + threat categorization |
| `mock_data.py` | Demo-mode fake detection generator |
| `templates/index.html` | Dark console UI — config form + job status/log panel |
| `templates/report.html` | The executive report itself, same dark card theme |
| `static/style.css` | Shared design tokens + styling for both pages |
