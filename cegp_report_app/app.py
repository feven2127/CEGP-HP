"""
CEGP Executive Report Generator
--------------------------------
A small Flask app that pulls Cloud Email Gateway Protection (CEGP)
detection logs from Trend Vision One (or uses built-in demo data) and
renders a customer-facing HTML "value statement": threats blocked,
detection efficacy, and estimated money saved over a chosen period.

Report generation runs as a background job so the UI can stream progress
log lines and poll for completion, rather than blocking on one request.

Run:
    pip install -r requirements.txt
    python app.py
Then open http://localhost:5000
"""

from __future__ import annotations

import datetime as dt
import threading
import uuid
import logging
from collections import Counter

from flask import Flask, render_template, request, jsonify, Response

from vision_one_client import VisionOneClient, VisionOneAPIError
from report_builder import build_outbound_summary, build_report_data
from cost_reference import IC3_SOURCE
from csv_import import (
    DIRECTION_INBOUND,
    DIRECTION_LABELS,
    DIRECTION_OUTBOUND,
    KIND_LABELS,
    KIND_MAIL_TRACKING,
    KIND_POLICY_EVENTS,
    parse_csv_upload,
)
from mock_data import (
    generate_mock_detections,
    generate_mock_scanned_count,
    generate_mock_restore_count,
    generate_mock_delivered_flagged_count,
)

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# In-memory job store: job_id -> {status, log, report_html, error, summary}
jobs: dict[str, dict] = {}


def _warn_period_vs_data(records, start_dt, end_dt, emit) -> None:
    """Value per detection is scaled by the SELECTED period length (TMES
    method), so a 30-day period over 4 days of data overstates the value
    ~7.5x. Warn when the data covers much less than the period."""
    days = sorted({(r.detected_time or "")[:10] for r in records if (r.detected_time or "")[:4].isdigit()})
    if not days:
        return
    selected = (end_dt.date() - start_dt.date()).days + 1
    covered = (dt.date.fromisoformat(days[-1]) - dt.date.fromisoformat(days[0])).days + 1
    if covered < selected * 0.8:
        emit(
            f"[WARN] The data covers {covered} day(s) ({days[0]} to {days[-1]}) but the selected period is "
            f"{selected} days. Value per detection scales with the selected period, so the value figure is "
            f"about {selected / covered:.1f}x too high. Set the period to {days[0]} – {days[-1]} for an accurate value."
        )


# ---------------------------------------------------------------- pipeline

def _parse_period(form: dict, mode: str):
    """(start, end) datetimes from the form. Both are required for live API
    and demo runs. For CSV uploads either may be left empty -- the missing
    side is filled in from the uploaded data (see _fill_period_from_data)."""
    def parse(key: str, end_of_day: bool = False):
        value = (form.get(key) or "").strip()
        if not value:
            return None
        try:
            day = dt.datetime.strptime(value, "%Y-%m-%d")
        except ValueError:
            raise ValueError(f"'{value}' isn't a valid date — use YYYY-MM-DD.")
        return day + dt.timedelta(days=1, seconds=-1) if end_of_day else day

    start, end = parse("period_start"), parse("period_end", end_of_day=True)
    if mode != "csv" and (start is None or end is None):
        raise ValueError("Period start and end are required for live API and demo runs.")
    if start and end and end < start:
        raise ValueError("Period end must be after period start.")
    return start, end


def _fill_period_from_data(start_dt, end_dt, uploads, emit):
    """CSV mode: use the earliest / latest timestamp in the uploaded files
    for whichever period date wasn't entered."""
    if start_dt is not None and end_dt is not None:
        return start_dt, end_dt
    firsts = [u.first_time for u in uploads if u.first_time]
    lasts = [u.last_time for u in uploads if u.last_time]
    if not firsts or not lasts:
        raise ValueError(
            "No dates could be read from the uploaded files, so the report period can't be "
            "worked out — enter a period start and end date."
        )
    if start_dt is None:
        start_dt = dt.datetime.combine(min(firsts).date(), dt.time.min)
    if end_dt is None:
        end_dt = dt.datetime.combine(max(lasts).date(), dt.time(23, 59, 59))
    emit(f"[Setup] Period taken from the uploaded data: {start_dt:%Y-%m-%d} to {end_dt:%Y-%m-%d}")
    return start_dt, end_dt


def run_report_job(job_id: str, form: dict):
    job_log: list[str] = []

    def emit(msg: str):
        job_log.append(msg)
        jobs[job_id]["log"] = list(job_log)
        log.info(msg)

    with app.test_request_context():
        try:
            customer_name = (form.get("customer_name") or "").strip() or "Customer"
            mode = form.get("mode", "demo")

            emit(f"[Setup] Customer: {customer_name}")

            start_dt, end_dt = _parse_period(form, mode)
            outbound_summary = None
            dates_given = start_dt is not None and end_dt is not None
            if dates_given:
                emit(f"[Setup] Period: {start_dt:%Y-%m-%d} to {end_dt:%Y-%m-%d}")
            else:
                emit("[Setup] No period entered — it will be taken from the dates in the uploaded files")

            if mode == "live":
                api_key = (form.get("api_key") or "").strip()
                region = form.get("region", "us")
                if not api_key:
                    raise ValueError("An API key is required for a live Vision One pull.")

                client = VisionOneClient(api_key=api_key, region=region)
                data_source = f"Trend Vision One API ({region.upper()}), productCode:sem"

                emit(f"[Vision One] Connecting to region '{region.upper()}'...")
                emit("[Vision One] Pulling CEGP detections (search/detections)...")
                # The up-front countonly call was skipped: it only fed an
                # advisory note and could stall the run for minutes before
                # the first page was fetched. Paging logs progress instead.
                records = client.get_cegp_detections(start_dt, end_dt, progress=emit)
                emit(f"[Vision One] {len(records):,} CEGP detections retrieved")

                try:
                    scan_type_breakdown = client.get_scan_type_breakdown(start_dt, end_dt)
                    total_sem = sum(scan_type_breakdown.values())
                    if total_sem > len(records):
                        emit(
                            f"[Diagnose] {total_sem:,} total productCode:sem detections exist this "
                            f"period across ALL scanTypes, vs {len(records):,} retrieved under the "
                            f"gateway-only scanType filter — {total_sem - len(records):,} detection(s) "
                            "are being excluded by scanType scoping. Breakdown by scanType:"
                        )
                        for st, cnt in scan_type_breakdown.items():
                            emit(f"[Diagnose]   scanType '{st}': {cnt:,}")
                    else:
                        emit(f"[Diagnose] {total_sem:,} total productCode:sem detections exist this period — matches what the gateway-only scanType filter retrieved, so scanType scoping is not the cause of any gap vs. the Vision One console.")
                except VisionOneAPIError as e:
                    emit(f"[WARN] scanType diagnostic failed ({e.status_code}) — skipping")

                if len(records) == 0:
                    emit("[Diagnose] Zero CEGP detections — checking whether this tenant has ANY detection data in this period...")
                    try:
                        any_count = client.probe_any_detections(start_dt, end_dt)
                        if any_count == 0:
                            emit("[Diagnose] No detections at all (any product) in this window — likely a permissions issue, a date range with no data, or this tenant's data hasn't reached the data lake yet. Not a pname mismatch.")
                        else:
                            emit(f"[Diagnose] Detections DO exist for other products in this window — the CEGP pname filter is likely excluding them.")
                            seen_pnames = client.probe_email_pname_values(start_dt, end_dt)
                            if seen_pnames:
                                emit(f"[Diagnose] Actual pname value(s) seen containing 'Email': {sorted(seen_pnames)}")
                            else:
                                emit("[Diagnose] No pname values containing 'Email' found either — this tenant may not have CEGP/email detections in this period at all, even though other products do.")
                    except VisionOneAPIError as e:
                        emit(f"[Diagnose] Probe query failed too ({e.status_code}): {e.message}")

                emit("[Vision One] Pulling scanned mail volume (search/emailActivities)...")
                accepted_records = None
                try:
                    # Fetch the accepted-mail records themselves (paged, with
                    # progress) instead of trusting a countonly figure: this
                    # gives real totals and shows the mailThreatType values.
                    accepted_records = client.get_accepted_mail_records(start_dt, end_dt, progress=emit)
                    total_scanned = len(accepted_records)
                    emit(f"[Vision One] {total_scanned:,} inbound messages scanned (fetched records)")
                    threat_values = Counter(
                        r.get("mailThreatType") or "(none)" for r in accepted_records
                    )
                    emit(f"[Diagnose] mailThreatType values seen: {dict(threat_values.most_common(10))}")
                    try:
                        total_sem_activity = client.get_total_sem_email_activity_count(start_dt, end_dt)
                        if total_sem_activity > total_scanned:
                            emit(
                                f"[Diagnose] {total_sem_activity:,} total productCode:sem email-activity "
                                f"records exist this period across ALL scanTypes, vs {total_scanned:,} "
                                "under the accepted-mail-only scanType filter — this tenant's mail "
                                "volume may be undercounted the same way detections can be; check "
                                "against Vision One's own Mail Tracking view for this period."
                            )
                        else:
                            emit(
                                f"[Diagnose] {total_sem_activity:,} total productCode:sem email-activity "
                                "records — matches the accepted-mail-only figure above. Note this "
                                "cross-check is still count()-based (not verified against real fetched "
                                "records, unlike the detections check above), so treat a match here as "
                                "a hint that scanType scoping isn't the issue, not definitive proof — "
                                "still worth a spot-check against Vision One's Mail Tracking view."
                            )
                    except VisionOneAPIError:
                        pass  # non-fatal -- this is a secondary cross-check
                except VisionOneAPIError as e:
                    total_scanned = None
                    emit(f"[WARN] Scanned-volume lookup failed ({e.status_code}) — block rate will show as N/A")

                emit("[Vision One] Pulling mail tracking log (delivered-but-flagged mail)...")
                try:
                    if accepted_records is not None:
                        delivered_flagged_count = sum(
                            1 for r in accepted_records if r.get("mailThreatType")
                        )
                    else:
                        delivered_flagged_count = client.get_delivered_flagged_count(start_dt, end_dt)
                    emit(f"[Vision One] {delivered_flagged_count:,} delivered messages flagged (spam/graymail)")
                except VisionOneAPIError as e:
                    delivered_flagged_count = None
                    emit(f"[WARN] Delivered-flagged lookup failed ({e.status_code}) — mail tracking breakdown will show fewer buckets")

                emit("[Vision One] Pulling quarantine-restore audit logs (audit/logs)...")
                try:
                    restore_count = client.get_quarantine_restore_count(start_dt, end_dt)
                    emit(f"[Vision One] {restore_count:,} messages restored from quarantine")
                except VisionOneAPIError as e:
                    restore_count = None
                    emit(f"[WARN] Audit-log lookup failed ({e.status_code}) — false-positive rate will show as N/A")
            elif mode == "csv":
                csv_files = form.get("csv_files") or []
                emit(f"[CSV] Parsing {len(csv_files)} uploaded file(s)...")
                seen: set = set()  # shared across files -> cross-file de-duplication
                uploads: list = []
                total_duplicates = 0
                kinds = Counter()
                # Incoming and outgoing files are processed separately: only
                # incoming mail feeds the inbound figures and the IC3 value.
                sides = {
                    d: {"policy": [], "tracking_records": [], "tracking": None, "files": 0}
                    for d in (DIRECTION_INBOUND, DIRECTION_OUTBOUND)
                }
                for filename, raw_bytes, kind, direction in csv_files:
                    try:
                        upload = parse_csv_upload(
                            raw_bytes, filename, start_dt, end_dt, seen, kind=kind, direction=direction
                        )
                    except ValueError as e:
                        raise ValueError(f"{filename}: {e}") from e
                    uploads.append(upload)
                    dir_label = DIRECTION_LABELS[direction]
                    span = ""
                    if upload.first_time and upload.last_time:
                        span = f", {upload.first_time:%Y-%m-%d} to {upload.last_time:%Y-%m-%d}"
                    emit(f"[CSV] {filename}: {dir_label} {upload.kind_label} — {upload.rows_read:,} rows read{span}")
                    if upload.detected_kind and upload.detected_kind != upload.kind:
                        emit(
                            f"[WARN]   {filename} was marked as a {upload.kind_label} but its columns look like a "
                            f"{KIND_LABELS[upload.detected_kind]} — processed as marked; check the selection if the figures look wrong"
                        )
                    if upload.other_direction_skipped:
                        other = DIRECTION_LABELS[DIRECTION_OUTBOUND if direction == DIRECTION_INBOUND else DIRECTION_INBOUND]
                        emit(f"[CSV]   {upload.other_direction_skipped:,} {other} row(s) in this file excluded (file marked {dir_label})")
                    elif not upload.has_direction_column:
                        emit(f"[CSV]   No direction column — every row treated as {dir_label}")
                    if upload.rows_outside_period:
                        emit(f"[CSV]   {upload.rows_outside_period:,} row(s) outside the selected period skipped")
                    if upload.duplicates:
                        emit(f"[CSV]   {upload.duplicates:,} row(s) already seen in an earlier file skipped (duplicate)")
                    total_duplicates += upload.duplicates
                    kinds[f"{dir_label} {upload.kind_label}"] += 1
                    side = sides[direction]
                    side["files"] += 1
                    if upload.kind == KIND_MAIL_TRACKING:
                        t = upload.tracking
                        emit(
                            f"[CSV]   {t.total_rows:,} {dir_label} messages: {t.delivered:,} delivered "
                            f"({t.delivered_flagged:,} flagged), {t.blocked:,} blocked/quarantined, "
                            f"{t.restored:,} released/restored, {t.other:,} other (bounced/deferred)"
                        )
                        emit(f"[Diagnose] Status values seen: {dict(t.status_counts.most_common(10))}")
                        side["tracking_records"].extend(upload.records)
                        if side["tracking"] is None:
                            side["tracking"] = upload.tracking
                        else:
                            side["tracking"].merge(upload.tracking)
                    else:
                        emit(f"[CSV]   {len(upload.records):,} policy events")
                        side["policy"].extend(upload.records)

                emit(
                    f"[CSV] Consolidated {len(csv_files)} file(s) ("
                    + ", ".join(f"{n} {k}" for k, n in kinds.items())
                    + f") into one data set; {total_duplicates:,} duplicate row(s) removed"
                )
                data_source = (
                    f"{len(csv_files)} uploaded CEGP export(s), consolidated and de-duplicated: "
                    + ", ".join(f"{name} ({DIRECTION_LABELS[d]} {KIND_LABELS[k]})" for name, _, k, d in csv_files)
                )

                inbound = sides[DIRECTION_INBOUND]
                tracking = inbound["tracking"]
                if inbound["policy"]:
                    records = inbound["policy"]
                    emit(f"[CSV] Incoming: using {len(records):,} policy events as the detection source")
                else:
                    records = inbound["tracking_records"]
                    if inbound["files"]:
                        emit(
                            f"[CSV] Incoming: no policy event log uploaded — using {len(records):,} blocked "
                            "rows from mail tracking as the detection source"
                        )
                    else:
                        emit("[WARN] No incoming files uploaded — the inbound sections of the report will be empty")

                outbound = sides[DIRECTION_OUTBOUND]
                if outbound["files"]:
                    out_records = outbound["policy"] or outbound["tracking_records"]
                    outbound_summary = build_outbound_summary(out_records, outbound["tracking"])
                    emit(
                        f"[CSV] Outgoing: {outbound_summary['detections']:,} threat detection(s), "
                        f"{outbound_summary['blocked']:,} blocked"
                        + (f", {outbound_summary['messages_scanned']:,} outgoing messages tracked"
                           if outbound_summary["messages_scanned"] is not None else "")
                        + " — reported separately, not added to inbound figures or the value estimate"
                    )

                if not records and tracking is None and not outbound["files"]:
                    raise ValueError(
                        "No usable rows found in the CSV(s) for the selected period — "
                        "check the dates and that the file has threat/policy or status values."
                    )

                start_dt, end_dt = _fill_period_from_data(start_dt, end_dt, uploads, emit)
                total_scanned = tracking.delivered if tracking else None
                delivered_flagged_count = tracking.delivered_flagged if tracking else None
                restore_count = tracking.restored if tracking and tracking.restored else None
                if tracking and not tracking.restored:
                    emit("[CSV] No released/restored rows in mail tracking — enter a restore count to show a false-positive rate")

                def _optional_count(key: str, label: str, current: int | None) -> int | None:
                    raw = (form.get(key) or "").strip().replace(",", "")
                    if not raw:
                        if current is None:
                            emit(f"[CSV] No {label} available — related rate will show as N/A")
                        return current
                    try:
                        value = int(raw)
                    except ValueError:
                        emit(f"[WARN] {label} value '{raw}' is not a number — ignoring")
                        return current
                    emit(f"[CSV] Using manually entered {label}: {value:,}")
                    return value

                total_scanned = _optional_count("total_scanned", "delivered (accepted) mail count", total_scanned)
                delivered_flagged_count = _optional_count("delivered_flagged_count", "delivered-flagged count", delivered_flagged_count)
                restore_count = _optional_count("restore_count", "quarantine-restore count", restore_count)
            else:
                data_source = "Demo data (randomly generated)"
                emit("[Demo] No API key provided — generating demo detection data")
                records = generate_mock_detections(start_dt, end_dt, count=250)
                total_scanned = generate_mock_scanned_count(len(records))
                restore_count = generate_mock_restore_count(len(records))
                delivered_flagged_count = generate_mock_delivered_flagged_count(total_scanned)
                emit(f"[Demo] {len(records):,} sample detections generated")

            period_start_str, period_end_str = f"{start_dt:%Y-%m-%d}", f"{end_dt:%Y-%m-%d}"
            if dates_given:
                _warn_period_vs_data(records, start_dt, end_dt, emit)
            emit("[Analysis] Categorizing threats and applying cost model...")
            data = build_report_data(
                records=records,
                customer_name=customer_name,
                period_start=period_start_str,
                period_end=period_end_str,
                total_scanned=total_scanned,
                restore_count=restore_count,
                delivered_flagged_count=delivered_flagged_count,
            )
            data.data_source = data_source
            data.outbound = outbound_summary
            emit(f"[Analysis] {len(data.category_lines)} threat categories, ${data.total_saved:,.0f} estimated value protected")

            emit("[Report] Rendering executive report and efficacy dashboard...")
            generated_on = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
            html = render_template(
                "report.html",
                data=data,
                generated_on=generated_on,
                ic3_source=IC3_SOURCE,
            )
            dashboard_html = render_template(
                "efficacy_dashboard.html",
                data=data,
                generated_on=generated_on,
            )

            jobs[job_id]["status"] = "done"
            jobs[job_id]["report_html"] = html
            jobs[job_id]["dashboard_html"] = dashboard_html
            jobs[job_id]["summary"] = {
                "total_blocked": data.total_blocked,
                "total_saved": round(data.total_saved),
                "block_rate": round(data.block_rate, 2) if data.block_rate is not None else None,
                "false_positive_rate": round(data.false_positive_rate, 2) if data.false_positive_rate is not None else None,
            }
            emit("[Report] Done")

        except ValueError as e:
            emit(f"[ERROR] {e}")
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"] = str(e)
        except VisionOneAPIError as e:
            emit(f"[ERROR] Vision One API error {e.status_code}: {e.message}")
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"] = f"Vision One API error {e.status_code}: {e.message}"
        except Exception as e:  # noqa: BLE001 - surface unexpected errors to the UI
            emit(f"[ERROR] {e}")
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"] = str(e)


# ---------------------------------------------------------------- routes

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/test-connection", methods=["POST"])
def test_connection():
    """Verify an API key + region can reach Vision One before running a job."""
    payload = request.get_json(silent=True) or {}
    api_key = (payload.get("api_key") or "").strip()
    region = payload.get("region", "us")

    if not api_key:
        return jsonify(ok=False, message="Enter an API key first."), 400

    try:
        client = VisionOneClient(api_key=api_key, region=region)
        client.test_connection()
        return jsonify(ok=True, message=f"Connected to Vision One ({region.upper()}).")
    except VisionOneAPIError as e:
        if e.status_code in (401, 403):
            return jsonify(ok=False, message="Authentication failed — check the API key and its Search permission."), 200
        return jsonify(ok=False, message=f"Vision One API error {e.status_code}: {e.message}"), 200
    except ValueError as e:
        return jsonify(ok=False, message=str(e)), 200
    except Exception as e:  # noqa: BLE001
        return jsonify(ok=False, message=f"Connection failed: {e}"), 200


@app.route("/run", methods=["POST"])
def run():
    # multipart/form-data, not JSON -- CSV mode needs a file upload, and
    # request.files only populates for form-encoded bodies.
    payload = request.form.to_dict()

    if not (payload.get("customer_name") or "").strip():
        return jsonify(error="Customer name is required."), 400
    if payload.get("mode") != "csv" and (not payload.get("period_start") or not payload.get("period_end")):
        return jsonify(error="Period start and end are required for live API and demo runs."), 400
    if payload.get("mode") == "live" and not (payload.get("api_key") or "").strip():
        return jsonify(error="An API key is required for a live Vision One pull."), 400
    if payload.get("mode") == "csv":
        csv_files = [f for f in request.files.getlist("csv_file") if f and f.filename]
        if not csv_files:
            return jsonify(error="At least one CSV file is required for CSV import mode."), 400
        # One log type + direction per file, sent in the same order as the files.
        file_kinds = request.form.getlist("csv_kind")
        file_dirs = request.form.getlist("csv_direction")
        if len(file_kinds) != len(csv_files) or len(file_dirs) != len(csv_files):
            return jsonify(error="Choose a log type and a direction for every uploaded file."), 400
        for f, k, d in zip(csv_files, file_kinds, file_dirs):
            if k not in (KIND_POLICY_EVENTS, KIND_MAIL_TRACKING):
                return jsonify(error=f"{f.filename}: choose whether it is a policy event log or a mail tracking log."), 400
            if d not in (DIRECTION_INBOUND, DIRECTION_OUTBOUND):
                return jsonify(error=f"{f.filename}: choose whether it is incoming or outgoing mail."), 400
        # Read into memory now -- the FileStorage's underlying stream isn't
        # safe to touch after this request ends, but the job runs in a
        # background thread. Kept as raw bytes (not decoded here) so
        # parse_csv_upload can detect UTF-16 vs UTF-8 itself -- Vision
        # One's own exports are UTF-16, not the UTF-8 a decode here would
        # assume.
        payload["csv_files"] = [
            (f.filename, f.read(), k, d) for f, k, d in zip(csv_files, file_kinds, file_dirs)
        ]

    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {
        "status": "running",
        "log": [],
        "report_html": None,
        "dashboard_html": None,
        "error": None,
        "summary": None,
    }

    t = threading.Thread(target=run_report_job, args=(job_id, payload), daemon=True)
    t.start()

    return jsonify(job_id=job_id)


@app.route("/status/<job_id>")
def status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify(error="Job not found"), 404
    # Don't ship the full report HTML through the polling endpoint
    return jsonify(
        status=job["status"],
        log=job["log"],
        error=job["error"],
        summary=job["summary"],
    )


@app.route("/report/<job_id>")
def report(job_id):
    job = jobs.get(job_id)
    if not job or not job.get("report_html"):
        return "Report not ready", 404
    return job["report_html"]


@app.route("/report/<job_id>/dashboard")
def dashboard(job_id):
    job = jobs.get(job_id)
    if not job or not job.get("dashboard_html"):
        return "Dashboard not ready", 404
    return job["dashboard_html"]


@app.route("/report/<job_id>/download")
def download_report(job_id):
    job = jobs.get(job_id)
    if not job or not job.get("report_html"):
        return "Report not ready", 404
    return Response(
        job["report_html"],
        mimetype="text/html",
        headers={"Content-Disposition": "attachment; filename=CEGP_report.html"},
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
