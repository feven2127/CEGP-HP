"""
CECP Executive Report Generator
-------------------------------
Flask app that turns Trend Vision One Cloud Email and Collaboration
Protection (CECP) detections -- from the live API, uploaded CECP log
exports, or built-in demo data -- into a customer-facing executive value
report and an efficacy dashboard.

Sister project of cegp_report_app (same layout and methodology). Runs on
port 5001 so both apps can run side by side.

Run:
    pip install -r requirements.txt
    python app.py
Then open http://localhost:5001
"""

from __future__ import annotations

import datetime as dt
import logging
import threading
import uuid

from flask import Flask, Response, jsonify, render_template, request

from cecp_client import CECPClient, VisionOneAPIError
from cost_reference import IC3_SOURCE, unmapped_subtypes
from csv_import import parse_csv_upload
from mock_data import (
    generate_mock_detections,
    generate_mock_restore_count,
    generate_mock_scanned_email_count,
    generate_mock_scanned_file_count,
)
from report_builder import build_report_data

PORT = 5001

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

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
            dates_given = start_dt is not None and end_dt is not None
            if dates_given:
                emit(f"[Setup] Period: {start_dt:%Y-%m-%d} to {end_dt:%Y-%m-%d}")
            else:
                emit("[Setup] No period entered — it will be taken from the dates in the uploaded files")

            emails_scanned = files_scanned = restore_count = None
            action_column_missing = False

            if mode == "live":
                api_key = (form.get("api_key") or "").strip()
                region = form.get("region", "us")
                if not api_key:
                    raise ValueError("An API key is required for a live Vision One pull.")
                client = CECPClient(api_key=api_key, region=region)
                data_source = f"Trend Vision One API ({region.upper()}), productCode:sca"
                emit(f"[Vision One] Connecting to region '{region.upper()}'...")
                emit("[Vision One] Pulling CECP detections (search/detections, productCode:sca)...")
                records = client.get_cecp_detections(start_dt, end_dt, progress=emit)
                emit(f"[Vision One] {len(records):,} CECP detections retrieved")

                try:
                    breakdown = client.get_scan_type_breakdown(start_dt, end_dt)
                    emit(f"[Diagnose] scanType values seen (used to infer the protected service): {breakdown}")
                except VisionOneAPIError as e:
                    emit(f"[WARN] scanType diagnostic failed ({e.status_code}) — skipping")

                emit("[Vision One] Counting scanned mailbox email (search/emailActivities)...")
                try:
                    emails_scanned = client.get_scanned_email_count(start_dt, end_dt)
                    emit(f"[Vision One] {emails_scanned:,} emails scanned by CECP")
                except VisionOneAPIError as e:
                    emit(f"[WARN] Scanned-email lookup failed ({e.status_code}) — prevalence will show as N/A")

                emit("[Vision One] Pulling quarantine-restore audit logs (audit/logs)...")
                try:
                    restore_count = client.get_quarantine_restore_count(start_dt, end_dt)
                    emit(f"[Vision One] {restore_count:,} restores performed through Vision One")
                except VisionOneAPIError as e:
                    emit(f"[WARN] Audit-log lookup failed ({e.status_code}) — false-positive rate will show as N/A")

            elif mode == "csv":
                csv_files = form.get("csv_files") or []
                emit(f"[CSV] Parsing {len(csv_files)} uploaded file(s)...")
                records, seen, total_duplicates = [], set(), 0
                has_restore_column = False
                uploads: list = []
                for filename, raw in csv_files:
                    try:
                        upload = parse_csv_upload(raw, filename, start_dt, end_dt, seen)
                        uploads.append(upload)
                    except ValueError as e:
                        raise ValueError(f"{filename}: {e}") from e
                    span = f", {upload.first_time:%Y-%m-%d} to {upload.last_time:%Y-%m-%d}" if upload.first_time else ""
                    emit(f"[CSV] {filename}: {upload.rows_read:,} rows read{span} — {len(upload.records):,} detections kept")
                    emit(f"[Diagnose]   Columns matched: {upload.columns_used}")
                    if "action" not in (upload.columns_used or {}):
                        action_column_missing = True
                        emit(f"[WARN]   {filename} has no Action column — detections can't be counted as remediated")
                    if "restored" in (upload.columns_used or {}):
                        has_restore_column = True
                    if "service" not in (upload.columns_used or {}):
                        emit(f"[WARN]   {filename} has no Scan source / service column — service breakdown will be limited")
                    if upload.rows_outside_period:
                        emit(f"[CSV]   {upload.rows_outside_period:,} row(s) outside the selected period skipped")
                    if upload.duplicates:
                        emit(f"[CSV]   {upload.duplicates:,} row(s) already seen in an earlier file skipped (duplicate)")
                    total_duplicates += upload.duplicates
                    if upload.rows_without_threat:
                        emit(f"[CSV]   {upload.rows_without_threat:,} row(s) with no threat/filter value skipped")
                    records.extend(upload.records)
                emit(
                    f"[CSV] Consolidated {len(csv_files)} file(s) into one data set: "
                    f"{len(records):,} unique detections, {total_duplicates:,} duplicate row(s) removed"
                )
                data_source = (
                    f"{len(csv_files)} uploaded CECP detection log export(s), consolidated and de-duplicated: "
                    + ", ".join(n for n, _ in csv_files)
                )
                start_dt, end_dt = _fill_period_from_data(start_dt, end_dt, uploads, emit)
                info = [r for r in records if r.is_informational]
                if info:
                    clean = sum(1 for r in info if r.informational_kind == "sandbox_clean")
                    emit(
                        f"[CSV] {len(info):,} row(s) are not threats and are excluded from threat figures: "
                        f"{clean:,} Virtual Analyzer analyses with no risk, {len(info) - clean:,} unscannable file(s)/URL(s)"
                    )
                emit(f"[CSV] {len(records) - len(info):,} threat detection(s) remain for the report")
                if has_restore_column:
                    restore_count = sum(1 for r in records if r.was_restored)
                    emit(f"[CSV] {restore_count:,} detection(s) have a 'Reason for restoration' — used as the false-positive count")
                if not records:
                    raise ValueError("No usable detections found in the CSV(s) for the selected period — check the dates and that the export includes a threat column.")
            else:
                data_source = "Demo data (randomly generated)"
                emit("[Demo] Generating sample CECP detections across mailboxes and collaboration apps")
                records = generate_mock_detections(start_dt, end_dt)
                email_n = sum(1 for r in records if r.channel == "Email")
                emails_scanned = generate_mock_scanned_email_count(email_n)
                files_scanned = generate_mock_scanned_file_count(len(records) - email_n)
                restore_count = generate_mock_restore_count(sum(1 for r in records if r.was_blocked))
                emit(f"[Demo] {len(records):,} sample detections generated")

            def _override(key: str, label: str, current):
                raw = (form.get(key) or "").strip().replace(",", "")
                if not raw:
                    return current
                try:
                    value = int(raw)
                except ValueError:
                    emit(f"[WARN] {label} value '{raw}' is not a number — ignoring")
                    return current
                emit(f"[Input] Using manually entered {label}: {value:,}")
                return value

            emails_scanned = _override("emails_scanned", "emails scanned", emails_scanned)
            files_scanned = _override("files_scanned", "files scanned", files_scanned)
            restore_count = _override("restore_count", "quarantine-restore count", restore_count)

            period_start_str, period_end_str = f"{start_dt:%Y-%m-%d}", f"{end_dt:%Y-%m-%d}"
            if dates_given:
                _warn_period_vs_data(records, start_dt, end_dt, emit)
            emit("[Analysis] Categorizing threats by service and applying the IC3 cost model...")
            data = build_report_data(
                records=records,
                customer_name=customer_name,
                period_start=period_start_str,
                period_end=period_end_str,
                emails_scanned=emails_scanned,
                files_scanned=files_scanned,
                restore_count=restore_count,
                data_source=data_source,
                action_column_missing=action_column_missing,
            )
            emit(
                f"[Analysis] {data.total_remediated:,} of {data.total_detections:,} detections remediated across "
                f"{len(data.service_breakdown)} service(s); ${data.total_saved:,.0f} estimated loss avoided"
            )

            emit("[Report] Rendering executive report and efficacy dashboard...")
            generated_on = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
            ctx = dict(data=data, generated_on=generated_on, ic3_source=IC3_SOURCE, unmapped_subtypes=unmapped_subtypes())
            jobs[job_id].update(
                status="done",
                report_html=render_template("report.html", **ctx),
                dashboard_html=render_template("efficacy_dashboard.html", **ctx),
                summary={
                    "total_blocked": data.total_remediated,
                    "total_saved": round(data.total_saved),
                    "block_rate": round(data.remediation_rate, 2) if data.remediation_rate is not None else None,
                    "false_positive_rate": round(data.false_positive_rate, 2) if data.false_positive_rate is not None else None,
                },
            )
            emit("[Report] Done")

        except ValueError as e:
            emit(f"[ERROR] {e}")
            jobs[job_id].update(status="error", error=str(e))
        except VisionOneAPIError as e:
            emit(f"[ERROR] Vision One API error {e.status_code}: {e.message}")
            jobs[job_id].update(status="error", error=f"Vision One API error {e.status_code}: {e.message}")
        except Exception as e:  # noqa: BLE001
            emit(f"[ERROR] {e}")
            jobs[job_id].update(status="error", error=str(e))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/test-connection", methods=["POST"])
def test_connection():
    payload = request.get_json(silent=True) or {}
    api_key = (payload.get("api_key") or "").strip()
    region = payload.get("region", "us")
    if not api_key:
        return jsonify(ok=False, message="Enter an API key first."), 400
    try:
        CECPClient(api_key=api_key, region=region).test_connection()
        return jsonify(ok=True, message=f"Connected to Vision One ({region.upper()}).")
    except VisionOneAPIError as e:
        if e.status_code in (401, 403):
            return jsonify(ok=False, message="Authentication failed — check the API key and its Search permission.")
        return jsonify(ok=False, message=f"Vision One API error {e.status_code}: {e.message}")
    except Exception as e:  # noqa: BLE001
        return jsonify(ok=False, message=f"Connection failed: {e}")


@app.route("/run", methods=["POST"])
def run():
    payload = request.form.to_dict()
    if not (payload.get("customer_name") or "").strip():
        return jsonify(error="Customer name is required."), 400
    if payload.get("mode") != "csv" and (not payload.get("period_start") or not payload.get("period_end")):
        return jsonify(error="Period start and end are required for live API and demo runs."), 400
    if payload.get("mode") == "live" and not (payload.get("api_key") or "").strip():
        return jsonify(error="An API key is required for a live Vision One pull."), 400
    if payload.get("mode") == "csv":
        files = [f for f in request.files.getlist("csv_file") if f and f.filename]
        if not files:
            return jsonify(error="At least one CSV file is required for CSV import mode."), 400
        # Read now: the upload stream isn't usable after this request ends.
        payload["csv_files"] = [(f.filename, f.read()) for f in files]

    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {"status": "running", "log": [], "report_html": None, "dashboard_html": None, "error": None, "summary": None}
    threading.Thread(target=run_report_job, args=(job_id, payload), daemon=True).start()
    return jsonify(job_id=job_id)


@app.route("/status/<job_id>")
def status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify(error="Job not found"), 404
    return jsonify(status=job["status"], log=job["log"], error=job["error"], summary=job["summary"])


@app.route("/report/<job_id>")
def report(job_id):
    job = jobs.get(job_id)
    return job["report_html"] if job and job.get("report_html") else ("Report not ready", 404)


@app.route("/report/<job_id>/dashboard")
def dashboard(job_id):
    job = jobs.get(job_id)
    return job["dashboard_html"] if job and job.get("dashboard_html") else ("Dashboard not ready", 404)


@app.route("/report/<job_id>/download")
def download_report(job_id):
    job = jobs.get(job_id)
    if not job or not job.get("report_html"):
        return "Report not ready", 404
    return Response(job["report_html"], mimetype="text/html",
                    headers={"Content-Disposition": "attachment; filename=CECP_report.html"})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=PORT, threaded=True)
