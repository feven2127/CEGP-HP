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

from flask import Flask, render_template, request, jsonify, Response

from vision_one_client import VisionOneClient, VisionOneAPIError
from report_builder import build_report_data
from cost_reference import IC3_SOURCE
from csv_import import parse_csv_detections
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


# ---------------------------------------------------------------- pipeline

def run_report_job(job_id: str, form: dict):
    job_log: list[str] = []

    def emit(msg: str):
        job_log.append(msg)
        jobs[job_id]["log"] = list(job_log)
        log.info(msg)

    with app.test_request_context():
        try:
            customer_name = (form.get("customer_name") or "").strip() or "Customer"
            period_start_str = form.get("period_start")
            period_end_str = form.get("period_end")
            mode = form.get("mode", "demo")

            emit(f"[Setup] Customer: {customer_name}")

            try:
                start_dt = dt.datetime.strptime(period_start_str, "%Y-%m-%d")
                end_dt = dt.datetime.strptime(period_end_str, "%Y-%m-%d") + dt.timedelta(
                    days=1, seconds=-1
                )
            except (TypeError, ValueError):
                raise ValueError("Please provide a valid start and end date.")

            if end_dt < start_dt:
                raise ValueError("Period end must be after period start.")

            emit(f"[Setup] Period: {period_start_str} to {period_end_str}")

            if mode == "live":
                api_key = (form.get("api_key") or "").strip()
                region = form.get("region", "us")
                if not api_key:
                    raise ValueError("An API key is required for a live Vision One pull.")

                client = VisionOneClient(api_key=api_key, region=region)

                emit(f"[Vision One] Connecting to region '{region.upper()}'...")
                emit("[Vision One] Pulling CEGP detections (search/detections)...")
                try:
                    expected_total = client.get_detection_count(start_dt, end_dt)
                    if expected_total >= 10_000:
                        emit(
                            f"[Vision One] Vision One's own count reports at least {expected_total:,} "
                            "detections for this period — note this count can itself be capped the same "
                            "way paging is, so the real total may be higher. Splitting the period into "
                            "smaller time windows to retrieve everything (this takes longer)..."
                        )
                except VisionOneAPIError:
                    pass  # non-fatal -- the pull below will still be attempted
                records = client.get_cegp_detections(start_dt, end_dt)
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
                try:
                    total_scanned = client.get_total_scanned_count(start_dt, end_dt)
                    emit(f"[Vision One] {total_scanned:,} inbound messages scanned")
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
                emit("[CSV] Parsing uploaded detection export...")
                records = parse_csv_detections(form.get("csv_bytes") or b"")
                emit(f"[CSV] {len(records):,} detection rows parsed")
                if len(records) == 0:
                    raise ValueError(
                        "No usable rows found in the CSV — check that it has a "
                        "threat/policy name column with values."
                    )

                def _optional_count(key: str, label: str) -> int | None:
                    raw = (form.get(key) or "").strip().replace(",", "")
                    if not raw:
                        emit(f"[CSV] No {label} provided — related rate will show as N/A")
                        return None
                    try:
                        value = int(raw)
                    except ValueError:
                        emit(f"[WARN] {label} value '{raw}' is not a number — ignoring")
                        return None
                    emit(f"[CSV] Using provided {label}: {value:,}")
                    return value

                total_scanned = _optional_count("total_scanned", "total inbound scanned count")
                delivered_flagged_count = _optional_count("delivered_flagged_count", "delivered-flagged count")
                restore_count = _optional_count("restore_count", "quarantine-restore count")
            else:
                emit("[Demo] No API key provided — generating demo detection data")
                records = generate_mock_detections(start_dt, end_dt, count=250)
                total_scanned = generate_mock_scanned_count(len(records))
                restore_count = generate_mock_restore_count(len(records))
                delivered_flagged_count = generate_mock_delivered_flagged_count(total_scanned)
                emit(f"[Demo] {len(records):,} sample detections generated")

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
    if not payload.get("period_start") or not payload.get("period_end"):
        return jsonify(error="Period start and end are required."), 400
    if payload.get("mode") == "live" and not (payload.get("api_key") or "").strip():
        return jsonify(error="An API key is required for a live Vision One pull."), 400
    if payload.get("mode") == "csv":
        csv_file = request.files.get("csv_file")
        if not csv_file or not csv_file.filename:
            return jsonify(error="A CSV file is required for CSV import mode."), 400
        # Read into memory now -- the FileStorage's underlying stream isn't
        # safe to touch after this request ends, but the job runs in a
        # background thread. Kept as raw bytes (not decoded here) so
        # parse_csv_detections can detect UTF-16 vs UTF-8 itself -- Vision
        # One's own exports are UTF-16, not the UTF-8 a decode here would
        # assume.
        payload["csv_bytes"] = csv_file.read()

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
