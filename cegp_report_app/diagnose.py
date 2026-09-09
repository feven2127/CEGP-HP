"""
diagnose.py
-----------
Standalone diagnostic for "0 records" live pulls. Run this locally --
the API key never leaves your machine or gets typed into chat.

Usage (PowerShell):
    $env:VISION_ONE_API_KEY = "your key here"
    $env:VISION_ONE_REGION  = "us"          # us/eu/sg/jp/au/in/mea
    $env:PERIOD_START       = "2026-07-14"  # keep inside the last 30 days
    $env:PERIOD_END         = "2026-08-13"
    python diagnose.py

Usage (bash):
    export VISION_ONE_API_KEY="your key here"
    export VISION_ONE_REGION="us"
    export PERIOD_START="2026-07-14"
    export PERIOD_END="2026-08-13"
    python diagnose.py

Paste back the printed output (counts only -- it contains no key, no
customer mail content) so we can pin down why live counts are 0.
"""

from __future__ import annotations

import datetime as dt
import os
import sys

from vision_one_client import VisionOneClient, VisionOneAPIError

api_key = os.environ.get("VISION_ONE_API_KEY", "").strip()
region = os.environ.get("VISION_ONE_REGION", "us").strip().lower()
period_start = os.environ.get("PERIOD_START", "").strip()
period_end = os.environ.get("PERIOD_END", "").strip()

if not api_key:
    print("ERROR: set VISION_ONE_API_KEY in your environment first (see docstring).")
    sys.exit(1)

try:
    start = dt.datetime.strptime(period_start, "%Y-%m-%d")
    end = dt.datetime.strptime(period_end, "%Y-%m-%d") + dt.timedelta(days=1, seconds=-1)
except ValueError:
    print("ERROR: set PERIOD_START and PERIOD_END as YYYY-MM-DD in your environment first.")
    sys.exit(1)

print(f"Region: {region}")
print(f"Window: {start} -> {end}  ({(end - start).days} days)")
print("-" * 60)

client = VisionOneClient(api_key=api_key, region=region)

def show(label, fn):
    try:
        result = fn()
        print(f"{label}: {result}")
    except VisionOneAPIError as e:
        print(f"{label}: FAILED -- HTTP {e.status_code}: {e.message}")
    except Exception as e:  # noqa: BLE001
        print(f"{label}: FAILED -- {e}")

show("1. Connection test (short window, sem detections)", client.test_connection)
show("2. CEGP (sem) detection count, blocking traffic", lambda: client.get_detection_count(start, end))
show("3. ANY product detection count (any pname)", lambda: client.probe_any_detections(start, end))
show("4. Per-product-code detection counts", lambda: client.probe_product_codes(start, end))
show("5. scanType values actually present for sem", lambda: client.probe_scan_types(start, end))
show("6. Total accepted/scanned mail count (sem)", lambda: client.get_total_scanned_count(start, end))
show("7. Delivered-but-flagged mail count (sem)", lambda: client.get_delivered_flagged_count(start, end))

print("-" * 60)
print("Done. Paste the block above back into the chat.")
