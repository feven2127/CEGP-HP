"""
csv_import.py  (CECP)

Parse Cloud Email and Collaboration Protection detection-log exports into
CECPRecords, so CSV mode feeds report_builder exactly like the live API.

The CECP console exports a consolidated "Detection logs" view (threat
protection and DLP together) or per-filter views, and the columns depend
on the "Manage Columns" layout -- there is no fixed header list. Columns
are therefore matched loosely on the console's facet names (Scan source,
Security filter, Threat type, Affected user, Action, ...) and common
aliases. Several files can be uploaded at once; exact duplicate rows
across files (e.g. "all logs" plus a DLP-only export) are dropped.
"""

from __future__ import annotations

import codecs
import csv
import datetime as dt
import io
from dataclasses import dataclass

from cecp_client import CECPRecord

_HEADER_ALIASES = {
    "time": (
        "detected", "detectedtime", "detectiontime", "date/time", "datetime",
        "timestamp", "time", "date", "eventtime", "generated", "loggedtime",
    ),
    "service": (
        "scansource", "service", "protectedservice", "cloudapp", "cloudapplication",
        "application", "app", "servicename", "source", "platform",
    ),
    "filter": (
        "securityfilter", "filter", "filtername", "detectedby", "scanner",
        "protectiontype", "scantype", "logtype",
    ),
    "threat": (
        "threattype", "threat", "threatname", "securityrisk", "securityriskname",
        "risk", "riskname", "detection", "detectionname", "detectiontype",
        "malwarename", "virusname", "violation", "violationtype", "rule", "rulename",
        "dlptemplate", "template",
    ),
    # Matched AFTER "threat", so in a real CECP export "Threat type" goes to
    # threat and "Security risk / Anomaly name" lands here.
    "riskname": (
        "securityrisk/anomalyname", "securityrisk/anomaly", "anomalyname",
        "securityriskname", "securityrisk", "riskname", "malwarename", "virusname",
    ),
    "detectedby": ("detectedby", "detectionengine", "engine"),
    "varisk": ("risklevel(virtualanalyzer)", "virtualanalyzerrisklevel", "varisklevel", "varisk"),
    "restored": ("reasonforrestoration", "restorationreason", "restorereason"),
    "action": ("action", "actiontaken", "act", "result", "actionresult", "status"),
    "user": ("affecteduser", "user", "mailbox", "owner", "account", "username", "affectedaccount"),
    "sender": ("sender", "from", "senderaddress", "fromaddress"),
    "recipient": ("recipient", "recipients", "to", "toaddress"),
    "subject": ("subject", "emailsubject", "mailsubject"),
    "file": ("filename", "file", "attachment", "attachmentname", "attachmentfilename", "objectname", "object"),
    "location": ("location", "folder", "path", "filepath", "site", "channel"),
    "policy": ("triggeredpolicy", "policy", "policyname"),
    "messageid": ("messageid", "internetmessageid", "msguuid"),
    "simulation": ("simulation", "simulated", "testmode"),
}

_TIME_FORMATS = (
    "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M %p", "%m/%d/%Y", "%Y-%m-%d",
    # CECP console exports: "Nov 19, 2026 22:21:33"
    "%b %d, %Y %H:%M:%S", "%b %d, %Y %I:%M:%S %p", "%b %d, %Y %H:%M", "%B %d, %Y %H:%M:%S",
)


@dataclass
class CsvUpload:
    filename: str
    records: list[CECPRecord]
    rows_read: int = 0
    rows_outside_period: int = 0
    rows_without_threat: int = 0
    duplicates: int = 0
    first_time: dt.datetime | None = None
    last_time: dt.datetime | None = None
    columns_used: dict | None = None


def _parse_time(value: str) -> dt.datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    for fmt in _TIME_FORMATS:
        try:
            return dt.datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo:
            parsed = parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        return None


def _decode_csv_bytes(raw: bytes) -> str:
    """Vision One exports are often UTF-16 + tab-delimited; hand-built
    files are UTF-8 + comma. Handle both."""
    if raw.startswith(codecs.BOM_UTF8):
        return raw.decode("utf-8-sig")
    if raw[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE):
        return raw.decode("utf-16")
    if b"\x00" in raw[:400]:
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def _sniff_delimiter(sample: str) -> str:
    try:
        return csv.Sniffer().sniff(sample, delimiters=",\t;").delimiter
    except csv.Error:
        return ","


def _clean(value) -> str:
    value = (value or "").strip()
    return "" if value in ("-", "--", "N/A", "n/a") else value


def _normalize(header: str) -> str:
    return header.strip().lower().replace(" ", "").replace("-", "").replace("_", "")


def _build_column_map(fieldnames: list[str]) -> dict[str, str]:
    normalized = {_normalize(f): f for f in fieldnames if f}
    column_map: dict[str, str] = {}
    used: set[str] = set()
    for canonical, aliases in _HEADER_ALIASES.items():
        for alias in aliases:
            col = normalized.get(alias)
            if col and col not in used:
                column_map[canonical] = col
                used.add(col)
                break
    return column_map


def parse_csv_upload(
    raw: bytes | str,
    filename: str = "",
    period_start: dt.datetime | None = None,
    period_end: dt.datetime | None = None,
    seen: set | None = None,
) -> CsvUpload:
    """Parse one CECP detection-log export. `seen` (shared across files in
    one run) drops exact duplicate rows."""
    text = _decode_csv_bytes(raw) if isinstance(raw, bytes) else raw
    reader = csv.DictReader(io.StringIO(text), delimiter=_sniff_delimiter(text[:2000]))
    if not reader.fieldnames:
        raise ValueError("CSV file appears to be empty.")
    cols = _build_column_map(list(reader.fieldnames))
    if "threat" not in cols and "filter" not in cols:
        raise ValueError(
            "Couldn't find a threat column. A CECP detection log needs a "
            "'Threat type' / 'Security risk' / 'Security filter' column."
        )

    def get(row, key):
        return _clean(row.get(cols.get(key, "")))

    upload = CsvUpload(filename=filename, records=[], columns_used=cols)
    seen = seen if seen is not None else set()
    for row in reader:
        upload.rows_read += 1
        threat, sec_filter = get(row, "threat"), get(row, "filter")
        if not threat and not sec_filter:
            upload.rows_without_threat += 1
            continue
        when = _parse_time(get(row, "time"))
        if when is not None:
            if (period_start and when < period_start) or (period_end and when > period_end):
                upload.rows_outside_period += 1
                continue
            upload.first_time = min(filter(None, (upload.first_time, when)))
            upload.last_time = max(filter(None, (upload.last_time, when)))

        # Key on EVERY column (by normalized header name, so column order
        # doesn't matter). CECP writes one row per analysed object -- the
        # same message can have many rows that differ only by SHA-1 / object
        # -- so a key on a subset of fields wrongly merges real detections.
        key = tuple(sorted((_normalize(h), _clean(v)) for h, v in row.items() if h and isinstance(v, str)))
        if key in seen:
            upload.duplicates += 1
            continue
        seen.add(key)

        upload.records.append(CECPRecord(raw={
            "threatType": threat,
            "securityFilter": sec_filter,
            "service": get(row, "service"),
            "act": get(row, "action"),
            "simulation": get(row, "simulation").lower() in ("1", "true", "yes"),
            "detectedDateTime": when.strftime("%Y-%m-%dT%H:%M:%S") if when else "",
            "affectedUser": get(row, "user") or get(row, "recipient"),
            "sender": get(row, "sender"),
            "mailMsgSubject": get(row, "subject"),
            "fileName": get(row, "file"),
            "location": get(row, "location"),
            "policyName": get(row, "policy"),
            "msgUuid": get(row, "messageid"),
            "riskName": get(row, "riskname"),
            "detectedBy": get(row, "detectedby"),
            "vaRisk": get(row, "varisk"),
            "restoreReason": get(row, "restored"),
        }))
    return upload
