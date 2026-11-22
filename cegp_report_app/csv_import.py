"""
csv_import.py

Fallback data path for when the Vision One API isn't reachable: parse CEGP
CSV exports into the same shapes the live API path produces, so
report_builder needs no CSV-specific branch.

Two kinds of export are understood, and each uploaded file is classified
automatically (see _classify):

  * Policy event log -- one row per policy/filter hit (Threat Type, Rule
    Name, Action...). Every row carries a threat, whatever the action
    (Quarantined, Deleted, Bypassed, Passed...). Rows become DetectionRecords,
    exactly like search/detections results.

  * Mail tracking log -- one row per message (Timestamp, Sender, Recipient,
    Subject, Last Action / Status, Details...). Most rows are clean,
    delivered mail. This is what the live path pulls from
    search/emailActivities + audit/logs, so it yields the mail-flow
    numbers: delivered volume (the block-rate denominator), delivered-but-
    flagged, and released/restored messages (the false-positive proxy).
    Blocked rows also become DetectionRecords, used only when no policy
    event log was uploaded alongside it.

Column names are matched case-insensitively and tolerate a handful of
common export aliases (see _HEADER_ALIASES) rather than requiring an exact
Vision One field name.
"""

from __future__ import annotations

import codecs
import csv
import datetime as dt
import io
from collections import Counter
from dataclasses import dataclass, field

from cost_reference import categorize
from vision_one_client import DetectionRecord

# Aliases are ordered tuples, tried first to last, so the column used is
# deterministic when a file has several candidates. CEGP's own event-log
# export has "Threat Type" (Spam, Phishing, Malware...), "Threat Name"
# (mostly "-") and "Rule Name" ("Organization: Spam or Phish") -- the
# Threat Type column is the one that carries the category, so it wins.
_HEADER_ALIASES = {
    "threat": (
        "threattype", "threat", "threatname", "policy", "policyname",
        "filter", "filtername", "malname", "detection", "rule", "rulename",
    ),
    "action": (
        "action", "act", "lastaction", "lastknownaction", "finalaction",
        "lastknownstatus", "deliverystatus", "messagestatus", "status",
        "disposition",
    ),
    "time": (
        "timestamp", "time", "detectedtime", "date", "datetime",
        "receivedtime", "mailreceivedtime",
    ),
    "sender": ("sender", "from", "suser", "fromaddress", "envelopesender"),
    "recipient": ("recipients", "recipient", "to", "mailbox", "toaddress", "enveloperecipient"),
    "subject": ("subject", "mailsubject"),
    "simulation": ("simulation", "simulated", "testmode"),
    "direction": ("direction", "maildirection", "trafficdirection"),
    "details": ("details", "detail", "reason", "description", "lastactiondetails"),
    "messageid": ("messageid", "internetmessageid", "msguuid", "uuid", "mailmsgid"),
}

# Headers that only a mail tracking export has -- a policy event log never
# carries a per-message delivery status or direction.
_TRACKING_HINT_HEADERS = {
    "lastaction", "lastknownaction", "lastknownstatus", "deliverystatus",
    "messagestatus", "finalaction",
}
# A direction column is NOT a tracking-only signal -- policy event logs can
# carry one too -- so it's deliberately not in the set above.

# Extra columns used only to sharpen a generic Threat Type such as
# "Domain-based Authentication" (subtype "SPF" / "DKIM" / "DMARC - SPF").
_DETAIL_ALIASES = ("subtype", "threatname", "rulename")

# Event-log columns kept as-is so the report can break threats down the
# same way the Vision One console's Threats widget does.
_CONSOLE_COLUMNS = {
    "consoleThreatType": "threattype",
    "consoleSubtype": "subtype",
    "detectedBy": "detectedby",
}

# Mail tracking statuses (first comma-separated part, lower-cased).
_TRACKING_BLOCKED = {
    "block", "blocked", "quarantine", "quarantined", "delete", "deleted",
    "reject", "rejected", "drop", "dropped", "reset", "terminate",
}
_TRACKING_DELIVERED = {
    "deliver", "delivered", "pass", "passed", "accept", "accepted",
    "allow", "allowed", "bypass", "bypassed", "relayed", "sent",
    "no action", "tagged", "subject tagged", "redirect", "redirected",
}
_TRACKING_RESTORED = {
    "release", "released", "restore", "restored", "released from quarantine",
}

KIND_POLICY_EVENTS = "policy_events"
KIND_MAIL_TRACKING = "mail_tracking"
DIRECTION_INBOUND = "inbound"
DIRECTION_OUTBOUND = "outbound"
DIRECTION_LABELS = {DIRECTION_INBOUND: "incoming", DIRECTION_OUTBOUND: "outgoing"}
KIND_LABELS = {
    KIND_POLICY_EVENTS: "policy event log",
    KIND_MAIL_TRACKING: "mail tracking log",
}

_TIME_FORMATS = (
    "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y",  "%Y-%m-%d",
    # Vision One console exports: "Nov 19, 2026 22:21:33"
    "%b %d, %Y %H:%M:%S", "%b %d, %Y %I:%M:%S %p", "%b %d, %Y %H:%M", "%B %d, %Y %H:%M:%S",
)


@dataclass
class MailTrackingSummary:
    """Mail-flow counts from a mail tracking export (inbound rows only)."""
    total_rows: int = 0
    blocked: int = 0
    delivered: int = 0
    delivered_flagged: int = 0
    restored: int = 0
    other: int = 0
    status_counts: Counter = field(default_factory=Counter)

    def merge(self, other: "MailTrackingSummary") -> None:
        self.total_rows += other.total_rows
        self.blocked += other.blocked
        self.delivered += other.delivered
        self.delivered_flagged += other.delivered_flagged
        self.restored += other.restored
        self.other += other.other
        self.status_counts.update(other.status_counts)


@dataclass
class CsvUpload:
    filename: str
    kind: str
    records: list[DetectionRecord]
    tracking: MailTrackingSummary | None = None
    rows_read: int = 0
    rows_outside_period: int = 0
    duplicates: int = 0
    direction: str = "inbound"
    detected_kind: str | None = None
    has_direction_column: bool = False
    other_direction_skipped: int = 0
    first_time: dt.datetime | None = None
    last_time: dt.datetime | None = None

    @property
    def kind_label(self) -> str:
        return KIND_LABELS.get(self.kind, self.kind)


# ---------------------------------------------------------------- helpers

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
        # ISO with Z / fractional seconds / offset -- compare as naive UTC.
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo:
            parsed = parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        return None


def _iso_time(value: str) -> str:
    """Export timestamps are US-style ("11/16/2026 18:09:53"); the report
    groups by day and week on an ISO date prefix, so convert when possible."""
    parsed = _parse_time(value)
    return parsed.strftime("%Y-%m-%dT%H:%M:%S") if parsed else value


def _decode_csv_bytes(raw: bytes) -> str:
    """Vision One's own "Ad Hoc Query" / mail-tracking exports are UTF-16
    with a byte-order mark and tab-delimited -- not the UTF-8 comma-CSV a
    hand-built spreadsheet would produce. Detect and handle both."""
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
    """Strip a cell and treat the export's "-" placeholder as empty."""
    value = (value or "").strip()
    return "" if value in ("-", "--", "N/A", "n/a") else value


def _normalize(header: str) -> str:
    return header.strip().lower().replace(" ", "").replace("-", "").replace("_", "")


def _build_column_map(fieldnames: list[str]) -> dict[str, str]:
    """canonical field -> actual CSV column name present in this file."""
    normalized = {_normalize(f): f for f in fieldnames if f}
    column_map = {}
    for canonical, aliases in _HEADER_ALIASES.items():
        for alias in aliases:
            if alias in normalized:
                column_map[canonical] = normalized[alias]
                break
    return column_map


def _read_rows(raw: bytes | str) -> tuple[list[str], list[dict]]:
    csv_text = _decode_csv_bytes(raw) if isinstance(raw, bytes) else raw
    delimiter = _sniff_delimiter(csv_text[:2000])
    reader = csv.DictReader(io.StringIO(csv_text), delimiter=delimiter)
    if not reader.fieldnames:
        raise ValueError("CSV file appears to be empty.")
    return list(reader.fieldnames), list(reader)


def _classify(fieldnames: list[str], rows: list[dict], column_map: dict[str, str]) -> str:
    """Policy event log vs mail tracking log.

    A policy event log has a threat on (nearly) every row; a mail tracking
    log is mostly clean mail, often has no threat column at all, and
    usually carries a delivery-status or direction column."""
    normalized = {_normalize(f) for f in fieldnames if f}
    # A CECP (Email and Collaboration Protection) detection-log export has
    # these together; it isn't gateway data and would otherwise be misread
    # as a mail tracking log (it also has "Mail direction").
    if {"scansource", "securityfilter"} <= normalized or "risklevel(virtualanalyzer)" in normalized:
        raise ValueError(
            "This is a Cloud Email and Collaboration Protection (CECP) detection log, not a CEGP "
            "gateway export. Upload it to the CECP report app (http://localhost:5001) instead."
        )
    if normalized & _TRACKING_HINT_HEADERS:
        return KIND_MAIL_TRACKING
    if "threat" not in column_map:
        if "action" in column_map:
            return KIND_MAIL_TRACKING
        raise ValueError(
            "Couldn't recognize this CSV. A policy event log needs a threat/"
            "policy/rule column (e.g. 'Threat Type', 'Rule Name'); a mail "
            "tracking log needs a status/action column (e.g. 'Last Action')."
        )
    if not rows:
        return KIND_POLICY_EVENTS
    with_threat = sum(1 for r in rows if _clean(r.get(column_map["threat"])))
    return KIND_POLICY_EVENTS if with_threat / len(rows) >= 0.9 else KIND_MAIL_TRACKING


def _threat_label(row: dict, column_map: dict[str, str], detail_columns: list[str]) -> str:
    threat = _clean(row.get(column_map.get("threat", "")))
    if threat and categorize(threat) == "Other":
        # A generic type like "Domain-based Authentication" -- append the
        # subtype / threat name / rule so "SPF", "DKIM" or "DMARC" can be
        # recognized. Only done when the type alone doesn't categorize.
        details = [_clean(row.get(c)) for c in detail_columns]
        threat = " - ".join([threat] + [d for d in details if d])
    return threat


def _first_part(value: str) -> str:
    """Exports write actions like "Quarantined, Notification sent"; the
    first part is the disposition, the rest is a side effect."""
    return value.split(",")[0].strip()


# ---------------------------------------------------------------- parsing

def parse_csv_upload(
    raw: bytes | str,
    filename: str = "",
    period_start: dt.datetime | None = None,
    period_end: dt.datetime | None = None,
    seen: set | None = None,
    kind: str | None = None,
    direction: str = DIRECTION_INBOUND,
) -> CsvUpload:
    """Parse one uploaded export, classify it, and keep only rows inside
    [period_start, period_end] (rows whose time can't be parsed are kept).

    `seen` is shared across every file in one run so the same event
    exported twice (overlapping date ranges, a period split into several
    exports to get under the console's row limit, the same file uploaded
    twice) is counted once. The key is the whole row keyed by normalized
    header name, so reordered columns still match; exports with a
    different column SET won't be de-duplicated against each other.

    `kind` / `direction` are what the user said the file is. The user's
    kind wins; the auto-detected kind is still recorded (detected_kind)
    so a mismatch can be flagged in the run log. When the file has a
    direction column, rows of the other direction are skipped."""
    seen = seen if seen is not None else set()
    fieldnames, rows = _read_rows(raw)
    column_map = _build_column_map(fieldnames)
    try:
        detected_kind = _classify(fieldnames, rows, column_map)
    except ValueError as e:
        # Always reject a CECP export; otherwise trust the user's choice.
        if kind is None or "Collaboration Protection" in str(e):
            raise
        detected_kind = None  # unrecognizable layout, but the user told us what it is
    kind = kind or detected_kind
    if kind == KIND_POLICY_EVENTS and "threat" not in column_map:
        raise ValueError(
            "Marked as a policy event log, but no threat/policy/rule column was found "
            "(e.g. 'Threat Type', 'Rule Name'). Is it a mail tracking log?"
        )
    if kind == KIND_MAIL_TRACKING and "action" not in column_map:
        raise ValueError(
            "Marked as a mail tracking log, but no status/action column was found "
            "(e.g. 'Last Action', 'Status'). Is it a policy event log?"
        )

    normalized_headers = {_normalize(f): f for f in fieldnames if f}
    detail_columns = [
        normalized_headers[a] for a in _DETAIL_ALIASES
        if a in normalized_headers and normalized_headers[a] != column_map.get("threat")
    ]

    upload = CsvUpload(
        filename=filename, kind=kind, records=[], rows_read=len(rows),
        direction=direction, detected_kind=detected_kind,
        has_direction_column="direction" in column_map,
    )
    if kind == KIND_MAIL_TRACKING:
        upload.tracking = MailTrackingSummary()

    for row in rows:
        row_direction = _clean(row.get(column_map.get("direction", ""))).lower()
        if row_direction:
            is_out = "out" in row_direction
            is_in = row_direction.startswith("in") and "internal" not in row_direction
            if (direction == DIRECTION_INBOUND and is_out) or (direction == DIRECTION_OUTBOUND and is_in):
                upload.other_direction_skipped += 1
                continue

        when = _parse_time(_clean(row.get(column_map.get("time", ""))))
        if when is not None:
            if (period_start and when < period_start) or (period_end and when > period_end):
                upload.rows_outside_period += 1
                continue
            upload.first_time = min(filter(None, (upload.first_time, when)))
            upload.last_time = max(filter(None, (upload.last_time, when)))

        # Every column, by normalized header (so column order doesn't
        # matter). A subset-of-fields key wrongly merges rows that differ
        # only in a column we don't map (attachment hash, rule, etc.).
        key = (kind,) + tuple(sorted(
            (_normalize(h), _clean(v)) for h, v in row.items() if h and isinstance(v, str)
        ))
        if key in seen:
            upload.duplicates += 1
            continue
        seen.add(key)

        threat = _threat_label(row, column_map, detail_columns)
        action = _first_part(_clean(row.get(column_map.get("action", ""))))

        if kind == KIND_MAIL_TRACKING:
            details = _clean(row.get(column_map.get("details", "")))
            if not threat and details and categorize(details) != "Other":
                threat = details
            status = action.lower()
            t = upload.tracking
            t.total_rows += 1
            t.status_counts[action or "(blank)"] += 1
            if status in _TRACKING_RESTORED:
                # Quarantined first, then released -- it was a block, and
                # the release is the false-positive signal.
                t.restored += 1
                t.blocked += 1
                action = "quarantined"
            elif status in _TRACKING_BLOCKED:
                t.blocked += 1
            elif status in _TRACKING_DELIVERED or not status:
                t.delivered += 1
                if threat:
                    t.delivered_flagged += 1
                # Delivered mail is counted in the mail-flow numbers, not
                # as a detection -- otherwise it would be counted twice.
                continue
            else:
                t.other += 1  # bounced / deferred / pending etc.
                continue
            threat = threat or details or "Unclassified detection"
        elif not threat:
            continue

        simulation = _clean(row.get(column_map.get("simulation", ""))).lower() in ("1", "true", "yes")
        raw_record = {
            "malName": threat,
            "act": action or "blocked",
            "simulation": simulation,
            "mailReceivedTime": when.strftime("%Y-%m-%dT%H:%M:%S") if when else "",
            "suser": _clean(row.get(column_map.get("sender", ""))),
            "mailbox": _clean(row.get(column_map.get("recipient", ""))),
            "mailMsgSubject": _clean(row.get(column_map.get("subject", ""))),
            "msgUuid": _clean(row.get(column_map.get("messageid", ""))),
        }
        for key, header in _CONSOLE_COLUMNS.items():
            if header in normalized_headers:
                raw_record[key] = _clean(row.get(normalized_headers[header]))
        upload.records.append(DetectionRecord(raw=raw_record))

    return upload


def parse_csv_detections(raw: bytes | str) -> list[DetectionRecord]:
    """Backward-compatible helper: detection records from one export,
    no period filtering."""
    return parse_csv_upload(raw).records
