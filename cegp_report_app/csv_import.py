"""
csv_import.py

Fallback data path for when the Vision One API isn't reachable: parse a
CEGP mail-tracking / quarantine CSV export into the same DetectionRecord
shape the live API and demo-data paths already produce (see
vision_one_client.DetectionRecord and mock_data.generate_mock_detections),
so report_builder needs no CSV-specific branch.

Column names are matched case-insensitively and tolerate a handful of
common export aliases (see _HEADER_ALIASES) rather than requiring an exact
Vision One field name -- a customer's CEGP console export or a hand-built
spreadsheet is unlikely to use "malName" or "mailSmtpRecipients" verbatim.
Only a threat/policy-name column is required; everything else is optional
and degrades the same way a failed live API call does (missing fields left
blank, action defaults to "blocked" since that's what a quarantine/blocked-
mail export represents).
"""

from __future__ import annotations

import codecs
import csv
import io

from vision_one_client import DetectionRecord

_HEADER_ALIASES = {
    "threat": {
        "threat", "threatname", "threat_name", "policy", "policyname",
        "filter", "filtername", "malname", "detection", "rule", "rulename",
    },
    "action": {"action", "act", "status", "disposition"},
    "time": {
        "time", "detectedtime", "detected_time", "date", "datetime",
        "receivedtime", "mailreceivedtime",
    },
    "sender": {"sender", "from", "suser", "fromaddress"},
    "recipient": {"recipient", "to", "mailbox", "toaddress"},
    "subject": {"subject", "mailsubject"},
    "simulation": {"simulation", "simulated", "testmode"},
}


def _decode_csv_bytes(raw: bytes) -> str:
    """Vision One's own "Ad Hoc Query" / mail-tracking exports are UTF-16
    with a byte-order mark and tab-delimited -- not the UTF-8 comma-CSV a
    hand-built spreadsheet would produce. Decoding those as UTF-8 turns
    every other byte into a stray null character, so the header line never
    matches any known column name. Detect and handle both."""
    if raw.startswith(codecs.BOM_UTF8):
        return raw.decode("utf-8-sig")
    if raw[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE):
        return raw.decode("utf-16")
    if b"\x00" in raw[:400]:
        # No BOM but still UTF-16 (interleaved null bytes) -- little-endian
        # is the common case for Windows-generated exports without one.
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def _sniff_delimiter(sample: str) -> str:
    """Vision One's own exports are tab-delimited; a hand-built CSV is
    more likely comma-delimited. Sniff rather than assume either."""
    try:
        return csv.Sniffer().sniff(sample, delimiters=",\t;").delimiter
    except csv.Error:
        return ","


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


def parse_csv_detections(raw: bytes | str) -> list[DetectionRecord]:
    """Parse a blocked/quarantined-mail CSV export into DetectionRecord
    objects. Raises ValueError if the file has no recognizable threat/
    policy-name column -- everything downstream keys off that field for
    both the cost model (cost_reference.categorize) and the threat-type
    breakdown.

    Accepts raw upload bytes (preferred -- lets this function detect
    UTF-16 vs UTF-8 itself) or already-decoded text.
    """
    csv_text = _decode_csv_bytes(raw) if isinstance(raw, bytes) else raw
    delimiter = _sniff_delimiter(csv_text[:2000])
    reader = csv.DictReader(io.StringIO(csv_text), delimiter=delimiter)
    if not reader.fieldnames:
        raise ValueError("CSV file appears to be empty.")

    column_map = _build_column_map(reader.fieldnames)
    if "threat" not in column_map:
        raise ValueError(
            "CSV must have a threat/policy/filter name column "
            "(e.g. 'Threat', 'Policy', 'Filter Name')."
        )

    records: list[DetectionRecord] = []
    for row in reader:
        threat = (row.get(column_map["threat"]) or "").strip()
        if not threat:
            continue
        action = (row.get(column_map.get("action", "")) or "").strip() or "blocked"
        simulation = (row.get(column_map.get("simulation", "")) or "").strip().lower() in (
            "1", "true", "yes",
        )
        records.append(
            DetectionRecord(
                raw={
                    "malName": threat,
                    "act": action,
                    "simulation": simulation,
                    "mailReceivedTime": (row.get(column_map.get("time", "")) or "").strip(),
                    "suser": (row.get(column_map.get("sender", "")) or "").strip(),
                    "mailbox": (row.get(column_map.get("recipient", "")) or "").strip(),
                    "mailMsgSubject": (row.get(column_map.get("subject", "")) or "").strip(),
                }
            )
        )
    return records
