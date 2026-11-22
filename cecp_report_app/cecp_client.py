"""
cecp_client.py

Cloud Email and Collaboration Protection (CECP, formerly Cloud App
Security) on top of the shared Vision One Search API client in
vision_one_client.py (copied unchanged from the CEGP app -- it supplies
the HTTP, paging, 10k-cap chunking, retry and audit-log machinery).

Product scoping: CECP is productCode "sca" on both detection data and
email activity data (KA-0015974; see the product-code table in
vision_one_client.py). CEGP is "sem" and is deliberately excluded.

What ProductIQ / the Vision One docs confirm (2026-11):
  - `act` / `actResult` carry the action (Quarantine, Delete, Block,
    Pass/Log, Redirect mail for approval...).
  - `fileName` / `attachmentFileName` carry the file; `mailbox`,
    `suser`, `duser` the affected user.
  - The protected service (Exchange Online, Gmail, OneDrive, SharePoint,
    Teams, Box, Dropbox, Google Drive) has NO documented dedicated field;
    `scanType` is the closest (example value "exchange"), and its full
    value list is undocumented. Service is therefore inferred from
    scanType plus any other field naming the app -- see CECPRecord.service
    -- and the run log prints the scanType values seen so the mapping can
    be checked against a real tenant.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter

from cost_reference import categorize, normalize_service, service_channel
from vision_one_client import (
    DETECTIONS_PATH,
    EMAIL_ACTIVITIES_PATH,
    DetectionRecord,
    VisionOneAPIError,  # noqa: F401  (re-exported for app.py)
    VisionOneClient,
)

CECP_PRODUCT_CODE = "sca"

# Action handling. CECP remediates after delivery as well as inline, and
# its actions are richer than the gateway's, so match on prefixes /
# substrings rather than an exact set. Non-remediating prefixes are
# checked FIRST so "not blocked" or "Pass/Log" never match "block".
_NON_REMEDIATING_PREFIXES = (
    "not ", "pass", "log", "monitor", "no action", "notify", "tag",
    "deliver", "allow", "bypass", "user decision", "detect only", "none",
)
_REMEDIATING_KEYWORDS = (
    "quarantin", "delet", "block", "reject", "junk", "spam folder",
    "redirect", "approval", "replac", "strip", "remov", "encrypt",
    "isolat", "terminat", "reset", "clean", "revok", "move", "sanitiz",
)


def classify_action(action: str) -> str | None:
    """'remediated', 'not_remediated', or None if unrecognized."""
    a = (action or "").strip().lower()
    if not a:
        return None
    if a.startswith(_NON_REMEDIATING_PREFIXES):
        return "not_remediated"
    if any(k in a for k in _REMEDIATING_KEYWORDS):
        return "remediated"
    return None


class CECPRecord(DetectionRecord):
    """A CECP detection (live API, CSV row or demo), normalized."""

    @property
    def action(self) -> str:
        act = self.raw.get("act") or self.raw.get("actResult")
        if isinstance(act, list):
            act = act[0] if act else ""
        return str(act or "").split(",")[0].strip().lower()

    @property
    def was_blocked(self) -> bool:
        """Remediated (quarantined / deleted / blocked / file replaced...).
        Kept under the CEGP name so shared template logic still reads."""
        if self.is_simulation:
            return False
        return classify_action(self.action) == "remediated"

    @property
    def action_is_unmapped(self) -> bool:
        return bool(self.action) and classify_action(self.action) is None

    @property
    def threat_text(self) -> str:
        """Everything that describes what was caught, for categorization."""
        keys = (
            "threatType", "malName", "threatName", "malType", "securityFilter",
            "filterName", "ruleName", "objectSubType", "eventSubName", "eventName",
        )
        parts = []
        for k in keys:
            v = self.raw.get(k)
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            if v:
                parts.append(str(v))
        return " | ".join(parts)

    @property
    def threat_name(self) -> str:
        """Display label. CSV exports put the most specific name in
        "Security risk / Anomaly name" (Spam, BEC, Phishing - Spam...), but
        for malicious URLs that column holds the defanged URL itself, so
        fall back to the threat type there."""
        risk = (self.raw.get("riskName") or "").strip()
        if risk and not risk.startswith("[http") and len(risk) <= 80:
            return risk
        return (
            self.raw.get("threatType")
            or self.raw.get("malName")
            or self.raw.get("threatName")
            or self.raw.get("securityFilter")
            or self.raw.get("filterName")
            or self.raw.get("ruleName")
            or self.raw.get("malType")
            or "Unclassified detection"
        )

    @property
    def category(self) -> str:
        """First field, most specific to least, that maps to a sub-type.
        Checking fields separately (not one joined string) matters: e.g.
        risk name "Possibly Unwanted Marketing Email" is Graymail even
        though its filter is Correlated Intelligence (-> account
        compromise), and "Spam" from the Advanced Spam Protection filter
        must not be overridden by its "Spam/Graymail" threat type."""
        for key in ("riskName", "threatType", "malName", "threatName", "malType",
                    "detectedBy", "securityFilter", "filterName", "ruleName",
                    "objectSubType", "eventSubName", "eventName"):
            value = self.raw.get(key)
            if isinstance(value, list):
                value = ", ".join(str(x) for x in value)
            if value:
                category = categorize(str(value))
                if category != "Other":
                    return category
        return "Other"

    @property
    def informational_kind(self) -> str | None:
        """Rows in a CECP detection-log export that are NOT threats:
        - "sandbox_clean": Virtual Analyzer analysed the URL/file and found
          no risk (threat type blank, risk "No risk detected"/"Unrated").
          These are usually the bulk of an export.
        - "unscannable": "Unscannable files/URLs" -- protected, oversized
          or otherwise unscannable objects, passed by policy.
        Excluded from detection / remediation figures, reported as
        sandbox-activity information instead."""
        threat_type = (self.raw.get("threatType") or "").lower()
        if "unscannable" in threat_type:
            return "unscannable"
        risk_name = self.raw.get("riskName") or ""
        va_risk = (self.raw.get("vaRisk") or "").lower()
        if not threat_type and not risk_name and (
            va_risk in ("no risk detected", "no risk", "unrated", "safe")
            or (self.raw.get("securityFilter") or "").lower() == "virtual analyzer"
        ):
            return "sandbox_clean"
        return None

    @property
    def is_informational(self) -> bool:
        return self.informational_kind is not None

    @property
    def was_restored(self) -> bool:
        return bool((self.raw.get("restoreReason") or "").strip())

    @property
    def security_filter(self) -> str:
        return self.raw.get("securityFilter") or self.raw.get("filterName") or ""

    @property
    def service(self) -> str:
        explicit = self.raw.get("service")
        if explicit:
            normalized = normalize_service(explicit)
            return explicit if normalized == "Unknown service" else normalized
        hints = " ".join(
            str(self.raw.get(k) or "")
            for k in ("scanType", "app", "saasApp", "appName", "source", "pname")
        )
        service = normalize_service(hints)
        if service == "Unknown service" and (self.raw.get("mailMsgSubject") or self.raw.get("mailbox")):
            service = "Exchange Online"  # mail detection with no app hint
        return service

    @property
    def channel(self) -> str:
        return service_channel(self.service)

    @property
    def affected_user(self) -> str:
        return self._first(
            self.raw.get("affectedUser")
            or self.raw.get("mailbox")
            or self.raw.get("mailToAddresses")
            or self.raw.get("duser")
            or self.raw.get("suser")
        )

    @property
    def recipient(self) -> str:
        return self.affected_user

    @property
    def sender(self) -> str:
        return self._first(
            self.raw.get("sender") or self.raw.get("mailFromAddresses") or self.raw.get("suser")
        )

    @property
    def file_name(self) -> str:
        return self._first(self.raw.get("fileName") or self.raw.get("attachmentFileName"))


class CECPClient(VisionOneClient):
    """VisionOneClient scoped to productCode:sca."""

    def get_cecp_detections(self, start: dt.datetime, end: dt.datetime, progress=None) -> list[CECPRecord]:
        # No `select`: CECP detection fields aren't fully documented, and
        # selecting an unsupported field fails the whole query. Pulling
        # every field also lets the service/threat inference use whatever
        # this tenant actually returns.
        raw = self._get_pages_chunked(
            DETECTIONS_PATH, f"productCode:{CECP_PRODUCT_CODE}", start, end, progress=progress
        )
        return [CECPRecord(raw=item) for item in raw]

    def get_scanned_email_count(self, start: dt.datetime, end: dt.datetime) -> int:
        """Mailbox email activity CECP scanned (Exchange Online / Gmail).
        countonly -- treat as approximate and spot-check against the
        CECP console's own statistics."""
        return self.count(EMAIL_ACTIVITIES_PATH, f"productCode:{CECP_PRODUCT_CODE}", start, end)

    def get_scan_type_breakdown(self, start: dt.datetime, end: dt.datetime) -> dict:
        items = self._get_pages_chunked(
            DETECTIONS_PATH, f"productCode:{CECP_PRODUCT_CODE}", start, end, select="scanType",
        )
        counts = Counter(i.get("scanType") or "(missing)" for i in items)
        return dict(counts.most_common())

    def test_connection(self) -> bool:
        now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
        self.count(DETECTIONS_PATH, f"productCode:{CECP_PRODUCT_CODE}", now - dt.timedelta(minutes=5), now)
        return True
