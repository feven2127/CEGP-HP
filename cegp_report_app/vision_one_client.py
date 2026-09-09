"""
vision_one_client.py  (rev 2 -- corrected against internal sources)

Thin client for the Trend Vision One Search API, focused on pulling
CEGP (Cloud Email Gateway Protection) data for executive and detection
efficacy reporting.

Verified against
----------------
- KA-0015974 "List of Pname and Product Codes in Search App Log Schema"
- Automation Center: Get detection data / Get email activity data /
  Get entries from audit logs / Get managed email domains
- trendmicro/tm-v1-schema (doc/Detections.yaml, doc/Email Activity Data.yaml)
  -- the schema reference the product docs now point to
- Online Help: XDR data retention licenses

IMPORTANT -- READ BEFORE RUNNING LIVE
-------------------------------------
The Vision One product docs mark the *activity data source query method*
this client uses as retired ("no longer available after May 1, 2026" in
the MEA docs, "after June 2026" in the main SaaS docs), and redirect to
https://trendmicro.github.io/tm-v1-schema/pages/index for the current
data sources. The /v3.0/search/* endpoints below are still published in
the Automation Center reference, and the field names here come from the
*current* schema repo rather than the deprecated doc tables -- but
confirm against your own tenant before relying on this for a customer
deliverable. See DEPRECATION_NOTICE below.

Key corrections from rev 1
--------------------------
1. Filter on `productCode`, not `pname`.
   `productCode:sem` scopes to the gateway product (CEGP) on BOTH
   detections and email activity. `pname` is marked "(depricated)" [sic]
   on Email Activity Data in the current schema, and its meaning differs
   per data source (text on detections, numeric 742 on email activity),
   which was the rev 1 silent-zero-rows trap.
2. Counts use `mode=countonly` -- one call, exact count. Rev 1 paged
   through records and returned a capped lower bound.
3. Blocked != detected. The `act` field distinguishes real blocks
   ('Block', 'Reset', ...) from non-blocks ('not blocked', 'Pass',
   'No action', 'log', 'User Decision'). Rev 1 counted every detection
   as "blocked", overstating the headline number.
4. `simulation:true` records are excluded -- monitor/simulation-mode
   detections are not blocks and must not be sold as such.
5. `mailDirection` is an **int** (samples 1, 3, 25), not a string.
6. The quarantine-restore "false positive proxy" is renamed and
   re-scoped: Response Management audit logs only capture restores
   performed *through Vision One* (/v3.0/response/emails/restore), not
   admin restores in the CEGP console. See the docstring.
"""

from __future__ import annotations

import datetime as dt
import time
from dataclasses import dataclass, field

import requests

# The Search API enforces a per-tenant rate limit that a single report run
# can trip on its own -- a detections pull alone can page through dozens of
# requests. Retry 429s with backoff (honoring Retry-After when the API sends
# one) instead of surfacing a rate-limit error to the caller.
RATE_LIMIT_MAX_RETRIES = 5
RATE_LIMIT_BACKOFF_SECONDS = 2.0

# A broad query over a full day (or more) of data can legitimately take a
# while to evaluate server-side -- observed live (2026-08) timing out a
# whole report run on the very first request. Retry transient network
# errors (read timeouts, connection resets) the same way 429s are retried,
# rather than failing the run on one slow/dropped response. Kept separate
# from RATE_LIMIT_MAX_RETRIES since each attempt here already costs a full
# REQUEST_TIMEOUT_SECONDS before it even fails.
NETWORK_ERROR_MAX_RETRIES = 3
REQUEST_TIMEOUT_SECONDS = 60

# Status codes worth retrying rather than failing the run outright: 429
# (rate limit, already retried before this was added) plus 5xx-ish
# transient server-side faults. 599 was observed live (2026-08) with the
# API's own error message being "An internal error has occurred on the
# data source. Please try again later." -- explicitly a retry-me signal
# from the server, not a client-side problem to fix.
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504, 599}

DEPRECATION_NOTICE = (
    "Vision One product docs mark this activity-data query method as retired "
    "(May 1 2026 for MEA, June 2026 for main SaaS). Current data-source schema: "
    "https://trendmicro.github.io/tm-v1-schema/pages/index -- verify against "
    "your tenant before using output as a customer deliverable."
)

# Region -> API base URL. Matches the Automation Center "API Servers for
# Trend Vision One" list exactly (7 regions).
REGION_SERVERS = {
    "us": "https://api.xdr.trendmicro.com",
    "eu": "https://api.eu.xdr.trendmicro.com",
    "sg": "https://api.sg.xdr.trendmicro.com",
    "jp": "https://api.xdr.trendmicro.co.jp",
    "au": "https://api.au.xdr.trendmicro.com",
    "in": "https://api.in.xdr.trendmicro.com",
    "mea": "https://api.mea.xdr.trendmicro.com",
}

# --- Product scoping -------------------------------------------------------
# productCode is searchable on both Detections and Email Activity Data and
# is the only field that cleanly separates the gateway product from the
# collaboration product:
#
#   sem = Trend Micro Email Security  -> the gateway (CEGP / TMES)  <-- ours
#   sca = Trend Micro Cloud App Security -> CECP / collaboration side
#   xms = Email Sensor
#   xca = Collaboration Sensor
#
# Filtering on pname:"Email and Collaboration Security" (rev 1) spans BOTH
# sem and sca, so a "CEGP report" built that way silently includes
# collaboration detections.
CEGP_PRODUCT_CODE = "sem"

# Legacy values, kept only for the diagnostic probes below.
LEGACY_DETECTION_PNAME = "Email and Collaboration Security"
LEGACY_EMAIL_ACTIVITY_PNAME = "742"

# --- scanType scoping ------------------------------------------------------
# scanType separates gateway traffic from mailbox/collab scanning, and on
# the gateway side separates blocked from accepted traffic:
#
#   detections:      gateway_realtime_blocking_traffic
#                    gateway_realtime_detection_log
#   email activity:  gateway_realtime_accepted_mail_traffic
#                    gateway_mailmetadata
#   (collab, excluded: realtime_mailmeta-exchange, realtime_mailmeta-gmail,
#                      exchange_mailbox_realtime_detection_logs)
#
# gateway_realtime_detection_log was found live (2026-08) on a tenant where
# get_detection_count (blocking-traffic-only) undercounted sem detections
# vs. the per-product-code total -- this second scanType is the gap. It's
# the monitor-mode sibling of blocking_traffic: same gateway detection
# pipeline, but the policy only logged instead of blocking. Detections are
# pulled from BOTH so the mail-tracking "detected, not blocked" bucket is
# complete; the per-record `act` field (see was_blocked) is still what
# decides blocked vs. not, not the scanType alone.
SCANTYPE_GATEWAY_BLOCKED = "gateway_realtime_blocking_traffic"
SCANTYPE_GATEWAY_DETECTION_LOG = "gateway_realtime_detection_log"
SCANTYPE_GATEWAY_DETECTION_SIDE = (SCANTYPE_GATEWAY_BLOCKED, SCANTYPE_GATEWAY_DETECTION_LOG)
SCANTYPE_GATEWAY_ACCEPTED = "gateway_realtime_accepted_mail_traffic"

# --- act values ------------------------------------------------------------
# From Detections.yaml, `act` samples:
#   'log', 'isolate', 'terminate', 'not blocked', 'Block', 'No action',
#   'Reset', 'Pass', 'User Decision'
# Only some of these represent the message actually being stopped. Anything
# not in BLOCKING_ACTIONS is treated as detected-but-delivered and reported
# separately rather than folded into "threats blocked".
BLOCKING_ACTIONS = {
    "block", "blocked", "reset", "quarantine", "quarantined",
    "delete", "deleted", "terminate", "isolate",
}
NON_BLOCKING_ACTIONS = {
    "not blocked", "pass", "no action", "log", "logged", "user decision",
    "monitor", "allow", "allowed", "deliver", "delivered",
}

DETECTIONS_PATH = "/v3.0/search/detections"
EMAIL_ACTIVITIES_PATH = "/v3.0/search/emailActivities"
AUDIT_LOGS_PATH = "/v3.0/audit/logs"
EMAIL_DOMAINS_PATH = "/v3.0/emailAssetInventory/emailDomains"

# `top` is an enum on these endpoints -- 200 is the max legal value.
MAX_TOP = 200

# The Search API caps total retrievable records per query at ~10,000
# regardless of how far nextLink is followed -- observed live (2026-08) on
# a tenant with a high-volume period: pagination simply stopped producing
# a nextLink around 10,000 records even though get_detection_count() (an
# exact countonly total) confirmed many more existed. This is a platform
# limit on a single query, not a per-tenant/per-key limit, so the fix is
# to split the time range into smaller windows and query each separately
# (see _get_pages_chunked) rather than trying to page further.
SEARCH_API_RESULT_CAP = 10_000


class VisionOneAPIError(Exception):
    """Raised when the Vision One API returns an error response."""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"Vision One API error {status_code}: {message}")


@dataclass
class DetectionRecord:
    raw: dict = field(default_factory=dict)

    # -- identity ----------------------------------------------------------
    @property
    def product_code(self) -> str:
        return self.raw.get("productCode", "")

    @property
    def pname(self) -> str:
        return self.raw.get("pname", "Unknown")

    @property
    def msg_uuid(self) -> str:
        """Per-message UUID. Use for de-duplication: one message can raise
        several detections (multiple filters hitting the same mail)."""
        return self.raw.get("msgUuid", "")

    # -- outcome -----------------------------------------------------------
    @property
    def action(self) -> str:
        """Normalized `act` value. `act` is typed `dynamic` in the schema,
        so it may arrive as a list."""
        act = self.raw.get("act")
        if isinstance(act, list):
            act = act[0] if act else ""
        return str(act or "").strip().lower()

    @property
    def is_simulation(self) -> bool:
        return bool(self.raw.get("simulation"))

    @property
    def was_blocked(self) -> bool:
        """True only if the message was actually stopped. Simulation-mode
        records are never counted as blocked."""
        if self.is_simulation:
            return False
        act = self.action
        if act in NON_BLOCKING_ACTIONS:
            return False
        if act in BLOCKING_ACTIONS:
            return True
        # Unknown/absent act: treat conservatively as NOT blocked so the
        # headline number can never be inflated by unmapped values.
        return False

    @property
    def action_is_unmapped(self) -> bool:
        """Surface act values we don't recognize, so they can be added to
        the maps rather than silently dropped from the block count."""
        act = self.action
        return bool(act) and act not in BLOCKING_ACTIONS and act not in NON_BLOCKING_ACTIONS

    # -- classification ----------------------------------------------------
    @property
    def threat_name(self) -> str:
        """Best available label for what was caught. objectSubType and
        filterName are CEGP-specific ('Spam Others', 'ContentFiltering',
        'ConnectionFilter', 'Virtual Analyzer', 'Data Loss Prevention')
        and describe policy-rule triggers far better than malName, which
        is usually empty for gateway policy events."""
        return (
            self.raw.get("malName")
            or self.raw.get("objectSubType")
            or self.raw.get("filterName")
            or self.raw.get("ruleName")
            or self.raw.get("eventSubName")
            or self.raw.get("eventName")
            or "Unclassified detection"
        )

    @property
    def filter_name(self) -> str:
        return self.raw.get("filterName", "")

    @property
    def policy_name(self) -> str:
        return self.raw.get("policyName", "")

    @property
    def risk_level(self) -> str:
        return self.raw.get("filterRiskLevel", "")

    # -- message metadata --------------------------------------------------
    @property
    def detected_time(self) -> str:
        return (
            self.raw.get("detectedDateTime")
            or self.raw.get("mailReceivedTime")
            or self.raw.get("eventTime")
            or self.raw.get("rt")
            or ""
        )

    @staticmethod
    def _first(v) -> str:
        if isinstance(v, list):
            return str(v[0]) if v else ""
        return str(v) if v else ""

    @property
    def sender(self) -> str:
        return self._first(
            self.raw.get("suser") or self.raw.get("mailSmtpFromAddresses")
        )

    @property
    def recipient(self) -> str:
        return self._first(
            self.raw.get("mailbox")
            or self.raw.get("mailSmtpRecipients")
            or self.raw.get("duser")
        )

    @property
    def subject(self) -> str:
        return self.raw.get("mailMsgSubject", "")


class VisionOneClient:
    def __init__(self, api_key: str, region: str = "us", timeout: int = REQUEST_TIMEOUT_SECONDS):
        if region not in REGION_SERVERS:
            raise ValueError(
                f"Unknown region '{region}'. Valid options: {', '.join(REGION_SERVERS)}"
            )
        self.base_url = REGION_SERVERS[region]
        self.api_key = api_key
        self.timeout = timeout

    # ------------------------------------------------------------------ util
    def _headers(self, query: str) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "TMV1-Query": query,
        }

    @staticmethod
    def _iso(t: dt.datetime) -> str:
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _raise_for_error(self, resp) -> None:
        if resp.status_code == 200:
            return
        try:
            msg = resp.json().get("error", {}).get("message", resp.text)
        except ValueError:
            msg = resp.text
        raise VisionOneAPIError(resp.status_code, msg)

    def _get(self, url: str, **kwargs) -> requests.Response:
        """requests.get with retry-on-retryable-status backoff (429 plus
        transient 5xx-ish faults -- see RETRYABLE_STATUS_CODES above) and
        retry-on-transient-network-error backoff (see
        NETWORK_ERROR_MAX_RETRIES above) -- a read timeout, connection
        reset, or a server telling us to try again later shouldn't fail an
        entire report run on one bad response."""
        for network_attempt in range(NETWORK_ERROR_MAX_RETRIES + 1):
            try:
                for attempt in range(RATE_LIMIT_MAX_RETRIES + 1):
                    resp = requests.get(url, **kwargs)
                    if resp.status_code not in RETRYABLE_STATUS_CODES or attempt == RATE_LIMIT_MAX_RETRIES:
                        return resp
                    retry_after = resp.headers.get("Retry-After")
                    try:
                        delay = float(retry_after) if retry_after is not None else None
                    except ValueError:
                        delay = None
                    if delay is None:
                        delay = RATE_LIMIT_BACKOFF_SECONDS * (2 ** attempt)
                    time.sleep(delay)
                return resp
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                if network_attempt == NETWORK_ERROR_MAX_RETRIES:
                    raise
                time.sleep(RATE_LIMIT_BACKOFF_SECONDS * (2 ** network_attempt))

    def _get_pages(
        self,
        path: str,
        query: str,
        start: dt.datetime,
        end: dt.datetime,
        top: int = MAX_TOP,
        select: str | None = None,
        max_pages: int | None = None,
    ) -> list[dict]:
        """Paginated GET against a Vision One search endpoint.

        max_pages=None means "follow nextLink to the end". Use the
        `count()` helper instead of paging when you only need a total.
        """
        url = self.base_url + path
        params = {
            "startDateTime": self._iso(start),
            "endDateTime": self._iso(end),
            "top": min(top, MAX_TOP),
        }
        if select:
            params["select"] = select

        headers = self._headers(query)
        items: list[dict] = []
        next_url, next_params, pages = url, params, 0

        while next_url and (max_pages is None or pages < max_pages):
            resp = self._get(
                next_url, params=next_params, headers=headers, timeout=self.timeout
            )
            self._raise_for_error(resp)
            payload = resp.json()
            items.extend(payload.get("items", []))
            pages += 1
            next_link = payload.get("nextLink")
            next_url = next_link or None
            next_params = None  # nextLink already carries the query params

        return items

    def _get_pages_chunked(
        self,
        path: str,
        query: str,
        start: dt.datetime,
        end: dt.datetime,
        top: int = MAX_TOP,
        select: str | None = None,
        cap: int = SEARCH_API_RESULT_CAP,
    ) -> list[dict]:
        """Like _get_pages, but works around the Search API's per-query
        result cap (see SEARCH_API_RESULT_CAP) by bisecting the time range
        whenever a window's actual fetched size hits the cap, recursing
        until every leaf window's real result fits comfortably under it.

        Deliberately does NOT decide whether to split by calling count()
        first: live testing (2026-08) found a window where get_cegp_
        detections() still returned exactly 10,000 records despite an
        earlier version of this method checking count() before fetching --
        Vision One's countonly count appears to share the same per-query
        evaluation ceiling as paged results, so it can itself silently
        under-report for a huge window and wrongly signal "under the cap,
        no need to split". Only the actual number of records that came
        back is trustworthy here.

        Splits land on whole seconds (the API's own timestamp precision
        here -- see _iso) with the right half starting one second after
        the left half's end, so windows never overlap and no record is
        double-counted.
        """
        items = self._get_pages(path, query, start, end, top=top, select=select)
        if len(items) < cap or (end - start) <= dt.timedelta(seconds=1):
            # Fewer than the cap came back, or the window can't usefully
            # be split further (down to a 1-second sliver) -- trust this
            # as complete. If a single sub-second window still hits the
            # cap, this returns a truncated result for that sliver rather
            # than looping forever; not observed in practice.
            return items

        # len(items) >= cap: this window may have been truncated by the
        # same ceiling that affects paging -- discard it and re-fetch each
        # half instead of trusting a possibly-incomplete batch.
        mid = start + (end - start) / 2
        left = self._get_pages_chunked(path, query, start, mid, top=top, select=select, cap=cap)
        right = self._get_pages_chunked(
            path, query, mid + dt.timedelta(seconds=1), end, top=top, select=select, cap=cap
        )
        return left + right

    def count(
        self, path: str, query: str, start: dt.datetime, end: dt.datetime
    ) -> int:
        """Exact record count via `mode=countonly` -- a single request.

        The search endpoints accept mode='default' (full data),
        'countonly' (just the number of matching records) and
        'performance' (caps results at 500). Rev 1 of this client paged
        through records and counted them, which capped out and returned a
        lower bound; countonly removes that problem entirely.
        """
        resp = self._get(
            self.base_url + path,
            params={
                "startDateTime": self._iso(start),
                "endDateTime": self._iso(end),
                "mode": "countonly",
            },
            headers=self._headers(query),
            timeout=self.timeout,
        )
        self._raise_for_error(resp)
        payload = resp.json()
        for key in ("count", "totalCount", "total"):
            if isinstance(payload.get(key), int):
                return payload[key]
        # Defensive: if the count schema shape differs, fall back to items.
        return len(payload.get("items", []))

    # -------------------------------------------------------------- queries
    @staticmethod
    def _cegp_query(
        scan_type: str | tuple[str, ...] | None = None, extra: str | None = None
    ) -> str:
        """Build a CEGP-scoped TMV1-Query.

        Scoping on productCode (not pname) and optionally on scanType to
        keep gateway traffic separate from collaboration traffic. Passing a
        tuple/list of scanTypes ORs them together -- used to pull both
        gateway detection scanTypes (blocking traffic + detection log) in
        one query.
        """
        parts = [f"productCode:{CEGP_PRODUCT_CODE}"]
        if scan_type:
            if isinstance(scan_type, str):
                parts.append(f'scanType:"{scan_type}"')
            else:
                clause = " or ".join(f'scanType:"{st}"' for st in scan_type)
                parts.append(f"({clause})")
        if extra:
            parts.append(f"({extra})")
        return " and ".join(parts)

    def get_cegp_detections(
        self,
        start: dt.datetime,
        end: dt.datetime,
        extra_query: str | None = None,
        gateway_only: bool = True,
        max_pages: int | None = None,
    ) -> list[DetectionRecord]:
        """Pull CEGP detection records for a date range.

        gateway_only=True restricts to the gateway detection scanTypes
        (SCANTYPE_GATEWAY_DETECTION_SIDE: blocking traffic + detection log),
        excluding mailbox/collaboration scan logs. Set False if you want
        every sem-attributed detection regardless of scan type.
        """
        query = self._cegp_query(
            scan_type=SCANTYPE_GATEWAY_DETECTION_SIDE if gateway_only else None,
            extra=extra_query,
        )
        # Ask only for the fields the report uses -- smaller payloads, and
        # it makes the field dependency explicit.
        select = ",".join([
            "productCode", "pname", "msgUuid", "act", "simulation",
            "malName", "objectSubType", "filterName", "ruleName",
            "policyName", "eventName", "eventSubName", "filterRiskLevel",
            "mailMsgSubject", "mailbox", "suser", "duser",
            "mailSmtpFromAddresses", "mailSmtpRecipients",
            "mailReceivedTime", "mailDirection", "scanType", "rt",
        ])
        if max_pages is None:
            # No explicit page cap requested -- pull everything for the
            # period, working around the ~10,000-record-per-query ceiling
            # by bisecting the time range instead of silently truncating.
            raw = self._get_pages_chunked(DETECTIONS_PATH, query, start, end, select=select)
        else:
            raw = self._get_pages(
                DETECTIONS_PATH, query, start, end,
                select=select, max_pages=max_pages,
            )
        return [DetectionRecord(raw=item) for item in raw]

    def get_detection_count(self, start: dt.datetime, end: dt.datetime) -> int:
        """Total CEGP gateway detections in the period (exact)."""
        return self.count(
            DETECTIONS_PATH,
            self._cegp_query(scan_type=SCANTYPE_GATEWAY_DETECTION_SIDE),
            start, end,
        )

    def get_total_scanned_count(
        self, start: dt.datetime, end: dt.datetime, **_ignored
    ) -> int:
        """Total inbound messages CEGP accepted/scanned in the period --
        the denominator for block rate.

        Uses email activity data scoped to productCode:sem and scanType
        'gateway_realtime_accepted_mail_traffic'. Exact count via
        countonly, so no page cap and no lower-bound caveat.

        `mailDirection` is deliberately not filtered here: it is an int
        field (samples 1, 3, 25) whose value meanings are not published,
        and guessing wrong silently returns zero rows. Scope by scanType
        instead, which is documented by sample value.

        **_ignored keeps the rev 1 max_pages kwarg accepted so existing
        callers don't break.
        """
        return self.count(
            EMAIL_ACTIVITIES_PATH,
            self._cegp_query(scan_type=SCANTYPE_GATEWAY_ACCEPTED),
            start, end,
        )

    def get_delivered_flagged_count(
        self, start: dt.datetime, end: dt.datetime
    ) -> int:
        """Count of accepted/delivered messages that still carry a threat
        flag -- e.g. graymail or low-confidence spam let through per policy
        rather than blocked outright.

        This is the "Delivered - flagged" bucket of the mail tracking
        status breakdown: same scanType as get_total_scanned_count
        (gateway_realtime_accepted_mail_traffic), narrowed to records where
        `mailThreatType` is present. Exact count via countonly -- no paging.

        `mailThreatType` is a string field (samples: "suspected", "phishing")
        per the Email Activity Data schema; a presence filter (`:*`) is used
        rather than guessing every value it can take.
        """
        return self.count(
            EMAIL_ACTIVITIES_PATH,
            self._cegp_query(scan_type=SCANTYPE_GATEWAY_ACCEPTED, extra="mailThreatType:*"),
            start, end,
        )

    def get_vision_one_restore_count(
        self, start: dt.datetime, end: dt.datetime, max_pages: int = 10
    ) -> int:
        """Count of email restores performed THROUGH VISION ONE in the period.

        Scope caveat -- read before putting this in a customer report:
        this reads Response Management audit logs, which record Vision One
        response tasks (the /v3.0/response/emails/restore action and its
        console equivalent). It does NOT capture an admin or end user
        restoring a message from the CEGP quarantine console, which is
        where most real false-positive recoveries happen. So this is a
        floor on Vision One-initiated restores, not a false-positive rate.

        For an actual false-positive measure, use CEGP's own Mail Tracking
        (180-day retention, 90-day search window, CSV export, filterable
        by action and by user feedback) or the quarantine logs in the
        Email and Collaboration Security console.

        Audit log retention is 180 days, so this tolerates longer
        reporting periods than the 30-day search default.
        """
        url = self.base_url + AUDIT_LOGS_PATH
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "TMV1-Filter": "category eq 'Response Management'",
        }
        params = {
            "startDateTime": self._iso(start),
            "endDateTime": self._iso(end),
            "top": 200,  # must be one of 50/100/200
        }

        count = 0
        next_url, next_params, pages = url, params, 0
        while next_url and pages < max_pages:
            resp = self._get(
                next_url, params=next_params, headers=headers, timeout=self.timeout
            )
            self._raise_for_error(resp)
            payload = resp.json()
            for item in payload.get("items", []):
                if "restore" in (item.get("activity") or "").lower():
                    count += 1
            pages += 1
            next_url = payload.get("nextLink") or None
            next_params = None
        return count

    # Back-compat alias for rev 1 callers.
    get_quarantine_restore_count = get_vision_one_restore_count

    def get_cegp_domains(self) -> list[dict]:
        """Email domains protected by CEGP, with inbound/outbound config and
        key-feature status.

        Useful as a "scope of protection" panel in the executive report --
        it shows what was actually covered during the period instead of
        leaving the reader to assume. Requires the Email Asset Inventory
        (View) permission; callers should degrade gracefully without it.
        """
        url = self.base_url + EMAIL_DOMAINS_PATH
        headers = {"Authorization": f"Bearer {self.api_key}"}
        items: list[dict] = []
        next_url, next_params = url, {"top": 1000}
        while next_url:
            resp = self._get(
                next_url, params=next_params, headers=headers, timeout=self.timeout
            )
            self._raise_for_error(resp)
            payload = resp.json()
            items.extend(payload.get("items", []))
            next_url = payload.get("nextLink") or None
            next_params = None
        return [
            d for d in items
            if d.get("protectionSolution") == "Cloud Email Gateway Protection"
        ]

    # ---------------------------------------------------------- diagnostics
    def probe_any_detections(self, start: dt.datetime, end: dt.datetime) -> int:
        """How many detections exist in this window for ANY product.
        Distinguishes "tenant has no detections" from "our filter excludes
        everything"."""
        return self.count(DETECTIONS_PATH, "productCode:*", start, end)

    def get_scan_type_breakdown(self, start: dt.datetime, end: dt.datetime) -> dict:
        """Exact detection count per scanType actually present for
        productCode:sem in this window -- the ceiling get_cegp_detections()'s
        gateway-only scanType filter should be compared against (sum the
        values). If that sum is bigger than what get_cegp_detections()
        retrieves, the gateway-only scanType scoping is excluding real
        detections, and this breakdown shows which scanType(s).

        Deliberately built from real fetched records via _get_pages_chunked
        (lightweight select -- just scanType), NOT count(): live testing
        found count() can itself under-report for a query with no scanType
        filter, which would make a count()-based version of this check
        wrongly conclude "no gap" by comparing one unreliable number
        against another. Tallying actual records is the only way to get a
        number as trustworthy as get_cegp_detections()'s own total.
        """
        items = self._get_pages_chunked(
            DETECTIONS_PATH, self._cegp_query(), start, end, select="scanType",
        )
        breakdown: dict[str, int] = {}
        for item in items:
            st = item.get("scanType") or "(missing)"
            breakdown[st] = breakdown.get(st, 0) + 1
        return dict(sorted(breakdown.items(), key=lambda kv: -kv[1]))

    def get_total_sem_email_activity_count(self, start: dt.datetime, end: dt.datetime) -> int:
        """Count of ALL productCode:sem email-activity records in the
        window, regardless of scanType -- a rough ceiling to compare
        get_total_scanned_count()'s accepted-mail-only scanType filter
        against.

        Caveat: unlike get_scan_type_breakdown() on the detections side,
        this is still count()-based, not fetch-based -- email activity
        volume is typically far larger than detection volume, so fetching
        every raw record just for this cross-check would be expensive.
        That means this inherits the same count() unreliability live
        testing found on the detections side (see get_scan_type_breakdown's
        docstring): treat a "no gap" result here as a hint, not proof, and
        cross-check against Vision One's own Mail Tracking view directly
        for anything that looks off.
        """
        return self.count(EMAIL_ACTIVITIES_PATH, f"productCode:{CEGP_PRODUCT_CODE}", start, end)

    def probe_product_codes(self, start: dt.datetime, end: dt.datetime) -> dict:
        """Per-product detection counts for the window, so a scoping
        mistake is visible directly instead of inferred."""
        out = {}
        for code in ("sem", "sca", "xms", "xca"):
            try:
                out[code] = self.count(
                    DETECTIONS_PATH, f"productCode:{code}", start, end
                )
            except VisionOneAPIError as exc:
                out[code] = f"error: {exc.status_code}"
        return out

    def probe_email_pname_values(self, start: dt.datetime, end: dt.datetime) -> set[str]:
        """Legacy diagnostic: sample pname values on email-ish detections.
        Kept because pname is still returned, but prefer probe_product_codes
        -- pname is deprecated on Email Activity Data."""
        items = self._get_pages(
            DETECTIONS_PATH, f'pname:"{LEGACY_DETECTION_PNAME}"',
            start, end, top=50, max_pages=1,
        )
        return {i.get("pname", "") for i in items if i.get("pname")}

    def probe_scan_types(self, start: dt.datetime, end: dt.datetime) -> set[str]:
        """Sample the scanType values actually present for sem in this
        window -- confirms the gateway scanType constant matches the
        tenant before it silently filters everything out."""
        items = self._get_pages(
            DETECTIONS_PATH, f"productCode:{CEGP_PRODUCT_CODE}",
            start, end, top=MAX_TOP, select="scanType,act", max_pages=1,
        )
        return {i.get("scanType", "") for i in items if i.get("scanType")}

    def test_connection(self) -> bool:
        """Lightweight call to verify the API key and region work.

        Uses countonly over a short window so it stays cheap and doesn't
        depend on any records existing.
        """
        now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
        self.count(
            DETECTIONS_PATH,
            f"productCode:{CEGP_PRODUCT_CODE}",
            now - dt.timedelta(minutes=5),
            now,
        )
        return True
