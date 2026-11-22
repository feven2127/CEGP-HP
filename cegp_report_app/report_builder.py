"""
report_builder.py

Turns a list of DetectionRecord objects into the summary numbers and
tables the executive report template needs, using the TMES Potential
Loss methodology in cost_reference.py (no manual cost input):
count x IC3 loss-per-victim x period-fraction-of-a-year.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter
from dataclasses import dataclass

from vision_one_client import DetectionRecord
from cost_reference import categorize, potential_loss_per_unit, period_fraction, IC3_SOURCE


@dataclass
class CategoryLine:
    category: str
    count: int
    unit_value: float
    subtotal: float
    ic3_category: str | None
    cost_mapped: bool
    loss_per_victim: float = 0.0
    scan_share: float | None = None


@dataclass
class ReportData:
    customer_name: str
    period_start: str
    period_end: str
    total_blocked: int
    total_saved: float
    category_lines: list[CategoryLine]
    threats_by_type: list[tuple[str, int]]
    top_targeted_recipients: list[tuple[str, int]]
    daily_counts: list[tuple[str, int]]
    sample_detections: list[dict]
    total_scanned: int | None
    total_inbound: int | None
    block_rate: float | None
    restore_count: int | None
    false_positive_rate: float | None
    efficacy_available: bool
    # rev 2: detections are not all blocks -- keep them separate so the
    # headline "blocked" figure is defensible.
    total_detections: int = 0
    detected_not_blocked: int = 0
    unique_messages_blocked: int = 0
    simulation_excluded: int = 0
    unmapped_actions: list[str] = None
    # Mail tracking: full mail-flow status breakdown, not just the blocked
    # side. total_tracked/mail_status_breakdown are None/empty when neither
    # side of accepted-mail data was available.
    delivered_flagged_count: int | None = None
    delivered_clean_count: int | None = None
    total_tracked: int = 0
    mail_status_breakdown: list[tuple[str, int, float | None]] = None
    # Efficacy dashboard (additional report, same underlying data)
    weekly_counts: list[tuple[str, int]] = None
    # Threats broken down the way the Vision One console's Threats widget
    # does it, so the two can be compared side by side.
    console_breakdown: list[dict] = None
    console_total: int = 0
    console_unique_messages: int = 0
    config_gaps: list[dict] = None
    security_posture: list[dict] = None
    coverage_status: str = "Unknown"
    enforcement_rate: float | None = None
    # Outgoing mail (CSV uploads marked "outgoing"): kept separate from every
    # inbound figure above -- see build_outbound_summary.
    outbound: dict | None = None
    data_source: str = ""


def console_category(record: DetectionRecord) -> str:
    """The label the Vision One console's Threats widget would use for this
    detection. Event-log CSV rows carry the console's own Threat Type;
    Advanced Persistent Threat and Malware are split further the way the
    widget splits them. Records without a Threat Type (live API pulls) fall
    back to the TMES sub-type."""
    threat_type = record.raw.get("consoleThreatType") or ""
    if not threat_type:
        return categorize(record.threat_name)
    if threat_type == "Advanced Persistent Threat":
        return record.raw.get("consoleSubtype") or threat_type
    if threat_type == "Malware":
        detected_by = (record.raw.get("detectedBy") or "").lower()
        return "Malware (PML Detected)" if "machine learning" in detected_by else "Malware (Pattern-based)"
    return threat_type


def build_report_data(
    records: list[DetectionRecord],
    customer_name: str,
    period_start: str,
    period_end: str,
    total_scanned: int | None = None,
    restore_count: int | None = None,
    delivered_flagged_count: int | None = None,
) -> ReportData:
    # rev 2: split on the `act` field instead of assuming every detection
    # was a block. Simulation-mode records are excluded from both sides --
    # they represent what *would* have happened, not what did.
    total_detections = len(records)
    simulation_excluded = sum(1 for r in records if r.is_simulation)
    live = [r for r in records if not r.is_simulation]

    blocked = [r for r in live if r.was_blocked]
    not_blocked = [r for r in live if not r.was_blocked]

    total_blocked = len(blocked)
    detected_not_blocked = len(not_blocked)

    # One message can trigger several filters, so detection count > message
    # count. Report both: the ledger is per-detection, the customer-facing
    # "messages stopped" figure should be per-message.
    unique_messages_blocked = len({r.msg_uuid for r in blocked if r.msg_uuid})

    # Any act value we don't recognize is counted as NOT blocked (see
    # was_blocked). Surface them so the maps can be corrected rather than
    # quietly under-reporting.
    unmapped_actions = sorted({r.action for r in live if r.action_is_unmapped})

    # TMES Potential Loss = count x IC3 loss-per-victim x period-fraction.
    # The sheet this mirrors uses a fixed 0.25 (one calendar quarter);
    # this app's period is free-form, so the fraction scales with the
    # actual number of days selected (see cost_reference.period_fraction).
    try:
        days_in_period = (
            dt.datetime.strptime(period_end, "%Y-%m-%d")
            - dt.datetime.strptime(period_start, "%Y-%m-%d")
        ).days + 1
    except (TypeError, ValueError):
        days_in_period = 1
    frac = period_fraction(max(days_in_period, 1))

    category_counter: Counter = Counter()
    for r in blocked:
        category_counter[categorize(r.threat_name)] += 1

    category_lines: list[CategoryLine] = []
    total_saved = 0.0
    for category, count in category_counter.most_common():
        loss_per_victim, ic3_category = potential_loss_per_unit(category)
        unit_value = loss_per_victim * frac
        subtotal = unit_value * count
        total_saved += subtotal
        category_lines.append(
            CategoryLine(
                category=category,
                count=count,
                unit_value=unit_value,
                subtotal=subtotal,
                ic3_category=ic3_category,
                cost_mapped=ic3_category is not None,
                loss_per_victim=loss_per_victim,
            )
        )

    # Vision One-style threat breakdown: every live detection, whatever its
    # action, with the blocked subset alongside so either can be matched
    # against the console.
    console_all = Counter(console_category(r) for r in live)
    console_blocked = Counter(console_category(r) for r in blocked)
    console_total = sum(console_all.values())
    console_breakdown = [
        {
            "category": name,
            "detections": n,
            "share": (n / console_total * 100) if console_total else 0.0,
            "blocked": console_blocked.get(name, 0),
        }
        for name, n in console_all.most_common()
    ]
    console_unique_messages = len({r.msg_uuid for r in live if r.msg_uuid})

    threat_counter = Counter(r.threat_name for r in blocked)
    threats_by_type = threat_counter.most_common(10)

    recipient_counter = Counter(r.recipient for r in blocked if r.recipient)
    top_recipients = recipient_counter.most_common(5)

    day_counter: Counter = Counter()
    for r in blocked:
        day = (r.detected_time or "")[:10]
        if day:
            day_counter[day] += 1
    daily_counts = sorted(day_counter.items())

    sample = [
        {
            "time": r.detected_time,
            "threat": r.threat_name,
            "sender": r.sender,
            "recipient": r.recipient,
            "subject": r.subject,
            "action": r.action or "(none)",
        }
        for r in blocked[:25]
    ]

    # total_scanned (get_total_scanned_count) is scoped to
    # gateway_realtime_accepted_mail_traffic -- the ACCEPTED side of gateway
    # traffic only, deliberately excluding anything blocked (see the
    # scanType note in vision_one_client.py). So it is not "total inbound"
    # on its own; total inbound = what got blocked + what got accepted.
    # Dividing total_blocked by total_scanned alone (rev 1 of this file)
    # double-excludes blocked mail from both sides of a "% blocked"
    # calculation, producing rates over 100% whenever blocked volume
    # exceeds accepted volume.
    total_inbound = total_blocked + total_scanned if total_scanned is not None else None

    block_rate = None
    if total_inbound:  # None or 0 both mean "can't compute a rate"
        block_rate = (total_blocked / total_inbound) * 100

    false_positive_rate = None
    if restore_count is not None and total_blocked:
        false_positive_rate = (restore_count / total_blocked) * 100

    # "Available" means the accepted-mail lookup succeeded, so there's a
    # real (if possibly zero) denominator to build total_inbound from.
    efficacy_available = total_scanned is not None

    # Attach each category's share of total inbound volume (not just of
    # blocked mix) -- a distinct "catch rate" view from the dollar ledger.
    for line in category_lines:
        line.scan_share = (
            (line.count / total_inbound) * 100 if total_inbound else None
        )

    # Mail tracking: volume by action/status across the WHOLE mail flow,
    # not just blocked messages. Built from whichever pieces are actually
    # available -- degrades one bucket at a time rather than all-or-nothing.
    delivered_clean_count = None
    if total_scanned is not None and delivered_flagged_count is not None:
        delivered_clean_count = max(total_scanned - delivered_flagged_count, 0)

    total_tracked = total_detections + (total_scanned or 0)

    mail_status_breakdown: list[tuple[str, int, float | None]] = []

    def _bucket(label: str, n: int):
        pct = (n / total_tracked * 100) if total_tracked else None
        mail_status_breakdown.append((label, n, pct))

    _bucket("Blocked / quarantined", total_blocked)
    if detected_not_blocked:
        _bucket("Detected, not blocked (monitor mode)", detected_not_blocked)
    if delivered_flagged_count is not None:
        _bucket("Delivered – flagged (spam/graymail)", delivered_flagged_count)
        if delivered_clean_count is not None:
            _bucket("Delivered – clean", delivered_clean_count)
    elif total_scanned is not None:
        _bucket("Delivered", total_scanned)

    # ---------------------------------------------------------- dashboard
    # Weekly event volume: ALL live detections (blocked + not blocked),
    # not just the blocked-only daily_counts above -- this is meant to
    # answer "how much did CEGP see", not "how much did it stop".
    week_counter: Counter = Counter()
    for r in live:
        day = (r.detected_time or "")[:10]
        if not day:
            continue
        try:
            d = dt.datetime.strptime(day, "%Y-%m-%d").date()
        except ValueError:
            continue
        week_start = d - dt.timedelta(days=d.weekday())
        week_counter[week_start] += 1
    weekly_counts = [
        (ws.strftime("%b %d"), count) for ws, count in sorted(week_counter.items())
    ]

    # Configuration gaps: derived only from real degrade-gracefully signals
    # already tracked above -- never fabricated placeholder findings.
    config_gaps: list[dict] = []
    if total_scanned is None:
        config_gaps.append({
            "priority": "P1",
            "title": "Scanned mail volume unavailable",
            "detail": "The scanned-volume lookup (search/emailActivities) failed or returned nothing, so block rate and coverage cannot be computed for this period.",
            "recommendation": "Grant the API key Search permission (View, filter, and search) on email activity data.",
        })
    if restore_count is None:
        config_gaps.append({
            "priority": "P2",
            "title": "False-positive proxy unavailable",
            "detail": "The quarantine-restore audit log lookup failed or returned nothing, so the false-positive rate cannot be estimated.",
            "recommendation": "Grant the API key Audit Logs view permission.",
        })
    if unmapped_actions:
        config_gaps.append({
            "priority": "P2",
            "title": "Unrecognized action value(s) seen",
            "detail": f"{len(unmapped_actions)} distinct action value(s) didn't match a known block/monitor mapping and were counted as not blocked: {', '.join(unmapped_actions)}.",
            "recommendation": "Add these values to the action map in vision_one_client.py so blocked mail isn't undercounted.",
        })
    other_count = next((l.count for l in category_lines if l.category == "Other"), 0)
    if other_count:
        config_gaps.append({
            "priority": "P3",
            "title": "Detections falling into the uncategorized 'Other' bucket",
            "detail": f"{other_count} detection(s) didn't match any of the 12 TMES sub-type keyword rules and are tracked as 'Other' — counted, but not cost-mapped.",
            "recommendation": "Add matching keywords to _SUBTYPE_KEYWORDS in cost_reference.py for this tenant's policy/filter naming.",
        })
    if simulation_excluded:
        config_gaps.append({
            "priority": "P3",
            "title": "Simulation-mode detections excluded from all counts",
            "detail": f"{simulation_excluded} detection(s) were flagged as simulation/test traffic and excluded from every figure in this report.",
            "recommendation": "No action needed unless this count looks too high for genuine test traffic — worth a spot-check if so.",
        })

    # Security posture: real category counts re-grouped into fixed CEGP
    # capability buckets. "Active" just means count > 0 in this window.
    def _cat_count(*names: str) -> int:
        return sum(l.count for l in category_lines if l.category in names)

    security_posture = [
        {
            "title": "Spam & Graymail Blocked",
            "desc": "Unwanted bulk messages removed before reaching user inboxes, reducing phishing lure exposure.",
            "icon": "🚫",
            "count": _cat_count("Spam", "Graymail"),
        },
        {
            "title": "Phishing & Malicious URLs Neutralized",
            "desc": "Credential-harvesting messages and malicious links detected via phishing and web-reputation filtering.",
            "icon": "🎣",
            "count": _cat_count("Phishing", "Web Reputation"),
        },
        {
            "title": "Malware Attachments Stopped",
            "desc": "Malicious payloads (executables, Office macros, scripts) blocked by pattern-matching and attachment scanning.",
            "icon": "🦠",
            "count": _cat_count("Malware"),
        },
        {
            "title": "Ransomware Attempts Blocked",
            "desc": "Ransomware delivery attempts intercepted at the SMTP layer, preventing encryption attacks on endpoints.",
            "icon": "🔒",
            "count": _cat_count("Ransomware"),
        },
        {
            "title": "APT / Targeted Attack Indicators",
            "desc": "Advanced Persistent Threat campaigns detected via correlation of low-volume, high-precision attack patterns.",
            "icon": "🎯",
            "count": _cat_count("Advanced Persistent Threat"),
        },
        {
            "title": "Email Spoofing / SPF Violations Caught",
            "desc": "Impersonation and domain-spoofing attempts caught by SPF / DKIM / DMARC enforcement at the gateway.",
            "icon": "🕵️",
            "count": _cat_count("SPF Violation"),
        },
    ]
    for entry in security_posture:
        entry["active"] = entry["count"] > 0

    # Dashboard score = ENFORCEMENT rate: of the threats CEGP detected, how
    # many did it actually block (vs. only log in monitor mode). The block
    # rate above (blocked / all inbound mail) mostly measures how much of
    # the customer's mail was malicious, so it can't be "improved" without
    # blocking clean mail -- it's shown as information, not graded.
    live_detections = total_blocked + detected_not_blocked
    enforcement_rate = (total_blocked / live_detections * 100) if live_detections else None
    if enforcement_rate is None:
        coverage_status = "Unknown"
    elif enforcement_rate < 50:
        coverage_status = "Critical"
    elif enforcement_rate < 80:
        coverage_status = "Needs attention"
    elif enforcement_rate < 95:
        coverage_status = "Good"
    else:
        coverage_status = "Strong"

    return ReportData(
        customer_name=customer_name,
        period_start=period_start,
        period_end=period_end,
        total_blocked=total_blocked,
        total_saved=total_saved,
        category_lines=category_lines,
        threats_by_type=threats_by_type,
        top_targeted_recipients=top_recipients,
        daily_counts=daily_counts,
        sample_detections=sample,
        total_scanned=total_scanned,
        total_inbound=total_inbound,
        block_rate=block_rate,
        restore_count=restore_count,
        false_positive_rate=false_positive_rate,
        efficacy_available=efficacy_available,
        total_detections=total_detections,
        detected_not_blocked=detected_not_blocked,
        unique_messages_blocked=unique_messages_blocked,
        simulation_excluded=simulation_excluded,
        unmapped_actions=unmapped_actions,
        delivered_flagged_count=delivered_flagged_count,
        delivered_clean_count=delivered_clean_count,
        total_tracked=total_tracked,
        mail_status_breakdown=mail_status_breakdown,
        weekly_counts=weekly_counts,
        console_breakdown=console_breakdown,
        console_total=console_total,
        console_unique_messages=console_unique_messages,
        config_gaps=config_gaps,
        security_posture=security_posture,
        coverage_status=coverage_status,
        enforcement_rate=enforcement_rate,
    )


def build_outbound_summary(records: list[DetectionRecord], tracking=None) -> dict:
    """Outgoing-mail figures, reported separately from inbound.

    Outbound threats (malware, phishing or spam sent FROM the customer's
    domain, DLP / content-filter hits) usually mean a compromised internal
    account or data leaving the organization -- a different story from
    inbound attacks. They are deliberately NOT added to the inbound block
    rate or to the IC3 potential-loss figure, which models attacks coming in.
    """
    live = [r for r in records if not r.is_simulation]
    blocked = [r for r in live if r.was_blocked]
    cats = Counter(categorize(r.threat_name) for r in live)
    cats_blocked = Counter(categorize(r.threat_name) for r in blocked)
    total = len(live)
    return {
        "messages_scanned": tracking.total_rows if tracking else None,
        "delivered": tracking.delivered if tracking else None,
        "detections": total,
        "blocked": len(blocked),
        "not_blocked": total - len(blocked),
        "categories": [
            {
                "category": c,
                "detections": n,
                "blocked": cats_blocked.get(c, 0),
                "share": n / total * 100 if total else 0.0,
            }
            for c, n in cats.most_common()
        ],
        "top_senders": Counter(r.sender for r in live if r.sender).most_common(5),
        "top_rules": Counter(r.threat_name for r in live).most_common(5),
    }
