"""
report_builder.py  (CECP)

Turns CECPRecords into the numbers the executive report and efficacy
dashboard need. Valuation follows the TMES/IC3 Potential Loss method in
cost_reference.py: count x IC3 loss-per-victim x period-fraction.

CECP differs from the gateway in what "efficacy" means: it scans mail
already in the mailbox (through the M365 / Google API) and files in
collaboration apps, so there is no "inbound volume blocked at the
perimeter". The headline efficacy measure is therefore the
**remediation rate** -- the share of real detections CECP actually acted
on (quarantined, deleted, blocked, replaced...) rather than only logged --
plus threat prevalence against scanned volume when that is available.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from cecp_client import CECPRecord
from cost_reference import (
    ALL_SERVICES,
    COLLAB_SERVICES,
    period_fraction,
    potential_loss_per_unit,
    service_channel,
)


@dataclass
class CategoryLine:
    category: str
    count: int
    unit_value: float
    subtotal: float
    ic3_category: str | None
    cost_mapped: bool
    loss_per_victim: float = 0.0
    prevalence: float | None = None


@dataclass
class ReportData:
    customer_name: str
    period_start: str
    period_end: str
    total_detections: int = 0
    total_remediated: int = 0
    not_remediated: int = 0
    simulation_excluded: int = 0
    unmapped_actions: list = field(default_factory=list)
    total_saved: float = 0.0
    category_lines: list = field(default_factory=list)
    threats_by_type: list = field(default_factory=list)
    service_breakdown: list = field(default_factory=list)
    services_with_detections: int = 0
    email_detections: int = 0
    collab_detections: int = 0
    unique_users: int = 0
    top_users: list = field(default_factory=list)
    top_files: list = field(default_factory=list)
    action_breakdown: list = field(default_factory=list)
    status_breakdown: list = field(default_factory=list)
    daily_counts: list = field(default_factory=list)
    weekly_counts: list = field(default_factory=list)
    sample_detections: list = field(default_factory=list)
    emails_scanned: int | None = None
    files_scanned: int | None = None
    email_prevalence: float | None = None
    collab_prevalence: float | None = None
    remediation_rate: float | None = None
    restore_count: int | None = None
    false_positive_rate: float | None = None
    config_gaps: list = field(default_factory=list)
    security_posture: list = field(default_factory=list)
    coverage_status: str = "Unknown"
    data_source: str = ""
    # Informational rows from CSV exports (not threats).
    sandbox_clean: int = 0
    sandbox_malicious: int = 0
    unscannable: int = 0

    # Aliases so the summary JSON / shared UI code keep the CEGP names.
    @property
    def total_blocked(self) -> int:
        return self.total_remediated

    @property
    def block_rate(self) -> float | None:
        return self.remediation_rate


def _days(period_start: str, period_end: str) -> int:
    try:
        return (
            dt.datetime.strptime(period_end, "%Y-%m-%d")
            - dt.datetime.strptime(period_start, "%Y-%m-%d")
        ).days + 1
    except (TypeError, ValueError):
        return 1


def build_report_data(
    records: list[CECPRecord],
    customer_name: str,
    period_start: str,
    period_end: str,
    emails_scanned: int | None = None,
    files_scanned: int | None = None,
    restore_count: int | None = None,
    data_source: str = "",
    action_column_missing: bool = False,
) -> ReportData:
    d = ReportData(customer_name=customer_name, period_start=period_start, period_end=period_end)
    d.data_source = data_source
    d.emails_scanned, d.files_scanned, d.restore_count = emails_scanned, files_scanned, restore_count

    # Clean sandbox analyses and unscannable items aren't threats -- drop
    # them from every threat figure, keep their counts as information.
    informational = [r for r in records if r.is_informational]
    records = [r for r in records if not r.is_informational]
    d.sandbox_clean = sum(1 for r in informational if r.informational_kind == "sandbox_clean")
    d.unscannable = sum(1 for r in informational if r.informational_kind == "unscannable")
    d.sandbox_malicious = sum(
        1 for r in records if (r.raw.get("securityFilter") or "").lower() == "virtual analyzer"
    )

    d.total_detections = len(records)
    d.simulation_excluded = sum(1 for r in records if r.is_simulation)
    live = [r for r in records if not r.is_simulation]
    remediated = [r for r in live if r.was_blocked]
    d.total_remediated = len(remediated)
    d.not_remediated = len(live) - len(remediated)
    d.unmapped_actions = sorted({r.action for r in live if r.action_is_unmapped})
    if live:
        d.remediation_rate = d.total_remediated / len(live) * 100

    # ------------------------------------------------------- valuation
    # Valued on REMEDIATED detections only -- a logged-but-delivered
    # threat wasn't prevented, so it isn't loss avoided.
    frac = period_fraction(max(_days(period_start, period_end), 1))
    cat_counter = Counter(r.category for r in remediated)
    for category, count in cat_counter.most_common():
        loss, ic3 = potential_loss_per_unit(category)
        unit = loss * frac
        d.total_saved += unit * count
        d.category_lines.append(CategoryLine(
            category=category, count=count, unit_value=unit, subtotal=unit * count,
            ic3_category=ic3, cost_mapped=ic3 is not None, loss_per_victim=loss,
        ))

    d.threats_by_type = Counter(r.threat_name for r in live).most_common(10)

    # -------------------------------------------------------- services
    svc_all = Counter(r.service for r in live)
    svc_rem = Counter(r.service for r in remediated)
    svc_cats: dict[str, Counter] = defaultdict(Counter)
    for r in live:
        svc_cats[r.service][r.category] += 1
    total_live = len(live)
    d.service_breakdown = [
        {
            "service": s,
            "channel": service_channel(s),
            "detections": n,
            "remediated": svc_rem.get(s, 0),
            "share": n / total_live * 100 if total_live else 0.0,
            "top_category": svc_cats[s].most_common(1)[0][0] if svc_cats[s] else "",
        }
        for s, n in svc_all.most_common()
    ]
    d.services_with_detections = len([s for s in svc_all if s in ALL_SERVICES])
    d.email_detections = sum(1 for r in live if r.channel == "Email")
    d.collab_detections = sum(1 for r in live if r.channel == "Collaboration")

    # ------------------------------------------------------ users/files
    users = Counter(r.affected_user for r in live if r.affected_user)
    d.unique_users = len(users)
    d.top_users = Counter(r.affected_user for r in remediated if r.affected_user).most_common(5)
    d.top_files = Counter(r.file_name for r in live if r.file_name).most_common(5)

    # ---------------------------------------------------- action/status
    d.action_breakdown = Counter((r.action or "(none)").title() for r in live).most_common(8)
    d.status_breakdown = [("Remediated (quarantined / deleted / blocked)", d.total_remediated)]
    if d.not_remediated:
        d.status_breakdown.append(("Detected, not remediated (log / monitor only)", d.not_remediated))
    if d.simulation_excluded:
        d.status_breakdown.append(("Simulation (excluded)", d.simulation_excluded))

    # -------------------------------------------------------- trends
    day_counter: Counter = Counter()
    week_counter: Counter = Counter()
    for r in live:
        day = (r.detected_time or "")[:10]
        try:
            day_d = dt.datetime.strptime(day, "%Y-%m-%d").date()
        except ValueError:
            continue
        day_counter[day] += 1
        week_counter[day_d - dt.timedelta(days=day_d.weekday())] += 1
    d.daily_counts = sorted(day_counter.items())
    d.weekly_counts = [(w.strftime("%b %d"), n) for w, n in sorted(week_counter.items())]

    d.sample_detections = [
        {
            "time": r.detected_time,
            "service": r.service,
            "threat": r.threat_name,
            "category": r.category,
            "user": r.affected_user,
            "object": r.subject or r.file_name,
            "action": r.action or "(none)",
        }
        for r in remediated[:25]
    ]

    # ------------------------------------------------------- efficacy
    if emails_scanned:
        d.email_prevalence = d.email_detections / emails_scanned * 100
    if files_scanned:
        d.collab_prevalence = d.collab_detections / files_scanned * 100
    if restore_count is not None and d.total_remediated:
        d.false_positive_rate = restore_count / d.total_remediated * 100
    for line in d.category_lines:
        denom = (emails_scanned or 0) + (files_scanned or 0)
        line.prevalence = line.count / denom * 100 if denom else None

    rr = d.remediation_rate
    if rr is None:
        d.coverage_status = "Unknown"
    elif rr < 50:
        d.coverage_status = "Critical"
    elif rr < 80:
        d.coverage_status = "Needs attention"
    elif rr < 95:
        d.coverage_status = "Good"
    else:
        d.coverage_status = "Strong"

    d.config_gaps = _config_gaps(d, live, action_column_missing)
    d.security_posture = _security_posture(d, remediated)
    return d


def _config_gaps(d: ReportData, live: list[CECPRecord], action_column_missing: bool) -> list[dict]:
    """Derived only from signals in the data -- never placeholder findings."""
    gaps: list[dict] = []
    if action_column_missing:
        gaps.append({
            "priority": "P1",
            "title": "No action column in the uploaded logs",
            "detail": "The CSV export had no Action column, so no detection could be counted as remediated and the remediation rate and value figures read as zero.",
            "recommendation": "Re-export the CECP detection logs with the Action column enabled (Manage Columns) and run the report again.",
        })
    if d.not_remediated and live:
        share = d.not_remediated / len(live) * 100
        by_filter = Counter(r.category for r in live if not r.was_blocked).most_common(3)
        gaps.append({
            "priority": "P1" if share >= 20 else "P2",
            "title": f"{d.not_remediated:,} detections logged but not remediated ({share:.1f}%)",
            "detail": "These threats were detected but the matching policy only logged them (Pass/Log, monitor or tag), so they stayed in the mailbox or file share. Most affected: "
                      + ", ".join(f"{c} ({n:,})" for c, n in by_filter) + ".",
            "recommendation": "Review the CECP policies for these filters and switch them from Pass/Log to Quarantine or Delete once tuning is complete.",
        })
    bec = sum(1 for r in live if r.category == "Business Email Compromise" and not r.was_blocked)
    if bec:
        gaps.append({
            "priority": "P1",
            "title": f"{bec:,} BEC detection(s) not remediated",
            "detail": "Business Email Compromise is the highest-loss threat category in the IC3 report (~$123K per victim), and these messages were left in place.",
            "recommendation": "Set the Advanced Spam Protection BEC action to Quarantine and enable Writing Style DNA for high-risk users (executives, finance).",
        })
    observed = {r.service for r in live}
    missing_collab = [s for s in COLLAB_SERVICES if s not in observed and s != "Salesforce"]
    if d.email_detections and not d.collab_detections:
        gaps.append({
            "priority": "P2",
            "title": "No collaboration-app detections this period",
            "detail": "Every detection came from mailboxes. CECP also protects OneDrive, SharePoint Online, Microsoft Teams, Box, Dropbox and Google Drive, but none of them produced a detection.",
            "recommendation": "Confirm those services are connected and have threat protection and DLP policies enabled in CECP; if they are, this is simply a clean period.",
        })
    elif missing_collab and d.collab_detections:
        gaps.append({
            "priority": "P3",
            "title": "Some collaboration services saw no detections",
            "detail": "No detections from: " + ", ".join(missing_collab) + ".",
            "recommendation": "If the customer uses these services, check they are connected and covered by a CECP policy.",
        })
    if d.emails_scanned is None:
        gaps.append({
            "priority": "P2",
            "title": "Scanned email volume unavailable",
            "detail": "Without the number of emails CECP scanned, threat prevalence (detections per scanned email) can't be shown.",
            "recommendation": "Grant the API key Search permission on email activity data, or enter the scanned count from the CECP console's statistics.",
        })
    if d.restore_count is None:
        gaps.append({
            "priority": "P2",
            "title": "False-positive proxy unavailable",
            "detail": "No quarantine-restore count was available, so the false-positive rate can't be estimated.",
            "recommendation": "Grant the API key Audit Logs view permission, or enter the restore count from CECP's quarantine view.",
        })
    if d.unmapped_actions:
        gaps.append({
            "priority": "P2",
            "title": "Unrecognized action value(s)",
            "detail": f"{len(d.unmapped_actions)} action value(s) weren't recognized and were counted as not remediated: {', '.join(d.unmapped_actions)}.",
            "recommendation": "Add them to the action keywords in cecp_client.py so remediated threats aren't undercounted.",
        })
    if d.unscannable:
        gaps.append({
            "priority": "P3",
            "title": f"{d.unscannable:,} unscannable file(s)/URL(s) passed",
            "detail": "These objects (password-protected or oversized archives, unreachable URLs) couldn't be scanned and were delivered per policy. They aren't counted as threats in this report.",
            "recommendation": "If the customer's risk appetite is low, change the unscannable-file action to quarantine, or enable password extraction (Keyword Extraction) for protected archives.",
        })
    other = sum(1 for r in live if r.category == "Other")
    if other:
        gaps.append({
            "priority": "P3",
            "title": "Detections in the uncategorized 'Other' bucket",
            "detail": f"{other:,} detection(s) didn't match any CECP threat sub-type and are counted but not valued.",
            "recommendation": "Add matching keywords to _SUBTYPE_PATTERNS in cost_reference.py.",
        })
    unknown_svc = sum(1 for r in live if r.channel == "Unknown")
    if unknown_svc:
        gaps.append({
            "priority": "P3",
            "title": "Detections with no identifiable service",
            "detail": f"{unknown_svc:,} detection(s) couldn't be attributed to a protected service (Exchange, OneDrive, Teams...).",
            "recommendation": "Include the 'Scan source' / service column in CSV exports; for live pulls, check the scanType values printed in the run log.",
        })
    if d.simulation_excluded:
        gaps.append({
            "priority": "P3",
            "title": "Simulation-mode detections excluded",
            "detail": f"{d.simulation_excluded:,} detection(s) were simulation/test traffic and excluded from every figure.",
            "recommendation": "No action needed unless this looks too high for genuine test traffic.",
        })
    return gaps


def _security_posture(d: ReportData, remediated: list[CECPRecord]) -> list[dict]:
    cats = Counter(r.category for r in remediated)

    def n(*names):
        return sum(cats.get(x, 0) for x in names)

    posture = [
        {"title": "Business Email Compromise Stopped", "icon": "💼",
         "desc": "Impersonation and payment-fraud emails caught by BEC detection and Writing Style DNA, the highest-loss email threat.",
         "count": n("Business Email Compromise")},
        {"title": "Phishing & Malicious URLs Neutralized", "icon": "🎣",
         "desc": "Credential-phishing messages and malicious links in email and Teams chats, caught by anti-phishing and Web Reputation.",
         "count": n("Phishing", "Malicious URL")},
        {"title": "Malware & Ransomware Removed", "icon": "🦠",
         "desc": "Malicious attachments and files in mailboxes and shared storage, removed by malware scanning and machine learning.",
         "count": n("Malware", "Ransomware")},
        {"title": "Zero-day Threats Caught in Sandbox", "icon": "🧪",
         "desc": "Unknown files and URLs detonated in Virtual Analyzer before they could run on a user's device.",
         "count": n("Advanced Threat (Sandbox)")},
        {"title": "Compromised Accounts Detected", "icon": "🔑",
         "desc": "Anomalous sign-ins and internal accounts sending malicious mail, spotted by Correlated Intelligence.",
         "count": n("Account Compromise")},
        {"title": "Sensitive Data Leaks Prevented", "icon": "🛡️",
         "desc": "DLP policy violations (financial, health and personal data) quarantined before they left the organization.",
         "count": n("Data Loss Prevention")},
        {"title": "Collaboration Apps Protected", "icon": "📁",
         "desc": "Threats removed from OneDrive, SharePoint, Teams, Box, Dropbox and Google Drive, beyond what an email gateway can see.",
         "count": sum(1 for r in remediated if r.channel == "Collaboration")},
        {"title": "Spam & Graymail Cleaned Up", "icon": "🚫",
         "desc": "Unwanted bulk mail moved out of inboxes, reducing exposure to phishing lures.",
         "count": n("Spam", "Graymail")},
    ]
    for p in posture:
        p["active"] = p["count"] > 0
    return posture
