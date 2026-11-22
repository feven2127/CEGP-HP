"""
mock_data.py  (CECP)

Realistic-looking fake CECP detections so the app can be demoed without a
Vision One API key. Mix approximates an M365 tenant: mailbox detections
dominate (spam / phishing / BEC), collaboration apps see fewer but
higher-impact file threats (malware, ransomware, DLP).
"""

from __future__ import annotations

import datetime as dt
import random

from cecp_client import CECPRecord

# (service, threat type, security filter, relative weight)
DETECTIONS_WEIGHTED = [
    ("Exchange Online", "Spam", "Advanced Spam Protection", 520),
    ("Exchange Online", "Phishing", "Advanced Spam Protection", 210),
    ("Exchange Online", "Business Email Compromise", "Advanced Spam Protection", 38),
    ("Exchange Online", "Writing Style Analysis - Impersonation", "Advanced Spam Protection", 12),
    ("Exchange Online", "Malicious URL", "Web Reputation", 95),
    ("Exchange Online", "Graymail", "Advanced Spam Protection", 140),
    ("Exchange Online", "Malware", "Malware Scanning", 24),
    ("Exchange Online", "Zero-day threat", "Virtual Analyzer", 9),
    ("Exchange Online", "Ransomware", "Malware Scanning", 3),
    ("Exchange Online", "Account compromise - anomalous sign-in", "Correlated Intelligence", 6),
    ("Exchange Online", "PCI-DSS credit card numbers", "Data Loss Prevention", 18),
    ("OneDrive", "Malware", "Malware Scanning", 14),
    ("OneDrive", "Ransomware", "Malware Scanning", 2),
    ("OneDrive", "Personal data (GDPR)", "Data Loss Prevention", 22),
    ("SharePoint Online", "Malware", "Malware Scanning", 11),
    ("SharePoint Online", "Blocked file type (.exe)", "File Blocking", 16),
    ("SharePoint Online", "HIPAA health records", "Data Loss Prevention", 9),
    ("Microsoft Teams", "Malicious URL", "Web Reputation", 19),
    ("Microsoft Teams", "Phishing", "Web Reputation", 7),
    ("Microsoft Teams", "Malware", "Malware Scanning", 5),
]

# (action, weight) per security filter family -- most threats remediated,
# a small monitor-only slice so the "detected, not remediated" bucket and
# its configuration gap have something to show.
ACTIONS = {
    "Data Loss Prevention": [("Quarantine", 55), ("Pass/Log", 45)],
    "File Blocking": [("Quarantine", 90), ("Pass/Log", 10)],
    "Correlated Intelligence": [("Pass/Log", 100)],
}
DEFAULT_ACTIONS = [("Quarantine", 78), ("Delete", 14), ("Move to Junk", 4), ("Pass/Log", 4)]

FILES = ["invoice_0457.docm", "payroll_Q3.xlsx", "setup.exe", "contract_signed.pdf.js", "scan_2026.zip", "hr_records.csv"]


def generate_mock_detections(start: dt.datetime, end: dt.datetime, count: int = 400) -> list[CECPRecord]:
    span = max(int((end - start).total_seconds()), 1)
    weights = [d[3] for d in DETECTIONS_WEIGHTED]
    records = []
    for _ in range(count):
        service, threat, sec_filter, _w = random.choices(DETECTIONS_WEIGHTED, weights=weights)[0]
        options = ACTIONS.get(sec_filter, DEFAULT_ACTIONS)
        action = random.choices([a for a, _ in options], weights=[w for _, w in options])[0]
        when = start + dt.timedelta(seconds=random.randint(0, span))
        user = f"user{random.randint(1, 60)}@acmecorp.com"
        is_mail = service == "Exchange Online"
        records.append(CECPRecord(raw={
            "service": service,
            "threatType": threat,
            "securityFilter": sec_filter,
            "act": action,
            "detectedDateTime": when.strftime("%Y-%m-%dT%H:%M:%S"),
            "affectedUser": user,
            "sender": f"sender{random.randint(1, 150)}@{random.choice(['evil-domain.com', 'fake-invoice.net', 'lookalike-acme.co'])}" if is_mail else user,
            "mailMsgSubject": random.choice([
                "Urgent wire transfer today", "Your mailbox is almost full",
                "Shared document: Q3 payroll", "Invoice overdue", "Quick favor - are you at your desk?",
            ]) if is_mail else "",
            "fileName": random.choice(FILES) if (not is_mail or sec_filter in ("Malware Scanning", "Data Loss Prevention")) else "",
        }))
    records.sort(key=lambda r: r.detected_time)
    return records


def generate_mock_scanned_email_count(email_detections: int) -> int:
    """~2-4% of mailbox email carries a detection in a typical tenant."""
    return int(email_detections / random.uniform(0.02, 0.04))


def generate_mock_scanned_file_count(collab_detections: int) -> int:
    return int(collab_detections / random.uniform(0.002, 0.006))


def generate_mock_restore_count(remediated: int) -> int:
    return max(0, round(remediated * random.uniform(0.005, 0.02)))
