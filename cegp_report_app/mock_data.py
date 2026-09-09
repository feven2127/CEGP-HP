"""
mock_data.py

Generates realistic-looking fake CEGP detection records so the app can be
demoed end-to-end without a live Vision One API key.

Threat/policy names below use the TMES sheet's own 12 sub-types directly
(see cost_reference.TMES_SUBTYPE_CATEGORY) rather than raw CEGP policy
names, so demo mode previews the exact groupings the live report produces.
Relative weights approximate a real tenant's monthly mix: Spam dominates
by a wide margin, authentication/reputation rules are next, and
malware/ransomware/attachment-based detections are comparatively rare.
"""

from __future__ import annotations

import datetime as dt
import random

from vision_one_client import DetectionRecord

# (TMES sub-type name, relative weight)
THREAT_TYPES_WEIGHTED = [
    ("Spam", 8060),
    ("SPF Violation", 1130),
    ("Advanced Persistent Threat", 424),
    ("Phishing", 300),
    ("Web Reputation", 90),
    ("Graymail", 57),
    ("Email Reputation Service", 45),
    ("Malware", 23),
    ("Content Filtering", 15),
    ("Ransomware", 12),
    ("Scan Exception", 10),
    ("Attachment", 5),
]

DOMAINS = ["acmecorp.com", "acmecorp.com", "acmecorp.com", "acmefinance.com"]


# act values and their relative weight -- mostly real blocks, with a small
# slice of monitor-mode detections that were logged but not stopped, so the
# mail-tracking "detected, not blocked" bucket has something to show in demo.
ACTIONS_WEIGHTED = [
    ("Block", 92),
    ("Quarantine", 5),
    ("not blocked", 3),
]


def generate_mock_detections(start: dt.datetime, end: dt.datetime, count: int = 250):
    records = []
    span_seconds = max(int((end - start).total_seconds()), 1)
    names = [t[0] for t in THREAT_TYPES_WEIGHTED]
    weights = [t[1] for t in THREAT_TYPES_WEIGHTED]
    action_names = [a[0] for a in ACTIONS_WEIGHTED]
    action_weights = [a[1] for a in ACTIONS_WEIGHTED]
    for i in range(count):
        offset = random.randint(0, span_seconds)
        detected = start + dt.timedelta(seconds=offset)
        threat = random.choices(names, weights=weights)[0]
        recipient_user = f"user{random.randint(1, 40)}"
        domain = random.choice(DOMAINS)
        records.append(
            DetectionRecord(
                raw={
                    "pname": "Email and Collaboration Security",
                    "malName": threat,
                    "act": random.choices(action_names, weights=action_weights)[0],
                    "detectedDateTime": detected.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "suser": f"external-sender-{random.randint(1, 200)}@{random.choice(['evil-domain.com','fake-invoice.net','phish-mail.ru'])}",
                    "duser": f"{recipient_user}@{domain}",
                    "mailMsgSubject": random.choice(
                        [
                            "Urgent: Invoice Payment Required",
                            "Your account has been suspended",
                            "Re: Wire transfer confirmation",
                            "Password expiry notice",
                            "Shared document - action needed",
                        ]
                    ),
                }
            )
        )
    records.sort(key=lambda r: r.detected_time)
    return records


def generate_mock_scanned_count(blocked_count: int) -> int:
    """
    Fabricate a plausible total-inbound-volume figure so the demo block
    rate looks realistic (~0.6%-1.2% of inbound mail is malicious, roughly
    in line with published email-threat-rate ranges).
    """
    assumed_block_rate = random.uniform(0.006, 0.012)
    return int(blocked_count / assumed_block_rate)


def generate_mock_restore_count(blocked_count: int) -> int:
    """Fabricate a small false-positive count, ~1-4% of blocked messages."""
    rate = random.uniform(0.01, 0.04)
    return max(0, round(blocked_count * rate))


def generate_mock_delivered_flagged_count(total_scanned: int) -> int:
    """Fabricate a "delivered but flagged" count (graymail/low-confidence
    spam let through per policy) for the mail tracking status breakdown,
    ~3-6% of accepted mail volume."""
    rate = random.uniform(0.03, 0.06)
    return max(0, round(total_scanned * rate))
