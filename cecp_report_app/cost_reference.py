"""
cost_reference.py  (CECP)

Potential-loss model for Cloud Email and Collaboration Protection, using
the same methodology as the CEGP report / TMES sheet:

    potential loss avoided = detections x IC3 loss-per-victim
                             x (days in period / 91.25)

Loss-per-victim figures come from the latest FBI IC3 Internet Crime
Report (2025 edition, published 2026) and are identical to the CEGP app's
table so the two products' reports stay comparable.

CECP's threat taxonomy differs from the gateway's: it protects mailboxes
(Exchange Online, Gmail) through the provider's API AND collaboration
apps (OneDrive, SharePoint, Teams, Box, Dropbox, Google Drive), and its
headline detections are BEC / writing-style impersonation, credential
phishing, ransomware and malware in shared files, sandbox (Virtual
Analyzer) zero-days, account compromise signals and DLP violations.
"""

from __future__ import annotations

import re

IC3_SOURCE = "FBI IC3 2025 Internet Crime Report -- avg. loss per victim, 2025"

IC3_CATEGORIES = {
    "C1": {"name": "BEC", "loss_per_victim": 123_005.43},
    "C2": {"name": "Computer Intrusion", "loss_per_victim": 25_567.71},
    "C3": {"name": "Corporate Data Breach", "loss_per_victim": 109_826.14},
    "C4": {"name": "Credit Card Fraud", "loss_per_victim": 15_056.47},
    "C5": {"name": "Botnet/DDOS", "loss_per_victim": 19_383.29},
    "C6": {"name": "Identity Theft", "loss_per_victim": 5_866.86},
    "C7": {"name": "Malware/Scareware", "loss_per_victim": 21_691.57},
    "C8": {"name": "Phishing/Spoofing", "loss_per_victim": 1_126.76},
    "C9": {"name": "Ransomware", "loss_per_victim": 8_950.46},
    "C10": {"name": "Network Equipment", "loss_per_victim": 44_664.10},
    "C11": {"name": "Extortion (DLP)", "loss_per_victim": 1_374.40},
}

# CECP threat sub-type -> IC3 category. None = counted, not costed.
#
# Assumptions worth confirming against your own template:
#   - BEC / writing-style (Writing Style DNA) / executive impersonation
#     -> C1 BEC. This is the largest single driver of the value figure.
#   - Account compromise (Correlated Intelligence anomalies, suspicious
#     sign-ins, compromised internal accounts) -> C2 Computer Intrusion.
#   - Virtual Analyzer / sandbox zero-day detections -> C3 Corporate Data
#     Breach, matching how the CEGP app values APT-style detections.
#   - DLP violations -> C11, the IC3 row the TMES sheet labels "(DLP)".
CECP_SUBTYPE_CATEGORY = {
    "Business Email Compromise": "C1",
    "Account Compromise": "C2",
    "Advanced Threat (Sandbox)": "C3",
    "Malware": "C7",
    "Ransomware": "C9",
    "Phishing": "C8",
    "Malicious URL": "C8",
    "Spam": "C8",
    "Data Loss Prevention": "C11",
    "File Blocking": None,
    "Shared Link Control": None,
    "Graymail": None,
    "Scan Exception": None,
}

QUARTER_DAYS = 365.0 / 4  # 91.25

# (pattern, sub-type) checked IN ORDER against the lower-cased threat text
# (threat type + threat name + security filter). Patterns are regexes so
# short tokens like "bec" only match as whole words.
_SUBTYPE_PATTERNS = [
    (r"ransom", "Ransomware"),
    # Before Malware: CECP labels unscannable items "Malware: Other protected
    # file" / "Malware: Over restriction (...)" -- scan exceptions, not malware.
    (r"password.?protected|unscannable|scan exception|encrypted file|protected file"
     r"|over restriction", "Scan Exception"),
    (r"brand impersonation", "Phishing"),
    # The anti-spam engine's combined label -- valued as Spam (C8).
    (r"spam/graymail", "Spam"),
    (r"unwanted marketing|marketing email", "Graymail"),
    (r"business email compromise|\bbec\b|writing style|impersonat"
     r"|ceo fraud|\bfraud\b|display name spoof", "Business Email Compromise"),
    (r"account compromise|compromised account|account takeover|suspicious sign"
     r"|suspicious login|anomal|correlated intelligence|impossible travel", "Account Compromise"),
    (r"virtual analyzer|sandbox|zero.?day|advanced persistent|targeted attack", "Advanced Threat (Sandbox)"),
    (r"troj|malware|virus|worm|backdoor|spyware|machine learning|\bpua\b|exploit", "Malware"),
    (r"shared link|sharing link|link control|external sharing", "Shared Link Control"),
    (r"phish|credential|brand impersonation", "Phishing"),
    (r"web reputation|malicious url|\burl\b|malicious link|suspicious link", "Malicious URL"),
    (r"graymail|marketing|newsletter|social network|bulk", "Graymail"),
    (r"spam", "Spam"),
    (r"data loss|\bdlp\b|sensitive|compliance|pci|hipaa|gdpr|\bpii\b|credit card|ssn", "Data Loss Prevention"),
    (r"file blocking|blocked file|file type|true file|file extension", "File Blocking"),
]
_COMPILED = [(re.compile(p), s) for p, s in _SUBTYPE_PATTERNS]


def categorize(threat_text: str) -> str:
    """Map threat text to a CECP sub-type, or "Other" (tracked, not costed)."""
    text = (threat_text or "").lower()
    for pattern, subtype in _COMPILED:
        if pattern.search(text):
            return subtype
    return "Other"


def period_fraction(days_in_period: float) -> float:
    return days_in_period / QUARTER_DAYS


def potential_loss_per_unit(subtype: str) -> tuple[float, str | None]:
    category = CECP_SUBTYPE_CATEGORY.get(subtype)
    if category is None:
        return 0.0, None
    return IC3_CATEGORIES[category]["loss_per_victim"], category


def unmapped_subtypes() -> list[str]:
    return [k for k, v in CECP_SUBTYPE_CATEGORY.items() if v is None]


# ------------------------------------------------------------- services

EMAIL_SERVICES = ("Exchange Online", "Gmail")
COLLAB_SERVICES = (
    "OneDrive", "SharePoint Online", "Microsoft Teams",
    "Box", "Dropbox", "Google Drive", "Salesforce",
)
ALL_SERVICES = EMAIL_SERVICES + COLLAB_SERVICES

_SERVICE_PATTERNS = [
    (r"dropbox", "Dropbox"),
    (r"onedrive", "OneDrive"),
    (r"sharepoint", "SharePoint Online"),
    (r"teams", "Microsoft Teams"),
    (r"google ?drive|gdrive", "Google Drive"),
    (r"gmail|google workspace mail", "Gmail"),
    (r"salesforce", "Salesforce"),
    (r"\bbox\b", "Box"),
    (r"exchange|outlook|office ?365 mail|m365 mail|mailbox", "Exchange Online"),
]
_SERVICE_COMPILED = [(re.compile(p), s) for p, s in _SERVICE_PATTERNS]


def normalize_service(text: str) -> str:
    t = (text or "").lower()
    for pattern, service in _SERVICE_COMPILED:
        if pattern.search(t):
            return service
    return "Unknown service"


def service_channel(service: str) -> str:
    if service in EMAIL_SERVICES:
        return "Email"
    if service in COLLAB_SERVICES:
        return "Collaboration"
    return "Unknown"
