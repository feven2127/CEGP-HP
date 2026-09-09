

from __future__ import annotations

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

# TMES sheet's 12 threat sub-types -> IC3 category. None = tracked for
# count/percentage only, no cost mapped (matches the blank Category
# Mapping column in the customer's template for these six).
TMES_SUBTYPE_CATEGORY = {
    "Spam": "C8",
    "Phishing": "C8",
    "Web Reputation": "C8",
    "Ransomware": "C9",
    "Advanced Persistent Threat": "C3",
    "Malware": "C7",
    "Email Reputation Service": None,
    "SPF Violation": None,
    "Graymail": None,
    "Scan Exception": None,
    "Content Filtering": None,
    "Attachment": None,
}

QUARTER_DAYS = 365.0 / 4  # 91.25 -- generalizes the sheet's fixed 0.25

# Keyword -> TMES sub-type, checked IN ORDER (case-insensitive substring
# match, most specific first). Vision One doesn't return these 12 labels
# natively, so real CEGP detection fields (malName/objectSubType/
# filterName/ruleName/eventName/eventSubName) are mapped in here.
#
# Assumptions worth double-checking against your own taxonomy:
#   - DMARC/SPF/DKIM rule triggers all fold into "SPF Violation" -- the
#     TMES template has no separate DMARC/DKIM bucket.
#   - CEGP's blended "Spam or Phish" catch-all folds into "Spam" (both
#     Spam and Phishing map to the same IC3 category C8 here, so this
#     doesn't skew the cost figure either way).
#   - "Correlated Intelligence Anomalies" / "Virtual Analyzer" fold into
#     "Advanced Persistent Threat" (cross-referenced threat intel /
#     sandboxing, both APT-adjacent detection mechanisms).
_SUBTYPE_KEYWORDS = [
    ("ransomware", "Ransomware"),
    ("virtual analyzer", "Advanced Persistent Threat"),
    ("correlated intelligence", "Advanced Persistent Threat"),
    ("advanced persistent threat", "Advanced Persistent Threat"),
    ("targeted attack", "Advanced Persistent Threat"),
    ("trojan", "Malware"),
    ("malware", "Malware"),
    ("virus", "Malware"),
    ("worm", "Malware"),
    ("password protected", "Scan Exception"),
    ("scan exception", "Scan Exception"),
    ("unscannable", "Scan Exception"),
    ("web reputation", "Web Reputation"),
    ("malicious url", "Web Reputation"),
    ("url", "Web Reputation"),
    ("credential", "Phishing"),
    ("brand impersonation", "Phishing"),
    ("phishing", "Phishing"),
    ("spam or phish", "Spam"),
    ("spam", "Spam"),
    ("graymail", "Graymail"),
    ("dmarc", "SPF Violation"),
    ("spf", "SPF Violation"),
    ("dkim", "SPF Violation"),
    ("email reputation", "Email Reputation Service"),
    ("sender reputation", "Email Reputation Service"),
    ("connectionfilter", "Email Reputation Service"),
    ("connection filter", "Email Reputation Service"),
    ("content filtering", "Content Filtering"),
    ("data loss prevention", "Content Filtering"),
    ("dlp", "Content Filtering"),
    ("recipient size", "Attachment"),
    ("attachment", "Attachment"),
]


def categorize(threat_name: str) -> str:
    """Map a raw threat/malware name string to one of the 12 TMES
    sub-types, or "Other" if nothing matches (tracked, never dropped)."""
    name = (threat_name or "").lower()
    for keyword, subtype in _SUBTYPE_KEYWORDS:
        if keyword in name:
            return subtype
    return "Other"


def period_fraction(days_in_period: float) -> float:
    """Generalizes the TMES sheet's fixed quarterly divisor (0.25) to any
    date-range length: days in the report period / days in an average
    quarter (91.25)."""
    return days_in_period / QUARTER_DAYS


def potential_loss_per_unit(subtype: str) -> tuple[float, str | None]:
    """(loss-per-victim, IC3 category code) for a TMES sub-type, or
    (0.0, None) if this sub-type isn't cost-mapped."""
    category = TMES_SUBTYPE_CATEGORY.get(subtype)
    if category is None:
        return 0.0, None
    return IC3_CATEGORIES[category]["loss_per_victim"], category
