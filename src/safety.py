"""Almanac Core — PII risk scoring and cohort safety gates.

Two responsibilities:
1. Score the privacy risk of a data record before it enters any pipeline.
2. Enforce cohort minimums to prevent re-identification through small groups.

Risk scoring uses 6 dimensions (0.0-1.0 each):
  identifiability  — how directly does this identify a person?
  sensitivity       — how harmful if exposed? (health, religion, politics = high)
  linkability       — can this be joined with other datasets to re-identify?
  permanency        — how hard is it for the person to change this? (SSN > email > IP)
  exposability      — how accessible is this data already? (public records < medical)
  compliance_risk   — does handling this trigger legal obligations? (CCPA/GDPR/HIPAA)

Overall risk = weighted mean. Above threshold = BLOCK.
"""

from dataclasses import dataclass


# --- Risk scoring ---

@dataclass
class PrivacyRiskScore:
    identifiability: float
    sensitivity: float
    linkability: float
    permanency: float
    exposability: float
    compliance_risk: float

    def overall(self) -> float:
        weights = {
            "identifiability": 0.25,
            "sensitivity": 0.20,
            "linkability": 0.15,
            "permanency": 0.15,
            "exposability": 0.10,
            "compliance_risk": 0.15,
        }
        total = sum(
            getattr(self, dim) * w for dim, w in weights.items()
        )
        return round(total, 4)

    def verdict(self, threshold: float = 0.60) -> str:
        return "BLOCK" if self.overall() >= threshold else "ALLOW"

    def to_dict(self) -> dict:
        return {
            "identifiability": self.identifiability,
            "sensitivity": self.sensitivity,
            "linkability": self.linkability,
            "permanency": self.permanency,
            "exposability": self.exposability,
            "compliance_risk": self.compliance_risk,
            "overall": self.overall(),
            "verdict": self.verdict(),
        }


# Category → default risk profile (conservative defaults)
CATEGORY_RISK_PROFILES: dict[str, dict[str, float]] = {
    "name_address": {
        "identifiability": 0.8, "sensitivity": 0.3, "linkability": 0.7,
        "permanency": 0.6, "exposability": 0.5, "compliance_risk": 0.5,
    },
    "phone_email": {
        "identifiability": 0.7, "sensitivity": 0.3, "linkability": 0.6,
        "permanency": 0.4, "exposability": 0.4, "compliance_risk": 0.4,
    },
    "ssn_financial": {
        "identifiability": 1.0, "sensitivity": 0.9, "linkability": 1.0,
        "permanency": 1.0, "exposability": 0.2, "compliance_risk": 0.9,
    },
    "court_records": {
        "identifiability": 0.7, "sensitivity": 0.7, "linkability": 0.5,
        "permanency": 0.9, "exposability": 0.6, "compliance_risk": 0.7,
    },
    "property_records": {
        "identifiability": 0.6, "sensitivity": 0.4, "linkability": 0.7,
        "permanency": 0.8, "exposability": 0.7, "compliance_risk": 0.4,
    },
    "social_media": {
        "identifiability": 0.6, "sensitivity": 0.4, "linkability": 0.8,
        "permanency": 0.3, "exposability": 0.8, "compliance_risk": 0.3,
    },
    "employment": {
        "identifiability": 0.7, "sensitivity": 0.5, "linkability": 0.6,
        "permanency": 0.5, "exposability": 0.3, "compliance_risk": 0.5,
    },
    "education": {
        "identifiability": 0.5, "sensitivity": 0.3, "linkability": 0.4,
        "permanency": 0.7, "exposability": 0.3, "compliance_risk": 0.4,
    },
    "health_records": {
        "identifiability": 0.8, "sensitivity": 1.0, "linkability": 0.7,
        "permanency": 0.9, "exposability": 0.1, "compliance_risk": 1.0,
    },
    "vehicle_records": {
        "identifiability": 0.5, "sensitivity": 0.2, "linkability": 0.6,
        "permanency": 0.4, "exposability": 0.5, "compliance_risk": 0.3,
    },
    "voter_records": {
        "identifiability": 0.7, "sensitivity": 0.6, "linkability": 0.5,
        "permanency": 0.7, "exposability": 0.6, "compliance_risk": 0.6,
    },
    "professional_license": {
        "identifiability": 0.6, "sensitivity": 0.3, "linkability": 0.5,
        "permanency": 0.6, "exposability": 0.6, "compliance_risk": 0.3,
    },
    "dating_profile": {
        "identifiability": 0.5, "sensitivity": 0.6, "linkability": 0.7,
        "permanency": 0.2, "exposability": 0.4, "compliance_risk": 0.4,
    },
    "mugshot": {
        "identifiability": 0.9, "sensitivity": 0.9, "linkability": 0.6,
        "permanency": 0.9, "exposability": 0.7, "compliance_risk": 0.7,
    },
    "other": {
        "identifiability": 0.5, "sensitivity": 0.5, "linkability": 0.5,
        "permanency": 0.5, "exposability": 0.5, "compliance_risk": 0.5,
    },
}


def score_category(category: str) -> PrivacyRiskScore:
    """Score a record category using default risk profiles."""
    profile = CATEGORY_RISK_PROFILES.get(category, CATEGORY_RISK_PROFILES["other"])
    return PrivacyRiskScore(**profile)


def score_record(
    category: str,
    has_exact_location: bool = False,
    has_financial: bool = False,
    has_health: bool = False,
    cohort_size: int | None = None,
) -> PrivacyRiskScore:
    """Score a record with context-specific adjustments."""
    score = score_category(category)

    if has_exact_location:
        score.identifiability = min(1.0, score.identifiability + 0.2)
        score.linkability = min(1.0, score.linkability + 0.2)

    if has_financial:
        score.sensitivity = min(1.0, score.sensitivity + 0.3)
        score.compliance_risk = min(1.0, score.compliance_risk + 0.2)

    if has_health:
        score.sensitivity = 1.0
        score.compliance_risk = 1.0

    if cohort_size is not None and cohort_size < 50:
        score.identifiability = min(1.0, score.identifiability + 0.3)

    return score


# --- Cohort safety gate ---

SENSITIVE_CATEGORIES = frozenset({
    "health_records", "ssn_financial", "court_records", "mugshot",
    "voter_records",
})

DEFAULT_COHORT_MINIMUM = 50
SENSITIVE_COHORT_MINIMUM = 100


def cohort_gate(
    cohort_size: int,
    category: str = "other",
    minimum: int | None = None,
) -> dict:
    """Check whether a cohort is large enough for safe aggregation/licensing.

    Returns dict with verdict (ALLOW/BLOCK), reason, and thresholds.
    """
    if minimum is None:
        minimum = (
            SENSITIVE_COHORT_MINIMUM
            if category in SENSITIVE_CATEGORIES
            else DEFAULT_COHORT_MINIMUM
        )

    if cohort_size < minimum:
        return {
            "verdict": "BLOCK",
            "cohort_size": cohort_size,
            "minimum_required": minimum,
            "category": category,
            "reason": f"Cohort size {cohort_size} below minimum {minimum} for {category}",
        }
    return {
        "verdict": "ALLOW",
        "cohort_size": cohort_size,
        "minimum_required": minimum,
        "category": category,
        "reason": f"Cohort size {cohort_size} meets minimum {minimum}",
    }
