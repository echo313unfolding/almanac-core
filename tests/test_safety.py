"""Almanac Core — PII risk scoring and cohort safety gate tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from safety import (
    PrivacyRiskScore,
    score_category,
    score_record,
    cohort_gate,
    CATEGORY_RISK_PROFILES,
    DEFAULT_COHORT_MINIMUM,
    SENSITIVE_COHORT_MINIMUM,
    SENSITIVE_CATEGORIES,
)


# --- Risk scoring ---

def test_ssn_financial_blocks():
    score = score_category("ssn_financial")
    assert score.verdict() == "BLOCK"
    assert score.overall() > 0.6

def test_education_allows():
    score = score_category("education")
    assert score.verdict() == "ALLOW"
    assert score.overall() < 0.6

def test_health_records_block():
    score = score_category("health_records")
    assert score.verdict() == "BLOCK"

def test_mugshot_blocks():
    score = score_category("mugshot")
    assert score.verdict() == "BLOCK"

def test_phone_email_allows():
    score = score_category("phone_email")
    assert score.verdict() == "ALLOW"

def test_unknown_category_uses_other():
    score = score_category("totally_unknown")
    other = score_category("other")
    assert score.overall() == other.overall()

def test_all_categories_have_profiles():
    categories = [
        "name_address", "phone_email", "ssn_financial", "court_records",
        "property_records", "social_media", "employment", "education",
        "health_records", "vehicle_records", "voter_records",
        "professional_license", "dating_profile", "mugshot", "other",
    ]
    for cat in categories:
        assert cat in CATEGORY_RISK_PROFILES

def test_score_to_dict():
    score = score_category("phone_email")
    d = score.to_dict()
    assert "overall" in d
    assert "verdict" in d
    assert 0.0 <= d["overall"] <= 1.0


# --- Contextual adjustments ---

def test_exact_location_increases_risk():
    base = score_record("phone_email")
    located = score_record("phone_email", has_exact_location=True)
    assert located.overall() > base.overall()

def test_financial_flag_increases_risk():
    base = score_record("phone_email")
    financial = score_record("phone_email", has_financial=True)
    assert financial.overall() > base.overall()

def test_health_flag_maxes_sensitivity():
    score = score_record("phone_email", has_health=True)
    assert score.sensitivity == 1.0
    assert score.compliance_risk == 1.0

def test_small_cohort_increases_identifiability():
    base = score_record("phone_email")
    small = score_record("phone_email", cohort_size=10)
    assert small.identifiability > base.identifiability


# --- Cohort gate ---

def test_cohort_gate_allows_large():
    result = cohort_gate(200, "phone_email")
    assert result["verdict"] == "ALLOW"
    assert result["minimum_required"] == DEFAULT_COHORT_MINIMUM

def test_cohort_gate_blocks_small():
    result = cohort_gate(10, "phone_email")
    assert result["verdict"] == "BLOCK"

def test_cohort_gate_sensitive_higher_threshold():
    result = cohort_gate(75, "health_records")
    assert result["verdict"] == "BLOCK"
    assert result["minimum_required"] == SENSITIVE_COHORT_MINIMUM

def test_cohort_gate_sensitive_allows_large():
    result = cohort_gate(150, "ssn_financial")
    assert result["verdict"] == "ALLOW"

def test_cohort_gate_custom_minimum():
    result = cohort_gate(30, "other", minimum=25)
    assert result["verdict"] == "ALLOW"

def test_cohort_gate_boundary():
    result = cohort_gate(50, "phone_email")
    assert result["verdict"] == "ALLOW"
    result = cohort_gate(49, "phone_email")
    assert result["verdict"] == "BLOCK"

def test_sensitive_categories_defined():
    for cat in SENSITIVE_CATEGORIES:
        assert cat in CATEGORY_RISK_PROFILES
