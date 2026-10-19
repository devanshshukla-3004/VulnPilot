import pytest
from backend.app.risk import calculate_risk, risk_label

def test_risk_increases_with_exposure_and_exploit():
    base, _ = calculate_risk(8.0, "high", False, False)
    elevated, factors = calculate_risk(8.0, "high", True, True)
    assert elevated > base
    assert any("Exploit availability" in item for item in factors)

def test_resolved_score_is_zero():
    score, _ = calculate_risk(10, "critical", True, True, "resolved")
    assert score == 0

def test_score_is_bounded():
    score, _ = calculate_risk(10, "critical", True, True)
    assert 0 <= score <= 100

def test_invalid_cvss_rejected():
    with pytest.raises(ValueError):
        calculate_risk(10.1, "high", False, False)

def test_label_boundaries():
    assert risk_label(85) == "critical"
    assert risk_label(65) == "high"
    assert risk_label(40) == "medium"
    assert risk_label(10) == "low"
