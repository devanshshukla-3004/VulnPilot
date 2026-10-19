"""Transparent prioritization heuristic; not a probability of compromise."""
CRITICALITY_POINTS = {"low": 5, "medium": 12, "high": 20, "critical": 25}
STATUS_MULTIPLIER = {"open": 1.0, "in_progress": 0.65, "resolved": 0.0}

def calculate_risk(cvss: float, criticality: str, internet_exposed: bool,
                   exploit_available: bool, status: str = "open") -> tuple[int, list[str]]:
    if not 0 <= cvss <= 10:
        raise ValueError("CVSS must be between 0 and 10")
    if criticality not in CRITICALITY_POINTS:
        raise ValueError("Unknown asset criticality")
    if status not in STATUS_MULTIPLIER:
        raise ValueError("Unknown remediation status")
    base = round(cvss * 5)  # maximum 50 points
    asset_points = CRITICALITY_POINTS[criticality]
    exposure_points = 15 if internet_exposed else 0
    exploit_points = 10 if exploit_available else 0
    raw = min(100, base + asset_points + exposure_points + exploit_points)
    score = round(raw * STATUS_MULTIPLIER[status])
    factors = [f"CVSS contribution: {base}/50", f"Asset criticality: +{asset_points}",
               f"Internet exposure: +{exposure_points}", f"Exploit availability: +{exploit_points}",
               f"Status multiplier: {STATUS_MULTIPLIER[status]:.2f}"]
    return score, factors

def risk_label(score: int) -> str:
    if score >= 80: return "critical"
    if score >= 60: return "high"
    if score >= 35: return "medium"
    return "low"
