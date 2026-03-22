"""
Fuzzi - Enhanced Fuzzy Logic Risk Assessment Engine
Mamdani-style FIS covering:
  Security dimensions  : security_headers, authentication_config, access_control,
                         directory_permissions, error_handling, debug_mode, cloud_config
  Website quality dims : seo_score, readability_score, design_consistency,
                         performance_risk, ssl_tls_config, input_validation,
                         third_party_risk
All inputs normalised 0-1 (higher = more problematic / riskier).
Outputs: risk_score 0-1, risk_level LOW/MEDIUM/HIGH/CRITICAL,
         category_scores 0-100 (inverted, higher = better), triggered_rules, etc.
"""
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Membership functions
# ---------------------------------------------------------------------------

def trimf(x: float, a: float, b: float, c: float) -> float:
    """Triangular MF."""
    v = max(0.0, min(1.0, x))
    if v <= a or v >= c:
        return 0.0
    if v == b:
        return 1.0
    if v < b:
        return (v - a) / (b - a) if b != a else 1.0
    return (c - v) / (c - b) if c != b else 1.0


def trapmf(x: float, a: float, b: float, c: float, d: float) -> float:
    """Trapezoidal MF."""
    v = max(0.0, min(1.0, x))
    if v >= d:
        return 0.0
    if v < a:
        return 0.0
    if b <= v <= c:
        return 1.0
    if v < b:
        return (v - a) / (b - a) if b != a else 1.0
    return (d - v) / (d - c) if d != c else 1.0


def gaussmf(x: float, mean: float, sigma: float) -> float:
    """Gaussian MF for smoother transitions."""
    import math
    v = max(0.0, min(1.0, x))
    return math.exp(-0.5 * ((v - mean) / sigma) ** 2)


# ---------------------------------------------------------------------------
# Fuzzification — 5-level linguistic variables
# ---------------------------------------------------------------------------

def fuzzify(value: float) -> dict:
    """
    Map crisp 0-1 value to 5 linguistic levels:
      VERY_LOW  : trapmf(0,   0,    0.10, 0.25)
      LOW       : trimf (0.10, 0.25, 0.40)
      MEDIUM    : trimf (0.30, 0.50, 0.70)
      HIGH      : trimf (0.60, 0.75, 0.90)
      VERY_HIGH : trapmf(0.75, 0.90, 1.0,  1.0)
    """
    v = max(0.0, min(1.0, value))
    return {
        "VERY_LOW":  trapmf(v, 0.0,  0.0,  0.10, 0.25),
        "LOW":       trimf(v,  0.10, 0.25, 0.40),
        "MEDIUM":    trimf(v,  0.30, 0.50, 0.70),
        "HIGH":      trimf(v,  0.60, 0.75, 0.90),
        "VERY_HIGH": trapmf(v, 0.75, 0.90, 1.0,  1.0),
    }


def fuzzify_simple(value: float) -> dict:
    """3-level LOW/MEDIUM/HIGH for backward compat."""
    m = fuzzify(value)
    return {
        "LOW":    max(m["VERY_LOW"], m["LOW"]),
        "MEDIUM": m["MEDIUM"],
        "HIGH":   max(m["HIGH"], m["VERY_HIGH"]),
    }


# ---------------------------------------------------------------------------
# Expanded rule base (40 rules)
# ---------------------------------------------------------------------------
# Format: (id, description, [(factor, level)], consequent, weight)
# Consequent levels: LOW / MEDIUM / HIGH / CRITICAL
# ---------------------------------------------------------------------------

RULES = [
    # ── Security Headers ──────────────────────────────────────────────────
    ("R01", "Missing security headers → HIGH risk",
     [("security_headers", "HIGH")], "HIGH", 1.0),
    ("R02", "Severely missing security headers → CRITICAL",
     [("security_headers", "VERY_HIGH")], "CRITICAL", 1.1),
    ("R03", "Good security headers → LOW risk",
     [("security_headers", "VERY_LOW")], "LOW", 1.0),

    # ── Authentication ────────────────────────────────────────────────────
    ("R04", "Weak authentication → HIGH risk",
     [("authentication_config", "HIGH")], "HIGH", 1.0),
    ("R05", "Very weak authentication → CRITICAL",
     [("authentication_config", "VERY_HIGH")], "CRITICAL", 1.2),
    ("R06", "CSP missing AND auth weak → CRITICAL",
     [("security_headers", "HIGH"), ("authentication_config", "HIGH")], "CRITICAL", 1.2),

    # ── Access Control ────────────────────────────────────────────────────
    ("R07", "Weak access control → MEDIUM risk",
     [("access_control", "MEDIUM")], "MEDIUM", 0.8),
    ("R08", "Weak access control → HIGH risk",
     [("access_control", "HIGH")], "HIGH", 1.0),
    ("R09", "Auth weak AND access control weak → CRITICAL",
     [("authentication_config", "HIGH"), ("access_control", "HIGH")], "CRITICAL", 1.25),
    ("R10", "CORS wildcard AND no auth → CRITICAL",
     [("access_control", "VERY_HIGH"), ("authentication_config", "HIGH")], "CRITICAL", 1.3),

    # ── Directory Permissions ─────────────────────────────────────────────
    ("R11", "Open directory listing → HIGH risk",
     [("directory_permissions", "HIGH")], "HIGH", 0.9),
    ("R12", "Cloud misconfiguration AND open dirs → CRITICAL",
     [("cloud_config", "HIGH"), ("directory_permissions", "HIGH")], "CRITICAL", 1.2),
    ("R13", "Sensitive paths exposed → CRITICAL",
     [("directory_permissions", "VERY_HIGH")], "CRITICAL", 1.15),

    # ── Error Handling ────────────────────────────────────────────────────
    ("R14", "Error handling weak → MEDIUM risk",
     [("error_handling", "MEDIUM")], "MEDIUM", 0.75),
    ("R15", "Error handling very weak → HIGH risk",
     [("error_handling", "HIGH")], "HIGH", 0.9),
    ("R16", "Debug mode AND error exposure → CRITICAL",
     [("debug_mode", "HIGH"), ("error_handling", "HIGH")], "CRITICAL", 1.3),

    # ── Debug Mode ────────────────────────────────────────────────────────
    ("R17", "Debug mode enabled → HIGH risk",
     [("debug_mode", "HIGH")], "HIGH", 1.1),
    ("R18", "Debug AND auth weak AND no headers → CRITICAL",
     [("debug_mode", "HIGH"), ("authentication_config", "HIGH"), ("security_headers", "HIGH")], "CRITICAL", 1.4),
    ("R19", "Debug mode active in production → CRITICAL",
     [("debug_mode", "VERY_HIGH")], "CRITICAL", 1.2),

    # ── Cloud Config ──────────────────────────────────────────────────────
    ("R20", "Misconfigured cloud config → HIGH risk",
     [("cloud_config", "HIGH")], "HIGH", 0.95),
    ("R21", "Cloud credentials exposed → CRITICAL",
     [("cloud_config", "VERY_HIGH")], "CRITICAL", 1.35),
    ("R22", "Medium debug AND medium cloud → MEDIUM risk",
     [("debug_mode", "MEDIUM"), ("cloud_config", "MEDIUM")], "MEDIUM", 0.7),

    # ── SSL / TLS ─────────────────────────────────────────────────────────
    ("R23", "Weak SSL/TLS config → HIGH risk",
     [("ssl_tls_config", "HIGH")], "HIGH", 1.05),
    ("R24", "No HTTPS → CRITICAL",
     [("ssl_tls_config", "VERY_HIGH")], "CRITICAL", 1.3),
    ("R25", "Weak SSL AND weak auth → CRITICAL",
     [("ssl_tls_config", "HIGH"), ("authentication_config", "HIGH")], "CRITICAL", 1.2),

    # ── Input Validation ──────────────────────────────────────────────────
    ("R26", "Poor input validation → HIGH risk",
     [("input_validation", "HIGH")], "HIGH", 1.0),
    ("R27", "No input validation → CRITICAL (injection risk)",
     [("input_validation", "VERY_HIGH")], "CRITICAL", 1.25),
    ("R28", "Input validation weak AND auth weak → CRITICAL",
     [("input_validation", "HIGH"), ("authentication_config", "HIGH")], "CRITICAL", 1.2),

    # ── Third-party Risk ──────────────────────────────────────────────────
    ("R29", "High third-party dependency risk → MEDIUM",
     [("third_party_risk", "MEDIUM")], "MEDIUM", 0.7),
    ("R30", "Very high third-party risk → HIGH",
     [("third_party_risk", "HIGH")], "HIGH", 0.85),

    # ── SEO ───────────────────────────────────────────────────────────────
    ("R31", "Poor SEO configuration → MEDIUM risk",
     [("seo_score", "HIGH")], "MEDIUM", 0.6),
    ("R32", "Very poor SEO → HIGH risk",
     [("seo_score", "VERY_HIGH")], "HIGH", 0.7),

    # ── Readability ───────────────────────────────────────────────────────
    ("R33", "Poor readability → MEDIUM risk",
     [("readability_score", "HIGH")], "MEDIUM", 0.55),

    # ── Performance ───────────────────────────────────────────────────────
    ("R34", "High performance risk → HIGH",
     [("performance_risk", "HIGH")], "HIGH", 0.8),
    ("R35", "Critical performance risk → HIGH",
     [("performance_risk", "VERY_HIGH")], "HIGH", 0.9),

    # ── Design Consistency ────────────────────────────────────────────────
    ("R36", "Inconsistent design → MEDIUM risk",
     [("design_consistency", "HIGH")], "MEDIUM", 0.5),

    # ── Compound LOW rules ────────────────────────────────────────────────
    ("R37", "All core factors LOW → LOW risk",
     [("security_headers", "LOW"), ("authentication_config", "LOW"),
      ("access_control", "LOW"), ("debug_mode", "LOW")], "LOW", 1.0),
    ("R38", "All core factors VERY_LOW → LOW risk",
     [("security_headers", "VERY_LOW"), ("authentication_config", "VERY_LOW"),
      ("debug_mode", "VERY_LOW")], "LOW", 1.0),

    # ── Compound MEDIUM rules ─────────────────────────────────────────────
    ("R39", "Medium headers AND medium auth → MEDIUM risk",
     [("security_headers", "MEDIUM"), ("authentication_config", "MEDIUM")], "MEDIUM", 0.85),
    ("R40", "All factors medium → MEDIUM risk",
     [("security_headers", "MEDIUM"), ("authentication_config", "MEDIUM"),
      ("access_control", "MEDIUM"), ("error_handling", "MEDIUM")], "MEDIUM", 0.9),
]

# Crisp output centers for each consequent level
RISK_CRISP = {
    "LOW":      0.12,
    "MEDIUM":   0.45,
    "HIGH":     0.75,
    "CRITICAL": 0.95,
}

# All recognised input dimensions
ALL_DIMENSIONS = [
    "security_headers", "authentication_config", "access_control",
    "directory_permissions", "error_handling", "debug_mode", "cloud_config",
    "ssl_tls_config", "input_validation", "third_party_risk",
    "seo_score", "readability_score", "design_consistency", "performance_risk",
]

# Category groupings for the category_scores output
CATEGORY_GROUPS = {
    "security":     ["security_headers", "authentication_config", "access_control",
                     "directory_permissions", "ssl_tls_config", "input_validation"],
    "configuration": ["error_handling", "debug_mode", "cloud_config", "third_party_risk"],
    "seo":          ["seo_score"],
    "readability":  ["readability_score"],
    "performance":  ["performance_risk"],
    "design":       ["design_consistency"],
}


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------

def evaluate_rule(rule: tuple, memberships: dict) -> float:
    """Firing strength = min of all antecedent memberships (Mamdani AND)."""
    _, _, antecedents, _, _ = rule
    strengths = [memberships.get(f, {}).get(lvl, 0.0) for f, lvl in antecedents]
    return min(strengths) if strengths else 0.0


def defuzzify_centroid(activated: list) -> float:
    """Weighted centroid defuzzification."""
    num = sum(c * s * w for c, s, w in activated)
    den = sum(s * w for _, s, w in activated)
    return num / den if den > 0 else 0.0


def score_to_level(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.62:
        return "HIGH"
    if score >= 0.32:
        return "MEDIUM"
    return "LOW"


def _category_score(inputs: dict, dims: list) -> float:
    """
    Average risk score for a group of dimensions → convert to 0-100 quality score
    (100 = perfect, 0 = worst).
    """
    vals = [inputs.get(d, 0.5) for d in dims if d in inputs]
    if not vals:
        return 50.0
    avg_risk = sum(vals) / len(vals)
    return round((1.0 - avg_risk) * 100, 1)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_fuzzy_assessment(inputs: dict) -> dict:
    """
    Full fuzzy inference pipeline.

    Parameters
    ----------
    inputs : dict
        Any subset of ALL_DIMENSIONS. Missing keys default to 0.5.
        Values: float 0-1 (higher = more problematic).

    Returns
    -------
    dict:
        risk_score          float 0-1
        risk_level          LOW | MEDIUM | HIGH | CRITICAL
        confidence          float 0-1
        overall_score       int 0-100  (inverted, higher = safer)
        category_scores     dict  {security, configuration, seo, ...} → 0-100
        triggered_rules     list of rule detail dicts
        fuzzy_inputs        dict of sanitised inputs
        fuzzy_memberships   dict of per-input membership degrees
        aggregate_output    summary counts
        explainability      human-readable summary string
    """
    sanitised = {k: float(inputs.get(k, 0.5)) for k in ALL_DIMENSIONS}

    # Fuzzify all inputs (5-level)
    memberships = {k: fuzzify(v) for k, v in sanitised.items()}

    # Evaluate rules
    triggered = []
    activated = []

    for rule in RULES:
        rid, desc, antecedents, consequent, weight = rule
        strength = evaluate_rule(rule, memberships)
        if strength > 0.005:
            crisp = RISK_CRISP[consequent]
            activated.append((crisp, strength, weight))
            triggered.append({
                "rule_id": rid,
                "description": desc,
                "consequent": consequent,
                "firing_strength": round(strength, 4),
                "weight": weight,
                "antecedents": [
                    {
                        "factor": f,
                        "required_level": lvl,
                        "membership": round(memberships.get(f, {}).get(lvl, 0.0), 4),
                    }
                    for f, lvl in antecedents
                ],
            })

    # Defuzzify
    risk_score = round(min(max(defuzzify_centroid(activated), 0.0), 1.0), 4) if activated else 0.1
    risk_level = score_to_level(risk_score)

    # Confidence: weighted average firing strength of triggered rules
    if triggered:
        total_w = sum(r["firing_strength"] * r["weight"] for r in triggered)
        max_w = sum(r["weight"] for r in triggered)
        confidence = round(total_w / max_w, 4) if max_w else 0.0
    else:
        confidence = 0.0

    # Category scores (0-100, higher = safer/better)
    category_scores = {cat: _category_score(sanitised, dims) for cat, dims in CATEGORY_GROUPS.items()}
    overall_score = round((1.0 - risk_score) * 100, 1)

    # Aggregate output
    aggregate_output = {
        "total_rules_evaluated": len(RULES),
        "rules_triggered": len(triggered),
        "activated_consequents": {
            level: round(sum(s * w for c, s, w in activated if abs(c - RISK_CRISP[level]) < 0.05), 4)
            for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        },
        "dominant_risk_factors": _dominant_factors(sanitised),
    }

    # Human-readable explainability
    top_rules = sorted(triggered, key=lambda r: r["firing_strength"] * r["weight"], reverse=True)[:3]
    top_rule_descs = "; ".join(r["description"] for r in top_rules)
    explainability = (
        f"Risk assessed as {risk_level} (score {risk_score:.2f}/1.00, overall site score {overall_score}/100). "
        f"{len(triggered)} of {len(RULES)} rules fired. "
        f"Top drivers: {top_rule_descs or 'none'}. "
        f"Confidence: {confidence*100:.1f}%."
    )

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "overall_score": overall_score,
        "category_scores": category_scores,
        "triggered_rules": triggered,
        "fuzzy_inputs": sanitised,
        "fuzzy_memberships": {
            k: {lvl: round(v, 4) for lvl, v in m.items()}
            for k, m in memberships.items()
        },
        "aggregate_output": aggregate_output,
        "explainability": explainability,
    }


def run_whatif_simulation(base_inputs: dict, overrides: dict) -> dict:
    """
    Simulate the effect of changing specific factor values.
    Returns original + simulated assessments and a delta summary.
    """
    original = run_fuzzy_assessment(base_inputs)
    simulated_inputs = {**base_inputs, **overrides}
    simulated = run_fuzzy_assessment(simulated_inputs)

    delta_score = round(simulated["risk_score"] - original["risk_score"], 4)
    delta_overall = round(simulated["overall_score"] - original["overall_score"], 1)

    category_deltas = {
        cat: round(simulated["category_scores"].get(cat, 0) - original["category_scores"].get(cat, 0), 1)
        for cat in original["category_scores"]
    }

    return {
        "original": original,
        "simulated": simulated,
        "overrides_applied": overrides,
        "risk_score_delta": delta_score,
        "overall_score_delta": delta_overall,
        "category_score_deltas": category_deltas,
        "improvement": delta_score < 0,
        "summary": (
            f"Applying overrides {'improves' if delta_score < 0 else 'worsens'} risk score by "
            f"{abs(delta_score):.4f} "
            f"({'↑' if delta_overall > 0 else '↓'}{abs(delta_overall)} overall score points)."
        ),
    }


def _dominant_factors(inputs: dict) -> list:
    """Return top 3 riskiest factors sorted by score descending."""
    sorted_factors = sorted(inputs.items(), key=lambda x: x[1], reverse=True)
    return [
        {"factor": k, "risk_value": round(v, 4), "level": score_to_level(v)}
        for k, v in sorted_factors[:3]
    ]
