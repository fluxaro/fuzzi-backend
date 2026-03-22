"""
Fuzzi Backend — Full Integration Test Suite
Tests every endpoint + engine against https://www.applybureau.com/
Run: python3 test_backend.py
"""
import os, sys, json, time, threading
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "fuzzi_backend.settings")
sys.path.insert(0, os.path.dirname(__file__))

import django
django.setup()

import requests as http_requests
from datetime import datetime

BASE = "http://127.0.0.1:8000/api"
TARGET_URL = "https://www.applybureau.com/"
TEST_EMAIL = f"tester_{int(time.time())}@fuzzi.dev"
TEST_PASSWORD = "FuzziTest@2024!"
RESULTS = []

# ── helpers ────────────────────────────────────────────────────────────────

def ok(label, data=None):
    RESULTS.append(("PASS", label))
    print(f"  ✅  {label}")
    if data and isinstance(data, dict):
        for k, v in list(data.items())[:4]:
            print(f"       {k}: {v}")

def fail(label, reason=""):
    RESULTS.append(("FAIL", label, reason))
    print(f"  ❌  {label}: {reason}")

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

# ── Phase 1: Engine tests (no server needed) ───────────────────────────────

def test_fuzzy_engine():
    section("PHASE 1 — Fuzzy Logic Engine")
    from scanner.fuzzy_engine import (
        run_fuzzy_assessment, run_whatif_simulation,
        fuzzify, trimf, trapmf, RULES, ALL_DIMENSIONS,
    )

    # 1a. Membership functions
    assert abs(trimf(0.5, 0.3, 0.5, 0.7) - 1.0) < 0.001
    assert trapmf(0.0, 0.0, 0.0, 0.25, 0.45) == 1.0
    assert trimf(0.0, 0.3, 0.5, 0.7) == 0.0
    ok("Membership functions (trimf, trapmf)")

    # 1b. Fuzzify
    m = fuzzify(0.5)
    assert set(m.keys()) == {"VERY_LOW", "LOW", "MEDIUM", "HIGH", "VERY_HIGH"}
    assert abs(m["MEDIUM"] - 1.0) < 0.001
    ok("Fuzzify 5-level output", m)

    # 1c. LOW risk scenario
    low_inputs = {d: 0.05 for d in ALL_DIMENSIONS}
    r = run_fuzzy_assessment(low_inputs)
    assert r["risk_level"] in ("LOW", "MEDIUM"), f"Expected LOW/MEDIUM, got {r['risk_level']}"
    assert r["overall_score"] > 70
    ok("LOW risk scenario", {"risk_level": r["risk_level"], "overall_score": r["overall_score"], "rules_triggered": len(r["triggered_rules"])})

    # 1d. CRITICAL risk scenario
    crit_inputs = {d: 0.95 for d in ALL_DIMENSIONS}
    r = run_fuzzy_assessment(crit_inputs)
    assert r["risk_level"] == "CRITICAL", f"Expected CRITICAL, got {r['risk_level']}"
    assert r["overall_score"] < 20
    ok("CRITICAL risk scenario", {"risk_level": r["risk_level"], "risk_score": r["risk_score"], "rules_triggered": len(r["triggered_rules"])})

    # 1e. Category scores present
    assert "security" in r["category_scores"]
    assert "seo" in r["category_scores"]
    assert "performance" in r["category_scores"]
    ok("Category scores present", r["category_scores"])

    # 1f. Explainability
    assert len(r["explainability"]) > 20
    ok("Explainability string", {"text": r["explainability"][:100]})

    # 1g. All 14 dimensions processed
    assert len(r["fuzzy_inputs"]) == len(ALL_DIMENSIONS)
    ok(f"All {len(ALL_DIMENSIONS)} dimensions processed")

    # 1h. Rule count
    assert len(RULES) == 40
    ok(f"Rule base has {len(RULES)} rules")

    # 1i. What-if simulation
    base = {d: 0.7 for d in ALL_DIMENSIONS}
    w = run_whatif_simulation(base, {"debug_mode": 0.0, "security_headers": 0.05})
    assert w["improvement"] is True
    assert w["risk_score_delta"] < 0
    ok("What-if simulation", {
        "delta": w["risk_score_delta"],
        "overall_delta": w["overall_score_delta"],
        "summary": w["summary"][:80],
    })

    # 1j. Mixed scenario (realistic)
    mixed = {
        "security_headers": 0.75, "authentication_config": 0.60,
        "directory_permissions": 0.40, "error_handling": 0.50,
        "debug_mode": 0.30, "access_control": 0.55,
        "cloud_config": 0.20, "ssl_tls_config": 0.65,
        "input_validation": 0.45, "third_party_risk": 0.35,
        "seo_score": 0.50, "readability_score": 0.30,
        "design_consistency": 0.25, "performance_risk": 0.55,
    }
    r = run_fuzzy_assessment(mixed)
    assert r["risk_level"] in ("MEDIUM", "HIGH")
    ok("Mixed realistic scenario", {
        "risk_level": r["risk_level"],
        "risk_score": r["risk_score"],
        "overall_score": r["overall_score"],
        "confidence": f"{r['confidence']*100:.1f}%",
    })


def test_web_scanner():
    section("PHASE 2 — Web Scanner against applybureau.com")
    from scanner.web_scanner import (
        scan_target, extract_html_features,
        probe_security_headers, probe_seo, probe_readability,
        probe_design_consistency, probe_performance_risk,
    )
    import requests as req

    # 2a. HTML feature extraction
    html = """<html><head>
        <title>Apply Bureau - Job Applications</title>
        <meta name="description" content="Apply for jobs easily">
        <meta name="viewport" content="width=device-width">
    </head><body>
        <h1>Welcome to Apply Bureau</h1>
        <h2>Find Jobs</h2>
        <p>We help you apply for jobs quickly and efficiently with our platform.</p>
        <img src="logo.png" alt="Logo">
        <img src="banner.jpg">
        <form action="/apply"><input type="text" name="name"><input type="submit"></form>
        <a href="/jobs">Browse Jobs</a>
    </body></html>"""
    features = extract_html_features(html)
    assert features["title"] == "Apply Bureau - Job Applications"
    assert len(features["h1_tags"]) == 1
    assert features["img_total"] == 2
    assert features["img_alts_missing"] == 1
    assert features["forms"] == 1
    ok("HTML feature extraction", {
        "title": features["title"],
        "h1": features["h1_tags"],
        "words": features["word_count"],
        "forms": features["forms"],
    })

    # 2b. Full scan of applybureau.com
    print(f"\n  🔍 Scanning {TARGET_URL} (this may take 15-30s)...")
    t0 = time.time()
    result = scan_target(TARGET_URL)
    elapsed = round(time.time() - t0, 1)

    assert result["url"] == TARGET_URL
    assert "factors" in result
    assert len(result["factors"]) == 14
    ok(f"Full scan completed in {elapsed}s", {
        "reachable": result["reachable"],
        "status_code": result["status_code"],
        "ssl_valid": result["ssl_valid"],
        "errors": result["errors"] or "none",
    })

    # 2c. All 14 factor scores present and valid
    factors = result["factors"]
    for name, score in factors.items():
        assert 0.0 <= score <= 1.0, f"{name} score {score} out of range"
    ok("All 14 factor scores valid (0-1 range)", {k: round(v, 3) for k, v in factors.items()})

    # 2d. Raw details populated
    details = result["raw_details"]
    assert "security_headers" in details
    assert "seo_score" in details
    sh = details["security_headers"]
    ok("Security headers detail", {
        "present": sh.get("total_present"),
        "missing": sh.get("missing", [])[:3],
    })

    seo = details["seo_score"]
    ok("SEO detail", {
        "title": seo.get("title", "")[:50],
        "h1_count": seo.get("h1_count"),
        "issues": seo.get("issues", [])[:2],
    })

    # 2e. Run fuzzy assessment on scan results
    from scanner.fuzzy_engine import run_fuzzy_assessment
    fuzzy = run_fuzzy_assessment(factors)
    ok("Fuzzy assessment on scan results", {
        "risk_level": fuzzy["risk_level"],
        "risk_score": fuzzy["risk_score"],
        "overall_score": fuzzy["overall_score"],
        "rules_triggered": len(fuzzy["triggered_rules"]),
        "explainability": fuzzy["explainability"][:100],
    })

    # 2f. Category scores
    ok("Category scores from real scan", fuzzy["category_scores"])

    # 2g. Triggered rules detail
    if fuzzy["triggered_rules"]:
        top = fuzzy["triggered_rules"][0]
        ok("Top triggered rule", {
            "id": top["rule_id"],
            "desc": top["description"],
            "strength": top["firing_strength"],
            "consequent": top["consequent"],
        })

    return factors, fuzzy


def test_report_generator(factors, fuzzy):
    section("PHASE 3 — Report Generator (PDF + CSV)")
    from scanner.report_generator import build_pdf_report
    from api.serializers import build_csv_report
    from api.models import Scan, FuzzyResult, Factor, Recommendation

    scan_data = {
        "id": "00000000-0000-0000-0000-000000000001",
        "target_url": TARGET_URL,
        "status": "completed",
    }
    recs = [
        {"title": "Add CSP Header", "description": "Missing Content-Security-Policy", "severity": "high", "remediation": "Add CSP header to all responses."},
        {"title": "Enable HSTS", "description": "Missing HSTS header", "severity": "medium", "remediation": "Add Strict-Transport-Security header."},
        {"title": "Fix CORS", "description": "Overly permissive CORS", "severity": "critical", "remediation": "Restrict CORS origins."},
    ]

    # 3a. PDF generation
    pdf_bytes = build_pdf_report(scan_data, fuzzy, recs)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes[:4] == b'%PDF'
    ok(f"PDF report generated ({len(pdf_bytes)//1024}KB)", {"starts_with": "%PDF", "size_bytes": len(pdf_bytes)})

    # 3b. CSV generation — use mock objects
    class MockScan:
        id = "00000000-0000-0000-0000-000000000001"
        target_url = TARGET_URL
        status = "completed"

    class MockFR:
        risk_score = fuzzy["risk_score"]
        risk_level = fuzzy["risk_level"]
        overall_score = fuzzy["overall_score"]
        confidence = fuzzy["confidence"]
        category_scores = fuzzy["category_scores"]

    class MockFactor:
        def __init__(self, name, val):
            self.name = name
            self.raw_value = val
            self.score_100 = round((1 - val) * 100, 1)
            self.linguistic_value = "HIGH" if val > 0.6 else "MEDIUM"

    class MockRec:
        def __init__(self, t, s, c, r):
            self.title = t; self.severity = s; self.category = c; self.remediation = r

    mock_factors = [MockFactor(k, v) for k, v in factors.items()]
    mock_recs = [MockRec(r["title"], r["severity"], "Security", r["remediation"]) for r in recs]

    csv_bytes = build_csv_report(MockScan(), MockFR(), mock_factors, mock_recs)
    assert len(csv_bytes) > 100
    assert b"FUZZI SECURITY REPORT" in csv_bytes
    assert b"RECOMMENDATIONS" in csv_bytes
    ok(f"CSV report generated ({len(csv_bytes)} bytes)", {"preview": csv_bytes[:80].decode()})


def test_api_endpoints(token, scan_id):
    section("PHASE 4 — API Endpoint Tests (live server)")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    tests = [
        # (method, path, payload, expected_status, label, check_key)
        ("GET",  "/me",                    None,                          200, "GET /me",                    "email"),
        ("PUT",  "/profile",               {"full_name": "Fuzzi Tester"}, 200, "PUT /profile",               "full_name"),
        ("GET",  "/preferences",           None,                          200, "GET /preferences",           "theme"),
        ("POST", "/preferences",           {"theme": "dark", "email_alerts": True}, 200, "POST /preferences", "theme"),
        ("GET",  "/scans",                 None,                          200, "GET /scans",                 "total"),
        ("GET",  f"/scan/{scan_id}",       None,                          200, "GET /scan/:id",              "status"),
        ("GET",  "/dashboard/summary",     None,                          200, "GET /dashboard/summary",     "total_scans"),
        ("GET",  "/dashboard/history",     None,                          200, "GET /dashboard/history",     "history"),
        ("GET",  "/analytics",             None,                          200, "GET /analytics",             "total_scans_in_period"),
        ("GET",  f"/dashboard/recommendations/{scan_id}", None,           200, "GET /dashboard/recommendations/:id", "recommendations"),
    ]

    for method, path, payload, expected, label, check_key in tests:
        try:
            if method == "GET":
                r = http_requests.get(f"{BASE}{path}", headers=headers, timeout=15)
            elif method == "POST":
                r = http_requests.post(f"{BASE}{path}", json=payload, headers=headers, timeout=15)
            elif method == "PUT":
                r = http_requests.put(f"{BASE}{path}", json=payload, headers=headers, timeout=15)
            elif method == "PATCH":
                r = http_requests.patch(f"{BASE}{path}", json=payload, headers=headers, timeout=15)

            if r.status_code == expected:
                data = r.json()
                val = data.get(check_key, "present" if check_key in data else "N/A")
                ok(label, {check_key: str(val)[:60]})
            else:
                fail(label, f"Expected {expected}, got {r.status_code}: {r.text[:120]}")
        except Exception as e:
            fail(label, str(e)[:100])


def test_scan_endpoints(token, scan_id, factors, fuzzy):
    section("PHASE 5 — Scan-specific Endpoints")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # 5a. PATCH scan (bookmark)
    try:
        r = http_requests.patch(f"{BASE}/scan/{scan_id}", json={"is_bookmarked": True}, headers=headers, timeout=10)
        if r.status_code == 200:
            ok("PATCH /scan/:id (bookmark)", {"is_bookmarked": r.json().get("is_bookmarked")})
        else:
            fail("PATCH /scan/:id (bookmark)", f"{r.status_code}: {r.text[:100]}")
    except Exception as e:
        fail("PATCH /scan/:id (bookmark)", str(e))

    # 5b. GET /scans?bookmarked=true
    try:
        r = http_requests.get(f"{BASE}/scans?bookmarked=true", headers=headers, timeout=10)
        ok("GET /scans?bookmarked=true", {"total": r.json().get("total")})
    except Exception as e:
        fail("GET /scans?bookmarked=true", str(e))

    # 5c. What-if simulation
    try:
        payload = {"scan_id": scan_id, "overrides": {"debug_mode": 0.0, "security_headers": 0.05}}
        r = http_requests.post(f"{BASE}/whatif", json=payload, headers=headers, timeout=10)
        if r.status_code == 200:
            d = r.json()
            ok("POST /whatif", {
                "delta": d.get("risk_score_delta"),
                "improvement": d.get("improvement"),
                "summary": str(d.get("summary", ""))[:60],
            })
        else:
            fail("POST /whatif", f"{r.status_code}: {r.text[:100]}")
    except Exception as e:
        fail("POST /whatif", str(e))

    # 5d. Generate PDF report
    try:
        r = http_requests.post(f"{BASE}/reports/{scan_id}", json={"format": "pdf"}, headers=headers, timeout=30)
        if r.status_code == 201:
            d = r.json()
            ok("POST /reports/:id (PDF)", {
                "file_size": d.get("file_size"),
                "uploaded": d.get("uploaded_to_storage"),
                "signed_url": "present" if d.get("signed_url") else "absent",
            })
        else:
            fail("POST /reports/:id (PDF)", f"{r.status_code}: {r.text[:120]}")
    except Exception as e:
        fail("POST /reports/:id (PDF)", str(e))

    # 5e. Generate CSV report
    try:
        r = http_requests.post(f"{BASE}/reports/{scan_id}", json={"format": "csv"}, headers=headers, timeout=30)
        if r.status_code == 201:
            ok("POST /reports/:id (CSV)", {"file_size": r.json().get("file_size")})
        else:
            fail("POST /reports/:id (CSV)", f"{r.status_code}: {r.text[:120]}")
    except Exception as e:
        fail("POST /reports/:id (CSV)", str(e))

    # 5f. Download report
    try:
        r = http_requests.get(f"{BASE}/report/{scan_id}/download?format=pdf", headers=headers, timeout=10)
        if r.status_code == 200:
            ok("GET /report/:id/download", {"download_count": r.json().get("download_count")})
        else:
            fail("GET /report/:id/download", f"{r.status_code}: {r.text[:100]}")
    except Exception as e:
        fail("GET /report/:id/download", str(e))

    # 5g. Compare scan with itself (edge case)
    try:
        r = http_requests.post(f"{BASE}/compare", json={"scan_a_id": scan_id, "scan_b_id": scan_id}, headers=headers, timeout=10)
        if r.status_code in (200, 201):
            d = r.json()
            ok("POST /compare", {"winner": d.get("comparison_data", {}).get("winner", "N/A")})
        else:
            fail("POST /compare", f"{r.status_code}: {r.text[:100]}")
    except Exception as e:
        fail("POST /compare", str(e))

    # 5h. GET comparisons list
    try:
        r = http_requests.get(f"{BASE}/compare", headers=headers, timeout=10)
        ok("GET /compare", {"count": len(r.json()) if isinstance(r.json(), list) else "N/A"})
    except Exception as e:
        fail("GET /compare", str(e))


def test_auth_endpoints():
    section("PHASE 6 — Auth Endpoints (live server)")
    token = None
    user_id = None

    # 6a. Signup
    try:
        r = http_requests.post(f"{BASE}/signup", json={
            "email": TEST_EMAIL, "password": TEST_PASSWORD, "full_name": "Fuzzi Tester"
        }, timeout=15)
        if r.status_code == 201:
            ok("POST /signup", {"user_id": r.json().get("user_id"), "email": r.json().get("email")})
        else:
            fail("POST /signup", f"{r.status_code}: {r.text[:120]}")
    except Exception as e:
        fail("POST /signup", str(e))

    # 6b. Login
    try:
        r = http_requests.post(f"{BASE}/login", json={
            "email": TEST_EMAIL, "password": TEST_PASSWORD
        }, timeout=15)
        if r.status_code == 200:
            d = r.json()
            token = d.get("access_token")
            ok("POST /login", {
                "token_type": d.get("token_type"),
                "expires_in": d.get("expires_in"),
                "user_email": d.get("user", {}).get("email"),
            })
        else:
            fail("POST /login", f"{r.status_code}: {r.text[:120]}")
    except Exception as e:
        fail("POST /login", str(e))

    # 6c. Bad login
    try:
        r = http_requests.post(f"{BASE}/login", json={"email": TEST_EMAIL, "password": "wrongpass"}, timeout=10)
        assert r.status_code == 401
        ok("POST /login (wrong password → 401)")
    except Exception as e:
        fail("POST /login (wrong password)", str(e))

    # 6d. Unauthenticated access
    try:
        r = http_requests.get(f"{BASE}/scans", timeout=10)
        assert r.status_code == 401
        ok("GET /scans without token → 401")
    except Exception as e:
        fail("GET /scans without token", str(e))

    # 6e. Password change
    if token:
        try:
            r = http_requests.post(f"{BASE}/password/change",
                json={"new_password": "FuzziNew@2024!"},
                headers={"Authorization": f"Bearer {token}"},
                timeout=10)
            if r.status_code == 200:
                ok("POST /password/change")
            else:
                fail("POST /password/change", f"{r.status_code}: {r.text[:100]}")
        except Exception as e:
            fail("POST /password/change", str(e))

    return token


def test_scan_flow(token):
    section("PHASE 7 — Full Scan Flow against applybureau.com")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    scan_id = None

    # 7a. Submit scan
    try:
        r = http_requests.post(f"{BASE}/scan", json={
            "url": TARGET_URL,
            "title": "ApplyBureau Security Audit",
        }, headers=headers, timeout=15)
        if r.status_code == 202:
            scan_id = r.json().get("scan_id")
            ok("POST /scan (submitted)", {"scan_id": scan_id, "status": r.json().get("status")})
        else:
            fail("POST /scan", f"{r.status_code}: {r.text[:120]}")
            return None
    except Exception as e:
        fail("POST /scan", str(e))
        return None

    # 7b. Poll until completed (max 90s)
    print(f"\n  ⏳ Waiting for scan to complete (max 90s)...")
    completed = False
    for i in range(18):
        time.sleep(5)
        try:
            r = http_requests.get(f"{BASE}/scan/{scan_id}", headers=headers, timeout=10)
            status = r.json().get("status")
            print(f"     [{(i+1)*5}s] status: {status}")
            if status == "completed":
                completed = True
                break
            elif status == "failed":
                fail("Scan completed", f"Scan failed: {r.json().get('error_message', '')[:100]}")
                return scan_id
        except Exception as e:
            print(f"     Poll error: {e}")

    if not completed:
        fail("Scan completed within 90s", "Timed out")
        return scan_id

    # 7c. Verify full scan result
    try:
        r = http_requests.get(f"{BASE}/scan/{scan_id}", headers=headers, timeout=10)
        d = r.json()
        assert d["status"] == "completed"
        fr = d.get("fuzzy_result", {})
        factors = d.get("factors", [])
        recs = d.get("recommendations", [])

        ok("GET /scan/:id (completed)", {
            "risk_level": fr.get("risk_level"),
            "risk_score": fr.get("risk_score"),
            "overall_score": fr.get("overall_score"),
            "confidence": fr.get("confidence"),
        })
        ok(f"Factors ({len(factors)} returned)", {
            f["name"]: f"{f['score_100']}/100" for f in factors[:4]
        })
        ok(f"Recommendations ({len(recs)} generated)", {
            r["severity"].upper(): r["title"] for r in recs[:3]
        })
        ok("Category scores", fr.get("category_scores", {}))
        ok("Explainability", {"text": fr.get("explainability", "")[:120]})

        if fr.get("triggered_rules"):
            top = fr["triggered_rules"][0]
            ok("Top triggered rule", {
                "id": top["rule_id"],
                "desc": top["description"][:60],
                "strength": top["firing_strength"],
            })
    except Exception as e:
        fail("Verify scan result", str(e))

    return scan_id


def print_summary():
    section("TEST SUMMARY")
    passed = [r for r in RESULTS if r[0] == "PASS"]
    failed = [r for r in RESULTS if r[0] == "FAIL"]
    print(f"\n  Total : {len(RESULTS)}")
    print(f"  Passed: {len(passed)} ✅")
    print(f"  Failed: {len(failed)} ❌")
    if failed:
        print("\n  Failed tests:")
        for f in failed:
            print(f"    ✗ {f[1]}: {f[2] if len(f) > 2 else ''}")
    print()
    return len(failed) == 0


# ── Main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  FUZZI BACKEND — FULL TEST SUITE")
    print(f"  Target: {TARGET_URL}")
    print(f"  Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    # Phase 1 & 2 — no server needed
    test_fuzzy_engine()
    factors, fuzzy = test_web_scanner()
    test_report_generator(factors, fuzzy)

    # Check if server is running
    section("PHASE 4-7 — Live Server Tests")
    try:
        ping = http_requests.get(f"{BASE}/login", timeout=3)
        server_up = True
        print("  ✅ Server is running at", BASE)
    except Exception:
        server_up = False
        print("  ⚠️  Server not running — skipping live API tests")
        print("  ➡️  Start server with: python3 manage.py runserver 0.0.0.0:8000")

    if server_up:
        token = test_auth_endpoints()
        if token:
            scan_id = test_scan_flow(token)
            if scan_id:
                test_api_endpoints(token, scan_id)
                test_scan_endpoints(token, scan_id, factors, fuzzy)

            # Logout
            try:
                r = http_requests.post(f"{BASE}/logout",
                    headers={"Authorization": f"Bearer {token}"}, timeout=10)
                ok("POST /logout", {"status": r.status_code})
            except Exception as e:
                fail("POST /logout", str(e))

    all_passed = print_summary()
    sys.exit(0 if all_passed else 1)
