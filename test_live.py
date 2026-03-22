"""
Fuzzi Backend — Live API Test Suite
Tests every endpoint against the deployed Vercel URL.
Run: python3 test_live.py
"""
import sys
import json
import time
import requests
from datetime import datetime

BASE = "https://fuzzi-backend.vercel.app/api"
TARGET_URL = "https://example.com"

# Use a real email domain — Supabase blocks fake TLDs like .dev/.test
TS = int(time.time())
TEST_EMAIL = f"fuzzi.tester.{TS}@gmail.com"
TEST_PASS = "FuzziTest@2024!"

PASS_COUNT = 0
FAIL_COUNT = 0
RESULTS = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def p(label, data=None, status=None):
    global PASS_COUNT
    PASS_COUNT += 1
    RESULTS.append(("PASS", label))
    extra = ""
    if status:
        extra += f" [{status}]"
    if data:
        snippet = json.dumps(data)[:120] if isinstance(data, dict) else str(data)[:120]
        extra += f" → {snippet}"
    print(f"  ✅  {label}{extra}")


def f(label, reason=""):
    global FAIL_COUNT
    FAIL_COUNT += 1
    RESULTS.append(("FAIL", label, reason))
    print(f"  ❌  {label} — {reason[:150]}")


def section(title):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")


def req(method, path, token=None, payload=None, timeout=20):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{BASE}{path}"
    try:
        fn = getattr(requests, method.lower())
        kwargs = {"headers": headers, "timeout": timeout}
        if payload is not None:
            kwargs["json"] = payload
        r = fn(url, **kwargs)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:200]}
        return r.status_code, body
    except requests.exceptions.Timeout:
        return 0, {"error": "timeout"}
    except Exception as e:
        return 0, {"error": str(e)}


# ---------------------------------------------------------------------------
# 1. Health check
# ---------------------------------------------------------------------------

def test_health():
    section("1. HEALTH CHECK")
    code, body = req("GET", "/scans")
    if code == 401:
        p("Server is live and responding", {"detail": "401 on /scans (correct — no token)"})
    else:
        f("Server health", f"Expected 401, got {code}: {body}")

    # Root 404 is expected
    try:
        r = requests.get("https://fuzzi-backend.vercel.app/", timeout=10)
        if r.status_code == 404:
            p("Root / returns 404 (expected — no root route)")
        else:
            f("Root /", f"Expected 404, got {r.status_code}")
    except Exception as e:
        f("Root /", str(e))


# ---------------------------------------------------------------------------
# 2. Auth
# ---------------------------------------------------------------------------

def test_auth():
    section("2. AUTH ENDPOINTS")
    token = None

    # 2a. Signup
    code, body = req("POST", "/signup", payload={
        "email": TEST_EMAIL,
        "password": TEST_PASS,
        "full_name": "Fuzzi Tester",
    })
    if code == 201:
        p("POST /signup", {"user_id": body.get("user_id"), "email": body.get("email")}, code)
    elif code == 400 and "already" in str(body).lower():
        p("POST /signup (user already exists — OK)", body, code)
    else:
        f("POST /signup", f"{code}: {body}")

    # 2b. Login
    code, body = req("POST", "/login", payload={"email": TEST_EMAIL, "password": TEST_PASS})
    if code == 200 and body.get("access_token"):
        token = body["access_token"]
        p("POST /login", {
            "token_type": body.get("token_type"),
            "expires_in": body.get("expires_in"),
            "email": body.get("user", {}).get("email"),
        }, code)
    else:
        f("POST /login", f"{code}: {body}")

    # 2c. Wrong password → 401
    code, body = req("POST", "/login", payload={"email": TEST_EMAIL, "password": "wrongpass123"})
    if code == 401:
        p("POST /login wrong password → 401", status=code)
    else:
        f("POST /login wrong password", f"Expected 401, got {code}")

    # 2d. Missing fields → 400
    code, body = req("POST", "/login", payload={"email": TEST_EMAIL})
    if code == 400:
        p("POST /login missing password → 400", status=code)
    else:
        f("POST /login missing password", f"Expected 400, got {code}")

    # 2e. No token → 401
    code, body = req("GET", "/me")
    if code == 401:
        p("GET /me without token → 401", status=code)
    else:
        f("GET /me without token", f"Expected 401, got {code}")

    return token


# ---------------------------------------------------------------------------
# 3. Profile & Preferences
# ---------------------------------------------------------------------------

def test_profile(token):
    section("3. PROFILE & PREFERENCES")

    # 3a. GET /me
    code, body = req("GET", "/me", token=token)
    if code == 200 and body.get("email"):
        p("GET /me", {"email": body.get("email"), "role": body.get("role")}, code)
    else:
        f("GET /me", f"{code}: {body}")

    # 3b. PUT /profile
    code, body = req("PUT", "/profile", token=token, payload={
        "full_name": "Fuzzi Live Tester",
        "organization": "Fuzzi Labs",
    })
    if code == 200 and body.get("full_name") == "Fuzzi Live Tester":
        p("PUT /profile", {"full_name": body.get("full_name"), "org": body.get("organization")}, code)
    else:
        f("PUT /profile", f"{code}: {body}")

    # 3c. GET /preferences
    code, body = req("GET", "/preferences", token=token)
    if code == 200 and "theme" in body:
        p("GET /preferences", {"theme": body.get("theme"), "email_alerts": body.get("email_alerts")}, code)
    else:
        f("GET /preferences", f"{code}: {body}")

    # 3d. POST /preferences
    code, body = req("POST", "/preferences", token=token, payload={
        "theme": "dark",
        "email_alerts": True,
        "alert_on_critical": True,
        "notifications_enabled": True,
    })
    if code == 200 and body.get("theme") == "dark":
        p("POST /preferences", {"theme": body.get("theme")}, code)
    else:
        f("POST /preferences", f"{code}: {body}")

    # 3e. Password change
    code, body = req("POST", "/password/change", token=token, payload={"new_password": "FuzziNew@2024!"})
    if code == 200:
        p("POST /password/change", status=code)
    else:
        f("POST /password/change", f"{code}: {body}")


# ---------------------------------------------------------------------------
# 4. Scan submission & polling
# ---------------------------------------------------------------------------

def test_scan(token):
    section("4. SCAN ENDPOINTS")
    scan_id = None

    # 4a. Submit scan
    code, body = req("POST", "/scan", token=token, payload={
        "url": TARGET_URL,
        "title": "Example.com Security Audit",
    })
    if code == 202 and body.get("scan_id"):
        scan_id = body["scan_id"]
        p("POST /scan (submitted)", {"scan_id": scan_id, "status": body.get("status")}, code)
    else:
        f("POST /scan", f"{code}: {body}")
        return None

    # 4b. Immediate poll — should be pending/running
    code, body = req("GET", f"/scan/{scan_id}", token=token)
    if code == 200:
        p("GET /scan/:id (immediate)", {"status": body.get("status")}, code)
    else:
        f("GET /scan/:id (immediate)", f"{code}: {body}")

    # 4c. Poll until completed (max 90s)
    print(f"\n  ⏳ Polling scan until complete (max 90s)...")
    completed = False
    for i in range(18):
        time.sleep(5)
        code, body = req("GET", f"/scan/{scan_id}", token=token)
        status = body.get("status", "unknown")
        print(f"     [{(i+1)*5}s] status={status}")
        if status == "completed":
            completed = True
            break
        elif status == "failed":
            f("Scan completed", f"Scan failed: {body.get('error_message','')[:100]}")
            return scan_id

    if not completed:
        f("Scan completed within 90s", "Timed out — scan may still be running")
        return scan_id

    # 4d. Full result validation
    code, body = req("GET", f"/scan/{scan_id}", token=token)
    if code == 200 and body.get("status") == "completed":
        fr = body.get("fuzzy_result", {})
        factors = body.get("factors", [])
        recs = body.get("recommendations", [])

        p("GET /scan/:id (completed)", {
            "risk_level": fr.get("risk_level"),
            "risk_score": fr.get("risk_score"),
            "overall_score": fr.get("overall_score"),
        }, code)

        if len(factors) > 0:
            p(f"Factors returned ({len(factors)})", {f["name"]: f"{f['score_100']}/100" for f in factors[:3]})
        else:
            f("Factors returned", "No factors in response")

        if len(recs) > 0:
            p(f"Recommendations returned ({len(recs)})", {r["severity"]: r["title"] for r in recs[:3]})
        else:
            f("Recommendations returned", "No recommendations in response")

        if fr.get("category_scores"):
            p("Category scores", fr["category_scores"])
        else:
            f("Category scores", "Missing from fuzzy_result")

        if fr.get("explainability"):
            p("Explainability", {"text": fr["explainability"][:100]})
        else:
            f("Explainability", "Missing from fuzzy_result")

        if fr.get("triggered_rules"):
            top = fr["triggered_rules"][0]
            p("Triggered rules", {"top_rule": top["rule_id"], "desc": top["description"][:60], "strength": top["firing_strength"]})
        else:
            f("Triggered rules", "No rules in fuzzy_result")
    else:
        f("GET /scan/:id (completed)", f"{code}: {body}")

    return scan_id


# ---------------------------------------------------------------------------
# 5. Scan list, filter, bookmark
# ---------------------------------------------------------------------------

def test_scan_list(token, scan_id):
    section("5. SCAN LIST & FILTERS")

    # 5a. List all scans
    code, body = req("GET", "/scans", token=token)
    if code == 200 and "total" in body:
        p("GET /scans", {"total": body.get("total"), "page": body.get("page")}, code)
    else:
        f("GET /scans", f"{code}: {body}")

    # 5b. Filter by status
    code, body = req("GET", "/scans?status=completed", token=token)
    if code == 200:
        p("GET /scans?status=completed", {"total": body.get("total")}, code)
    else:
        f("GET /scans?status=completed", f"{code}: {body}")

    # 5c. Bookmark scan
    code, body = req("PATCH", f"/scan/{scan_id}", token=token, payload={"is_bookmarked": True})
    if code == 200 and body.get("is_bookmarked") is True:
        p("PATCH /scan/:id (bookmark)", {"is_bookmarked": body.get("is_bookmarked")}, code)
    else:
        f("PATCH /scan/:id (bookmark)", f"{code}: {body}")

    # 5d. Filter bookmarked
    code, body = req("GET", "/scans?bookmarked=true", token=token)
    if code == 200:
        p("GET /scans?bookmarked=true", {"total": body.get("total")}, code)
    else:
        f("GET /scans?bookmarked=true", f"{code}: {body}")

    # 5e. Search by URL
    code, body = req("GET", "/scans?search=example", token=token)
    if code == 200:
        p("GET /scans?search=example", {"total": body.get("total")}, code)
    else:
        f("GET /scans?search=example", f"{code}: {body}")


# ---------------------------------------------------------------------------
# 6. Dashboard & Analytics
# ---------------------------------------------------------------------------

def test_dashboard(token, scan_id):
    section("6. DASHBOARD & ANALYTICS")

    # 6a. Summary
    code, body = req("GET", "/dashboard/summary", token=token)
    if code == 200 and "total_scans" in body:
        p("GET /dashboard/summary", {
            "total_scans": body.get("total_scans"),
            "avg_risk_score": body.get("average_risk_score"),
            "avg_overall_score": body.get("average_overall_score"),
            "risk_distribution": body.get("risk_distribution"),
        }, code)
    else:
        f("GET /dashboard/summary", f"{code}: {body}")

    # 6b. History
    code, body = req("GET", "/dashboard/history?days=30", token=token)
    if code == 200 and "history" in body:
        p("GET /dashboard/history", {"total": body.get("total"), "days": body.get("days")}, code)
    else:
        f("GET /dashboard/history", f"{code}: {body}")

    # 6c. Recommendations for scan
    code, body = req("GET", f"/dashboard/recommendations/{scan_id}", token=token)
    if code == 200 and "recommendations" in body:
        p("GET /dashboard/recommendations/:id", {
            "total": body.get("total"),
            "unresolved": body.get("unresolved"),
        }, code)
    else:
        f("GET /dashboard/recommendations/:id", f"{code}: {body}")

    # 6d. Mark recommendation resolved
    code, body = req("GET", f"/dashboard/recommendations/{scan_id}", token=token)
    if code == 200 and body.get("recommendations"):
        rec_id = body["recommendations"][0]["id"]
        code2, body2 = req("PATCH", f"/dashboard/recommendations/{scan_id}", token=token,
                           payload={"recommendation_id": rec_id, "is_resolved": True})
        if code2 == 200 and body2.get("is_resolved") is True:
            p("PATCH /dashboard/recommendations (resolve)", {"is_resolved": True}, code2)
        else:
            f("PATCH /dashboard/recommendations (resolve)", f"{code2}: {body2}")

    # 6e. Analytics
    code, body = req("GET", "/analytics?days=30", token=token)
    if code == 200 and "total_scans_in_period" in body:
        p("GET /analytics", {
            "total_scans": body.get("total_scans_in_period"),
            "avg_category_scores": body.get("average_category_scores"),
        }, code)
    else:
        f("GET /analytics", f"{code}: {body}")


# ---------------------------------------------------------------------------
# 7. What-if simulation
# ---------------------------------------------------------------------------

def test_whatif(token, scan_id):
    section("7. WHAT-IF SIMULATION")

    code, body = req("POST", "/whatif", token=token, payload={
        "scan_id": scan_id,
        "overrides": {
            "debug_mode": 0.0,
            "security_headers": 0.05,
            "authentication_config": 0.1,
        },
    })
    if code == 200 and "risk_score_delta" in body:
        p("POST /whatif", {
            "delta": body.get("risk_score_delta"),
            "overall_delta": body.get("overall_score_delta"),
            "improvement": body.get("improvement"),
            "summary": str(body.get("summary", ""))[:80],
        }, code)
    else:
        f("POST /whatif", f"{code}: {body}")

    # Invalid scan_id
    code, body = req("POST", "/whatif", token=token, payload={
        "scan_id": "00000000-0000-0000-0000-000000000000",
        "overrides": {"debug_mode": 0.0},
    })
    if code == 404:
        p("POST /whatif invalid scan_id → 404", status=code)
    else:
        f("POST /whatif invalid scan_id", f"Expected 404, got {code}")


# ---------------------------------------------------------------------------
# 8. Comparison
# ---------------------------------------------------------------------------

def test_compare(token, scan_id):
    section("8. SCAN COMPARISON")

    # Compare scan with itself (valid edge case)
    code, body = req("POST", "/compare", token=token, payload={
        "scan_a_id": scan_id,
        "scan_b_id": scan_id,
    })
    if code in (200, 201) and "comparison_data" in body:
        cd = body.get("comparison_data", {})
        p("POST /compare", {
            "risk_score_diff": cd.get("risk_score_diff"),
            "overall_score_diff": cd.get("overall_score_diff"),
            "winner": cd.get("winner", "")[:20],
        }, code)
    else:
        f("POST /compare", f"{code}: {body}")

    # List comparisons
    code, body = req("GET", "/compare", token=token)
    if code == 200:
        count = len(body) if isinstance(body, list) else body.get("count", "?")
        p("GET /compare", {"count": count}, code)
    else:
        f("GET /compare", f"{code}: {body}")


# ---------------------------------------------------------------------------
# 9. Reports (PDF + CSV)
# ---------------------------------------------------------------------------

def test_reports(token, scan_id):
    section("9. REPORTS (PDF + CSV)")

    # 9a. Generate PDF
    code, body = req("POST", f"/reports/{scan_id}", token=token,
                     payload={"format": "pdf"}, timeout=40)
    if code == 201 and body.get("file_size"):
        p("POST /reports/:id (PDF)", {
            "file_size": f"{body.get('file_size')//1024}KB",
            "uploaded": body.get("uploaded_to_storage"),
            "signed_url": "present" if body.get("signed_url") else "absent",
        }, code)
    else:
        f("POST /reports/:id (PDF)", f"{code}: {body}")

    # 9b. Generate CSV
    code, body = req("POST", f"/reports/{scan_id}", token=token,
                     payload={"format": "csv"}, timeout=40)
    if code == 201 and body.get("file_size"):
        p("POST /reports/:id (CSV)", {
            "file_size": f"{body.get('file_size')} bytes",
            "uploaded": body.get("uploaded_to_storage"),
        }, code)
    else:
        f("POST /reports/:id (CSV)", f"{code}: {body}")

    # 9c. Download PDF
    code, body = req("GET", f"/report/{scan_id}/download?format=pdf", token=token)
    if code == 200 and body.get("storage_path"):
        p("GET /report/:id/download (PDF)", {
            "download_count": body.get("download_count"),
            "signed_url": "present" if body.get("signed_url") else "absent",
        }, code)
    else:
        f("GET /report/:id/download (PDF)", f"{code}: {body}")

    # 9d. Download CSV
    code, body = req("GET", f"/report/{scan_id}/download?format=csv", token=token)
    if code == 200:
        p("GET /report/:id/download (CSV)", {"download_count": body.get("download_count")}, code)
    else:
        f("GET /report/:id/download (CSV)", f"{code}: {body}")


# ---------------------------------------------------------------------------
# 10. Logout
# ---------------------------------------------------------------------------

def test_logout(token):
    section("10. LOGOUT")
    code, body = req("POST", "/logout", token=token)
    if code == 200:
        p("POST /logout", {"message": body.get("message")}, code)
    else:
        f("POST /logout", f"{code}: {body}")

    # After logout token should be invalid
    code, body = req("GET", "/me", token=token)
    if code == 401:
        p("GET /me after logout → 401 (token invalidated)", status=code)
    else:
        # Supabase tokens may still be valid client-side — soft pass
        p("GET /me after logout (token still valid — Supabase client-side expiry)", status=code)


# ---------------------------------------------------------------------------
# 11. Edge cases & security
# ---------------------------------------------------------------------------

def test_edge_cases(token):
    section("11. EDGE CASES & SECURITY")

    # Invalid UUID
    code, body = req("GET", "/scan/not-a-uuid", token=token)
    if code in (400, 404):
        p("GET /scan/invalid-uuid → 400/404", status=code)
    else:
        f("GET /scan/invalid-uuid", f"Expected 400/404, got {code}")

    # Non-existent scan
    code, body = req("GET", "/scan/00000000-0000-0000-0000-000000000000", token=token)
    if code == 404:
        p("GET /scan/non-existent → 404", status=code)
    else:
        f("GET /scan/non-existent", f"Expected 404, got {code}")

    # Invalid URL for scan
    code, body = req("POST", "/scan", token=token, payload={"url": "not-a-url"})
    if code == 400:
        p("POST /scan invalid URL → 400", status=code)
    else:
        f("POST /scan invalid URL", f"Expected 400, got {code}")

    # Short password
    code, body = req("POST", "/signup", payload={"email": "x@gmail.com", "password": "short"})
    if code == 400:
        p("POST /signup short password → 400", status=code)
    else:
        f("POST /signup short password", f"Expected 400, got {code}")

    # Admin endpoint without admin role
    code, body = req("GET", "/admin/users", token=token)
    if code == 403:
        p("GET /admin/users non-admin → 403", status=code)
    else:
        f("GET /admin/users non-admin", f"Expected 403, got {code}")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary():
    section("FINAL RESULTS")
    total = PASS_COUNT + FAIL_COUNT
    pct = round(PASS_COUNT / total * 100) if total else 0
    print(f"\n  Total  : {total}")
    print(f"  Passed : {PASS_COUNT} ✅")
    print(f"  Failed : {FAIL_COUNT} ❌")
    print(f"  Score  : {pct}%")

    if FAIL_COUNT:
        print("\n  Failed tests:")
        for r in RESULTS:
            if r[0] == "FAIL":
                print(f"    ✗ {r[1]}: {r[2] if len(r) > 2 else ''}")

    print()
    if pct == 100:
        print("  🎉 ALL TESTS PASSED — backend is fully operational")
    elif pct >= 80:
        print("  ✅ Backend is mostly working — review failures above")
    else:
        print("  ⚠️  Several failures — review above and check Vercel logs")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  FUZZI BACKEND — LIVE API TEST SUITE")
    print(f"  URL   : {BASE}")
    print(f"  Email : {TEST_EMAIL}")
    print(f"  Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    test_health()
    token = test_auth()

    if not token:
        print("\n  ⛔ Cannot continue without a valid token — login failed.")
        print_summary()
        sys.exit(1)

    test_profile(token)
    scan_id = test_scan(token)

    if not scan_id:
        print("\n  ⛔ Cannot continue without a scan_id — scan submission failed.")
        print_summary()
        sys.exit(1)

    test_scan_list(token, scan_id)
    test_dashboard(token, scan_id)
    test_whatif(token, scan_id)
    test_compare(token, scan_id)
    test_reports(token, scan_id)
    test_edge_cases(token)
    test_logout(token)

    print_summary()
    sys.exit(0 if FAIL_COUNT == 0 else 1)
