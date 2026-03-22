"""
Scan execution pipeline — runs in a background thread.
"""
import logging
from datetime import datetime, timezone

from django.conf import settings

from api.models import Scan, FuzzyResult, Factor, Recommendation
from api.supabase_client import upload_file
from scanner.fuzzy_engine import run_fuzzy_assessment
from scanner.web_scanner import scan_target
from scanner.report_generator import build_pdf_report

logger = logging.getLogger(__name__)

RECOMMENDATIONS_MAP = {
    "security_headers": {
        "title": "Implement HTTP Security Headers",
        "description": "Critical HTTP security headers are missing, exposing users to XSS, clickjacking, and MIME-sniffing attacks.",
        "remediation": "Add Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy to all responses.",
        "category": "Security Headers",
        "ref_links": ["https://owasp.org/www-project-secure-headers/", "https://securityheaders.com"],
    },
    "authentication_config": {
        "title": "Harden Authentication Configuration",
        "description": "Authentication mechanisms are weak or misconfigured, risking credential theft and session hijacking.",
        "remediation": "Enforce HTTPS, set Secure/HttpOnly/SameSite cookie flags, implement MFA, and avoid HTTP Basic Auth.",
        "category": "Authentication",
        "ref_links": ["https://owasp.org/www-project-authentication-cheat-sheet/"],
    },
    "directory_permissions": {
        "title": "Restrict Directory and File Access",
        "description": "Sensitive files or directories are publicly accessible, leaking configuration and source code.",
        "remediation": "Disable directory listing, restrict access to .env, .git, config files, and backup directories.",
        "category": "Access Control",
        "ref_links": ["https://owasp.org/www-community/attacks/Path_Traversal"],
    },
    "error_handling": {
        "title": "Suppress Verbose Error Messages",
        "description": "Detailed error messages and stack traces are exposed, revealing internal architecture.",
        "remediation": "Configure custom error pages, disable debug mode in production, and log errors server-side only.",
        "category": "Error Handling",
        "ref_links": ["https://owasp.org/www-community/Improper_Error_Handling"],
    },
    "debug_mode": {
        "title": "Disable Debug Mode in Production",
        "description": "Debug mode is active, exposing internal state, environment variables, and detailed tracebacks.",
        "remediation": "Set DEBUG=False in production, remove debug toolbars, and strip server version headers.",
        "category": "Configuration",
        "ref_links": ["https://owasp.org/www-project-top-ten/"],
    },
    "access_control": {
        "title": "Fix CORS and Access Control Policies",
        "description": "Overly permissive CORS configuration allows unauthorized cross-origin requests.",
        "remediation": "Restrict Access-Control-Allow-Origin to trusted domains, never use wildcard with credentials.",
        "category": "Access Control",
        "ref_links": ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
    },
    "cloud_config": {
        "title": "Secure Cloud Configuration",
        "description": "Cloud provider credentials or bucket configurations are exposed in responses.",
        "remediation": "Remove cloud credentials from source code, restrict S3/GCS bucket policies, enable logging.",
        "category": "Cloud Security",
        "ref_links": ["https://owasp.org/www-project-cloud-native-application-security-top-10/"],
    },
    "ssl_tls_config": {
        "title": "Upgrade SSL/TLS Configuration",
        "description": "SSL/TLS configuration is weak or certificate is expiring soon.",
        "remediation": "Use TLS 1.2+, disable weak ciphers, renew certificates before expiry, enable HSTS.",
        "category": "Encryption",
        "ref_links": ["https://ssl-config.mozilla.org/"],
    },
    "input_validation": {
        "title": "Implement Input Validation and CSRF Protection",
        "description": "Forms lack proper input validation or CSRF tokens, enabling injection and CSRF attacks.",
        "remediation": "Add CSRF tokens to all forms, validate and sanitize all user inputs server-side.",
        "category": "Input Security",
        "ref_links": ["https://owasp.org/www-community/attacks/csrf"],
    },
    "third_party_risk": {
        "title": "Audit Third-Party Dependencies",
        "description": "Multiple third-party scripts are loaded, increasing supply chain attack surface.",
        "remediation": "Use Subresource Integrity (SRI) for external scripts, audit and minimise third-party dependencies.",
        "category": "Supply Chain",
        "ref_links": ["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"],
    },
    "seo_score": {
        "title": "Improve SEO Configuration",
        "description": "Missing or misconfigured SEO elements reduce search engine visibility.",
        "remediation": "Add title tags (50-70 chars), meta descriptions (120-160 chars), single H1, and alt text for images.",
        "category": "SEO",
        "ref_links": ["https://developers.google.com/search/docs/fundamentals/seo-starter-guide"],
    },
    "readability_score": {
        "title": "Improve Content Readability",
        "description": "Content structure and sentence complexity make the page difficult to read.",
        "remediation": "Use shorter sentences, add subheadings (H2/H3), break up long paragraphs.",
        "category": "Content Quality",
        "ref_links": ["https://www.w3.org/WAI/WCAG21/Understanding/reading-level"],
    },
    "design_consistency": {
        "title": "Improve Design Consistency",
        "description": "Inconsistent fonts, heavy inline styles, or missing viewport meta reduce UX quality.",
        "remediation": "Use a CSS design system, add viewport meta tag, minimise inline styles.",
        "category": "Design",
        "ref_links": ["https://developer.mozilla.org/en-US/docs/Web/HTML/Viewport_meta_tag"],
    },
    "performance_risk": {
        "title": "Optimise Page Performance",
        "description": "Missing caching, compression, or too many scripts increase load time.",
        "remediation": "Enable gzip/brotli compression, set Cache-Control headers, lazy-load images, bundle scripts.",
        "category": "Performance",
        "ref_links": ["https://web.dev/performance/"],
    },
}

SEVERITY_MAP = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}

FACTOR_CATEGORIES = {
    "security_headers": "HTTP Security",
    "authentication_config": "Authentication",
    "directory_permissions": "Access Control",
    "error_handling": "Error Management",
    "debug_mode": "Configuration",
    "access_control": "Access Control",
    "cloud_config": "Cloud Security",
    "ssl_tls_config": "Encryption",
    "input_validation": "Input Security",
    "third_party_risk": "Supply Chain",
    "seo_score": "SEO",
    "readability_score": "Content Quality",
    "design_consistency": "Design",
    "performance_risk": "Performance",
}


def execute_scan(scan_id: str) -> None:
    """Run the full scan pipeline for a given Scan UUID."""
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        logger.error("Scan %s not found", scan_id)
        return

    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    scan.save(update_fields=["status", "started_at"])

    try:
        logger.info("Starting scan for %s", scan.target_url)
        scan_result = scan_target(scan.target_url, scan.scan_options)
        scan.raw_results = scan_result
        # Store extracted text for future analysis
        html_features = scan_result.get("html_features", {})
        scan.html_content = html_features.get("full_text", "")[:10000]
        scan.save(update_fields=["raw_results", "html_content"])

        factors_input = scan_result.get("factors", {})
        fuzzy_output = run_fuzzy_assessment(factors_input)

        # Persist FuzzyResult
        FuzzyResult.objects.filter(scan=scan).delete()
        FuzzyResult.objects.create(
            scan=scan,
            risk_score=fuzzy_output["risk_score"],
            risk_level=fuzzy_output["risk_level"],
            overall_score=fuzzy_output["overall_score"],
            confidence=fuzzy_output["confidence"],
            category_scores=fuzzy_output["category_scores"],
            triggered_rules=fuzzy_output["triggered_rules"],
            fuzzy_inputs=fuzzy_output["fuzzy_inputs"],
            fuzzy_memberships=fuzzy_output["fuzzy_memberships"],
            aggregate_output=fuzzy_output["aggregate_output"],
            explainability=fuzzy_output["explainability"],
        )

        # Persist Factors
        Factor.objects.filter(scan=scan).delete()
        raw_details = scan_result.get("raw_details", {})
        memberships = fuzzy_output["fuzzy_memberships"]
        for factor_name, raw_score in factors_input.items():
            m = memberships.get(factor_name, {})
            dominant = max(m, key=m.get) if m else "MEDIUM"
            Factor.objects.create(
                scan=scan,
                name=factor_name,
                category=FACTOR_CATEGORIES.get(factor_name, "General"),
                raw_value=raw_score,
                score_100=round((1.0 - raw_score) * 100, 1),
                linguistic_value=dominant,
                details=raw_details.get(factor_name, {}),
            )

        # Generate recommendations
        Recommendation.objects.filter(scan=scan).delete()
        _generate_recommendations(scan, fuzzy_output)

        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.save(update_fields=["status", "completed_at"])

        # Update user scan count
        from api.models import UserProfile
        UserProfile.objects.filter(supabase_uid=scan.user_id).update(
            total_scans=models_total_scans(scan.user_id)
        )

        logger.info("Scan %s done. Risk=%s score=%.2f overall=%s",
                    scan_id, fuzzy_output["risk_level"], fuzzy_output["risk_score"], fuzzy_output["overall_score"])

    except Exception as exc:
        logger.exception("Scan %s failed: %s", scan_id, exc)
        scan.status = "failed"
        scan.error_message = str(exc)
        scan.completed_at = datetime.now(timezone.utc)
        scan.save(update_fields=["status", "error_message", "completed_at"])


def models_total_scans(user_id: str) -> int:
    from api.models import Scan as ScanModel
    return ScanModel.objects.filter(user_id=user_id, status="completed").count()


def _generate_recommendations(scan: Scan, fuzzy_output: dict) -> None:
    fuzzy_inputs = fuzzy_output["fuzzy_inputs"]
    memberships = fuzzy_output["fuzzy_memberships"]

    for factor, rec_template in RECOMMENDATIONS_MAP.items():
        factor_score = fuzzy_inputs.get(factor, 0)
        m = memberships.get(factor, {})
        dominant = max(m, key=m.get) if m else "LOW"

        if dominant in ("MEDIUM", "HIGH", "VERY_HIGH") or factor_score > 0.3:
            sev = "high" if dominant in ("HIGH", "VERY_HIGH") else "medium" if dominant == "MEDIUM" else "low"
            Recommendation.objects.create(
                scan=scan,
                title=rec_template["title"],
                description=rec_template["description"],
                severity=sev,
                category=rec_template["category"],
                remediation=rec_template["remediation"],
                ref_links=rec_template["references"],
                triggered_by_rule=factor,
            )

    # Critical rule-specific recommendations
    for rule in fuzzy_output.get("triggered_rules", []):
        if rule["consequent"] == "CRITICAL" and rule["firing_strength"] > 0.5:
            Recommendation.objects.create(
                scan=scan,
                title=f"Critical Rule Triggered: {rule['rule_id']}",
                description=rule["description"],
                severity="critical",
                category="Fuzzy Rule",
                remediation="Immediately address all antecedent factors listed in this rule.",
                ref_links=[],
                triggered_by_rule=rule["rule_id"],
            )
