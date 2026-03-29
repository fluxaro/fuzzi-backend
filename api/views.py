import hashlib
import hmac
import json
import logging
import threading
from datetime import datetime, timezone, timedelta

import requests as http_requests
from django.conf import settings
from django.db.models import Count, Avg, Min, Max
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import (
    Scan, FuzzyResult, Factor, Recommendation, Report,
    UserProfile, UserPreferences, ScanComparison,
    FuzzyRule, ConfigUpload, AuditLog, Webhook,
)
from .serializers import (
    ScanCreateSerializer, ScanDetailSerializer, ScanListSerializer,
    RecommendationSerializer, ReportSerializer, WhatIfSerializer,
    UserProfileSerializer, UserPreferencesSerializer,
    ScanComparisonSerializer, build_csv_report,
    FuzzyRuleSerializer, ConfigUploadSerializer,
    AuditLogSerializer, WebhookSerializer,
)
from .supabase_client import get_service_client, upload_file, get_signed_url
from scanner.fuzzy_engine import run_whatif_simulation, run_fuzzy_assessment, ALL_DIMENSIONS
from scanner.report_generator import build_pdf_report
from scanner.tasks import execute_scan

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _audit(request, action, resource_type='', resource_id='', details=None):
    """Fire-and-forget audit log entry."""
    try:
        AuditLog.objects.create(
            user_id=request.user.id,
            user_email=getattr(request.user, 'email', ''),
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id),
            details=details or {},
            ip_address=_get_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
        )
    except Exception:
        pass


def _get_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
    return xff.split(',')[0].strip() if xff else request.META.get('REMOTE_ADDR')


def _require_role(request, *roles):
    """Return 403 Response if user's profile role not in roles, else None."""
    try:
        profile = UserProfile.objects.get(supabase_uid=request.user.id)
        if profile.role not in roles:
            return Response({"error": f"Requires role: {', '.join(roles)}"}, status=403)
    except UserProfile.DoesNotExist:
        return Response({"error": "Profile not found"}, status=403)
    return None


def _fire_webhooks(user_id, event, payload):
    """Send webhook notifications in background thread."""
    def _send():
        hooks = Webhook.objects.filter(user_id=user_id, is_active=True)
        for hook in hooks:
            if event not in (hook.events or []):
                continue
            try:
                body = json.dumps({"event": event, "data": payload})
                headers = {"Content-Type": "application/json"}
                if hook.secret:
                    sig = hmac.new(hook.secret.encode(), body.encode(), hashlib.sha256).hexdigest()
                    headers["X-Fuzzi-Signature"] = f"sha256={sig}"
                r = http_requests.post(hook.url, data=body, headers=headers, timeout=10)
                hook.last_triggered_at = datetime.now(timezone.utc)
                if r.status_code >= 400:
                    hook.failure_count += 1
                hook.save(update_fields=["last_triggered_at", "failure_count"])
            except Exception as e:
                logger.warning("Webhook %s failed: %s", hook.url, e)
                hook.failure_count += 1
                hook.save(update_fields=["failure_count"])
    threading.Thread(target=_send, daemon=True).start()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email", "").strip()
        password = request.data.get("password", "")
        full_name = request.data.get("full_name", "")
        role = request.data.get("role", "analyst")

        if not email or not password:
            return Response({"error": "email and password are required"}, status=400)
        if len(password) < 8:
            return Response({"error": "Password must be at least 8 characters"}, status=400)
        if role not in ("admin", "analyst", "developer", "viewer"):
            role = "analyst"

        try:
            client = get_service_client()
            res = client.auth.admin.create_user({
                "email": email,
                "password": password,
                "email_confirm": True,
                "user_metadata": {"full_name": full_name},
            })
            user = res.user
            profile, _ = UserProfile.objects.get_or_create(
                supabase_uid=user.id,
                defaults={"email": email, "full_name": full_name, "role": role},
            )
            UserPreferences.objects.get_or_create(user=profile)
            return Response({"message": "User created successfully", "user_id": user.id, "email": user.email}, status=201)
        except Exception as exc:
            logger.error("Signup error: %s", exc)
            return Response({"error": str(exc)}, status=400)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email", "").strip()
        password = request.data.get("password", "")
        if not email or not password:
            return Response({"error": "email and password are required"}, status=400)
        try:
            client = get_service_client()
            res = client.auth.sign_in_with_password({"email": email, "password": password})
            session = res.session
            user = res.user
            profile, _ = UserProfile.objects.get_or_create(
                supabase_uid=user.id, defaults={"email": user.email}
            )
            profile.last_login = datetime.now(timezone.utc)
            profile.save(update_fields=["last_login"])
            return Response({
                "access_token": session.access_token,
                "refresh_token": session.refresh_token,
                "token_type": "Bearer",
                "expires_in": session.expires_in,
                "user": {
                    "id": user.id, "email": user.email,
                    "full_name": user.user_metadata.get("full_name", ""),
                    "role": profile.role,
                },
            })
        except Exception as exc:
            logger.error("Login error: %s", exc)
            return Response({"error": "Invalid credentials"}, status=401)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        _audit(request, "auth.logout")
        try:
            get_service_client().auth.admin.sign_out(request.auth)
        except Exception:
            pass
        return Response({"message": "Logged out successfully"})


class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        new_password = request.data.get("new_password", "")
        if len(new_password) < 8:
            return Response({"error": "Password must be at least 8 characters"}, status=400)
        try:
            # Use the user's own access token to change their password
            from supabase import create_client
            user_client = create_client(settings.SUPABASE_URL, settings.SUPABASE_ANON_KEY)
            user_client.auth.set_session(request.auth, "")
            user_client.auth.update_user({"password": new_password})
            _audit(request, "auth.password_change")
            return Response({"message": "Password updated successfully"})
        except Exception:
            # Fallback: admin update
            try:
                get_service_client().auth.admin.update_user_by_id(
                    request.user.id, {"password": new_password}
                )
                _audit(request, "auth.password_change")
                return Response({"message": "Password updated successfully"})
            except Exception as exc:
                return Response({"error": str(exc)}, status=400)


# ---------------------------------------------------------------------------
# Profile & Preferences
# ---------------------------------------------------------------------------

class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile, _ = UserProfile.objects.get_or_create(
            supabase_uid=request.user.id, defaults={"email": request.user.email}
        )
        UserPreferences.objects.get_or_create(user=profile)
        return Response(UserProfileSerializer(profile).data)

    def put(self, request):
        profile, _ = UserProfile.objects.get_or_create(
            supabase_uid=request.user.id, defaults={"email": request.user.email}
        )
        allowed = ["full_name", "organization", "avatar_url", "alert_threshold"]
        data = {k: v for k, v in request.data.items() if k in allowed}
        serializer = UserProfileSerializer(profile, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            try:
                get_service_client().auth.admin.update_user_by_id(
                    request.user.id, {"user_metadata": {"full_name": data.get("full_name", profile.full_name)}}
                )
            except Exception:
                pass
            _audit(request, "profile.update", "user", profile.id, data)
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def patch(self, request):
        return self.put(request)


class PreferencesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile, _ = UserProfile.objects.get_or_create(
            supabase_uid=request.user.id, defaults={"email": request.user.email}
        )
        prefs, _ = UserPreferences.objects.get_or_create(user=profile)
        return Response(UserPreferencesSerializer(prefs).data)

    def post(self, request):
        profile, _ = UserProfile.objects.get_or_create(
            supabase_uid=request.user.id, defaults={"email": request.user.email}
        )
        prefs, _ = UserPreferences.objects.get_or_create(user=profile)
        serializer = UserPreferencesSerializer(prefs, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            _audit(request, "preferences.update", "user", profile.id)
            return Response(serializer.data)
        return Response(serializer.errors, status=400)


# ---------------------------------------------------------------------------
# Config Upload & Parsing
# ---------------------------------------------------------------------------

class ConfigUploadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Upload JSON/YAML/CSV config file and extract fuzzy input parameters."""
        import io
        file_obj = request.FILES.get("file")
        if not file_obj:
            # Also accept raw JSON body
            raw = request.data.get("config")
            if not raw:
                return Response({"error": "Provide a file or config JSON body"}, status=400)
            parsed, fmt, error = _parse_config_body(raw)
        else:
            parsed, fmt, error = _parse_config_file(file_obj)

        if error:
            return Response({"error": error}, status=400)

        # Map parsed config keys to fuzzy dimensions
        fuzzy_inputs = _map_config_to_inputs(parsed)

        upload = ConfigUpload.objects.create(
            user_id=request.user.id,
            filename=getattr(file_obj, 'name', 'inline.json'),
            format=fmt,
            parsed_config=parsed,
            status='parsed',
        )

        # Optionally run fuzzy assessment immediately
        run_now = request.data.get("run_assessment", False)
        assessment = None
        if run_now:
            assessment = run_fuzzy_assessment(fuzzy_inputs)

        _audit(request, "config.upload", "config", upload.id, {"format": fmt, "keys": list(parsed.keys())[:10]})
        return Response({
            "upload_id": str(upload.id),
            "format": fmt,
            "parsed_keys": list(parsed.keys()),
            "fuzzy_inputs_extracted": fuzzy_inputs,
            "assessment": assessment,
        }, status=201)

    def get(self, request):
        uploads = ConfigUpload.objects.filter(user_id=request.user.id).order_by("-created_at")[:50]
        return Response(ConfigUploadSerializer(uploads, many=True).data)


def _parse_config_file(file_obj):
    import yaml
    name = file_obj.name.lower()
    content = file_obj.read().decode("utf-8", errors="replace")
    try:
        if name.endswith(".json"):
            return json.loads(content), "json", None
        elif name.endswith((".yaml", ".yml")):
            return yaml.safe_load(content), "yaml", None
        elif name.endswith(".csv"):
            import csv, io
            reader = csv.DictReader(io.StringIO(content))
            rows = list(reader)
            parsed = {row.get("key", row.get("parameter", f"row_{i}")): row.get("value", row.get("score", "")) for i, row in enumerate(rows)}
            return parsed, "csv", None
        else:
            return {}, "json", "Unsupported file format. Use JSON, YAML, or CSV."
    except Exception as e:
        return {}, "json", f"Parse error: {e}"


def _parse_config_body(raw):
    if isinstance(raw, dict):
        return raw, "json", None
    try:
        return json.loads(raw), "json", None
    except Exception as e:
        return {}, "json", f"Invalid JSON: {e}"


def _map_config_to_inputs(config: dict) -> dict:
    """Map arbitrary config keys to fuzzy dimension names (0-1 risk values)."""
    mapping = {
        # Security headers
        "content_security_policy": "security_headers", "csp": "security_headers",
        "hsts": "security_headers", "x_frame_options": "security_headers",
        "security_headers": "security_headers",
        # Auth
        "authentication": "authentication_config", "auth": "authentication_config",
        "mfa": "authentication_config", "two_factor": "authentication_config",
        "authentication_config": "authentication_config",
        # Access control
        "cors": "access_control", "access_control": "access_control",
        "rbac": "access_control", "permissions": "access_control",
        # Debug
        "debug": "debug_mode", "debug_mode": "debug_mode",
        # Error handling
        "error_handling": "error_handling", "verbose_errors": "error_handling",
        # SSL
        "ssl": "ssl_tls_config", "tls": "ssl_tls_config", "https": "ssl_tls_config",
        "ssl_tls_config": "ssl_tls_config",
        # Cloud
        "cloud": "cloud_config", "s3": "cloud_config", "cloud_config": "cloud_config",
        # Input validation
        "input_validation": "input_validation", "csrf": "input_validation",
        # Directory
        "directory_listing": "directory_permissions", "directory_permissions": "directory_permissions",
    }
    result = {}
    for key, val in config.items():
        dim = mapping.get(key.lower().replace("-", "_"))
        if dim and dim not in result:
            # Normalise value to 0-1 risk score
            try:
                v = float(val)
                result[dim] = max(0.0, min(1.0, v))
            except (TypeError, ValueError):
                # Boolean-like
                sv = str(val).lower()
                if sv in ("true", "yes", "1", "enabled", "on"):
                    result[dim] = 0.1   # feature present = low risk
                elif sv in ("false", "no", "0", "disabled", "off"):
                    result[dim] = 0.8   # feature absent = high risk
    return result


# ---------------------------------------------------------------------------
# Fuzzy Rule Management (admin + analyst)
# ---------------------------------------------------------------------------

class FuzzyRuleListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """List all active rules. Admins see all, others see active only."""
        try:
            profile = UserProfile.objects.get(supabase_uid=request.user.id)
            is_admin = profile.role == "admin"
        except UserProfile.DoesNotExist:
            is_admin = False

        rules = FuzzyRule.objects.all() if is_admin else FuzzyRule.objects.filter(is_active=True)
        return Response(FuzzyRuleSerializer(rules, many=True).data)

    def post(self, request):
        """Create a new custom rule. Admin only."""
        err = _require_role(request, "admin")
        if err:
            return err

        serializer = FuzzyRuleSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)

        # Validate antecedents structure
        antecedents = serializer.validated_data.get("antecedents", [])
        valid_levels = {"VERY_LOW", "LOW", "MEDIUM", "HIGH", "VERY_HIGH"}
        for ant in antecedents:
            if ant.get("factor") not in ALL_DIMENSIONS:
                return Response({"error": f"Unknown factor: {ant.get('factor')}. Valid: {ALL_DIMENSIONS}"}, status=400)
            if ant.get("level") not in valid_levels:
                return Response({"error": f"Unknown level: {ant.get('level')}. Valid: {valid_levels}"}, status=400)

        rule = serializer.save(source="custom", created_by=request.user.id)
        _audit(request, "rule.create", "fuzzy_rule", rule.id, {"rule_id": rule.rule_id})
        return Response(FuzzyRuleSerializer(rule).data, status=201)


class FuzzyRuleDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, rule_id):
        try:
            rule = FuzzyRule.objects.get(id=rule_id)
        except FuzzyRule.DoesNotExist:
            return Response({"error": "Rule not found"}, status=404)
        return Response(FuzzyRuleSerializer(rule).data)

    def put(self, request, rule_id):
        err = _require_role(request, "admin")
        if err:
            return err
        try:
            rule = FuzzyRule.objects.get(id=rule_id)
        except FuzzyRule.DoesNotExist:
            return Response({"error": "Rule not found"}, status=404)
        serializer = FuzzyRuleSerializer(rule, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            _audit(request, "rule.update", "fuzzy_rule", rule_id, request.data)
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, rule_id):
        err = _require_role(request, "admin")
        if err:
            return err
        try:
            rule = FuzzyRule.objects.get(id=rule_id)
            rule.is_active = False
            rule.save(update_fields=["is_active"])
            _audit(request, "rule.deactivate", "fuzzy_rule", rule_id)
            return Response({"message": "Rule deactivated"})
        except FuzzyRule.DoesNotExist:
            return Response({"error": "Rule not found"}, status=404)


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

class ScanCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Developers and above can submit scans
        err = _require_role(request, "admin", "analyst", "developer")
        if err:
            return err

        serializer = ScanCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)

        url = serializer.validated_data["url"]
        # Link to previous scan of same URL for versioning
        previous = Scan.objects.filter(
            user_id=request.user.id, target_url=url, status="completed"
        ).order_by("-created_at").first()

        scan = Scan.objects.create(
            user_id=request.user.id,
            target_url=url,
            title=serializer.validated_data.get("title", ""),
            environment=serializer.validated_data.get("environment", "production"),
            scan_options=serializer.validated_data.get("options", {}),
            previous_scan=previous,
            status="pending",
        )
        t = threading.Thread(target=_scan_with_hooks, args=(str(scan.id), request.user.id), daemon=True)
        t.start()
        _audit(request, "scan.create", "scan", scan.id, {"url": url})
        return Response({
            "scan_id": str(scan.id),
            "status": "pending",
            "message": "Scan started. Poll /api/scan/{id} for results.",
            "target_url": scan.target_url,
            "environment": scan.environment,
            "previous_scan_id": str(previous.id) if previous else None,
        }, status=202)


def _scan_with_hooks(scan_id: str, user_id: str):
    """Run scan then fire webhooks."""
    execute_scan(scan_id)
    try:
        scan = Scan.objects.select_related("fuzzy_result").get(id=scan_id)
        event = "scan.completed" if scan.status == "completed" else "scan.failed"
        payload = {"scan_id": scan_id, "status": scan.status, "url": scan.target_url}
        if scan.status == "completed":
            try:
                fr = scan.fuzzy_result
                payload.update({"risk_level": fr.risk_level, "risk_score": fr.risk_score, "overall_score": fr.overall_score})
                # Also fire risk-level events
                if fr.risk_level == "CRITICAL":
                    _fire_webhooks(user_id, "risk.critical", payload)
                elif fr.risk_level == "HIGH":
                    _fire_webhooks(user_id, "risk.high", payload)
            except Exception:
                pass
        _fire_webhooks(user_id, event, payload)
    except Exception as e:
        logger.warning("Post-scan hooks failed: %s", e)


class ScanDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        try:
            scan = Scan.objects.prefetch_related(
                "fuzzy_result", "factors", "recommendations"
            ).get(id=scan_id, user_id=request.user.id)
        except Scan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=404)
        return Response(ScanDetailSerializer(scan).data)

    def delete(self, request, scan_id):
        err = _require_role(request, "admin", "analyst")
        if err:
            return err
        try:
            Scan.objects.get(id=scan_id, user_id=request.user.id).delete()
            _audit(request, "scan.delete", "scan", scan_id)
            return Response({"message": "Scan deleted"})
        except Scan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=404)

    def patch(self, request, scan_id):
        try:
            scan = Scan.objects.get(id=scan_id, user_id=request.user.id)
        except Scan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=404)
        if "title" in request.data:
            scan.title = request.data["title"]
        if "is_bookmarked" in request.data:
            scan.is_bookmarked = bool(request.data["is_bookmarked"])
        scan.save(update_fields=["title", "is_bookmarked", "updated_at"])
        return Response(ScanListSerializer(scan).data)


class ScanListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        scans = Scan.objects.filter(user_id=request.user.id).select_related("fuzzy_result").order_by("-created_at")

        if request.query_params.get("status"):
            scans = scans.filter(status=request.query_params["status"])
        if request.query_params.get("risk_level"):
            scans = scans.filter(fuzzy_result__risk_level=request.query_params["risk_level"].upper())
        if request.query_params.get("bookmarked") == "true":
            scans = scans.filter(is_bookmarked=True)
        if request.query_params.get("search"):
            scans = scans.filter(target_url__icontains=request.query_params["search"])
        if request.query_params.get("environment"):
            scans = scans.filter(environment=request.query_params["environment"])

        page_size = int(request.query_params.get("page_size", 20))
        page = int(request.query_params.get("page", 1))
        total = scans.count()
        return Response({
            "total": total, "page": page, "page_size": page_size,
            "results": ScanListSerializer(scans[(page - 1) * page_size: page * page_size], many=True).data,
        })


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class DashboardSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        uid = request.user.id
        scans = Scan.objects.filter(user_id=uid)
        total = scans.count()
        risk_dist = (FuzzyResult.objects.filter(scan__user_id=uid)
                     .values("risk_level").annotate(count=Count("id")))
        agg = FuzzyResult.objects.filter(scan__user_id=uid).aggregate(
            avg_score=Avg("risk_score"), avg_overall=Avg("overall_score"),
            min_overall=Min("overall_score"), max_overall=Max("overall_score"),
        )
        week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        top_misconfigs = (
            Recommendation.objects.filter(scan__user_id=uid, severity__in=["high", "critical"])
            .values("category", "title").annotate(count=Count("id")).order_by("-count")[:5]
        )
        return Response({
            "total_scans": total,
            "completed_scans": scans.filter(status="completed").count(),
            "failed_scans": scans.filter(status="failed").count(),
            "running_scans": scans.filter(status__in=["pending", "running"]).count(),
            "bookmarked_scans": scans.filter(is_bookmarked=True).count(),
            "risk_distribution": {r["risk_level"]: r["count"] for r in risk_dist},
            "average_risk_score": round(agg["avg_score"] or 0, 4),
            "average_overall_score": round(agg["avg_overall"] or 0, 1),
            "best_overall_score": agg["max_overall"],
            "worst_overall_score": agg["min_overall"],
            "high_risk_last_7_days": FuzzyResult.objects.filter(
                scan__user_id=uid, scan__created_at__gte=week_ago,
                risk_level__in=["HIGH", "CRITICAL"],
            ).count(),
            "top_misconfigurations": list(top_misconfigs),
        })


class DashboardHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        uid = request.user.id
        days = int(request.query_params.get("days", 30))
        since = datetime.now(timezone.utc) - timedelta(days=days)
        scans = (Scan.objects.filter(user_id=uid, created_at__gte=since, status="completed")
                 .select_related("fuzzy_result").order_by("created_at"))
        history = []
        for scan in scans:
            entry = {"date": scan.created_at.strftime("%Y-%m-%d"), "scan_id": str(scan.id),
                     "target_url": scan.target_url, "environment": scan.environment,
                     "risk_score": None, "risk_level": None, "overall_score": None, "category_scores": None}
            try:
                fr = scan.fuzzy_result
                entry.update({"risk_score": fr.risk_score, "risk_level": fr.risk_level,
                               "overall_score": fr.overall_score, "category_scores": fr.category_scores})
            except Exception:
                pass
            history.append(entry)
        return Response({"days": days, "total": len(history), "history": history})


class DashboardRecommendationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        try:
            scan = Scan.objects.get(id=scan_id, user_id=request.user.id)
        except Scan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=404)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        recs = sorted(Recommendation.objects.filter(scan=scan),
                      key=lambda r: severity_order.get(r.severity, 5))
        return Response({
            "scan_id": str(scan_id), "target_url": scan.target_url,
            "total": len(recs), "unresolved": sum(1 for r in recs if not r.is_resolved),
            "recommendations": RecommendationSerializer(recs, many=True).data,
        })

    def patch(self, request, scan_id):
        rec_id = request.data.get("recommendation_id")
        try:
            rec = Recommendation.objects.get(id=rec_id, scan__user_id=request.user.id)
            rec.is_resolved = request.data.get("is_resolved", True)
            rec.save(update_fields=["is_resolved"])
            _audit(request, "recommendation.resolve", "recommendation", rec_id)
            return Response(RecommendationSerializer(rec).data)
        except Recommendation.DoesNotExist:
            return Response({"error": "Recommendation not found"}, status=404)


class AnalyticsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from django.db.models.functions import TruncDate
        uid = request.user.id
        days = int(request.query_params.get("days", 30))
        since = datetime.now(timezone.utc) - timedelta(days=days)
        fuzzy_results = FuzzyResult.objects.filter(scan__user_id=uid)
        cat_avgs = {}
        for fr in fuzzy_results.filter(scan__created_at__gte=since):
            for cat, score in (fr.category_scores or {}).items():
                cat_avgs.setdefault(cat, []).append(score)
        return Response({
            "period_days": days,
            "total_scans_in_period": Scan.objects.filter(user_id=uid, status="completed", created_at__gte=since).count(),
            "average_category_scores": {cat: round(sum(v) / len(v), 1) for cat, v in cat_avgs.items()},
            "top_performing_scans": list(fuzzy_results.filter(scan__created_at__gte=since)
                                         .order_by("-overall_score")[:5]
                                         .values("scan__id", "scan__target_url", "overall_score", "risk_level")),
            "worst_performing_scans": list(fuzzy_results.filter(scan__created_at__gte=since)
                                           .order_by("overall_score")[:5]
                                           .values("scan__id", "scan__target_url", "overall_score", "risk_level")),
            "most_common_issues": list(Recommendation.objects.filter(scan__user_id=uid, scan__created_at__gte=since)
                                       .values("category").annotate(count=Count("id")).order_by("-count")[:8]),
            "daily_scan_counts": [{"date": str(d["day"]), "count": d["count"]} for d in
                                   Scan.objects.filter(user_id=uid, created_at__gte=since)
                                   .annotate(day=TruncDate("created_at"))
                                   .values("day").annotate(count=Count("id")).order_by("day")],
        })


# ---------------------------------------------------------------------------
# What-if simulation
# ---------------------------------------------------------------------------

class WhatIfView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = WhatIfSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)
        try:
            scan = Scan.objects.get(id=serializer.validated_data["scan_id"], user_id=request.user.id)
            fuzzy_result = scan.fuzzy_result
        except Scan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=404)
        except FuzzyResult.DoesNotExist:
            return Response({"error": "Scan has no fuzzy result yet"}, status=400)
        return Response(run_whatif_simulation(fuzzy_result.fuzzy_inputs, serializer.validated_data["overrides"]))


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

class ScanCompareView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        scan_a_id = request.data.get("scan_a_id")
        scan_b_id = request.data.get("scan_b_id")
        if not scan_a_id or not scan_b_id:
            return Response({"error": "scan_a_id and scan_b_id are required"}, status=400)
        try:
            scan_a = Scan.objects.get(id=scan_a_id, user_id=request.user.id)
            scan_b = Scan.objects.get(id=scan_b_id, user_id=request.user.id)
            fr_a, fr_b = scan_a.fuzzy_result, scan_b.fuzzy_result
        except Scan.DoesNotExist:
            return Response({"error": "One or both scans not found"}, status=404)
        except FuzzyResult.DoesNotExist:
            return Response({"error": "Both scans must be completed with fuzzy results"}, status=400)
        comparison_data = {
            "risk_score_diff": round(fr_b.risk_score - fr_a.risk_score, 4),
            "overall_score_diff": round(fr_b.overall_score - fr_a.overall_score, 1),
            "category_diffs": {cat: round((fr_b.category_scores or {}).get(cat, 0) - (fr_a.category_scores or {}).get(cat, 0), 1)
                               for cat in (fr_a.category_scores or {})},
            "risk_level_a": fr_a.risk_level, "risk_level_b": fr_b.risk_level,
            "winner": str(scan_a.id) if fr_a.overall_score >= fr_b.overall_score else str(scan_b.id),
        }
        comparison, _ = ScanComparison.objects.update_or_create(
            user_id=request.user.id, scan_a=scan_a, scan_b=scan_b,
            defaults={"comparison_data": comparison_data},
        )
        return Response(ScanComparisonSerializer(comparison).data, status=201)

    def get(self, request):
        comparisons = ScanComparison.objects.filter(user_id=request.user.id).order_by("-created_at")[:20]
        return Response(ScanComparisonSerializer(comparisons, many=True).data)


# ---------------------------------------------------------------------------
# Reports (PDF + CSV + JSON)
# ---------------------------------------------------------------------------

class ReportGenerateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, scan_id):
        fmt = request.data.get("format", "pdf").lower()
        if fmt not in ("pdf", "csv", "json"):
            return Response({"error": "format must be pdf, csv, or json"}, status=400)
        try:
            scan = Scan.objects.prefetch_related("fuzzy_result", "recommendations", "factors").get(
                id=scan_id, user_id=request.user.id)
        except Scan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=404)
        if scan.status != "completed":
            return Response({"error": "Scan is not completed yet"}, status=400)
        try:
            fr = scan.fuzzy_result
        except FuzzyResult.DoesNotExist:
            return Response({"error": "No fuzzy result for this scan"}, status=400)

        scan_data = {"id": str(scan.id), "target_url": scan.target_url, "status": scan.status}
        factors = list(scan.factors.all())
        recommendations = list(scan.recommendations.all())
        recs_dicts = [{"title": r.title, "description": r.description, "severity": r.severity, "remediation": r.remediation} for r in recommendations]

        if fmt == "pdf":
            fuzzy_data = {
                "risk_score": fr.risk_score, "risk_level": fr.risk_level, "overall_score": fr.overall_score,
                "confidence": fr.confidence, "category_scores": fr.category_scores,
                "triggered_rules": fr.triggered_rules, "fuzzy_inputs": fr.fuzzy_inputs,
                "fuzzy_memberships": fr.fuzzy_memberships, "aggregate_output": fr.aggregate_output,
                "explainability": fr.explainability,
            }
            file_bytes = build_pdf_report(scan_data, fuzzy_data, recs_dicts)
            content_type = "application/pdf"
        elif fmt == "csv":
            file_bytes = build_csv_report(scan, fr, factors, recommendations)
            content_type = "text/csv"
        else:  # json
            import json as _json
            export = {
                "scan": scan_data, "fuzzy_result": {
                    "risk_score": fr.risk_score, "risk_level": fr.risk_level,
                    "overall_score": fr.overall_score, "confidence": fr.confidence,
                    "category_scores": fr.category_scores, "triggered_rules": fr.triggered_rules,
                    "explainability": fr.explainability,
                },
                "factors": [{"name": f.name, "category": f.category, "raw_value": f.raw_value,
                              "score_100": f.score_100, "level": f.linguistic_value} for f in factors],
                "recommendations": recs_dicts,
            }
            file_bytes = _json.dumps(export, indent=2).encode("utf-8")
            content_type = "application/json"

        storage_path = f"reports/{scan.user_id}/{scan.id}.{fmt}"
        uploaded = upload_file(settings.SUPABASE_REPORTS_BUCKET, storage_path, file_bytes, content_type)
        report, _ = Report.objects.update_or_create(
            scan=scan, format=fmt,
            defaults={"storage_path": storage_path, "file_size": len(file_bytes)},
        )
        signed_url = get_signed_url(settings.SUPABASE_REPORTS_BUCKET, storage_path) if uploaded else None
        _audit(request, "report.generate", "report", report.id, {"format": fmt})
        return Response({
            "report_id": str(report.id), "scan_id": str(scan_id), "format": fmt,
            "file_size": len(file_bytes), "storage_path": storage_path,
            "signed_url": signed_url, "uploaded_to_storage": uploaded,
            "generated_at": report.generated_at.isoformat(),
        }, status=201)


class ReportRetrieveView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        fmt = request.query_params.get("format", "pdf").lower()
        try:
            scan = Scan.objects.get(id=scan_id, user_id=request.user.id)
        except Scan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=404)
        try:
            report = Report.objects.get(scan=scan, format=fmt)
        except Report.DoesNotExist:
            return Response({"error": f"No {fmt.upper()} report. POST to /api/reports/{scan_id} first."}, status=404)
        report.download_count += 1
        report.save(update_fields=["download_count"])
        return Response(ReportSerializer(report).data)


# ---------------------------------------------------------------------------
# Webhooks
# ---------------------------------------------------------------------------

class WebhookListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        hooks = Webhook.objects.filter(user_id=request.user.id)
        return Response(WebhookSerializer(hooks, many=True).data)

    def post(self, request):
        serializer = WebhookSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)
        hook = serializer.save(user_id=request.user.id)
        _audit(request, "webhook.create", "webhook", hook.id, {"url": hook.url})
        return Response(WebhookSerializer(hook).data, status=201)


class WebhookDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, webhook_id):
        try:
            hook = Webhook.objects.get(id=webhook_id, user_id=request.user.id)
        except Webhook.DoesNotExist:
            return Response({"error": "Webhook not found"}, status=404)
        serializer = WebhookSerializer(hook, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, webhook_id):
        try:
            Webhook.objects.get(id=webhook_id, user_id=request.user.id).delete()
            _audit(request, "webhook.delete", "webhook", webhook_id)
            return Response({"message": "Webhook deleted"})
        except Webhook.DoesNotExist:
            return Response({"error": "Webhook not found"}, status=404)


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------

class AuditLogView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        err = _require_role(request, "admin")
        if err:
            # Non-admins can only see their own logs
            logs = AuditLog.objects.filter(user_id=request.user.id).order_by("-created_at")[:100]
        else:
            logs = AuditLog.objects.all().order_by("-created_at")[:200]
        return Response(AuditLogSerializer(logs, many=True).data)


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

class AdminUsersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        err = _require_role(request, "admin")
        if err:
            return err
        users = UserProfile.objects.all().order_by("-created_at")
        return Response(UserProfileSerializer(users, many=True).data)

    def patch(self, request):
        err = _require_role(request, "admin")
        if err:
            return err
        uid = request.data.get("supabase_uid")
        try:
            profile = UserProfile.objects.get(supabase_uid=uid)
            allowed = ["role", "is_active", "organization", "full_name"]
            data = {k: v for k, v in request.data.items() if k in allowed}
            serializer = UserProfileSerializer(profile, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                _audit(request, "admin.user_update", "user", profile.id, data)
                return Response(serializer.data)
            return Response(serializer.errors, status=400)
        except UserProfile.DoesNotExist:
            return Response({"error": "User not found"}, status=404)
