import logging
import threading
from datetime import datetime, timezone, timedelta

from django.conf import settings
from django.db.models import Count, Avg, Min, Max, Q
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import (
    Scan, FuzzyResult, Factor, Recommendation, Report,
    UserProfile, UserPreferences, ScanComparison,
)
from .serializers import (
    ScanCreateSerializer, ScanDetailSerializer, ScanListSerializer,
    RecommendationSerializer, ReportSerializer, WhatIfSerializer,
    UserProfileSerializer, UserPreferencesSerializer,
    ScanComparisonSerializer, build_csv_report,
)
from .supabase_client import get_service_client, upload_file, get_signed_url
from scanner.fuzzy_engine import run_whatif_simulation
from scanner.report_generator import build_pdf_report
from scanner.tasks import execute_scan

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email", "").strip()
        password = request.data.get("password", "")
        full_name = request.data.get("full_name", "")

        if not email or not password:
            return Response({"error": "email and password are required"}, status=400)
        if len(password) < 8:
            return Response({"error": "Password must be at least 8 characters"}, status=400)

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
                defaults={"email": email, "full_name": full_name},
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
            UserProfile.objects.filter(supabase_uid=user.id).update(last_login=datetime.now(timezone.utc))
            return Response({
                "access_token": session.access_token,
                "refresh_token": session.refresh_token,
                "token_type": "Bearer",
                "expires_in": session.expires_in,
                "user": {"id": user.id, "email": user.email, "full_name": user.user_metadata.get("full_name", "")},
            })
        except Exception as exc:
            logger.error("Login error: %s", exc)
            return Response({"error": "Invalid credentials"}, status=401)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
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
            client = get_service_client()
            client.auth.admin.update_user_by_id(request.user.id, {"password": new_password})
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
            supabase_uid=request.user.id,
            defaults={"email": request.user.email},
        )
        UserPreferences.objects.get_or_create(user=profile)
        return Response(UserProfileSerializer(profile).data)

    def put(self, request):
        profile, _ = UserProfile.objects.get_or_create(
            supabase_uid=request.user.id,
            defaults={"email": request.user.email},
        )
        allowed = ["full_name", "organization", "avatar_url"]
        data = {k: v for k, v in request.data.items() if k in allowed}
        serializer = UserProfileSerializer(profile, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            # Sync name to Supabase
            try:
                get_service_client().auth.admin.update_user_by_id(
                    request.user.id, {"user_metadata": {"full_name": data.get("full_name", profile.full_name)}}
                )
            except Exception:
                pass
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
            return Response(serializer.data)
        return Response(serializer.errors, status=400)


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

class ScanCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ScanCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)

        scan = Scan.objects.create(
            user_id=request.user.id,
            target_url=serializer.validated_data["url"],
            title=serializer.validated_data.get("title", ""),
            scan_options=serializer.validated_data.get("options", {}),
            status="pending",
        )
        t = threading.Thread(target=execute_scan, args=(str(scan.id),), daemon=True)
        t.start()
        return Response({
            "scan_id": str(scan.id),
            "status": "pending",
            "message": "Scan started. Poll /api/scan/{id} for results.",
            "target_url": scan.target_url,
        }, status=202)


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
        try:
            Scan.objects.get(id=scan_id, user_id=request.user.id).delete()
            return Response({"message": "Scan deleted"})
        except Scan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=404)

    def patch(self, request, scan_id):
        """Update scan title or bookmark status."""
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

        status_filter = request.query_params.get("status")
        risk_filter = request.query_params.get("risk_level")
        bookmarked = request.query_params.get("bookmarked")
        search = request.query_params.get("search")

        if status_filter:
            scans = scans.filter(status=status_filter)
        if risk_filter:
            scans = scans.filter(fuzzy_result__risk_level=risk_filter.upper())
        if bookmarked == "true":
            scans = scans.filter(is_bookmarked=True)
        if search:
            scans = scans.filter(target_url__icontains=search)

        page_size = int(request.query_params.get("page_size", 20))
        page = int(request.query_params.get("page", 1))
        total = scans.count()
        scans_page = scans[(page - 1) * page_size: page * page_size]

        return Response({
            "total": total, "page": page, "page_size": page_size,
            "results": ScanListSerializer(scans_page, many=True).data,
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
        completed = scans.filter(status="completed").count()
        failed = scans.filter(status="failed").count()
        running = scans.filter(status__in=["pending", "running"]).count()

        risk_dist = (
            FuzzyResult.objects.filter(scan__user_id=uid)
            .values("risk_level").annotate(count=Count("id"))
        )
        risk_counts = {r["risk_level"]: r["count"] for r in risk_dist}

        agg = FuzzyResult.objects.filter(scan__user_id=uid).aggregate(
            avg_score=Avg("risk_score"),
            avg_overall=Avg("overall_score"),
            min_overall=Min("overall_score"),
            max_overall=Max("overall_score"),
        )

        week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        recent_high = FuzzyResult.objects.filter(
            scan__user_id=uid, scan__created_at__gte=week_ago,
            risk_level__in=["HIGH", "CRITICAL"],
        ).count()

        top_misconfigs = (
            Recommendation.objects.filter(scan__user_id=uid, severity__in=["high", "critical"])
            .values("category", "title").annotate(count=Count("id")).order_by("-count")[:5]
        )

        bookmarked = scans.filter(is_bookmarked=True).count()

        return Response({
            "total_scans": total,
            "completed_scans": completed,
            "failed_scans": failed,
            "running_scans": running,
            "bookmarked_scans": bookmarked,
            "risk_distribution": risk_counts,
            "average_risk_score": round(agg["avg_score"] or 0, 4),
            "average_overall_score": round(agg["avg_overall"] or 0, 1),
            "best_overall_score": agg["max_overall"],
            "worst_overall_score": agg["min_overall"],
            "high_risk_last_7_days": recent_high,
            "top_misconfigurations": list(top_misconfigs),
        })


class DashboardHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        uid = request.user.id
        days = int(request.query_params.get("days", 30))
        since = datetime.now(timezone.utc) - timedelta(days=days)

        scans = (
            Scan.objects.filter(user_id=uid, created_at__gte=since, status="completed")
            .select_related("fuzzy_result").order_by("created_at")
        )

        history = []
        for scan in scans:
            entry = {
                "date": scan.created_at.strftime("%Y-%m-%d"),
                "scan_id": str(scan.id),
                "target_url": scan.target_url,
                "risk_score": None, "risk_level": None,
                "overall_score": None, "category_scores": None,
            }
            try:
                fr = scan.fuzzy_result
                entry.update({
                    "risk_score": fr.risk_score,
                    "risk_level": fr.risk_level,
                    "overall_score": fr.overall_score,
                    "category_scores": fr.category_scores,
                })
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
        recs = sorted(
            Recommendation.objects.filter(scan=scan),
            key=lambda r: severity_order.get(r.severity, 5)
        )
        return Response({
            "scan_id": str(scan_id),
            "target_url": scan.target_url,
            "total": len(recs),
            "unresolved": sum(1 for r in recs if not r.is_resolved),
            "recommendations": RecommendationSerializer(recs, many=True).data,
        })

    def patch(self, request, scan_id):
        rec_id = request.data.get("recommendation_id")
        try:
            rec = Recommendation.objects.get(id=rec_id, scan__user_id=request.user.id)
            rec.is_resolved = request.data.get("is_resolved", True)
            rec.save(update_fields=["is_resolved"])
            return Response(RecommendationSerializer(rec).data)
        except Recommendation.DoesNotExist:
            return Response({"error": "Recommendation not found"}, status=404)


class AnalyticsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        uid = request.user.id
        days = int(request.query_params.get("days", 30))
        since = datetime.now(timezone.utc) - timedelta(days=days)

        completed_scans = Scan.objects.filter(user_id=uid, status="completed")
        fuzzy_results = FuzzyResult.objects.filter(scan__user_id=uid)

        # Average category scores
        cat_avgs = {}
        for fr in fuzzy_results.filter(scan__created_at__gte=since):
            for cat, score in (fr.category_scores or {}).items():
                cat_avgs.setdefault(cat, []).append(score)
        avg_category_scores = {cat: round(sum(v) / len(v), 1) for cat, v in cat_avgs.items()}

        # Top performing and worst performing scans
        top_scans = (
            fuzzy_results.filter(scan__created_at__gte=since)
            .order_by("-overall_score")[:5]
            .values("scan__id", "scan__target_url", "overall_score", "risk_level")
        )
        worst_scans = (
            fuzzy_results.filter(scan__created_at__gte=since)
            .order_by("overall_score")[:5]
            .values("scan__id", "scan__target_url", "overall_score", "risk_level")
        )

        # Most common recommendation categories
        common_issues = (
            Recommendation.objects.filter(scan__user_id=uid, scan__created_at__gte=since)
            .values("category").annotate(count=Count("id")).order_by("-count")[:8]
        )

        # Scan frequency per day
        from django.db.models.functions import TruncDate
        daily_counts = (
            Scan.objects.filter(user_id=uid, created_at__gte=since)
            .annotate(day=TruncDate("created_at"))
            .values("day").annotate(count=Count("id")).order_by("day")
        )

        return Response({
            "period_days": days,
            "total_scans_in_period": completed_scans.filter(created_at__gte=since).count(),
            "average_category_scores": avg_category_scores,
            "top_performing_scans": list(top_scans),
            "worst_performing_scans": list(worst_scans),
            "most_common_issues": list(common_issues),
            "daily_scan_counts": [{"date": str(d["day"]), "count": d["count"]} for d in daily_counts],
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

        scan_id = serializer.validated_data["scan_id"]
        overrides = serializer.validated_data["overrides"]

        try:
            scan = Scan.objects.get(id=scan_id, user_id=request.user.id)
            fuzzy_result = scan.fuzzy_result
        except Scan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=404)
        except FuzzyResult.DoesNotExist:
            return Response({"error": "Scan has no fuzzy result yet"}, status=400)

        result = run_whatif_simulation(fuzzy_result.fuzzy_inputs, overrides)
        return Response(result)


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
        except Scan.DoesNotExist:
            return Response({"error": "One or both scans not found"}, status=404)

        try:
            fr_a = scan_a.fuzzy_result
            fr_b = scan_b.fuzzy_result
        except FuzzyResult.DoesNotExist:
            return Response({"error": "Both scans must be completed with fuzzy results"}, status=400)

        # Build comparison data
        comparison_data = {
            "risk_score_diff": round(fr_b.risk_score - fr_a.risk_score, 4),
            "overall_score_diff": round(fr_b.overall_score - fr_a.overall_score, 1),
            "category_diffs": {
                cat: round((fr_b.category_scores or {}).get(cat, 0) - (fr_a.category_scores or {}).get(cat, 0), 1)
                for cat in (fr_a.category_scores or {})
            },
            "risk_level_a": fr_a.risk_level,
            "risk_level_b": fr_b.risk_level,
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
# Reports (PDF + CSV)
# ---------------------------------------------------------------------------

class ReportGenerateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, scan_id):
        fmt = request.data.get("format", "pdf").lower()
        if fmt not in ("pdf", "csv"):
            return Response({"error": "format must be pdf or csv"}, status=400)

        try:
            scan = Scan.objects.prefetch_related(
                "fuzzy_result", "recommendations", "factors"
            ).get(id=scan_id, user_id=request.user.id)
        except Scan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=404)

        if scan.status != "completed":
            return Response({"error": "Scan is not completed yet"}, status=400)

        try:
            fr = scan.fuzzy_result
        except FuzzyResult.DoesNotExist:
            return Response({"error": "No fuzzy result for this scan"}, status=400)

        scan_data = {"id": str(scan.id), "target_url": scan.target_url, "status": scan.status}
        recs = list(scan.recommendations.all().values("title", "description", "severity", "remediation"))
        factors = list(scan.factors.all())
        recommendations = list(scan.recommendations.all())

        if fmt == "pdf":
            fuzzy_data = {
                "risk_score": fr.risk_score, "risk_level": fr.risk_level,
                "overall_score": fr.overall_score, "confidence": fr.confidence,
                "category_scores": fr.category_scores,
                "triggered_rules": fr.triggered_rules, "fuzzy_inputs": fr.fuzzy_inputs,
                "fuzzy_memberships": fr.fuzzy_memberships, "aggregate_output": fr.aggregate_output,
                "explainability": fr.explainability,
            }
            file_bytes = build_pdf_report(scan_data, fuzzy_data, recs)
            content_type = "application/pdf"
            ext = "pdf"
        else:
            file_bytes = build_csv_report(scan, fr, factors, recommendations)
            content_type = "text/csv"
            ext = "csv"

        storage_path = f"reports/{scan.user_id}/{scan.id}.{ext}"
        uploaded = upload_file(settings.SUPABASE_REPORTS_BUCKET, storage_path, file_bytes, content_type)

        report, _ = Report.objects.update_or_create(
            scan=scan, format=fmt,
            defaults={"storage_path": storage_path, "file_size": len(file_bytes)},
        )

        signed_url = get_signed_url(settings.SUPABASE_REPORTS_BUCKET, storage_path) if uploaded else None

        return Response({
            "report_id": str(report.id),
            "scan_id": str(scan_id),
            "format": fmt,
            "file_size": len(file_bytes),
            "storage_path": storage_path,
            "signed_url": signed_url,
            "uploaded_to_storage": uploaded,
            "generated_at": report.generated_at.isoformat(),
        }, status=201)


class ReportRetrieveView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        fmt = request.query_params.get("format", "pdf").lower()
        try:
            scan = Scan.objects.get(id=scan_id, user_id=request.user.id)
            report = scan.reports.get(format=fmt)
        except Scan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=404)
        except Report.DoesNotExist:
            return Response({"error": f"No {fmt.upper()} report. POST to /api/reports/{scan_id} first."}, status=404)

        report.download_count += 1
        report.save(update_fields=["download_count"])
        return Response(ReportSerializer(report).data)


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

class AdminUsersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.is_staff:
            return Response({"error": "Admin access required"}, status=403)
        users = UserProfile.objects.all().order_by("-created_at")
        return Response(UserProfileSerializer(users, many=True).data)

    def patch(self, request):
        if not request.user.is_staff:
            return Response({"error": "Admin access required"}, status=403)
        uid = request.data.get("supabase_uid")
        try:
            profile = UserProfile.objects.get(supabase_uid=uid)
            serializer = UserProfileSerializer(profile, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=400)
        except UserProfile.DoesNotExist:
            return Response({"error": "User not found"}, status=404)
