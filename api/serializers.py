import csv
import io
from rest_framework import serializers
from .models import (
    Scan, FuzzyResult, Factor, Recommendation, Report,
    UserProfile, UserPreferences, ScanComparison,
    FuzzyRule, ConfigUpload, AuditLog, Webhook,
)


class UserPreferencesSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserPreferences
        fields = [
            "id", "theme", "email_alerts", "alert_on_high_risk",
            "alert_on_critical", "default_scan_depth", "dashboard_layout",
            "notifications_enabled", "webhook_url", "updated_at",
        ]
        read_only_fields = ["id"]


class UserProfileSerializer(serializers.ModelSerializer):
    preferences = UserPreferencesSerializer(read_only=True)

    class Meta:
        model = UserProfile
        fields = [
            "id", "supabase_uid", "email", "full_name", "role",
            "organization", "avatar_url", "is_active", "total_scans",
            "alert_threshold", "created_at", "last_login", "preferences",
        ]
        read_only_fields = ["id", "supabase_uid", "created_at", "total_scans"]


class FactorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Factor
        fields = ["id", "name", "category", "raw_value", "score_100", "linguistic_value", "details", "weight"]


class RecommendationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Recommendation
        fields = [
            "id", "title", "description", "severity", "category",
            "remediation", "ref_links", "triggered_by_rule", "is_resolved", "created_at",
        ]


class FuzzyResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = FuzzyResult
        fields = [
            "id", "risk_score", "risk_level", "overall_score", "confidence",
            "category_scores", "triggered_rules", "fuzzy_inputs",
            "fuzzy_memberships", "aggregate_output", "explainability", "created_at",
        ]


class ScanListSerializer(serializers.ModelSerializer):
    risk_level = serializers.SerializerMethodField()
    risk_score = serializers.SerializerMethodField()
    overall_score = serializers.SerializerMethodField()
    category_scores = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = [
            "id", "target_url", "title", "status", "is_bookmarked",
            "risk_level", "risk_score", "overall_score", "category_scores",
            "created_at", "completed_at",
        ]

    def get_risk_level(self, obj):
        try:
            return obj.fuzzy_result.risk_level
        except Exception:
            return None

    def get_risk_score(self, obj):
        try:
            return obj.fuzzy_result.risk_score
        except Exception:
            return None

    def get_overall_score(self, obj):
        try:
            return obj.fuzzy_result.overall_score
        except Exception:
            return None

    def get_category_scores(self, obj):
        try:
            return obj.fuzzy_result.category_scores
        except Exception:
            return None


class ScanDetailSerializer(serializers.ModelSerializer):
    fuzzy_result = FuzzyResultSerializer(read_only=True)
    factors = FactorSerializer(many=True, read_only=True)
    recommendations = RecommendationSerializer(many=True, read_only=True)

    class Meta:
        model = Scan
        fields = [
            "id", "user_id", "target_url", "title", "status", "scan_options",
            "raw_results", "error_message", "is_bookmarked",
            "started_at", "completed_at", "created_at",
            "fuzzy_result", "factors", "recommendations",
        ]


class ScanCreateSerializer(serializers.Serializer):
    url = serializers.URLField()
    title = serializers.CharField(required=False, allow_blank=True, default="")
    environment = serializers.ChoiceField(choices=["production", "staging", "development"], required=False, default="production")
    options = serializers.DictField(required=False, default=dict)


class WhatIfSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField()
    overrides = serializers.DictField(child=serializers.FloatField(min_value=0.0, max_value=1.0))


class ReportSerializer(serializers.ModelSerializer):
    signed_url = serializers.SerializerMethodField()

    class Meta:
        model = Report
        fields = ["id", "scan_id", "format", "storage_path", "file_size", "generated_at", "download_count", "signed_url"]

    def get_signed_url(self, obj):
        from api.supabase_client import get_signed_url
        from django.conf import settings
        return get_signed_url(settings.SUPABASE_REPORTS_BUCKET, obj.storage_path)


class ScanComparisonSerializer(serializers.ModelSerializer):
    scan_a_summary = serializers.SerializerMethodField()
    scan_b_summary = serializers.SerializerMethodField()

    class Meta:
        model = ScanComparison
        fields = ["id", "scan_a_id", "scan_b_id", "scan_a_summary", "scan_b_summary", "comparison_data", "created_at"]

    def get_scan_a_summary(self, obj):
        return _scan_summary(obj.scan_a)

    def get_scan_b_summary(self, obj):
        return _scan_summary(obj.scan_b)


def _scan_summary(scan):
    try:
        fr = scan.fuzzy_result
        return {
            "id": str(scan.id),
            "target_url": scan.target_url,
            "risk_level": fr.risk_level,
            "risk_score": fr.risk_score,
            "overall_score": fr.overall_score,
            "category_scores": fr.category_scores,
            "created_at": scan.created_at.isoformat(),
        }
    except Exception:
        return {"id": str(scan.id), "target_url": scan.target_url}


def build_csv_report(scan, fuzzy_result, factors, recommendations) -> bytes:
    """Generate a CSV report as bytes."""
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["FUZZI SECURITY REPORT"])
    writer.writerow(["Scan ID", str(scan.id)])
    writer.writerow(["Target URL", scan.target_url])
    writer.writerow(["Status", scan.status])
    writer.writerow(["Risk Level", fuzzy_result.risk_level])
    writer.writerow(["Risk Score", fuzzy_result.risk_score])
    writer.writerow(["Overall Score", fuzzy_result.overall_score])
    writer.writerow(["Confidence", fuzzy_result.confidence])
    writer.writerow([])

    writer.writerow(["CATEGORY SCORES"])
    writer.writerow(["Category", "Score (0-100)"])
    for cat, score in fuzzy_result.category_scores.items():
        writer.writerow([cat.title(), score])
    writer.writerow([])

    writer.writerow(["FACTOR SCORES"])
    writer.writerow(["Factor", "Risk Value (0-1)", "Score (0-100)", "Level"])
    for f in factors:
        writer.writerow([f.name, f.raw_value, f.score_100, f.linguistic_value])
    writer.writerow([])

    writer.writerow(["RECOMMENDATIONS"])
    writer.writerow(["Severity", "Category", "Title", "Remediation"])
    for r in recommendations:
        writer.writerow([r.severity.upper(), r.category, r.title, r.remediation])

    return output.getvalue().encode("utf-8")


class FuzzyRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = FuzzyRule
        fields = [
            "id", "rule_id", "description", "antecedents", "consequent",
            "weight", "is_active", "source", "created_by", "created_at", "updated_at",
        ]
        read_only_fields = ["id", "source", "created_by", "created_at", "updated_at"]


class ConfigUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = ConfigUpload
        fields = [
            "id", "filename", "format", "parsed_config", "status",
            "error_message", "scan_id", "created_at",
        ]
        read_only_fields = ["id", "status", "error_message", "created_at"]


class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = [
            "id", "user_id", "user_email", "action", "resource_type",
            "resource_id", "details", "ip_address", "created_at",
        ]


class WebhookSerializer(serializers.ModelSerializer):
    class Meta:
        model = Webhook
        fields = [
            "id", "name", "url", "events", "secret", "is_active",
            "last_triggered_at", "failure_count", "created_at",
        ]
        read_only_fields = ["id", "last_triggered_at", "failure_count", "created_at"]
        extra_kwargs = {"secret": {"write_only": True}}
