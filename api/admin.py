from django.contrib import admin
from .models import UserProfile, Scan, FuzzyResult, Factor, Recommendation, Report


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ["email", "role", "organization", "is_active", "created_at"]
    list_filter = ["role", "is_active"]
    search_fields = ["email", "full_name", "supabase_uid"]


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ["id", "target_url", "user_id", "status", "created_at"]
    list_filter = ["status"]
    search_fields = ["target_url", "user_id"]
    readonly_fields = ["id", "created_at", "updated_at"]


@admin.register(FuzzyResult)
class FuzzyResultAdmin(admin.ModelAdmin):
    list_display = ["scan", "risk_level", "risk_score", "confidence", "created_at"]
    list_filter = ["risk_level"]


@admin.register(Factor)
class FactorAdmin(admin.ModelAdmin):
    list_display = ["name", "category", "raw_value", "linguistic_value", "scan"]
    list_filter = ["category", "linguistic_value"]


@admin.register(Recommendation)
class RecommendationAdmin(admin.ModelAdmin):
    list_display = ["title", "severity", "category", "is_resolved", "scan"]
    list_filter = ["severity", "category", "is_resolved"]
    search_fields = ["title", "description"]


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ["scan", "file_size", "generated_at", "download_count"]
