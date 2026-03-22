from django.urls import path
from . import views

urlpatterns = [
    # Auth
    path("signup", views.SignupView.as_view(), name="signup"),
    path("login", views.LoginView.as_view(), name="login"),
    path("logout", views.LogoutView.as_view(), name="logout"),
    path("password/change", views.PasswordChangeView.as_view(), name="password-change"),

    # Profile & Preferences
    path("me", views.MeView.as_view(), name="me"),
    path("profile", views.MeView.as_view(), name="profile"),          # PUT /profile alias
    path("preferences", views.PreferencesView.as_view(), name="preferences"),

    # Scans
    path("scan", views.ScanCreateView.as_view(), name="scan-create"),
    path("scan/<uuid:scan_id>", views.ScanDetailView.as_view(), name="scan-detail"),
    path("scans", views.ScanListView.as_view(), name="scan-list"),

    # Dashboard
    path("dashboard/summary", views.DashboardSummaryView.as_view(), name="dashboard-summary"),
    path("dashboard/history", views.DashboardHistoryView.as_view(), name="dashboard-history"),
    path("dashboard/recommendations/<uuid:scan_id>", views.DashboardRecommendationsView.as_view(), name="dashboard-recommendations"),

    # Analytics
    path("analytics", views.AnalyticsView.as_view(), name="analytics"),

    # What-if simulation
    path("whatif", views.WhatIfView.as_view(), name="whatif"),

    # Comparison
    path("compare", views.ScanCompareView.as_view(), name="scan-compare"),

    # Reports (PDF + CSV)
    path("reports/<uuid:scan_id>", views.ReportGenerateView.as_view(), name="report-generate"),
    path("report/<uuid:scan_id>/download", views.ReportRetrieveView.as_view(), name="report-retrieve"),

    # Admin
    path("admin/users", views.AdminUsersView.as_view(), name="admin-users"),
]
