import uuid
from django.db import models


class UserProfile(models.Model):
    """Extended profile stored in our DB, keyed by Supabase user UUID."""

    ROLE_CHOICES = [('admin', 'Admin'), ('analyst', 'Analyst'), ('viewer', 'Viewer')]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    supabase_uid = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255, blank=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='analyst')
    organization = models.CharField(max_length=255, blank=True)
    avatar_url = models.URLField(blank=True)
    is_active = models.BooleanField(default=True)
    total_scans = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'user_profiles'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.email} ({self.role})'


class UserPreferences(models.Model):
    """Per-user dashboard and notification preferences."""

    THEME_CHOICES = [('light', 'Light'), ('dark', 'Dark'), ('system', 'System')]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(UserProfile, on_delete=models.CASCADE, related_name='preferences')
    theme = models.CharField(max_length=10, choices=THEME_CHOICES, default='system')
    email_alerts = models.BooleanField(default=True)
    alert_on_high_risk = models.BooleanField(default=True)
    alert_on_critical = models.BooleanField(default=True)
    default_scan_depth = models.CharField(max_length=20, default='standard')
    dashboard_layout = models.JSONField(default=dict, blank=True)
    notifications_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_preferences'

    def __str__(self):
        return f'Preferences for {self.user.email}'


class Scan(models.Model):
    """Represents a single web security scan job."""

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.CharField(max_length=255, db_index=True)
    target_url = models.URLField(max_length=2048)
    title = models.CharField(max_length=255, blank=True)  # optional user-given label
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    scan_options = models.JSONField(default=dict, blank=True)
    raw_results = models.JSONField(default=dict, blank=True)
    html_content = models.TextField(blank=True)   # stored extracted text for analysis
    error_message = models.TextField(blank=True)
    is_bookmarked = models.BooleanField(default=False)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'scans'
        ordering = ['-created_at']

    def __str__(self):
        return f'Scan {self.id} → {self.target_url} [{self.status}]'


class FuzzyResult(models.Model):
    """Fuzzy logic assessment output for a scan."""

    RISK_LEVELS = [
        ('LOW', 'Low'), ('MEDIUM', 'Medium'), ('HIGH', 'High'), ('CRITICAL', 'Critical'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.OneToOneField(Scan, on_delete=models.CASCADE, related_name='fuzzy_result')
    risk_score = models.FloatField()           # 0.0 – 1.0
    risk_level = models.CharField(max_length=10, choices=RISK_LEVELS)
    overall_score = models.FloatField(default=50.0)   # 0-100, higher = safer
    confidence = models.FloatField(default=0.0)
    category_scores = models.JSONField(default=dict)  # {security: 72, seo: 85, ...}
    triggered_rules = models.JSONField(default=list)
    fuzzy_inputs = models.JSONField(default=dict)
    fuzzy_memberships = models.JSONField(default=dict)
    aggregate_output = models.JSONField(default=dict)
    explainability = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'fuzzy_results'

    def __str__(self):
        return f'FuzzyResult scan={self.scan_id} score={self.risk_score:.2f} [{self.risk_level}]'


class Factor(models.Model):
    """Individual security/quality factor measured during a scan."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='factors')
    name = models.CharField(max_length=100)
    category = models.CharField(max_length=100)
    raw_value = models.FloatField()           # 0.0 – 1.0 risk score
    score_100 = models.FloatField(default=50.0)  # 0-100 quality score
    linguistic_value = models.CharField(max_length=20)
    details = models.JSONField(default=dict)
    weight = models.FloatField(default=1.0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'factors'
        ordering = ['category', 'name']

    def __str__(self):
        return f'{self.name}: {self.linguistic_value} ({self.raw_value:.2f})'


class Recommendation(models.Model):
    """Actionable recommendation generated for a scan."""

    SEVERITY_CHOICES = [
        ('info', 'Info'), ('low', 'Low'), ('medium', 'Medium'),
        ('high', 'High'), ('critical', 'Critical'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='recommendations')
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    category = models.CharField(max_length=100)
    remediation = models.TextField()
    ref_links = models.JSONField(default=list, db_column='ref_links')
    triggered_by_rule = models.CharField(max_length=255, blank=True)
    is_resolved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'recommendations'
        ordering = ['-severity', 'category']

    def __str__(self):
        return f'[{self.severity.upper()}] {self.title}'


class Report(models.Model):
    """PDF/CSV report artifact for a scan."""

    FORMAT_CHOICES = [('pdf', 'PDF'), ('csv', 'CSV')]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='reports')
    format = models.CharField(max_length=5, choices=FORMAT_CHOICES, default='pdf')
    storage_path = models.CharField(max_length=512)
    file_size = models.IntegerField(default=0)
    generated_at = models.DateTimeField(auto_now_add=True)
    download_count = models.IntegerField(default=0)

    class Meta:
        db_table = 'reports'
        unique_together = [('scan', 'format')]

    def __str__(self):
        return f'Report [{self.format.upper()}] for scan {self.scan_id}'


class ScanComparison(models.Model):
    """Stores a side-by-side comparison of two scans."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.CharField(max_length=255, db_index=True)
    scan_a = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='comparisons_as_a')
    scan_b = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='comparisons_as_b')
    comparison_data = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'scan_comparisons'
        ordering = ['-created_at']

    def __str__(self):
        return f'Compare {self.scan_a_id} vs {self.scan_b_id}'
