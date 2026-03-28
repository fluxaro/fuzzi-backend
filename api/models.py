import uuid
from django.db import models


class UserProfile(models.Model):
    ROLE_CHOICES = [('admin', 'Admin'), ('analyst', 'Analyst'), ('developer', 'Developer'), ('viewer', 'Viewer')]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    supabase_uid = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255, blank=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='analyst')
    organization = models.CharField(max_length=255, blank=True)
    avatar_url = models.URLField(blank=True)
    is_active = models.BooleanField(default=True)
    total_scans = models.IntegerField(default=0)
    alert_threshold = models.FloatField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'user_profiles'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.email} ({self.role})'


class UserPreferences(models.Model):
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
    webhook_url = models.URLField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_preferences'

    def __str__(self):
        return f'Preferences for {self.user.email}'


class FuzzyRule(models.Model):
    CONSEQUENT_CHOICES = [('LOW', 'Low'), ('MEDIUM', 'Medium'), ('HIGH', 'High'), ('CRITICAL', 'Critical')]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    rule_id = models.CharField(max_length=20, unique=True)
    description = models.CharField(max_length=500)
    antecedents = models.JSONField()
    consequent = models.CharField(max_length=10, choices=CONSEQUENT_CHOICES)
    weight = models.FloatField(default=1.0)
    is_active = models.BooleanField(default=True)
    source = models.CharField(max_length=100, default='predefined')
    created_by = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'fuzzy_rules'
        ordering = ['rule_id']

    def __str__(self):
        return f'{self.rule_id}: {self.description[:60]}'


class ConfigUpload(models.Model):
    FORMAT_CHOICES = [('json', 'JSON'), ('yaml', 'YAML'), ('csv', 'CSV')]
    STATUS_CHOICES = [('pending', 'Pending'), ('parsed', 'Parsed'), ('failed', 'Failed')]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.CharField(max_length=255, db_index=True)
    filename = models.CharField(max_length=255)
    format = models.CharField(max_length=10, choices=FORMAT_CHOICES)
    storage_path = models.CharField(max_length=512, blank=True)
    parsed_config = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    error_message = models.TextField(blank=True)
    scan = models.ForeignKey('Scan', null=True, blank=True, on_delete=models.SET_NULL, related_name='config_uploads')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'config_uploads'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.filename} [{self.format}] ({self.status})'


class Scan(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'), ('running', 'Running'),
        ('completed', 'Completed'), ('failed', 'Failed'),
    ]
    ENV_CHOICES = [('production', 'Production'), ('staging', 'Staging'), ('development', 'Development')]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.CharField(max_length=255, db_index=True)
    target_url = models.URLField(max_length=2048)
    title = models.CharField(max_length=255, blank=True)
    environment = models.CharField(max_length=20, choices=ENV_CHOICES, default='production')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    scan_options = models.JSONField(default=dict, blank=True)
    raw_results = models.JSONField(default=dict, blank=True)
    html_content = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    is_bookmarked = models.BooleanField(default=False)
    previous_scan = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL, related_name='next_scans')
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
    RISK_LEVELS = [('LOW', 'Low'), ('MEDIUM', 'Medium'), ('HIGH', 'High'), ('CRITICAL', 'Critical')]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.OneToOneField(Scan, on_delete=models.CASCADE, related_name='fuzzy_result')
    risk_score = models.FloatField()
    risk_level = models.CharField(max_length=10, choices=RISK_LEVELS)
    overall_score = models.FloatField(default=50.0)
    confidence = models.FloatField(default=0.0)
    category_scores = models.JSONField(default=dict)
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
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='factors')
    name = models.CharField(max_length=100)
    category = models.CharField(max_length=100)
    raw_value = models.FloatField()
    score_100 = models.FloatField(default=50.0)
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
    FORMAT_CHOICES = [('pdf', 'PDF'), ('csv', 'CSV'), ('json', 'JSON')]

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


class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.CharField(max_length=255, db_index=True)
    user_email = models.EmailField(blank=True)
    action = models.CharField(max_length=100)
    resource_type = models.CharField(max_length=50, blank=True)
    resource_id = models.CharField(max_length=255, blank=True)
    details = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'audit_logs'
        ordering = ['-created_at']

    def __str__(self):
        return f'[{self.action}] {self.user_email} @ {self.created_at}'


class Webhook(models.Model):
    EVENT_CHOICES = [
        ('scan.completed', 'Scan Completed'),
        ('scan.failed', 'Scan Failed'),
        ('risk.high', 'High Risk Detected'),
        ('risk.critical', 'Critical Risk Detected'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.CharField(max_length=255, db_index=True)
    name = models.CharField(max_length=100)
    url = models.URLField()
    events = models.JSONField(default=list)
    secret = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    last_triggered_at = models.DateTimeField(null=True, blank=True)
    failure_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'webhooks'
        ordering = ['-created_at']

    def __str__(self):
        return f'Webhook {self.name} → {self.url}'
