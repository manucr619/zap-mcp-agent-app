from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
import uuid


class SecurityScan(models.Model):
    """Model for tracking security scans"""

    SCAN_TYPES = [
        ('api', 'API Security Scan'),
        ('full', 'Full Application Scan'),
        ('quick', 'Quick Vulnerability Scan'),
    ]

    SCAN_STATUSES = [
        ('queued', 'Queued'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]

    RISK_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    # Primary fields
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_id = models.CharField(max_length=100, unique=True, db_index=True)
    target_url = models.URLField(max_length=500)

    # Scan configuration
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES, default='api')
    scan_policy = models.CharField(max_length=100, default='default')

    # Authentication details (encrypted in production)
    auth_username = models.CharField(max_length=255, blank=True, null=True)
    auth_password = models.CharField(max_length=255, blank=True, null=True)
    auth_token = models.TextField(blank=True, null=True)

    # Status and timing
    status = models.CharField(max_length=20, choices=SCAN_STATUSES, default='queued')
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Results summary
    vulnerabilities_found = models.PositiveIntegerField(default=0)
    critical_count = models.PositiveIntegerField(default=0)
    high_count = models.PositiveIntegerField(default=0)
    medium_count = models.PositiveIntegerField(default=0)
    low_count = models.PositiveIntegerField(default=0)

    # Overall risk assessment
    overall_risk = models.CharField(max_length=20, choices=RISK_LEVELS, default='low')
    risk_score = models.DecimalField(max_digits=5, decimal_places=2, default=0.00,
                                   validators=[MinValueValidator(0), MaxValueValidator(100)])

    # Scan metadata
    scan_duration = models.DurationField(null=True, blank=True)
    zap_scan_id = models.CharField(max_length=100, blank=True, null=True)
    mcp_session_id = models.CharField(max_length=100, blank=True, null=True)

    # User and ownership
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scans')
    is_active = models.BooleanField(default=True)

    # Additional settings
    max_scan_time = models.PositiveIntegerField(default=3600, help_text='Max scan time in seconds')
    follow_redirects = models.BooleanField(default=True)
    scan_subdomains = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['created_by', 'created_at']),
            models.Index(fields=['scan_type', 'status']),
        ]

    def __str__(self):
        return f"Scan {self.scan_id} - {self.target_url}"

    def save(self, *args, **kwargs):
        """Override save to update timestamps and calculate risk score"""
        if self.status == 'running' and not self.started_at:
            self.started_at = timezone.now()
        elif self.status in ['completed', 'failed', 'cancelled'] and not self.completed_at:
            self.completed_at = timezone.now()
            if self.started_at:
                self.scan_duration = self.completed_at - self.started_at

        # Calculate overall risk based on vulnerability counts
        if self.critical_count > 0:
            self.overall_risk = 'critical'
            self.risk_score = min(95 + self.critical_count, 100)
        elif self.high_count > 5:
            self.overall_risk = 'high'
            self.risk_score = min(70 + self.high_count, 94)
        elif self.medium_count > 10:
            self.overall_risk = 'medium'
            self.risk_score = min(40 + self.medium_count, 69)
        else:
            self.overall_risk = 'low'
            self.risk_score = min(self.low_count + self.medium_count, 39)

        super().save(*args, **kwargs)

    @property
    def is_completed(self):
        """Check if scan is completed"""
        return self.status in ['completed', 'failed', 'cancelled']

    @property
    def duration_seconds(self):
        """Get scan duration in seconds"""
        if self.scan_duration:
            return int(self.scan_duration.total_seconds())
        return 0


class Vulnerability(models.Model):
    """Model for individual vulnerabilities found during scans"""

    RISK_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    CONFIDENCE_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('confirmed', 'Confirmed'),
    ]

    VULN_TYPES = [
        ('injection', 'Injection'),
        ('broken_auth', 'Broken Authentication'),
        ('sensitive_data', 'Sensitive Data Exposure'),
        ('xml_external', 'XML External Entities'),
        ('broken_access', 'Broken Access Control'),
        ('misconfiguration', 'Security Misconfiguration'),
        ('xss', 'Cross-Site Scripting'),
        ('insecure_deserialization', 'Insecure Deserialization'),
        ('vulnerable_components', 'Vulnerable Components'),
        ('insufficient_logging', 'Insufficient Logging'),
    ]

    # Primary fields
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(SecurityScan, on_delete=models.CASCADE, related_name='vulnerabilities')

    # Vulnerability details
    vuln_id = models.CharField(max_length=100, db_index=True)  # ZAP plugin ID or CVE
    name = models.CharField(max_length=500)
    description = models.TextField()
    solution = models.TextField(blank=True, null=True)

    # Risk assessment
    risk_level = models.CharField(max_length=20, choices=RISK_LEVELS)
    confidence = models.CharField(max_length=20, choices=CONFIDENCE_LEVELS, default='medium')
    vuln_type = models.CharField(max_length=50, choices=VULN_TYPES, blank=True, null=True)

    # Location details
    url = models.URLField(max_length=1000)
    method = models.CharField(max_length=10, default='GET')
    param = models.CharField(max_length=255, blank=True, null=True)
    evidence = models.TextField(blank=True, null=True)

    # References and metadata
    cwe_id = models.CharField(max_length=100, blank=True, null=True)
    cve_id = models.CharField(max_length=100, blank=True, null=True)
    owasp_category = models.CharField(max_length=100, blank=True, null=True)
    reference = models.TextField(blank=True, null=True)

    # AI analysis (populated by MCP server)
    ai_analysis = models.JSONField(blank=True, null=True)
    exploitability_score = models.DecimalField(max_digits=3, decimal_places=2, default=0.00)
    remediation_priority = models.PositiveIntegerField(default=1,
                                                     validators=[MinValueValidator(1), MaxValueValidator(5)])

    # Timestamps
    discovered_at = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    # Status tracking
    is_false_positive = models.BooleanField(default=False)
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                   related_name='resolved_vulnerabilities')

    class Meta:
        ordering = ['-remediation_priority', 'risk_level', '-discovered_at']
        indexes = [
            models.Index(fields=['scan', 'risk_level']),
            models.Index(fields=['vuln_type', 'risk_level']),
            models.Index(fields=['is_resolved', 'is_false_positive']),
            models.Index(fields=['cve_id']),
            models.Index(fields=['remediation_priority']),
        ]
        unique_together = ['scan', 'vuln_id']

    def __str__(self):
        return f"{self.name} ({self.risk_level}) - {self.url}"

    @property
    def severity_score(self):
        """Calculate severity score based on risk and confidence"""
        risk_scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        confidence_scores = {'low': 0.5, 'medium': 0.75, 'high': 1.0, 'confirmed': 1.25}

        base_score = risk_scores.get(self.risk_level, 1)
        confidence_multiplier = confidence_scores.get(self.confidence, 0.75)

        return round(base_score * confidence_multiplier, 2)


class ComplianceReport(models.Model):
    """Model for OWASP API compliance reports"""

    REPORT_TYPES = [
        ('api_top_10', 'OWASP API Top 10'),
        ('full_compliance', 'Full Compliance Report'),
        ('delta_report', 'Delta Compliance Report'),
    ]

    COMPLIANCE_LEVELS = [
        ('non_compliant', 'Non Compliant'),
        ('partial', 'Partially Compliant'),
        ('compliant', 'Compliant'),
        ('exemplary', 'Exemplary'),
    ]

    # Primary fields
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.OneToOneField(SecurityScan, on_delete=models.CASCADE, related_name='compliance_report')

    # Report details
    report_type = models.CharField(max_length=50, choices=REPORT_TYPES, default='api_top_10')
    compliance_level = models.CharField(max_length=20, choices=COMPLIANCE_LEVELS, default='non_compliant')
    compliance_score = models.DecimalField(max_digits=5, decimal_places=2, default=0.00,
                                         validators=[MinValueValidator(0), MaxValueValidator(100)])

    # OWASP API Top 10 Categories
    api1_broken_object_level_authorization = models.JSONField(blank=True, null=True)
    api2_broken_authentication = models.JSONField(blank=True, null=True)
    api3_broken_object_property_level_authorization = models.JSONField(blank=True, null=True)
    api4_unrestricted_resource_consumption = models.JSONField(blank=True, null=True)
    api5_broken_function_level_authorization = models.JSONField(blank=True, null=True)
    api6_unrestricted_access_to_sensitive_business_flows = models.JSONField(blank=True, null=True)
    api7_server_side_request_forgery = models.JSONField(blank=True, null=True)
    api8_security_misconfiguration = models.JSONField(blank=True, null=True)
    api9_improper_inventory_management = models.JSONField(blank=True, null=True)
    api10_unsafe_consumption_of_apis = models.JSONField(blank=True, null=True)

    # Summary metrics
    total_categories = models.PositiveIntegerField(default=10)
    compliant_categories = models.PositiveIntegerField(default=0)
    partial_categories = models.PositiveIntegerField(default=0)
    non_compliant_categories = models.PositiveIntegerField(default=0)

    # AI-generated insights
    ai_insights = models.JSONField(blank=True, null=True)
    recommended_actions = models.JSONField(blank=True, null=True)

    # Report metadata
    generated_at = models.DateTimeField(auto_now_add=True)
    generated_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='compliance_reports')

    # Additional details
    report_data = models.JSONField(blank=True, null=True)  # Full report data
    report_format = models.CharField(max_length=20, default='json', choices=[
        ('json', 'JSON'),
        ('html', 'HTML'),
        ('pdf', 'PDF'),
    ])

    class Meta:
        ordering = ['-generated_at']
        indexes = [
            models.Index(fields=['scan', 'compliance_level']),
            models.Index(fields=['generated_by', 'generated_at']),
            models.Index(fields=['report_type', 'compliance_score']),
        ]

    def __str__(self):
        return f"Compliance Report for {self.scan.scan_id} - {self.compliance_level}"

    def save(self, *args, **kwargs):
        """Override save to calculate compliance metrics"""
        self._calculate_compliance_metrics()
        super().save(*args, **kwargs)

    def _calculate_compliance_metrics(self):
        """Calculate compliance score and category counts"""
        categories = [
            self.api1_broken_object_level_authorization,
            self.api2_broken_authentication,
            self.api3_broken_object_property_level_authorization,
            self.api4_unrestricted_resource_consumption,
            self.api5_broken_function_level_authorization,
            self.api6_unrestricted_access_to_sensitive_business_flows,
            self.api7_server_side_request_forgery,
            self.api8_security_misconfiguration,
            self.api9_improper_inventory_management,
            self.api10_unsafe_consumption_of_apis,
        ]

        compliant = partial = non_compliant = 0

        for category in categories:
            if category:
                status = category.get('status', 'non_compliant')
                if status == 'compliant':
                    compliant += 1
                elif status == 'partial':
                    partial += 1
                else:
                    non_compliant += 1

        self.compliant_categories = compliant
        self.partial_categories = partial
        self.non_compliant_categories = non_compliant

        # Calculate compliance score
        total_score = (compliant * 100 + partial * 50 + non_compliant * 0) / self.total_categories
        self.compliance_score = round(total_score, 2)

        # Determine compliance level
        if self.compliance_score >= 90:
            self.compliance_level = 'exemplary'
        elif self.compliance_score >= 75:
            self.compliance_level = 'compliant'
        elif self.compliance_score >= 50:
            self.compliance_level = 'partial'
        else:
            self.compliance_level = 'non_compliant'

    @property
    def compliance_percentage(self):
        """Get compliance percentage"""
        return f"{self.compliance_score}%"

    def get_category_status(self, category_number):
        """Get status of specific OWASP category"""
        category_map = {
            1: self.api1_broken_object_level_authorization,
            2: self.api2_broken_authentication,
            3: self.api3_broken_object_property_level_authorization,
            4: self.api4_unrestricted_resource_consumption,
            5: self.api5_broken_function_level_authorization,
            6: self.api6_unrestricted_access_to_sensitive_business_flows,
            7: self.api7_server_side_request_forgery,
            8: self.api8_security_misconfiguration,
            9: self.api9_improper_inventory_management,
            10: self.api10_unsafe_consumption_of_apis,
        }

        category_data = category_map.get(category_number)
        return category_data.get('status', 'unknown') if category_data else 'not_assessed'
