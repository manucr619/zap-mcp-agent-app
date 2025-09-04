from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import SecurityScan, Vulnerability, ComplianceReport


@admin.register(SecurityScan)
class SecurityScanAdmin(admin.ModelAdmin):
    """Admin interface for SecurityScan model"""

    list_display = [
        'scan_id', 'target_url', 'status', 'scan_type',
        'overall_risk', 'risk_score', 'vulnerabilities_found',
        'created_at', 'duration_seconds'
    ]
    list_filter = [
        'status', 'scan_type', 'overall_risk', 'created_by',
        'created_at', 'scan_policy'
    ]
    search_fields = ['scan_id', 'target_url', 'created_by__username']
    readonly_fields = [
        'id', 'scan_id', 'created_at', 'started_at',
        'completed_at', 'scan_duration', 'duration_seconds'
    ]
    ordering = ['-created_at']

    fieldsets = (
        ('Basic Information', {
            'fields': ('scan_id', 'target_url', 'scan_type', 'scan_policy')
        }),
        ('Authentication', {
            'fields': ('auth_username', 'auth_password', 'auth_token'),
            'classes': ('collapse',)
        }),
        ('Status & Timing', {
            'fields': ('status', 'created_at', 'started_at', 'completed_at', 'scan_duration')
        }),
        ('Results Summary', {
            'fields': ('vulnerabilities_found', 'critical_count', 'high_count',
                      'medium_count', 'low_count', 'overall_risk', 'risk_score')
        }),
        ('Configuration', {
            'fields': ('max_scan_time', 'follow_redirects', 'scan_subdomains'),
            'classes': ('collapse',)
        }),
        ('External IDs', {
            'fields': ('zap_scan_id', 'mcp_session_id'),
            'classes': ('collapse',)
        }),
        ('Ownership', {
            'fields': ('created_by', 'is_active')
        })
    )

    def get_queryset(self, request):
        """Filter scans based on user permissions"""
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        return qs.filter(created_by=request.user)

    def duration_seconds(self, obj):
        """Display scan duration in seconds"""
        return obj.duration_seconds
    duration_seconds.short_description = 'Duration (seconds)'


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    """Admin interface for Vulnerability model"""

    list_display = [
        'id', 'name', 'risk_level', 'confidence', 'scan_target_url',
        'discovered_at', 'is_resolved', 'is_false_positive'
    ]
    list_filter = [
        'risk_level', 'confidence', 'vuln_type', 'is_resolved',
        'is_false_positive', 'discovered_at'
    ]
    search_fields = ['name', 'description', 'url', 'cve_id', 'cwe_id']
    readonly_fields = [
        'id', 'discovered_at', 'last_updated', 'severity_score'
    ]
    ordering = ['-discovered_at']

    fieldsets = (
        ('Basic Information', {
            'fields': ('scan', 'vuln_id', 'name', 'description', 'solution')
        }),
        ('Risk Assessment', {
            'fields': ('risk_level', 'confidence', 'vuln_type', 'severity_score')
        }),
        ('Location', {
            'fields': ('url', 'method', 'param', 'evidence')
        }),
        ('References', {
            'fields': ('cwe_id', 'cve_id', 'owasp_category', 'reference')
        }),
        ('AI Analysis', {
            'fields': ('ai_analysis', 'exploitability_score', 'remediation_priority'),
            'classes': ('collapse',)
        }),
        ('Status', {
            'fields': ('is_false_positive', 'is_resolved', 'resolved_at', 'resolved_by')
        })
    )

    actions = ['mark_as_resolved', 'mark_as_false_positive', 'reset_status']

    def scan_target_url(self, obj):
        """Display the target URL from the associated scan"""
        return obj.scan.target_url
    scan_target_url.short_description = 'Target URL'

    def mark_as_resolved(self, request, queryset):
        """Mark selected vulnerabilities as resolved"""
        updated = queryset.update(is_resolved=True, resolved_at=timezone.now())
        self.message_user(request, f'{updated} vulnerabilities marked as resolved.')
    mark_as_resolved.short_description = 'Mark as resolved'

    def mark_as_false_positive(self, request, queryset):
        """Mark selected vulnerabilities as false positives"""
        updated = queryset.update(is_false_positive=True)
        self.message_user(request, f'{updated} vulnerabilities marked as false positives.')
    mark_as_false_positive.short_description = 'Mark as false positive'

    def reset_status(self, request, queryset):
        """Reset vulnerability status"""
        updated = queryset.update(
            is_resolved=False,
            is_false_positive=False,
            resolved_at=None,
            resolved_by=None
        )
        self.message_user(request, f'{updated} vulnerabilities reset.')
    reset_status.short_description = 'Reset status'

    def get_queryset(self, request):
        """Filter vulnerabilities based on user permissions"""
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        return qs.filter(scan__created_by=request.user)


@admin.register(ComplianceReport)
class ComplianceReportAdmin(admin.ModelAdmin):
    """Admin interface for ComplianceReport model"""

    list_display = [
        'scan_scan_id', 'compliance_level', 'compliance_score',
        'generated_at', 'generated_by_username', 'report_type'
    ]
    list_filter = [
        'compliance_level', 'report_type', 'generated_at'
    ]
    search_fields = ['scan__scan_id', 'generated_by__username']
    readonly_fields = [
        'id', 'generated_at', 'compliance_score', 'compliance_percentage'
    ]
    ordering = ['-generated_at']

    fieldsets = (
        ('Report Information', {
            'fields': ('scan', 'report_type', 'generated_by')
        }),
        ('Compliance Results', {
            'fields': ('compliance_level', 'compliance_score', 'compliance_percentage')
        }),
        ('Category Breakdown', {
            'fields': (
                'total_categories', 'compliant_categories',
                'partial_categories', 'non_compliant_categories'
            )
        }),
        ('OWASP Categories', {
            'fields': (
                'api1_broken_object_level_authorization',
                'api2_broken_authentication',
                'api3_broken_object_property_level_authorization',
                'api4_unrestricted_resource_consumption',
                'api5_broken_function_level_authorization',
                'api6_unrestricted_access_to_sensitive_business_flows',
                'api7_server_side_request_forgery',
                'api8_security_misconfiguration',
                'api9_improper_inventory_management',
                'api10_unsafe_consumption_of_apis'
            ),
            'classes': ('collapse',)
        }),
        ('AI Insights', {
            'fields': ('ai_insights', 'recommended_actions'),
            'classes': ('collapse',)
        })
    )

    def scan_scan_id(self, obj):
        """Display the scan ID"""
        return obj.scan.scan_id
    scan_scan_id.short_description = 'Scan ID'

    def generated_by_username(self, obj):
        """Display the username of who generated the report"""
        return obj.generated_by.username
    generated_by_username.short_description = 'Generated By'

    def compliance_percentage(self, obj):
        """Display compliance as percentage"""
        return f"{obj.compliance_score}%"
    compliance_percentage.short_description = 'Compliance %'

    def get_queryset(self, request):
        """Filter reports based on user permissions"""
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        return qs.filter(generated_by=request.user)
