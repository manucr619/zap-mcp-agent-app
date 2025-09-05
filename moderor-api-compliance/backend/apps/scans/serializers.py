from rest_framework import serializers
from django.utils import timezone
from .models import SecurityScan, Vulnerability, ComplianceReport


class VulnerabilitySerializer(serializers.ModelSerializer):
    """Serializer for Vulnerability model"""

    severity_score = serializers.ReadOnlyField()
    discovered_days_ago = serializers.SerializerMethodField()
    scan_target_url = serializers.CharField(source='scan.target_url', read_only=True)

    class Meta:
        model = Vulnerability
        fields = [
            'id', 'vuln_id', 'name', 'description', 'solution',
            'risk_level', 'confidence', 'vuln_type', 'url', 'method',
            'param', 'evidence', 'cwe_id', 'cve_id', 'owasp_category',
            'reference', 'ai_analysis', 'exploitability_score',
            'remediation_priority', 'discovered_at', 'severity_score',
            'discovered_days_ago', 'scan_target_url', 'is_false_positive',
            'is_resolved', 'resolved_at'
        ]
        read_only_fields = ['id', 'discovered_at', 'severity_score', 'discovered_days_ago']

    def get_discovered_days_ago(self, obj):
        """Calculate days since vulnerability was discovered"""
        if obj.discovered_at:
            delta = timezone.now() - obj.discovered_at
            return delta.days
        return 0


class SecurityScanSerializer(serializers.ModelSerializer):
    """Serializer for SecurityScan model"""

    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    duration_seconds = serializers.ReadOnlyField()
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    compliance_report = serializers.SerializerMethodField()

    class Meta:
        model = SecurityScan
        fields = [
            'id', 'scan_id', 'target_url', 'scan_type', 'scan_policy',
            'status', 'created_at', 'started_at', 'completed_at',
            'vulnerabilities_found', 'critical_count', 'high_count',
            'medium_count', 'low_count', 'overall_risk', 'risk_score',
            'scan_duration', 'duration_seconds', 'zap_scan_id',
            'mcp_session_id', 'created_by_username', 'is_active',
            'max_scan_time', 'follow_redirects', 'scan_subdomains',
            'vulnerabilities', 'compliance_report'
        ]
        read_only_fields = [
            'id', 'scan_id', 'created_at', 'started_at', 'completed_at',
            'duration_seconds', 'created_by_username', 'vulnerabilities'
        ]

    def get_compliance_report(self, obj):
        """Get compliance report if it exists"""
        try:
            report = obj.compliance_report
            return ComplianceReportSerializer(report).data
        except ComplianceReport.DoesNotExist:
            return None

    def create(self, validated_data):
        """Create a new scan with the current user"""
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)


class SecurityScanCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new security scans"""

    class Meta:
        model = SecurityScan
        fields = [
            'target_url', 'scan_type', 'scan_policy',
            'auth_username', 'auth_password', 'auth_token',
            'max_scan_time', 'follow_redirects', 'scan_subdomains'
        ]

    def validate_target_url(self, value):
        """Validate target URL"""
        if not value.startswith(('http://', 'https://')):
            raise serializers.ValidationError("URL must start with http:// or https://")
        return value

    def validate_max_scan_time(self, value):
        """Validate max scan time"""
        if value < 60:
            raise serializers.ValidationError("Minimum scan time is 60 seconds")
        if value > 36000:  # 10 hours
            raise serializers.ValidationError("Maximum scan time is 36000 seconds (10 hours)")
        return value


class SecurityScanListSerializer(serializers.ModelSerializer):
    """Serializer for listing security scans"""

    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    duration_seconds = serializers.ReadOnlyField()

    class Meta:
        model = SecurityScan
        fields = [
            'id', 'scan_id', 'target_url', 'scan_type', 'status',
            'created_at', 'completed_at', 'vulnerabilities_found',
            'overall_risk', 'risk_score', 'duration_seconds',
            'created_by_username'
        ]


class ComplianceReportSerializer(serializers.ModelSerializer):
    """Serializer for ComplianceReport model"""

    generated_by_username = serializers.CharField(source='generated_by.username', read_only=True)
    compliance_percentage = serializers.ReadOnlyField()
    scan_details = serializers.SerializerMethodField()

    class Meta:
        model = ComplianceReport
        fields = [
            'id', 'report_type', 'compliance_level', 'compliance_score',
            'compliance_percentage', 'total_categories', 'compliant_categories',
            'partial_categories', 'non_compliant_categories', 'generated_at',
            'generated_by_username', 'report_format', 'ai_insights',
            'recommended_actions', 'scan_details'
        ]
        read_only_fields = ['id', 'generated_at', 'compliance_percentage']

    def get_scan_details(self, obj):
        """Get basic scan information"""
        scan = obj.scan
        return {
            'scan_id': scan.scan_id,
            'target_url': scan.target_url,
            'scan_type': scan.scan_type,
            'completed_at': scan.completed_at,
            'overall_risk': scan.overall_risk,
            'risk_score': scan.risk_score
        }


class ComplianceReportCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating compliance reports"""

    class Meta:
        model = ComplianceReport
        fields = [
            'report_type', 'report_format', 'ai_insights', 'recommended_actions'
        ]


class OWASPComplianceSerializer(serializers.Serializer):
    """Serializer for OWASP compliance data"""

    api1_broken_object_level_authorization = serializers.DictField()
    api2_broken_authentication = serializers.DictField()
    api3_broken_object_property_level_authorization = serializers.DictField()
    api4_unrestricted_resource_consumption = serializers.DictField()
    api5_broken_function_level_authorization = serializers.DictField()
    api6_unrestricted_access_to_sensitive_business_flows = serializers.DictField()
    api7_server_side_request_forgery = serializers.DictField()
    api8_security_misconfiguration = serializers.DictField()
    api9_improper_inventory_management = serializers.DictField()
    api10_unsafe_consumption_of_apis = serializers.DictField()


class ScanStatisticsSerializer(serializers.Serializer):
    """Serializer for scan statistics"""

    total_scans = serializers.IntegerField()
    completed_scans = serializers.IntegerField()
    failed_scans = serializers.IntegerField()
    running_scans = serializers.IntegerField()
    queued_scans = serializers.IntegerField()

    total_vulnerabilities = serializers.IntegerField()
    critical_vulnerabilities = serializers.IntegerField()
    high_vulnerabilities = serializers.IntegerField()
    medium_vulnerabilities = serializers.IntegerField()
    low_vulnerabilities = serializers.IntegerField()

    average_risk_score = serializers.DecimalField(max_digits=5, decimal_places=2)
    average_scan_duration = serializers.IntegerField()

    scans_by_type = serializers.DictField()
    scans_by_risk = serializers.DictField()
    scans_over_time = serializers.ListField()


class VulnerabilityStatisticsSerializer(serializers.Serializer):
    """Serializer for vulnerability statistics"""

    total_vulnerabilities = serializers.IntegerField()
    unique_vulnerabilities = serializers.IntegerField()
    vulnerabilities_by_type = serializers.DictField()
    vulnerabilities_by_risk = serializers.DictField()
    top_vulnerable_urls = serializers.ListField()
    most_common_cwe = serializers.ListField()
    resolved_vs_unresolved = serializers.DictField()


class ScanStatusUpdateSerializer(serializers.Serializer):
    """Serializer for updating scan status"""

    status = serializers.ChoiceField(choices=[
        'running', 'completed', 'failed', 'cancelled'
    ])
    error_message = serializers.CharField(required=False, allow_blank=True)
    zap_scan_id = serializers.CharField(required=False, allow_blank=True)
    mcp_session_id = serializers.CharField(required=False, allow_blank=True)
