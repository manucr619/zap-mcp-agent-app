from django.shortcuts import get_object_or_404
from django.db.models import Count, Avg, Q, F
from django.utils import timezone
from django.http import JsonResponse
from rest_framework import viewsets, status, generics
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.filters import OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from datetime import timedelta
import uuid

from .models import SecurityScan, Vulnerability, ComplianceReport
from .serializers import (
    SecurityScanSerializer, SecurityScanCreateSerializer,
    SecurityScanListSerializer, VulnerabilitySerializer,
    ComplianceReportSerializer, ComplianceReportCreateSerializer,
    ScanStatisticsSerializer, VulnerabilityStatisticsSerializer,
    ScanStatusUpdateSerializer
)
from .tasks import run_security_scan, generate_compliance_report


class SecurityScanViewSet(viewsets.ModelViewSet):
    """ViewSet for managing security scans"""

    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['status', 'scan_type', 'overall_risk', 'created_by']
    ordering_fields = ['created_at', 'completed_at', 'risk_score', 'vulnerabilities_found']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'create':
            return SecurityScanCreateSerializer
        elif self.action == 'list':
            return SecurityScanListSerializer
        return SecurityScanSerializer

    def get_queryset(self):
        """Filter scans by user (unless superuser)"""
        user = self.request.user
        if user.is_superuser:
            return SecurityScan.objects.all()
        return SecurityScan.objects.filter(created_by=user)

    def perform_create(self, serializer):
        """Create scan and trigger background task"""
        scan = serializer.save()

        # Generate unique scan ID
        scan.scan_id = f"scan_{scan.id}_{uuid.uuid4().hex[:8]}"
        scan.save()

        # Trigger background scan
        run_security_scan.delay(scan.id)

        return scan

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel a running scan"""
        scan = self.get_object()

        if scan.status not in ['queued', 'running']:
            return Response(
                {'error': 'Cannot cancel scan that is not queued or running'},
                status=status.HTTP_400_BAD_REQUEST
            )

        scan.status = 'cancelled'
        scan.completed_at = timezone.now()
        scan.save()

        return Response({'message': 'Scan cancelled successfully'})

    @action(detail=True, methods=['post'])
    def retry(self, request, pk=None):
        """Retry a failed scan"""
        scan = self.get_object()

        if scan.status != 'failed':
            return Response(
                {'error': 'Cannot retry scan that did not fail'},
                status=status.HTTP_400_BAD_REQUEST
            )

        scan.status = 'queued'
        scan.started_at = None
        scan.completed_at = None
        scan.save()

        # Trigger background scan
        run_security_scan.delay(scan.id)

        return Response({'message': 'Scan retry initiated'})

    @action(detail=True, methods=['get'])
    def export_report(self, request, pk=None):
        """Export scan report in various formats"""
        scan = self.get_object()
        format_type = request.query_params.get('format', 'json')

        if format_type == 'json':
            data = SecurityScanSerializer(scan).data
            return JsonResponse(data)
        elif format_type == 'summary':
            summary = {
                'scan_id': scan.scan_id,
                'target_url': scan.target_url,
                'status': scan.status,
                'risk_score': scan.risk_score,
                'vulnerabilities_found': scan.vulnerabilities_found,
                'scan_duration': scan.duration_seconds,
                'completed_at': scan.completed_at
            }
            return JsonResponse(summary)
        else:
            return Response(
                {'error': 'Unsupported format. Use json or summary'},
                status=status.HTTP_400_BAD_REQUEST
            )


class VulnerabilityViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing vulnerabilities"""

    permission_classes = [IsAuthenticated]
    serializer_class = VulnerabilitySerializer
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['risk_level', 'confidence', 'vuln_type', 'is_resolved', 'is_false_positive']
    ordering_fields = ['discovered_at', 'risk_level', 'remediation_priority', 'severity_score']
    ordering = ['-remediation_priority', '-discovered_at']

    def get_queryset(self):
        """Filter vulnerabilities by user's scans"""
        user = self.request.user
        if user.is_superuser:
            return Vulnerability.objects.all()
        return Vulnerability.objects.filter(scan__created_by=user)

    @action(detail=True, methods=['post'])
    def mark_resolved(self, request, pk=None):
        """Mark vulnerability as resolved"""
        vulnerability = self.get_object()
        vulnerability.is_resolved = True
        vulnerability.resolved_at = timezone.now()
        vulnerability.resolved_by = request.user
        vulnerability.save()

        return Response({'message': 'Vulnerability marked as resolved'})

    @action(detail=True, methods=['post'])
    def mark_false_positive(self, request, pk=None):
        """Mark vulnerability as false positive"""
        vulnerability = self.get_object()
        vulnerability.is_false_positive = True
        vulnerability.save()

        return Response({'message': 'Vulnerability marked as false positive'})


class ComplianceReportViewSet(viewsets.ModelViewSet):
    """ViewSet for managing compliance reports"""

    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['report_type', 'compliance_level']
    ordering_fields = ['generated_at', 'compliance_score']
    ordering = ['-generated_at']

    def get_serializer_class(self):
        if self.action == 'create':
            return ComplianceReportCreateSerializer
        return ComplianceReportSerializer

    def get_queryset(self):
        """Filter reports by user's scans"""
        user = self.request.user
        if user.is_superuser:
            return ComplianceReport.objects.all()
        return ComplianceReport.objects.filter(generated_by=user)

    def perform_create(self, serializer):
        """Create compliance report"""
        scan_id = self.request.data.get('scan_id')
        if not scan_id:
            raise serializers.ValidationError({'scan_id': 'This field is required'})

        try:
            scan = SecurityScan.objects.get(id=scan_id, created_by=self.request.user)
        except SecurityScan.DoesNotExist:
            raise serializers.ValidationError({'scan_id': 'Scan not found or access denied'})

        # Generate compliance report asynchronously
        generate_compliance_report.delay(scan.id, self.request.user.id)

        return Response({'message': 'Compliance report generation initiated'})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scan_statistics(request):
    """Get comprehensive scan statistics"""

    user = request.user
    queryset = SecurityScan.objects.filter(created_by=user) if not user.is_superuser else SecurityScan.objects.all()

    # Basic scan counts
    total_scans = queryset.count()
    completed_scans = queryset.filter(status='completed').count()
    failed_scans = queryset.filter(status='failed').count()
    running_scans = queryset.filter(status='running').count()
    queued_scans = queryset.filter(status='queued').count()

    # Vulnerability counts
    vulnerabilities = Vulnerability.objects.filter(scan__in=queryset)
    total_vulnerabilities = vulnerabilities.count()
    critical_vulnerabilities = vulnerabilities.filter(risk_level='critical').count()
    high_vulnerabilities = vulnerabilities.filter(risk_level='high').count()
    medium_vulnerabilities = vulnerabilities.filter(risk_level='medium').count()
    low_vulnerabilities = vulnerabilities.filter(risk_level='low').count()

    # Average metrics
    avg_risk_score = queryset.filter(status='completed').aggregate(
        avg_score=Avg('risk_score')
    )['avg_score'] or 0

    avg_duration = queryset.filter(status='completed').exclude(scan_duration__isnull=True).aggregate(
        avg_duration=Avg('scan_duration')
    )['avg_duration']

    avg_duration_seconds = int(avg_duration.total_seconds()) if avg_duration else 0

    # Distribution data
    scans_by_type = queryset.values('scan_type').annotate(count=Count('scan_type'))
    scans_by_risk = queryset.filter(status='completed').values('overall_risk').annotate(count=Count('overall_risk'))

    # Recent scans (last 30 days)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    recent_scans = queryset.filter(created_at__gte=thirty_days_ago).values(
        'created_at__date'
    ).annotate(count=Count('id')).order_by('created_at__date')

    scans_over_time = [
        {'date': str(scan['created_at__date']), 'count': scan['count']}
        for scan in recent_scans
    ]

    data = {
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'failed_scans': failed_scans,
        'running_scans': running_scans,
        'queued_scans': queued_scans,
        'total_vulnerabilities': total_vulnerabilities,
        'critical_vulnerabilities': critical_vulnerabilities,
        'high_vulnerabilities': high_vulnerabilities,
        'medium_vulnerabilities': medium_vulnerabilities,
        'low_vulnerabilities': low_vulnerabilities,
        'average_risk_score': round(avg_risk_score, 2),
        'average_scan_duration': avg_duration_seconds,
        'scans_by_type': {item['scan_type']: item['count'] for item in scans_by_type},
        'scans_by_risk': {item['overall_risk']: item['count'] for item in scans_by_risk},
        'scans_over_time': scans_over_time
    }

    serializer = ScanStatisticsSerializer(data=data)
    serializer.is_valid(raise_exception=True)

    return Response(serializer.validated_data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def vulnerability_statistics(request):
    """Get comprehensive vulnerability statistics"""

    user = request.user
    scan_queryset = SecurityScan.objects.filter(created_by=user) if not user.is_superuser else SecurityScan.objects.all()
    vuln_queryset = Vulnerability.objects.filter(scan__in=scan_queryset)

    # Basic counts
    total_vulnerabilities = vuln_queryset.count()
    unique_vulnerabilities = vuln_queryset.values('vuln_id').distinct().count()

    # Distribution by type and risk
    by_type = vuln_queryset.values('vuln_type').annotate(count=Count('vuln_type'))
    by_risk = vuln_queryset.values('risk_level').annotate(count=Count('risk_level'))

    # Top vulnerable URLs
    top_urls = vuln_queryset.values('url').annotate(
        vuln_count=Count('id')
    ).order_by('-vuln_count')[:10]

    # Most common CWE IDs
    common_cwe = vuln_queryset.exclude(cwe_id__isnull=True).values('cwe_id').annotate(
        count=Count('cwe_id')
    ).order_by('-count')[:10]

    # Resolution status
    resolved_count = vuln_queryset.filter(is_resolved=True).count()
    unresolved_count = vuln_queryset.filter(is_resolved=False).count()
    false_positive_count = vuln_queryset.filter(is_false_positive=True).count()

    data = {
        'total_vulnerabilities': total_vulnerabilities,
        'unique_vulnerabilities': unique_vulnerabilities,
        'vulnerabilities_by_type': {item['vuln_type']: item['count'] for item in by_type if item['vuln_type']},
        'vulnerabilities_by_risk': {item['risk_level']: item['count'] for item in by_risk},
        'top_vulnerable_urls': [
            {'url': item['url'], 'vulnerability_count': item['vuln_count']}
            for item in top_urls
        ],
        'most_common_cwe': [
            {'cwe_id': item['cwe_id'], 'count': item['count']}
            for item in common_cwe
        ],
        'resolved_vs_unresolved': {
            'resolved': resolved_count,
            'unresolved': unresolved_count,
            'false_positives': false_positive_count
        }
    }

    serializer = VulnerabilityStatisticsSerializer(data=data)
    serializer.is_valid(raise_exception=True)

    return Response(serializer.validated_data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def owasp_compliance_overview(request):
    """Get OWASP API Top 10 compliance overview"""

    user = request.user
    queryset = ComplianceReport.objects.filter(generated_by=user) if not user.is_superuser else ComplianceReport.objects.all()

    if not queryset.exists():
        return Response({'message': 'No compliance reports found'})

    # Get latest report
    latest_report = queryset.order_by('-generated_at').first()

    # Aggregate compliance data
    reports = queryset.order_by('-generated_at')[:10]  # Last 10 reports

    compliance_trend = []
    for report in reports:
        compliance_trend.append({
            'date': report.generated_at.date(),
            'score': report.compliance_score,
            'level': report.compliance_level
        })

    # OWASP category performance
    categories = {
        'API1': latest_report.api1_broken_object_level_authorization,
        'API2': latest_report.api2_broken_authentication,
        'API3': latest_report.api3_broken_object_property_level_authorization,
        'API4': latest_report.api4_unrestricted_resource_consumption,
        'API5': latest_report.api5_broken_function_level_authorization,
        'API6': latest_report.api6_unrestricted_access_to_sensitive_business_flows,
        'API7': latest_report.api7_server_side_request_forgery,
        'API8': latest_report.api8_security_misconfiguration,
        'API9': latest_report.api9_improper_inventory_management,
        'API10': latest_report.api10_unsafe_consumption_of_apis,
    }

    category_performance = []
    for cat_id, cat_data in categories.items():
        if cat_data:
            category_performance.append({
                'category': cat_id,
                'name': cat_data.get('name', cat_id),
                'status': cat_data.get('status', 'unknown'),
                'issues_count': cat_data.get('issues_count', 0),
                'description': cat_data.get('description', '')
            })

    return Response({
        'latest_report': ComplianceReportSerializer(latest_report).data,
        'compliance_trend': compliance_trend,
        'category_performance': category_performance,
        'recommendations': latest_report.recommended_actions or []
    })
