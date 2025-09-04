from celery import shared_task
from django.utils import timezone
from django.conf import settings
import httpx
import json
import logging
from datetime import timedelta

from .models import SecurityScan, Vulnerability, ComplianceReport

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def run_security_scan(self, scan_id):
    """Run security scan using MCP server"""

    try:
        # Get scan object
        scan = SecurityScan.objects.get(id=scan_id)

        # Update status
        scan.status = 'running'
        scan.started_at = timezone.now()
        scan.save()

        logger.info(f"Starting security scan {scan.scan_id} for {scan.target_url}")

        # Prepare scan data
        scan_data = {
            "target_url": scan.target_url,
            "scan_type": scan.scan_type,
            "scan_policy": scan.scan_policy,
            "max_scan_time": scan.max_scan_time,
            "follow_redirects": scan.follow_redirects,
            "scan_subdomains": scan.scan_subdomains,
        }

        # Add authentication if provided
        if scan.auth_username and scan.auth_password:
            scan_data["authentication"] = {
                "type": "basic",
                "username": scan.auth_username,
                "password": scan.auth_password,
            }
        elif scan.auth_token:
            scan_data["authentication"] = {
                "type": "bearer",
                "token": scan.auth_token,
            }

        # Call MCP server
        mcp_url = f"{settings.MCP_SERVER_HOST}:{settings.MCP_SERVER_PORT}/api/v1/scan/start"

        import requests
        response = requests.post(
            mcp_url,
            json=scan_data,
            headers={"Content-Type": "application/json"},
            timeout=scan.max_scan_time + 60
        )
        response.raise_for_status()

        result = response.json()
        mcp_scan_id = result.get("scan_id")

        # Update scan with MCP session ID
        scan.mcp_session_id = mcp_scan_id
        scan.save()

        # Poll for completion
        poll_scan_status(scan.id, mcp_scan_id)

        logger.info(f"Security scan {scan.scan_id} completed successfully")

    except SecurityScan.DoesNotExist:
        logger.error(f"Scan {scan_id} not found")
        raise self.retry(countdown=60)
    except httpx.RequestError as e:
        logger.error(f"Network error during scan {scan_id}: {e}")
        _mark_scan_failed(scan_id, f"Network error: {str(e)}")
        raise self.retry(countdown=300)
    except Exception as e:
        logger.error(f"Unexpected error during scan {scan_id}: {e}")
        _mark_scan_failed(scan_id, f"Unexpected error: {str(e)}")
        raise


@shared_task(bind=True)
def poll_scan_status(self, scan_id, mcp_scan_id):
    """Poll MCP server for scan status"""

    try:
        scan = SecurityScan.objects.get(id=scan_id)
        mcp_url = f"{settings.MCP_SERVER_HOST}:{settings.MCP_SERVER_PORT}/api/v1/scan/{mcp_scan_id}/status"

        max_polls = scan.max_scan_time // 30  # Poll every 30 seconds
        poll_count = 0

        while poll_count < max_polls:
            response = requests.get(mcp_url, timeout=30)
            response.raise_for_status()

            status_data = response.json()

            if status_data.get("status") == "completed":
                # Get final report
                fetch_scan_results(scan.id, mcp_scan_id)
                break
            elif status_data.get("status") == "failed":
                _mark_scan_failed(scan.id, "MCP scan failed")
                break

            poll_count += 1
            import time
            time.sleep(30)

        if poll_count >= max_polls:
            _mark_scan_failed(scan.id, "Scan timeout")

    except Exception as e:
        logger.error(f"Error polling scan status {scan_id}: {e}")
        _mark_scan_failed(scan_id, f"Polling error: {str(e)}")


@shared_task(bind=True)
def fetch_scan_results(self, scan_id, mcp_scan_id):
    """Fetch final scan results from MCP server"""

    try:
        scan = SecurityScan.objects.get(id=scan_id)
        mcp_url = f"{settings.MCP_SERVER_HOST}:{settings.MCP_SERVER_PORT}/api/v1/scan/{mcp_scan_id}/report"

        response = requests.get(mcp_url, timeout=60)
        response.raise_for_status()

        report_data = response.json()

        # Update scan with results
        scan_result = report_data.get("scan_summary", {})
        scan.status = "completed"
        scan.completed_at = timezone.now()
        scan.vulnerabilities_found = scan_result.get("vulnerabilities_found", 0)
        scan.critical_count = scan_result.get("critical_count", 0)
        scan.high_count = scan_result.get("high_count", 0)
        scan.medium_count = scan_result.get("medium_count", 0)
        scan.low_count = scan_result.get("low_count", 0)
        scan.save()

        # Create vulnerabilities
        vulnerabilities_data = scan_result.get("findings", [])
        for vuln_data in vulnerabilities_data:
            Vulnerability.objects.create(
                scan=scan,
                vuln_id=vuln_data.get("id", f"custom_{timezone.now().timestamp()}"),
                name=vuln_data.get("name", "Unknown Vulnerability"),
                description=vuln_data.get("description", ""),
                solution=vuln_data.get("solution", ""),
                risk_level=vuln_data.get("risk", "low"),
                confidence=vuln_data.get("confidence", "medium"),
                url=vuln_data.get("url", scan.target_url),
                method=vuln_data.get("method", "GET"),
                param=vuln_data.get("param", ""),
                evidence=vuln_data.get("evidence", ""),
                cwe_id=vuln_data.get("cwe_id"),
                cve_id=vuln_data.get("cve_id"),
                owasp_category=vuln_data.get("owasp_category"),
                reference=vuln_data.get("reference"),
            )

        logger.info(f"Fetched results for scan {scan.scan_id}: {len(vulnerabilities_data)} vulnerabilities")

    except Exception as e:
        logger.error(f"Error fetching scan results {scan_id}: {e}")
        _mark_scan_failed(scan_id, f"Results fetch error: {str(e)}")


@shared_task(bind=True)
def generate_compliance_report(self, scan_id, user_id):
    """Generate OWASP compliance report for a scan"""

    try:
        from django.contrib.auth.models import User

        scan = SecurityScan.objects.get(id=scan_id)
        user = User.objects.get(id=user_id)

        # Get all vulnerabilities for this scan
        vulnerabilities = Vulnerability.objects.filter(scan=scan)

        # Analyze OWASP compliance
        owasp_analysis = analyze_owasp_compliance(vulnerabilities)

        # Create compliance report
        report = ComplianceReport.objects.create(
            scan=scan,
            report_type='api_top_10',
            generated_by=user,
            api1_broken_object_level_authorization=owasp_analysis.get('api1'),
            api2_broken_authentication=owasp_analysis.get('api2'),
            api3_broken_object_property_level_authorization=owasp_analysis.get('api3'),
            api4_unrestricted_resource_consumption=owasp_analysis.get('api4'),
            api5_broken_function_level_authorization=owasp_analysis.get('api5'),
            api6_unrestricted_access_to_sensitive_business_flows=owasp_analysis.get('api6'),
            api7_server_side_request_forgery=owasp_analysis.get('api7'),
            api8_security_misconfiguration=owasp_analysis.get('api8'),
            api9_improper_inventory_management=owasp_analysis.get('api9'),
            api10_unsafe_consumption_of_apis=owasp_analysis.get('api10'),
            ai_insights=owasp_analysis.get('ai_insights', {}),
            recommended_actions=owasp_analysis.get('recommendations', []),
            report_data=owasp_analysis
        )

        logger.info(f"Generated compliance report for scan {scan.scan_id}")

    except Exception as e:
        logger.error(f"Error generating compliance report for scan {scan_id}: {e}")
        raise


def analyze_owasp_compliance(vulnerabilities):
    """Analyze vulnerabilities against OWASP API Top 10"""

    # Initialize OWASP categories
    owasp_categories = {
        'api1': {'name': 'Broken Object Level Authorization', 'issues': [], 'status': 'compliant'},
        'api2': {'name': 'Broken Authentication', 'issues': [], 'status': 'compliant'},
        'api3': {'name': 'Broken Object Property Level Authorization', 'issues': [], 'status': 'compliant'},
        'api4': {'name': 'Unrestricted Resource Consumption', 'issues': [], 'status': 'compliant'},
        'api5': {'name': 'Broken Function Level Authorization', 'issues': [], 'status': 'compliant'},
        'api6': {'name': 'Unrestricted Access to Sensitive Business Flows', 'issues': [], 'status': 'compliant'},
        'api7': {'name': 'Server Side Request Forgery', 'issues': [], 'status': 'compliant'},
        'api8': {'name': 'Security Misconfiguration', 'issues': [], 'status': 'compliant'},
        'api9': {'name': 'Improper Inventory Management', 'issues': [], 'status': 'compliant'},
        'api10': {'name': 'Unsafe Consumption of APIs', 'issues': [], 'status': 'compliant'},
    }

    # Analyze each vulnerability
    for vuln in vulnerabilities:
        name = vuln.name.lower()
        desc = vuln.description.lower()

        # API1: Broken Object Level Authorization
        if any(keyword in name or keyword in desc for keyword in
               ['authorization', 'access control', 'object level', 'idor']):
            owasp_categories['api1']['issues'].append({
                'id': vuln.id,
                'name': vuln.name,
                'risk': vuln.risk_level,
                'url': vuln.url
            })
            if vuln.risk_level in ['high', 'critical']:
                owasp_categories['api1']['status'] = 'non_compliant'
            elif owasp_categories['api1']['status'] == 'compliant':
                owasp_categories['api1']['status'] = 'partial'

        # API2: Broken Authentication
        if any(keyword in name or keyword in desc for keyword in
               ['authentication', 'session', 'login', 'token', 'jwt']):
            owasp_categories['api2']['issues'].append({
                'id': vuln.id,
                'name': vuln.name,
                'risk': vuln.risk_level,
                'url': vuln.url
            })
            if vuln.risk_level in ['high', 'critical']:
                owasp_categories['api2']['status'] = 'non_compliant'
            elif owasp_categories['api2']['status'] == 'compliant':
                owasp_categories['api2']['status'] = 'partial'

        # API8: Security Misconfiguration (catch-all for config issues)
        if any(keyword in name or keyword in desc for keyword in
               ['configuration', 'misconfiguration', 'default', 'exposed']):
            owasp_categories['api8']['issues'].append({
                'id': vuln.id,
                'name': vuln.name,
                'risk': vuln.risk_level,
                'url': vuln.url
            })
            if vuln.risk_level in ['high', 'critical']:
                owasp_categories['api8']['status'] = 'non_compliant'
            elif owasp_categories['api8']['status'] == 'compliant':
                owasp_categories['api8']['status'] = 'partial'

    # Generate AI insights and recommendations
    total_issues = sum(len(cat['issues']) for cat in owasp_categories.values())
    high_risk_issues = sum(
        1 for cat in owasp_categories.values()
        for issue in cat['issues']
        if issue['risk'] in ['high', 'critical']
    )

    ai_insights = {
        'total_issues': total_issues,
        'high_risk_issues': high_risk_issues,
        'compliance_level': 'High' if high_risk_issues == 0 else 'Medium' if high_risk_issues < 5 else 'Low',
        'top_risks': [cat['name'] for cat in owasp_categories.values() if cat['status'] == 'non_compliant']
    }

    recommendations = [
        "Implement proper authentication and authorization mechanisms",
        "Regular security configuration reviews",
        "Input validation and sanitization",
        "API rate limiting and resource protection",
        "Regular security testing and vulnerability assessments"
    ]

    # Add issue counts to categories
    for cat_key, cat_data in owasp_categories.items():
        cat_data['issues_count'] = len(cat_data['issues'])

    return {
        **owasp_categories,
        'ai_insights': ai_insights,
        'recommendations': recommendations
    }


def _mark_scan_failed(scan_id, error_message):
    """Mark scan as failed with error message"""

    try:
        scan = SecurityScan.objects.get(id=scan_id)
        scan.status = 'failed'
        scan.completed_at = timezone.now()
        # Could add error_message field to model if needed
        scan.save()
        logger.error(f"Marked scan {scan_id} as failed: {error_message}")
    except Exception as e:
        logger.error(f"Error marking scan {scan_id} as failed: {e}")


@shared_task
def cleanup_old_scans():
    """Periodic task to clean up old completed scans"""

    # Delete scans older than 90 days that are completed
    cutoff_date = timezone.now() - timedelta(days=90)

    old_scans = SecurityScan.objects.filter(
        status__in=['completed', 'failed'],
        completed_at__lt=cutoff_date
    )

    deleted_count = old_scans.count()

    # Only delete if there are associated vulnerabilities and reports
    for scan in old_scans:
        # Check if scan has compliance reports or important vulnerabilities
        has_reports = ComplianceReport.objects.filter(scan=scan).exists()
        has_critical_vulns = Vulnerability.objects.filter(
            scan=scan,
            risk_level='critical'
        ).exists()

        if not has_reports and not has_critical_vulns:
            scan.delete()

    logger.info(f"Cleaned up {deleted_count} old scans")


@shared_task
def update_vulnerability_knowledge_base():
    """Update vulnerability knowledge base with latest threat intelligence"""

    # This could integrate with threat intelligence feeds
    # For now, just log that the task ran
    logger.info("Vulnerability knowledge base update task executed")

    # Could implement:
    # - Fetch latest CVE data
    # - Update vulnerability patterns
    # - Refresh AI models
    # - Update compliance rules
