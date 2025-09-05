"""
URL configuration for Moderor API Compliance Tool.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework import routers
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

from apps.scans.views import (
    SecurityScanViewSet,
    VulnerabilityViewSet,
    ComplianceReportViewSet,
    scan_statistics,
    vulnerability_statistics,
    owasp_compliance_overview,
)

# API Router
router = routers.DefaultRouter()
router.register(r'scans', SecurityScanViewSet, basename='scan')
router.register(r'vulnerabilities', VulnerabilityViewSet, basename='vulnerability')
router.register(r'compliance-reports', ComplianceReportViewSet, basename='compliance-report')

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),

    # API Authentication
    path('api/auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/auth/token/verify/', TokenVerifyView.as_view(), name='token_verify'),

    # API v1
    path('api/v1/', include(router.urls)),

    # Statistics endpoints
    path('api/v1/statistics/scans/', scan_statistics, name='scan-statistics'),
    path('api/v1/statistics/vulnerabilities/', vulnerability_statistics, name='vulnerability-statistics'),

    # Compliance endpoints
    path('api/v1/compliance/overview/', owasp_compliance_overview, name='owasp-compliance-overview'),

    # Health check
    path('api/health/', include('health_check.urls')),

    # API documentation (if using drf-yasg)
    # path('api/docs/', include('drf_yasg.urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# API Schema and documentation
from rest_framework.schemas import get_schema_view
from rest_framework.documentation import include_docs_urls

API_TITLE = 'Moderor API Compliance Tool'
API_DESCRIPTION = 'API for automated security scanning and compliance testing'

urlpatterns += [
    # OpenAPI schema
    path('api/schema/', get_schema_view(
        title=API_TITLE,
        description=API_DESCRIPTION,
        version='1.0.0'
    ), name='openapi-schema'),

    # API documentation
    path('api/docs/', include_docs_urls(
        title=API_TITLE,
        description=API_DESCRIPTION,
        public=True
    )),
]
