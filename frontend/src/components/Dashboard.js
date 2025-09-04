import React from 'react';
import {
  Container,
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  Button,
  Chip,
  LinearProgress,
  Alert,
} from '@mui/material';
import {
  Security as SecurityIcon,
  BugReport as BugIcon,
  Assessment as AssessmentIcon,
  TrendingUp as TrendingIcon,
  Add as AddIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useScans, useScanStatistics, useVulnerabilityStatistics, useHealthCheck } from '../hooks/useScans';
import ComplianceChart from './ComplianceChart';

const Dashboard = () => {
  const navigate = useNavigate();
  const { data: scansData, isLoading: scansLoading, error: scansError, refetch: refetchScans } = useScans();
  const { data: scanStats } = useScanStatistics();
  const { data: vulnStats, isLoading: vulnLoading } = useVulnerabilityStatistics();
  const { data: healthData } = useHealthCheck();

  const scans = scansData?.data || [];
  const stats = scanStats?.data || {};
  const vulnData = vulnStats?.data || {};

  // Calculate metrics
  const activeScans = scans.filter(scan => ['queued', 'running'].includes(scan.status)).length;
  const recentScans = scans.slice(0, 5); // Last 5 scans

  const MetricCard = ({ title, value, subtitle, icon: Icon, color = 'primary' }) => (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
          <Typography variant="h6" color="text.secondary">
            {title}
          </Typography>
          <Icon color={color} fontSize="large" />
        </Box>
        <Typography variant="h3" component="div" fontWeight="bold" color={`${color}.main`}>
          {value}
        </Typography>
        {subtitle && (
          <Typography variant="body2" color="text.secondary" mt={1}>
            {subtitle}
          </Typography>
        )}
      </CardContent>
    </Card>
  );

  const StatusChip = ({ status }) => {
    const getStatusColor = (status) => {
      switch (status) {
        case 'completed': return 'success';
        case 'running': return 'primary';
        case 'failed': return 'error';
        case 'queued': return 'warning';
        case 'cancelled': return 'default';
        default: return 'default';
      }
    };

    return (
      <Chip
        label={status}
        color={getStatusColor(status)}
        size="small"
        variant="outlined"
      />
    );
  };

  return (
    <Container maxWidth="xl" sx={{ py: 4 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={4}>
        <Typography variant="h4" component="h1" fontWeight="bold">
          API Compliance Dashboard
        </Typography>
        <Box display="flex" gap={2}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => refetchScans()}
            disabled={scansLoading}
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => navigate('/scan/new')}
          >
            New Scan
          </Button>
        </Box>
      </Box>

      {/* Health Status */}
      {healthData && (
        <Alert
          severity={healthData.data?.services?.zap && healthData.data?.services?.chromadb ? 'success' : 'warning'}
          sx={{ mb: 3 }}
        >
          System Status: {
            healthData.data?.services?.zap && healthData.data?.services?.chromadb
              ? 'All services operational'
              : 'Some services may be unavailable'
          }
        </Alert>
      )}

      {/* Metrics Cards */}
      <Grid container spacing={3} mb={4}>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Total Scans"
            value={stats.total_scans || 0}
            subtitle={`${stats.completed_scans || 0} completed`}
            icon={AssessmentIcon}
            color="primary"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Active Scans"
            value={activeScans}
            subtitle="Currently running"
            icon={SecurityIcon}
            color="warning"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Vulnerabilities"
            value={stats.total_vulnerabilities || 0}
            subtitle={`${stats.critical_vulnerabilities || 0} critical`}
            icon={BugIcon}
            color="error"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Avg Risk Score"
            value={`${stats.average_risk_score || 0}%`}
            subtitle="Across all scans"
            icon={TrendingIcon}
            color="info"
          />
        </Grid>
      </Grid>

      {/* Main Content Grid */}
      <Grid container spacing={3}>
        {/* Recent Scans */}
        <Grid item xs={12} lg={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Recent Scans
              </Typography>
              {scansLoading ? (
                <LinearProgress sx={{ mt: 2 }} />
              ) : scansError ? (
                <Alert severity="error" sx={{ mt: 2 }}>
                  Failed to load scans: {scansError.message}
                </Alert>
              ) : scans.length === 0 ? (
                <Box textAlign="center" py={4}>
                  <Typography color="text.secondary" mb={2}>
                    No scans found. Start your first security scan!
                  </Typography>
                  <Button
                    variant="contained"
                    startIcon={<AddIcon />}
                    onClick={() => navigate('/scan/new')}
                  >
                    Start New Scan
                  </Button>
                </Box>
              ) : (
                <Box>
                  {recentScans.map((scan) => (
                    <Box
                      key={scan.id}
                      sx={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        py: 1.5,
                        borderBottom: '1px solid',
                        borderColor: 'divider',
                        '&:last-child': { borderBottom: 'none' },
                        cursor: 'pointer',
                        '&:hover': { backgroundColor: 'action.hover' },
                      }}
                      onClick={() => navigate(`/scan/${scan.id}`)}
                    >
                      <Box>
                        <Typography variant="body1" fontWeight="medium">
                          {scan.target_url}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {scan.scan_type} • {scan.duration_seconds}s • {scan.vulnerabilities_found} vulnerabilities
                        </Typography>
                      </Box>
                      <Box textAlign="right">
                        <StatusChip status={scan.status} />
                        <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
                          {new Date(scan.created_at).toLocaleDateString()}
                        </Typography>
                      </Box>
                    </Box>
                  ))}
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Compliance Overview */}
        <Grid item xs={12} lg={4}>
          <ComplianceChart compact />
        </Grid>
      </Grid>

      {/* Vulnerability Summary */}
      {!vulnLoading && vulnData && (
        <Grid container spacing={3} mt={2}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Vulnerability Summary
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6} sm={3}>
                    <Box textAlign="center">
                      <Typography variant="h4" color="error.main" fontWeight="bold">
                        {vulnData.total_vulnerabilities || 0}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Total Issues
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Box textAlign="center">
                      <Typography variant="h4" color="error.dark" fontWeight="bold">
                        {vulnData.vulnerabilities_by_risk?.Critical || 0}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Critical
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Box textAlign="center">
                      <Typography variant="h4" color="warning.main" fontWeight="bold">
                        {vulnData.vulnerabilities_by_risk?.High || 0}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        High Risk
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Box textAlign="center">
                      <Typography variant="h4" color="success.main" fontWeight="bold">
                        {vulnData.resolved_vs_unresolved?.resolved || 0}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Resolved
                      </Typography>
                    </Box>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}
    </Container>
  );
};

export default Dashboard;
