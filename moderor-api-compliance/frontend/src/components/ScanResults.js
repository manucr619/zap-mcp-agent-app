import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Container,
  Card,
  CardContent,
  Typography,
  Box,
  Grid,
  Chip,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Alert,
  LinearProgress,
  Tabs,
  Tab,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Refresh as RefreshIcon,
  Download as DownloadIcon,
  Cancel as CancelIcon,
  Replay as ReplayIcon,
  BugReport as BugIcon,
  Security as SecurityIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { format } from 'date-fns';
import {
  useScan,
  useScanReport,
  useCancelScan,
  useRetryScan,
  useExportScanReport,
  useMarkVulnerabilityResolved,
  useMarkVulnerabilityFalsePositive,
} from '../hooks/useScans';

const ScanResults = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState(0);

  const { data: scanData, isLoading: scanLoading, error: scanError, refetch: refetchScan } = useScan(id);
  const { data: reportData, isLoading: reportLoading } = useScanReport(id);

  const cancelScanMutation = useCancelScan();
  const retryScanMutation = useRetryScan();
  const exportReportMutation = useExportScanReport();
  const markResolvedMutation = useMarkVulnerabilityResolved();
  const markFalsePositiveMutation = useMarkVulnerabilityFalsePositive();

  const scan = scanData?.data;
  const report = reportData?.data;

  const handleTabChange = (event, newValue) => {
    setActiveTab(newValue);
  };

  const handleCancelScan = () => {
    if (window.confirm('Are you sure you want to cancel this scan?')) {
      cancelScanMutation.mutate({ id });
    }
  };

  const handleRetryScan = () => {
    retryScanMutation.mutate({ id });
  };

  const handleExportReport = (format) => {
    exportReportMutation.mutate({ id, format });
  };

  const handleMarkResolved = (vulnId) => {
    markResolvedMutation.mutate({ id: vulnId });
  };

  const handleMarkFalsePositive = (vulnId) => {
    markFalsePositiveMutation.mutate({ id: vulnId });
  };

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

  const getRiskColor = (risk) => {
    switch (risk) {
      case 'critical': return 'error';
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  if (scanLoading) {
    return (
      <Container maxWidth="xl" sx={{ py: 4 }}>
        <LinearProgress />
        <Typography sx={{ mt: 2 }}>Loading scan results...</Typography>
      </Container>
    );
  }

  if (scanError) {
    return (
      <Container maxWidth="xl" sx={{ py: 4 }}>
        <Alert severity="error">
          Failed to load scan: {scanError.message}
        </Alert>
        <Button sx={{ mt: 2 }} onClick={() => navigate('/')}>
          Back to Dashboard
        </Button>
      </Container>
    );
  }

  if (!scan) {
    return (
      <Container maxWidth="xl" sx={{ py: 4 }}>
        <Alert severity="warning">Scan not found</Alert>
        <Button sx={{ mt: 2 }} onClick={() => navigate('/')}>
          Back to Dashboard
        </Button>
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ py: 4 }}>
      {/* Header */}
      <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={4}>
        <Box>
          <Typography variant="h4" component="h1" fontWeight="bold" gutterBottom>
            Scan Results
          </Typography>
          <Typography variant="h6" color="text.secondary" sx={{ wordBreak: 'break-all' }}>
            {scan.target_url}
          </Typography>
          <Box display="flex" alignItems="center" gap={2} mt={1}>
            <Chip
              label={scan.status}
              color={getStatusColor(scan.status)}
              variant="outlined"
            />
            <Typography variant="body2" color="text.secondary">
              Started: {format(new Date(scan.created_at), 'PPpp')}
            </Typography>
            {scan.completed_at && (
              <Typography variant="body2" color="text.secondary">
                Completed: {format(new Date(scan.completed_at), 'PPpp')}
              </Typography>
            )}
          </Box>
        </Box>

        <Box display="flex" gap={1}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => refetchScan()}
          >
            Refresh
          </Button>
          {scan.status === 'completed' && (
            <>
              <Button
                variant="outlined"
                startIcon={<DownloadIcon />}
                onClick={() => handleExportReport('json')}
              >
                Export JSON
              </Button>
              <Button
                variant="outlined"
                startIcon={<DownloadIcon />}
                onClick={() => handleExportReport('pdf')}
              >
                Export PDF
              </Button>
            </>
          )}
          {['queued', 'running'].includes(scan.status) && (
            <Button
              variant="outlined"
              color="error"
              startIcon={<CancelIcon />}
              onClick={handleCancelScan}
              disabled={cancelScanMutation.isLoading}
            >
              Cancel Scan
            </Button>
          )}
          {scan.status === 'failed' && (
            <Button
              variant="outlined"
              startIcon={<ReplayIcon />}
              onClick={handleRetryScan}
              disabled={retryScanMutation.isLoading}
            >
              Retry Scan
            </Button>
          )}
        </Box>
      </Box>

      {/* Scan Summary Cards */}
      <Grid container spacing={3} mb={4}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography variant="h6" color="text.secondary" gutterBottom>
                Scan Type
              </Typography>
              <Typography variant="h4">{scan.scan_type}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography variant="h6" color="text.secondary" gutterBottom>
                Vulnerabilities Found
              </Typography>
              <Typography variant="h4" color="error.main">
                {scan.vulnerabilities_found}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography variant="h6" color="text.secondary" gutterBottom>
                Risk Score
              </Typography>
              <Typography variant="h4" color={`${getRiskColor(scan.overall_risk)}.main`}>
                {scan.risk_score}%
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography variant="h6" color="text.secondary" gutterBottom>
                Duration
              </Typography>
              <Typography variant="h4">
                {scan.duration_seconds ? `${scan.duration_seconds}s` : 'N/A'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs for different views */}
      <Card>
        <Tabs value={activeTab} onChange={handleTabChange} sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tab label="Vulnerabilities" />
          <Tab label="AI Analysis" />
          <Tab label="Compliance" />
        </Tabs>

        {/* Vulnerabilities Tab */}
        {activeTab === 0 && (
          <CardContent>
            {scan.vulnerabilities && scan.vulnerabilities.length > 0 ? (
              <TableContainer component={Paper} elevation={0}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Vulnerability</TableCell>
                      <TableCell>Risk Level</TableCell>
                      <TableCell>Confidence</TableCell>
                      <TableCell>URL</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {scan.vulnerabilities.map((vuln) => (
                      <TableRow key={vuln.id}>
                        <TableCell>
                          <Box>
                            <Typography variant="body2" fontWeight="medium">
                              {vuln.name}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {vuln.vuln_type}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={vuln.risk_level}
                            color={getRiskColor(vuln.risk_level)}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>{vuln.confidence}</TableCell>
                        <TableCell sx={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {vuln.url}
                        </TableCell>
                        <TableCell>
                          <Box display="flex" gap={1}>
                            <Tooltip title="Mark as Resolved">
                              <IconButton
                                size="small"
                                onClick={() => handleMarkResolved(vuln.id)}
                                disabled={markResolvedMutation.isLoading}
                              >
                                <SecurityIcon />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Mark as False Positive">
                              <IconButton
                                size="small"
                                onClick={() => handleMarkFalsePositive(vuln.id)}
                                disabled={markFalsePositiveMutation.isLoading}
                              >
                                <BugIcon />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <Box textAlign="center" py={4}>
                <InfoIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
                <Typography variant="h6" color="text.secondary">
                  No vulnerabilities found
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  The scan completed successfully with no security issues detected.
                </Typography>
              </Box>
            )}
          </CardContent>
        )}

        {/* AI Analysis Tab */}
        {activeTab === 1 && (
          <CardContent>
            {reportLoading ? (
              <LinearProgress />
            ) : report?.ai_analysis ? (
              <Box>
                <Typography variant="h6" gutterBottom>
                  AI-Powered Analysis
                </Typography>
                <Grid container spacing={2} mb={3}>
                  <Grid item xs={12} md={4}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography variant="h6">Risk Level</Typography>
                        <Chip
                          label={report.ai_analysis.risk_level}
                          color={getRiskColor(report.ai_analysis.overall_risk_score > 7 ? 'high' : 'medium')}
                          sx={{ mt: 1 }}
                        />
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography variant="h6">Overall Score</Typography>
                        <Typography variant="h4" color="primary">
                          {report.ai_analysis.overall_risk_score}%
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography variant="h6">Total Findings</Typography>
                        <Typography variant="h4">
                          {report.ai_analysis.total_findings}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                </Grid>

                {report.ai_analysis.top_vulnerabilities && (
                  <Box>
                    <Typography variant="h6" gutterBottom>
                      Top Vulnerabilities
                    </Typography>
                    {report.ai_analysis.top_vulnerabilities.map((vuln, index) => (
                      <Accordion key={index}>
                        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                          <Typography fontWeight="medium">
                            {vuln.name} - {vuln.risk}
                          </Typography>
                        </AccordionSummary>
                        <AccordionDetails>
                          <Typography variant="body2" color="text.secondary">
                            {vuln.description}
                          </Typography>
                        </AccordionDetails>
                      </Accordion>
                    ))}
                  </Box>
                )}
              </Box>
            ) : (
              <Alert severity="info">
                AI analysis not available for this scan.
              </Alert>
            )}
          </CardContent>
        )}

        {/* Compliance Tab */}
        {activeTab === 2 && (
          <CardContent>
            {report?.owasp_compliance ? (
              <Box>
                <Typography variant="h6" gutterBottom>
                  OWASP API Top 10 Compliance
                </Typography>
                <Grid container spacing={2} mb={3}>
                  <Grid item xs={12} md={4}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography variant="h6">Compliance Score</Typography>
                        <Typography variant="h3" color="primary" fontWeight="bold">
                          {report.owasp_compliance.compliance_score}%
                        </Typography>
                        <Chip
                          label={report.owasp_compliance.compliance_level}
                          color={report.owasp_compliance.compliance_score >= 75 ? 'success' : 'warning'}
                          sx={{ mt: 1 }}
                        />
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography variant="h6">Categories Assessed</Typography>
                        <Typography variant="h3">
                          {report.owasp_compliance.total_categories}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography variant="h6">Compliant Categories</Typography>
                        <Typography variant="h3" color="success.main">
                          {report.owasp_compliance.compliant_categories}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                </Grid>

                {report.remediation_recommendations && (
                  <Box>
                    <Typography variant="h6" gutterBottom>
                      Remediation Recommendations
                    </Typography>
                    {report.remediation_recommendations.map((rec, index) => (
                      <Card key={index} variant="outlined" sx={{ mb: 2 }}>
                        <CardContent>
                          <Typography variant="subtitle1" fontWeight="medium">
                            {rec.vulnerability}
                          </Typography>
                          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                            {rec.impact}
                          </Typography>
                          <Typography variant="body2" sx={{ mt: 1 }}>
                            <strong>Effort:</strong> {rec.estimated_effort}
                          </Typography>
                        </CardContent>
                      </Card>
                    ))}
                  </Box>
                )}
              </Box>
            ) : (
              <Alert severity="info">
                Compliance report not available for this scan.
              </Alert>
            )}
          </CardContent>
        )}
      </Card>
    </Container>
  );
};

export default ScanResults;
