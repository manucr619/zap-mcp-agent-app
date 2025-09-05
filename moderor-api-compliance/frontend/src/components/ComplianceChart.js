import React from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Grid,
  Chip,
  Alert,
} from '@mui/material';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
} from 'recharts';
import { useComplianceOverview } from '../hooks/useScans';

const COLORS = {
  compliant: '#4caf50',
  partial: '#ff9800',
  non_compliant: '#f44336',
  critical: '#d32f2f',
  high: '#f57c00',
  medium: '#ffb74d',
  low: '#81c784',
};

const ComplianceChart = ({ compact = false }) => {
  const { data: complianceData, isLoading, error } = useComplianceOverview();

  if (isLoading) {
    return (
      <Card>
        <CardContent>
          <Typography>Loading compliance data...</Typography>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent>
          <Alert severity="error">
            Failed to load compliance data: {error.message}
          </Alert>
        </CardContent>
      </Card>
    );
  }

  if (!complianceData?.data) {
    return (
      <Card>
        <CardContent>
          <Typography>No compliance data available</Typography>
        </CardContent>
      </Card>
    );
  }

  const data = complianceData.data;

  // Prepare data for category performance chart
  const categoryData = data.category_performance?.map(cat => ({
    name: cat.category.replace('API', ''),
    status: cat.status,
    issues: cat.issues_count,
    compliant: cat.status === 'compliant' ? 1 : 0,
    partial: cat.status === 'partial' ? 1 : 0,
    non_compliant: cat.status === 'non_compliant' ? 1 : 0,
  })) || [];

  // Prepare data for compliance trend (if available)
  const trendData = data.compliance_trend?.slice(-10).map(item => ({
    date: new Date(item.date).toLocaleDateString(),
    score: item.score,
    level: item.level,
  })) || [];

  // Overall compliance distribution
  const overallData = [
    {
      name: 'Compliant',
      value: data.latest_report?.compliant_categories || 0,
      color: COLORS.compliant,
    },
    {
      name: 'Partial',
      value: data.latest_report?.partial_categories || 0,
      color: COLORS.partial,
    },
    {
      name: 'Non-Compliant',
      value: data.latest_report?.non_compliant_categories || 0,
      color: COLORS.non_compliant,
    },
  ];

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <Box
          sx={{
            backgroundColor: 'white',
            p: 2,
            border: '1px solid #ccc',
            borderRadius: 1,
            boxShadow: 1,
          }}
        >
          <Typography variant="subtitle2">{label}</Typography>
          {payload.map((entry, index) => (
            <Typography key={index} variant="body2" color={entry.color}>
              {entry.name}: {entry.value}
            </Typography>
          ))}
        </Box>
      );
    }
    return null;
  };

  if (compact) {
    return (
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            OWASP Compliance
          </Typography>

          <Box display="flex" alignItems="center" justifyContent="center" mb={2}>
            <Typography variant="h2" color="primary" fontWeight="bold">
              {data.latest_report?.compliance_score || 0}%
            </Typography>
          </Box>

          <Box display="flex" justifyContent="center" mb={2}>
            <Chip
              label={data.latest_report?.compliance_level || 'Unknown'}
              color={data.latest_report?.compliance_score >= 75 ? 'success' : 'warning'}
            />
          </Box>

          <Box sx={{ height: 200 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={overallData}
                  cx="50%"
                  cy="50%"
                  innerRadius={40}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {overallData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </Box>
        </CardContent>
      </Card>
    );
  }

  return (
    <Box>
      <Typography variant="h5" gutterBottom>
        OWASP API Top 10 Compliance Dashboard
      </Typography>

      {/* Overall Compliance Score */}
      <Grid container spacing={3} mb={4}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" color="text.secondary" gutterBottom>
                Overall Compliance Score
              </Typography>
              <Typography variant="h2" color="primary" fontWeight="bold">
                {data.latest_report?.compliance_score || 0}%
              </Typography>
              <Chip
                label={data.latest_report?.compliance_level || 'Unknown'}
                color={data.latest_report?.compliance_score >= 75 ? 'success' : 'warning'}
                sx={{ mt: 1 }}
              />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" color="text.secondary" gutterBottom>
                Categories Assessed
              </Typography>
              <Typography variant="h2">
                {data.latest_report?.total_categories || 10}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Total OWASP categories
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" color="text.secondary" gutterBottom>
                Issues Found
              </Typography>
              <Typography variant="h2" color="error.main">
                {data.latest_report?.total_issues || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Across all categories
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3}>
        {/* Compliance Distribution */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Compliance Distribution
              </Typography>
              <Box sx={{ height: 300 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={overallData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={120}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {overallData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Category Performance */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Category Performance
              </Typography>
              <Box sx={{ height: 300 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={categoryData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip content={<CustomTooltip />} />
                    <Legend />
                    <Bar dataKey="compliant" stackId="a" fill={COLORS.compliant} name="Compliant" />
                    <Bar dataKey="partial" stackId="a" fill={COLORS.partial} name="Partial" />
                    <Bar dataKey="non_compliant" stackId="a" fill={COLORS.non_compliant} name="Non-Compliant" />
                  </BarChart>
                </ResponsiveContainer>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Compliance Trend */}
        {trendData.length > 1 && (
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Compliance Trend (Last 10 Reports)
                </Typography>
                <Box sx={{ height: 300 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={trendData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="date" />
                      <YAxis domain={[0, 100]} />
                      <Tooltip content={<CustomTooltip />} />
                      <Legend />
                      <Line
                        type="monotone"
                        dataKey="score"
                        stroke={COLORS.compliant}
                        strokeWidth={3}
                        name="Compliance Score (%)"
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* Detailed Category Status */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Detailed Category Status
              </Typography>
              <Grid container spacing={2}>
                {data.category_performance?.map((category, index) => (
                  <Grid item xs={12} sm={6} md={4} key={index}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                          <Typography variant="subtitle2">
                            {category.name}
                          </Typography>
                          <Chip
                            label={category.status}
                            size="small"
                            color={
                              category.status === 'compliant' ? 'success' :
                              category.status === 'partial' ? 'warning' : 'error'
                            }
                          />
                        </Box>
                        <Typography variant="body2" color="text.secondary">
                          Issues: {category.issues_count}
                        </Typography>
                        {category.description && (
                          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                            {category.description}
                          </Typography>
                        )}
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default ComplianceChart;
