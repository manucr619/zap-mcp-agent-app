import React, { useState } from 'react';
import {
  Container,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Box,
  Grid,
  Alert,
  Paper,
  Divider,
  Switch,
  FormControlLabel,
  InputAdornment,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Http as HttpIcon,
  Settings as SettingsIcon,
  PlayArrow as PlayIcon,
  Clear as ClearIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useCreateScan } from '../hooks/useScans';

const ScanForm = () => {
  const navigate = useNavigate();
  const createScanMutation = useCreateScan();

  const [formData, setFormData] = useState({
    target_url: '',
    scan_type: 'api',
    scan_policy: 'default',
    auth_username: '',
    auth_password: '',
    auth_token: '',
    max_scan_time: 1800, // 30 minutes default
    follow_redirects: true,
    scan_subdomains: false,
  });

  const [errors, setErrors] = useState({});
  const [showAdvanced, setShowAdvanced] = useState(false);

  const handleInputChange = (field, value) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
    // Clear error when user starts typing
    if (errors[field]) {
      setErrors(prev => ({
        ...prev,
        [field]: null
      }));
    }
  };

  const validateForm = () => {
    const newErrors = {};

    // URL validation
    if (!formData.target_url) {
      newErrors.target_url = 'Target URL is required';
    } else if (!formData.target_url.match(/^https?:\/\/.+/)) {
      newErrors.target_url = 'URL must start with http:// or https://';
    }

    // Max scan time validation
    if (formData.max_scan_time < 60) {
      newErrors.max_scan_time = 'Minimum scan time is 60 seconds';
    } else if (formData.max_scan_time > 36000) {
      newErrors.max_scan_time = 'Maximum scan time is 36000 seconds (10 hours)';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    try {
      const scanData = {
        target_url: formData.target_url,
        scan_type: formData.scan_type,
        scan_policy: formData.scan_policy,
        max_scan_time: formData.max_scan_time,
        follow_redirects: formData.follow_redirects,
        scan_subdomains: formData.scan_subdomains,
      };

      // Add authentication if provided
      if (formData.auth_username && formData.auth_password) {
        scanData.auth_username = formData.auth_username;
        scanData.auth_password = formData.auth_password;
      } else if (formData.auth_token) {
        scanData.auth_token = formData.auth_token;
      }

      const result = await createScanMutation.mutateAsync(scanData);

      // Navigate to scan results page
      navigate(`/scan/${result.data.scan_id}`);

    } catch (error) {
      console.error('Failed to create scan:', error);
    }
  };

  const clearForm = () => {
    setFormData({
      target_url: '',
      scan_type: 'api',
      scan_policy: 'default',
      auth_username: '',
      auth_password: '',
      auth_token: '',
      max_scan_time: 1800,
      follow_redirects: true,
      scan_subdomains: false,
    });
    setErrors({});
  };

  const formatDuration = (seconds) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const remainingSeconds = seconds % 60;

    if (hours > 0) {
      return `${hours}h ${minutes}m ${remainingSeconds}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${remainingSeconds}s`;
    } else {
      return `${remainingSeconds}s`;
    }
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Box display="flex" alignItems="center" mb={4}>
        <SecurityIcon sx={{ mr: 2, fontSize: 40 }} color="primary" />
        <Typography variant="h4" component="h1" fontWeight="bold">
          New Security Scan
        </Typography>
      </Box>

      <Card>
        <CardContent sx={{ p: 4 }}>
          <form onSubmit={handleSubmit}>
            <Grid container spacing={3}>
              {/* Basic Information */}
              <Grid item xs={12}>
                <Paper elevation={0} sx={{ p: 2, bgcolor: 'grey.50' }}>
                  <Typography variant="h6" gutterBottom display="flex" alignItems="center">
                    <HttpIcon sx={{ mr: 1 }} />
                    Target Configuration
                  </Typography>
                  <Divider sx={{ mb: 2 }} />
                </Paper>
              </Grid>

              {/* Target URL */}
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Target URL"
                  placeholder="https://api.example.com"
                  value={formData.target_url}
                  onChange={(e) => handleInputChange('target_url', e.target.value)}
                  error={!!errors.target_url}
                  helperText={errors.target_url}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <HttpIcon />
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>

              {/* Scan Type */}
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Scan Type</InputLabel>
                  <Select
                    value={formData.scan_type}
                    label="Scan Type"
                    onChange={(e) => handleInputChange('scan_type', e.target.value)}
                  >
                    <MenuItem value="api">API Security Scan</MenuItem>
                    <MenuItem value="full">Full Application Scan</MenuItem>
                    <MenuItem value="quick">Quick Vulnerability Scan</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              {/* Scan Policy */}
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Scan Policy</InputLabel>
                  <Select
                    value={formData.scan_policy}
                    label="Scan Policy"
                    onChange={(e) => handleInputChange('scan_policy', e.target.value)}
                  >
                    <MenuItem value="default">Default Policy</MenuItem>
                    <MenuItem value="strict">Strict Policy</MenuItem>
                    <MenuItem value="passive">Passive Policy</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              {/* Advanced Settings Toggle */}
              <Grid item xs={12}>
                <Box display="flex" justifyContent="space-between" alignItems="center">
                  <Typography variant="h6" display="flex" alignItems="center">
                    <SettingsIcon sx={{ mr: 1 }} />
                    Advanced Settings
                  </Typography>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={showAdvanced}
                        onChange={(e) => setShowAdvanced(e.target.checked)}
                      />
                    }
                    label="Show advanced options"
                  />
                </Box>
              </Grid>

              {/* Advanced Settings */}
              {showAdvanced && (
                <>
                  {/* Authentication */}
                  <Grid item xs={12}>
                    <Typography variant="subtitle1" gutterBottom>
                      Authentication (Optional)
                    </Typography>
                  </Grid>

                  <Grid item xs={12} md={6}>
                    <TextField
                      fullWidth
                      label="Username"
                      value={formData.auth_username}
                      onChange={(e) => handleInputChange('auth_username', e.target.value)}
                      placeholder="admin"
                    />
                  </Grid>

                  <Grid item xs={12} md={6}>
                    <TextField
                      fullWidth
                      label="Password"
                      type="password"
                      value={formData.auth_password}
                      onChange={(e) => handleInputChange('auth_password', e.target.value)}
                      placeholder="••••••••"
                    />
                  </Grid>

                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      label="Bearer Token (Alternative to username/password)"
                      value={formData.auth_token}
                      onChange={(e) => handleInputChange('auth_token', e.target.value)}
                      placeholder="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
                    />
                  </Grid>

                  {/* Scan Options */}
                  <Grid item xs={12}>
                    <Typography variant="subtitle1" gutterBottom>
                      Scan Options
                    </Typography>
                  </Grid>

                  <Grid item xs={12} md={4}>
                    <TextField
                      fullWidth
                      label="Max Scan Time (seconds)"
                      type="number"
                      value={formData.max_scan_time}
                      onChange={(e) => handleInputChange('max_scan_time', parseInt(e.target.value) || 0)}
                      error={!!errors.max_scan_time}
                      helperText={errors.max_scan_time || `Duration: ${formatDuration(formData.max_scan_time)}`}
                      inputProps={{ min: 60, max: 36000 }}
                    />
                  </Grid>

                  <Grid item xs={12} md={4}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={formData.follow_redirects}
                          onChange={(e) => handleInputChange('follow_redirects', e.target.checked)}
                        />
                      }
                      label="Follow redirects"
                    />
                  </Grid>

                  <Grid item xs={12} md={4}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={formData.scan_subdomains}
                          onChange={(e) => handleInputChange('scan_subdomains', e.target.checked)}
                        />
                      }
                      label="Scan subdomains"
                    />
                  </Grid>
                </>
              )}

              {/* Submit Buttons */}
              <Grid item xs={12}>
                <Box display="flex" gap={2} justifyContent="flex-end" mt={3}>
                  <Button
                    type="button"
                    variant="outlined"
                    startIcon={<ClearIcon />}
                    onClick={clearForm}
                  >
                    Clear Form
                  </Button>
                  <Button
                    type="submit"
                    variant="contained"
                    size="large"
                    startIcon={<PlayIcon />}
                    disabled={createScanMutation.isLoading}
                  >
                    {createScanMutation.isLoading ? 'Starting Scan...' : 'Start Security Scan'}
                  </Button>
                </Box>
              </Grid>
            </Grid>
          </form>

          {/* Loading State */}
          {createScanMutation.isLoading && (
            <Alert severity="info" sx={{ mt: 2 }}>
              Initiating security scan... This may take a few moments.
            </Alert>
          )}

          {/* Error Display */}
          {createScanMutation.isError && (
            <Alert severity="error" sx={{ mt: 2 }}>
              Failed to start scan: {createScanMutation.error?.response?.data?.detail || createScanMutation.error?.message}
            </Alert>
          )}
        </CardContent>
      </Card>
    </Container>
  );
};

export default ScanForm;
