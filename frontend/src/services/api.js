import axios from 'axios';

// Create axios instance with default configuration
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:8001',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for adding auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('authToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for handling errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized access - show toast notification instead of redirect
      localStorage.removeItem('authToken');
      // Show a toast notification for development
      if (typeof window !== 'undefined' && window.toast) {
        window.toast.error('Authentication required. Some features may not work properly.');
      }
      console.warn('API returned 401 - Authentication required');
    }
    return Promise.reject(error);
  }
);

// Authentication API
export const authAPI = {
  login: (credentials) => api.post('/api/auth/token/', credentials),
  refresh: (refreshToken) => api.post('/api/auth/token/refresh/', { refresh: refreshToken }),
  verify: (token) => api.post('/api/auth/token/verify/', { token }),
};

// Security Scans API
export const scansAPI = {
  // Get all scans
  getScans: (params) => api.get('/api/v1/scans/', { params }),

  // Get single scan
  getScan: (id) => api.get(`/api/v1/scans/${id}/`),

  // Create new scan
  createScan: (data) => api.post('/api/v1/scans/', data),

  // Cancel scan
  cancelScan: (id) => api.post(`/api/v1/scans/${id}/cancel/`),

  // Retry scan
  retryScan: (id) => api.post(`/api/v1/scans/${id}/retry/`),

  // Get scan report
  getScanReport: (id) => api.get(`/api/v1/scans/${id}/report`),

  // Export scan report
  exportScanReport: (id, format = 'json') =>
    api.get(`/api/v1/scans/${id}/export/`, {
      params: { format },
      responseType: 'blob'
    }),
};

// Vulnerabilities API
export const vulnerabilitiesAPI = {
  // Get all vulnerabilities
  getVulnerabilities: (params) => api.get('/api/v1/vulnerabilities/', { params }),

  // Get single vulnerability
  getVulnerability: (id) => api.get(`/api/v1/vulnerabilities/${id}/`),

  // Mark as resolved
  markResolved: (id) => api.post(`/api/v1/vulnerabilities/${id}/mark_resolved/`),

  // Mark as false positive
  markFalsePositive: (id) => api.post(`/api/v1/vulnerabilities/${id}/mark_false_positive/`),
};

// Compliance Reports API
export const complianceAPI = {
  // Get all compliance reports
  getReports: (params) => api.get('/api/v1/compliance-reports/', { params }),

  // Get single report
  getReport: (id) => api.get(`/api/v1/compliance-reports/${id}/`),

  // Create new report
  createReport: (data) => api.post('/api/v1/compliance-reports/', data),

  // Get compliance overview
  getComplianceOverview: () => api.get('/api/v1/compliance/overview/'),
};

// Statistics API
export const statisticsAPI = {
  // Get scan statistics
  getScanStatistics: () => api.get('/api/v1/statistics/scans/'),

  // Get vulnerability statistics
  getVulnerabilityStatistics: () => api.get('/api/v1/statistics/vulnerabilities/'),
};

// Health check API
export const healthAPI = {
  checkHealth: () => api.get('/api/health/'),
};

// Export default API instance
export default api;
