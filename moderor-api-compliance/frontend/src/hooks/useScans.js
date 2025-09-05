import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  scansAPI,
  vulnerabilitiesAPI,
  complianceAPI,
  statisticsAPI,
  healthAPI
} from '../services/api';

// Query keys for React Query
export const QUERY_KEYS = {
  SCANS: 'scans',
  SCAN: (id) => ['scan', id],
  SCAN_REPORT: (id) => ['scan-report', id],
  VULNERABILITIES: 'vulnerabilities',
  COMPLIANCE_REPORTS: 'compliance-reports',
  COMPLIANCE_OVERVIEW: 'compliance-overview',
  SCAN_STATISTICS: 'scan-statistics',
  VULNERABILITY_STATISTICS: 'vulnerability-statistics',
  HEALTH: 'health',
};

// Custom hook for fetching all scans
export const useScans = (params = {}) => {
  return useQuery({
    queryKey: [QUERY_KEYS.SCANS, params],
    queryFn: () => scansAPI.getScans(params),
    staleTime: 30000, // 30 seconds
    refetchInterval: 10000, // Refetch every 10 seconds for real-time updates
    retry: 2,
  });
};

// Custom hook for fetching a single scan
export const useScan = (id) => {
  return useQuery({
    queryKey: QUERY_KEYS.SCAN(id),
    queryFn: () => scansAPI.getScan(id),
    enabled: !!id,
    staleTime: 15000, // 15 seconds
    refetchInterval: (data) => {
      // Stop polling if scan is completed or failed
      if (data?.status && ['completed', 'failed', 'cancelled'].includes(data.status)) {
        return false;
      }
      return 5000; // Poll every 5 seconds for active scans
    },
  });
};

// Custom hook for fetching scan report
export const useScanReport = (id) => {
  return useQuery({
    queryKey: QUERY_KEYS.SCAN_REPORT(id),
    queryFn: () => scansAPI.getScanReport(id),
    enabled: !!id,
    staleTime: 60000, // 1 minute
  });
};

// Custom hook for creating a new scan
export const useCreateScan = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: scansAPI.createScan,
    onSuccess: (data) => {
      toast.success('Security scan initiated successfully!');
      // Invalidate and refetch scans list
      queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.SCANS] });
      // Add the new scan to cache
      queryClient.setQueryData(QUERY_KEYS.SCAN(data.id), data);
    },
    onError: (error) => {
      toast.error(`Failed to start scan: ${error.response?.data?.detail || error.message}`);
    },
  });
};

// Custom hook for canceling a scan
export const useCancelScan = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id }) => scansAPI.cancelScan(id),
    onSuccess: (_, { id }) => {
      toast.info('Scan cancelled successfully');
      // Update scan status in cache
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.SCAN(id) });
      queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.SCANS] });
    },
    onError: (error) => {
      toast.error(`Failed to cancel scan: ${error.response?.data?.detail || error.message}`);
    },
  });
};

// Custom hook for retrying a scan
export const useRetryScan = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id }) => scansAPI.retryScan(id),
    onSuccess: (_, { id }) => {
      toast.success('Scan retry initiated successfully!');
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.SCAN(id) });
      queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.SCANS] });
    },
    onError: (error) => {
      toast.error(`Failed to retry scan: ${error.response?.data?.detail || error.message}`);
    },
  });
};

// Custom hook for fetching vulnerabilities
export const useVulnerabilities = (params = {}) => {
  return useQuery({
    queryKey: [QUERY_KEYS.VULNERABILITIES, params],
    queryFn: () => vulnerabilitiesAPI.getVulnerabilities(params),
    staleTime: 30000,
  });
};

// Custom hook for marking vulnerability as resolved
export const useMarkVulnerabilityResolved = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id }) => vulnerabilitiesAPI.markResolved(id),
    onSuccess: (_, { id }) => {
      toast.success('Vulnerability marked as resolved');
      queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.VULNERABILITIES] });
    },
    onError: (error) => {
      toast.error(`Failed to mark vulnerability as resolved: ${error.response?.data?.detail || error.message}`);
    },
  });
};

// Custom hook for marking vulnerability as false positive
export const useMarkVulnerabilityFalsePositive = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id }) => vulnerabilitiesAPI.markFalsePositive(id),
    onSuccess: (_, { id }) => {
      toast.success('Vulnerability marked as false positive');
      queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.VULNERABILITIES] });
    },
    onError: (error) => {
      toast.error(`Failed to mark vulnerability as false positive: ${error.response?.data?.detail || error.message}`);
    },
  });
};

// Custom hook for compliance reports
export const useComplianceReports = (params = {}) => {
  return useQuery({
    queryKey: [QUERY_KEYS.COMPLIANCE_REPORTS, params],
    queryFn: () => complianceAPI.getReports(params),
    staleTime: 60000, // 1 minute
  });
};

// Custom hook for compliance overview
export const useComplianceOverview = () => {
  return useQuery({
    queryKey: [QUERY_KEYS.COMPLIANCE_OVERVIEW],
    queryFn: () => complianceAPI.getComplianceOverview(),
    staleTime: 300000, // 5 minutes
  });
};

// Custom hook for scan statistics
export const useScanStatistics = () => {
  return useQuery({
    queryKey: [QUERY_KEYS.SCAN_STATISTICS],
    queryFn: () => statisticsAPI.getScanStatistics(),
    staleTime: 60000, // 1 minute
    refetchInterval: 300000, // Refetch every 5 minutes
  });
};

// Custom hook for vulnerability statistics
export const useVulnerabilityStatistics = () => {
  return useQuery({
    queryKey: [QUERY_KEYS.VULNERABILITY_STATISTICS],
    queryFn: () => statisticsAPI.getVulnerabilityStatistics(),
    staleTime: 60000, // 1 minute
    refetchInterval: 300000, // Refetch every 5 minutes
  });
};

// Custom hook for health check
export const useHealthCheck = () => {
  return useQuery({
    queryKey: [QUERY_KEYS.HEALTH],
    queryFn: () => healthAPI.checkHealth(),
    staleTime: 30000, // 30 seconds
    refetchInterval: 60000, // Check every minute
    retry: 3,
  });
};

// Custom hook for exporting scan report
export const useExportScanReport = () => {
  return useMutation({
    mutationFn: ({ id, format }) => scansAPI.exportScanReport(id, format),
    onSuccess: (data, { format }) => {
      // Create download link
      const url = window.URL.createObjectURL(new Blob([data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `scan-report.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      toast.success('Report downloaded successfully!');
    },
    onError: (error) => {
      toast.error(`Failed to download report: ${error.response?.data?.detail || error.message}`);
    },
  });
};
