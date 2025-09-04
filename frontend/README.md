# Moderor Frontend

A modern React application for the Moderor API Compliance Tool, built with Material-UI and TanStack Query.

## 🚀 Features

- **Real-time Dashboard** - Live scan metrics and status updates
- **Interactive Scan Management** - Start, monitor, and manage security scans
- **Advanced Vulnerability Analysis** - Detailed vulnerability reports with AI insights
- **OWASP Compliance Visualization** - Beautiful charts showing API security compliance
- **Responsive Design** - Works seamlessly on desktop and mobile devices
- **Modern UX** - Toast notifications, loading states, and smooth interactions

## 🛠️ Tech Stack

- **React 18** - Modern React with hooks
- **Material-UI (MUI)** - Beautiful, accessible component library
- **TanStack Query** - Powerful data fetching and state management
- **React Router** - Declarative routing
- **Recharts** - Data visualization library
- **Axios** - HTTP client for API communication
- **React Toastify** - Toast notifications
- **Date-fns** - Date utility functions

## 📁 Project Structure

```
frontend/
├── public/
│   ├── index.html          # Main HTML template
│   └── manifest.json       # PWA manifest
├── src/
│   ├── components/         # React components
│   │   ├── Dashboard.js    # Main dashboard with metrics
│   │   ├── ScanForm.js     # Security scan configuration form
│   │   ├── ScanResults.js  # Scan results and vulnerability display
│   │   └── ComplianceChart.js # OWASP compliance visualization
│   ├── services/
│   │   └── api.js         # API service layer
│   ├── hooks/
│   │   └── useScans.js    # Custom React Query hooks
│   ├── App.js             # Main application component
│   ├── index.js           # Application entry point
│   └── index.css          # Global styles
├── package.json           # Dependencies and scripts
├── Dockerfile            # Container configuration
└── README.md             # This file
```

## 🚀 Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn
- Backend API server running (see backend README)

### Installation

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Start development server:**
   ```bash
   npm start
   ```

3. **Open browser:**
   ```
   http://localhost:3001
   ```

### Available Scripts

- `npm start` - Start development server
- `npm build` - Build for production
- `npm test` - Run tests
- `npm run eject` - Eject from Create React App

## 🔧 Configuration

### Environment Variables

Create a `.env.local` file in the root directory:

```env
REACT_APP_API_URL=http://localhost:8001
REACT_APP_API_BASE_URL=http://localhost:8001/api/v1
```

### Backend Integration

The frontend automatically proxies API calls to the backend during development. In production, ensure the backend is accessible at the configured API URL.

## 🎯 Key Features

### Dashboard
- Real-time scan metrics
- Active scan monitoring
- Recent scan history
- Vulnerability summary
- OWASP compliance overview

### Scan Management
- Intuitive scan configuration form
- Authentication options (Basic/Bearer)
- Advanced scan settings
- Real-time progress tracking
- Scan cancellation and retry

### Vulnerability Analysis
- Interactive vulnerability tables
- Risk level visualization
- False positive management
- Resolution tracking
- Detailed vulnerability information

### Compliance Visualization
- OWASP API Top 10 compliance charts
- Category-wise breakdown
- Compliance trend analysis
- Remediation recommendations
- Interactive data visualization

## 🔌 API Integration

The application uses a comprehensive API service layer:

```javascript
import { scansAPI, vulnerabilitiesAPI } from './services/api';

// Fetch scans
const scans = await scansAPI.getScans();

// Start new scan
const result = await scansAPI.createScan(scanData);
```

## 🎣 Custom Hooks

Powerful React Query hooks for data management:

```javascript
import { useScans, useScan, useCreateScan } from './hooks/useScans';

// Fetch scans with caching
const { data: scans, isLoading } = useScans();

// Get single scan with real-time updates
const { data: scan } = useScan(scanId);

// Create scan with optimistic updates
const createScanMutation = useCreateScan();
```

## 🎨 Styling & Theming

Built with Material-UI's theming system:

- **Light/Dark mode support**
- **Custom color palette**
- **Responsive breakpoints**
- **Accessible components**
- **Consistent spacing and typography**

## 📱 Responsive Design

- **Mobile-first approach**
- **Responsive grid layouts**
- **Adaptive navigation**
- **Touch-friendly interactions**
- **Optimized for all screen sizes**

## 🔒 Security Features

- **Input validation**
- **XSS protection**
- **CSRF protection**
- **Secure API communication**
- **Authentication state management**

## 🚀 Performance

- **Code splitting**
- **Lazy loading**
- **Query caching**
- **Optimistic updates**
- **Background refetching**

## 🧪 Testing

```bash
# Run tests
npm test

# Run tests with coverage
npm test -- --coverage
```

## 📦 Build & Deployment

```bash
# Build for production
npm run build

# Serve production build
npx serve -s build
```

## 🤝 Contributing

1. Follow the existing code style
2. Add tests for new features
3. Update documentation
4. Ensure responsive design
5. Test across different browsers

## 📄 License

This project is part of the Moderor API Compliance Tool suite.
