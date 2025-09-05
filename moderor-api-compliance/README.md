# Moderor API Compliance Tool

A comprehensive API compliance and security testing platform built with Django, React, FastAPI, and AI-powered MCP (Model Context Protocol) integration.

## Architecture

This project follows a production-ready microservices architecture with the following components:

### Core Services
- **Backend** (Django + Django REST Framework): Core API and business logic with Celery for background tasks
- **Frontend** (React): Modern user interface for managing scans and viewing results
- **MCP Server** (FastAPI): Model Context Protocol server for AI-assisted testing and compliance analysis
- **Database** (PostgreSQL 15): Primary data persistence with connection pooling
- **Cache** (Redis 7): High-performance caching and task queue management

### AI & ML Services
- **ChromaDB**: Vector database for semantic search and AI embeddings
- **OWASP ZAP Scanner**: Automated security scanning and vulnerability assessment

### Background Processing
- **Celery Worker**: Asynchronous task processing for long-running scans
- **Celery Beat**: Scheduled tasks for periodic compliance checks and maintenance

## Services Overview

### Database & Caching Layer
- **PostgreSQL (port 5432)**: Primary database for application data, user sessions, and scan results
- **Redis (port 6379)**: High-performance caching and Celery task queue backend

### AI & Vector Services
- **ChromaDB (port 8000)**: Vector database for storing and retrieving AI embeddings, enabling semantic search
- **MCP Server (port 3000)**: FastAPI-based Model Context Protocol server for AI agent integration

### Security & Scanning
- **OWASP ZAP (port 8080)**: Automated web application security scanner with API testing capabilities

### Application Layer
- **Django Backend (port 8001)**: REST API with Celery integration for background task processing
- **React Frontend (port 3001)**: Modern web interface for managing scans and viewing compliance reports

## Project Structure

```
moderor-api-compliance/
├── docker-compose.yml          # Multi-service orchestration with health checks
├── env.template               # Environment variables template
├── README.md                   # Comprehensive documentation
├── backend/                    # Django backend application
│   ├── Dockerfile             # Python 3.11 container with ARM64 support
│   ├── requirements.txt       # Django, DRF, Celery, PostgreSQL, Redis
│   ├── manage.py             # Django management script
│   ├── config/               # Django settings with production config
│   └── apps/                 # Django applications
├── frontend/                  # React frontend application
│   ├── Dockerfile            # Node.js 18 container with ARM64 support
│   ├── package.json          # React with Material-UI, Axios, Recharts
│   └── src/                  # React source code with TypeScript support
├── mcp-server/               # MCP server for AI integration
│   ├── Dockerfile           # FastAPI MCP server with ARM64 support
│   ├── requirements.txt     # FastAPI, uvicorn, WebSockets, ChromaDB client
│   └── server.py            # AI-assisted testing server with ZAP integration
├── zap-config/              # OWASP ZAP configuration
│   └── policies/           # Custom security scan policies
└── scripts/                # Utility scripts
    └── init.sh            # Executable initialization and setup script
```

## Prerequisites

- Docker & Docker Compose (v2.0+)
- Python 3.11+ (for local development)
- Node.js 18+ (for local development)
- Git
- At least 8GB RAM (recommended for all services)
- ARM64 or x86_64 architecture

## Quick Start

1. **Clone and navigate to the project:**
   ```bash
   cd moderor-api-compliance
   ```

2. **Set up environment variables:**
   ```bash
   cp env.template .env
   # Edit .env with your configuration (optional - defaults will work for development)
   ```

3. **Run the initialization script:**
   ```bash
   ./scripts/init.sh
   ```

   Or manually:
   ```bash
   # Build and start all services
   docker-compose up --build -d

   # Check service health
   docker-compose ps

   # View logs
   docker-compose logs -f
   ```

4. **Access the applications:**
   - **Frontend UI**: http://localhost:3001
   - **Backend API**: http://localhost:8001
   - **MCP Server**: http://localhost:3000
   - **ChromaDB**: http://localhost:8000
   - **ZAP Scanner**: http://localhost:8080
   - **PostgreSQL**: localhost:5432
   - **Redis**: localhost:6379
   - **API Documentation**: http://localhost:8001/docs (Django REST Framework)

## Development

### Backend (Django)
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python manage.py runserver
```

### Frontend (React)
```bash
cd frontend
npm install
npm start
```

### MCP Server
```bash
cd mcp-server
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python server.py
```

## API Endpoints

### Backend API
- `GET /api/health/` - Health check
- `POST /api/scan/` - Start security scan
- `GET /api/scan/{id}/` - Get scan results

### MCP Server
- `GET /` - Server info
- `GET /health` - Health check
- `POST /scan` - Start AI-assisted scan
- `GET /policies` - Get available policies

## Configuration

Key environment variables (see `.env.example`):

- `DEBUG`: Enable/disable debug mode
- `SECRET_KEY`: Django secret key
- `DB_*`: Database configuration
- `ZAP_API_KEY`: OWASP ZAP API key
- `MCP_SERVER_PORT`: MCP server port

## Security Features

- OWASP ZAP integration for automated scanning
- JWT authentication
- CORS protection
- Input validation
- Rate limiting
- Security headers

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

This project is licensed under the MIT License.
