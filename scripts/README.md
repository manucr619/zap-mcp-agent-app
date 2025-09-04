# Scripts Directory

This directory contains utility scripts for the Moderor API Compliance Tool.

## 📋 Available Scripts

### `init.sh` - Main Initialization Script

**Purpose**: Complete setup and initialization of the Moderor API Compliance Tool

**Features**:
- ✅ Apple Silicon (ARM64) support
- ✅ Automatic directory creation
- ✅ Secure secret key generation
- ✅ Docker service health checks
- ✅ Database migrations
- ✅ Optional superuser creation

**Usage**:
```bash
# Make executable (if not already)
chmod +x scripts/init.sh

# Run initialization
./scripts/init.sh
```

**What it does**:

### `status.sh` - Service Status Check Script

**Purpose**: Comprehensive health check for all MODEROR services

**Features**:
- ✅ Docker container status monitoring
- ✅ Network connectivity checks
- ✅ HTTP endpoint availability testing
- ✅ Database and cache connectivity
- ✅ System resource monitoring
- ✅ Quick action commands reference

**Usage**:
```bash
# Check all service statuses
./scripts/status.sh

# Monitor continuously (every 30 seconds)
watch -n 30 ./scripts/status.sh
```

**What it checks**:
1. **Docker Containers**: Status and resource usage
2. **Network Services**: Port availability and connectivity
3. **HTTP Endpoints**: API and web service responsiveness
4. **Databases**: PostgreSQL and Redis connectivity
5. **System Resources**: CPU, memory, and disk usage
6. **Service URLs**: Quick reference for all endpoints

## 🔧 Manual Commands

If you prefer to run commands manually instead of using the init script:

### Directory Setup
```bash
mkdir -p backend/config backend/apps/scans
mkdir -p frontend/src/components frontend/src/services frontend/src/hooks
mkdir -p zap-config/policies mcp-server
```

### Environment Configuration
```bash
# Generate secure keys
DJANGO_SECRET=$(python3 -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())')
JWT_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
ENCRYPTION_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')

# Update .env file
sed -i.bak "s/your-secret-key-here-change-in-production/$DJANGO_SECRET/" .env
sed -i.bak "s/jwt-secret-key-change-in-production/$JWT_SECRET/" .env
sed -i.bak "s/your-32-byte-encryption-key-here/$ENCRYPTION_KEY/" .env
```

### Docker Operations
```bash
# Set platform for Apple Silicon
export DOCKER_DEFAULT_PLATFORM=linux/arm64

# Build and start services
docker-compose build --no-cache
docker-compose up -d

# Check service health
docker-compose ps

# View logs
docker-compose logs -f [service-name]

# Run migrations
docker-compose exec backend python manage.py makemigrations
docker-compose exec backend python manage.py migrate

# Create superuser
docker-compose exec backend python manage.py createsuperuser
```

## 🚨 Troubleshooting

### Docker Issues
```bash
# Check Docker status
docker info

# Clean up containers
docker-compose down -v

# Rebuild specific service
docker-compose build --no-cache [service-name]
```

### Permission Issues
```bash
# Fix script permissions
chmod +x scripts/init.sh
```

### Network Issues
```bash
# Check port availability
lsof -i :3001
lsof -i :8001

# Stop conflicting services
docker-compose down
```

### Database Issues
```bash
# Reset database
docker-compose down -v
docker-compose up -d db
docker-compose exec backend python manage.py migrate
```

## 📊 Service Endpoints

After successful initialization:

- **Frontend Dashboard**: http://localhost:3001
- **Backend API**: http://localhost:8001
- **Django Admin**: http://localhost:8001/admin
- **ZAP Proxy UI**: http://localhost:8080
- **ChromaDB API**: http://localhost:8000
- **MCP Server**: http://localhost:3000
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

## 🔄 Development Workflow

### Daily Development
```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f backend

# Run Django commands
docker-compose exec backend python manage.py shell

# Stop services
docker-compose down
```

### Code Updates
```bash
# Rebuild after code changes
docker-compose up -d --build backend
docker-compose up -d --build frontend
```

### Database Updates
```bash
# After model changes
docker-compose exec backend python manage.py makemigrations
docker-compose exec backend python manage.py migrate
```

## 📝 Adding New Scripts

When adding new scripts to this directory:

1. **Make executable**: `chmod +x scripts/your-script.sh`
2. **Add documentation**: Update this README.md
3. **Include error handling**: Add proper error checking
4. **Follow naming convention**: Use lowercase with hyphens
5. **Add shebang**: `#!/bin/bash` at the top

## 🆘 Support

If you encounter issues:

1. Check the logs: `docker-compose logs -f`
2. Verify Docker is running: `docker info`
3. Check port availability
4. Ensure all required files exist
5. Review environment variables in `.env`

For additional help, refer to the main project documentation or create an issue in the repository.
