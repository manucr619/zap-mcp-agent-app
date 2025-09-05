#!/bin/bash

# MODEROR API Compliance Scanner Initialization Script
# For Apple Silicon MacBook (M1/M2)

echo "🚀 Initializing MODEROR API Compliance Scanner..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop and try again."
    exit 1
fi

# Set platform for Apple Silicon
export DOCKER_DEFAULT_PLATFORM=linux/arm64

# Create necessary directories
echo "📁 Creating project directories..."
mkdir -p backend/config
mkdir -p backend/apps/scans
mkdir -p frontend/src/components
mkdir -p frontend/src/services
mkdir -p frontend/src/hooks
mkdir -p zap-config/policies
mkdir -p mcp-server

# Generate Django secret key
echo "🔐 Generating Django secret key..."
DJANGO_SECRET=$(python3 -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())')
sed -i.bak "s/your-secret-key-here-change-in-production/$DJANGO_SECRET/" .env

# Generate JWT secret key
JWT_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
sed -i.bak "s/jwt-secret-key-change-in-production/$JWT_SECRET/" .env

# Generate encryption key
ENCRYPTION_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
sed -i.bak "s/your-32-byte-encryption-key-here/$ENCRYPTION_KEY/" .env

echo "🔧 Setting up Docker services..."

# Build and start services
docker-compose build --no-cache

echo "🌟 Starting MODEROR API Compliance Scanner..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 30

# Check service health
echo "🏥 Checking service health..."

services=("db:5432" "redis:6379" "chromadb:8000" "zap-scanner:8080" "mcp-server:3000" "backend:8000" "frontend:3000")

for service in "${services[@]}"; do
    IFS=':' read -r name port <<< "$service"
    if docker-compose exec "$name" sh -c "nc -z localhost $port" 2>/dev/null; then
        echo "✅ $name service is healthy"
    else
        echo "⚠️  $name service may need more time to start"
    fi
done

# Run Django migrations
echo "🗄️  Running Django migrations..."
docker-compose exec backend python manage.py makemigrations
docker-compose exec backend python manage.py migrate

# Create Django superuser (optional)
read -p "Create Django superuser? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker-compose exec backend python manage.py createsuperuser
fi

echo "
🎉 MODEROR API Compliance Scanner is ready!

📊 Access your services:
- Frontend Dashboard: http://localhost:3001
- Backend API: http://localhost:8001
- Django Admin: http://localhost:8001/admin
- ZAP Proxy: http://localhost:8080
- ChromaDB: http://localhost:8000
- MCP Server: http://localhost:3000

📝 Next steps:
1. Open http://localhost:3001 in your browser
2. Start a security scan by entering a target URL
3. Monitor scan progress in real-time
4. Review AI-powered vulnerability analysis

🔧 Useful commands:
- View logs: docker-compose logs -f [service-name]
- Restart service: docker-compose restart [service-name]
- Stop all services: docker-compose down
- Update services: docker-compose up -d --build

Happy scanning! 🛡️


"
