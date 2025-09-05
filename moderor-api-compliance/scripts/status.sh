#!/bin/bash

# MODEROR API Compliance Scanner Status Check Script

echo "🔍 Checking MODEROR API Compliance Scanner Status..."
echo

# Function to check if a port is open
check_port() {
    local host=$1
    local port=$2
    local service_name=$3

    if nc -z "$host" "$port" 2>/dev/null; then
        echo "✅ $service_name ($host:$port) - RUNNING"
        return 0
    else
        echo "❌ $service_name ($host:$port) - NOT ACCESSIBLE"
        return 1
    fi
}

# Function to check HTTP endpoint
check_http() {
    local url=$1
    local service_name=$2

    if curl -s --max-time 5 "$url" > /dev/null 2>&1; then
        echo "✅ $service_name ($url) - RESPONDING"
        return 0
    else
        echo "⚠️  $service_name ($url) - NOT RESPONDING"
        return 1
    fi
}

echo "🌐 Checking Network Services:"
echo "-----------------------------"

# Check container status
echo
echo "🐳 Docker Container Status:"
echo "---------------------------"
docker-compose ps

echo
echo "🔌 Service Connectivity:"
echo "------------------------"

# Check database connectivity
if docker-compose exec -T db pg_isready -U moderor_user -d moderor_compliance > /dev/null 2>&1; then
    echo "✅ PostgreSQL Database - CONNECTED"
else
    echo "❌ PostgreSQL Database - NOT CONNECTED"
fi

# Check Redis
if docker-compose exec -T redis redis-cli ping | grep -q PONG; then
    echo "✅ Redis Cache - CONNECTED"
else
    echo "❌ Redis Cache - NOT CONNECTED"
fi

echo
echo "🌐 HTTP Service Status:"
echo "-----------------------"

# Check HTTP services
check_http "http://localhost:3001" "Frontend Dashboard"
check_http "http://localhost:8001/api/health/" "Backend API"
check_http "http://localhost:3000/health" "MCP Server"
check_http "http://localhost:8080" "ZAP Scanner"
check_http "http://localhost:8000/api/v1/heartbeat" "ChromaDB"

echo
echo "📊 System Resources:"
echo "--------------------"

# Show container resource usage
echo "Docker Container Resources:"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"

echo
echo "💾 Disk Usage:"
echo "--------------"
df -h | grep -E "(Filesystem|/$|docker)"

echo
echo "🎯 Quick Actions:"
echo "-----------------"
echo "• View detailed logs: docker-compose logs -f [service-name]"
echo "• Restart service: docker-compose restart [service-name]"
echo "• Rebuild service: docker-compose up -d --build [service-name]"
echo "• Stop all services: docker-compose down"
echo "• Start all services: docker-compose up -d"

echo
echo "📝 Service URLs:"
echo "----------------"
echo "• Frontend Dashboard: http://localhost:3001"
echo "• Backend API: http://localhost:8001"
echo "• Django Admin: http://localhost:8001/admin"
echo "• ZAP Proxy UI: http://localhost:8080"
echo "• ChromaDB API: http://localhost:8000"
echo "• MCP Server: http://localhost:3000"

echo
echo "🔧 Environment Info:"
echo "--------------------"
echo "• Docker Platform: $DOCKER_DEFAULT_PLATFORM"
echo "• Working Directory: $(pwd)"
echo "• Python Version: $(python3 --version 2>/dev/null || echo 'Not found')"
echo "• Docker Version: $(docker --version 2>/dev/null || echo 'Not found')"
echo "• Docker Compose Version: $(docker-compose --version 2>/dev/null || echo 'Not found')"
