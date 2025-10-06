#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETBOX_DOCKER_DIR="${SCRIPT_DIR}/netbox-docker"
PLUGIN_DIR="${SCRIPT_DIR}/netbox-netbox-auto-discovery-plugin"

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     NetBox Auto Discovery Plugin - Monorepo Setup           ║${NC}"
echo -e "${CYAN}║     Author: hamidzamani445@gmail.com                        ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to print status messages
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${CYAN}[i]${NC} $1"
}

# Function to check command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Check prerequisites
print_status "Checking prerequisites..."
echo ""

if ! command_exists docker; then
    print_error "Docker is not installed"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi
print_success "Docker found: $(docker --version | head -n1)"

if ! command_exists docker && ! docker compose version &> /dev/null; then
    print_error "Docker Compose is not installed"
    echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi
print_success "Docker Compose found: $(docker compose version 2>&1 | head -n1)"

# Check if Docker daemon is running
if ! docker info &> /dev/null; then
    print_error "Docker daemon is not running"
    echo "Please start Docker and try again"
    exit 1
fi
print_success "Docker daemon is running"

# Check if jq is available (needed for JSON parsing)
if ! command_exists jq; then
    print_warning "jq is not installed - will use alternative health check method"
    USE_JQ=false
else
    USE_JQ=true
fi

echo ""

# Verify directory structure
print_status "Verifying directory structure..."

if [ ! -d "$NETBOX_DOCKER_DIR" ]; then
    print_error "NetBox-Docker directory not found at: $NETBOX_DOCKER_DIR"
    exit 1
fi
print_success "Found netbox-docker directory"

if [ ! -d "$PLUGIN_DIR" ]; then
    print_error "Plugin directory not found at: $PLUGIN_DIR"
    exit 1
fi
print_success "Found plugin directory"

# Verify required files
if [ ! -f "$NETBOX_DOCKER_DIR/docker-compose.yml" ]; then
    print_error "docker-compose.yml not found"
    exit 1
fi

if [ ! -f "$NETBOX_DOCKER_DIR/docker-compose.override.yml" ]; then
    print_error "docker-compose.override.yml not found"
    exit 1
fi

if [ ! -f "$NETBOX_DOCKER_DIR/Dockerfile-Plugins" ]; then
    print_error "Dockerfile-Plugins not found"
    exit 1
fi

if [ ! -f "$PLUGIN_DIR/pyproject.toml" ]; then
    print_error "Plugin pyproject.toml not found"
    exit 1
fi

print_success "All required files present"
echo ""

# Clean up any existing containers
print_status "Cleaning up any existing NetBox containers..."
cd "$NETBOX_DOCKER_DIR"

# Stop and remove old containers
docker compose down -v 2>/dev/null || true
print_success "Cleanup complete"
echo ""

# Build the custom NetBox image with plugin
print_status "Building NetBox Docker image with Auto Discovery plugin..."
print_info "This may take 5-15 minutes on first run..."
echo ""

docker compose build --no-cache netbox

if [ $? -ne 0 ]; then
    print_error "Docker build failed"
    echo ""
    echo "Common issues:"
    echo "  - Check if port 8000 is already in use"
    echo "  - Verify Docker has enough resources (4GB RAM minimum)"
    echo "  - Check docker-compose.override.yml paths are correct"
    exit 1
fi

print_success "Docker image built successfully"
echo ""

# Start all services
print_status "Starting NetBox services..."
print_info "Starting: PostgreSQL, Redis, Redis-Cache, NetBox, NetBox-Worker"
echo ""

# Start base services first (postgres, redis)
docker compose up -d postgres redis redis-cache

if [ $? -ne 0 ]; then
    print_error "Failed to start base services"
    exit 1
fi

print_info "Base services (PostgreSQL, Redis) started, waiting for health checks..."
echo ""

# Wait for PostgreSQL to be ready
print_status "Waiting for PostgreSQL to be ready..."
max_attempts=60
attempt=0

while ! docker compose exec -T postgres pg_isready -U netbox > /dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ $attempt -ge $max_attempts ]; then
        print_error "PostgreSQL failed to start after $max_attempts attempts"
        echo ""
        print_info "Check logs with: cd $NETBOX_DOCKER_DIR && docker compose logs postgres"
        exit 1
    fi
    echo -n "."
    sleep 2
done

echo ""
print_success "PostgreSQL is ready"
echo ""

# Wait for Redis to be ready
print_status "Waiting for Redis to be ready..."
attempt=0
max_attempts=30

while ! docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD:-H733kdjudDq4kt44Dfwt4}" ping > /dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ $attempt -ge $max_attempts ]; then
        print_error "Redis failed to start after $max_attempts attempts"
        exit 1
    fi
    echo -n "."
    sleep 1
done

echo ""
print_success "Redis is ready"
echo ""

# Now start NetBox service and wait for it to be healthy
print_status "Starting NetBox application..."
docker compose up -d netbox

if [ $? -ne 0 ]; then
    print_error "Failed to start NetBox"
    exit 1
fi

print_info "NetBox container started, waiting for it to become healthy..."
print_info "This includes running all database migrations (may take 3-5 minutes on first run)"
echo ""

# Wait for Docker's health check to pass (up to 5 minutes)
# The docker-compose.override.yml extends healthcheck start_period to 300s
print_status "Waiting for NetBox healthcheck to pass (timeout: 5 minutes)..."
echo ""

attempt=0
max_attempts=20  # 20 attempts * 15 seconds = 5 minutes total

while [ $attempt -lt $max_attempts ]; do
    # Check container health status
    if [ "$USE_JQ" = true ]; then
        health_status=$(docker compose ps netbox --format json 2>/dev/null | jq -r '.[0].Health // "unknown"' 2>/dev/null || echo "unknown")
    else
        if docker compose ps netbox | grep -q "(healthy)"; then
            health_status="healthy"
        elif docker compose ps netbox | grep -q "(unhealthy)"; then
            health_status="unhealthy"
        else
            health_status="starting"
        fi
    fi

    # Success! Container is healthy
    if [ "$health_status" = "healthy" ]; then
        echo ""
        print_success "NetBox is healthy and ready!"
        break
    fi

    # Container became unhealthy - something is wrong
    if [ "$health_status" = "unhealthy" ]; then
        echo ""
        print_error "NetBox container became unhealthy"
        echo ""
        print_info "Showing last 50 lines of logs:"
        docker compose logs netbox --tail 50
        echo ""
        exit 1
    fi

    # Check if container crashed
    if ! docker compose ps netbox | grep -q "Up"; then
        echo ""
        print_error "NetBox container stopped unexpectedly"
        echo ""
        print_info "Showing last 50 lines of logs:"
        docker compose logs netbox --tail 50
        echo ""
        exit 1
    fi

    # Show progress indicator
    elapsed=$((attempt * 15))
    if [ $((attempt % 4)) -eq 0 ]; then
        echo -n " [${elapsed}s]"
    else
        echo -n "."
    fi

    attempt=$((attempt + 1))
    sleep 15
done

# Check if we timed out
if [ $attempt -ge $max_attempts ]; then
    echo ""
    print_error "NetBox failed to become healthy after 5 minutes"
    echo ""
    print_info "This might indicate:"
    echo "  - Migrations are taking longer than expected"
    echo "  - Database connection issues"
    echo "  - Plugin installation problems"
    echo ""
    print_info "Showing last 50 lines of logs:"
    docker compose logs netbox --tail 50
    echo ""
    print_info "You can check the full logs with:"
    echo "  cd $NETBOX_DOCKER_DIR && docker compose logs -f netbox"
    exit 1
fi

echo ""# Now start the worker
print_status "Starting NetBox worker..."
docker compose up -d netbox-worker

if [ $? -ne 0 ]; then
    print_error "Failed to start NetBox worker"
    exit 1
fi

print_success "All services started successfully"
echo ""

# Run core NetBox migrations
print_status "Running NetBox core migrations..."
docker compose exec -T netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py migrate --no-input 2>&1 | grep -v "No changes detected" || true
print_success "Core migrations complete"
echo ""

# Run plugin migrations
print_status "Running Auto Discovery plugin migrations..."
docker compose exec -T netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py migrate netbox_netbox_auto_discovery_plugin --no-input

if [ $? -ne 0 ]; then
    print_error "Plugin migrations failed"
    echo ""
    print_info "This might happen if the plugin is not installed correctly"
    print_info "Check logs with: cd $NETBOX_DOCKER_DIR && docker compose logs netbox"
    exit 1
fi

print_success "Plugin migrations complete"
echo ""

# Collect static files
print_status "Collecting static files..."
docker compose exec -T netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py collectstatic --no-input > /dev/null 2>&1
print_success "Static files collected"
echo ""

# Verify plugin is installed
print_status "Verifying plugin installation..."
plugin_check=$(docker compose exec -T netbox /opt/netbox/venv/bin/pip list | grep netbox-netbox-auto-discovery-plugin || true)

if [ -z "$plugin_check" ]; then
    print_warning "Plugin not found in pip list, but this might be normal for editable installs"
else
    print_success "Plugin installed: $plugin_check"
fi
echo ""

# Restart NetBox to ensure everything is loaded
print_status "Restarting NetBox services to load plugin..."
docker compose restart netbox
sleep 10
print_success "NetBox restarted"
echo ""

# Wait for NetBox to be fully ready
print_status "Waiting for NetBox to be fully operational..."
max_attempts=90
attempt=0

until curl -s -f http://localhost:8000/login/ > /dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ $attempt -ge $max_attempts ]; then
        print_warning "NetBox web interface may still be starting..."
        print_info "Check status with: cd $NETBOX_DOCKER_DIR && docker compose logs -f netbox"
        break
    fi
    echo -n "."
    sleep 2
done

echo ""

if curl -s -f http://localhost:8000/login/ > /dev/null 2>&1; then
    print_success "NetBox web interface is ready!"
else
    print_warning "NetBox might still be initializing. Give it another minute."
fi

echo ""

# Ensure NetBox worker is started (critical for background jobs!)
print_status "Starting NetBox worker for background job processing..."
docker compose up -d netbox-worker

# Wait for worker to be healthy
sleep 5
worker_status=$(docker compose ps netbox-worker --format json 2>/dev/null | grep -o '"Health":"[^"]*"' | cut -d'"' -f4 || echo "unknown")

if [ "$worker_status" = "healthy" ] || docker compose ps netbox-worker | grep -q "Up"; then
    print_success "NetBox worker is running"
else
    print_warning "Worker may still be starting. This is needed for scan jobs!"
    print_info "Check with: docker compose ps netbox-worker"
fi

echo ""

# Show service status
print_status "Service Status:"
echo ""
docker compose ps
echo ""

# Print success banner
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    🎉 Setup Complete! 🎉                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Print access information
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                   Access Information                         ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}NetBox URL:${NC}       http://localhost:8000"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT: Create Superuser${NC}"
echo ""
echo "Before you can login, you need to create a superuser account:"
echo ""
echo -e "${CYAN}cd $NETBOX_DOCKER_DIR${NC}"
echo -e "${CYAN}docker compose exec netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py createsuperuser${NC}"
echo ""
echo "Follow the prompts to create your admin account."
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    Quick Start Guide                         ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}1. Create Superuser:${NC}"
echo "   cd $NETBOX_DOCKER_DIR"
echo "   docker compose exec netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py createsuperuser"
echo ""
echo "   OR use non-interactive mode:"
echo "   docker compose exec netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py createsuperuser --noinput --username admin --email admin@example.com"
echo "   # Then set password:"
echo "   echo \"from django.contrib.auth import get_user_model; User = get_user_model(); user = User.objects.get(username='admin'); user.set_password('admin'); user.save()\" | docker compose exec -T netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py shell"
echo ""
echo -e "${YELLOW}2. Access NetBox:${NC}"
echo "   Open your browser and navigate to: http://localhost:8000"
echo ""
echo -e "${YELLOW}2. Login:${NC}"
echo "   Username: admin"
echo "   Password: admin"
echo ""
echo -e "${YELLOW}3. Navigate to the Plugin:${NC}"
echo "   Click: Plugins → Auto Discovery → Scanners"
echo ""
echo -e "${YELLOW}4. Create a Scanner:${NC}"
echo "   a) Network Range Scan:"
echo "      - Name: Test Network Scan"
echo "      - Type: Network Range Scan"
echo "      - IP Range: 192.168.1.0/24 (adjust to your network)"
echo "      - Status: Active"
echo ""
echo "   b) Cisco Switch Scan (requires Cisco device):"
echo "      - Name: Test Cisco Scan"
echo "      - Type: Cisco Switch Scan"
echo "      - Target Host: <your-cisco-switch-ip>"
echo "      - Port: 22 (SSH) or 161 (SNMP)"
echo "      - Protocol: SSH or SNMP"
echo "      - Username/Password or Community String"
echo ""
echo -e "${YELLOW}6. Run a Scan:${NC}"
echo "   - Click on your scanner"
echo "   - Click the 'Run Scan' button"
echo "   - View results in the 'Scan Runs' tab"
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    Useful Commands                           ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}View logs:${NC}"
echo "  cd $NETBOX_DOCKER_DIR"
echo "  docker compose logs -f netbox"
echo ""
echo -e "${BLUE}Stop services:${NC}"
echo "  cd $NETBOX_DOCKER_DIR"
echo "  docker compose down"
echo ""
echo -e "${BLUE}Start services:${NC}"
echo "  cd $NETBOX_DOCKER_DIR"
echo "  docker compose up -d"
echo ""
echo -e "${BLUE}Restart services:${NC}"
echo "  cd $NETBOX_DOCKER_DIR"
echo "  docker compose restart"
echo ""
echo -e "${BLUE}Enter NetBox container:${NC}"
echo "  cd $NETBOX_DOCKER_DIR"
echo "  docker compose exec netbox bash"
echo ""
echo -e "${BLUE}View background jobs:${NC}"
echo "  In NetBox UI: System → Background Jobs"
echo ""
echo -e "${BLUE}Access Python shell:${NC}"
echo "  docker compose exec netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py shell"
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    API Access                                ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Get API Token:${NC}"
echo "  1. Login to NetBox"
echo "  2. Click on your username (top right)"
echo "  3. Go to 'API Tokens'"
echo "  4. Click 'Add a token'"
echo "  5. Generate and copy your token"
echo ""
echo -e "${YELLOW}Test API:${NC}"
echo "  # List scanners"
echo "  curl -H \"Authorization: Token YOUR_TOKEN\" \\"
echo "       http://localhost:8000/api/plugins/auto-discovery/scanners/"
echo ""
echo "  # Create scanner via API"
echo "  curl -X POST -H \"Authorization: Token YOUR_TOKEN\" \\"
echo "       -H \"Content-Type: application/json\" \\"
echo "       -d '{\"name\": \"API Scanner\", \"scanner_type\": \"network_range\", "
echo "            \"status\": \"active\", \"ip_range\": \"10.0.0.0/24\"}' \\"
echo "       http://localhost:8000/api/plugins/auto-discovery/scanners/"
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    Documentation                             ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  README:              cat $PLUGIN_DIR/README.md"
echo "  Deployment Guide:    cat $PLUGIN_DIR/DEPLOYMENT_GUIDE.md"
echo "  Architecture:        cat $PLUGIN_DIR/ARCHITECTURE.md"
echo "  Technical Details:   cat $PLUGIN_DIR/TECHNICAL_VERIFICATION.md"
echo "  API Docs:            http://localhost:8000/api/docs/"
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    Troubleshooting                           ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}If you encounter issues:${NC}"
echo ""
echo "  1. Check logs:"
echo "     cd $NETBOX_DOCKER_DIR && docker compose logs -f netbox"
echo ""
echo "  2. Verify all containers are running (including netbox-worker):"
echo "     cd $NETBOX_DOCKER_DIR && docker compose ps"
echo ""
echo "  3. If netbox-worker is not running (CRITICAL for scans):"
echo "     cd $NETBOX_DOCKER_DIR"
echo "     docker compose up -d netbox-worker"
echo "     docker compose logs -f netbox-worker"
echo ""
echo "  4. Restart services:"
echo "     cd $NETBOX_DOCKER_DIR && docker compose restart"
echo ""
echo "  4. Full rebuild (WARNING: destroys all data):"
echo "     cd $NETBOX_DOCKER_DIR"
echo "     docker compose down -v"
echo "     cd $SCRIPT_DIR"
echo "     ./setup-monorepo.sh"
echo ""
echo "  5. Check plugin installation:"
echo "     docker compose exec netbox /opt/netbox/venv/bin/pip list | grep auto-discovery"
echo ""
echo "  6. Verify plugin is loaded:"
echo "     docker compose exec netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py shell"
echo "     >>> from django.conf import settings"
echo "     >>> print(settings.PLUGINS)"
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    Happy Testing! 🚀                         ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  For questions: hamidzamani445@gmail.com                    ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
