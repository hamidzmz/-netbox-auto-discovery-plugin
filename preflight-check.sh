#!/bin/bash

# Pre-flight check script
# Run this before setup to verify your system is ready

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║            NetBox Auto Discovery - Pre-flight Check         ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

ERRORS=0
WARNINGS=0

# Check Docker
echo -n "Checking Docker... "
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version | grep -oP '\d+\.\d+' | head -1)
    DOCKER_MAJOR=$(echo $DOCKER_VERSION | cut -d. -f1)
    DOCKER_MINOR=$(echo $DOCKER_VERSION | cut -d. -f2)

    if [ "$DOCKER_MAJOR" -gt 20 ] || ([ "$DOCKER_MAJOR" -eq 20 ] && [ "$DOCKER_MINOR" -ge 10 ]); then
        echo -e "${GREEN}✓${NC} $(docker --version)"
    else
        echo -e "${YELLOW}⚠${NC} Docker $DOCKER_VERSION found (recommended: 20.10+)"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "${RED}✗${NC} Not installed"
    ERRORS=$((ERRORS + 1))
fi

# Check Docker Compose
echo -n "Checking Docker Compose... "
if docker compose version &> /dev/null; then
    echo -e "${GREEN}✓${NC} $(docker compose version)"
elif command -v docker-compose &> /dev/null; then
    echo -e "${GREEN}✓${NC} $(docker-compose --version)"
else
    echo -e "${RED}✗${NC} Not installed"
    ERRORS=$((ERRORS + 1))
fi

# Check Docker daemon
echo -n "Checking Docker daemon... "
if docker info &> /dev/null; then
    echo -e "${GREEN}✓${NC} Running"
else
    echo -e "${RED}✗${NC} Not running"
    ERRORS=$((ERRORS + 1))
fi

# Check available disk space
echo -n "Checking disk space... "
AVAILABLE_GB=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')
if [ "$AVAILABLE_GB" -ge 10 ]; then
    echo -e "${GREEN}✓${NC} ${AVAILABLE_GB}GB available"
else
    echo -e "${YELLOW}⚠${NC} Only ${AVAILABLE_GB}GB available (recommended: 10GB+)"
    WARNINGS=$((WARNINGS + 1))
fi

# Check available RAM
echo -n "Checking available RAM... "
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    AVAILABLE_RAM_MB=$(free -m | awk 'NR==2 {print $7}')
    AVAILABLE_RAM_GB=$((AVAILABLE_RAM_MB / 1024))
    if [ "$AVAILABLE_RAM_GB" -ge 4 ]; then
        echo -e "${GREEN}✓${NC} ${AVAILABLE_RAM_GB}GB available"
    else
        echo -e "${YELLOW}⚠${NC} Only ${AVAILABLE_RAM_GB}GB available (recommended: 4GB+)"
        WARNINGS=$((WARNINGS + 1))
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    TOTAL_RAM_GB=$(sysctl -n hw.memsize | awk '{print int($1/1024/1024/1024)}')
    echo -e "${BLUE}ℹ${NC} ${TOTAL_RAM_GB}GB total (check Docker Desktop settings)"
else
    echo -e "${BLUE}ℹ${NC} Unable to detect (ensure 4GB+ allocated to Docker)"
fi

# Check port 8000
echo -n "Checking port 8000... "
if lsof -Pi :8000 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠${NC} Already in use"
    WARNINGS=$((WARNINGS + 1))
    echo "   Process using port 8000:"
    lsof -Pi :8000 -sTCP:LISTEN | grep LISTEN || true
else
    echo -e "${GREEN}✓${NC} Available"
fi

# Check Git
echo -n "Checking Git... "
if command -v git &> /dev/null; then
    echo -e "${GREEN}✓${NC} $(git --version)"
else
    echo -e "${YELLOW}⚠${NC} Not installed (only needed for development)"
    WARNINGS=$((WARNINGS + 1))
fi

# Check curl
echo -n "Checking curl... "
if command -v curl &> /dev/null; then
    echo -e "${GREEN}✓${NC} Installed"
else
    echo -e "${YELLOW}⚠${NC} Not installed (needed for API testing)"
    WARNINGS=$((WARNINGS + 1))
fi

# Check directory structure
echo -n "Checking directory structure... "
if [ -d "netbox-docker" ] && [ -d "netbox-netbox-auto-discovery-plugin" ]; then
    echo -e "${GREEN}✓${NC} Valid"
else
    echo -e "${RED}✗${NC} Invalid"
    echo "   Expected directories not found"
    ERRORS=$((ERRORS + 1))
fi

# Check required files
echo -n "Checking required files... "
MISSING_FILES=()
[ ! -f "setup-monorepo.sh" ] && MISSING_FILES+=("setup-monorepo.sh")
[ ! -f "netbox-docker/docker-compose.yml" ] && MISSING_FILES+=("docker-compose.yml")
[ ! -f "netbox-docker/Dockerfile-Plugins" ] && MISSING_FILES+=("Dockerfile-Plugins")
[ ! -f "netbox-netbox-auto-discovery-plugin/pyproject.toml" ] && MISSING_FILES+=("pyproject.toml")

if [ ${#MISSING_FILES[@]} -eq 0 ]; then
    echo -e "${GREEN}✓${NC} All present"
else
    echo -e "${RED}✗${NC} Missing files:"
    for file in "${MISSING_FILES[@]}"; do
        echo "   - $file"
    done
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                        Summary                               ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo "You're ready to run:"
    echo "  ./setup-monorepo.sh"
    echo ""
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠ $WARNINGS warning(s) found${NC}"
    echo ""
    echo "You can proceed, but be aware of the warnings above."
    echo ""
    echo "To continue:"
    echo "  ./setup-monorepo.sh"
    echo ""
    exit 0
else
    echo -e "${RED}✗ $ERRORS error(s) found${NC}"
    if [ $WARNINGS -gt 0 ]; then
        echo -e "${YELLOW}⚠ $WARNINGS warning(s) found${NC}"
    fi
    echo ""
    echo "Please fix the errors above before proceeding."
    echo ""
    exit 1
fi
