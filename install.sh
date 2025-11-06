#!/bin/bash
# X-Ray Mass Scanner - Installation Script
# Installs all dependencies required for the scanner tools

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo " ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ "
echo "||X |||R |||A |||Y |||C |||R |||A |||W |||L |||E |||R |||R |||U |||N |||N |||E |||R ||"
echo "||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||"
echo "|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|"
echo -e "${NC}"
echo ""
echo -e "${GREEN}X-Ray Mass Scanner - Installation Script${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}Warning: Running as root. This is not recommended.${NC}"
    echo -e "${YELLOW}Press Ctrl+C to cancel or wait 5 seconds to continue...${NC}"
    sleep 5
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo -e "${RED}Error: Cannot detect OS${NC}"
    exit 1
fi

echo -e "${CYAN}[+] Detected OS: ${OS}${NC}"
echo ""

# Update package list
echo -e "${CYAN}[+] Updating package list...${NC}"
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ] || [ "$OS" = "kali" ]; then
    sudo apt-get update -qq
elif [ "$OS" = "fedora" ] || [ "$OS" = "rhel" ] || [ "$OS" = "centos" ]; then
    sudo dnf update -y -q
elif [ "$OS" = "arch" ] || [ "$OS" = "manjaro" ]; then
    sudo pacman -Sy --noconfirm
else
    echo -e "${YELLOW}Warning: Unsupported OS. Trying Debian/Ubuntu commands...${NC}"
fi

# Install Python 3
echo ""
echo -e "${CYAN}[+] Installing Python 3...${NC}"
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ] || [ "$OS" = "kali" ]; then
    sudo apt-get install -y -qq python3 python3-pip
elif [ "$OS" = "fedora" ] || [ "$OS" = "rhel" ] || [ "$OS" = "centos" ]; then
    sudo dnf install -y -q python3 python3-pip
elif [ "$OS" = "arch" ] || [ "$OS" = "manjaro" ]; then
    sudo pacman -S --noconfirm python python-pip
fi

# Verify Python installation
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 installation failed${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo -e "${GREEN}✓ Python ${PYTHON_VERSION} installed${NC}"

# Install byobu and tmux
echo ""
echo -e "${CYAN}[+] Installing byobu and tmux...${NC}"
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ] || [ "$OS" = "kali" ]; then
    sudo apt-get install -y -qq byobu tmux
elif [ "$OS" = "fedora" ] || [ "$OS" = "rhel" ] || [ "$OS" = "centos" ]; then
    sudo dnf install -y -q byobu tmux
elif [ "$OS" = "arch" ] || [ "$OS" = "manjaro" ]; then
    sudo pacman -S --noconfirm byobu tmux
fi

# Verify byobu and tmux
if command -v byobu &> /dev/null; then
    echo -e "${GREEN}✓ byobu installed${NC}"
else
    echo -e "${YELLOW}⚠ byobu not installed (sqlmap_runner.py will not work)${NC}"
fi

if command -v tmux &> /dev/null; then
    echo -e "${GREEN}✓ tmux installed${NC}"
else
    echo -e "${YELLOW}⚠ tmux not installed (sqlmap_runner_tmx.py will not work)${NC}"
fi

# Install SQLMap
echo ""
echo -e "${CYAN}[+] Installing SQLMap...${NC}"

SQLMAP_DIR="$HOME/sqlmap"

if [ -d "$SQLMAP_DIR" ]; then
    echo -e "${YELLOW}SQLMap directory already exists at ${SQLMAP_DIR}${NC}"
    echo -e "${YELLOW}Updating SQLMap...${NC}"
    cd "$SQLMAP_DIR"
    git pull -q
else
    echo -e "${CYAN}Cloning SQLMap from GitHub...${NC}"
    git clone -q https://github.com/sqlmapproject/sqlmap.git "$SQLMAP_DIR"
fi

# Verify SQLMap installation
if [ -f "$SQLMAP_DIR/sqlmap.py" ]; then
    echo -e "${GREEN}✓ SQLMap installed at ${SQLMAP_DIR}${NC}"
    SQLMAP_VERSION=$(cd "$SQLMAP_DIR" && python3 sqlmap.py --version 2>/dev/null | head -1 || echo "unknown")
    echo -e "${GREEN}  Version: ${SQLMAP_VERSION}${NC}"
else
    echo -e "${RED}Error: SQLMap installation failed${NC}"
    exit 1
fi

# Install libpcap (required by X-Ray)
echo ""
echo -e "${CYAN}[+] Installing libpcap (required by X-Ray)...${NC}"
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ] || [ "$OS" = "kali" ]; then
    sudo apt-get install -y -qq libpcap0.8
elif [ "$OS" = "fedora" ] || [ "$OS" = "rhel" ] || [ "$OS" = "centos" ]; then
    sudo dnf install -y -q libpcap
elif [ "$OS" = "arch" ] || [ "$OS" = "manjaro" ]; then
    sudo pacman -S --noconfirm libpcap
fi

if ldconfig -p | grep -q libpcap; then
    echo -e "${GREEN}✓ libpcap installed${NC}"
else
    echo -e "${YELLOW}⚠ libpcap not found (X-Ray may not work)${NC}"
fi

# Make scripts executable
echo ""
echo -e "${CYAN}[+] Making scripts executable...${NC}"
chmod +x xr_crawler_runner.py xr_json_parser.py sqlmap_runner.py sqlmap_runner_tmx.py 2>/dev/null || true
echo -e "${GREEN}✓ Scripts are now executable${NC}"

# Create example configuration
echo ""
echo -e "${CYAN}[+] Setup complete!${NC}"
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Installation Summary:${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "  ✓ Python 3 installed"
echo -e "  ✓ byobu/tmux installed"
echo -e "  ✓ SQLMap installed at: ${CYAN}${SQLMAP_DIR}${NC}"
echo -e "  ✓ libpcap installed"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo -e "  1. Place X-Ray binary in ./xray/ directory"
echo -e "     ${CYAN}mkdir -p xray && mv xray_linux_amd64 xray/${NC}"
echo ""
echo -e "  2. Run vulnerability scanner:"
echo -e "     ${CYAN}./xr_crawler_runner.py --targets urls.txt --xray ./xray/xray_linux_amd64 -w 10${NC}"
echo ""
echo -e "  3. Parse JSON reports to CSV:"
echo -e "     ${CYAN}./xr_json_parser.py -d output/json -o vulnerabilities.csv${NC}"
echo ""
echo -e "  4. Launch SQLMap sessions (byobu):"
echo -e "     ${CYAN}./sqlmap_runner.py --csv vulnerabilities.csv --sqlmap ${SQLMAP_DIR}/sqlmap.py -d 10${NC}"
echo ""
echo -e "  4b. Or use tmux instead:"
echo -e "     ${CYAN}./sqlmap_runner_tmx.py --csv vulnerabilities.csv --sqlmap ${SQLMAP_DIR}/sqlmap.py -d 10${NC}"
echo ""
echo -e "${GREEN}========================================${NC}"
echo ""
