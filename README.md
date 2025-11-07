# X-Ray Mass Scanner (XMS)

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-green.svg)

A powerful Python CLI toolkit for large-scale vulnerability scanning and automated exploitation using X-Ray scanner and SQLMap. Designed for penetration testers and security researchers who need to scan hundreds or thousands of targets efficiently.

## 🎯 Overview

X-Ray Mass Scanner (XMS) is a complete ecosystem of three specialized tools that work together to streamline the vulnerability assessment workflow:

1. **crawler_runner.py** - Parallel vulnerability scanner with real-time progress tracking
2. **request_generator.py** - Request file generator for GET and POST vulnerabilities (SQLMap `-r` flag)
3. **sqlmap_runner.py** - Automated SQLMap launcher using byobu sessions

## ✨ Features

### crawler_runner.py (Scanner)
- **Parallel Scanning**: Run multiple X-Ray instances simultaneously (configurable workers)
- **Live Progress**: Real-time worker status with URL counts and vulnerability detection
- **Smart Timeouts**: Automatic timeout management to prevent hanging scans
- **Dual Output**: Generates both HTML and JSON reports for each target
- **Resume Support**: Skip already scanned targets automatically

### request_generator.py (Request Generator)
- **Full HTTP Extraction**: Creates clean SQLMap request files from both GET and POST vulnerabilities
- **Regex-Based Parsing**: Works with corrupted JSON data
- **Organized Structure**: Generates `requests/domain/param_001.txt` hierarchy
- **Payload Cleaning**: Removes X-Ray SQL injection payloads from all parameters (body and query string)
- **Validation**: Skips requests where parameter not found

### sqlmap_runner.py (SQLMap Automation)
- **Automated Sessions**: Creates organized byobu sessions for each domain
- **Smart Selection**: Prioritizes unique parameters (configurable windows per domain)
- **Request File Input**: Reads directly from request_generator.py output
- **Customizable Templates**: Edit SQLMap command template at top of script
- **Domain Range**: Process specific domain ranges with `--start` and `-c` flags
- **Session Management**: Use `--stop` to kill all existing xr_* sessions before starting
- **Command Logging**: Save all generated SQLMap commands to file (`--log` option)

## 📦 Installation

### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/xray-mass-scanner.git
cd xray-mass-scanner

# Run automated installer
chmod +x install.sh
./install.sh
```

The installer will automatically:
- Install Python 3 and pip
- Install byobu and
- Clone and setup SQLMap from GitHub
- Install libpcap (required by X-Ray)
- Make all scripts executable

### Manual Installation

#### Prerequisites

```bash
# Ubuntu/Debian/Kali
sudo apt-get update
sudo apt-get install -y python3 python3-pip byobu libpcap0.8

# Fedora/RHEL/CentOS
sudo dnf install -y python3 python3-pip byobu libpcap

# Arch/Manjaro
sudo pacman -S python python-pip byobu libpcap
```

#### Install SQLMap

```bash
# Clone SQLMap
cd ~
git clone https://github.com/sqlmapproject/sqlmap.git
```

#### Setup X-Ray

```bash
# Create xray directory and place X-Ray binary
mkdir -p xray
mv xray_linux_amd64 xray/
chmod +x xray/xray_linux_amd64
```

## 🚀 Quick Start

### Using Unified Launcher (xms.py)

The easiest way to use XMS is through the unified launcher:

```bash
# Show help and all available modules
python3 xms.py -h

# Run scanner (cr = Crawler Runner)
python3 xms.py cr -l urls.txt --xray ~/xray/xray_linux_amd64 -w 10

# Generate request files (rg = Request Generator)
python3 xms.py rg -d output/json -o requests

# Run SQLMap automation (sr = SQLMap Runner)
python3 xms.py sr -r requests --sqlmap ~/sqlmap/sqlmap.py -c 10 -w 3
```

**Module shortcuts:**
- `cr` - Crawler Runner (scanner)
- `rg` - Request Generator
- `sr` - SQLMap Runner

## 🚀 Detailed Usage

### Step 1: Scan Targets (crawler_runner.py)

Scan multiple targets in parallel and generate HTML/JSON reports:

```bash
# X-Ray in subdirectory (recommended)
./crawler_runner.py -l urls.txt --xray ./xray/xray_linux_amd64 -w 10

# X-Ray in home directory
./crawler_runner.py -l urls.txt --xray ~/tools/xray/xray_linux_amd64 -w 10

# X-Ray with absolute path
./crawler_runner.py -l urls.txt --xray /usr/local/bin/xray -w 10
```

**Options:**
- `--targets FILE` - Text file with one URL per line
- `--xray PATH` - Path to X-Ray binary (supports relative, absolute, and ~ home directory paths)
- `-w, --workers NUM` - Number of parallel workers (default: 5)
- `--timeout SEC` - Timeout per target in seconds (default: 300)
- `--reports-dir DIR` - Output directory (default: ./output)

**Example URLs file:**
```
https://example.com
https://test.com
https://vulnerable-site.com
```

**Output:**
```
output/
├── example_com.html
├── test_com.html
└── json/
    ├── example_com.json
    └── test_com.json
```

### Step 2b (Optional): Generate Request Files (request_generator.py)

For GET and POST vulnerabilities, generate clean SQLMap request files:

```bash
# Generate request files from JSON reports
./request_generator.py -d output/json -o requests

# Output structure:
# requests/
#   example.com/
#     id_GET_001.txt
#     username_POST_001.txt
#     password_POST_001.txt
#   test.com/
#     search_GET_001.txt
#     email_POST_001.txt

# Test with SQLMap
sqlmap -r requests/example.com/username_POST_001.txt -p username --batch --risk 3 --level 5
```

**Options:**
- `-d, --directory DIR` - Directory containing JSON files
- `-f, --files LIST` - Comma-separated list of JSON files
- `-o, --output DIR` - Output directory (default: requests)

**Features:**
- Extracts both GET (query string) and POST (body) vulnerabilities
- Creates one directory per domain
- Clear naming: `param_METHOD_001.txt` (e.g., `anyo_i_POST_001.txt`, `servicio_GET_001.txt`)
- Automatically cleans X-Ray SQL injection payloads from all parameters
- Full HTTP requests ready for manual SQLMap testing

### Step 3: Automated Exploitation (sqlmap_runner.py)

Launch SQLMap in organized byobu sessions using request files:

```bash
# Process first 10 domains with 3 windows each
./sqlmap_runner.py -r requests --sqlmap ~/sqlmap/sqlmap.py -c 10 -w 3

# Log all commands to file
./sqlmap_runner.py -r requests --sqlmap ~/sqlmap/sqlmap.py -c 10 --log commands.txt

# Dry run (preview commands)

# Process domains 11-20
./sqlmap_runner.py -r requests --sqlmap ~/sqlmap/sqlmap.py --start 11 -c 10
```

**Options:**
- `--req DIR` - Request files directory (from request_generator.py)
- `--sqlmap PATH` - Path to sqlmap.py
- `-d, --count NUM` - Process only first N domains
- `-w, --windows NUM` - Max windows (parameters) per domain (default: 3)
- `--start NUM` - Start from Nth domain (default: 1)
- `-pf, --prefix STR` - Session name prefix (default: xr)
- `--log FILE` - Save all generated sqlmap commands to file
- `--dry-run` - Print commands without executing

**Or use instead:**

```bash
./sqlmap_runner.py -r requests --sqlmap ~/sqlmap/sqlmap.py -c 10 -w 3
```

### Byobu Navigation

**Byobu:**
- `F2` - Create new window
- `F3/F4` - Switch between windows
- `F6` - Detach session
- `byobu attach -t xr_example_com` - Reattach to session

## ⚙️ Configuration

### Customize SQLMap Commands

Edit the `SQLMAP_CMD_TEMPLATE` at the top of `sqlmap_runner.py` or `sqlmap_runner.py`:

```python
# Default template (with -p flag for explicit parameter targeting)
SQLMAP_CMD_TEMPLATE = 'python3 {sqlmap_path} -r "{request_file}" -p "{parameter}" --risk 3 --level 5 --batch'

# Example with proxychains4
SQLMAP_CMD_TEMPLATE = 'proxychains4 -q python3 {sqlmap_path} -r "{request_file}" -p "{parameter}" --risk 3 --level 5 --batch'

# Example with custom options
SQLMAP_CMD_TEMPLATE = 'python3 {sqlmap_path} -r "{request_file}" -p "{parameter}" --risk 3 --level 5 --batch --threads 10 --tamper=space2comment'
```

## 📊 Workflow Example

Complete workflow from scanning to exploitation:

```bash
# 1. Prepare target list
cat > targets.txt << EOF
https://example.com
https://test.com
https://demo.com
EOF

# 2. Run parallel scan (10 workers) - X-Ray path can be relative, absolute, or ~
./crawler_runner.py -l targets.txt --xray ./xray/xray_linux_amd64 -w 10

# 3. Generate request files (GET and POST parameters)
./request_generator.py -d output/json -o requests

# 5. Launch SQLMap sessions (first 5 domains, log commands)
./sqlmap_runner.py -r requests --sqlmap ~/sqlmap/sqlmap.py -c 5 --log sqlmap_commands.txt

# 6. Attach to a specific session
byobu attach -t xr_example_com

# 7. Detach and continue in background
# Press F6 in byobu

# 8. View generated commands
cat sqlmap_commands.txt

# 9. (Optional) Test vulnerabilities manually
sqlmap -r requests/example.com/username_POST_001.txt -p username --batch --risk 3 --level 5
```

## ⚠️ Important Notes

### X-Ray Requirements

- **libpcap.so.0.8** is REQUIRED by X-Ray scanner
- Use on **native Linux** systems (Ubuntu, Debian, Kali, Fedora, Arch)

### Installation on Linux:

```bash
# Ubuntu/Debian/Kali
sudo apt-get install libpcap0.8

# Fedora/RHEL/CentOS
sudo dnf install libpcap

# Arch/Manjaro
sudo pacman -S libpcap
```

### Session Management

- Sessions continue running after detach - reattach to see progress
- List sessions: `byobu list-sessions`
- Kill session: `byobu kill-session -t xr_example_com`

### Handling Duplicate Sessions

When you run the script multiple times, it **automatically creates numbered sessions**:

```bash
# First run
./sqlmap_runner.py -r requests --sqlmap ~/sqlmap/sqlmap.py
# Creates: xr_example_com

# Second run (session exists)
./sqlmap_runner.py -r requests --sqlmap ~/sqlmap/sqlmap.py
# Creates: xr_example_com_2

# Third run
./sqlmap_runner.py -r requests --sqlmap ~/sqlmap/sqlmap.py
# Creates: xr_example_com_3
```

**Manual session cleanup:**
```bash
# Use --stop flag to kill all xr_* sessions and create new ones
./sqlmap_runner.py -r requests --sqlmap ~/sqlmap/sqlmap.py --stop

# Kill specific session
byobu kill-session -t xr_example_com

# Kill all sessions with prefix
byobu list-sessions | grep '^xr_' | cut -d: -f1 | xargs -I{} byobu kill-session -t {}
```

## 🐛 Troubleshooting

### X-Ray "error while loading shared libraries: libpcap.so.0.8"

```bash
# Install libpcap
sudo apt-get install libpcap0.8

# Verify installation
ldconfig -p | grep libpcap
```

### SQLMap Not Found

```bash
# Clone SQLMap if not installed
git clone https://github.com/sqlmapproject/sqlmap.git ~/sqlmap

# Use full path in commands
./sqlmap_runner.py --sqlmap ~/sqlmap/sqlmap.py ...
```

### Byobu Not Creating Sessions

```bash
# List sessions
byobu list-sessions

# Test manually if needed
byobu attach -t session_name
```

## 📝 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## ⭐ Credits

- **X-Ray Scanner**: https://github.com/chaitin/xray
- **SQLMap**: https://github.com/sqlmapproject/sqlmap

## 📧 Contact

For bugs, feature requests, or questions, please open an issue on GitHub.

---

**Disclaimer**: This tool is for authorized security testing only. Always obtain proper authorization before testing any systems you don't own.
