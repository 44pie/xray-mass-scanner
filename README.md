# X-Ray Mass Scanner (XMS)

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-green.svg)

A powerful Python CLI toolkit for large-scale vulnerability scanning and automated exploitation using X-Ray scanner and SQLMap. Designed for penetration testers and security researchers who need to scan hundreds or thousands of targets efficiently.

## 🎯 Overview

X-Ray Mass Scanner (XMS) is a complete ecosystem of four specialized tools that work together to streamline the vulnerability assessment workflow:

1. **xr_crawler_runner.py** - Parallel vulnerability scanner with real-time progress tracking
2. **xr_json_parser.py** - JSON report parser that extracts vulnerabilities to CSV
3. **sqlmap_runner.py** - Automated SQLMap launcher using byobu sessions  
4. **sqlmap_runner_tmx.py** - Automated SQLMap launcher using tmux sessions

## ✨ Features

### xr_crawler_runner.py (Scanner)
- **Parallel Scanning**: Run multiple X-Ray instances simultaneously (configurable workers)
- **Live Progress**: Real-time worker status with URL counts and vulnerability detection
- **Smart Timeouts**: Automatic timeout management to prevent hanging scans
- **Dual Output**: Generates both HTML and JSON reports for each target
- **Resume Support**: Skip already scanned targets automatically

### xr_json_parser.py (Parser)
- **Accurate Extraction**: Reads parameter names from `detail.extra.param.key` (the correct source!)
- **Method Detection**: Automatically determines GET/POST from parameter position
- **SQLi Classification**: Categorizes vulnerabilities (Error-based, Time-based, General)
- **CSV Export**: Structured output with domain, URL, parameter, method, and type
- **Progress Tracking**: Shows file-by-file processing with counts

### sqlmap_runner.py & sqlmap_runner_tmx.py (Exploiters)
- **Automated Sessions**: Creates organized byobu/tmux sessions for each domain
- **Smart Selection**: Prioritizes unique parameters (configurable windows per domain)
- **CSV Input**: Reads directly from xr_json_parser.py output
- **Customizable Templates**: Edit SQLMap command template at top of script
- **Domain Range**: Process specific domain ranges with `--start` and `-d` flags
- **Dry Run Mode**: Preview commands before execution
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
- Install byobu and tmux
- Clone and setup SQLMap from GitHub
- Install libpcap (required by X-Ray)
- Make all scripts executable

### Manual Installation

#### Prerequisites

```bash
# Ubuntu/Debian/Kali
sudo apt-get update
sudo apt-get install -y python3 python3-pip byobu tmux libpcap0.8

# Fedora/RHEL/CentOS
sudo dnf install -y python3 python3-pip byobu tmux libpcap

# Arch/Manjaro
sudo pacman -S python python-pip byobu tmux libpcap
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

## 🚀 Usage

### Step 1: Scan Targets (xr_crawler_runner.py)

Scan multiple targets in parallel and generate HTML/JSON reports:

```bash
./xr_crawler_runner.py --targets urls.txt --xray ./xray/xray_linux_amd64 -w 10
```

**Options:**
- `--targets FILE` - Text file with one URL per line
- `--xray PATH` - Path to X-Ray binary (accepts both `xray_linux_amd64` and `./xray/xray_linux_amd64`)
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

### Step 2: Extract Vulnerabilities (xr_json_parser.py)

Parse JSON reports and extract SQL injection vulnerabilities to CSV:

```bash
# Parse entire directory
./xr_json_parser.py -d output/json -o vulnerabilities.csv

# Parse specific files
./xr_json_parser.py -f output/json/site1.json,output/json/site2.json -o results.csv
```

**Options:**
- `-d, --directory DIR` - Directory containing JSON files
- `-f, --files LIST` - Comma-separated list of JSON files
- `-o, --output FILE` - Output CSV file (auto-generated if not specified)

**CSV Output Format:**
```csv
domain,sqli_count,url,parameter,method,sqli_type
https://example.com,3,https://example.com/page?id=1,id,GET,Error-based SQLi
https://example.com,3,https://example.com/login,username,POST,Time-based SQLi
```

### Step 3: Automated Exploitation (sqlmap_runner.py)

Launch SQLMap in organized byobu sessions:

```bash
# Process first 10 domains with 3 windows each
./sqlmap_runner.py --csv vulnerabilities.csv --sqlmap ~/sqlmap/sqlmap.py -d 10 -w 3

# Log all commands to file
./sqlmap_runner.py --csv vulnerabilities.csv --sqlmap ~/sqlmap/sqlmap.py -d 10 --log commands.txt

# Dry run (preview commands)
./sqlmap_runner.py --csv vulnerabilities.csv --sqlmap ~/sqlmap/sqlmap.py -d 5 --dry-run

# Process domains 11-20
./sqlmap_runner.py --csv vulnerabilities.csv --sqlmap ~/sqlmap/sqlmap.py --start 11 -d 10
```

**Options:**
- `--csv FILE` - Input CSV file from xr_json_parser.py
- `--sqlmap PATH` - Path to sqlmap.py
- `-d, --domains NUM` - Process only first N domains
- `-w, --windows NUM` - Max windows (parameters) per domain (default: 3)
- `--start NUM` - Start from Nth domain (default: 1)
- `-pf, --prefix STR` - Session name prefix (default: xr)
- `--log FILE` - Save all generated sqlmap commands to file
- `--dry-run` - Print commands without executing

**Or use tmux instead:**

```bash
./sqlmap_runner_tmx.py --csv vulnerabilities.csv --sqlmap ~/sqlmap/sqlmap.py -d 10 -w 3
```

### Byobu/Tmux Navigation

**Byobu:**
- `F2` - Create new window
- `F3/F4` - Switch between windows
- `F6` - Detach session
- `byobu attach -t xr_example_com` - Reattach to session

**Tmux:**
- `Ctrl+b c` - Create new window
- `Ctrl+b n/p` - Next/Previous window
- `Ctrl+b d` - Detach session
- `tmux attach -t xr_example_com` - Reattach to session

## ⚙️ Configuration

### Customize SQLMap Commands

Edit the `SQLMAP_CMD_TEMPLATE` at the top of `sqlmap_runner.py` or `sqlmap_runner_tmx.py`:

```python
# Default template
SQLMAP_CMD_TEMPLATE = "python3 {sqlmap_path} -u '{url}' -p '{param}' --method {method} --risk 3 --level 5 --batch"

# Example with proxychains4
SQLMAP_CMD_TEMPLATE = "proxychains4 -q python3 {sqlmap_path} -u '{url}' -p '{param}' --method {method} --risk 3 --level 5 --batch"

# Example with custom options
SQLMAP_CMD_TEMPLATE = "python3 {sqlmap_path} -u '{url}' -p '{param}' --method {method} --risk 3 --level 5 --batch --threads 10 --tamper=space2comment"
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

# 2. Run parallel scan (10 workers)
./xr_crawler_runner.py --targets targets.txt --xray ./xray/xray_linux_amd64 -w 10

# 3. Parse JSON reports to CSV
./xr_json_parser.py -d output/json -o vulns.csv

# 4. Launch SQLMap sessions (first 5 domains, log commands)
./sqlmap_runner.py --csv vulns.csv --sqlmap ~/sqlmap/sqlmap.py -d 5 --log sqlmap_commands.txt

# 5. Attach to a specific session
byobu attach -t xr_example_com

# 6. Detach and continue in background
# Press F6 in byobu

# 7. View generated commands
cat sqlmap_commands.txt
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
- List sessions: `byobu list-sessions` or `tmux list-sessions`
- Kill session: `byobu kill-session -t xr_example_com`

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

### Byobu/Tmux Not Creating Sessions

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
