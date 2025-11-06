#!/usr/bin/env python3
"""
SQLMap Runner - Automated byobu session launcher for SQL injection testing
Reads CSV from FINAL_FIX.py and creates byobu sessions with sqlmap
"""

import argparse
import csv
import re
import subprocess
import sys
from pathlib import Path
from collections import defaultdict
from urllib.parse import urlparse

# ANSI color codes
COLOR_YELLOW = '\033[93m'
COLOR_GREEN = '\033[92m'
COLOR_CYAN = '\033[96m'
COLOR_MAGENTA = '\033[95m'
COLOR_RESET = '\033[0m'

# ASCII Banner
BANNER_LINES = [
    " ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ",
    "||S |||Q |||L |||M |||A |||P |||R |||U |||N |||N |||E |||R ||",
    "||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||",
    "|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|"
]
BANNER = f"{COLOR_YELLOW}" + "\n".join(BANNER_LINES) + f"{COLOR_RESET}"

# SQLMAP COMMAND TEMPLATE - EDIT THIS TO CUSTOMIZE SQLMAP PARAMETERS
SQLMAP_CMD_TEMPLATE = "python3 {sqlmap_path} -u '{url}' -p '{param}' --method {method} --risk 3 --level 5 --batch"


def load_csv_data(csv_file):
    """
    Load CSV file and group vulnerabilities by domain
    
    Returns:
        dict: {domain: [list of vuln dicts]}
    """
    if not Path(csv_file).exists():
        print(f"{COLOR_YELLOW}Error: CSV file not found: {csv_file}{COLOR_RESET}")
        sys.exit(1)
    
    domains = defaultdict(list)
    
    # Auto-detect delimiter (comma or tab)
    with open(csv_file, 'r', encoding='utf-8') as f:
        first_line = f.readline().strip()
        delimiter = ',' if ',' in first_line else '\t'
        f.seek(0)  # Reset to beginning
        
        # CSV format: domain, vuln_count, url, parameter, method, sqli_type
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            parts = line.split(delimiter)
            if len(parts) < 6:
                continue
            
            # Skip header row if present
            if parts[0].lower() == 'domain' or parts[3].lower() == 'parameter':
                continue
            
            domain = parts[0].replace('https://', '').replace('http://', '')
            domains[domain].append({
                'url': parts[2],
                'parameter': parts[3],
                'method': parts[4],
                'sqli_type': parts[5]
            })
    
    return domains


def select_top_vulns(vulns, max_count=3):
    """
    Select top vulnerabilities for a domain (max 3)
    Priority: unique parameters first, then unique vulns
    
    Returns:
        list: Selected vulnerabilities (max 3)
    """
    # Try to select vulnerabilities with unique parameters
    seen_params = set()
    selected = []
    
    for vuln in vulns:
        param = vuln['parameter']
        if param not in seen_params:
            selected.append(vuln)
            seen_params.add(param)
            if len(selected) >= max_count:
                break
    
    # If we have less than max_count, add more vulns (even with duplicate params)
    if len(selected) < max_count:
        for vuln in vulns:
            if vuln not in selected:
                selected.append(vuln)
                if len(selected) >= max_count:
                    break
    
    return selected


def sanitize_session_name(domain):
    """Convert domain to valid byobu session name"""
    # Replace dots with underscores, remove special chars
    return domain.replace('.', '_').replace('-', '_').replace('/', '_')


def create_byobu_session(domain, vulns, prefix, sqlmap_path, dry_run=False, log_file=None):
    """
    Create byobu session for a domain with windows for each vulnerability
    
    Args:
        domain: Domain name
        vulns: List of vulnerabilities (max 3)
        prefix: Session name prefix
        sqlmap_path: Path to sqlmap.py
        dry_run: If True, only print commands without executing
        log_file: Optional file to log all sqlmap commands
    """
    session_name = f"{prefix}_{sanitize_session_name(domain)}"
    
    if not vulns:
        print(f"{COLOR_YELLOW}No vulnerabilities for {domain}, skipping...{COLOR_RESET}")
        return
    
    # Build byobu commands and collect sqlmap commands for logging
    commands = []
    sqlmap_commands = []
    
    # First vulnerability - create new session
    first_vuln = vulns[0]
    window_name = first_vuln['parameter'][:20]  # Limit window name length
    sqlmap_cmd = SQLMAP_CMD_TEMPLATE.format(
        sqlmap_path=sqlmap_path,
        url=first_vuln['url'],
        param=first_vuln['parameter'],
        method=first_vuln['method']
    )
    sqlmap_commands.append(sqlmap_cmd)
    
    # Create session with first window in detached mode
    create_cmd = f"byobu new-session -d -s '{session_name}' -n '{window_name}' '{sqlmap_cmd}'"
    commands.append(create_cmd)
    
    # Additional vulnerabilities - create new windows (no send-keys needed)
    for vuln in vulns[1:]:
        window_name = vuln['parameter'][:20]
        sqlmap_cmd = SQLMAP_CMD_TEMPLATE.format(
            sqlmap_path=sqlmap_path,
            url=vuln['url'],
            param=vuln['parameter'],
            method=vuln['method']
        )
        sqlmap_commands.append(sqlmap_cmd)
        
        new_window_cmd = f"byobu new-window -t '{session_name}' -n '{window_name}' '{sqlmap_cmd}'"
        commands.append(new_window_cmd)
    
    # Print session info
    print(f"\n{COLOR_CYAN}[+] Domain:{COLOR_RESET} {COLOR_MAGENTA}{domain}{COLOR_RESET}")
    print(f"    {COLOR_GREEN}Session:{COLOR_RESET} {session_name}")
    print(f"    {COLOR_GREEN}Windows:{COLOR_RESET} {len(vulns)}")
    
    for i, vuln in enumerate(vulns, 1):
        print(f"      {COLOR_YELLOW}W{i}:{COLOR_RESET} {vuln['parameter']} ({vuln['method']}) - {vuln['sqli_type']}")
    
    # Log commands to file if specified
    if log_file:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n# Domain: {domain} | Session: {session_name}\n")
            for sqlmap_cmd in sqlmap_commands:
                f.write(f"{sqlmap_cmd}\n")
    
    if dry_run:
        print(f"\n{COLOR_YELLOW}[DRY RUN] Commands:{COLOR_RESET}")
        for cmd in commands:
            print(f"  {cmd}")
        return
    
    # Execute commands
    for cmd in commands:
        try:
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            print(f"{COLOR_YELLOW}Warning: Failed to execute: {cmd}{COLOR_RESET}")
            print(f"{COLOR_YELLOW}Error: {e.stderr.decode()}{COLOR_RESET}")


def main():
    print(BANNER)
    print()
    
    parser = argparse.ArgumentParser(description='SQLMap Runner - Automated byobu session launcher')
    parser.add_argument('--csv', required=True, help='Path to CSV file with vulnerabilities (from FINAL_FIX.py)')
    parser.add_argument('--sqlmap', required=True, help='Path to sqlmap.py (e.g., sqlmap/sqlmap.py)')
    parser.add_argument('-d', '--domains', type=int, help='Process only first N domains')
    parser.add_argument('-w', '--windows', type=int, default=3, help='Max windows (parameters) per domain (default: 3)')
    parser.add_argument('--start', type=int, default=1, help='Start from Nth domain (default: 1)')
    parser.add_argument('-pf', '--prefix', default='xr', help='Session name prefix (default: xr)')
    parser.add_argument('--log', help='Log file to save all sqlmap commands')
    parser.add_argument('--dry-run', action='store_true', help='Print commands without executing')
    
    args = parser.parse_args()
    
    # Normalize sqlmap path
    if not args.sqlmap.startswith(('./', '/', '~')):
        args.sqlmap = './' + args.sqlmap
    
    # Check if sqlmap exists
    if not Path(args.sqlmap).exists():
        print(f"{COLOR_YELLOW}Error: SQLMap not found: {args.sqlmap}{COLOR_RESET}")
        sys.exit(1)
    
    # Load CSV data
    print(f"{COLOR_CYAN}Loading vulnerabilities from:{COLOR_RESET} {args.csv}")
    domains_data = load_csv_data(args.csv)
    
    # Get unique domains
    unique_domains = sorted(domains_data.keys())
    total_domains = len(unique_domains)
    
    print(f"{COLOR_GREEN}Loaded {total_domains} unique domains{COLOR_RESET}\n")
    
    # Apply domain filtering
    start_idx = args.start - 1  # Convert to 0-based index
    end_idx = start_idx + args.domains if args.domains else total_domains
    
    selected_domains = unique_domains[start_idx:end_idx]
    
    if not selected_domains:
        print(f"{COLOR_YELLOW}No domains to process with given filters{COLOR_RESET}")
        sys.exit(0)
    
    print(f"{COLOR_CYAN}Processing domains {args.start} to {args.start + len(selected_domains) - 1} ({len(selected_domains)} total){COLOR_RESET}")
    
    if args.dry_run:
        print(f"{COLOR_YELLOW}[DRY RUN MODE - No sessions will be created]{COLOR_RESET}\n")
    
    # Initialize log file if specified
    if args.log:
        with open(args.log, 'w', encoding='utf-8') as f:
            f.write(f"# SQLMap Commands Log\n")
            f.write(f"# Generated by sqlmaprunner.py\n")
            f.write(f"# CSV: {args.csv}\n")
            f.write(f"# Timestamp: {__import__('datetime').datetime.now()}\n")
        print(f"{COLOR_GREEN}Logging commands to: {args.log}{COLOR_RESET}\n")
    
    # Process each domain
    for domain in selected_domains:
        vulns = domains_data[domain]
        
        # Select top vulnerabilities (configurable via -w)
        top_vulns = select_top_vulns(vulns, max_count=args.windows)
        
        # Create byobu session
        create_byobu_session(domain, top_vulns, args.prefix, args.sqlmap, dry_run=args.dry_run, log_file=args.log)
    
    # Summary
    print(f"\n{COLOR_GREEN}{'='*60}{COLOR_RESET}")
    print(f"{COLOR_GREEN}Summary:{COLOR_RESET}")
    print(f"  {COLOR_CYAN}Domains processed:{COLOR_RESET} {len(selected_domains)}")
    print(f"  {COLOR_CYAN}Sessions created:{COLOR_RESET} {len(selected_domains)}")
    
    if not args.dry_run:
        print(f"\n{COLOR_YELLOW}To attach to a session:{COLOR_RESET}")
        print(f"  byobu attach-session -t {args.prefix}_<domain_name>")
        print(f"\n{COLOR_YELLOW}To list all sessions:{COLOR_RESET}")
        print(f"  byobu list-sessions")
        print(f"\n{COLOR_YELLOW}To kill a session:{COLOR_RESET}")
        print(f"  byobu kill-session -t {args.prefix}_<domain_name>")
    
    print(f"{COLOR_GREEN}{'='*60}{COLOR_RESET}\n")


if __name__ == '__main__':
    main()
