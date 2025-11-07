#!/usr/bin/env python3
"""
SQLMap Runner - Automated byobu session launcher for SQL injection testing
Reads request files from xr_request_generator.py and creates byobu sessions with sqlmap
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path
from collections import defaultdict

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
SQLMAP_CMD_TEMPLATE = 'python3 {sqlmap_path} -r "{request_file}" -p "{parameter}" --risk 3 --level 5 --batch'


def parse_request_filename(filename):
    """
    Parse request filename to extract parameter and method
    Format: param_METHOD_001.txt (e.g., anyo_i_POST_001.txt)
    
    Returns:
        tuple: (parameter, method) or (None, None) if parsing fails
    """
    match = re.match(r'^(.+)_(GET|POST)_\d+\.txt$', filename)
    if match:
        param = match.group(1)
        method = match.group(2)
        return param, method
    return None, None


def load_request_files(req_dir):
    """
    Scan request directory and group request files by domain
    Directory structure: requests/domain/param_METHOD_001.txt
    
    Returns:
        dict: {domain: [list of request file dicts]}
    """
    req_path = Path(req_dir)
    
    if not req_path.exists():
        print(f"{COLOR_YELLOW}Error: Request directory not found: {req_dir}{COLOR_RESET}")
        sys.exit(1)
    
    if not req_path.is_dir():
        print(f"{COLOR_YELLOW}Error: {req_dir} is not a directory{COLOR_RESET}")
        sys.exit(1)
    
    domains = defaultdict(list)
    
    # Scan subdirectories (each subdirectory is a domain)
    for domain_dir in sorted(req_path.iterdir()):
        if not domain_dir.is_dir():
            continue
        
        domain = domain_dir.name
        
        # Scan request files in domain directory
        for req_file in sorted(domain_dir.glob('*.txt')):
            param, method = parse_request_filename(req_file.name)
            
            if param is None or method is None:
                continue
            
            domains[domain].append({
                'request_file': str(req_file.absolute()),
                'parameter': param,
                'method': method
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
    """Convert domain to valid byobu session name (letters and numbers only)"""
    # Replace dots, dashes, slashes with underscores, remove all other special chars
    sanitized = domain.replace('.', '_').replace('-', '_').replace('/', '_')
    # Remove any remaining special characters, keep only alphanumeric and underscores
    sanitized = ''.join(c for c in sanitized if c.isalnum() or c == '_')
    return sanitized


def session_exists(session_name):
    """Check if byobu session already exists"""
    try:
        result = subprocess.run(
            f"byobu list-sessions 2>/dev/null | grep -q '^{session_name}:'",
            shell=True,
            capture_output=True
        )
        return result.returncode == 0
    except:
        return False


def get_unique_session_name(base_name):
    """
    Get unique session name by adding number suffix if session exists
    Returns: unique session name (e.g., xr_domain_2, xr_domain_3)
    """
    if not session_exists(base_name):
        return base_name
    
    # Session exists, find next available number
    counter = 2
    while counter < 100:  # Safety limit
        candidate = f"{base_name}_{counter}"
        if not session_exists(candidate):
            return candidate
        counter += 1
    
    # Fallback: use timestamp
    import time
    return f"{base_name}_{int(time.time())}"


def create_byobu_session(domain, vulns, prefix, sqlmap_path, log_file=None):
    """
    Create byobu session for a domain with windows for each request file
    
    Args:
        domain: Domain name
        vulns: List of request file dicts (max 3)
        prefix: Session name prefix
        sqlmap_path: Path to sqlmap.py
        log_file: Optional file to log all sqlmap commands
    """
    base_session_name = f"{prefix}_{sanitize_session_name(domain)}"
    session_name = get_unique_session_name(base_session_name)
    
    if not vulns:
        print(f"{COLOR_YELLOW}No request files for {domain}, skipping...{COLOR_RESET}")
        return
    
    # Build byobu commands and collect sqlmap commands for logging
    commands = []
    sqlmap_commands = []
    
    # First request file - create new session
    first_vuln = vulns[0]
    window_name = first_vuln['parameter'][:20]  # Limit window name length
    sqlmap_cmd = SQLMAP_CMD_TEMPLATE.format(
        sqlmap_path=sqlmap_path,
        request_file=first_vuln['request_file'],
        parameter=first_vuln['parameter']
    )
    sqlmap_commands.append(sqlmap_cmd)
    
    # Create session WITHOUT command first
    create_cmd = f"byobu new-session -d -s {session_name} -n {window_name}"
    commands.append(create_cmd)
    
    # Send the sqlmap command to the first window
    # Use literal string mode with -l flag to avoid shell interpretation
    send_cmd = f"byobu send-keys -t {session_name}:0 -l '{sqlmap_cmd}'"
    commands.append(send_cmd)
    # Send Enter separately
    enter_cmd = f"byobu send-keys -t {session_name}:0 Enter"
    commands.append(enter_cmd)
    
    # Additional request files - create new windows
    for idx, vuln in enumerate(vulns[1:], start=1):
        window_name = vuln['parameter'][:20]
        sqlmap_cmd = SQLMAP_CMD_TEMPLATE.format(
            sqlmap_path=sqlmap_path,
            request_file=vuln['request_file'],
            parameter=vuln['parameter']
        )
        sqlmap_commands.append(sqlmap_cmd)
        
        # Create new window WITHOUT command
        new_window_cmd = f"byobu new-window -t {session_name} -n {window_name}"
        commands.append(new_window_cmd)
        
        # Send the sqlmap command to the window
        # Use literal string mode with -l flag to avoid shell interpretation
        send_cmd = f"byobu send-keys -t {session_name}:{idx} -l '{sqlmap_cmd}'"
        commands.append(send_cmd)
        # Send Enter separately
        enter_cmd = f"byobu send-keys -t {session_name}:{idx} Enter"
        commands.append(enter_cmd)
    
    # Print session info
    print(f"\n{COLOR_CYAN}[+] Domain:{COLOR_RESET} {COLOR_MAGENTA}{domain}{COLOR_RESET}")
    print(f"    {COLOR_GREEN}Session:{COLOR_RESET} {session_name}")
    print(f"    {COLOR_GREEN}Windows:{COLOR_RESET} {len(vulns)}")
    
    for i, vuln in enumerate(vulns, 1):
        req_filename = Path(vuln['request_file']).name
        print(f"      {COLOR_YELLOW}W{i}:{COLOR_RESET} {vuln['parameter']} ({vuln['method']}) - {req_filename}")
    
    # Log commands to file if specified
    if log_file:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n# Domain: {domain} | Session: {session_name}\n")
            for sqlmap_cmd in sqlmap_commands:
                f.write(f"{sqlmap_cmd}\n")
    
    # Execute commands
    for cmd in commands:
        try:
            # Use shell=True for byobu commands (they need shell expansion)
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            print(f"{COLOR_YELLOW}Warning: Failed to execute: {cmd}{COLOR_RESET}")
            if e.stderr:
                print(f"{COLOR_YELLOW}Error: {e.stderr}{COLOR_RESET}")


def main():
    print(BANNER)
    print()
    
    parser = argparse.ArgumentParser(description='SQLMap Runner - Automated byobu session launcher')
    parser.add_argument('-r', '--request', required=True, help='Path to request files directory (from xr_request_generator.py)')
    parser.add_argument('--sqlmap', required=True, help='Path to sqlmap.py (e.g., sqlmap/sqlmap.py)')
    parser.add_argument('-c', '--count', type=int, help='Process only first N domains')
    parser.add_argument('-w', '--windows', type=int, default=3, help='Max windows (parameters) per domain (default: 3)')
    parser.add_argument('--start', type=int, default=1, help='Start from Nth domain (default: 1)')
    parser.add_argument('-pf', '--prefix', default='xr', help='Session name prefix (default: xr)')
    parser.add_argument('--log', help='Log file to save all sqlmap commands')
    parser.add_argument('--stop', action='store_true', help='Stop (kill) all existing xr_* sessions before starting')
    
    args = parser.parse_args()
    
    # Handle --stop flag: kill all existing xr_* sessions
    if args.stop:
        print(f"{COLOR_YELLOW}Stopping all existing xr_* sessions...{COLOR_RESET}")
        try:
            result = subprocess.run("byobu list-sessions 2>/dev/null | grep '^xr_' | cut -d: -f1", 
                                  shell=True, capture_output=True, text=True)
            if result.stdout.strip():
                sessions = result.stdout.strip().split('\n')
                for session in sessions:
                    subprocess.run(f"byobu kill-session -t {session}", shell=True, capture_output=True)
                    print(f"{COLOR_GREEN}Killed session: {session}{COLOR_RESET}")
                print(f"{COLOR_GREEN}Stopped {len(sessions)} session(s){COLOR_RESET}\n")
            else:
                print(f"{COLOR_CYAN}No xr_* sessions found{COLOR_RESET}\n")
        except Exception as e:
            print(f"{COLOR_YELLOW}Warning: Failed to stop sessions: {e}{COLOR_RESET}\n")
    
    # Normalize sqlmap path
    if not args.sqlmap.startswith(('./', '/', '~')):
        args.sqlmap = './' + args.sqlmap
    
    # Check if sqlmap exists
    if not Path(args.sqlmap).exists():
        print(f"{COLOR_YELLOW}Error: SQLMap not found: {args.sqlmap}{COLOR_RESET}")
        sys.exit(1)
    
    # Load request files
    print(f"{COLOR_CYAN}Loading request files from:{COLOR_RESET} {args.request}")
    domains_data = load_request_files(args.request)
    
    # Get unique domains
    unique_domains = sorted(domains_data.keys())
    total_domains = len(unique_domains)
    
    print(f"{COLOR_GREEN}Loaded {total_domains} unique domains{COLOR_RESET}\n")
    
    # Apply domain filtering
    start_idx = args.start - 1  # Convert to 0-based index
    end_idx = start_idx + args.count if args.count else total_domains
    
    selected_domains = unique_domains[start_idx:end_idx]
    
    if not selected_domains:
        print(f"{COLOR_YELLOW}No domains to process with given filters{COLOR_RESET}")
        sys.exit(0)
    
    print(f"{COLOR_CYAN}Processing domains {args.start} to {args.start + len(selected_domains) - 1} ({len(selected_domains)} total){COLOR_RESET}\n")
    
    # Initialize log file if specified
    if args.log:
        with open(args.log, 'w', encoding='utf-8') as f:
            f.write(f"# SQLMap Commands Log\n")
            f.write(f"# Generated by sqlmap_runner.py\n")
            f.write(f"# Request directory: {args.request}\n")
            f.write(f"# Timestamp: {__import__('datetime').datetime.now()}\n")
        print(f"{COLOR_GREEN}Logging commands to: {args.log}{COLOR_RESET}\n")
    
    # Process each domain
    for domain in selected_domains:
        vulns = domains_data[domain]
        
        # Select top vulnerabilities (configurable via -w)
        top_vulns = select_top_vulns(vulns, max_count=args.windows)
        
        # Create byobu session
        create_byobu_session(domain, top_vulns, args.prefix, args.sqlmap, log_file=args.log)
    
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
