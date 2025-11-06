#!/usr/bin/env python3
"""
X-Ray Parallel Runner
Live parallel scanning with real-time worker output
"""

import argparse
import subprocess
import threading
import queue
import time
import re
import os
import sys
import shutil
import json
from pathlib import Path
from urllib.parse import urlparse, unquote


# ANSI escape codes for terminal control
CURSOR_UP = '\033[{n}A'
CURSOR_DOWN = '\033[{n}B'
CURSOR_TO_COL = '\033[{col}G'
CURSOR_SAVE = '\033[s'
CURSOR_RESTORE = '\033[u'
CLEAR_LINE = '\033[2K'
CURSOR_POSITION = '\033[{row};{col}H'
HIDE_CURSOR = '\033[?25l'
SHOW_CURSOR = '\033[?25h'

# ANSI color codes
COLOR_CYAN = '\033[96m'
COLOR_GREEN = '\033[92m'
COLOR_MAGENTA = '\033[95m'
COLOR_YELLOW = '\033[93m'
COLOR_RESET = '\033[0m'

# ASCII Banner - XRAY CRAWLER RUNNER (4 lines, no leading newline)
BANNER_LINES = [
    " ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ",
    "||X |||R |||A |||Y |||C |||R |||A |||W |||L |||E |||R |||R |||U |||N |||N |||E |||R ||",
    "||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||",
    "|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|"
]
BANNER = f"{COLOR_GREEN}" + "\n".join(BANNER_LINES) + f"{COLOR_RESET}"
BANNER_HEIGHT = len(BANNER_LINES)


class ConsoleRenderer:
    """Manages terminal output with in-place updates"""
    
    def __init__(self, num_workers):
        self.num_workers = num_workers
        self.lock = threading.Lock()
        self.worker_states = {}
        self.progress_state = {
            'completed': 0,
            'total': 0,
            'found': 0,
            'types': {'B': 0, 'E': 0, 'U': 0, 'S': 0, 'T': 0, 'Q': 0}
        }
        self.start_row = None
        self.end_row = None
        
        # Get terminal size
        self.term_width, self.term_height = shutil.get_terminal_size((80, 24))
        
    def reserve_space(self):
        """Reserve terminal space for workers + progress line"""
        with self.lock:
            # Clear screen and move to top
            sys.stdout.write('\033[2J\033[H')
            
            # Print banner (BANNER already has leading \n, print() adds trailing \n)
            print(BANNER)
            
            # Print empty lines for each worker
            for i in range(self.num_workers):
                print()
            
            # Print empty line before progress
            print()
            
            # Hide cursor for cleaner output
            sys.stdout.write(HIDE_CURSOR)
            sys.stdout.flush()
    
    def update_worker(self, worker_id, urls_processed, domain, found, types, current_url):
        """Update a specific worker's line"""
        with self.lock:
            self.worker_states[worker_id] = {
                'urls_processed': urls_processed,
                'domain': domain,
                'found': found,
                'types': types,
                'url': current_url
            }
            self._redraw_worker(worker_id)
    
    def _redraw_worker(self, worker_id):
        """Redraw a worker's line"""
        state = self.worker_states.get(worker_id, {})
        if not state:
            return
        
        # Format the line
        domain = state.get('domain', 'idle')
        urls_processed = state.get('urls_processed', 0)
        found = state.get('found', 0)
        types = state.get('types', {})
        current_url = state.get('url', '')
        
        # Format types - colored counts
        type_parts = []
        for t in ['B', 'E', 'U', 'S', 'T', 'Q']:
            count = types.get(t, 0)
            if count > 0:
                type_parts.append(f"{COLOR_YELLOW}{t}:{count}{COLOR_RESET}")
            else:
                type_parts.append(f"{t}:")
        
        types_str = ' '.join(type_parts)
        
        # Truncate URL if too long
        if len(current_url) > 60:
            current_url = current_url[:57] + '...'
        
        # Build simple line format: W1: 2 domain.com Found: 3 B: E:1 U:2 S: T: Q: | https://...
        line = f"{COLOR_CYAN}W{worker_id}:{COLOR_RESET} {COLOR_GREEN}{urls_processed}{COLOR_RESET} {COLOR_MAGENTA}{domain}{COLOR_RESET} Found: {COLOR_YELLOW}{found}{COLOR_RESET} {types_str} | {COLOR_CYAN}{current_url}{COLOR_RESET}"
        
        # Save cursor, move to worker line, print, restore
        # Banner + 1 blank, workers start after that
        row = BANNER_HEIGHT + 1 + worker_id
        sys.stdout.write(CURSOR_SAVE)
        sys.stdout.write(f"\033[{row};1H")  # Absolute position
        sys.stdout.write(CLEAR_LINE)
        sys.stdout.write(line)
        sys.stdout.write(CURSOR_RESTORE)
        sys.stdout.flush()
    
    def update_progress(self, completed, total, found, types):
        """Update the progress line"""
        with self.lock:
            self.progress_state = {
                'completed': completed,
                'total': total,
                'found': found,
                'types': types
            }
            self._redraw_progress()
    
    def _redraw_progress(self):
        """Redraw the progress line"""
        state = self.progress_state
        completed = state.get('completed', 0)
        total = state.get('total', 0)
        found = state.get('found', 0)
        types = state.get('types', {})
        
        progress_pct = int((completed / total) * 100) if total > 0 else 0
        
        # Format types with colors
        type_parts = []
        for t in ['B', 'E', 'U', 'S', 'T', 'Q']:
            count = types.get(t, 0)
            if count > 0:
                type_parts.append(f"{COLOR_YELLOW}{t}:{count}{COLOR_RESET}")
            else:
                type_parts.append(f"{t}:")
        
        types_str = ' '.join(type_parts)
        
        # Build simple progress line (removed leading \n - it breaks CLEAR_LINE)
        line = f"{COLOR_CYAN}PROGRESS:{COLOR_RESET} {COLOR_MAGENTA}[{completed}/{total}]{COLOR_RESET} {COLOR_YELLOW}{progress_pct}%{COLOR_RESET} {COLOR_CYAN}FOUND:{COLOR_RESET} {COLOR_YELLOW}{found}{COLOR_RESET} {types_str}"
        
        # Progress at row: banner(4) + blank(1) + workers + blank(1) + progress = 7 + workers
        progress_row = BANNER_HEIGHT + 1 + self.num_workers + 2
        
        # Print progress line
        sys.stdout.write(CURSOR_SAVE)
        sys.stdout.write(f"\033[{progress_row};1H")
        sys.stdout.write(CLEAR_LINE)  # Clear entire line first
        sys.stdout.write(line)
        sys.stdout.write(CURSOR_RESTORE)
        sys.stdout.flush()
    
    def cleanup(self):
        """Restore cursor and move past the output"""
        with self.lock:
            sys.stdout.write(SHOW_CURSOR)
            sys.stdout.write('\n')
            sys.stdout.flush()


def parse_xray_json(json_file):
    """
    Parse X-Ray JSON report and extract vulnerabilities
    
    Returns:
        dict: {
            'total': int,
            'baseline': int,
            'error_based': int,  
            'upload': int,
            'sqldet': int,
            'time_based': int,
            'other': int,
            'vulnerabilities': [list of vuln dicts with url, param, type, payload]
        }
    """
    if not Path(json_file).exists() or os.path.getsize(json_file) == 0:
        return {'total': 0, 'baseline': 0, 'error_based': 0, 'upload': 0, 
                'sqldet': 0, 'time_based': 0, 'other': 0, 'vulnerabilities': []}
    
    try:
        with open(json_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        if not content.strip():
            return {'total': 0, 'baseline': 0, 'error_based': 0, 'upload': 0, 
                    'sqldet': 0, 'time_based': 0, 'other': 0, 'vulnerabilities': []}
        
        # X-Ray outputs JSON array: [{"plugin":"...", "detail":{...}}, ...]
        try:
            vulns = json.loads(content)
            if not isinstance(vulns, list):
                vulns = [vulns]
        except json.JSONDecodeError:
            # Fallback: try line-by-line NDJSON parsing
            vulns = []
            for line in content.split('\n'):
                line = line.strip().rstrip(',')
                if line and line not in ['[', ']']:
                    try:
                        obj = json.loads(line)
                        vulns.append(obj)
                    except:
                        continue
        
        result = {
            'total': 0,
            'baseline': 0,
            'error_based': 0,
            'upload': 0,
            'sqldet': 0,
            'time_based': 0,
            'other': 0,
            'vulnerabilities': []
        }
        
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
                
            detail = vuln.get('detail', {})
            plugin = vuln.get('plugin', '')
            
            # Extract vulnerability info
            addr = detail.get('addr', '')
            payload = detail.get('payload', '')
            
            # Extract HTTP method and parameter from snapshot
            param = ''
            method = 'GET'
            
            # FIX: snapshot is inside detail, not at root level!
            snapshot = detail.get('snapshot', [])
            if snapshot and len(snapshot) > 0 and len(snapshot[0]) > 0:
                request_text = snapshot[0][0]
                
                # Extract HTTP method (first line: "GET /path..." or "POST /path...")
                first_line = request_text.split('\r\n')[0] if '\r\n' in request_text else request_text.split('\n')[0]
                if first_line.startswith('POST'):
                    method = 'POST'
                elif first_line.startswith('GET'):
                    method = 'GET'
                
                # Extract parameter name from payload (NOT from request)
            # X-Ray payload patterns:
            # - "param=value'" → extract "param"
            # - "param'" → extract "param"
            # - "filter.price=100'" → extract "filter.price" (dot notation)
            # - "2fa_code=123'" → extract "2fa_code" (starts with digit)
            # - "session[id]=abc'" → extract "session[id]" (brackets)
            # - "123456" → return "<path>" (path-based injection)
            
            if payload:
                # Comprehensive regex: allows letters, digits, underscore, dots, hyphens, colons, brackets, %
                # First char can be letter, digit, or underscore
                # Pattern 1: param=value' (POST body or query string injection)
                match = re.match(r'^([a-zA-Z0-9_][\w\[\]%.\-:]+)=.+', payload)
                if match:
                    param = unquote(match.group(1))
                else:
                    # Pattern 2: param' (direct parameter injection)
                    match = re.match(r'^([a-zA-Z0-9_][\w\[\]%.\-:]+)[\'"]', payload)
                    if match:
                        param = unquote(match.group(1))
                    else:
                        # Pattern 3: No clear parameter name (path-based injection)
                        param = '<path>'
            
            # Classify vulnerability type based on plugin name
            # X-Ray plugins: sqldet/error-based/default, sqldet/blind-based/default, etc.
            plugin_lower = plugin.lower()
            payload_lower = payload.lower()
            
            vuln_type = 'S'  # default
            if 'baseline' in plugin_lower or 'cors' in plugin_lower:
                result['baseline'] += 1
                vuln_type = 'B'
            elif 'upload' in plugin_lower:
                result['upload'] += 1
                vuln_type = 'U'
            elif 'sqldet' in plugin_lower or 'sql' in plugin_lower:
                # Classify SQL injection types
                if 'error-based' in plugin_lower:
                    result['error_based'] += 1
                    vuln_type = 'E'
                elif 'blind-based' in plugin_lower or 'time' in plugin_lower or 'sleep' in payload_lower:
                    result['time_based'] += 1
                    vuln_type = 'T'
                else:
                    result['sqldet'] += 1
                    vuln_type = 'S'
            else:
                result['other'] += 1
                vuln_type = 'Q'
            
            result['total'] += 1
            result['vulnerabilities'].append({
                'url': addr,
                'param': param,
                'method': method,
                'type': vuln_type,
                'payload': payload,
                'plugin': plugin
            })
        
        return result
        
    except Exception as e:
        return {'total': 0, 'baseline': 0, 'error_based': 0, 'upload': 0,
                'sqldet': 0, 'time_based': 0, 'other': 0, 'vulnerabilities': []}


def parse_xray_report(html_file):
    """
    Parse X-Ray HTML report and extract vulnerabilities by type
    (Legacy function - now using JSON parsing)
    
    Returns:
        dict: {
            'total': int,
            'baseline': int,
            'error_based': int,  
            'upload': int,
            'sqldet': int,
            'time_based': int,
            'other': int,
            'urls': [list of vulnerable URLs]
        }
    """
    if not Path(html_file).exists() or os.path.getsize(html_file) == 0:
        return {'total': 0, 'baseline': 0, 'error_based': 0, 'upload': 0, 
                'sqldet': 0, 'time_based': 0, 'other': 0, 'urls': []}
    
    try:
        with open(html_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        result = {
            'total': 0,
            'baseline': 0,
            'error_based': 0,
            'upload': 0,
            'sqldet': 0,
            'time_based': 0,
            'other': 0,
            'urls': []
        }
        
        # Parse webVulns.push(...) JavaScript data  
        # Extract data directly from patterns (handles truncated files)
        
        # Find all plugin and addr fields in the content
        # Pattern: "plugin":"value" and "addr":"url"
        plugins = re.findall(r'"plugin"\s*:\s*"([^"]+)"', content)
        addrs = re.findall(r'"addr"\s*:\s*"(https?://[^"]+)"', content)
        
        # Use plugins count as authoritative (each vulnerability has plugin)
        result['total'] = len(plugins)
        result['urls'] = list(set(addrs))[:20]
        
        if result['total'] == 0:
            return result
        
        # Also extract Details to classify SQLi types better
        details = re.findall(r'"detail"\s*:\s*"([^"]*)"', content)
        
        # Count by vulnerability type
        for idx, plugin_name in enumerate(plugins):
            plugin_lower = plugin_name.lower()
            
            # Get corresponding detail if available
            detail_lower = details[idx].lower() if idx < len(details) else ''
            combined = plugin_lower + ' ' + detail_lower
            
            # Classify by plugin name + detail (check specific types FIRST!)
            if 'baseline' in plugin_lower or 'cors' in plugin_lower or 'phpinfo' in plugin_lower:
                result['baseline'] += 1
            elif 'upload' in plugin_lower:
                result['upload'] += 1
            elif 'sql' in combined or 'sqli' in combined:
                # SQL injection found - classify by type
                if 'time' in combined or 'sleep' in combined or 'benchmark' in combined or 'delay' in combined:
                    result['time_based'] += 1
                elif 'error' in combined or 'syntax' in combined:
                    result['error_based'] += 1
                else:
                    result['sqldet'] += 1
            else:
                result['other'] += 1
        
        return result
        
    except Exception as e:
        return {'total': 0, 'baseline': 0, 'error_based': 0, 'upload': 0,
                'sqldet': 0, 'time_based': 0, 'other': 0, 'urls': []}


def sanitize_filename(url):
    """Convert URL to safe filename"""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = re.sub(r'[^\w\-.]', '_', domain)
    return domain


class Worker(threading.Thread):
    """Worker thread for scanning targets"""
    
    def __init__(self, worker_id, task_queue, results_queue, reports_dir, xray_path, renderer):
        super().__init__()
        self.worker_id = worker_id
        self.task_queue = task_queue
        self.results_queue = results_queue
        self.reports_dir = Path(reports_dir)
        self.xray_path = xray_path
        self.renderer = renderer
        self.current_target = None
        self.urls_processed = 0
        self.current_url = ""
        self.found_count = 0
        self.vuln_types = {'B': 0, 'E': 0, 'U': 0, 'S': 0, 'T': 0, 'Q': 0}
        self.daemon = True
    
    def run(self):
        while True:
            try:
                target = self.task_queue.get(timeout=1)
                if target is None:
                    break
                    
                self.scan_target(target)
                self.task_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception:
                self.task_queue.task_done()
    
    def scan_target(self, target):
        """Scan a single target with live progress"""
        self.current_target = target
        self.found_count = 0
        self.vuln_types = {'B': 0, 'E': 0, 'U': 0, 'S': 0, 'T': 0, 'Q': 0}
        self.current_url = target
        
        domain = sanitize_filename(target)
        
        # Track unique URLs found during this scan
        seen_urls = set()
        
        # Update initial status
        self.renderer.update_worker(self.worker_id, len(seen_urls), domain, 0, self.vuln_types, target)
        
        # Prepare output filename
        output_file = self.reports_dir / f"{domain}.html"
        
        # Prepare JSON output filename  
        json_dir = self.reports_dir / 'json'
        json_dir.mkdir(exist_ok=True)
        json_file = json_dir / f"{domain}.json"
        
        # Build command with both HTML and JSON output
        cmd = [
            self.xray_path,
            'ws',
            '--plugins', 'sqldet',
            '--basic-crawler', target,
            '--html-output', str(output_file),
            '--json-output', str(json_file)
        ]
        
        try:
            # Start scan process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            # Monitor process output in real-time
            last_update = time.time()
            error_output = []
            start_time = time.time()
            
            import select
            import fcntl
            
            # Make stdout non-blocking
            try:
                flags = fcntl.fcntl(process.stdout, fcntl.F_GETFL)
                fcntl.fcntl(process.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            except:
                pass
            
            vuln_block = []
            in_vuln_block = False
            
            while process.poll() is None:
                # Non-blocking read from stdout
                try:
                    if select.select([process.stdout], [], [], 0.1)[0]:
                        line = process.stdout.readline()
                        if line:
                            # Detect vulnerability block start
                            if '[Vuln:' in line:
                                in_vuln_block = True
                                vuln_block = [line]
                                # Extract vulnerability type
                                vuln_match = re.search(r'\[Vuln:\s*(\w+)\]', line)
                                if vuln_match:
                                    vuln_type = vuln_match.group(1).lower()
                                    # Increment counter immediately
                                    if 'sqldet' in vuln_type or 'sql' in vuln_type:
                                        self.vuln_types['S'] += 1
                                    elif 'baseline' in vuln_type:
                                        self.vuln_types['B'] += 1
                                    elif 'upload' in vuln_type:
                                        self.vuln_types['U'] += 1
                                    else:
                                        self.vuln_types['Q'] += 1
                                    self.found_count += 1
                                    # Immediate update when vuln found
                                    self.renderer.update_worker(
                                        self.worker_id, 
                                        len(seen_urls), 
                                        domain, 
                                        self.found_count, 
                                        self.vuln_types, 
                                        self.current_url
                                    )
                            elif in_vuln_block:
                                vuln_block.append(line)
                                # Extract Target URL from vuln block
                                if 'Target' in line:
                                    target_match = re.search(r'Target\s+"(https?://[^"]+)"', line)
                                    if target_match:
                                        vuln_url = target_match.group(1)
                                        seen_urls.add(vuln_url)
                                        self.current_url = vuln_url
                                # End of vuln block (empty line)
                                if line.strip() == '':
                                    in_vuln_block = False
                            else:
                                # Try to extract URL being scanned from xray output
                                url_match = re.search(r'https?://[^\s]+', line)
                                if url_match:
                                    self.current_url = url_match.group(0)
                                    seen_urls.add(self.current_url)
                except:
                    pass
                
                # Also read stderr for errors (non-blocking)
                try:
                    if select.select([process.stderr], [], [], 0)[0]:
                        err_line = process.stderr.readline()
                        if err_line:
                            error_output.append(err_line.strip())
                except:
                    pass
                
                # Update progress every 2 seconds - ALWAYS runs even when X-Ray is quiet
                if time.time() - last_update >= 2:
                    self.renderer.update_worker(
                        self.worker_id, 
                        len(seen_urls), 
                        domain, 
                        self.found_count, 
                        self.vuln_types, 
                        self.current_url
                    )
                    last_update = time.time()
                
                time.sleep(0.1)
            
            # Get remaining stderr
            remaining_err = process.stderr.read()
            if remaining_err:
                error_output.append(remaining_err.strip())
            
            # Check exit code
            exit_code = process.returncode
            
            # If process failed, report error
            if exit_code != 0:
                error_msg = ' '.join(error_output[:3]) if error_output else f'Exit code {exit_code}'
                self.results_queue.put({
                    'target': target,
                    'found': 0,
                    'by_type': {'B': 0, 'E': 0, 'U': 0, 'S': 0, 'T': 0, 'Q': 0},
                    'urls': [],
                    'error': error_msg
                })
                return
            
            # Parse results from JSON (authoritative source)
            vulns = parse_xray_json(json_file)
            
            # If JSON parsing failed or returned zero, fallback to HTML parsing
            if vulns.get('total', 0) == 0 and self.found_count > 0:
                vulns = parse_xray_report(output_file)
            
            # CRITICAL FIX: Only overwrite counts if parsed report has data
            # When parsers return 0, keep live stdout-detected counts
            parsed_total = vulns.get('total', 0)
            if parsed_total > 0:
                # Use parsed counts (more accurate when available)
                json_types = {
                    'B': vulns.get('baseline', 0),
                    'E': vulns.get('error_based', 0),
                    'U': vulns.get('upload', 0),
                    'S': vulns.get('sqldet', 0),
                    'T': vulns.get('time_based', 0),
                    'Q': vulns.get('other', 0)
                }
                self.vuln_types = json_types
                self.found_count = parsed_total
            # else: keep live counts from stdout detection
            
            # Final status update
            self.renderer.update_worker(
                self.worker_id, 
                len(seen_urls), 
                domain, 
                self.found_count, 
                self.vuln_types, 
                self.current_url
            )
            
            # Collect results
            result = {
                'target': target,
                'found': self.found_count,
                'by_type': self.vuln_types,
                'vulnerabilities': vulns.get('vulnerabilities', []),
                'output_file': str(output_file),
                'json_file': str(json_file)
            }
            
            self.results_queue.put(result)
            
        except Exception:
            self.results_queue.put({
                'target': target,
                'found': 0,
                'by_type': {'B': 0, 'E': 0, 'U': 0, 'S': 0, 'T': 0, 'Q': 0},
                'urls': [],
                'error': 'Scan failed'
            })


def load_targets(file_path):
    """Load targets from file"""
    targets = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Add https:// if no scheme
            if not line.startswith(('http://', 'https://')):
                line = 'https://' + line
            
            targets.append(line)
    
    return targets


def main():
    parser = argparse.ArgumentParser(description='X-Ray Parallel Runner - Live Progress Scanner')
    parser.add_argument('-t', '--targets', required=True, help='File with target URLs/domains')
    parser.add_argument('-w', '--workers', type=int, default=4, help='Number of parallel workers (default: 4)')
    parser.add_argument('-r', '--reports', default='./reports', help='Directory to save HTML and JSON reports (default: ./reports)')
    parser.add_argument('--xray', default='./xray_linux_amd64', help='Path to X-Ray executable (e.g., xray_linux_amd64 or ./xray_linux_amd64)')
    
    args = parser.parse_args()
    
    # Normalize X-Ray path - add ./ if relative path without prefix
    if not args.xray.startswith(('./', '/', '~')):
        args.xray = './' + args.xray
    
    # Create reports directory
    reports_dir = Path(args.reports)
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    # Load targets
    print(f"Loading targets from {args.targets}...")
    targets = load_targets(args.targets)
    print(f"Loaded {len(targets)} targets\n")
    
    if len(targets) == 0:
        print("No targets found!")
        return
    
    # Initialize console renderer
    renderer = ConsoleRenderer(args.workers)
    
    # Create queues
    task_queue = queue.Queue()
    results_queue = queue.Queue()
    
    # Fill task queue
    for target in targets:
        task_queue.put(target)
    
    # Reserve terminal space
    renderer.reserve_space()
    
    # Start workers
    workers = []
    for i in range(args.workers):
        worker = Worker(i + 1, task_queue, results_queue, reports_dir, args.xray, renderer)
        worker.start()
        workers.append(worker)
    
    # Monitor overall progress
    total_targets = len(targets)
    completed = 0
    total_found = 0
    failed_count = 0
    type_totals = {'B': 0, 'E': 0, 'U': 0, 'S': 0, 'T': 0, 'Q': 0}
    results = []
    errors = []
    
    start_time = time.time()
    last_progress_update = 0
    
    # Initial progress display
    renderer.update_progress(0, total_targets, 0, type_totals)
    
    try:
        while completed < total_targets:
            try:
                result = results_queue.get(timeout=1)
                results.append(result)
                completed += 1
                total_found += result['found']
                
                # Track errors
                if 'error' in result:
                    failed_count += 1
                    errors.append({
                        'target': result['target'],
                        'error': result['error']
                    })
                
                # Update type totals
                for vtype, count in result.get('by_type', {}).items():
                    type_totals[vtype] += count
                
                # Update progress line
                renderer.update_progress(completed, total_targets, total_found, type_totals)
                last_progress_update = time.time()
                
            except queue.Empty:
                # Update progress periodically with LIVE counts from active workers
                if time.time() - last_progress_update >= 3:
                    # Collect live counts from all active workers
                    live_found = total_found  # Start with completed results
                    live_types = dict(type_totals)  # Copy completed totals
                    
                    for worker in workers:
                        if worker.is_alive() and worker.current_target:
                            # Add worker's current counts (not yet in queue)
                            live_found += worker.found_count
                            for vtype, count in worker.vuln_types.items():
                                live_types[vtype] = live_types.get(vtype, 0) + count
                    
                    renderer.update_progress(completed, total_targets, live_found, live_types)
                    last_progress_update = time.time()
                continue
        
        # Stop workers
        for _ in range(args.workers):
            task_queue.put(None)
        
        for worker in workers:
            worker.join()
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Cleaning up...")
    finally:
        renderer.cleanup()
    
    elapsed = time.time() - start_time
    
    # Calculate total vulnerabilities from results (authoritative count)
    total_vulns = sum(r.get('found', 0) for r in results)
    
    # Final summary
    print(f"\n{'='*70}")
    print(f"SCAN COMPLETED")
    print(f"{'='*70}")
    print(f"Total targets: {total_targets}")
    print(f"Completed: {completed}")
    print(f"Failed: {failed_count}")
    print(f"Vulnerabilities found: {total_vulns} (from JSON)")
    print(f"  Time-based (T): {type_totals.get('T', 0)}")
    print(f"  Error-based (E): {type_totals.get('E', 0)}")
    print(f"  General SQLi (S): {type_totals.get('S', 0)}")
    print(f"  Other: {type_totals.get('B', 0) + type_totals.get('U', 0) + type_totals.get('Q', 0)}")
    print(f"Time elapsed: {elapsed:.1f}s")
    if completed > 0:
        print(f"Average: {elapsed/completed:.1f}s per target")
    
    # Show errors if any
    if errors:
        print(f"\n{'='*70}")
        print(f"ERRORS ({len(errors)}):")
        print(f"{'='*70}")
        for err in errors[:10]:  # Show first 10 errors
            print(f"  {err['target']}: {err['error']}")
        if len(errors) > 10:
            print(f"  ... and {len(errors) - 10} more")
    
    print(f"\nReports saved to: {reports_dir}/")


if __name__ == '__main__':
    main()
