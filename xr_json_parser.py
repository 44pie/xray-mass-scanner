#!/usr/bin/env python3

import json
import csv
import re
import sys
import argparse
from pathlib import Path
from urllib.parse import unquote, parse_qs, urlparse


# ANSI color codes
COLOR_CYAN = '\033[96m'
COLOR_GREEN = '\033[92m'
COLOR_MAGENTA = '\033[95m'
COLOR_YELLOW = '\033[93m'
COLOR_RESET = '\033[0m'

# ASCII Banner
BANNER = f"""{COLOR_CYAN}
 ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ 
||X |||R |||A |||Y |||J |||S |||O |||N |||P |||A |||R |||S |||E |||R ||
||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||
|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|
{COLOR_RESET}"""


def find_parameter_in_request(request_text, payload):
    """
    Parse HTTP request and find parameter whose NAME or VALUE contains the payload.
    This is the CORRECT way - we search for which parameter was injected.
    """
    if not request_text or not payload:
        return ''
    
    # Clean payload - remove injection markers like quotes
    # payload might be: "123456'", "Vino'", "action=OK'", "123456'and'x'='x", etc.
    clean_payload = payload.rstrip("'\"").lstrip("'\"")
    
    # Extract the BASE value before SQL injection syntax
    # Examples: "123456'and'b'='b" → "123456"
    #           "Vino'" → "Vino"
    #           "action=OK'" → "action", "OK"
    #           "123456\"and\"c\"=\"n" → "123456"
    # Split by either single or double quote
    import re
    match = re.match(r'^([^\'\"]+)', clean_payload)
    base_value = match.group(1) if match else clean_payload
    
    # If payload contains "=", it's "param=value'" format - extract param name
    if '=' in base_value:
        param_from_payload = base_value.split('=')[0]
        value_from_payload = base_value.split('=', 1)[1]
    else:
        param_from_payload = None
        value_from_payload = None
    
    lines = request_text.split('\r\n')
    if not lines:
        return ''
    
    # Parse request line: GET /path?query HTTP/1.1 or POST /path HTTP/1.1
    first_line = lines[0]
    parts = first_line.split(' ')
    if len(parts) < 2:
        return ''
    
    method = parts[0]
    url_path = parts[1]
    
    # 1. Check GET query parameters
    if '?' in url_path:
        query_string = url_path.split('?', 1)[1]
        params = parse_qs(query_string, keep_blank_values=True)
        
        # If payload is "param=value'" format, look for exact param name
        if param_from_payload and param_from_payload in params:
            return unquote(param_from_payload)
        
        for param_name, values in params.items():
            # Check if base value is in parameter NAME (e.g., "Vino" in param name)
            if base_value in param_name:
                return unquote(param_name)
            # Check if base value is START of parameter VALUE
            # This handles cases where X-Ray modifies the payload in the request
            for value in values:
                # URL decode the value from request
                decoded_value = unquote(value)
                # Check if decoded value STARTS with base_value
                if decoded_value.startswith(base_value) or base_value in decoded_value:
                    return unquote(param_name)
    
    # 2. Check POST body
    if method == 'POST' and '\r\n\r\n' in request_text:
        body = request_text.split('\r\n\r\n', 1)[1]
        
        # Try form-urlencoded
        if '=' in body and not body.startswith('{'):
            try:
                params = parse_qs(body, keep_blank_values=True)
                
                # If payload is "param=value'" format, look for exact param name
                if param_from_payload and param_from_payload in params:
                    return unquote(param_from_payload)
                
                for param_name, values in params.items():
                    # Check parameter NAME
                    if base_value in param_name:
                        return unquote(param_name)
                    # Check parameter VALUE
                    for value in values:
                        decoded_value = unquote(value)
                        if decoded_value.startswith(base_value) or base_value in decoded_value:
                            return unquote(param_name)
            except:
                pass
    
    # 3. Path-based injection - base value is in the URL path itself
    if base_value in url_path:
        return '<path>'
    
    return ''


def parse_json_files(json_files):
    """
    Parse X-Ray JSON reports and extract vulnerabilities.
    Returns dict: {domain: [(url, parameter, method, sqli_type), ...]}
    """
    results = {}
    
    for json_file in sorted(json_files):
        domain = Path(json_file).stem
        print(f"Processing: {COLOR_CYAN}{domain}{COLOR_RESET}")
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Try parsing as JSON array first
            try:
                items = json.loads(content)
            except json.JSONDecodeError:
                # Fallback: line-by-line NDJSON parsing
                items = []
                for line in content.split('\n'):
                    line = line.strip().rstrip(',')
                    if line and line not in ['[', ']']:
                        try:
                            items.append(json.loads(line))
                        except:
                            pass
            
            if not items:
                print(f"  No vulnerabilities found")
                continue
            
            sqli_count = 0
            domain_vulns = []
            
            for item in items:
                plugin = item.get('plugin', '')
                if 'sql' not in plugin.lower():
                    continue
                
                sqli_count += 1
                detail = item.get('detail', {})
                addr = detail.get('addr', '')
                payload = detail.get('payload', '')
                snapshot = detail.get('snapshot', [])
                
                # Extract parameter name from extra.param.key (the CORRECT source!)
                extra = detail.get('extra', {})
                param_info = extra.get('param', {})
                param = param_info.get('key', '')
                param_position = param_info.get('position', '')  # 'query' or 'body'
                
                # Determine HTTP method from param_position
                if param_position == 'body':
                    method = 'POST'
                elif param_position == 'query':
                    method = 'GET'
                else:
                    # Fallback: get method from snapshot
                    method = 'GET'
                    if snapshot and len(snapshot) > 0 and len(snapshot[0]) > 0:
                        request_text = snapshot[0][0]
                        first_line = request_text.split('\r\n')[0] if '\r\n' in request_text else ''
                        if first_line.startswith('POST'):
                            method = 'POST'
                
                # If param is still empty, try to find it in request (fallback)
                if not param and snapshot and len(snapshot) > 0 and len(snapshot[0]) > 0:
                    param = find_parameter_in_request(snapshot[0][0], payload)
                
                # Classify vulnerability type
                pl = plugin.lower()
                if 'error-based' in pl:
                    sqli_type = 'Error-based SQLi'
                elif 'time-based' in pl or 'blind' in pl:
                    sqli_type = 'Time-based SQLi'
                else:
                    sqli_type = 'SQL Injection'
                
                domain_vulns.append((addr, param, method, sqli_type))
            
            if sqli_count > 0:
                results[domain] = domain_vulns
                print(f"{COLOR_GREEN}  ✓ {COLOR_MAGENTA}{domain}{COLOR_RESET}: {COLOR_YELLOW}{sqli_count}{COLOR_RESET} SQLi")
            
        except Exception as e:
            print(f"{COLOR_YELLOW}  ✗ Error: {e}{COLOR_RESET}")
    
    return results


def write_csv(results, output_file):
    """Write results to CSV file."""
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['domain', 'sqli_count', 'url', 'parameter', 'method', 'sqli_type'])
        
        for domain, vulns in results.items():
            sqli_count = len(vulns)
            domain_url = f"https://{domain}"
            
            for url, param, method, sqli_type in vulns:
                writer.writerow([domain_url, sqli_count, url, param, method, sqli_type])


def main():
    parser = argparse.ArgumentParser(
        description='X-Ray JSON Report Parser - Extract SQLi vulnerabilities to CSV'
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--directory', help='Directory containing JSON files')
    group.add_argument('-f', '--files', help='Comma-separated list of JSON files')
    parser.add_argument('-o', '--output', help='Output CSV file (default: auto-generated)')
    
    args = parser.parse_args()
    
    # Banner
    print(BANNER)
    print(f"{COLOR_CYAN}{'=' * 71}")
    print("X-Ray JSON Report Parser")
    print(f"{'=' * 71}{COLOR_RESET}")
    print()
    
    # Collect JSON files
    json_files = []
    
    if args.directory:
        directory = Path(args.directory)
        if not directory.exists():
            print(f"{COLOR_YELLOW}Error: Directory '{args.directory}' not found{COLOR_RESET}")
            sys.exit(1)
        
        json_files = list(directory.glob('*.json'))
        print(f"Scanning directory: {COLOR_CYAN}{args.directory}{COLOR_RESET}")
        print(f"Found {COLOR_YELLOW}{len(json_files)}{COLOR_RESET} JSON files")
    
    elif args.files:
        for file_path in args.files.split(','):
            file_path = file_path.strip()
            if Path(file_path).exists():
                json_files.append(Path(file_path))
            else:
                print(f"{COLOR_YELLOW}Warning: File '{file_path}' not found{COLOR_RESET}")
        
        print(f"Using {COLOR_YELLOW}{len(json_files)}{COLOR_RESET} JSON file(s)")
    
    if not json_files:
        print(f"{COLOR_YELLOW}No JSON files to process{COLOR_RESET}")
        sys.exit(1)
    
    print()
    
    # Parse JSON files (with colored output for each domain)
    results = parse_json_files(json_files)
    
    if not results:
        print(f"\n{COLOR_YELLOW}No vulnerabilities found{COLOR_RESET}")
        sys.exit(0)
    
    # Generate output filename
    if args.output:
        output_file = args.output
    else:
        output_file = f"vulnerabilities_{Path(json_files[0]).parent.name}.csv"
    
    # Write CSV
    write_csv(results, output_file)
    
    # Print summary
    print()
    print(f"{COLOR_CYAN}{'=' * 71}")
    print("RESULTS:")
    print(f"{'=' * 71}{COLOR_RESET}")
    
    total_domains = len(results)
    total_vulns = sum(len(vulns) for vulns in results.values())
    
    print(f"Total domains with vulnerabilities: {COLOR_GREEN}{total_domains}{COLOR_RESET}")
    print(f"Total vulnerabilities: {COLOR_GREEN}{total_vulns}{COLOR_RESET}")
    print(f"CSV: {COLOR_CYAN}{output_file}{COLOR_RESET}")
    print()
    
    print("Domains with vulnerabilities:")
    for domain, vulns in results.items():
        print(f"  {COLOR_MAGENTA}{domain}{COLOR_RESET}: {COLOR_YELLOW}{len(vulns)}{COLOR_RESET}")
    
    # Final status
    with open(output_file, 'r', encoding='utf-8') as f:
        row_count = sum(1 for line in f)
    
    print()
    print(f"{COLOR_CYAN}{'=' * 71}{COLOR_RESET}")
    print(f"{COLOR_GREEN}CSV created: {output_file}{COLOR_RESET}")
    print(f"{COLOR_GREEN}CSV rows: {row_count} (including header){COLOR_RESET}")
    print(f"{COLOR_CYAN}{'=' * 71}{COLOR_RESET}")


if __name__ == '__main__':
    main()
