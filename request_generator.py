#!/usr/bin/env python3
"""
X-Ray Request File Generator v2 - Creates SQLMap request files using regex parsing
Works with partially corrupted X-Ray JSON files
"""

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import urlparse, unquote, parse_qs, urlencode

# ANSI color codes
COLOR_BLUE = '\033[94m'
COLOR_GREEN = '\033[92m'
COLOR_CYAN = '\033[96m'
COLOR_MAGENTA = '\033[95m'
COLOR_YELLOW = '\033[93m'
COLOR_RESET = '\033[0m'

# ASCII Banner
BANNER_LINES = [
    " ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ",
    "||R |||E |||Q |||U |||E |||S |||T |||G |||E |||N |||E |||R |||A |||T |||O |||R ||",
    "||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||",
    "|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|"
]
BANNER = f"{COLOR_CYAN}" + "\n".join(BANNER_LINES) + f"{COLOR_RESET}"


def extract_post_vulns_regex(content):
    """
    Extract POST vulnerabilities using regex patterns
    Returns list of (param_key, http_request, method) tuples
    """
    results = []
    
    # Pattern to find POST requests with body parameters
    # ВАЖНО: В JSON порядок может быть snapshot → param или param → snapshot
    # Увеличен лимит для огромных JSON файлов (до 2MB между param и snapshot)
    # ВАЖНО: НЕ используем [^\]]* т.к. ] может быть внутри POST данных!
    
    # Вариант 1: snapshot идет ПЕРЕД param
    # Используем (?:[^"\\]|\\.)* чтобы захватывать escaped кавычки \"
    pattern1 = r'"snapshot":\[\["(POST(?:[^"\\]|\\.)*)".{1,2000000}?"key":"([^"]+)","position":"body"'
    # Вариант 2: param идет ПЕРЕД snapshot
    pattern2 = r'"key":"([^"]+)","position":"body".{1,2000000}?"snapshot":\[\["(POST(?:[^"\\]|\\.)*)"'
    
    # Пробуем оба паттерна
    for match in re.finditer(pattern1, content, re.DOTALL):
        http_request = match.group(1)  # POST request
        param_key = match.group(2)      # parameter name
        
        # Unescape the HTTP request (включая escaped кавычки)
        http_request = http_request.replace('\\r\\n', '\r\n')
        http_request = http_request.replace('\\/', '/')
        http_request = http_request.replace('\\"', '"')
        
        # Валидация: параметр должен быть в теле (multipart: name="param" или обычный: param=)
        if param_key in http_request or f'name="{param_key}"' in http_request or f"name='{param_key}'" in http_request:
            results.append((param_key, http_request, 'POST'))
    
    for match in re.finditer(pattern2, content, re.DOTALL):
        param_key = match.group(1)      # parameter name
        http_request = match.group(2)  # POST request
        
        # Unescape the HTTP request (включая escaped кавычки)
        http_request = http_request.replace('\\r\\n', '\r\n')
        http_request = http_request.replace('\\/', '/')
        http_request = http_request.replace('\\"', '"')
        
        # Валидация: параметр должен быть в теле (multipart: name="param" или обычный: param=)
        if param_key in http_request or f'name="{param_key}"' in http_request or f"name='{param_key}'" in http_request:
            results.append((param_key, http_request, 'POST'))
    
    return results


def extract_get_vulns_regex(content):
    """
    Extract GET vulnerabilities using regex patterns
    Returns list of (param_key, http_request, method) tuples
    """
    results = []
    
    # Pattern to find GET requests with query parameters
    # ВАЖНО: В JSON порядок может быть snapshot → param или param → snapshot
    # Ищем оба варианта
    # ВАЖНО: НЕ используем [^\]]* т.к. ] может быть внутри GET данных!
    
    # Вариант 1: snapshot идет ПЕРЕД param (увеличен лимит для огромных JSON файлов)
    # Используем (?:[^"\\]|\\.)* чтобы захватывать escaped кавычки \"
    pattern1 = r'"snapshot":\[\["(GET(?:[^"\\]|\\.)*)".{1,2000000}?"key":"([^"]+)","position":"query"'
    # Вариант 2: param идет ПЕРЕД snapshot
    pattern2 = r'"key":"([^"]+)","position":"query".{1,2000000}?"snapshot":\[\["(GET(?:[^"\\]|\\.)*)"'
    
    # Пробуем оба паттерна
    for match in re.finditer(pattern1, content, re.DOTALL):
        http_request = match.group(1)  # GET request
        param_key = match.group(2)      # parameter name
        
        # Unescape the HTTP request (включая escaped кавычки)
        http_request = http_request.replace('\\r\\n', '\r\n')
        http_request = http_request.replace('\\/', '/')
        http_request = http_request.replace('\\"', '"')
        
        results.append((param_key, http_request, 'GET'))
    
    for match in re.finditer(pattern2, content, re.DOTALL):
        param_key = match.group(1)      # parameter name
        http_request = match.group(2)  # GET request
        
        # Unescape the HTTP request (включая escaped кавычки)
        http_request = http_request.replace('\\r\\n', '\r\n')
        http_request = http_request.replace('\\/', '/')
        http_request = http_request.replace('\\"', '"')
        
        results.append((param_key, http_request, 'GET'))
    
    return results


def clean_sql_payloads(params_string):
    """
    Remove SQL injection payloads from parameters (body or query string)
    Replaces payload values with simple '1' to get clean request
    """
    import re
    
    # Strategy: Replace complex values containing SQL patterns with '1'
    # Split by &, clean each parameter, rebuild
    
    params = []
    for pair in params_string.split('&'):
        if '=' in pair:
            key, value = pair.split('=', 1)
            
            # Check if value contains SQL injection patterns
            if any(pattern in value.lower() for pattern in [
                '%27',  # '
                '%2f%2a',  # /*
                'convert',
                'hashbytes',
                'sys.fn',
                '%e9%8e%88',  # 鎈
                'and+',  # and+
                'or+',  # or+
            ]):
                # Replace with clean value
                params.append(f'{key}=1')
            else:
                # Keep original
                params.append(pair)
        else:
            params.append(pair)
    
    return '&'.join(params)


def clean_get_url(url):
    """
    Clean GET URL from SQL injection payloads in query string
    """
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    
    parsed = urlparse(url)
    
    # If no query string, return as is
    if not parsed.query:
        return url
    
    # Clean the query string
    cleaned_query = clean_sql_payloads(parsed.query)
    
    # Rebuild URL
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        cleaned_query,
        parsed.fragment
    ))


def clean_request_body(body):
    """
    Clean POST body from SQL injection payloads
    Returns clean request without any markers
    """
    if not body:
        return body
    
    # Decode unicode escapes first (\u0026 -> &)
    body = body.encode('utf-8').decode('unicode-escape')
    
    # Clean SQL injection payloads from ALL parameters
    return clean_sql_payloads(body)


def generate_request_file_from_http(param_key, http_request, domain, output_dir, param_counter, method='POST'):
    """
    Generate request file from HTTP request string (POST or GET)
    Structure: output_dir/domain/param_NNN.txt
    """
    try:
        # Split request into lines
        lines = http_request.split('\r\n')
        
        if not lines:
            return None
        
        # Decode unicode escapes in all lines
        lines = [line.encode('utf-8').decode('unicode-escape') if '\\u' in line else line for line in lines]
        
        # For GET requests - check parameter in URL and clean it
        if method == 'GET':
            if not lines[0]:
                return None
            
            # Extract URL from first line (e.g., "GET /path?param=value HTTP/1.1")
            parts = lines[0].split(' ')
            if len(parts) >= 2:
                url = parts[1]
                
                # Check if parameter exists in URL
                if param_key not in url:
                    return None
                
                # Clean URL from SQL payloads
                cleaned_url = clean_get_url(url)
                
                # Replace URL in first line
                lines[0] = f"{parts[0]} {cleaned_url} {parts[2] if len(parts) > 2 else 'HTTP/1.1'}"
            
            # GET requests don't have body
            request_lines = lines
        
        # For POST requests - check parameter in body and clean it
        else:
            # Find empty line separating headers and body
            body_start_idx = None
            for i, line in enumerate(lines):
                if line.strip() == '':
                    body_start_idx = i + 1
                    break
            
            if body_start_idx is None:
                # No body found in POST - skip
                return None
            
            headers_lines = lines[:body_start_idx]
            body = '\r\n'.join(lines[body_start_idx:])
            
            # Check if parameter exists in body
            if param_key not in body:
                return None
            
            # Clean SQL injection payloads from body
            cleaned_body = clean_request_body(body)
            
            # Reconstruct request
            request_lines = headers_lines + ['', cleaned_body] if cleaned_body else headers_lines
        
        # Create domain directory
        domain_dir = Path(output_dir) / domain
        domain_dir.mkdir(parents=True, exist_ok=True)
        
        # Sanitize parameter name for filename
        safe_param = param_key.replace('/', '_').replace('\\', '_').replace(':', '_').replace('?', '_').replace('&', '_')
        
        # Get counter for this parameter
        counter = param_counter[param_key]
        param_counter[param_key] += 1
        
        # Generate filename: param_METHOD_001.txt (e.g., anyo_i_POST_001.txt)
        filename = f"{safe_param}_{method}_{counter:03d}.txt"
        
        # Write file
        output_path = domain_dir / filename
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\r\n'.join(request_lines))
        
        return output_path
        
    except Exception as e:
        print(f"{COLOR_YELLOW}  Warning: Failed to generate {param_key}: {e}{COLOR_RESET}")
        return None


def process_json_file_regex(json_file, output_dir):
    """
    Process JSON file using regex extraction (POST and GET)
    """
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract domain from filename
        domain = json_file.stem
        
        # Extract POST and GET vulnerabilities
        post_vulns = extract_post_vulns_regex(content)
        get_vulns = extract_get_vulns_regex(content)
        
        all_vulns = post_vulns + get_vulns
        
        if not all_vulns:
            return 0
        
        # Counter for each parameter (for multiple requests with same param)
        from collections import defaultdict
        param_counter = defaultdict(int)
        param_counter.default_factory = lambda: 1
        
        # Initialize counters at 1
        for param_key, _, _ in all_vulns:
            if param_key not in param_counter:
                param_counter[param_key] = 1
        
        # Generate request files
        count = 0
        for param_key, http_request, method in all_vulns:
            result = generate_request_file_from_http(param_key, http_request, domain, output_dir, param_counter, method)
            if result:
                count += 1
        
        return count
        
    except Exception as e:
        print(f"{COLOR_YELLOW}Error processing {json_file}: {e}{COLOR_RESET}")
        return 0


def main():
    print(BANNER)
    print()
    
    parser = argparse.ArgumentParser(
        description='X-Ray Request Generator v2 - Create SQLMap request files using regex parsing'
    )
    parser.add_argument('-d', '--directory', help='Directory containing JSON files')
    parser.add_argument('-f', '--files', help='Comma-separated list of JSON files')
    parser.add_argument('-o', '--output', default='requests', help='Output directory (default: requests)')
    
    args = parser.parse_args()
    
    # Collect JSON files
    json_files = []
    
    if args.directory:
        json_dir = Path(args.directory)
        if not json_dir.exists():
            print(f"{COLOR_YELLOW}Error: Directory not found: {args.directory}{COLOR_RESET}")
            sys.exit(1)
        json_files = list(json_dir.glob('*.json'))
    
    if args.files:
        for file_path in args.files.split(','):
            file_path = file_path.strip()
            if Path(file_path).exists():
                json_files.append(Path(file_path))
    
    if not json_files:
        print(f"{COLOR_YELLOW}No JSON files found. Use -d or -f to specify input.{COLOR_RESET}")
        parser.print_help()
        sys.exit(1)
    
    print(f"{COLOR_CYAN}Processing {len(json_files)} JSON file(s)...{COLOR_RESET}\n")
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Process files
    total_generated = 0
    
    for json_file in json_files:
        print(f"{COLOR_MAGENTA}Processing:{COLOR_RESET} {json_file.name}...", end=' ')
        
        count = process_json_file_regex(json_file, output_dir)
        total_generated += count
        
        if count > 0:
            print(f"{COLOR_GREEN}✓ {count} request(s){COLOR_RESET}")
        else:
            print(f"{COLOR_CYAN}✓ 0 request(s){COLOR_RESET}")
    
    # Summary
    print(f"\n{COLOR_GREEN}{'='*70}{COLOR_RESET}")
    print(f"{COLOR_GREEN}Summary:{COLOR_RESET}")
    print(f"  {COLOR_CYAN}JSON files processed:{COLOR_RESET} {len(json_files)}")
    print(f"  {COLOR_CYAN}Request files generated:{COLOR_RESET} {total_generated}")
    print(f"  {COLOR_CYAN}Output directory:{COLOR_RESET} {output_dir}")
    print(f"{COLOR_GREEN}{'='*70}{COLOR_RESET}\n")


if __name__ == '__main__':
    main()
