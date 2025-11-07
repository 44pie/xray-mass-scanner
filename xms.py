#!/usr/bin/env python3
"""
XMS - X-Ray Mass Scanner Launcher
Unified wrapper for all XMS modules
"""

import sys
import subprocess
from pathlib import Path

RAINBOW_BANNER = """
\033[95m ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ \033[0m
\033[95m||X |||R |||A |||Y |||M |||A |||S |||S |||C |||A |||N |||N |||E |||R ||\033[0m
\033[95m||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||\033[0m
\033[95m|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|/__\\|\033[0m
"""

MODULES = {
    'cr': {
        'script': 'crawler_runner.py',
        'name': 'Crawler Runner',
        'desc': 'Parallel X-Ray vulnerability scanner'
    },
    'rg': {
        'script': 'request_generator.py',
        'name': 'Request Generator',
        'desc': 'Generate SQLMap request files from JSON reports'
    },
    'sr': {
        'script': 'sqlmap_runner.py',
        'name': 'SQLMap Runner',
        'desc': 'Automated SQLMap exploitation using byobu sessions'
    }
}

def show_help():
    """Display unified help with all module banners"""
    print(RAINBOW_BANNER)
    print("\n\033[1;36mX-Ray Mass Scanner - Unified Module Launcher\033[0m\n")
    
    print("\033[1mUsage:\033[0m")
    print("  python3 xms.py <module> [options]")
    print("  python3 xms.py -h | --help")
    print()
    
    print("\033[1mAvailable Modules:\033[0m")
    for shortcut, info in MODULES.items():
        print(f"  \033[1;33m{shortcut:3}\033[0m  {info['name']:20} - {info['desc']}")
    print()
    
    print("\033[1mExamples:\033[0m")
    print("  \033[90m# Run crawler (scanner)\033[0m")
    print("  python3 xms.py cr -l urls.txt --xray ~/xray/xray_linux_amd64 -w 10")
    print()
    print("  \033[90m# Generate request files\033[0m")
    print("  python3 xms.py rg -d output/json -o requests")
    print()
    print("  \033[90m# Run SQLMap automation\033[0m")
    print("  python3 xms.py sr -r requests --sqlmap ~/sqlmap/sqlmap.py -c 10 -w 3")
    print()
    
    print("\033[1mModule Help:\033[0m")
    print("  python3 xms.py <module> -h    \033[90m# Show module-specific help\033[0m")
    print()
    
    print("\033[1;36m" + "=" * 70 + "\033[0m\n")
    
    for shortcut, info in MODULES.items():
        script_path = Path(__file__).parent / info['script']
        if script_path.exists():
            print(f"\033[1;35m{'─' * 70}\033[0m")
            print(f"\033[1;33m{shortcut.upper()}\033[0m - \033[1m{info['name']}\033[0m ({info['script']})")
            print(f"\033[1;35m{'─' * 70}\033[0m\n")
            
            result = subprocess.run(
                [sys.executable, str(script_path), '-h'],
                capture_output=True,
                text=True
            )
            print(result.stdout)
            print()

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ['-h', '--help', 'help']:
        show_help()
        return
    
    module = sys.argv[1]
    
    if module not in MODULES:
        print(f"\033[1;31mError: Unknown module '{module}'\033[0m")
        print(f"\nAvailable modules: {', '.join(MODULES.keys())}")
        print("Use 'python3 xms.py -h' for help")
        sys.exit(1)
    
    script_path = Path(__file__).parent / MODULES[module]['script']
    
    if not script_path.exists():
        print(f"\033[1;31mError: Module script not found: {script_path}\033[0m")
        sys.exit(1)
    
    module_args = sys.argv[2:]
    
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)] + module_args,
            check=False
        )
        sys.exit(result.returncode)
    except KeyboardInterrupt:
        print("\n\n\033[1;33mInterrupted by user\033[0m")
        sys.exit(130)
    except Exception as e:
        print(f"\033[1;31mError running module: {e}\033[0m")
        sys.exit(1)

if __name__ == '__main__':
    main()
