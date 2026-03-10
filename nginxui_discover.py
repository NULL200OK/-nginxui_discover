#!/usr/bin/env python3
"""
nginxui_discover.py - Nginx UI Instance Discovery & Version Scanner
Discover Nginx UI web interfaces and identify versions ≤2.3.2 vulnerable to CVE-2026-27944

"""

import argparse
import requests
import json
import re
import sys
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from typing import List, Tuple, Dict, Optional
import csv
from datetime import datetime

print("""

███╗░░██╗██╗░░░██╗██╗░░░░░██╗░░░░░██████╗░░█████╗░░█████╗░  ░█████╗░██╗░░██╗
████╗░██║██║░░░██║██║░░░░░██║░░░░░╚════██╗██╔══██╗██╔══██╗  ██╔══██╗██║░██╔╝
██╔██╗██║██║░░░██║██║░░░░░██║░░░░░░░███╔═╝██║░░██║██║░░██║  ██║░░██║█████═╝░
██║╚████║██║░░░██║██║░░░░░██║░░░░░██╔══╝░░██║░░██║██║░░██║  ██║░░██║██╔═██╗░
██║░╚███║╚██████╔╝███████╗███████╗███████╗╚█████╔╝╚█████╔╝  ╚█████╔╝██║░╚██╗
╚═╝░░╚══╝░╚═════╝░╚══════╝╚══════╝╚══════╝░╚════╝░░╚════╝░  ░╚════╝░╚═╝░░╚═╝
nginxui_discover.py - Nginx UI Instance Discovery & Version Scanner
Discover Nginx UI web interfaces and identify versions ≤2.3.2 vulnerable to CVE-2026-27944
– NULL200OL-AI💀🔥created by NABEEL

""")

# Suppress SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ==================== CONFIGURATION ====================
TIMEOUT = 5
MAX_THREADS = 20
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
COMMON_PORTS = [80, 443, 8080, 8443, 9000, 9001, 9080, 9443]
COMMON_PATHS = [
    "/",
    "/api/backup",
    "/api/version",
    "/api/configs",
    "/api/settings",
    "/login",
    "/dashboard",
    "/static/js/main.js",
    "/favicon.ico"
]

# Nginx UI specific fingerprints
FINGERPRINTS = {
    "title": ["Nginx UI", "Nginx-UI", "nginx ui"],
    "headers": {
        "server": ["nginx-ui", "nginx-ui-server"],
        "x-powered-by": ["nginx-ui"]
    },
    "body_patterns": [
        r"nginx.?ui",
        r"nginxui",
        r"version\s*:\s*(\d+\.\d+\.\d+[^"]*)",
        r"<title>Nginx UI</title>",
        r"nginx-ui-web"
    ]
}

# ==================== VERSION DETECTION ====================
VULNERABLE_VERSION_RANGE = {
    "max": "2.3.2",
    "min": "1.0.0"  # Assuming versions start here
}

def parse_version(version_str: str) -> tuple:
    """Convert version string to comparable tuple"""
    if not version_str:
        return (0, 0, 0)
    
    # Handle beta/alpha suffixes
    version_str = re.sub(r'[^\d\.]', '', version_str.split('-')[0].split('_')[0])
    parts = version_str.split('.')
    while len(parts) < 3:
        parts.append('0')
    
    try:
        return tuple(int(p) for p in parts[:3])
    except ValueError:
        return (0, 0, 0)

def is_version_vulnerable(version_str: str) -> bool:
    """Check if version is ≤ 2.3.2"""
    if not version_str:
        return None  # Unknown
    
    version_tuple = parse_version(version_str)
    max_tuple = parse_version(VULNERABLE_VERSION_RANGE["max"])
    
    return version_tuple <= max_tuple and version_tuple >= (1, 0, 0)

# ==================== SCANNING FUNCTIONS ====================
def normalize_url(target: str, port: int = None, ssl: bool = False) -> str:
    """Build URL from target and port"""
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        scheme = parsed.scheme
        netloc = parsed.netloc
    else:
        scheme = 'https' if ssl else 'http'
        if ':' in target:
            netloc = target
        else:
            netloc = f"{target}:{port}" if port else target
    
    return f"{scheme}://{netloc}"

def check_endpoint(url: str, path: str, timeout: int = TIMEOUT) -> Dict:
    """Check if endpoint exists and return response info"""
    full_url = urljoin(url, path)
    try:
        session = requests.Session()
        session.mount('http://', HTTPAdapter(max_retries=2))
        session.mount('https://', HTTPAdapter(max_retries=2))
        
        response = session.get(
            full_url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={'User-Agent': USER_AGENT}
        )
        
        return {
            'url': full_url,
            'status': response.status_code,
            'headers': dict(response.headers),
            'body': response.text[:1000] if response.text else '',
            'content_type': response.headers.get('Content-Type', ''),
            'server': response.headers.get('Server', ''),
            'elapsed': response.elapsed.total_seconds()
        }
    except requests.exceptions.SSLError:
        # Try without SSL
        if url.startswith('https://'):
            return check_endpoint(url.replace('https://', 'http://'), path, timeout)
        return {'url': full_url, 'error': 'SSL Error', 'status': 0}
    except Exception as e:
        return {'url': full_url, 'error': str(e), 'status': 0}

def extract_version_from_response(response: Dict) -> Optional[str]:
    """Extract Nginx UI version from response"""
    # Method 1: Check /api/version endpoint
    if '/api/version' in response.get('url', ''):
        try:
            data = json.loads(response.get('body', '{}'))
            if data.get('version'):
                return data['version']
        except:
            pass
    
    # Method 2: Check response headers
    headers = response.get('headers', {})
    for header, value in headers.items():
        if 'version' in header.lower():
            version_match = re.search(r'(\d+\.\d+\.\d+[^"\']*)', value)
            if version_match:
                return version_match.group(1)
    
    # Method 3: Parse from HTML/JS
    body = response.get('body', '')
    patterns = [
        r'version["\']?\s*:\s*["\'](\d+\.\d+\.\d+[^"\']*)',
        r'Nginx UI[^\d]*(\d+\.\d+\.\d+)',
        r'v(\d+\.\d+\.\d+)[^<]*</',
        r'window\.__INITIAL_STATE__.*?"version":"(\d+\.\d+\.\d+)"'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            return match.group(1)
    
    # Method 4: Check X-Backup-Security header (vulnerable versions expose this)
    if '/api/backup' in response.get('url', ''):
        if 'X-Backup-Security' in headers:
            return "≤2.3.2 (vulnerable - header present)"
    
    return None

def is_nginx_ui(response: Dict) -> Tuple[bool, float]:
    """Determine if response indicates Nginx UI with confidence score"""
    confidence = 0.0
    reasons = []
    
    if not response or response.get('status', 0) not in [200, 401, 403]:
        return False, 0.0
    
    headers = response.get('headers', {})
    body = response.get('body', '').lower()
    url = response.get('url', '')
    
    # Check title
    title_match = re.search(r'<title>(.*?)</title>', response.get('body', ''), re.IGNORECASE)
    if title_match:
        title = title_match.group(1).lower()
        for fp_title in FINGERPRINTS['title']:
            if fp_title.lower() in title:
                confidence += 0.3
                reasons.append(f"title contains '{fp_title}'")
    
    # Check headers
    for header, patterns in FINGERPRINTS['headers'].items():
        header_value = headers.get(header, '').lower()
        for pattern in patterns:
            if pattern.lower() in header_value:
                confidence += 0.2
                reasons.append(f"header '{header}' matches '{pattern}'")
    
    # Check body patterns
    for pattern in FINGERPRINTS['body_patterns']:
        if re.search(pattern, response.get('body', ''), re.IGNORECASE):
            confidence += 0.15
            reasons.append(f"body matches pattern '{pattern}'")
    
    # API endpoint detection
    if '/api/backup' in url and response.get('status') == 200:
        confidence += 0.4
        reasons.append("accessible /api/backup endpoint")
    
    if '/api/version' in url and response.get('status') == 200:
        try:
            json.loads(response.get('body', '{}'))
            confidence += 0.5
            reasons.append("valid JSON API response")
        except:
            pass
    
    # Version extraction increases confidence
    version = extract_version_from_response(response)
    if version:
        confidence += 0.25
        reasons.append(f"version detected: {version}")
    
    return confidence >= 0.4, confidence

# ==================== MAIN SCANNER ====================
def scan_target(target: str, port: int = None, ssl: bool = False) -> Dict:
    """Scan a single target for Nginx UI"""
    base_url = normalize_url(target, port, ssl)
    result = {
        'target': target,
        'port': port,
        'ssl': ssl,
        'url': base_url,
        'is_nginx_ui': False,
        'confidence': 0.0,
        'version': None,
        'vulnerable': False,
        'endpoints': {},
        'timestamp': datetime.now().isoformat()
    }
    
    # Check common paths
    for path in COMMON_PATHS:
        response = check_endpoint(base_url, path)
        result['endpoints'][path] = {
            'status': response.get('status', 0),
            'headers': {k: v for k, v in response.get('headers', {}).items() if k in ['Server', 'X-Powered-By', 'X-Backup-Security']}
        }
        
        # Extract version from any response
        version = extract_version_from_response(response)
        if version and not result['version']:
            result['version'] = version
        
        # Check if this is Nginx UI
        is_ui, confidence = is_nginx_ui(response)
        if is_ui:
            result['is_nginx_ui'] = True
            result['confidence'] = max(result['confidence'], confidence)
    
    # Determine vulnerability status
    if result['version']:
        result['vulnerable'] = is_version_vulnerable(result['version'])
    elif result['is_nginx_ui']:
        # Check for direct vulnerability indicators
        backup_resp = result['endpoints'].get('/api/backup', {})
        if backup_resp.get('status') == 200 and backup_resp.get('headers', {}).get('X-Backup-Security'):
            result['vulnerable'] = True
            result['version'] = "≤2.3.2 (confirmed by header)"
    
    return result

def scan_target_wrapper(args):
    """Wrapper for thread pool execution"""
    target, port, ssl = args
    try:
        return scan_target(target, port, ssl)
    except Exception as e:
        return {
            'target': target,
            'port': port,
            'ssl': ssl,
            'error': str(e),
            'is_nginx_ui': False
        }

def generate_targets_from_cidr(cidr: str) -> List[str]:
    """Generate IP addresses from CIDR notation"""
    try:
        from ipaddress import ip_network
        network = ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ImportError:
        print("[-] ipaddress module not available for CIDR expansion")
        return [cidr]
    except Exception as e:
        print(f"[-] Invalid CIDR: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(
        description="Nginx UI Discovery Scanner - Find instances of Nginx UI web interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 nginxui_discover.py --target 192.168.1.100
  python3 nginxui_discover.py --target example.com --port 9000
  python3 nginxui_discover.py --cidr 192.168.1.0/24 --threads 50
  python3 nginxui_discover.py --file targets.txt --output results.json
        """
    )
    
    # Target input options
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--target', '-t', help='Single target (IP or domain)')
    group.add_argument('--cidr', help='CIDR range to scan (e.g., 192.168.1.0/24)')
    group.add_argument('--file', '-f', help='File containing targets (one per line)')
    
    # Scan options
    parser.add_argument('--port', '-p', type=int, help='Specific port to scan')
    parser.add_argument('--ports', help='Comma-separated list of ports (e.g., 80,443,9000)')
    parser.add_argument('--ssl', action='store_true', help='Force HTTPS')
    parser.add_argument('--threads', type=int, default=MAX_THREADS, help=f'Thread count (default: {MAX_THREADS})')
    parser.add_argument('--timeout', type=int, default=TIMEOUT, help=f'Request timeout (default: {TIMEOUT}s)')
    parser.add_argument('--output', '-o', help='Output file (JSON or CSV based on extension)')
    parser.add_argument('--vulnerable-only', action='store_true', help='Show only vulnerable instances')
    parser.add_argument('--no-banner', action='store_true', help='Disable banner display')
    
    args = parser.parse_args()
    global TIMEOUT
    TIMEOUT = args.timeout
    
    # Display banner
    if not args.no_banner:
        print("=" * 70)
        print("Nginx UI Discovery Scanner - CVE-2026-27944 Version Detection")
        print("=" * 70)
        print(f"Threads: {args.threads} | Timeout: {TIMEOUT}s | Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
    
    # Build target list
    targets = []
    
    if args.target:
        targets = [args.target]
    elif args.cidr:
        targets = generate_targets_from_cidr(args.cidr)
        print(f"[*] Generated {len(targets)} targets from CIDR {args.cidr}")
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(targets)} targets from {args.file}")
        except Exception as e:
            print(f"[-] Error reading file: {e}")
            sys.exit(1)
    
    # Build port list
    ports_to_scan = []
    if args.port:
        ports_to_scan = [args.port]
    elif args.ports:
        ports_to_scan = [int(p.strip()) for p in args.ports.split(',')]
    else:
        ports_to_scan = COMMON_PORTS
    
    # Prepare scan jobs
    scan_jobs = []
    for target in targets:
        for port in ports_to_scan:
            scan_jobs.append((target, port, args.ssl))
    
    print(f"[*] Starting scan of {len(targets)} targets × {len(ports_to_scan)} ports = {len(scan_jobs)} checks")
    print("[*] Press Ctrl+C to stop...\n")
    
    # Run scans
    results = []
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(scan_target_wrapper, job) for job in scan_jobs]
            
            for i, future in enumerate(as_completed(futures), 1):
                result = future.result()
                
                # Filter results
                if result.get('is_nginx_ui'):
                    if args.vulnerable_only and not result.get('vulnerable'):
                        continue
                    results.append(result)
                    
                    # Display result
                    status = "🔴 VULNERABLE" if result.get('vulnerable') else "🟢 PATCHED"
                    version_info = f"v{result['version']}" if result.get('version') else "unknown version"
                    print(f"[{i}/{len(scan_jobs)}] {status} | {result['url']} | {version_info} | confidence: {result['confidence']:.1%}")
                
                # Progress indicator
                if i % 100 == 0:
                    print(f"[*] Progress: {i}/{len(scan_jobs)} checks completed")
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    
    # Summary
    print("\n" + "=" * 70)
    print("SCAN SUMMARY")
    print("=" * 70)
    print(f"Total targets scanned: {len(targets)}")
    print(f"Total ports checked: {len(ports_to_scan)}")
    print(f"Nginx UI instances found: {len(results)}")
    
    if results:
        vulnerable_count = sum(1 for r in results if r.get('vulnerable'))
        print(f"  - Vulnerable (≤2.3.2): {vulnerable_count}")
        print(f"  - Patched/Unknown: {len(results) - vulnerable_count}")
        
        # Display top results
        print("\n[+] Discovered Nginx UI instances:")
        for r in sorted(results, key=lambda x: x.get('vulnerable', False), reverse=True)[:10]:
            vuln_tag = "🔴" if r.get('vulnerable') else "🟢"
            print(f"  {vuln_tag} {r['url']} - v{r.get('version', 'unknown')}")
    
    # Save results if requested
    if args.output and results:
        try:
            if args.output.endswith('.csv'):
                with open(args.output, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['url', 'version', 'vulnerable', 'confidence', 'timestamp', 'target', 'port'])
                    writer.writeheader()
                    for r in results:
                        writer.writerow({
                            'url': r['url'],
                            'version': r.get('version', ''),
                            'vulnerable': r.get('vulnerable', False),
                            'confidence': r.get('confidence', 0),
                            'timestamp': r['timestamp'],
                            'target': r['target'],
                            'port': r.get('port', '')
                        })
            else:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
            print(f"\n[+] Results saved to {args.output}")
        except Exception as e:
            print(f"[-] Error saving results: {e}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
