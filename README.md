Nginx UI Discovery Scanner - CVE-2026-27944 Version Detector

https://img.shields.io/badge/python-3.6+-blue.svg

https://img.shields.io/badge/license-MIT-green

https://img.shields.io/badge/threading-multi--threaded-brightgreen

Author: NULL200OK

A high‑performance, multi‑threaded scanner to discover Nginx UI web interfaces, detect their version, and identify instances vulnerable to CVE‑2026‑27944 (versions ≤ 2.3.2).

The tool uses passive fingerprinting (titles, headers, body patterns) and probes common API endpoints to accurately identify Nginx UI installations across large networks.

🔍 **Features**

Flexible target input – scan a single host, a CIDR range (e.g., 192.168.1.0/24), or a list from a file.

Multi‑port scanning – checks common Nginx UI ports (80, 443, 8080, 8443, 9000, 9001, 9080, 9443) or custom lists.

Fingerprinting – identifies Nginx UI via:

Page title (<title>Nginx UI</title>)

HTTP headers (Server, X-Powered-By)

Body regex patterns (version strings, UI identifiers)

Version extraction – from /api/version JSON, embedded HTML/JS, or response headers.

Direct vulnerability check – detects the presence of the /api/backup endpoint with the X-Backup-Security header (a clear sign of CVE‑2026‑27944).

Confidence scoring – reduces false positives by combining multiple detection signals.

Vulnerable‑only mode – show only instances that are confirmed vulnerable.

Output to JSON/CSV – save results for further analysis.

Fast multi‑threading – scan hundreds of hosts in seconds.

🚨 **Why This Matters**

CVE‑2026‑27944 is a critical vulnerability in Nginx UI ≤ 2.3.2 that allows any unauthenticated attacker to download and decrypt the server’s full backup, exposing:

User credentials and session tokens

SSL private keys

Application secrets

Full Nginx configuration

This scanner helps you quickly locate vulnerable instances in your environment before attackers do.

⚙️ Installation

bash

git clone https://github.com/NULL200OK/nginx-ui-scanner.git

cd nginx-ui-scanner

pip install requests

No additional dependencies are required (the scanner does not need pycryptodome).

🔧 Usage

text

usage: nginxui_discover.py [-h] (--target TARGET | --cidr CIDR | --file FILE) [--port PORT] [--ports PORTS] [--ssl] [--threads THREADS] [--timeout TIMEOUT] [--output OUTPUT] [--vulnerable-only] [--no-banner]

Examples

bash

# Scan a single host (default ports)

python3 nginxui_discover.py --target 192.168.1.100

# Scan a CIDR range with 50 threads, save JSON results

python3 nginxui_discover.py --cidr 192.168.1.0/24 --threads 50 --output results.json

# Scan from a file, show only vulnerable instances

python3 nginxui_discover.py --file targets.txt --vulnerable-only

# Scan a specific port with HTTPS forced

python3 nginxui_discover.py --target example.com --port 8443 --ssl

**Output**

text

Nginx UI Discovery Scanner - CVE-2026-27944 Version Detection

Threads: 20 | Timeout: 5s | Date: 2026-03-10 14:23:45


[*] Starting scan of 256 targets × 8 ports = 2048 checks

[42/2048] 🔴 VULNERABLE | http://192.168.1.105:9000 | v2.3.2 | confidence: 85%

[87/2048] 🟢 PATCHED | https://192.168.1.110:8443 | v2.4.0 | confidence: 72%

...

**SCAN SUMMARY**

Nginx UI instances found: 12

  - Vulnerable (≤2.3.2): 3
  - 
  - Patched/Unknown: 9
  - 
📚 How It Works

Build scan jobs – expands targets and ports into a list of (host, port) pairs.

Multi‑threaded probing – for each combination, sends HTTP requests to common paths:

/ – root page

/api/version – version API

/api/backup – vulnerable endpoint

/login, /dashboard, /static/js/main.js – additional fingerprints

Fingerprint analysis – examines responses for Nginx UI indicators and assigns a confidence score.

Version extraction – uses JSON parsing, header inspection, and regex on the page body.

Vulnerability check – marks as vulnerable if version ≤ 2.3.2 or the /api/backup endpoint returns the X-Backup-Security header.

Real‑time reporting – displays results as they come in; saves to file if requested.

⚠️ Disclaimer

This tool is intended for authorized security assessments and educational purposes only.

Unauthorized scanning of networks you do not own or have explicit permission to test is illegal. The author (NULL200OK) assumes no liability for misuse.

📄 License

MIT License – see LICENSE for details.

📬 References

CVE‑2026‑27944 (placeholder)

Nginx UI Official Site

