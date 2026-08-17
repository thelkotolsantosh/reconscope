# ReconScope

A Python CLI that takes a domain and builds a structured reconnaissance report — DNS, WHOIS, subdomains, HTTP security posture, technology fingerprinting, TLS info, and open ports — then exports everything to JSON and CSV.

```
╔══════════════════════════════════════╗
║           ReconScope v1.0            ║
╚══════════════════════════════════════╝
Target: example.com

[+] DNS
    A       : 93.184.216.34
    NS      : a.iana-servers.net

[+] Subdomains (3 found)
    api.example.com
    dev.example.com
    mail.example.com

[+] Technologies
    Nginx
    Cloudflare

[+] Security Headers
    X-Frame-Options          : MISSING
    Content-Security-Policy  : MISSING
    Strict-Transport-Security: PRESENT

[+] Ports (method: nmap)
    80/tcp   OPEN   http
    443/tcp  OPEN   https

[+] Report
    reports/example.com_report.json
    reports/example.com_report.csv
```

## ⚠️ Use responsibly

ReconScope only performs **passive/OSINT-style reconnaissance** (public DNS, WHOIS, certificate-transparency logs) plus **lightweight active checks** (HTTP requests, a TLS handshake, and a common-port scan) against the target itself. This is the same class of check as `nmap`, `curl`, or `dig`, run against a single host.

**Only run this against domains you own or have explicit authorization to test.** Scanning systems without permission may violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), or equivalent laws elsewhere, and may violate the target's terms of service. You are responsible for how you use this tool.

## Features

- **DNS enumeration** — A, AAAA, MX, NS, TXT, CNAME, SOA records
- **WHOIS lookup** — registrar, creation/expiration dates, name servers, status
- **Subdomain discovery** — via certificate transparency logs (crt.sh)
- **HTTP/HTTPS detection** — scheme, status, redirects, server banner
- **Security header analysis** — HSTS, CSP, X-Frame-Options, and more
- **Technology fingerprinting** — server, framework, and CDN signatures from headers/cookies/body
- **Open-port scanning** — uses `nmap` if installed, falls back to a threaded socket scan otherwise
- **robots.txt inspection** — disallowed paths and sitemap references
- **Basic SSL/TLS info** — issuer, expiry, TLS version, SAN entries
- **Export** — clean JSON and CSV reports, plus a readable terminal report

## Installation

```bash
git clone https://github.com/<your-username>/reconscope.git
cd reconscope
python3 -m venv .venv && source .venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

Optional but recommended: install [nmap](https://nmap.org/download.html) for faster, more accurate port scans (`apt install nmap`, `brew install nmap`, etc.). ReconScope works without it — it falls back to a built-in socket scanner over a common-port list.

To install as a CLI command (`reconscope` instead of `python reconscope.py`):

```bash
pip install -e .
```

## Usage

```bash
python reconscope.py example.com
```

Or, if installed via `pip install -e .`:

```bash
reconscope example.com
```

### Options

| Flag | Description |
|---|---|
| `-o, --output-dir DIR` | Directory for JSON/CSV reports (default: `reports/`) |
| `--skip-ports` | Skip the port scan |
| `--skip-subdomains` | Skip certificate-transparency subdomain discovery |
| `--no-export` | Print the terminal report only; don't write files |
| `--version` | Print version and exit |

Examples:

```bash
# Full scan
python reconscope.py example.com

# Fast scan, no port scan, no file output
python reconscope.py example.com --skip-ports --no-export

# Custom report location
python reconscope.py example.com -o ./out
```

## Project structure

```
reconscope/
├── reconscope/
│   ├── __init__.py
│   ├── cli.py            # argument parsing + scan orchestration
│   ├── dns_enum.py        # DNS record enumeration
│   ├── whois_lookup.py   # WHOIS lookup
│   ├── subdomains.py     # certificate-transparency subdomain discovery
│   ├── headers.py        # HTTP detection, security headers, robots.txt, TLS
│   ├── technologies.py   # technology fingerprinting
│   ├── ports.py          # nmap / socket port scanning
│   └── reporter.py       # terminal rendering + JSON/CSV export
├── tests/                 # pytest unit tests (network calls mocked)
├── examples/               # example output for reference
├── reports/                 # generated reports land here (gitignored)
├── reconscope.py            # thin entrypoint script
├── requirements.txt
├── requirements-dev.txt
├── setup.py
├── README.md
├── LICENSE
└── .gitignore
```

## Running tests

```bash
pip install -r requirements-dev.txt
pytest
```

All tests mock network calls (via `responses` / `pytest-mock`) — no live traffic is sent during the test suite.

## Roadmap ideas

- [ ] Wordlist-based subdomain brute-forcing as a fallback/complement to cert transparency
- [ ] Async HTTP for faster multi-subdomain probing
- [ ] Wappalyzer-style JSON signature file instead of hardcoded fingerprints
- [ ] HTML report output (in addition to JSON/CSV)
- [ ] Rate limiting / concurrency controls for large scans
- [ ] Docker image for a zero-install run

## License

MIT — see [LICENSE](LICENSE).
