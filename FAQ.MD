# ReconScope — Frequently Asked Questions

100 questions covering installation, day-to-day use, what ReconScope is *for*, and troubleshooting. Use Ctrl+F / Cmd+F to jump to a topic, or browse by section:

1. [What & Why](#1-what--why) (Q1–15)
2. [Installation](#2-installation) (Q16–35)
3. [Basic Usage](#3-basic-usage) (Q36–50)
4. [Feature-Specific Questions](#4-feature-specific-questions) (Q51–70)
5. [Output, Reports & Automation](#5-output-reports--automation) (Q71–82)
6. [Legal, Ethics & Safety](#6-legal-ethics--safety) (Q83–90)
7. [Troubleshooting](#7-troubleshooting) (Q91–100)

---

## 1. What & Why

### Q1. What is ReconScope?
ReconScope is a Python command-line tool that runs passive and lightweight active reconnaissance against a single domain — DNS records, WHOIS data, subdomains, HTTP/HTTPS behavior, security headers, detected technologies, open ports, `robots.txt`, and TLS certificate info — then prints a readable terminal report and exports JSON/CSV files.

### Q2. Who is ReconScope for?
Security students, bug bounty hunters (on in-scope targets), pentesters doing authorized engagements, sysadmins auditing their own infrastructure, and developers who want a quick external view of their own site's security posture.

### Q3. What problem does it solve?
Normally you'd run `dig`, `whois`, `curl -I`, `nmap`, and a browser dev-tools check separately, then manually assemble notes. ReconScope runs all of that in one command and hands you a structured report you can read, diff over time, or feed into other tools.

### Q4. Is ReconScope a vulnerability scanner?
No. It doesn't exploit anything or test for specific CVEs. It's a **reconnaissance / information-gathering** tool — it tells you what's exposed and what's missing (like a missing security header), not whether something is exploitable.

### Q5. Is this the same as Nmap?
No — Nmap is a general-purpose network scanner that ReconScope *uses* (as one module, for port scanning) if it's installed. ReconScope is a higher-level orchestrator that combines Nmap's output with DNS, WHOIS, HTTP, and TLS data into one report.

### Q6. Is this the same as Wappalyzer?
No, though the `technologies.py` module does a similar job on a smaller scale — matching response headers, cookies, and HTML body substrings against known signatures. It's intentionally conservative and won't catch everything Wappalyzer's larger signature database would.

### Q7. Does ReconScope need an internet connection?
Yes, for DNS resolution, WHOIS, certificate-transparency lookups (crt.sh), HTTP requests, and TLS handshakes. It cannot scan purely offline targets.

### Q8. Can I scan an internal/private (non-internet-facing) host?
Yes, if your machine can reach it (e.g., over VPN or on the same LAN) — DNS enumeration and WHOIS won't return much for a purely internal name, but HTTP, headers, TLS, and port scanning will still work against a reachable IP or internal hostname.

### Q9. Can I scan an IP address instead of a domain?
The current domain-validation regex expects a domain name (e.g. `example.com`), not a bare IP. If you need IP-based scanning, that's a good next feature — see the note in Q100 on customizing the tool, or pass a hostname that resolves to the IP you care about.

### Q10. Does ReconScope brute-force subdomains?
Not currently. Subdomain discovery relies entirely on certificate transparency logs (crt.sh) — it finds subdomains that have ever had a TLS certificate issued for them. It doesn't guess names like `dev1`, `staging2`, etc. A wordlist brute-forcer is on the roadmap (see README).

### Q11. Does ReconScope try to log in, upload files, or fuzz endpoints?
No. Every request it makes is a plain, unauthenticated `GET` (to the homepage, `/robots.txt`, and DNS/WHOIS/crt.sh endpoints) or a raw TCP connect (for port scanning). Nothing intrusive, nothing that submits data.

### Q12. What does "certificate transparency" mean, and why does ReconScope use it?
Certificate Authorities are required to publish every TLS certificate they issue to public logs. crt.sh indexes those logs and lets you search them. Since a certificate's "Subject Alternative Name" field often lists every subdomain it covers, searching crt.sh for `%.yourdomain.com` surfaces subdomains that have ever gotten a certificate — all without touching the target directly.

### Q13. Why does the tool check "security headers" specifically?
Headers like `Content-Security-Policy`, `Strict-Transport-Security`, and `X-Frame-Options` are cheap, high-leverage defenses against XSS, clickjacking, and protocol-downgrade attacks. Their presence/absence is a fast proxy for how security-conscious a deployment is, which is why they're a standard part of any recon report.

### Q14. Can ReconScope tell me if a site has been hacked?
No. It reports current configuration and exposure, not compromise indicators. That's a different discipline (incident response / forensics).

### Q15. Is ReconScope actively maintained / production-grade?
It's a solid, tested foundation (14 unit tests, all core modules covered) meant to be extended. Treat it like a personal/team tool you'll keep improving rather than a hardened commercial product — read the Roadmap section in the README for what's intentionally left out for now.

---

## 2. Installation

### Q16. What are the minimum requirements to run ReconScope?
Python 3.9+, `pip`, and internet access. Nmap is optional (recommended) — see Q28.

### Q17. How do I check my Python version?
```bash
python3 --version
```
You need 3.9 or newer. If you're below that, install a newer Python via [python.org](https://www.python.org/downloads/), `pyenv`, or your OS package manager.

### Q18. How do I get the ReconScope source code?
Clone it from GitHub:
```bash
git clone https://github.com/<your-username>/reconscope.git
cd reconscope
```
(Replace `<your-username>` with wherever you pushed the repo.)

### Q19. Should I use a virtual environment?
Yes, it's recommended so ReconScope's dependencies don't clash with other Python projects on your system:
```bash
python3 -m venv .venv
source .venv/bin/activate      # macOS/Linux
.venv\Scripts\activate         # Windows (PowerShell: .venv\Scripts\Activate.ps1)
```

### Q20. How do I install the required Python packages?
From inside the project directory, with your virtual environment activated:
```bash
pip install -r requirements.txt
```
This installs `requests`, `dnspython`, `python-whois`, and `rich`.

### Q21. How do I install the developer/testing dependencies?
```bash
pip install -r requirements-dev.txt
```
This layers `pytest`, `pytest-mock`, and `responses` (for mocked-network tests) on top of the base requirements.

### Q22. How do I verify the installation worked?
Run the version flag:
```bash
python reconscope.py --version
```
You should see `ReconScope 1.0.0`. Then try a real scan (Q37).

### Q23. Do I have to install it as a package, or can I just run the script?
Both work. Running `python reconscope.py <domain>` directly from the cloned folder works with no extra steps. Installing as a package (Q24) is only needed if you want the shorter `reconscope <domain>` command available system-wide.

### Q24. How do I install ReconScope as a proper CLI command?
```bash
pip install -e .
```
The `-e` (editable) flag means changes you make to the source still take effect without reinstalling. After this, `reconscope example.com` works from any directory (while your virtualenv is active).

### Q25. How do I uninstall it?
```bash
pip uninstall reconscope
```
Then just delete the cloned folder if you want to remove the source too.

### Q26. How do I update to a newer version?
If installed via git clone:
```bash
git pull
pip install -r requirements.txt --upgrade
```
If installed with `pip install -e .`, the `git pull` alone is usually enough since it's editable.

### Q27. Does ReconScope work on Windows?
Yes. Use PowerShell or Command Prompt, adjust the virtualenv activation command (Q19), and everything else is identical. Native Nmap for Windows works too if you want port-scan acceleration (Q28).

### Q28. Do I need to install Nmap separately?
Nmap is optional but recommended for faster, more accurate port scans. Without it, ReconScope automatically falls back to a built-in multi-threaded socket scanner over a list of ~20 common ports — slower and less detailed (no service/version fingerprinting) but fully functional.

### Q29. How do I install Nmap?
- **Debian/Ubuntu:** `sudo apt install nmap`
- **macOS (Homebrew):** `brew install nmap`
- **Windows:** download the installer from [nmap.org](https://nmap.org/download.html)
- **Fedora/RHEL:** `sudo dnf install nmap`

### Q30. How do I confirm Nmap is detected by ReconScope?
Run a scan and look at the Ports section's title — it prints `[+] Ports (method: nmap)` when Nmap is found, or `[+] Ports (method: socket-fallback)` when it isn't. You can also just run `which nmap` (macOS/Linux) or `where nmap` (Windows) yourself.

### Q31. Does installation require admin/root/sudo privileges?
No for the Python package install (inside a virtualenv). Installing Nmap system-wide typically needs `sudo`/admin rights, but running ReconScope itself does not require elevated privileges — it doesn't do raw-socket SYN scans, just regular TCP connects and HTTP requests.

### Q32. Can I run ReconScope inside Docker?
Not yet packaged, but it's straightforward to containerize: a `Dockerfile` based on `python:3.12-slim` that installs `requirements.txt`, optionally `apt-get install -y nmap`, copies the source, and sets `ENTRYPOINT ["python", "reconscope.py"]` would work. This is listed as a roadmap item in the README — ask if you'd like one built.

### Q33. How much disk space does it need?
Trivial — the source is a few hundred KB, dependencies are a few MB, and each report is typically under 50KB (JSON+CSV combined) unless a domain has an unusually large number of subdomains.

### Q34. Can I install it on a Raspberry Pi / ARM device?
Yes — pure Python plus small pip packages, all of which have ARM wheels. Nmap also has ARM builds via most package managers.

### Q35. I got a "permission denied" running `python reconscope.py`. What do I do?
That means the file isn't marked executable, which only matters if you're calling it as `./reconscope.py`. Just invoke it via the interpreter instead:
```bash
python3 reconscope.py example.com
```
or make it executable: `chmod +x reconscope.py`.

---

## 3. Basic Usage

### Q36. What's the absolute simplest command to run?
```bash
python reconscope.py example.com
```
That performs a full scan and writes reports to `reports/`.

### Q37. How do I scan my first domain as a test?
Use a domain you own, or a public test target such as `example.com` (a real, stable domain maintained for demonstration purposes) so you don't need authorization concerns while learning the tool.

### Q38. Can I pass a URL instead of a bare domain?
Yes — the CLI strips `http://`/`https://` and any path automatically. `python reconscope.py https://example.com/some/page` and `python reconscope.py example.com` behave identically.

### Q39. How long does a typical scan take?
Usually 15–60 seconds, dominated by the port scan (especially the socket fallback) and WHOIS. Use `--skip-ports` for a much faster pass (a few seconds) when you don't need port data.

### Q40. How do I skip the port scan?
```bash
python reconscope.py example.com --skip-ports
```
Useful on networks that block outbound scanning, or when you just want DNS/HTTP/TLS info fast.

### Q41. How do I skip subdomain discovery?
```bash
python reconscope.py example.com --skip-subdomains
```
Useful for very large domains where crt.sh might return thousands of certificate entries and slow things down.

### Q42. How do I skip writing report files and just see terminal output?
```bash
python reconscope.py example.com --no-export
```

### Q43. How do I change where reports get saved?
```bash
python reconscope.py example.com -o ./my-reports
```
or the long form `--output-dir ./my-reports`. The directory is created automatically if it doesn't exist.

### Q44. Can I combine multiple flags?
Yes:
```bash
python reconscope.py example.com --skip-ports --skip-subdomains -o ./quick-scan
```

### Q45. How do I see all available options?
```bash
python reconscope.py --help
```

### Q46. Can I scan multiple domains in one command?
Not natively as a single invocation, but a simple shell loop works:
```bash
for d in example.com example.org example.net; do
    python reconscope.py "$d" -o "reports/$d"
done
```

### Q47. Where do report files get named/saved by default?
`reports/<domain>_report.json` and `reports/<domain>_report.csv`, e.g. `reports/example.com_report.json`.

### Q48. What happens if I scan the same domain twice?
The report files are overwritten (same filename each time) unless you point `-o` at a different directory per run — handy if you want a timestamped history, e.g. `-o reports/$(date +%F)`.

### Q49. Can I stop a scan partway through?
Yes, press `Ctrl+C`. ReconScope catches the interrupt cleanly and exits with a message rather than dumping a traceback.

### Q50. Does it show progress while running?
Yes — each stage (DNS, WHOIS, subdomains, HTTP, technologies, robots.txt, TLS, ports) shows a live status spinner in the terminal so you can see what it's currently doing.

---

## 4. Feature-Specific Questions

### Q51. What DNS record types does it check?
A, AAAA, MX, NS, TXT, CNAME, and SOA.

### Q52. Why might some DNS record types show no results?
Not every domain has every record type (e.g., no MX record means no mail is configured), or the resolver timed out — both are normal and non-fatal.

### Q53. What WHOIS fields are captured?
Registrar, creation date, expiration date, last-updated date, name servers, status codes, org, and country — when the registry/registrar exposes them (many now redact personal data under GDPR-driven privacy policies).

### Q54. Why did my WHOIS lookup fail or time out?
WHOIS servers are notoriously inconsistent — some rate-limit aggressively, some are slow, and some registries don't run a WHOIS server at all (relying on RDAP instead). ReconScope catches this gracefully and reports the error rather than crashing; it just means that section of the report will be sparse for that domain.

### Q55. How does subdomain discovery actually work under the hood?
It queries `https://crt.sh/?q=%.yourdomain.com&output=json`, parses every returned certificate's `name_value` field (which can contain multiple hostnames, one per line), filters to names ending in your domain, and deduplicates the result.

### Q56. Why do I see subdomains that don't seem to resolve or exist anymore?
Certificate transparency logs are permanent — once a cert is issued, it stays in the log forever, even after the subdomain is decommissioned. So results reflect *historical* certificate issuance, not necessarily currently-live hosts.

### Q57. How does ReconScope decide HTTP vs HTTPS?
It tries HTTPS first; if that fails outright, it falls back to plain HTTP. If HTTPS answers but with a certificate error, it retries once with certificate verification disabled (flagging a `tls_warning`) so you still get header/technology data even from misconfigured HTTPS hosts.

### Q58. Which security headers does it check?
`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and `X-XSS-Protection`.

### Q59. A header shows "MISSING" but I know it's set — why?
Double-check it's set on the exact URL/scheme being tested (the report shows `final_url` and `scheme` in the HTTP section) — headers set only on HTTP but not HTTPS (or only on a redirect target) can look "missing" if ReconScope landed somewhere slightly different than expected.

### Q60. How does technology fingerprinting work?
It checks three signal sources on the homepage response: response headers (like `Server`, `X-Powered-By`, `CF-RAY`), cookie names (like `laravel_session`, `PHPSESSID`), and substrings in the HTML body (like `data-reactroot` or `wp-content`). Matches are conservative by design to minimize false positives.

### Q61. Why didn't it detect a technology I know is in use?
The fingerprint database is intentionally small and header/cookie/body-based — it won't catch everything (e.g., JS-rendered frameworks that don't leave a detectable server-side marker, or technologies with no distinctive signature configured). See Q98 for how to add your own signatures.

### Q62. Which ports does the scan check?
21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, and 27017 — common services (SSH, mail, databases, RDP, web, etc.).

### Q63. Can I scan a custom/different set of ports?
Not via a CLI flag yet — it's a hardcoded list in `reconscope/ports.py` (`COMMON_PORTS`). You can edit that list directly, or ask me to add a `--ports` CLI flag if you'd like it exposed as an option.

### Q64. Why does the Nmap scan and the socket-fallback scan sometimes disagree?
Nmap does proper protocol-aware probing and can distinguish "closed" from "filtered" (firewalled); the socket fallback only knows "did a TCP connect succeed within the timeout" — so it can under-report ports that are open but slow to respond, or over-report on very forgiving firewalls.

### Q65. Is the port scan an aggressive/loud scan that might trigger alerts?
It's a simple `-Pn -T4` Nmap connect-style scan (or an even simpler socket connect scan in fallback mode) against ~20 ports — not a stealth scan, not a full 65535-port sweep, and not something designed to evade detection. It's the kind of activity most IDS/IPS systems would log as a routine, low-volume scan, but it can still be visible to the target — see Q84.

### Q66. What does the `robots.txt` section actually check?
It fetches `/robots.txt`, counts `Disallow:` directives (paths the site is asking crawlers to skip — often unintentionally revealing sensitive paths) and any `Sitemap:` references.

### Q67. Why is `robots.txt` useful for recon?
Disallow rules sometimes reveal admin panels, staging paths, or internal tooling that the site owner didn't want indexed by Google — but the file itself is public, so it's a classic (and completely passive) recon source.

### Q68. What TLS/certificate info does it capture?
Issuer, subject (common name), validity dates, days until expiry, negotiated TLS version, cipher suite, and the certificate's Subject Alternative Names (SANs).

### Q69. Why would TLS info show an error?
Common causes: the domain doesn't listen on port 443 at all, a firewall blocks the connection from your network, or the handshake times out. The error message from the underlying exception is included so you can diagnose which.

### Q70. Can ReconScope detect an expired or soon-to-expire certificate?
Yes — the `expires_in_days` field in the TLS section tells you exactly how many days remain, which is handy for catching renewal issues before they cause outages.

---

## 5. Output, Reports & Automation

### Q71. What's in the JSON report?
The full structured scan result: `metadata`, `dns`, `whois`, `subdomains`, `http`, `security_headers`, `technologies`, `robots`, `tls`, and `ports` — machine-readable and suitable for feeding into other tools or dashboards.

### Q72. What's in the CSV report?
A flattened `category,key,value` table covering the same data — easier to open in Excel/Google Sheets or import into a spreadsheet-based tracker than nested JSON.

### Q73. Can I open the JSON report in a browser or text editor?
Yes, it's plain UTF-8 JSON — any text editor works, and browsers will pretty-print it if you open the file directly (`file:///path/to/report.json`).

### Q74. How do I pretty-print or query the JSON from the command line?
Using `jq` (if installed):
```bash
cat reports/example.com_report.json | jq '.security_headers'
```

### Q75. Can I diff two scans of the same domain over time?
Yes — since output is deterministic JSON keyed by category, running `diff` (or a JSON-aware diff tool) between two scans saved to different directories/timestamps is an easy way to track configuration drift.

### Q76. Can I schedule ReconScope to run automatically (e.g., daily)?
Yes, via cron (Linux/macOS) or Task Scheduler (Windows). Example crontab entry for a daily 6am scan:
```
0 6 * * * cd /path/to/reconscope && /path/to/.venv/bin/python reconscope.py example.com -o reports/$(date +\%F)
```

### Q77. Can I integrate ReconScope into a CI/CD pipeline?
Yes — it's a plain CLI with a clean exit code (0 on success, non-zero on failure), so it drops into any CI system (GitHub Actions, GitLab CI, Jenkins) as a step. You could, for example, fail a build if a required security header goes missing by parsing the JSON output in a follow-up script.

### Q78. Does it support output formats other than JSON/CSV?
Not currently — those two plus the terminal report are the built-in options. An HTML report is on the roadmap.

### Q79. Can I suppress the colored/terminal-styled output for logging purposes?
The terminal report uses the `rich` library, which auto-detects non-interactive output (like a redirected file or CI log) and typically degrades formatting sensibly. For guaranteed plain output in a script, capture the JSON/CSV files instead of parsing the terminal display.

### Q80. How do I use the report data in my own Python script?
```python
import json
data = json.load(open("reports/example.com_report.json"))
print(data["security_headers"])
```

### Q81. Are report files overwritten or appended to?
Overwritten — each run replaces the previous JSON/CSV for that domain in that output directory. Use per-date output directories (Q76) if you want history preserved.

### Q82. Can multiple people share one `reports/` folder (e.g., on a team drive)?
Yes, there's nothing environment-specific in the files themselves — just be mindful that scan results can reveal infrastructure details, so treat the folder with the same access control you'd give any internal security documentation.

---

## 6. Legal, Ethics & Safety

### Q83. Is it legal to run ReconScope against any domain I want?
No. You should only scan domains you **own** or have **explicit written authorization** to test (e.g., a bug bounty program's documented scope, or a signed pentest agreement). Passive lookups (DNS, WHOIS, crt.sh) are generally low-risk, but the active components (HTTP requests, port scanning) against a system you don't control can violate laws like the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse Act, or similar statutes elsewhere, plus the target's terms of service.

### Q84. Will the target know I scanned them?
Possibly. HTTP requests appear in the target's access logs with ReconScope's User-Agent string (`ReconScope/1.0`); the port scan is visible to any firewall/IDS logging connection attempts. It is not a stealth tool.

### Q85. Does ReconScope try to hide or spoof its identity?
No — it identifies itself with a clear User-Agent string on HTTP requests and makes no attempt at evasion, which is appropriate for authorized, above-board reconnaissance work.

### Q86. Can I use ReconScope for a bug bounty program?
Yes, as long as the target domain (and the specific techniques — some programs restrict active scanning even within scope) is covered by that program's published scope and rules of engagement. Always read the program's policy first.

### Q87. Is scanning my own company's domain from my personal laptop okay?
Generally yes if you're authorized to do so as an employee/contractor, but many organizations have internal policies requiring security testing to go through a specific team or ticket — check before running unsanctioned scans against production systems, even your own employer's.

### Q88. Could a scan cause a denial-of-service or crash a website?
Unlikely with ReconScope's default behavior (a handful of GET requests and a ~20-port connect scan), but any interaction with a fragile or misconfigured system carries some risk. Don't run repeated scans in a tight loop against production infrastructure, and use `--skip-ports` on systems known to be sensitive.

### Q89. Does ReconScope store or transmit my scan data anywhere (telemetry)?
No — everything runs locally on your machine, and results are written only to the local `reports/` directory (or wherever `-o` points). The only outbound network calls are the recon lookups themselves (DNS, WHOIS, crt.sh, HTTP, TLS, port connects) to the target/registries — there's no analytics or phone-home behavior.

### Q90. What should I do if a scan reveals a real vulnerability on a system I'm authorized to test?
Follow responsible disclosure practices: document it clearly (the JSON/CSV report is a good start), report it through the appropriate channel (the organization's security contact, bug bounty platform, or your internal ticketing process), and avoid taking any exploitative action beyond what your authorization covers.

---

## 7. Troubleshooting

### Q91. I get `ModuleNotFoundError: No module named 'reconscope'`. What's wrong?
You're likely running the script from outside the project folder, or without activating your virtualenv. `cd` into the cloned `reconscope/` directory and make sure `source .venv/bin/activate` (or the Windows equivalent) has been run first.

### Q92. I get `ModuleNotFoundError` for `requests`, `dns`, `whois`, or `rich`. What's wrong?
Dependencies aren't installed in your active environment. Run `pip install -r requirements.txt` again, and confirm you're inside the virtualenv (`which python` should point into `.venv/`).

### Q93. The domain I entered gets rejected with "does not look like a valid domain." Why?
The validator expects a plain hostname like `example.com` — no protocol, no path, no trailing slash issues it can't strip, and no spaces or invalid characters. Double check for typos, stray whitespace, or an accidentally included query string.

### Q94. WHOIS always fails for every domain I try — is something broken?
Some networks (corporate proxies, certain cloud environments, some ISPs) block outbound WHOIS traffic on port 43. Test with `whois example.com` directly in your terminal — if that also hangs, it's a network/firewall issue outside ReconScope's control, not a bug in the tool.

### Q95. The port scan takes forever. How do I speed it up?
Install Nmap (Q29) — it's significantly faster than the socket fallback. Alternatively, use `--skip-ports` if you don't need port data for that run, or reduce the `COMMON_PORTS` list in `reconscope/ports.py`.

### Q96. I'm getting SSL/certificate errors even for sites I know have valid HTTPS. Why?
This usually means your Python installation's CA certificate bundle is outdated, or you're behind a corporate TLS-inspecting proxy presenting its own certificate. Try `pip install --upgrade certifi`, or check with your IT team if you're on a managed network.

### Q97. Tests fail when I run `pytest`. What should I check first?
Confirm `requirements-dev.txt` is installed (`pip install -r requirements-dev.txt`) — the test suite needs `pytest`, `pytest-mock`, and `responses` specifically, separate from the base runtime dependencies.

### Q98. How do I add a new technology-fingerprint signature?
Open `reconscope/technologies.py` and add an entry to `HEADER_SIGNATURES`, `COOKIE_SIGNATURES`, or `BODY_SIGNATURES` (format is documented in comments at the top of each list) — e.g. `("server", "litespeed", "LiteSpeed")` to detect the LiteSpeed web server.

### Q99. Can I get help extending ReconScope (new features, Docker, CI, etc.)?
Yes — just ask. The codebase is modular by design (one file per concern) specifically so new recon capabilities can be added as new modules without touching the others.

### Q100. Where do I report a bug or request a feature?
If you've pushed this to your own GitHub repo, open an Issue there to track it for yourself. If you'd like, I can also help you draft `CONTRIBUTING.md` guidelines or a GitHub issue template as a follow-up.
