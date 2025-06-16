# grAPI — Aggressive & Stealthy API Discovery Toolkit

`grAPI` is a Python-based API recon tool built for security researchers, red teamers, and bug bounty hunters who need a fast, effective way to uncover hidden API endpoints, tokens, routes, and documentation across modern web applications. It combines active and passive discovery methods, fingerprinting, and threat-aware crawling. All with built-in mechanisms to evade WAFs, IDS, and IP-based rate-limiting.

This tool isn't just another crawler. It's tuned for real-world offensive operations where stealth, noise control, and accuracy matter.

---

## Why Use grAPI?

Modern applications are powered by APIs like REST, GraphQL, OpenAPI, and others. These interfaces often become the weakest link in the security chain. `grAPI` was designed to:

- Map API routes and endpoints, even those dynamically generated via JavaScript
- Find hidden API specs (Swagger, OpenAPI, YAML, etc.)
- Detect and extract hardcoded tokens from scripts
- Identify API documentation exposure (e.g., /swagger.json)
- Passively pull archived endpoints from Wayback Machine
- Crawl aggressively while avoiding detection or rate-limit bans
- Auto-analyze headers for fingerprinting WAFs or CDNs

---

## Features

- ✅ Active and Passive API Endpoint Discovery  
- ✅ JavaScript Link and Token Scraper  
- ✅ Swagger/OpenAPI Spec Detection  
- ✅ GraphQL Endpoint Identification  
- ✅ Custom Wordlist-Based Fuzzing  
- ✅ Dynamic Endpoint Extraction (Regex + Script Parsing)  
- ✅ WAF and CDN Fingerprinting  
- ✅ Smart Throttling to Evade IDS/IPS  
- ✅ Result Export to JSON or TXT  
- ✅ Parallel Status Code Checker  
- ✅ Optional Verbose Logging  

---

## Usage

Run the tool with any combination of flags. Here's a quick look:

### Basic Usage:

```bash
python3 grAPI.py --url https://example.com --all -v
```

### Flags:

| Flag | Description |
|------|-------------|
| --url | Target base URL (e.g., https://site.com) |
| --active | Enable active crawling & JS parsing |
| --passive | Use Wayback Machine for endpoint gathering |
| --fingerprint | Detect WAF/CDN + grab robots/sitemap |
| --swagger | Check for Swagger/OpenAPI files |
| --graphql | Try to locate GraphQL endpoint |
| --tokens | Extract API tokens & secrets from JS files |
| --wordlist | Custom fuzz list for brute-forcing endpoints |
| --all | Run everything (recommended for thorough recon) |
| --output | Save output to a file (JSON or TXT) |
| --format | Set output format (json or txt, default: json) |
| -v, --verbose | Show debug/log output during scan |

### Example:

Full aggressive scan with stealth:

```bash
python3 grAPI.py --url https://target.com --all --wordlist payloads/api-fuzz.txt -v --output results.json
```

---

## Installation

Clone the repo:

```bash
git clone https://github.com/DghostNinja/grAPI.git
cd grAPI
```

Install dependencies:

```bash
pip3 install -r requirements.txt
```

### Requirements

- Python 3.8+
- Modules:
  - requests
  - beautifulsoup4
  - fake-useragent
  - argparse

You can install them manually if needed:

```bash
pip3 install requests beautifulsoup4 fake-useragent
```

---

## Tips for Use in the Field

- Avoid IP bans: Use VPN, Tor, or proxy chains during scans  
- Reduce noise: Limit crawl depth and use --active cautiously  
- Start passive: Run --passive first to avoid tripping alarms  
- Token hunting: Use --tokens to find secrets in production JS files  
- Customize fuzzing: Supply your own wordlist via --wordlist

---

## What It’s Not

This is not a vulnerability scanner — it's an endpoint discovery and reconnaissance tool. You can chain it with tools like nuclei, Burp Suite, or your custom scripts for deeper analysis.

---

## Sample Output

```txt
[+] API Endpoints Found:
https://example.com/api/v1/user/login             => 200
https://example.com/graphql                       => 200
https://example.com/swagger.json                  => 200
https://example.com/js/app.js                     => Token found
```

---

## Author

Built with security research in mind by [@DghostNinja](https://github.com/DghostNinja)

---

## License

MIT

---

Got feedback, suggestions, or pull requests? Open an issue or contribute back. Let’s make this beast even more powerful.
