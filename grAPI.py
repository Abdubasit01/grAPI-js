"""
Unified API Recon Tool - Aggressive & Stealthy Endpoint Discovery
Combines Active/Passive Discovery, Token Detection, and Spec Scanning
"""

import requests
import re
import time
import random
import argparse
import json
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

# Globals
ua = UserAgent()
visited = set()
endpoints = {}
verbose = False
root_url = ""

# Signatures and Patterns
WAF_SIGNATURES = ["cloudflare", "sucuri", "akamai", "imperva", "aws"]
KEYWORDS = [
    'auth', 'login', 'logout', 'register', 'users?', 'admin', 'dashboard',
    'profile', 'settings', 'account', 'session', 'token', 'graphql', 'rest',
    'api', 'v1', 'v2', 'products?', 'items?', 'orders?', 'data', 'service', 'backend'
]

# Header generator
HEADERS = lambda: {
    'User-Agent': ua.random,
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept': '*/*'
}

# Logger
def log(msg):
    if verbose:
        print(msg)

# Safe HTTP GET
def safe_get(url):
    try:
        resp = requests.get(url, headers=HEADERS(), timeout=10)
        return resp
    except Exception as e:
        log(f"[!] GET failed for {url}: {e}")
        return None

# Passive Recon: Wayback
def passive_wayback(target):
    print("[*] Running passive scan via Wayback Machine...")
    domain = urlparse(target).netloc
    wayback_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        resp = requests.get(wayback_url)
        if resp.status_code == 200:
            entries = resp.json()[1:]
            for entry in entries:
                if any(re.search(k, entry[0], re.IGNORECASE) for k in KEYWORDS):
                    endpoints[entry[0]] = None
    except:
        log("[!] Wayback failed.")

# Fingerprint Detection
def fingerprint():
    print("[*] Running fingerprint scan...")
    try:
        r = safe_get(root_url)
        if r:
            print("[+] Headers:")
            for k, v in r.headers.items():
                print(f"  {k}: {v}")
            for sig in WAF_SIGNATURES:
                if sig in str(r.headers).lower():
                    print(f"[!] Possible WAF/CDN detected: {sig}")
        rt = safe_get(urljoin(root_url, "/robots.txt"))
        sm = safe_get(urljoin(root_url, "/sitemap.xml"))
        if rt and rt.status_code == 200:
            print("[+] robots.txt found")
        if sm and sm.status_code == 200:
            print("[+] sitemap.xml found")
    except:
        pass

# Swagger/OpenAPI Detection
def scan_swagger():
    print("[*] Scanning for Swagger/OpenAPI...")
    candidates = ["/swagger.json", "/api-docs", "/v1/swagger.json", "/openapi.json"]
    for path in candidates:
        url = urljoin(root_url, path)
        resp = safe_get(url)
        if resp and resp.status_code == 200 and 'swagger' in resp.text:
            print(f"[+] Swagger/OpenAPI found: {url}")
            endpoints[url] = 200

# GraphQL Detection
def scan_graphql():
    print("[*] Scanning for GraphQL endpoint...")
    graphql_url = urljoin(root_url, "/graphql")
    headers = HEADERS()
    headers['Content-Type'] = 'application/json'
    payload = {'query': '{ __schema { types { name } } }'}
    try:
        resp = requests.post(graphql_url, headers=headers, json=payload)
        if resp.status_code == 200 and 'data' in resp.text:
            print(f"[+] GraphQL endpoint detected: {graphql_url}")
            endpoints[graphql_url] = 200
    except:
        pass

# Token Extraction
def extract_tokens_from_text(text):
    pattern = r'(?:api_key|token|access_token|auth_token|jwt)["\']?\s*[:=]\s*["\']([^"\']+)'
    return re.findall(pattern, text, re.IGNORECASE)

def scan_for_tokens():
    print("[*] Searching for hardcoded tokens...")
    links = [root_url]
    html = safe_get(root_url)
    if not html:
        return []
    soup = BeautifulSoup(html.text, 'html.parser')
    for tag in soup.find_all(["script", "link"]):
        attr = tag.get('src') or tag.get('href')
        if attr and attr.endswith(".js"):
            links.append(urljoin(root_url, attr))
    found = []
    for link in links:
        resp = safe_get(link)
        if resp and resp.text:
            toks = extract_tokens_from_text(resp.text)
            for t in toks:
                print(f"[+] Token found in {link}: {t}")
                found.append((link, t))
    return found

# Link Extractor
def extract_links(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    urls = set()
    for tag in soup.find_all(["a", "script", "link"]):
        attr = tag.get('href') or tag.get('src')
        if attr:
            full_url = urljoin(base_url, attr)
            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                urls.add(full_url)
    return urls

# Enhanced Endpoint Extractor (from Code 1)
def extract_endpoints(text):
    patterns = [
        r'(["\'`])(/[^"\'>\s]{1,200}?)\1',
        r'(["\'`])((?:https?:)?//[^"\'>\s]+/[^"\'>\s]+)\1'
    ]
    for pattern in patterns:
        matches = re.findall(pattern, text)
        for _, match in matches:
            if any(re.search(rf'\b{k}\b', match, re.IGNORECASE) for k in KEYWORDS):
                path = match.strip()
                ep_url = path if path.startswith("http") else urljoin(root_url, path)
                if ep_url not in endpoints:
                    endpoints[ep_url] = None
                    log(f"[+] Found possible endpoint: {ep_url}")

# Enhanced Crawler (from Code 1)
def crawl(url, depth=2):
    if depth == 0 or url in visited:
        return
    visited.add(url)

    resp = safe_get(url)
    if not resp or not resp.text:
        return

    extract_endpoints(resp.text)

    links = extract_links(resp.text, url)
    js_links = [l for l in links if l.endswith('.js')]
    crawl_links = list(links) + js_links

    for link in crawl_links:
        time.sleep(random.uniform(0.8, 2.5))
        crawl(link, depth - 1)

# Endpoint Status Check
def check_status():
    print("[*] Checking endpoint statuses...")
    for ep in endpoints:
        try:
            r = requests.head(ep, headers=HEADERS(), timeout=5, allow_redirects=True)
            endpoints[ep] = r.status_code
        except:
            endpoints[ep] = "ERR"

# Main Execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stealthy API Recon Tool")
    parser.add_argument("--url", required=True, help="Target website URL")
    parser.add_argument("--active", action="store_true", help="Perform active crawling")
    parser.add_argument("--depth", type=int, default=2, help="Depth for active crawl")
    parser.add_argument("--passive", action="store_true", help="Use passive Wayback scan")
    parser.add_argument("--fingerprint", action="store_true", help="Check for WAF, robots.txt, etc.")
    parser.add_argument("--swagger", action="store_true", help="Scan for Swagger/OpenAPI docs")
    parser.add_argument("--graphql", action="store_true", help="Detect GraphQL endpoints")
    parser.add_argument("--tokens", action="store_true", help="Find hardcoded tokens in JS/HTML")
    parser.add_argument("--all", action="store_true", help="Run all scans")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--format", default="json", choices=["json", "txt"], help="Output format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")

    args = parser.parse_args()
    verbose = args.verbose
    root_url = args.url if args.url.startswith("http") else f"https://{args.url}"

    if args.all or args.passive:
        passive_wayback(root_url)
    if args.all or args.fingerprint:
        fingerprint()
    if args.all or args.active:
        crawl(root_url, depth=args.depth)
    if args.all or args.swagger:
        scan_swagger()
    if args.all or args.graphql:
        scan_graphql()
    if args.all or args.tokens:
        scan_for_tokens()

    check_status()

    print("\n[+] Endpoints:")
    for ep, code in sorted(endpoints.items()):
        print(f"{ep:<70} => {code}")

    if args.output:
        with open(args.output, 'w') as f:
            if args.format == "json":
                json.dump(endpoints, f, indent=2)
            else:
                for ep, code in endpoints.items():
                    f.write(f"{ep} => {code}\n")
        print(f"[+] Results saved to {args.output}")
