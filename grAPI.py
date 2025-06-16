import requests
import re
import time
import random
import argparse
import json
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from queue import Queue

# ASCII Banner
ascii_banner = r"""
            _   ___ ___ 
  __ _ _ _ /_\ | _ \_ _|
 / _` | '_/ _ \|  _/| | 
 \__, |_|/_/ \_\_| |___|
 |___/                  
    by iPsalmy
"""

ua = UserAgent()
visited = set()
endpoints = {}
verbose = False
root_url = ""

KEYWORDS = [
    'auth', 'login', 'logout', 'register', 'user', 'users', 'admin', 'dashboard',
    'profile', 'settings', 'account', 'session', 'token', 'graphql', 'rest',
    'api', 'v1', 'v2', 'products', 'items', 'orders', 'data', 'service'
]

WAF_SIGNATURES = ["cloudflare", "sucuri", "akamai", "imperva", "aws"]
BAD_EXTENSIONS = re.compile(r'\.(jpg|jpeg|png|gif|svg|css|woff|ico|ttf|eot|pdf)(\?|$)', re.IGNORECASE)

HEADERS = lambda: {
    'User-Agent': ua.random,
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept': '*/*'
}

def log(msg):
    if verbose:
        print(msg)

def safe_get(url):
    try:
        return requests.get(url, headers=HEADERS(), timeout=8)
    except:
        return None

def passive_wayback(target, max_results=300):
    print("[*] Running passive scan via Wayback Machine...")
    domain = urlparse(target).netloc
    wayback_url = (
        f"http://web.archive.org/cdx/search/cdx?url={domain}/"
        f"&output=json&fl=original&collapse=urlkey&limit={max_results}"
    )
    try:
        resp = requests.get(wayback_url, timeout=10)
        if resp.status_code == 200:
            entries = resp.json()[1:]
            for entry in entries:
                url = entry[0]
                if BAD_EXTENSIONS.search(url): continue
                if any(re.search(k, url, re.IGNORECASE) for k in KEYWORDS):
                    endpoints[url] = None
    except Exception as e:
        log(f"[!] Wayback failed: {e}")

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
        for path in ["/robots.txt", "/sitemap.xml"]:
            res = safe_get(urljoin(root_url, path))
            if res and res.status_code == 200:
                print(f"[+] {path} found")
    except:
        pass

def scan_swagger():
    print("[*] Scanning for Swagger/OpenAPI...")
    candidates = ["/swagger.json", "/api-docs", "/v1/swagger.json", "/openapi.json"]
    for path in candidates:
        url = urljoin(root_url, path)
        resp = safe_get(url)
        if resp and resp.status_code == 200 and 'swagger' in resp.text.lower():
            print(f"[+] Swagger/OpenAPI found: {url}")
            endpoints[url] = 200

def scan_graphql():
    print("[*] Scanning for GraphQL endpoint...")
    graphql_url = urljoin(root_url, "/graphql")
    headers = HEADERS()
    headers['Content-Type'] = 'application/json'
    payload = {'query': '{ __schema { types { name } } }'}
    try:
        resp = requests.post(graphql_url, headers=headers, json=payload, timeout=8)
        if resp.status_code == 200 and 'data' in resp.text:
            print(f"[+] GraphQL endpoint detected: {graphql_url}")
            endpoints[graphql_url] = 200
    except:
        pass

def extract_tokens_from_text(text):
    pattern = r"(?:api_key|token|access_token|auth_token|jwt)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9\-_\.]+)[\"']?"
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
    for link in links:
        resp = safe_get(link)
        if resp and resp.text:
            toks = extract_tokens_from_text(resp.text)
            for t in toks:
                print(f"[+] Token found in {link}: {t}")

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

def extract_endpoints(text):
    patterns = [
        r'(["\'])(/[^"\'>\s]{1,200}?)\1',
        r'(["\'])((?:https?:)?//[^"\'>\s]+/[^"\'>\s]+)\1'
    ]
    for pattern in patterns:
        matches = re.findall(pattern, text)
        for _, match in matches:
            if any(re.search(rf'\b{k}\b', match, re.IGNORECASE) for k in KEYWORDS):
                ep_url = match if match.startswith("http") else urljoin(root_url, match)
                if ep_url not in endpoints:
                    endpoints[ep_url] = None
                    log(f"[+] Found endpoint: {ep_url}")

def concurrent_crawl(start_url, max_depth=2, max_threads=10):
    q = Queue()
    q.put((start_url, 0))

    def worker():
        while not q.empty():
            url, depth = q.get()
            if depth > max_depth or url in visited or BAD_EXTENSIONS.search(url):
                q.task_done()
                continue
            visited.add(url)
            try:
                resp = safe_get(url)
                if resp and resp.text:
                    extract_endpoints(resp.text)
                    for link in extract_links(resp.text, url):
                        q.put((link, depth + 1))
            except:
                pass
            q.task_done()

    threads = []
    for _ in range(max_threads):
        t = Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()

def check_single_endpoint(ep):
    try:
        r = requests.head(ep, headers=HEADERS(), timeout=6)
        return ep, r.status_code
    except:
        return ep, "ERR"

def check_status():
    print("[*] Checking endpoint statuses (parallel)...")
    with ThreadPoolExecutor(max_workers=12) as executor:
        results = executor.map(check_single_endpoint, endpoints.keys())
        for ep, status in results:
            endpoints[ep] = status

if __name__ == "__main__":
    print(ascii_banner)

    parser = argparse.ArgumentParser(description="grAPI - Aggressive & Stealthy API Recon Tool")
    parser.add_argument("--url", required=True, help="Target website URL")
    parser.add_argument("--active", action="store_true", help="Perform active crawling")
    parser.add_argument("--passive", action="store_true", help="Use passive Wayback scan")
    parser.add_argument("--fingerprint", action="store_true", help="Check for WAF, robots.txt, etc.")
    parser.add_argument("--swagger", action="store_true", help="Scan for Swagger/OpenAPI")
    parser.add_argument("--graphql", action="store_true", help="Detect GraphQL endpoints")
    parser.add_argument("--tokens", action="store_true", help="Find hardcoded tokens")
    parser.add_argument("--all", action="store_true", help="Run all scans")
    parser.add_argument("--output", help="Save results to file")
    parser.add_argument("--format", default="json", choices=["json", "txt"], help="Output file format")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--depth", type=int, default=2, help="Crawling depth")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")

    args = parser.parse_args()
    verbose = args.verbose
    root_url = args.url if args.url.startswith("http") else f"https://{args.url}"

    if args.all or args.passive:
        passive_wayback(root_url)
    if args.all or args.fingerprint:
        fingerprint()
    if args.all or args.active:
        concurrent_crawl(root_url, args.depth, args.threads)
    if args.all or args.swagger:
        scan_swagger()
    if args.all or args.graphql:
        scan_graphql()
    if args.all or args.tokens:
        scan_for_tokens()

    check_status()

    print(f"\n[+] API Endpoints Found: {len(endpoints)}")
    for ep, code in sorted(endpoints.items()):
        print(f"{ep:<60} => {code}")

    if args.output:
        with open(args.output, 'w') as f:
            if args.format == "json":
                json.dump(endpoints, f, indent=2)
            else:
                for ep, code in endpoints.items():
                    f.write(f"{ep} => {code}\n")
        print(f"[+] Results saved to {args.output}")
